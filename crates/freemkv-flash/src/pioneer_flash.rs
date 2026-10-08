//! Live Pioneer OEM flash executor.
//!
//! Issues the OEM `WRITE BUFFER` command sequence over the wire imperatively,
//! with the documented result checks, post-entry identity gate, settle delays,
//! and completion poll (see the Pioneer firmware protocol notes). It issues real writes and must only be reached behind the engine's
//! `--execute`/`--i-understand-risk` safety gate, an empty/closed tray guard,
//! and a captured pre-flash backup.
//!
//! No raw CDB is built here: every Pioneer vendor command goes through
//! `pioneer_optical::drive` over the single adapter in
//! [`crate::drive::pioneer_transport`].
//!
//! The caller ([`crate::drive::pioneer`]) builds the 256-byte control buffer
//! (descriptor + key resolved from the live receiver) and selects the components
//! from the flash input — a Kernel (`07/FE`), a Normal (`07/F0`), or both. This
//! executor is straight-line: entry, the chunks, finish. There is no
//! model-specific schedule; validated layout selects the transfer framing.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use pioneer_optical::drive::enter_update;
use pioneer_optical::{DriveClass, Identity, Role};

#[cfg(test)]
use crate::drive::pioneer::FLASH_CHUNK;
use crate::drive::pioneer::{transfer, TransferStage, CONTROL_LEN};
use crate::drive::pioneer_transport::{self as transport, flash_err, ScsiTransport, SharedDevice};
use crate::platform::ScsiDevice;
use crate::style;

/// A failed transfer or finish past the entry gate leaves the drive mid-flash.
const PARTIAL_HINT: &str = " — the drive may now hold a partial firmware; re-flash the captured \
                            pre-flash backup to restore it";

/// Documented post-entry settle before the identity check.
const ENTRY_SETTLE: Duration = Duration::from_secs(1);
/// Documented post-finish settle before status polling.
const FINISH_SETTLE: Duration = Duration::from_secs(2);
/// Upper bound on the completion poll after `05/FF` finish.
const POLL_TIMEOUT: Duration = Duration::from_secs(90);
/// Delay between completion-poll attempts.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The drive dialect an update session must speak. Taken from the drive's own
/// identity (`drive::identify` -> `Identity::class`) when that identity is
/// unambiguous: a `BD-*` product, or a `DVD-R*` product on a `DVR*` platform.
///
/// FALLBACK (`--recover` ONLY): an identity that cannot be read (a degraded
/// drive) or that is neither of those is ambiguous. If the target Normal
/// profiles as a known family (`target_family_known`, from
/// `pioneer_optical::image::family` on its decoded body) the flash is a
/// BD-generation image, so assume [`DriveClass::Bd`] — the `04/FF`-only entry,
/// which is the only flash route validated on hardware. A normal (non-recover)
/// flash never guesses: an unreadable/ambiguous identity is refused before any
/// write, as is a recover flash with no family to lean on.
fn resolve_class(
    identity: Result<Identity>,
    target_family_known: bool,
    recover: bool,
) -> Result<DriveClass> {
    if let Some(class) = identity.as_ref().ok().and_then(Identity::class) {
        return Ok(class);
    }
    if recover && target_family_known {
        println!(
            "{}",
            style::dim("  drive class not reported; target is a known BD family, assuming Bd")
        );
        return Ok(DriveClass::Bd);
    }
    match identity {
        Err(error) => Err(error).context(
            "could not read the drive identity to choose the update dialect (a guess is only \
             made under --recover, for a recognised BD family); refusing before any write",
        ),
        Ok(_) => bail!(
            "the drive does not identify as a BD or DVR generation (a guess is only made under \
             --recover, for a recognised BD family); refusing before any write"
        ),
    }
}

/// Execute the OEM update against the drive with the pre-built 256-byte
/// `control` buffer (descriptor + key resolved from the live receiver).
///
/// Every Pioneer vendor command is issued by `pioneer_optical::drive`: identify
/// -> [`enter_update`] (OEM update entry; the crate adds the DVR handshake
/// first when the class needs it) -> post-entry settle + identity gate ->
/// Kernel slices (if any) -> Normal chunks -> `finish` ->
/// finish settle + ready poll. Every write goes through the strict
/// (abort-on-any-nonzero, no-retry) transport, exactly as the OEM host loop
/// does. The caller resolves the control key and components and guarantees
/// gating, the tray guard, and a pre-flash backup.
///
/// `patch_kernel` requests the §15.3 Site-1 marker patch on an `FF`/`00` Kernel
/// (the caller sets it only when writing onto a new-generation or unknown
/// receiver); when `false` the Kernel is written unmodified.
///
/// A failure after entry never commits: the session sends nothing when dropped,
/// so a partial image is not blessed.
pub(crate) fn execute_flash(
    dev: &mut dyn ScsiDevice,
    control: &[u8; CONTROL_LEN],
    kernel: Option<&[u8]>,
    normal: &[u8],
    recover: bool,
    patch_kernel: bool,
    force: bool,
) -> Result<()> {
    // §15.3 Site-1 downgrade patch: if the incoming Kernel's decoded marker
    // byte is `FF`/`00` (older generation), the receiver's Site-1 gate at
    // runtime `0x405266` rejects it. Patch body[`0xFE`]`FF/00`→`01` and
    // compensate the §8.1 additive checksum word at `0x1020`, then re-encode
    // the envelope with the original key table. Only the two edited words
    // differ in ciphertext; the LCG keystream is unchanged. On an older-than-
    // Site-1 drive the patch is a no-op (marker is already `01`-equivalent in
    // all paths that reach here with a `FF` body because gate 1/2 already
    // ran — but we check idempotently). Applied ONLY when the caller asks for it
    // (`patch_kernel`): writing onto an installed-`01` drive. Otherwise the
    // Kernel is written byte-identical.
    let patched_kernel: Option<Vec<u8>> = if patch_kernel {
        kernel
            .map(apply_downgrade_patch_if_needed)
            .transpose()?
            .flatten()
    } else {
        None
    };
    let kernel: Option<&[u8]> = patched_kernel.as_deref().or(kernel);

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32;
    let kernel_transfer = kernel
        .map(|k| transfer::select_kernel(k, seed))
        .transpose()?;
    let steps = transfer::data_out(control, normal, kernel_transfer)?;
    let kernel_total = steps
        .iter()
        .filter(|s| {
            matches!(
                s.stage,
                TransferStage::KernelPrefix | TransferStage::KernelFe
            )
        })
        .map(|s| s.data.len())
        .sum();

    style::trace(&format!(
        "execute_flash: kernel={} bytes, normal={} bytes",
        kernel.map_or(0, <[u8]>::len),
        normal.len()
    ));

    // Two independent progress bars: the Kernel phase and the Normal phase each
    // report against their own byte total.
    let mut kernel_progress = style::Progress::new("flashing kernel", kernel_total);
    let mut normal_progress = style::Progress::new("flashing normal", normal.len());

    crate::engine::guard_no_medium(dev, true, force || recover)?;
    let shared = SharedDevice::new(dev);
    let class = resolve_class(
        transport::identify_on(&shared),
        crate::pioneer_flash_plan::normal_family(normal).is_some(),
        recover,
    )?;
    let mut port = ScsiTransport::flash(&shared);

    // OEM update-mode entry, then settle and identity gate. In recover mode the
    // drive is degraded and may not report a trustworthy identity, so the
    // post-entry gate is skipped — we force the write. A failed entry is before
    // the update state, so it carries no partial-firmware hint.
    let mut session = enter_update(&mut port, class, control)
        .map_err(flash_err)
        .context("OEM Entry write failed")?;
    std::thread::sleep(ENTRY_SETTLE);
    if recover {
        println!(
            "{}",
            style::dim("  update mode entered (recover: identity gate skipped)")
        );
    } else {
        entry_identity_gate(&shared)?;
        println!("{}", style::dim("  update mode entered"));
    }

    let mut kernel_written = 0;
    let mut normal_written = 0;
    let mut kernel_pending_settle = false;
    for step in &steps {
        let role = match step.stage {
            TransferStage::Entry | TransferStage::Finish => continue,
            TransferStage::KernelFe => Role::Kernel,
            TransferStage::KernelPrefix | TransferStage::Normal => Role::Normal,
        };
        if step.stage == TransferStage::Normal && kernel_pending_settle {
            std::thread::sleep(Duration::from_secs(2));
            kernel_pending_settle = false;
        }
        session
            .write(role, step.offset, &step.data)
            .map_err(flash_err)
            .with_context(|| {
                format!(
                    "OEM {:?} write failed at offset {:#x}, length {}{PARTIAL_HINT}",
                    step.stage,
                    step.offset,
                    step.data.len()
                )
            })?;
        if step.stage == TransferStage::Normal {
            normal_written += step.data.len();
            normal_progress.set(normal_written);
        } else {
            kernel_written += step.data.len();
            kernel_progress.set(kernel_written);
            kernel_pending_settle = true;
        }
    }

    // Commit with the control buffer, then settle and poll for ready.
    session
        .finish()
        .map_err(flash_err)
        .with_context(|| format!("OEM Finish write failed{PARTIAL_HINT}"))?;
    std::thread::sleep(FINISH_SETTLE);
    poll_until_ready(&shared)?;
    Ok(())
}

/// Try the §15.3 downgrade patch on an incoming Kernel envelope. Returns
/// `Ok(None)` when no patch is needed (marker is already `01`, or the envelope
/// does not decode); a wrong-sized body is an error, `Ok(Some(new_envelope))` when the
/// decoded body's marker was `FF`/`00` and we flipped it to `01` + rebalanced
/// the checksum and re-encoded. Logs the exact two-word diff on patch.
fn apply_downgrade_patch_if_needed(kernel_enc: &[u8]) -> Result<Option<Vec<u8>>> {
    let decoded = match pioneer_optical::envelope::decode_envelope(kernel_enc) {
        Some(d) => d,
        None => return Ok(None), // not a decodable envelope; nothing to patch
    };
    if decoded.image.len() != pioneer_optical::envelope::KERNEL_BODY_LEN {
        // The caller only asks for the patch (and warns about it) for an FF/00
        // marker, so a wrong-sized body must be refused, never skipped silently.
        bail!(
            "cannot apply the downgrade patch: the Kernel body is {:#x} bytes, expected {:#x}",
            decoded.image.len(),
            pioneer_optical::envelope::KERNEL_BODY_LEN
        );
    }
    let (patched_body, outcome) = pioneer_optical::envelope::downgrade_patch(&decoded.image)
        .map_err(|e| anyhow!("downgrade patch refused the Kernel body: {e:?}"))?;
    match outcome {
        pioneer_optical::envelope::DowngradePatchOutcome::AlreadyNewer => Ok(None),
        pioneer_optical::envelope::DowngradePatchOutcome::Patched {
            marker_before,
            checksum_word_before,
            checksum_word_after,
        } => {
            style::trace(&format!(
                "§15.3 downgrade patch applied: body[0xFE] {marker_before:#04x}->0x01, \
                 word@0x1020 {checksum_word_before:#010x}->{checksum_word_after:#010x}"
            ));
            let repacked = decoded.repack(&patched_body).ok_or_else(|| {
                anyhow!("could not re-encode the patched Kernel envelope (codec repack failed)")
            })?;
            Ok(Some(repacked))
        }
        _ => bail!("downgrade patch returned an unrecognized outcome"),
    }
}

/// After the update entry the OEM host waits ~1 s, issues INQUIRY, and requires
/// ASCII `000` at response bytes `[0x20..0x23]` before transferring. Mirror that
/// gate: a drive not in the expected update state aborts before any transfer.
fn entry_identity_gate(shared: &SharedDevice<'_>) -> Result<()> {
    let inquiry = shared.inquiry(0x60).context("post-entry INQUIRY")?;
    if inquiry.get(0x20..0x23) != Some(b"000".as_slice()) {
        bail!(
            "drive did not report the expected post-entry update state \
             (INQUIRY[0x20..0x23] != \"000\", returned {} bytes, revision bytes {:02x?}); aborting before any transfer",
             inquiry.len(), inquiry.get(0x20..0x24).unwrap_or_default()
        );
    }
    Ok(())
}

/// After the commit the OEM host waits ~2 s, then polls event status and
/// TEST UNIT READY using status/sense to continue or stop. Poll until the drive
/// returns ready or the timeout elapses.
fn poll_until_ready(shared: &SharedDevice<'_>) -> Result<()> {
    let start = Instant::now();
    loop {
        match shared.poll_ready_once() {
            Ok(()) => return Ok(()),
            Err(error) => {
                crate::diagnostics::record(format!(
                    "Pioneer post-flash readiness: elapsed_ms={} error={error:#}",
                    start.elapsed().as_millis()
                ));
                if start.elapsed() >= POLL_TIMEOUT {
                    return Err(error)
                        .context("drive did not return ready within the post-flash poll timeout");
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

#[cfg(test)]
#[path = "pioneer_flash_tests.rs"]
mod tests;
