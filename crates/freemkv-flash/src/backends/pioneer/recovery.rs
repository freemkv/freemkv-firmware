//! Recovery with user-supplied receiver evidence, no implicit firmware reads.
//! The installed Kernel receives its replacement, then the incoming Kernel
//! receives Normal. Preserve the paired Normal's encoding and OEM signature.
use crate::backend::WriteDevice;
use crate::backends::pioneer::classify_flash_input;
use crate::platform::ScsiDevice;
use crate::transport::{self as transport, flash_err, ScsiTransport, SharedDevice};
use anyhow::{anyhow, bail, ensure, Context, Result};
use pioneer_optical::drive::Segment;
use pioneer_optical::envelope::{Envelope, Update, UpdateError};
use pioneer_optical::receiver::transport as kernel_transport;
use pioneer_optical::{cdb, image::ReceiverControl, Identity, Role};
use std::time::Duration;

pub(crate) struct Plan {
    control: [u8; 256],
    kernel_transfer: Vec<u8>,
    normal_transfer: Vec<u8>,
    /// How the installed loader receives a Kernel, decided from the decoded
    /// Kernel body (same family as the installed drive, enforced by the family
    /// gate), so the write segments match the loader — not a linear stream.
    receive: kernel_transport::KernelReceive,
    /// True when the Normal was re-encoded for the receiving Kernel's receiver
    /// transport rather than written as the target package shipped it.
    reencoded: bool,
}

/// The big-endian 32-bit additive checksum a resident Kernel requires to be zero
/// before it programs a decoded body. Single source of truth in `flash_plan`
/// (empty body and trailing partial word both fail).
#[cfg(test)]
fn be32_sum_zero(body: &[u8]) -> bool {
    crate::backends::pioneer::flash_plan::be32_sum_zero(body)
}

/// Readiness poll after a recover write: this many attempts, 500 ms apart, so
/// the "within N seconds" ceiling in the failure message is half this count.
const READINESS_POLLS: usize = 180;

/// Load the target package to flash, with the Normal-signature guidance, and
/// enforce the boot-time (model, variant) pairing on the written pair.
fn load_target(bytes: &[u8]) -> Result<(Update, Vec<u8>)> {
    let (kernel, normal) = classify_flash_input(bytes)?;
    let kernel = kernel.context("Firmware to flash must include Kernel and Normal")?;
    let normal = normal.context("Firmware to flash must include Kernel and Normal")?;
    let result = Update::load(&kernel, &normal);
    // 0x170..0x1c0 is the Normal envelope's signature field (layout owned by
    // pioneer-optical). An all-zero field on an Authentication failure means the
    // package is unsigned, so give the actionable "use a signed OEM package"
    // guidance instead of the generic decode error.
    if matches!(result, Err(UpdateError::Authentication))
        && normal
            .get(0x170..0x1c0)
            .is_some_and(|signature| signature.iter().all(|b| *b == 0))
    {
        bail!("Firmware to flash has no Normal signature, but its Kernel requires one. Use a signed OEM package for the firmware to flash; an unsigned backup can still be used as Current firmware");
    }
    let update = result.context("cannot decode Firmware to flash")?;
    crate::backends::pioneer::flash_plan::validate_component_headers(Some(&kernel), Some(&normal))
        .map_err(|e| anyhow!("Firmware to flash: {e}"))?;
    // Refuse a target whose envelope tail cannot be reproduced, exactly as the
    // flash path does: the re-encode rebuilds the Normal from the decoded body,
    // so an unrecoverable tail would be silently dropped from the written image.
    crate::backends::pioneer::flash_plan::ensure_no_unrecovered_tail(Some(&kernel), Some(&normal))
        .map_err(|e| anyhow!("Firmware to flash: {e}"))?;
    Ok((update, normal))
}

impl Plan {
    pub(crate) fn prepare(current: &[u8], target: &[u8]) -> Result<Self> {
        let (kernel, normal) = classify_flash_input(current)?;
        let installed_kernel =
            Envelope::load(&kernel.context("Current firmware must include Kernel and Normal")?)
                .context("decoding Current Kernel")?;
        let installed_normal = Envelope::load_with_kernel(
            &normal.context("Current firmware must include Kernel and Normal")?,
            &installed_kernel,
        )
        .context("decoding Current Normal")?;
        ensure!(
            installed_kernel.info().kind == pioneer_optical::ComponentKind::Kernel
                && installed_normal.info().kind == pioneer_optical::ComponentKind::Normal,
            "Current firmware must contain Kernel and Normal components"
        );
        let (target, target_normal) = load_target(target)?;
        Self::assemble(
            &installed_kernel,
            &installed_normal.image,
            target,
            Some(&target_normal),
        )
    }

    #[cfg(test)]
    fn from_updates(current: Update, target: Update) -> Result<Self> {
        Self::assemble(current.kernel(), &current.normal().image, target, None)
    }

    /// True when the Normal was re-encoded for the receiving Kernel.
    pub(crate) fn was_reencoded(&self) -> bool {
        self.reencoded
    }

    fn assemble(
        installed_kernel: &Envelope,
        installed_normal_image: &[u8],
        target: Update,
        target_normal_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let control = control_from_image(installed_normal_image)?;
        // Same hardware family remains mandatory across the Kernel handoff.
        match (
            pioneer_optical::image::family(installed_normal_image),
            target.family(),
        ) {
            (Some(i), Some(t)) => ensure!(
                i == t,
                "recover refused: the installed firmware is family {i} but the target is family \
                 {t} (different hardware family)"
            ),
            (None, None) => {}
            (installed, _) => bail!(
                "recover refused: cannot confirm the target is the installed drive's hardware \
                 family — {} is unrecognized; refusing (fail closed)",
                if installed.is_none() {
                    "the installed firmware"
                } else {
                    "the target"
                }
            ),
        }
        // Kernel programming hands off before Normal is transferred. The target
        // Kernel, not the old installed Kernel, receives this Normal.
        let (normal_transfer, reencoded) = if let Some(bytes) = target_normal_bytes {
            let encoded = super::normal_prepare::prepare(target.kernel(), target.normal(), bytes)?;
            let changed = encoded != bytes;
            let normal = Envelope::load_with_kernel(&encoded, target.kernel())?;
            (
                normal
                    .normal_transfer_image()
                    .context("Normal has no transfer representation")?,
                changed,
            )
        } else {
            (target.normal_transfer().to_vec(), false)
        };
        pioneer_optical::image::check_kernel_handoff(
            &installed_kernel.image,
            &target.kernel().image,
        )
        .map_err(pioneer_optical::receiver::PreparationError::KernelHandoff)
        .map_err(super::flash::preparation_error)?;
        Ok(Self {
            control,
            kernel_transfer: target.kernel_transfer().to_vec(),
            normal_transfer,
            // Detect on the decoded Kernel body (the loader's own code), never
            // the transformed wire bytes, or the fingerprint would be scrambled.
            receive: kernel_transport::detect(&target.kernel().image),
            reencoded,
        })
    }

    pub(crate) fn execute(&self, dev: &mut WriteDevice<'_>) -> Result<()> {
        self.run(dev, &mut |duration| std::thread::sleep(duration))
    }

    fn run(&self, dev: &mut WriteDevice<'_>, sleep: &mut impl FnMut(Duration)) -> Result<()> {
        let identity = identify_receiver(dev)?;
        let class = identity.class().context("unsupported recovery dialect")?;
        crate::diagnostics::record(format!("Recovery receiver: product={} revision={} platform={} kernel_tag={} normal_tag={} code={}", identity.product(), identity.revision(), identity.platform(), identity.kernel_tag(), identity.normal_tag(), identity.code()));
        let updating = in_update_mode(&identity);
        crate::output::field(
            "Recovery mode",
            if updating {
                "Already in update mode; entry skipped"
            } else {
                "Entering update mode"
            },
        );
        if !updating {
            let shared = SharedDevice::new(dev);
            let mut transport = ScsiTransport::flash(&shared);
            pioneer_optical::drive::enter_update(&mut transport, class, &self.control)
                .map_err(flash_err)
                .context("update entry failed; no firmware transferred")?;
            sleep(Duration::from_secs(1));
        }
        // The installed loader decides how a Kernel is received. Most BD 10xx
        // loaders stage it in two regions at distinct wire offsets rather than
        // one linear stream; the shared planner emits the exact segments (same
        // logic the non-recover flash path uses), so flash and recover deliver a
        // Kernel identically.
        let mut storage = [Segment::PLACEHOLDER; 3];
        let plan = kernel_transport::plan(
            Some(self.kernel_transfer.as_slice()),
            self.normal_transfer.as_slice(),
            self.receive,
            &mut storage,
        )
        .map_err(|_| {
            anyhow!(
                "recover refused: the installed Kernel's receive layout is not recognised, so a \
                 safe transfer plan cannot be built; refusing before any write"
            )
        })?;
        // Validate every segment before the first write: an oversized, empty or
        // misaligned span must be refused up front, never discovered only after
        // the Kernel is already written (which would leave the drive half-flashed
        // in update mode). The transfer offset is a 24-bit CDB field, so a length
        // above IMAGE_MAX (0x00ff_ff00) or an offset/length not 256-aligned would
        // truncate the offset mid-session.
        for segment in plan.segments {
            let end = segment.dest_offset as usize + segment.bytes.len();
            ensure!(
                (super::IMAGE_MIN..=super::IMAGE_MAX).contains(&segment.bytes.len())
                    && segment.bytes.len().is_multiple_of(0x100)
                    && (segment.dest_offset as usize).is_multiple_of(0x100)
                    && end <= super::IMAGE_MAX,
                "invalid transfer size"
            );
        }
        let last_kernel = plan.segments.iter().rposition(|s| s.role == Role::Kernel);
        let mut current: Option<Role> = None;
        let mut progress = crate::style::Progress::new("Recovering", 0);
        let mut done = 0usize;
        for (index, segment) in plan.segments.iter().enumerate() {
            if current != Some(segment.role) {
                current = Some(segment.role);
                done = 0;
                let total: usize = plan
                    .segments
                    .iter()
                    .filter(|s| s.role == segment.role)
                    .map(|s| s.bytes.len())
                    .sum();
                progress = crate::style::Progress::new(
                    match segment.role {
                        Role::Kernel => "Recovering Kernel",
                        Role::Normal => "Recovering Normal",
                    },
                    total,
                );
            }
            let role = segment.role;
            for (chunk_index, chunk) in segment.bytes.chunks(super::FLASH_CHUNK).enumerate() {
                let offset = segment.dest_offset + (chunk_index * super::FLASH_CHUNK) as u32;
                let sent = dev.command_out_strict(
                    &cdb::transfer_with_id(segment.buffer_id, offset, chunk.len() as u32),
                    chunk,
                );
                match &sent {
                    Ok(()) => crate::diagnostics::record(format!(
                        "Recovery WRITE BUFFER chunk: role={role:?} offset={offset:#x} length={} result=ok",
                        chunk.len()
                    )),
                    Err(error) => crate::diagnostics::record(format!(
                        "Recovery WRITE BUFFER chunk: role={role:?} offset={offset:#x} length={} result=FAILED sense={:?}: {error:#}",
                        chunk.len(),
                        crate::platform::sense_triplet(error)
                    )),
                }
                sent.with_context(|| format!("{role:?} write failed at {offset:#x}; firmware may be partial; write was not retried"))?;
                done += chunk.len();
                progress.set(done);
            }
            if Some(index) == last_kernel {
                sleep(Duration::from_secs(2));
            }
        }
        dev.command_out_strict(&cdb::finish(), &self.control)
            .context("firmware transferred but finish command failed")?;
        sleep(Duration::from_secs(2));
        // No readback: prove normal operation through identity and readiness.
        // NO MEDIUM is normal for an empty recovered optical drive.
        for attempt in 0..=READINESS_POLLS {
            let _ = dev.command_in(&cdb::get_event_status(), 8);
            let ready = dev.command_in(&cdb::test_unit_ready(), 0);
            if let Err(error) = &ready {
                crate::diagnostics::record(format!("Recovery readiness poll {attempt}: {error:#}"));
            }
            let usable = ready.is_ok()
                || ready
                    .as_ref()
                    .err()
                    .and_then(crate::platform::sense_triplet)
                    .is_some_and(|(key, asc, _)| key == 2 && asc == 0x3a);
            if usable {
                if let Ok(id) = transport::identify(dev) {
                    crate::diagnostics::record(format!("Recovery post-write identity: revision={} kernel_tag={} normal_tag={} code={}", id.revision(), id.kernel_tag(), id.normal_tag(), id.code()));
                    if !id.revision().is_empty()
                        && !id.revision().starts_with("000")
                        && !id.normal_tag().is_empty()
                    {
                        crate::output::field("Recovery", crate::report::Value::text(&format!("Firmware transferred; normal mode reported (revision {}). No firmware readback performed.", id.revision())));
                        return Ok(());
                    }
                }
            }
            if attempt < READINESS_POLLS {
                sleep(Duration::from_millis(500));
            }
        }
        bail!("firmware transferred, but return to normal mode could not be verified within {} seconds; save the diagnostic log", READINESS_POLLS / 2)
    }
}

/// The update-entry control block, built from the installed firmware image: a
/// descriptor and (for a keyed receiver) the entry key. Extracted from supplied
/// code, never from a controller table or a pretend live descriptor.
fn control_from_image(image: &[u8]) -> Result<[u8; 256]> {
    let policy = pioneer_optical::image::receiver_control(image)
        .context("Current firmware has an unsupported receiver entry handler")?;
    let descriptor = image
        .get(..16)
        .context("Current firmware has no descriptor")?;
    ensure!(
        descriptor.starts_with(b"PIONEER "),
        "invalid Current firmware descriptor"
    );
    let mut control = [0; 256];
    control[..16].copy_from_slice(descriptor);
    if let ReceiverControl::Key(key) = policy {
        control[16..20].copy_from_slice(&key);
    }
    Ok(control)
}

/// The refusal for a drive that is not a Pioneer receiver.
pub(crate) const NOT_A_RECEIVER: &str = "Recovery currently supports Pioneer optical drives only; use Flash for supported MediaTek firmware. No firmware written";

/// Check protocol eligibility before firmware reads, even for a dry run.
pub(crate) fn identify_receiver(dev: &mut dyn ScsiDevice) -> Result<Identity> {
    find_receiver(dev)?.context(NOT_A_RECEIVER)
}

/// [`identify_receiver`], with a drive that is not a Pioneer optical drive
/// as `None` (read-only: INQUIRY, then the vendor identity).
pub(crate) fn find_receiver(dev: &mut dyn ScsiDevice) -> Result<Option<Identity>> {
    let inquiry = dev
        .command_in(
            &cdb::inquiry(pioneer_optical::INQUIRY_LEN as u8),
            pioneer_optical::INQUIRY_LEN,
        )
        .context("Recovery could not identify the selected drive; no firmware written")?;
    ensure!(
        inquiry.len() >= pioneer_optical::INQUIRY_LEN,
        "Recovery received a truncated drive identity; no firmware written"
    );
    if inquiry[0] & 0x1f != 5 || &inquiry[8..16] != b"PIONEER " {
        return Ok(None);
    }
    let vendor = dev
        .command_in(&cdb::vendor_identity(), pioneer_optical::IDENTITY_LEN)
        .context("Recovery could not read the Pioneer receiver identity; no firmware written")?;
    let identity = Identity::parse(&inquiry, &vendor)
        .context("Recovery received a truncated Pioneer receiver identity; no firmware written")?;
    ensure!(
        identity.class().is_some(),
        "Recovery does not support this receiver's update dialect; no firmware written"
    );
    Ok(Some(identity))
}

fn in_update_mode(id: &Identity) -> bool {
    id.revision() == "0000" && id.normal_tag().is_empty() && !id.kernel_tag().is_empty()
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
