//! Generic Pioneer envelope validation and live receiver-controlled flashing.
//!
//! The engine enforces backup, empty tray and acknowledgement. This backend
//! validates component integrity and compatibility, reads the receiver control
//! descriptor/key, then streams validated components with strict transport errors.

use anyhow::{anyhow, bail, Context, Result};
use pioneer_optical::receiver::Receiver;
use pioneer_optical::Role;
use std::borrow::Cow;

#[cfg(test)]
use super::Identity;
use super::{Capabilities, DriveFamily, Family, FullImage};
use crate::platform::ScsiDevice;

/// Offline reconstruction of Pioneer backup candidates from captured images.
#[path = "pioneer/backup.rs"]
pub mod backup;
/// Read-only validation of extractor-produced Pioneer firmware bundles.
#[path = "pioneer/bundle.rs"]
pub mod bundle;
/// Pioneer vendor fields for `info`.
#[path = "pioneer/device_info.rs"]
pub(crate) mod device_info;
/// Address-oriented Pioneer diagnostic captures.
#[path = "pioneer/dump.rs"]
pub mod dump;
/// `info <file>` for Pioneer bundles and the offline transfer plan.
#[path = "pioneer/file_info.rs"]
pub mod file_info;
/// Live Pioneer OEM flash executor — crate-private so the gate chain in `engine`
/// (--execute/--i-understand-risk, tray guard, backup-first) cannot be bypassed.
#[path = "pioneer/flash.rs"]
pub(crate) mod flash;
/// Pioneer flash planning: family gates and Kernel/Normal transfer plans.
#[path = "pioneer/flash_plan.rs"]
pub mod flash_plan;
/// Embedded OEM kernel label/key table (k.bin), loaded lazily for Pioneer.
#[path = "pioneer/k.rs"]
pub(crate) mod k;
/// Historical OEM control-key test oracles, excluded from production.
#[cfg(test)]
#[path = "pioneer/keys.rs"]
pub(crate) mod keys;
/// Embedded OEM normal seed/signature table (n.bin), loaded lazily for Pioneer.
#[path = "pioneer/n.rs"]
pub(crate) mod n;
/// Pioneer receiver identification and recovery flashing.
#[path = "pioneer/recovery.rs"]
pub(crate) mod recovery;
#[path = "pioneer/transfer.rs"]
pub mod transfer;

// ---- Protocol constants -----------------------------------------------------

// ============================================================================
// Pioneer transfer framing
// ============================================================================

pub(crate) const CONTROL_LEN: usize = 0x100;
/// OEM Normal transfer chunk limit.
pub(crate) const FLASH_CHUNK: usize = 0x8000;
/// Minimum/maximum plausible Pioneer image sizes for the size safety-belt.
pub(crate) const IMAGE_MIN: usize = 0x200; // envelope header
pub(crate) const IMAGE_MAX: usize = 0x00ff_ff00; // aligned 24-bit transfer address limit
/// The ASCII banner magic every genuine Pioneer image starts with
/// (re-exported from `pioneer-optical`; used by tests and banner callers).
#[allow(unused_imports)]
pub(crate) use pioneer_optical::ident::BANNER_MAGIC as PIONEER_MAGIC;

/// The plaintext Pioneer banner and its parser, re-exported from
/// `pioneer-optical` (the crate that owns the firmware-identity format).
pub use pioneer_optical::ident::{parse_banner, Banner as PioneerBanner};

// ---- CDB builders ----------------------------------------------------------

/// OEM update entry CDB.
pub fn cdb_wb_flash_entry() -> [u8; 10] {
    pioneer_optical::cdb::enter_update()
}

/// OEM raw Normal-envelope transfer CDB. `len` excludes any control prefix.
pub fn cdb_wb_flash_chunk(off: u32, len: u32) -> [u8; 10] {
    pioneer_optical::cdb::transfer(Role::Normal, off, len)
}

/// OEM after-transfer CDB; this is not a zero-length commit.
pub fn cdb_wb_flash_finish() -> [u8; 10] {
    pioneer_optical::cdb::finish()
}

fn installed_receiver(backup: Option<&[u8]>) -> Result<Receiver> {
    let backup = backup.context("installed firmware backup is required to recover the receiver control key; refusing update entry")?;
    let (kernel, normal) = classify_flash_input(backup)?;
    let normal = normal.context(
        "installed backup has no Normal component; cannot recover the receiver control key",
    )?;
    let kernel = kernel
        .as_deref()
        .map(pioneer_optical::envelope::Envelope::load)
        .transpose()
        .context("installed Kernel cannot be decoded for receiver control")?;
    let normal = match kernel.as_ref() {
        Some(kernel) => pioneer_optical::envelope::Envelope::load_with_kernel(&normal, kernel),
        None => pioneer_optical::envelope::Envelope::load(&normal),
    }
    .context("installed Normal cannot be decoded for receiver control")?;
    match kernel.as_ref() {
        Some(kernel) => Receiver::detect_with_kernel(&normal, kernel),
        None => Receiver::detect(&normal),
    }
    .context("cannot establish installed receiver entry requirements")
}

/// Validate a Normal envelope without marketing-model or revision restrictions.
pub fn validate_normal_envelope(envelope: &[u8]) -> Result<()> {
    check_normal_size(envelope)?;
    crate::drive::pioneer::flash_plan::validate_bundle(None, Some(envelope))
        .map_err(anyhow::Error::msg)?;
    use pioneer_optical::envelope::signature::{verify_normal_signature, SignatureCheck};
    match verify_normal_signature(envelope) {
        SignatureCheck::ValidKeyAndCiphertext | SignatureCheck::ValidCiphertextOnly => Ok(()),
        SignatureCheck::Invalid => bail!("Normal signature mismatch"),
        _ => bail!("Normal authentication requires a matching Kernel component"),
    }
}

/// Resolve and check the effective pair before any payload decoding.
fn validate_header_chain(
    kernel: Option<&[u8]>,
    normal: &[u8],
    backup: Option<&[u8]>,
    force: bool,
) -> Result<()> {
    use crate::drive::pioneer::flash_plan::validate_component_headers;
    validate_component_headers(kernel, Some(normal)).map_err(anyhow::Error::msg)?;
    if kernel.is_some() {
        return Ok(());
    }
    let captured = backup.map(classify_flash_input).transpose()?;
    let installed_kernel = captured.as_ref().and_then(|(k, _)| k.as_deref());
    match installed_kernel {
        Some(k) => validate_component_headers(Some(k), Some(normal)).map_err(anyhow::Error::msg),
        None if force => Ok(()),
        None => {
            bail!("Normal-only flash needs the installed Kernel; supply a Kernel+Normal package")
        }
    }
}

/// Offline framing with an unresolved control placeholder; live control comes from the drive.
pub fn generic_normal_transcript(envelope: &[u8]) -> Result<Vec<OemTransfer<'_>>> {
    validate_normal_envelope(envelope)?;
    transfer::data_out(&[0; CONTROL_LEN], envelope, None)
}

/// Size sanity for a Normal about to be written: within `IMAGE_MIN..=IMAGE_MAX`
/// and 256-byte aligned (offsets are 24-bit; a bad size would fail mid-session).
fn check_normal_size(envelope: &[u8]) -> Result<()> {
    if !(IMAGE_MIN..=IMAGE_MAX).contains(&envelope.len()) || !envelope.len().is_multiple_of(0x100) {
        bail!("Pioneer envelope length is outside the supported transfer range or not 256-byte aligned");
    }
    Ok(())
}

/// One data-out command in an offline OEM transfer transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStage {
    /// Enter the OEM update mode with a 256-byte control buffer.
    Entry,
    /// Transfer one Kernel FE slice, possibly generated at runtime.
    KernelFe,
    /// Transfer one raw Normal envelope chunk.
    Normal,
    /// Finish the OEM transfer with a 256-byte control buffer.
    Finish,
}

/// A data-out SCSI command and its exact payload, held offline.
#[derive(Debug, Clone)]
pub struct OemTransfer<'a> {
    /// Stage of the observed host sequence.
    pub stage: TransferStage,
    /// Destination offset supplied to the transport API.
    pub offset: u32,
    /// Ten-byte WRITE BUFFER command descriptor block.
    pub cdb: [u8; 10],
    /// Data-out bytes; Normal chunks borrow the original envelope.
    pub data: Cow<'a, [u8]>,
}

/// Validate transfer layout and decoded integrity, independent of model and revision.
fn validate_kernel_normal(kernel: &[u8], normal: &[u8]) -> Result<()> {
    check_normal_size(kernel)?;
    check_normal_size(normal)?;
    crate::drive::pioneer::flash_plan::validate_bundle(Some(kernel), Some(normal))
        .map_err(anyhow::Error::msg)?;
    pioneer_optical::envelope::Update::load(kernel, normal)?;
    Ok(())
}

/// Validate and plan an envelope pair from its contents.
/// Offline-only transcript for dry-run/verification; the live write goes through
/// the imperative executor. Receiver acceptance is a separate, untested question.
pub fn offline_pair_data_out<'a>(
    kernel: &'a [u8],
    normal: &'a [u8],
) -> Result<Vec<OemTransfer<'a>>> {
    validate_kernel_normal(kernel, normal)?;
    let control = [0; CONTROL_LEN]; // Offline placeholder; the live key belongs to the installed receiver.
    let update = pioneer_optical::envelope::Update::load(kernel, normal)?;
    let steps = transfer::data_out(
        &control,
        update.normal_transfer(),
        Some(transfer::select_kernel(kernel)?),
    )?;
    Ok(steps
        .into_iter()
        .map(|step| OemTransfer {
            data: Cow::Owned(step.data.into_owned()),
            ..step
        })
        .collect())
}

// ---- Flash input classification + confirm prompt ---------------------------

/// Writable components resolved from a flash input: `(kernel, normal)`, each
/// present only when the input carries that envelope.
pub(crate) type FlashComponents = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Resolve the flash input into its writable components: `(kernel, normal)`.
/// A bare Normal `.enc` (recognizable Pioneer banner) is a Normal-only input;
/// anything else MUST parse as a strict bundle — a malformed/hostile tar is
/// refused, never silently reinterpreted as a raw envelope.
pub(crate) fn classify_flash_input(input: &[u8]) -> Result<FlashComponents> {
    if parse_banner(input).is_some() {
        return Ok((None, Some(input.to_vec())));
    }
    let bundle = crate::drive::pioneer::bundle::Bundle::from_tar_bytes(input)
        .context("flash input is neither a valid Pioneer bundle nor a Normal .enc")?;
    let find = |role| {
        bundle
            .components
            .iter()
            .find(|c| c.role == role)
            .map(|c| c.bytes.clone())
    };
    Ok((
        find(crate::drive::pioneer::bundle::Role::Kernel),
        find(crate::drive::pioneer::bundle::Role::Main),
    ))
}

/// Which components a flash will write, decided from the classified input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlashSelection {
    /// Write the Normal envelope only (bare `.enc` or a Normal-only bundle).
    NormalOnly,
    /// Write both the Kernel and the Normal (crossflash/downgrade package).
    KernelAndNormal,
}

/// Decide the flash path from the presence of each component. Kernel-only has
/// no validated transcript; neither present is a malformed selection.
pub(crate) fn decide_flash(has_kernel: bool, has_normal: bool) -> Result<FlashSelection> {
    match (has_kernel, has_normal) {
        (true, true) => Ok(FlashSelection::KernelAndNormal),
        (false, true) => Ok(FlashSelection::NormalOnly),
        (true, false) => {
            bail!("kernel-only flash is not yet supported (no validated kernel-only transcript)")
        }
        (false, false) => bail!("flash input has neither a Kernel nor a Normal component to write"),
    }
}

/// One-line human summary of what the flash WILL write and what is MISSING.
/// Revisions come from each envelope header; a missing/unreadable header shows
/// `unknown` rather than failing.
pub(crate) fn flash_summary(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> String {
    fn rev(bytes: &[u8]) -> String {
        pioneer_optical::envelope::header_info(bytes)
            .map(|h| h.revision)
            .filter(|r| !r.is_empty())
            .map(|r| crate::style::printable(&r))
            .unwrap_or_else(|| "unknown".to_string())
    }
    match (kernel, normal) {
        (Some(k), Some(n)) => format!(
            "This will flash: KERNEL (rev {}) + NORMAL (rev {})",
            rev(k),
            rev(n)
        ),
        (None, Some(_)) => "This will flash: NORMAL only — no Kernel in the package".to_string(),
        (Some(_), None) => "This will flash: KERNEL only — no Normal in the package".to_string(),
        (None, None) => "This will flash: (nothing selected)".to_string(),
    }
}

/// Derive installed-firmware routing facts from the pre-flash backup — the OEM
/// package captured off this very drive moments earlier. Returns `None` when the
/// backup is absent or its identity cannot be resolved (callers then treat the
/// flash as plain; the backup + gates still protect the drive).
pub(crate) fn installed_facts(
    backup: Option<&[u8]>,
) -> Option<crate::drive::pioneer::flash_plan::Installed> {
    use crate::drive::pioneer::flash_plan::{FwDate, Installed};
    let (installed_kernel, installed_normal) = classify_flash_input(backup?).ok()?;
    let header = |b: &Option<Vec<u8>>| {
        b.as_deref()
            .and_then(pioneer_optical::envelope::header_info)
    };
    let kinfo = header(&installed_kernel);
    let ninfo = header(&installed_normal);
    // Controller id from the Normal (preferred) or Kernel header.
    let controller_id = ninfo.as_ref().or(kinfo.as_ref()).and_then(|h| {
        crate::drive::pioneer::flash_plan::controller_id_from_sat(&h.hardware_version)
    })?;
    let normal_date = ninfo
        .as_ref()
        .and_then(|h| FwDate::parse(&h.generated_date));
    // Recognize the resident receiver code independently of marker edits.
    let receiver_new_gen = installed_kernel
        .as_deref()
        .and_then(pioneer_optical::envelope::decode_envelope)
        .and_then(|d| crate::drive::pioneer::k::receiver_generation(&d.image));
    // Installed family: profile the decoded installed Normal body (the same
    // decode used for the target, so the two keys are directly comparable).
    let family = installed_normal.as_deref().and_then(|n| {
        crate::drive::pioneer::flash_plan::normal_family_with_kernel(
            n,
            installed_kernel.as_deref()?,
        )
    });
    // Installed Kernel ID tag: use the installed Normal envelope header's
    // declared required-Kernel tag. On a drive that was shipped as a paired
    // Kernel+Normal release this is exactly the drive's live `3C/02/F1`
    // kernel-tag byte-for-byte (OEM Pioneer updaters compare the two). If a
    // live Identity is also available we would prefer it (handles the
    // paired-mismatch edge case), but the backup header is a reliable source.
    let kernel_tag = ninfo
        .as_ref()
        .map(|h| h.kernel_version.trim().to_string())
        .filter(|s| !s.is_empty());
    Some(Installed {
        controller_id,
        receiver_new_gen,
        normal_date,
        family,
        kernel_tag,
    })
}

/// Route the installed firmware against the target ([`crate::drive::pioneer::flash_plan`])
/// and return the plan. The installed facts come from the just-captured pre-flash
/// backup (the planner stays pure; the family keys are computed here, where the
/// backup bytes are in hand). `recover` uses the recover plan (family gate only);
/// `force` ignores the family match. Without installed facts (no backup) the
/// family cannot be proven, so the flash is refused unless `force`.
pub(crate) fn resolve_flash_plan(
    installed_backup: Option<&[u8]>,
    kernel: Option<&[u8]>,
    normal: Option<&[u8]>,
    recover: bool,
    force: bool,
) -> Result<crate::drive::pioneer::flash_plan::FlashPlan> {
    use crate::drive::pioneer::flash_plan::{
        decide_recover_plan, normal_family_with_kernel, target_from_components,
    };

    let installed = installed_facts(installed_backup);
    let captured_kernel = installed_backup
        .and_then(|b| classify_flash_input(b).ok())
        .and_then(|(k, _)| k);
    let receiver_kernel = kernel.or(captured_kernel.as_deref());
    let target_family = normal.and_then(|n| normal_family_with_kernel(n, receiver_kernel?));
    if recover {
        let plan = decide_recover_plan(
            installed.as_ref().and_then(|i| i.family.as_ref()),
            target_family.as_ref(),
            force,
        );
        crate::style::trace(&format!("recover plan = {plan:?}"));
        return Ok(plan);
    }
    let mut target = target_from_components(kernel, normal)
        .context("could not read target bundle identity for flash routing")?;
    target.family = target_family;
    crate::style::trace(&format!(
        "flash routing: installed={installed:?}, target={target:?}"
    ));
    let plan = plan_for(installed.as_ref(), &target, force);
    crate::style::trace(&format!("flash plan = {plan:?}"));
    Ok(plan)
}

/// Pure routing core of [`resolve_flash_plan`]: no installed facts means the
/// installed family is unknown, so the family gate refuses (or `force` overrides).
fn plan_for(
    installed: Option<&crate::drive::pioneer::flash_plan::Installed>,
    target: &crate::drive::pioneer::flash_plan::Target,
    force: bool,
) -> crate::drive::pioneer::flash_plan::FlashPlan {
    use crate::drive::pioneer::flash_plan::{decide_flash_plan, Installed};
    match installed {
        Some(inst) => decide_flash_plan(inst, target, force),
        None => {
            // Nothing known about the installed firmware: only the family gate's
            // "unknown installed" refusal applies, which `force` waives.
            let unknown = Installed {
                controller_id: target.controller_id,
                receiver_new_gen: None,
                normal_date: None,
                family: None,
                kernel_tag: None,
            };
            decide_flash_plan(&unknown, target, force)
        }
    }
}

/// Loud notice that a safety gate was waived (--force): the firmware family
/// and/or the installed Kernel tag could not be verified. A known Kernel-tag
/// mismatch is still refused.
const FORCED_WARNING: &str = "WARNING: a safety gate was bypassed (--force): the firmware family \
    and/or the installed Kernel tag could not be verified. Flashing firmware from a different \
    or unprofiled family, or onto an incompatible Kernel, can permanently brick this drive.";

/// Explain the temporary marker patch and required pristine-Kernel restore.
const DOWNGRADE_WARNING: &str = "WARNING: this flash crosses the firmware generation barrier. \
    The Kernel generation marker is patched temporarily for the first update. A second update \
    restores the unmodified OEM Kernel, and readback must verify it before success is reported. \
    Keep the pre-flash backup and dump until both updates complete.";

/// The post-flash identity readback line. The fields are drive-supplied bytes,
/// so each goes through [`crate::style::printable`].
fn post_flash_line(ident: &pioneer_optical::Identity) -> String {
    use crate::style::printable;
    format!(
        "post-flash: vendor='{}' product='{}' rev='{}' platform='{}' kernel-tag='{}'",
        printable(ident.vendor()),
        printable(ident.product()),
        printable(ident.revision()),
        printable(ident.platform()),
        printable(ident.kernel_tag()),
    )
}

/// Whether the plan (or a `Forced` plan's inner plan) is `KernelDowngrade`.
fn plan_is_downgrade(plan: &crate::drive::pioneer::flash_plan::FlashPlan) -> bool {
    use crate::drive::pioneer::flash_plan::FlashPlan;
    match plan {
        FlashPlan::KernelDowngrade => true,
        FlashPlan::Forced(inner) => plan_is_downgrade(inner),
        _ => false,
    }
}

/// Decide whether the executor may act on a plan. `Refused` aborts before any
/// write. Same-generation and same/newer flashes execute via the ordinary OEM
/// route. The library prepares any temporary marker patch and pristine restore
/// before entry. The bundle executor verifies both passes before reporting
/// success. No plan requires kernel mode
/// ([`crate::drive::pioneer::flash_plan::kernel_mode_required`]).
pub(crate) fn check_plan_executable(
    plan: &crate::drive::pioneer::flash_plan::FlashPlan,
) -> Result<()> {
    use crate::drive::pioneer::flash_plan::FlashPlan;
    match plan {
        FlashPlan::Plain | FlashPlan::KernelCrossflash => Ok(()),
        FlashPlan::Forced(inner) => {
            eprintln!("{}", crate::style::amber(FORCED_WARNING));
            check_plan_executable(inner)
        }
        FlashPlan::KernelDowngrade => {
            eprintln!("{}", crate::style::amber(DOWNGRADE_WARNING));
            Ok(())
        }
        FlashPlan::Refused(reason) => bail!("refusing to flash: {reason}"),
    }
}

/// Print the summary and get explicit consent. On a TTY, require `y`/`yes`;
/// when stdin is not a TTY the `--execute`/`--i-understand-risk` flags already
/// are the consent, so proceed automatically (and say so).
pub(crate) fn confirm_proceed(summary: &str) -> Result<()> {
    use std::io::IsTerminal;
    if crate::output::captured() {
        println!("{}", crate::style::bold(summary));
        return Ok(()); // The GUI already collected explicit confirmation.
    }
    let is_tty = std::io::stdin().is_terminal();
    confirm_with(summary, is_tty, &mut std::io::stdin().lock())
}

/// Testable core of [`confirm_proceed`]: decoupled from the real stdin so the
/// non-TTY auto-proceed and the explicit-yes TTY paths can be exercised offline.
fn confirm_with(summary: &str, is_tty: bool, reader: &mut impl std::io::BufRead) -> Result<()> {
    use std::io::Write;
    println!("{}", crate::style::bold(summary));
    if !is_tty {
        println!(
            "{}",
            crate::style::dim(
                "stdin is not a TTY; proceeding on the --execute / --i-understand-risk consent."
            )
        );
        return Ok(());
    }
    print!("Proceed? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    reader.read_line(&mut line)?;
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => bail!("flash aborted at confirmation prompt"),
    }
}

// ---- The Pioneer DriveFamily impl ------------------------------------------

/// Pioneer OEM protocol backend: identity, byte-exact OEM backup capture, and a
/// gated live OEM write (Normal-only) via [`DriveFamily::flash_bundle`]. The
/// image-chunk `flash_open/chunk/close` methods stay fail-closed and unused —
/// Pioneer's live write goes through `flash_bundle`, not that path.
#[derive(Default)]
pub struct Pioneer;

impl Pioneer {
    /// Create a fresh Pioneer family handle with no cached session state.
    pub const fn new() -> Self {
        Self
    }
}

impl DriveFamily for Pioneer {
    fn backend_name(&self) -> &'static str {
        "pioneer-oem"
    }

    fn probe(
        &self,
        dev: &mut dyn ScsiDevice,
        identity: &super::Identity,
    ) -> Result<Option<super::ProbeEvidence>> {
        let pioneer_model = identity
            .product
            .split_whitespace()
            .last()
            .is_some_and(|model| {
                ["BDR-", "BDC-", "DVR-"]
                    .iter()
                    .any(|prefix| model.starts_with(prefix))
            });
        Ok((identity.vendor.eq_ignore_ascii_case("PIONEER")
            && pioneer_model
            && read_buffer_f1_ok(dev))
        .then_some(super::ProbeEvidence {
            family: Family::Pioneer,
            backend_name: self.backend_name(),
            discriminator: "PIONEER BDR/BDC/DVR INQUIRY + READ BUFFER 02/F1 hardware",
        }))
    }
    fn offline_plan(&self, req: &super::FlashRequest) -> Option<Result<()>> {
        // On --execute the live bundle executor owns the flow (engine gates it);
        // offline_plan only serves the dry run.
        if req.execute {
            return None;
        }
        Some(file_info::plan_offline(
            &req.input,
            req.input_kind,
            &req.drive_model,
            req.allow_crossflash,
            req.verbose,
        ))
    }
    fn flash_is_bundle(&self) -> bool {
        true
    }
    fn verify_preflash_backup(&self, backup: &[u8], input: &[u8]) -> Result<()> {
        // The backup must hold a rollback for EVERY region this flash overwrites.
        // Decide what will be written from the input; if it cannot be classified
        // yet, fall back to the historical rule (a Normal is always written).
        let (writes_kernel, writes_normal) = match classify_flash_input(input) {
            Ok((kernel, normal)) => (kernel.is_some(), normal.is_some()),
            Err(_) => (false, true),
        };
        let roles = crate::drive::pioneer::backup::component_roles(backup);
        let has = |role: &str| roles.iter().any(|(r, _)| r == role);
        for (writes, role, label) in [
            (writes_normal, "main", "Normal"),
            (writes_kernel, "kernel", "Kernel"),
        ] {
            if writes && !has(role) {
                bail!(
                    "pre-flash backup is incomplete: the {label} region (which the flash \
                     overwrites) could not be captured, so it has no rollback. Refusing to flash. \
                     Resolve the read error first (`freemkv-flash dump <device>` saves a raw salvage image, which is NOT a flashable backup), and capture a complete backup before retrying."
                );
            }
        }
        Ok(())
    }
    fn flash_bundle(
        &self,
        dev: &mut dyn ScsiDevice,
        req: &super::FlashRequest,
        installed_backup: Option<&[u8]>,
    ) -> Option<Result<()>> {
        if !req.execute {
            return None;
        }
        Some((|| {
            // Flash whatever components the input carries: a Kernel+Normal
            // package selects its transfer schedule by decoded layout, a Normal-only input
            // (bundle or bare `.enc`) via the OEM Normal path. A Kernel-only
            // input has no validated path and is refused. The 256-byte control
            // buffer comes from the live receiver, then the executor issues the WRITE
            // BUFFER CDBs imperatively — there is no pre-built replayed list.
            let (kernel, normal) = classify_flash_input(&req.input)?;
            let selection = decide_flash(kernel.is_some(), normal.is_some())?;
            let normal = normal
                .as_deref()
                .expect("normal present for both selections");

            check_normal_size(normal)?;

            validate_header_chain(kernel.as_deref(), normal, installed_backup, req.force)?;

            // An image with an unrecoverable envelope tail is never flashed — not
            // even with --force or --recover.
            crate::drive::pioneer::flash_plan::ensure_no_unrecovered_tail(
                kernel.as_deref(),
                Some(normal),
            )?;

            // Routing: the family-match gate (installed vs target Normal family,
            // computed from the just-captured pre-flash backup and the target).
            // `--recover` skips the downgrade/pair refusals but keeps the family
            // gate; `--force` ignores the family match. No path uses kernel mode.
            // Bundle self-consistency gate: refuse malformed bundles (bad
            // headers, SAT mismatch between Kernel/Normal, Kernel ID tag ≠
            // Normal's required-Kernel tag, unrecovered envelope tail) BEFORE
            // any planning or writes. Even `--force` would still be flashing
            // garbage; a broken bundle never has a legitimate path.
            crate::drive::pioneer::flash_plan::validate_bundle(kernel.as_deref(), Some(normal))
                .map_err(|e| anyhow!("{e}"))?;

            let receiver = installed_receiver(installed_backup)?;
            let (prepared, normal_only) = match selection {
                FlashSelection::KernelAndNormal => {
                    let target = pioneer_optical::envelope::Update::load(
                        kernel.as_deref().expect("selected Kernel"),
                        normal,
                    )
                    .map_err(crate::drive::pioneer::flash::preparation_error)?;
                    (
                        Some(if req.force {
                            receiver
                                .prepare_without_family_check(target)
                                .map_err(crate::drive::pioneer::flash::preparation_error)?
                        } else {
                            receiver
                                .prepare(target)
                                .map_err(crate::drive::pioneer::flash::preparation_error)?
                        }),
                        None,
                    )
                }
                FlashSelection::NormalOnly => (
                    None,
                    Some(if req.force {
                        receiver
                            .prepare_normal_without_family_check(normal)
                            .map_err(crate::drive::pioneer::flash::preparation_error)?
                    } else {
                        receiver
                            .prepare_normal(normal)
                            .map_err(crate::drive::pioneer::flash::preparation_error)?
                    }),
                ),
            };
            let plan = resolve_flash_plan(
                installed_backup,
                kernel.as_deref(),
                Some(normal),
                req.recover,
                req.force,
            )?;
            check_plan_executable(&plan)?;
            debug_assert!(!crate::drive::pioneer::flash_plan::kernel_mode_required(
                &plan
            ));

            let will_patch = prepared
                .as_ref()
                .is_some_and(|p| p.restoration_kernel_transfer().is_some());
            if will_patch && !plan_is_downgrade(&plan) {
                eprintln!("{}", crate::style::amber(DOWNGRADE_WARNING));
            }
            // Summarize what will be written and what is missing, then confirm.
            confirm_proceed(&flash_summary(kernel.as_deref(), Some(normal)))?;
            let prepared = match (&prepared, &normal_only) {
                (Some(plan), None) => crate::drive::pioneer::flash::PreparedFlash::Complete(plan),
                (None, Some(plan)) => crate::drive::pioneer::flash::PreparedFlash::Normal(plan),
                _ => unreachable!("one prepared plan selected"),
            };
            crate::drive::pioneer::flash::execute_prepared(dev, prepared, req.recover, req.force)?;
            println!(
                "{}",
                crate::style::green("flash complete; drive returned ready.")
            );
            // Auto post-flash identity readback: the drive just rebooted into
            // whatever it now reports as its live identity. Print it so the user
            // sees exactly what landed without a separate `info` invocation.
            // Non-fatal: a transient post-boot read error is a warning, not a
            // flash failure (the write already committed).
            match crate::drive::transport::identify(dev) {
                Ok(ident) => println!("{}", post_flash_line(&ident)),
                Err(e) => eprintln!(
                    "{}",
                    crate::style::amber(&format!(
                        "post-flash identify failed ({e:#}); the flash itself committed OK"
                    ))
                ),
            }
            Ok(())
        })())
    }
    fn family(&self) -> Family {
        Family::Pioneer
    }
    fn backup_extension(&self) -> Option<&'static str> {
        Some("tar")
    }
    fn backup_kind(&self) -> super::BackupKind {
        // The advisory is decided per-capture in `backup_notice`, not statically:
        // a byte-exact OEM capture gets no warning.
        super::BackupKind {
            infix: "candidate",
            notice: None,
        }
    }
    fn describe_file(&self, image: &[u8]) -> Option<Result<()>> {
        file_info::describe(image)
    }

    fn print_device_info(&self, dev: &mut dyn ScsiDevice) {
        device_info::show(dev);
    }

    fn classify_input(&self, path: &std::path::Path, bytes: &[u8]) -> super::InputKind {
        // A `.tar` that fails to parse still routes to the bundle path, which
        // reports the specific package-parse error.
        if bundle::Bundle::from_tar_bytes(bytes).is_ok()
            || path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"))
        {
            super::InputKind::PioneerBundle
        } else {
            super::InputKind::Bin
        }
    }

    fn force_refusal(&self) -> Option<&'static str> {
        Some("Pioneer recovery requires Current firmware: use recover --current <file> (or --read-from-drive)")
    }

    fn recover(
        &self,
        dev: &mut dyn ScsiDevice,
        current: Option<Vec<u8>>,
        target: &[u8],
        execute: bool,
    ) -> Option<Result<()>> {
        Some((|| {
            recovery::identify_receiver(dev)?;
            let current = match current {
                Some(bytes) => bytes,
                None => self.capture_backup(dev).context(
                    "cannot read Current firmware; supply a Current firmware file instead",
                )?,
            };
            let plan = recovery::Plan::prepare(&current, target)?;
            crate::output::field(
                "Recovery",
                "No automatic backup; compatibility policy bypassed",
            );
            if execute {
                plan.execute(dev)
            } else {
                crate::output::field(
                    "Recovery",
                    "Prepared Kernel + Normal; dry run, no firmware written",
                );
                Ok(())
            }
        })())
    }

    fn backup_notice(&self, bytes: &[u8]) -> super::BackupNotice {
        use super::BackupNotice;
        let components = crate::drive::pioneer::backup::component_roles(bytes);
        let kernel = components.iter().find(|(role, _)| *role == "kernel");
        let normal = components.iter().find(|(role, _)| *role == "main");
        // Partial capture: one region could not be read. Name what was saved and
        // point the user at `dump` for a raw salvage read of the missing region.
        match (kernel, normal) {
            (Some((_, kname)), None) => {
                return BackupNotice::Unverified(format!(
                    "PARTIAL BACKUP: saved the Kernel only (as {kname}). The Normal region could \
                     not be read — `freemkv-flash dump <device>` can save a best-effort raw salvage image (not a flashable backup)."
                ))
            }
            (None, Some((_, nname))) => {
                return BackupNotice::Unverified(format!(
                    "PARTIAL BACKUP: saved the Normal only (as {nname}). The Kernel region could \
                     not be read — `freemkv-flash dump <device>` can save a best-effort raw salvage image (not a flashable backup)."
                ))
            }
            _ => {}
        }
        let p = crate::drive::pioneer::backup::package_provenance(bytes);
        if p.kernel_generation_patched {
            return BackupNotice::Unverified(format!(
                "OEM kernel — generation patched. Captured kernel bytes are preserved. Normal: {}.",
                if p.normal_oem {
                    "OEM recognized"
                } else {
                    "not recognized OEM"
                }
            ));
        }
        match (p.kernel_oem, p.normal_oem) {
            (true, true) => BackupNotice::VerifiedOem(
                "OEM-VERIFIED: kernel and normal are byte-exact OEM originals."
                    .to_string(),
            ),
            (true, false) => BackupNotice::Unverified(
                "PARTIAL OEM: kernel is a byte-exact OEM original; the normal is NOT recognized OEM \
                 (zero seed + zeroed signature sentinel). Physical restore and drive acceptance are untested."
                    .to_string(),
            ),
            (false, true) => BackupNotice::Unverified(
                "PARTIAL OEM: normal is a byte-exact OEM original; the kernel is NOT recognized OEM \
                 (zero placeholders). Physical restore and drive acceptance are untested."
                    .to_string(),
            ),
            (false, false) => BackupNotice::Unverified(
                "UNVERIFIED: neither kernel nor normal is recognized OEM (zero placeholders + zeroed \
                 signature sentinel). Physical restore and drive acceptance are untested."
                    .to_string(),
            ),
        }
    }
    fn capture_backup(&self, dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
        // Dump the live H8/SAT image regions and re-wrap them as byte-exact OEM
        // envelopes where recognized, else zero-sentinel. Read-only: no write.
        crate::drive::pioneer::backup::capture_signed_candidate(dev)
    }
    fn dump_is_raw(&self) -> bool {
        true
    }
    fn capture_dump(&self, dev: &mut dyn ScsiDevice, _force: bool) -> Result<Vec<u8>> {
        crate::drive::pioneer::dump::capture(dev)
    }
    fn validate_backup(&self, bytes: &[u8], target_model: &str) -> Result<Vec<u8>> {
        // Per-component structural/codec/signature checks; accepts 1 or 2
        // components (a partial capture still yields a valid single-component
        // archive).
        crate::drive::pioneer::backup::validate_envelope_package(bytes, target_model)?;
        Ok(bytes.to_vec())
    }
    fn capabilities(&self) -> Capabilities {
        // Identity, OEM backup, and a gated live OEM write (via flash_bundle)
        // are implemented; the image-chunk flash_open/chunk/close stay off.
        Capabilities {
            info: true,
            backup: true,
            // Live write is the Normal-only OEM update session executed by
            // `flash_bundle`; still gated by --execute/--i-understand-risk and a
            // mandatory pre-flash backup in the engine.
            flash: true,
            // A per-component capture: if a region read fails, `dump` can salvage
            // it with a deeper, instability-tolerant read.
            recover: true,
        }
    }
    fn read_full_image(&self, _dev: &mut dyn ScsiDevice) -> Result<FullImage> {
        bail!("Pioneer has no proven restorable firmware read path")
    }
    fn image_size(&self) -> usize {
        // OEM envelope sizes vary; no restorable image size is established.
        0
    }
    fn chunk_size(&self) -> usize {
        FLASH_CHUNK
    }
    fn envelope(
        &self,
        _dev: &mut dyn ScsiDevice,
        image: &[u8],
        _enc_override: Option<bool>,
    ) -> Result<(Vec<u8>, bool)> {
        // Pioneer .fw.bin is already the on-wire image (the drive decrypts /
        // decompresses the body itself). Pass through.
        Ok((image.to_vec(), false))
    }
    fn flash_plan(&self, image_len: usize, verbose: bool) -> Result<String> {
        use std::fmt::Write;
        let mut plan = format!(
            "Pioneer offline transcript: OEM update entry (256 B control), \
             then {} raw-envelope chunks of at most {} B via the OEM Normal transfer, \
             then OEM finish (256 B control) and status polling. \
             This is a dry run: no writes are issued. Add --execute --i-understand-risk to flash (a fresh pre-flash backup is required; drive acceptance is not guaranteed).\n",
            image_len.div_ceil(FLASH_CHUNK),
            FLASH_CHUNK,
        );
        if verbose {
            writeln!(&mut plan, "Pioneer transfer CDBs:")?;
            writeln!(&mut plan, "  entry  {:02X?}", cdb_wb_flash_entry())?;
            for offset in (0..image_len).step_by(FLASH_CHUNK) {
                let len = (image_len - offset).min(FLASH_CHUNK);
                writeln!(
                    &mut plan,
                    "  chunk  {:06X}  {:05X}  {:02X?}",
                    offset,
                    len,
                    cdb_wb_flash_chunk(offset as u32, len as u32)
                )?;
            }
            writeln!(&mut plan, "  finish {:02X?}", cdb_wb_flash_finish())?;
        }
        Ok(plan)
    }
}

#[cfg(test)]
#[path = "pioneer_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pioneer/oem_reference_tests.rs"]
mod oem_reference_tests;
#[cfg(test)]
use oem_reference_tests::*;

#[cfg(test)]
#[path = "pioneer/matrix_tests.rs"]
mod matrix_tests;

fn read_buffer_f1_ok(dev: &mut dyn ScsiDevice) -> bool {
    // This is the firmware receiver's 48-byte identity response, not the
    // unrelated READ BUFFER mode-0/F1 8-byte probe once used here.
    let cdb = pioneer_optical::cdb::vendor_identity();
    matches!(dev.command_in(&cdb, 48), Ok(d)
        if d.len() == 48
            && d[16..24].iter().all(|b| (0x20..=0x7e).contains(b))
            && [b"SAT ".as_slice(), b"ATA ".as_slice(), b"SCSI".as_slice()]
                .iter()
                .any(|prefix| d[16..24].starts_with(prefix)))
}

#[cfg(test)]
#[path = "pioneer/prepared_tests.rs"]
mod prepared_tests;
