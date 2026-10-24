//! Generic Pioneer envelope validation and live receiver-controlled flashing.
//!
//! The engine enforces backup, empty tray and acknowledgement. This backend
//! validates component integrity and compatibility, reads the receiver control
//! descriptor/key, then streams validated components with strict transport errors.

use anyhow::{anyhow, bail, Context, Result};
use pioneer_optical::receiver::Receiver;
use pioneer_optical::Role;
use std::borrow::Cow;

use crate::backend::{
    AuthorizedPlan, Backend, BackendId, BackupFacet, BackupFormat, BackupNotice, CdbPattern,
    Confidence, Descriptor, DetailsFacet, DeviceAccess, DumpFacet, FileFacet, FileFormat,
    FlashFacet, FlashPlan, FlashRequest, FormatRole, Identity, InspectFacet, Match, PlanLine,
    ReadDevice, Recognized, RecoveryFacet, RecoveryTarget, SavedBackup, SettingsFacet,
    UpdateOutcome, WriteDevice,
};
#[cfg(test)]
use crate::platform::ScsiDevice;

/// Offline reconstruction of Pioneer backup candidates from captured images.
pub mod backup;
/// Read-only validation of extractor-produced Pioneer firmware bundles.
pub mod bundle;
/// Pioneer's `info` rows and read-only settings.
mod details;
#[cfg(test)]
mod dialect;
/// Address-oriented Pioneer diagnostic captures.
pub mod dump;
/// `info <file>` for Pioneer bundles and the offline transfer plan.
pub mod file_info;
/// Live Pioneer OEM flash executor — crate-private so the gate chain in `engine`
/// (--execute/--i-understand-risk, tray guard, backup-first) cannot be bypassed.
pub(crate) mod flash;
pub mod flash_plan;
/// Pioneer inspect provider for `inspection`: package analysis and live drive state.
pub(crate) mod inspect;
/// Embedded OEM kernel label/key table (k.bin), loaded lazily for Pioneer.
pub(crate) mod k;
/// Historical OEM control-key test oracles, excluded from production.
#[cfg(test)]
pub(crate) mod keys;
/// Embedded OEM normal seed/signature table (n.bin), loaded lazily for Pioneer.
pub(crate) mod n;
mod normal_prepare;
pub(crate) mod recovery;
pub mod transfer;

// ---- Pioneer transfer framing -----------------------------------------------

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

#[cfg(test)]
fn installed_receiver(backup: Option<&[u8]>) -> Result<Receiver> {
    let backup = backup.context("installed firmware backup is required to recover the receiver control key; refusing update entry")
        .map_err(|error| error.context(crate::user_error::IssueCode::BackupRequired))?;
    let (kernel, normal) = classify_flash_input(backup)?;
    receiver_from_components(kernel.as_deref(), normal.as_deref())
}

fn receiver_from_components(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> Result<Receiver> {
    let normal = normal.context(
        "installed backup has no Normal component; cannot recover the receiver control key",
    )?;
    let kernel = kernel
        .map(pioneer_optical::envelope::Envelope::load)
        .transpose()
        .context("installed Kernel cannot be decoded for receiver control")?;
    let normal = match kernel.as_ref() {
        Some(kernel) => pioneer_optical::envelope::Envelope::load_with_kernel(normal, kernel),
        None => pioneer_optical::envelope::Envelope::load(normal),
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
    crate::backends::pioneer::flash_plan::validate_bundle(None, Some(envelope))
        .map_err(anyhow::Error::msg)?;
    use pioneer_optical::envelope::signature::{verify_normal_signature, SignatureCheck};
    match verify_normal_signature(envelope) {
        SignatureCheck::ValidKeyAndCiphertext | SignatureCheck::ValidCiphertextOnly => Ok(()),
        SignatureCheck::Invalid => bail!("Normal signature mismatch"),
        _ => bail!("Normal authentication requires a matching Kernel component"),
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
    crate::backends::pioneer::flash_plan::validate_bundle(Some(kernel), Some(normal))
        .map_err(anyhow::Error::msg)?;
    normal_prepare::load_pair(kernel, normal)?;
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
    let update = normal_prepare::load_pair(kernel, normal)?;
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

// ---- Flash input classification and routing --------------------------------

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
    let bundle = crate::backends::pioneer::bundle::Bundle::from_tar_bytes(input)
        .context("flash input is neither a valid Pioneer bundle nor a Normal .enc")?;
    let find = |role| {
        bundle
            .components
            .iter()
            .find(|c| c.role == role)
            .map(|c| c.bytes.clone())
    };
    Ok((
        find(crate::backends::pioneer::bundle::Role::Kernel),
        find(crate::backends::pioneer::bundle::Role::Main),
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
/// backup is absent or its identity cannot be resolved; callers (`plan_for`)
/// then route an all-unknown installed through the family gate, which REFUSES
/// (fail closed) rather than proceeding, so an unidentifiable installed firmware
/// never flashes.
#[cfg(test)]
pub(crate) fn installed_facts(
    backup: Option<&[u8]>,
) -> Option<crate::backends::pioneer::flash_plan::Installed> {
    let (kernel, normal) = classify_flash_input(backup?).ok()?;
    installed_component_facts(kernel.as_deref(), normal.as_deref())
}

#[cfg(test)]
fn installed_component_facts(
    installed_kernel: Option<&[u8]>,
    installed_normal: Option<&[u8]>,
) -> Option<crate::backends::pioneer::flash_plan::Installed> {
    use crate::backends::pioneer::flash_plan::{FwDate, Installed};
    let kinfo = installed_kernel.and_then(pioneer_optical::envelope::header_info);
    let ninfo = installed_normal.and_then(pioneer_optical::envelope::header_info);
    // Controller id from the Normal (preferred) or Kernel header.
    let controller_id = ninfo.as_ref().or(kinfo.as_ref()).and_then(|h| {
        crate::backends::pioneer::flash_plan::controller_id_from_sat(&h.hardware_version)
    })?;
    let normal_date = ninfo
        .as_ref()
        .and_then(|h| FwDate::parse(&h.generated_date));
    // Recognize the resident receiver code independently of marker edits.
    let receiver_new_gen = installed_kernel
        .and_then(pioneer_optical::envelope::decode_envelope)
        .and_then(|d| crate::backends::pioneer::k::receiver_generation(&d.image));
    // Installed family: profile the decoded installed Normal body (the same
    // decode used for the target, so the two keys are directly comparable).
    let family = installed_normal.and_then(|n| {
        crate::backends::pioneer::flash_plan::normal_family_with_kernel(n, installed_kernel?)
    });
    // The installed Normal header's required-Kernel tag: for a paired release
    // it equals the drive's live `3C/02/F1` kernel tag byte for byte, which is
    // what OEM updaters compare.
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

/// Route the installed firmware against the target ([`crate::backends::pioneer::flash_plan`])
/// and return the plan. The installed facts come from the just-captured pre-flash
/// backup (the planner stays pure; the family keys are computed here, where the
/// backup bytes are in hand). Without installed facts (no usable backup) the
/// family cannot be proven, so the flash is refused.
#[cfg(test)]
pub(crate) fn resolve_flash_plan(
    installed_backup: Option<&[u8]>,
    kernel: Option<&[u8]>,
    normal: Option<&[u8]>,
) -> Result<crate::backends::pioneer::flash_plan::FlashPlan> {
    use crate::backends::pioneer::flash_plan::{normal_family_with_kernel, target_from_components};

    let captured = installed_backup.and_then(|bytes| classify_flash_input(bytes).ok());
    let captured_kernel = captured.as_ref().and_then(|(kernel, _)| kernel.as_deref());
    let captured_normal = captured.as_ref().and_then(|(_, normal)| normal.as_deref());
    let installed = installed_component_facts(captured_kernel, captured_normal);
    let receiver_kernel = kernel.or(captured_kernel);
    let target_family = normal.and_then(|n| normal_family_with_kernel(n, receiver_kernel?));
    let mut target = target_from_components(kernel, normal)
        .context("could not read target bundle identity for flash routing")?;
    target.family = target_family;
    crate::style::trace(&format!(
        "flash routing: installed={installed:?}, target={target:?}"
    ));
    let plan = plan_for(installed.as_ref(), &target);
    crate::style::trace(&format!("flash plan = {plan:?}"));
    Ok(plan)
}

/// Pure routing core: no installed facts means the
/// installed family is unknown, so the family gate refuses.
fn plan_for(
    installed: Option<&crate::backends::pioneer::flash_plan::Installed>,
    target: &crate::backends::pioneer::flash_plan::Target,
) -> crate::backends::pioneer::flash_plan::FlashPlan {
    use crate::backends::pioneer::flash_plan::{decide_flash_plan, Installed};
    match installed {
        Some(inst) => decide_flash_plan(inst, target),
        None => {
            // Nothing known about the installed firmware: only the family gate's
            // "unknown installed" refusal applies.
            let unknown = Installed {
                controller_id: target.controller_id,
                receiver_new_gen: None,
                normal_date: None,
                family: None,
                kernel_tag: None,
            };
            decide_flash_plan(&unknown, target)
        }
    }
}

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

/// Whether the plan is `KernelDowngrade`.
fn plan_is_downgrade(plan: &crate::backends::pioneer::flash_plan::FlashPlan) -> bool {
    matches!(
        plan,
        crate::backends::pioneer::flash_plan::FlashPlan::KernelDowngrade
    )
}

/// The cautions a routed plan carries; `Refused` aborts before any write.
/// Same-generation and newer flashes take the ordinary OEM route. A
/// generation-barrier downgrade is prepared by the library (temporary marker
/// patch, then a verified pristine-Kernel restore). No plan needs kernel mode.
pub(crate) fn routing_warnings(
    plan: &crate::backends::pioneer::flash_plan::FlashPlan,
) -> Result<Vec<String>> {
    use crate::backends::pioneer::flash_plan::FlashPlan as Route;
    match plan {
        Route::Plain | Route::KernelCrossflash => Ok(Vec::new()),
        Route::KernelDowngrade => Ok(vec![DOWNGRADE_WARNING.to_string()]),
        Route::Refused(reason) => bail!("refusing to flash: {reason}"),
    }
}

/// The components an execute plan resolved from the input; the installed
/// firmware is not needed to build it.
pub(crate) struct ExecutePlan {
    kernel: Option<Vec<u8>>,
    normal: Vec<u8>,
    selection: FlashSelection,
}

/// The pre-backup checks of a live flash: component selection, transfer size,
/// header chain, envelope tail and bundle self-consistency.
pub(crate) fn execute_plan(input: &[u8]) -> Result<ExecutePlan> {
    use crate::backends::pioneer::flash_plan::{
        ensure_no_unrecovered_tail, validate_component_headers,
    };
    let (kernel, normal) = classify_flash_input(input)?;
    let selection = decide_flash(kernel.is_some(), normal.is_some())?;
    let normal = normal.expect("normal present for both selections");
    check_normal_size(&normal)?;
    validate_component_headers(kernel.as_deref(), Some(&normal)).map_err(anyhow::Error::msg)?;
    ensure_no_unrecovered_tail(kernel.as_deref(), Some(&normal))?;
    Ok(ExecutePlan {
        kernel,
        normal,
        selection,
    })
}

/// The whole `flash` decision with no device: `installed` (a Kernel+Normal
/// package) stands in for the drive's pre-flash backup. Runs the same plan,
/// backup-coverage and authorize gates `flash` runs before any write.
pub(crate) fn decide_offline(installed: &[u8], target: &[u8]) -> Result<()> {
    let plan = execute_plan(target)?;
    verify_coverage(installed, plan.kernel.is_some(), true)?;
    authorize_installed(FlashPlan::new(plan), Some(installed)).map(|_| ())
}

/// The routing facts the offline crossflash pre-filter compares: the family
/// the family gate compares, the controller id (SAT), and whether the package
/// is Normal-only.
pub(crate) fn offline_prefilter(bytes: &[u8]) -> crate::crossflash::Prefilter {
    use crate::backends::pioneer::flash_plan::{controller_id_from_sat, normal_family_with_kernel};
    let (kernel, normal) = classify_flash_input(bytes).unwrap_or((None, None));
    let header = normal
        .as_deref()
        .or(kernel.as_deref())
        .and_then(pioneer_optical::envelope::header_info);
    crate::crossflash::Prefilter {
        platform: crate::crossflash::Platform::Pioneer,
        family: normal
            .as_deref()
            .zip(kernel.as_deref())
            .and_then(|(n, k)| normal_family_with_kernel(n, k))
            .map(|f| f.to_string()),
        model: header
            .and_then(|h| controller_id_from_sat(&h.hardware_version))
            .map(|id| format!("{id:04X}")),
        normal_only: kernel.is_none() && normal.is_some(),
    }
}

/// The library plan the receiver accepted.
struct Prepared {
    complete: Option<pioneer_optical::receiver::PreparedUpdate>,
    normal: Option<pioneer_optical::receiver::PreparedNormal>,
}

/// The installed-firmware gates: the Kernel a Normal-only flash pairs with,
/// the receiver's entry requirements, preparation of the transfer, and the
/// family/generation routing. `installed` is the saved pre-flash backup.
pub(crate) fn authorize_installed(
    plan: FlashPlan,
    installed: Option<&[u8]>,
) -> Result<AuthorizedPlan> {
    use crate::backends::pioneer::flash::preparation_error;
    let p: &ExecutePlan = plan.state()?;
    let (kernel, normal) = (p.kernel.as_deref(), p.normal.as_slice());
    let (installed_kernel, installed_normal) = classify_flash_input(installed.context(
        "installed firmware backup is required to recover the receiver control key; refusing update entry"
    ).map_err(|error| error.context(crate::user_error::IssueCode::BackupRequired))?)?;
    let receiver =
        receiver_from_components(installed_kernel.as_deref(), installed_normal.as_deref())?;
    if kernel.is_none() {
        flash_plan::validate_component_headers(installed_kernel.as_deref(), Some(normal))
            .map_err(anyhow::Error::msg)
            .context(crate::user_error::IssueCode::InstalledFirmwareMismatch)?;
    }
    let (prepared, target_facts, receiver_check) = match p.selection {
        FlashSelection::KernelAndNormal => {
            let target = normal_prepare::pair(kernel.expect("selected Kernel"), normal)?;
            let facts = flash_plan::target_from_loaded(
                Some(target.kernel()),
                target.normal(),
                kernel,
                normal,
            )?;
            let check = if installed_kernel.as_deref() == kernel {
                // Preserve the existing identical-envelope fast path. The
                // library still validates the complete pair and live plan.
                Ok(())
            } else {
                flash_plan::check_loaded_receiver(&target)
            };
            let prepared = receiver
                .prepare(target)
                .map(|complete| (Some(complete), None));
            (prepared, facts, check)
        }
        FlashSelection::NormalOnly => {
            let k = receiver
                .installed_kernel()
                .context("installed Kernel is required")?;
            let source = pioneer_optical::envelope::Envelope::load_with_kernel(normal, k)?;
            let facts = flash_plan::target_from_loaded(None, &source, None, normal)?;
            let bytes = normal_prepare::prepare(k, &source, normal)?;
            let prepared = receiver
                .prepare_normal(&bytes)
                .map(|normal| (None, Some(normal)));
            (prepared, facts, Ok(()))
        }
    };
    // A known handoff mismatch is a candidate for future adaptation, but all
    // other gates must also pass before advertising it as such. No Prepared
    // write grant is produced for that candidate.
    if let Err(error) = &prepared {
        if crate::crossflash::refusal_status(error)
            != crate::crossflash::CompatibilityStatus::SoftNo
        {
            let source = preparation_error(error.clone());
            if matches!(
                error,
                pioneer_optical::receiver::PreparationError::Compatibility(
                    pioneer_optical::receiver::Error::FamilyMismatch { .. }
                )
            ) {
                let installed_model = installed_normal
                    .as_deref()
                    .and_then(pioneer_optical::envelope::header_info)
                    .map(|header| header.model)
                    .unwrap_or_default();
                let target_model = pioneer_optical::envelope::header_info(normal)
                    .map(|header| header.model)
                    .unwrap_or_default();
                return Err(crate::backend::HardwareMismatch {
                    installed_model,
                    target_model,
                    source,
                }
                .into());
            }
            return Err(source);
        }
    }
    // The paired Normal is received by its incoming Kernel. Reuse the loaded
    // Update proof; Normal-only preparation validates the installed receiver.
    // Keep preparation errors ahead of the routing/receiver presentation.
    receiver_check.map_err(|reason| anyhow!("refusing to flash: {reason}"))?;
    let installed_facts = flash_plan::installed_from_loaded(
        &receiver,
        installed_normal
            .as_deref()
            .context("installed Normal is required")?,
    );
    let route = plan_for(installed_facts.as_ref(), &target_facts);
    let mut warnings = routing_warnings(&route)?;
    let (complete, prepared_normal) = prepared.map_err(preparation_error)?;
    let prepared = Prepared {
        complete,
        normal: prepared_normal,
    };
    debug_assert!(!crate::backends::pioneer::flash_plan::kernel_mode_required(
        &route
    ));
    let will_patch = prepared
        .complete
        .as_ref()
        .is_some_and(|p| p.restoration_kernel_transfer().is_some());
    if will_patch && !plan_is_downgrade(&route) {
        warnings.push(DOWNGRADE_WARNING.to_string());
    }
    let confirmation = flash_summary(kernel, Some(normal));
    let mut authorized = AuthorizedPlan::new(plan, prepared);
    authorized.warnings = warnings;
    authorized.confirmation = Some(confirmation);
    Ok(authorized)
}

/// Whether `backup` holds a rollback for every region the flash overwrites.
fn verify_coverage(backup: &[u8], writes_kernel: bool, writes_normal: bool) -> Result<()> {
    let roles = crate::backends::pioneer::backup::component_roles(backup);
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

/// Backup coverage decided from the raw input: an input that cannot be
/// classified yet is assumed to write a Normal.
#[cfg(test)]
pub(crate) fn verify_preflash_backup(backup: &[u8], input: &[u8]) -> Result<()> {
    let (writes_kernel, writes_normal) = match classify_flash_input(input) {
        Ok((kernel, normal)) => (kernel.is_some(), normal.is_some()),
        Err(_) => (false, true),
    };
    verify_coverage(backup, writes_kernel, writes_normal)
}

// ---- The Pioneer backend ---------------------------------------------------

/// Pioneer OEM protocol backend: identity, byte-exact OEM backup capture, a
/// raw dump, Recovery, inspection, and a gated live OEM package update.
#[derive(Default)]
pub struct Pioneer;

/// Raw capture for Pioneer identities without an OEM backup/update backend.
pub(crate) struct DumpOnly;

static DUMP_DESCRIPTOR: Descriptor = Descriptor {
    id: BackendId("pioneer-dump"),
    display_name: "Pioneer",
    flash_summary: None,
    formats: &[],
};

impl Backend for DumpOnly {
    fn descriptor(&self) -> &'static Descriptor {
        &DUMP_DESCRIPTOR
    }

    fn probe(&self, dev: &mut ReadDevice<'_>, _identity: &Identity) -> Result<Option<Match>> {
        crate::backend::registry::probe_backend(dev, DUMP_DESCRIPTOR.id)
    }

    fn dump(&self) -> Option<&dyn DumpFacet> {
        Some(&Pioneer)
    }
}

impl Pioneer {
    /// Create a fresh Pioneer family handle with no cached session state.
    pub const fn new() -> Self {
        Self
    }
}

/// An extractor-produced Pioneer package (tar of Kernel and/or Normal).
pub const PACKAGE: FileFormat = FileFormat {
    id: "pioneer-package",
    label: "Pioneer firmware bundle",
    extensions: &["firmware.tar", "installer.tar", "tar"],
    update_input: true,
    role: FormatRole::Package,
};

/// A bare Pioneer Normal envelope (`.enc`).
pub const ENVELOPE: FileFormat = FileFormat {
    id: "pioneer-envelope",
    label: "Pioneer firmware envelope",
    extensions: &["enc", "bin"],
    update_input: false,
    role: FormatRole::Image,
};

/// What the Pioneer backend declares.
pub static DESCRIPTOR: Descriptor = Descriptor {
    id: BackendId("pioneer-oem"),
    display_name: "Pioneer",
    flash_summary: None,
    formats: &[PACKAGE, ENVELOPE],
};

impl Backend for Pioneer {
    fn can_read(&self) -> bool {
        pioneer_optical::DriveClass::Bd.can_read()
    }

    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    fn probe(&self, dev: &mut ReadDevice<'_>, _identity: &Identity) -> Result<Option<Match>> {
        crate::backend::registry::probe_backend(dev, DESCRIPTOR.id)
    }

    fn allowed_data_out(&self) -> &'static [CdbPattern] {
        READ_UNLOCK
    }

    fn files(&self) -> Option<&dyn FileFacet> {
        Some(self)
    }
    fn details(&self) -> Option<&dyn DetailsFacet> {
        Some(self)
    }
    fn backup(&self) -> Option<&dyn BackupFacet> {
        Some(self)
    }
    fn dump(&self) -> Option<&dyn DumpFacet> {
        Some(self)
    }
    fn flash(&self) -> Option<&dyn FlashFacet> {
        Some(self)
    }
    fn recovery(&self) -> Option<&dyn RecoveryFacet> {
        Some(self)
    }
    fn inspect(&self) -> Option<&dyn InspectFacet> {
        Some(self)
    }
    fn settings(&self) -> Option<&dyn SettingsFacet> {
        Some(self)
    }
}

/// The memory-read unlock (no data phase), the one data-out a Pioneer read
/// sends.
static READ_UNLOCK: &[CdbPattern] = &[CdbPattern {
    label: "read-unlock knock",
    matches: knock,
}];

/// What a dump may send: the read unlock and the RAM-only logging switch.
static DUMP_WRITES: &[CdbPattern] = &[
    CdbPattern {
        label: "read-unlock knock",
        matches: knock,
    },
    CdbPattern {
        label: "RAM logging switch",
        matches: ram_logging_switch,
    },
];

fn knock(cdb: &[u8], data: &[u8]) -> bool {
    cdb == pioneer_optical::cdb::knock() && data.is_empty()
}

/// `pioneer_optical::logging`'s private RAM-only set command; its persistent
/// twin (`0x10`) writes nonvolatile settings with the same CDB.
const LOGGING_SET_RAM: u8 = 0x12;

/// `logging::discover` reads the group per drive from a dispatch-table entry
/// and only accepts entries whose group byte is at least `0x80` (UD04: `0x93`).
const LOGGING_GROUPS: std::ops::RangeInclusive<u8> = 0x80..=0xff;

/// `logging::LoggingLayout::bit`, the CDB arrival bit. The dump only enables
/// logging, so the mask it sends (the drive's mask OR this bit) always has it.
const LOGGING_ARRIVAL_BIT: u32 = 0x0004_0000;

/// The diagnostic control envelope with the RAM-only logging command: a
/// dispatcher `group`, `LOGGING_SET_RAM`, mask-supplied flag `1`, the 4-byte
/// mask with the arrival bit set, zero padding.
fn ram_logging_switch(cdb: &[u8], data: &[u8]) -> bool {
    cdb == pioneer_optical::cdb::write_diagnostic_control()
        && data.len() == pioneer_optical::cdb::DIAGNOSTIC_CONTROL_LEN as usize
        && LOGGING_GROUPS.contains(&data[0])
        && data[1] == LOGGING_SET_RAM
        && data[2] == 1
        && u32::from_be_bytes([data[3], data[4], data[5], data[6]]) & LOGGING_ARRIVAL_BIT != 0
        && data[7..].iter().all(|&b| b == 0)
}

impl FileFacet for Pioneer {
    fn family_evidence(&self, bytes: &[u8]) -> Option<(String, String)> {
        let (kernel, normal) = classify_flash_input(bytes).ok()?;
        let kernel = kernel
            .as_deref()
            .map(pioneer_optical::envelope::Envelope::load)
            .transpose()
            .ok()?;
        let normal_bytes = normal.as_deref()?;
        let normal = match kernel {
            Some(ref kernel) => {
                pioneer_optical::envelope::Envelope::load_with_kernel(normal_bytes, kernel)
            }
            None => pioneer_optical::envelope::Envelope::load(normal_bytes),
        }
        .ok()?;
        Some((normal.family()?.to_string(), normal.info().model.clone()))
    }
    /// A parsed package or envelope header establishes the protocol. A TAR
    /// header alone is shared with MediaTek and cannot identify Pioneer.
    fn recognize(&self, bytes: &[u8]) -> Option<Recognized> {
        let structural = |format| {
            Some(Recognized {
                format,
                confidence: Confidence::Structural,
            })
        };
        if bundle::Bundle::from_tar_bytes(bytes).is_ok()
            || bundle::Bundle::from_backup_tar_bytes(bytes).is_ok()
        {
            return structural(&PACKAGE);
        }
        if parse_banner(bytes).is_some() || pioneer_optical::envelope::header_info(bytes).is_some()
        {
            return structural(&ENVELOPE);
        }
        None
    }

    fn describe(&self, image: &[u8], _recognized: &Recognized) -> Option<Result<()>> {
        file_info::describe(image)
    }

    fn classify_input(&self, path: &std::path::Path, bytes: &[u8]) -> &'static FileFormat {
        // A `.tar` that fails to parse still routes to the bundle path, which
        // reports the specific package-parse error.
        if bundle::Bundle::from_tar_bytes(bytes).is_ok()
            || path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"))
        {
            &PACKAGE
        } else {
            &ENVELOPE
        }
    }

    fn claims_by_name(&self, path: &std::path::Path) -> Option<&'static FileFormat> {
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        (name.ends_with(".firmware.tar") || name.ends_with(".installer.tar")).then_some(&PACKAGE)
    }
}

impl BackupFacet for Pioneer {
    fn format(&self) -> BackupFormat {
        // The advisory is decided per capture in `notice`: a byte-exact OEM
        // capture gets no warning.
        BackupFormat {
            extension: "tar",
            infix: "candidate",
        }
    }

    fn capture(&self, dev: &mut ReadDevice<'_>) -> Result<Vec<u8>> {
        // Dump the live H8/SAT image regions and re-wrap them as byte-exact OEM
        // envelopes where recognized, else zero-sentinel. Read-only: no write.
        crate::backends::pioneer::backup::capture_signed_candidate(dev)
    }

    fn notice(&self, bytes: &[u8]) -> BackupNotice {
        let components = crate::backends::pioneer::backup::component_roles(bytes);
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
        let p = crate::backends::pioneer::backup::package_provenance(bytes);
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
                "OEM likely: Kernel and Normal match known OEM references."
                    .to_string(),
            ),
            (true, false) => BackupNotice::Unverified(
                "User provided: firmware captured from this drive; Kernel matches a known OEM reference. \
                 Normal update metadata was reconstructed."
                    .to_string(),
            ),
            (false, true) => BackupNotice::Unverified(
                "User provided: firmware captured from this drive; Normal matches a known OEM reference. \
                 Kernel update metadata was reconstructed."
                    .to_string(),
            ),
            (false, false) => BackupNotice::Unverified(
                "User provided: firmware captured from this drive; update metadata was reconstructed. \
                 Not identified as an original OEM release."
                    .to_string(),
            ),
        }
    }

    fn validate(&self, bytes: &[u8], target_model: &str) -> Result<Vec<u8>> {
        // Per-component structural/codec/signature checks; accepts 1 or 2
        // components (a partial capture still yields a valid single-component
        // archive).
        crate::backends::pioneer::backup::validate_envelope_package(bytes, target_model)?;
        Ok(bytes.to_vec())
    }
}

impl DumpFacet for Pioneer {
    // A per-component capture: if a region read fails, `dump` can salvage it
    // with a deeper, instability-tolerant read.
    fn deep_salvage(&self) -> bool {
        true
    }

    fn writes(&self) -> &'static [CdbPattern] {
        DUMP_WRITES
    }

    fn capture(&self, dev: DeviceAccess<'_, '_>) -> Result<Vec<u8>> {
        crate::backends::pioneer::dump::capture(dev)
    }
}

impl FlashFacet for Pioneer {
    fn plan(&self, _dev: &mut ReadDevice<'_>, req: &FlashRequest) -> Result<FlashPlan> {
        if !req.execute {
            let mut plan = FlashPlan::new(());
            plan.dry_run = file_info::plan_offline(
                &req.input,
                req.input_format,
                &req.drive_model,
                req.verbose,
            )?;
            return Ok(plan);
        }
        let mut plan = FlashPlan::new(execute_plan(&req.input)?);
        plan.after_backup = vec![PlanLine::Backup];
        Ok(plan)
    }

    /// The dry run plans from the file alone: no device I/O.
    fn dry_run_uses_device(&self) -> bool {
        false
    }

    fn verify_backup(&self, plan: &FlashPlan, backup: &[u8]) -> Result<()> {
        let p: &ExecutePlan = plan.state()?;
        verify_coverage(backup, p.kernel.is_some(), true)
    }

    fn authorize(
        &self,
        _dev: &mut ReadDevice<'_>,
        plan: FlashPlan,
        backup: Option<&SavedBackup>,
    ) -> Result<AuthorizedPlan> {
        authorize_installed(plan, backup.map(|b| b.bytes()))
    }

    fn execute(&self, dev: &mut WriteDevice<'_>, plan: &AuthorizedPlan) -> Result<UpdateOutcome> {
        use crate::backends::pioneer::flash::{execute_prepared, PreparedFlash};
        let prepared: &Prepared = plan.state()?;
        let selected = match (&prepared.complete, &prepared.normal) {
            (Some(plan), None) => PreparedFlash::Complete(plan),
            (None, Some(plan)) => PreparedFlash::Normal(plan),
            _ => unreachable!("one prepared plan selected"),
        };
        execute_prepared(
            dev,
            selected,
            pioneer_optical::receiver::ExecutionMode::Flash,
        )
    }
}

impl RecoveryFacet for Pioneer {
    fn accepts_current_for_identification(&self) -> bool {
        true
    }

    fn identify(&self, dev: &mut ReadDevice<'_>) -> Result<Option<RecoveryTarget>> {
        self.identify_with_current(dev, None)
    }

    fn identify_with_current(
        &self,
        dev: &mut ReadDevice<'_>,
        current: Option<&[u8]>,
    ) -> Result<Option<RecoveryTarget>> {
        let current = current
            .map(recovery::Current::load)
            .transpose()
            .context("cannot establish Current receiver evidence; no firmware written")?;
        Ok(
            recovery::find_receiver_with_current(dev, current.as_ref())?.map(|id| {
                let label = format!(
                    "{} {}",
                    crate::style::printable(id.product()),
                    crate::style::printable(id.revision())
                );
                RecoveryTarget::new(label, current)
            }),
        )
    }

    fn unidentified(&self) -> &'static str {
        recovery::NOT_A_RECEIVER
    }

    fn supports_family_override(&self) -> bool {
        true
    }

    fn prepare(
        &self,
        dev: &mut ReadDevice<'_>,
        receiver: &RecoveryTarget,
        current: Option<&[u8]>,
        target: &[u8],
        bypass_family_check: bool,
    ) -> Result<Box<dyn crate::backend::PreparedRecoveryUpdate>> {
        let evidence = receiver
            .state::<Option<recovery::Current>>()
            .map_err(|error| {
                crate::backend::UpdateFailure::before_write("recovery preparation", error)
            })?;
        crate::output::publish(crate::output::Event::Phase {
            phase: "preparing",
            component: "filter.firmware",
            done: None,
            total: None,
        });
        let target = recovery::Target::load(target).map_err(|error| {
            crate::backend::UpdateFailure::before_write("recovery preparation", error)
        })?;
        let captured;
        let evidence = match evidence {
            Some(evidence) => evidence,
            None => {
                // Validate the captured pair here: a Kernel-only partial backup
                // is a capture failure, not an invalid target firmware file.
                captured = match current {
                    Some(bytes) => recovery::Current::load(bytes),
                    None => recovery::captured_current(
                        crate::backends::pioneer::backup::capture_signed_candidate(dev),
                    ),
                }
                .map_err(|error| {
                    crate::backend::UpdateFailure::before_write("current firmware capture", error)
                })?;
                &captured
            }
        };
        crate::output::publish(crate::output::Event::Phase {
            phase: "preparing",
            component: "filter.firmware",
            done: None,
            total: None,
        });
        let plan = target
            .bind(evidence, bypass_family_check)
            .map_err(|error| {
                crate::backend::UpdateFailure::before_write("recovery preparation", error)
            })?;
        crate::output::field(
            "Recovery",
            if bypass_family_check {
                "recovery.override_family"
            } else {
                "recovery.family_retained"
            },
        );
        if plan.was_reencoded() {
            crate::output::field(
                "Recovery",
                "Normal transfer encoding or local signature prepared for the receiving Kernel \
                 (experimental, offline-proven, hardware-unproven)",
            );
        }
        if plan.requires_restoration() {
            crate::output::field(
                "Recovery plan",
                "Two passes: temporary accepted Kernel, then verified restoration of the original OEM Kernel",
            );
        }
        Ok(Box::new(plan))
    }

    fn recover(
        &self,
        dev: DeviceAccess<'_, '_>,
        receiver: &RecoveryTarget,
        current: Option<&[u8]>,
        target: &[u8],
    ) -> Result<UpdateOutcome> {
        self.recover_with_family_override(dev, receiver, current, target, false)
    }

    fn recover_with_family_override(
        &self,
        mut dev: DeviceAccess<'_, '_>,
        receiver: &RecoveryTarget,
        current: Option<&[u8]>,
        target: &[u8],
        bypass_family_check: bool,
    ) -> Result<UpdateOutcome> {
        let plan = self.prepare(
            &mut ReadDevice::for_backend(dev.scsi(), self),
            receiver,
            current,
            target,
            bypass_family_check,
        )?;
        match dev.writer() {
            Some(writer) => plan.execute(writer),
            None => {
                crate::output::field(
                    "Recovery",
                    "Prepared Kernel + Normal; dry run, no firmware written",
                );
                Ok(UpdateOutcome::Planned)
            }
        }
    }
}

impl InspectFacet for Pioneer {
    fn inspect(
        &self,
        source: String,
        bytes: &[u8],
        control: &crate::inspection::Control,
    ) -> Option<Result<crate::inspection::Inspection>> {
        inspect::inspect_file(source, bytes, control)
    }

    fn live_state(&self, dev: &mut ReadDevice<'_>) -> crate::inspection::LiveState {
        inspect::live_state(dev)
    }
}

#[cfg(test)]
#[path = "pioneer_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "oem_reference_tests.rs"]
mod oem_reference_tests;
#[cfg(test)]
use oem_reference_tests::*;

#[cfg(test)]
#[path = "matrix_tests.rs"]
mod matrix_tests;

#[cfg(test)]
#[path = "receiver_gate_tests.rs"]
mod receiver_gate_tests;

#[cfg(test)]
#[path = "prepared_tests.rs"]
mod prepared_tests;

#[cfg(test)]
pub(crate) fn test_oem_recovery_package(vendor: &str) -> Vec<u8> {
    recovery::tests::oem_recovery_package(vendor)
}
