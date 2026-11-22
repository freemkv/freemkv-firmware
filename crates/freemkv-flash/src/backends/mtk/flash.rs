//! MediaTek lifecycle adapter: app backup/consent policy surrounds optical
//! receiver plans. Every packaged stage is prepared before writing; the optical
//! crate revalidates each receiver, executes its wire plan and confirms the
//! exact requested target. Verification quality remains part of the result.

use anyhow::{anyhow, bail, Context, Result};

impl From<mediatek_optical::IssueKind> for crate::user_error::IssueCode {
    fn from(kind: mediatek_optical::IssueKind) -> Self {
        use mediatek_optical::IssueKind;
        match kind {
            IssueKind::InvalidFirmware => Self::FirmwareInvalid,
            IssueKind::UnsupportedFirmware => Self::UnsupportedFirmware,
            IssueKind::ReceiverMismatch => Self::CurrentMismatch,
            IssueKind::HardwareMismatch => Self::IncompatibleFirmware,
            IssueKind::Connection => Self::Connection,
            IssueKind::Verification | IssueKind::Update => Self::UpdateUncertain,
            IssueKind::Unexpected => Self::Unexpected,
        }
    }
}
use mediatek_optical::classify::{self, InstalledFirmware, Refusal};
use mediatek_optical::drive::Error as DriveError;
use mediatek_optical::drive::{
    ExecutionRuntime, FlashTransport, ForcedError, ForcedUpdate, ProbeError, Stage, Status,
};
use mediatek_optical::prepare::{TransferEncoding, ValidatedUpdate};
use mediatek_optical::Identity;

use super::crossflash::{Build, Verdict};
use super::{
    backup, cdb, crossflash, describe_sequence, ensure_flashable_boot_page, live_identity_checked,
    Mtk, DESCRIPTOR, IMAGE_SIZE, ROM_003000_LEN, ROM_003000_OFFSET,
};
use crate::backend::{
    AuthorizedPlan, FlashFacet, FlashPlan, FlashRequest, FormatRole, PlanLine, ReadDevice,
    SavedBackup, UpdateEvidence, UpdateFailure, UpdateOutcome, WriteDevice,
};
use crate::platform::ScsiDevice;
use crate::style;
use crate::transport::{ScsiTransport, SharedDevice};

/// What `plan` decided, for `authorize`/`execute`.
struct Plan {
    image: Vec<u8>,
    live: Identity,
    drive_product: String,
    verdict: Verdict,
    mode: PlanMode,
}

/// How this flash determines the wire encoding and reaches the drive.
// The reference variant carries a whole receiver and prepared plan; the probe
// variant is lightweight. A flash holds exactly one plan, so the size gap is
// not worth a heap indirection.
#[allow(clippy::large_enum_variant)]
enum PlanMode {
    /// `--current` supplied: the proven receiver-reference flow derives the wire
    /// encoding from the installed-firmware reference and binds a prepared plan.
    Reference {
        receiver: mediatek_optical::prepare::Receiver,
        /// The final image of a two-stage package, flashed after `image`.
        following: Vec<Executable>,
    },
    /// Default (current-free): a safe pre-erase probe discovers the wire
    /// encoding in the write phase, then a forced-encoding flash runs with no
    /// installed-firmware reference and no backup.
    Probe {
        /// The final image of a two-stage package, flashed after `image`.
        final_image: Option<Vec<u8>>,
    },
}

/// What `authorize` decided, for `execute`.
// One authorization is held per flash; the reference variant's prepared plan is
// not worth boxing for the size gap with the unit probe variant.
#[allow(clippy::large_enum_variant)]
pub(super) enum Authorized {
    /// A receiver-bound prepared first stage (`--current` path).
    Reference(Executable),
    /// The current-free probe path: all the state `execute` needs lives in the
    /// [`Plan`], which probes and forces the encoding at write time.
    Probe,
}

/// The reference-path prepared stage, carried from `authorize` into `execute`.
pub(super) struct Prepared {
    pub(super) prepared: ValidatedUpdate,
    /// A crossflash's target model, which the drive must report afterwards.
    #[cfg(test)]
    pub(super) expect: Option<String>,
}

pub(super) struct Executable {
    pub(super) prepared: mediatek_optical::prepare::PreparedUpdate,
}

impl Prepared {
    fn bind(self, receiver: &mediatek_optical::prepare::Receiver) -> Result<Executable> {
        let prepared = receiver.bind_prepared(&self.prepared).map_err(refusal)?;
        Ok(Executable { prepared })
    }
}

impl FlashFacet for Mtk {
    fn can_proceed_without_backup(&self) -> bool {
        true
    }
    fn accepts_current(&self) -> bool {
        true
    }
    /// MediaTek flashes with no pre-flash backup: a full-image backup is
    /// provably impossible on these drives, so requiring one only blocks legit
    /// flashes. The engine captures none and never gates on one for MediaTek.
    fn requires_preflash_backup(&self) -> bool {
        false
    }
    fn plan(&self, dev: &mut ReadDevice<'_>, req: &FlashRequest) -> Result<FlashPlan> {
        let format = req.input_format;
        if !DESCRIPTOR.owns(format) {
            bail!(
                "a {} cannot be flashed to this {} drive",
                format.label,
                DESCRIPTOR.id
            );
        }
        let mut notes = Vec::new();
        let mut final_image = None;
        let image = match format.role {
            // A backup archive restores its firmware image only; its per-unit
            // members are reference data, never written.
            FormatRole::Backup => {
                let firmware = backup::validate(&req.input, &req.drive_model, IMAGE_SIZE)?;
                notes.push(PlanLine::Header(
                    "== reflash backup firmware (per-unit data retained as reference) ==".into(),
                ));
                firmware
            }
            FormatRole::Package => {
                let package = crate::mediatek_package::Package::parse(&req.input)?;
                if let Some(intermediate) = package.intermediate() {
                    check_image(intermediate)?;
                    final_image = Some(package.firmware().to_vec());
                    notes.push(PlanLine::Text("Two-stage update: intermediate, confirm startup, then final firmware; the wire encoding is confirmed on the drive before each stage".into()));
                    intermediate.to_vec()
                } else {
                    package.firmware().to_vec()
                }
            }
            FormatRole::Image => req.input.clone(),
        };
        // Family and chip are confirmed from the drive (read-only) before any
        // probe or write; the family decides compatibility, not the model name.
        let (live, verdict) = self.validate_image(dev, &image, &req.drive_model)?;
        let family = mediatek_optical::envelope::family(&image)
            .map(|f| f.to_string())
            .unwrap_or_else(|| "unknown".into());

        // `--current` is an optional manual override: when supplied, the proven
        // receiver-reference flow derives the wire encoding from the installed
        // firmware; otherwise the drive is probed in the write phase.
        let mode = match req.current.as_deref() {
            Some(current) => {
                let receiver = super::receiver_reference::detect(dev, current)?;
                let enc = receiver.encoding() == mediatek_optical::prepare::Encoding::Encrypted;
                if req.enc_override.is_some_and(|requested| requested != enc) {
                    bail!("encoding override contradicts the active MediaTek receiver");
                }
                let following = final_image
                    .as_deref()
                    .map(|target| prepare_next_stage(&image, target))
                    .transpose()
                    .context("preparing final-stage receiver plan before any firmware write")?
                    .into_iter()
                    .collect();
                PlanMode::Reference {
                    receiver,
                    following,
                }
            }
            None => PlanMode::Probe { final_image },
        };

        // Technical facts (shown under "technical details" in rich front-ends).
        let mut detail = vec![
            PlanLine::Field("device", dev.describe()),
            PlanLine::Field("drive", style::ident_or_unknown(&req.drive_model).into()),
            PlanLine::Field("hardware family", family),
            PlanLine::Field(
                "firmware",
                format!("{} verbatim image", style::human_size(image.len())),
            ),
        ];
        if let PlanMode::Reference { receiver, .. } = &mode {
            detail.push(PlanLine::Field(
                "receiver",
                format!(
                    "{:?} ({:?}, signature at {:#x})",
                    receiver.mode(),
                    receiver.encoding(),
                    receiver.signature_address()
                ),
            ));
        }
        let mut block: Vec<_> = std::iter::once(PlanLine::Header("== flash plan ==".into()))
            .chain(
                detail
                    .into_iter()
                    .map(|line| PlanLine::Detail(Box::new(line))),
            )
            .collect();
        // User-facing encoding/backup lines (shown as notices).
        match &mode {
            PlanMode::Reference { .. } => block.push(PlanLine::Field("receiver code source", "Using your selected Current firmware to choose the transfer format. Its match to the installed firmware has not been verified.".into())),
            PlanMode::Probe { .. } => block.push(PlanLine::Field(
                "encoding",
                "will be probed on the drive (PP/EE/EP) — a safe pre-erase probe; a wrong guess \
                 cannot erase because the probe aborts before COMMIT"
                    .into(),
            )),
        }
        if verdict == Verdict::Crossflash {
            block.extend(crossflash_lines(&live, &image)?);
        }
        block.push(PlanLine::Field(
            "backup",
            "no pre-flash backup (MediaTek backup is not supported by the drive)".into(),
        ));
        block.push(PlanLine::Text(String::new()));
        block.push(PlanLine::Detail(Box::new(PlanLine::Text(
            "The command sequence is validated before execution".into(),
        ))));
        let mut plan = FlashPlan::new(Plan {
            image,
            live,
            drive_product: req.drive_model.clone(),
            verdict,
            mode,
        });
        plan.notes = notes;
        plan.dry_run = block.clone();
        plan.after_backup = block;
        Ok(plan)
    }

    fn preflight(&self, dev: &mut ReadDevice<'_>, _plan: &FlashPlan) -> Result<Vec<PlanLine>> {
        self.readiness(dev).context("read-only preflight failed")?;
        Ok(vec![
            PlanLine::Ok(
                "preflight",
                "transport ready; the wire encoding is probed safely on execute".into(),
            ),
            PlanLine::Spaced(Box::new(PlanLine::Warning(
                "DRY RUN: no firmware writes. MediaTek flashes without a pre-flash backup; \
                 a full-image rollback cannot be captured from the drive."
                    .into(),
            ))),
        ])
    }

    /// Confirm compatibility from the live drive (read-only). The probe path
    /// defers the wire encoding to the write phase; the reference path binds the
    /// prepared plan now. MediaTek keeps no pre-flash backup (`backup` is always
    /// `None`): a full-image rollback is impossible on these drives.
    fn authorize(
        &self,
        _dev: &mut ReadDevice<'_>,
        plan: FlashPlan,
        _backup: Option<&SavedBackup>,
    ) -> Result<AuthorizedPlan> {
        let state: &Plan = plan.state()?;
        crate::output::field(
            "Pre-flash backup",
            "None — MediaTek backup is not supported by the drive; a full-image rollback is \
             impossible. Compatibility is confirmed from the drive's hardware family.",
        );
        let authorized = match &state.mode {
            PlanMode::Reference { receiver, .. } => {
                let executable = authorize_bytes(
                    &state.live,
                    &state.drive_product,
                    state.verdict,
                    &state.image,
                    None,
                )?
                .bind(receiver)?;
                crate::output::field(
                    "Receiver sequence",
                    describe_sequence(&executable.prepared.plan().steps(), false),
                );
                crate::output::field(
                    "Transfer encoding",
                    format!(
                        "header {:?}; body {:?}",
                        executable.prepared.plan().encoding().header,
                        executable.prepared.plan().encoding().body
                    ),
                );
                Authorized::Reference(executable)
            }
            PlanMode::Probe { .. } => {
                // The chip and hardware-family gate already ran read-only in
                // `plan` (via `validate_image`), and `ForcedUpdate::prepare`
                // re-runs it at write time before any destructive command.
                crate::output::field(
                    "Transfer encoding",
                    "will be probed on the drive before writing (PP/EE/EP)",
                );
                Authorized::Probe
            }
        };
        Ok(AuthorizedPlan::new(plan, authorized))
    }

    fn execute(
        &self,
        dev: &mut WriteDevice<'_>,
        authorized: &AuthorizedPlan,
    ) -> Result<UpdateOutcome> {
        let state: &Plan = authorized.plan.state()?;
        match (authorized.state::<Authorized>()?, &state.mode) {
            (Authorized::Reference(first), PlanMode::Reference { following, .. }) => {
                execute_reference(dev, first, following)
            }
            (Authorized::Probe, PlanMode::Probe { final_image }) => {
                execute_probe(dev, state, final_image.as_deref())
            }
            _ => bail!("inconsistent MediaTek flash authorization"),
        }
    }
}

/// Stage labels for a one- or two-stage flash.
fn stage_label(index: usize, total: usize) -> &'static str {
    if total == 1 {
        "firmware"
    } else if index + 1 == total {
        "final firmware"
    } else {
        "intermediate"
    }
}

/// The `--current` reference path: run each receiver-bound prepared stage.
fn execute_reference(
    dev: &mut WriteDevice<'_>,
    first: &Executable,
    following: &[Executable],
) -> Result<UpdateOutcome> {
    let total = 1 + following.len();
    let mut completed = Vec::new();
    let mut outcome = None;
    for (index, stage) in std::iter::once(first).chain(following).enumerate() {
        let mut evidence = execute_stage(dev, &stage.prepared, total > 1, completed.clone())?;
        completed.push(stage_label(index, total).to_string());
        evidence.completed_stages = completed.clone();
        outcome = Some(evidence);
    }
    Ok(UpdateOutcome::Completed(
        outcome.expect("authorized sequence includes its initial stage"),
    ))
}

/// The current-free probe path: for each stage, probe the wire encoding safely
/// (no COMMIT, no erase), prepare a forced-encoding update against the live
/// drive identity, and flash it. A two-stage package re-reads the drive identity
/// and re-probes before the final stage, because the just-installed intermediate
/// changes the running receiver.
fn execute_probe(
    dev: &mut WriteDevice<'_>,
    state: &Plan,
    final_image: Option<&[u8]>,
) -> Result<UpdateOutcome> {
    let mut stages: Vec<&[u8]> = vec![state.image.as_slice()];
    stages.extend(final_image);
    let total = stages.len();
    let mut completed = Vec::new();
    let mut outcome = None;
    for (index, &image) in stages.iter().enumerate() {
        // Stage one trusts the plan's live identity; a later stage re-reads the
        // drive, which now runs the just-flashed firmware.
        let identity = if index == 0 {
            state.live.clone()
        } else {
            super::live_identity(dev)
        };
        let mut evidence =
            execute_forced_stage(dev, image, &identity, total > 1, completed.clone())?;
        completed.push(stage_label(index, total).to_string());
        evidence.completed_stages = completed.clone();
        outcome = Some(evidence);
    }
    Ok(UpdateOutcome::Completed(
        outcome.expect("the probe sequence includes its initial stage"),
    ))
}

/// Probe the drive's wire encoding (non-destructive), then flash `image` with
/// that encoding and no installed-firmware reference.
fn execute_forced_stage(
    dev: &mut WriteDevice<'_>,
    image: &[u8],
    identity: &Identity,
    temporary_firmware: bool,
    completed_stages: Vec<String>,
) -> Result<UpdateEvidence> {
    let shared = SharedDevice::new(dev);
    // The probe enters the update session and streams only the first header
    // chunk per candidate, reading REQUEST SENSE and aborting with TEST UNIT
    // READY — it never sends COMMIT, so the drive erases nothing.
    let encoding = {
        let mut probe = ScsiTransport::flash(&shared);
        mediatek_optical::drive::probe_encoding(&mut probe, image)
            .map_err(|error| probe_failure(error, &completed_stages))?
    };
    crate::output::field("Probed encoding", encoding_label(encoding));
    crate::diagnostics::record(format!(
        "MediaTek probe selected wire encoding header={:?} body={:?}",
        encoding.header, encoding.body
    ));
    let forced = ForcedUpdate::prepare(image, identity, encoding).map_err(refusal)?;
    log_forced(&forced, image);
    let (mut reads, mut writes) = (ScsiTransport::reads(&shared), ScsiTransport::flash(&shared));
    let mut runtime = Runtime::new();
    let completion = forced
        .flash_completed(
            FlashTransport {
                reads: &mut reads,
                writes: &mut writes,
            },
            &mut runtime,
        )
        .map_err(|error| {
            forced_failure(
                error,
                &writes,
                &runtime,
                temporary_firmware,
                completed_stages,
            )
        })?;
    Ok(completion_evidence(completion))
}

/// A short label for a probed transfer encoding.
fn encoding_label(encoding: TransferEncoding) -> String {
    format!("header {:?}; body {:?}", encoding.header, encoding.body)
}

/// A probe failure, before any firmware write: no erase can have occurred.
fn probe_failure(error: ProbeError<anyhow::Error>, completed_stages: &[String]) -> anyhow::Error {
    let operation_already_wrote = !completed_stages.is_empty();
    let detail = error.to_string();
    let (source, issue) = match error {
        ProbeError::Transport(e) => (
            crate::transport::mtk_err(e),
            crate::user_error::IssueCode::Connection,
        ),
        other => (
            anyhow::anyhow!("{other}"),
            crate::user_error::IssueCode::UpdateUncertain,
        ),
    };
    source
        .context(detail)
        .context("MediaTek encoding probe failed before any firmware write")
        .context(issue)
        .context(UpdateFailure {
            phase: "wire-encoding probe".into(),
            write_started: operation_already_wrote,
            progress: if operation_already_wrote {
                crate::backend::UpdateProgress::UploadComplete
            } else {
                crate::backend::UpdateProgress::Preflight
            },
            payload_bytes_accepted: Some(0),
            temporary_firmware: operation_already_wrote,
            completed_stages: completed_stages.to_vec(),
        })
}

/// A forced-encoding flash failure, mapped to the flasher's progress model.
fn forced_failure(
    error: ForcedError<anyhow::Error>,
    writes: &ScsiTransport<'_, '_>,
    runtime: &Runtime,
    temporary_firmware: bool,
    completed_stages: Vec<String>,
) -> anyhow::Error {
    let write_started = error.firmware_write_started();
    let firmware_payload_started = writes.payload_write_attempted();
    let operation_already_wrote = !completed_stages.is_empty();
    use crate::user_error::IssueCode;
    let (phase, source, issue) = match error {
        ForcedError::Identity(e) => (
            "live identity read",
            anyhow::anyhow!("{e}"),
            IssueCode::Connection,
        ),
        ForcedError::Flash(e) => (
            failure_phase(&e).0,
            flash_error(e),
            IssueCode::UpdateUncertain,
        ),
        // `ForcedError` is non-exhaustive; a future variant is a firmware update
        // failure with conservative write evidence.
        other => (
            "firmware update",
            anyhow::anyhow!("{other}"),
            IssueCode::UpdateUncertain,
        ),
    };
    let progress = if operation_already_wrote || runtime.upload_complete() {
        crate::backend::UpdateProgress::UploadComplete
    } else if runtime.payload_bytes_accepted() > 0 {
        crate::backend::UpdateProgress::PayloadAccepted
    } else if writes.payload_write_attempted() {
        crate::backend::UpdateProgress::PayloadAttempted
    } else if writes.empty_write_attempted() {
        crate::backend::UpdateProgress::EntryAttempted
    } else {
        crate::backend::UpdateProgress::Preflight
    };
    source
        .context("MediaTek update failed")
        .context(issue)
        .context(UpdateFailure {
            phase: phase.into(),
            write_started: (write_started && progress != crate::backend::UpdateProgress::Preflight)
                || operation_already_wrote,
            progress,
            payload_bytes_accepted: Some(runtime.payload_bytes_accepted()),
            temporary_firmware: temporary_firmware
                && (firmware_payload_started || operation_already_wrote),
            completed_stages,
        })
}

/// Diagnostics for a forced-encoding transfer (no receiver code is read).
fn log_forced(forced: &ForcedUpdate, image: &[u8]) {
    crate::diagnostics::record(format!(
        "MediaTek forced transfer: class={:?} family={} header={:?} body={:?} image_sha256={} wire_sha256={}",
        forced.class(),
        forced.family(),
        forced.encoding().header,
        forced.encoding().body,
        crate::mediatek_package::digest(image),
        crate::mediatek_package::digest(forced.transfer())
    ));
}

/// Compile every statically knowable second-stage check before stage one.
/// The prepared receiver revalidates the actual drive at the handoff.
fn prepare_next_stage(intermediate: &[u8], target: &[u8]) -> Result<Executable> {
    check_image(target)?;
    let envelope = mediatek_optical::envelope::Envelope::load(intermediate)?;
    let receiver = mediatek_optical::prepare::Receiver::from_firmware(&envelope)
        .map_err(|e| anyhow!("{e}"))?;
    let live = identity_of_image(intermediate)?;
    let product = crossflash::build_of_image(intermediate)?.product;
    let verdict = crossflash::decide_plan(
        &product,
        &Build::of_drive(&live),
        &crossflash::build_of_image(target)?,
    )?;
    authorize_bytes(&live, &product, verdict, target, Some(intermediate))?.bind(&receiver)
}

fn execute_stage(
    dev: &mut WriteDevice<'_>,
    prepared: &mediatek_optical::prepare::PreparedUpdate,
    temporary_firmware: bool,
    completed_stages: Vec<String>,
) -> Result<UpdateEvidence> {
    log_transfer(prepared.plan());
    let shared = SharedDevice::new(dev);
    let (mut reads, mut writes) = (ScsiTransport::reads(&shared), ScsiTransport::flash(&shared));
    let mut runtime = Runtime::new();
    let completion = prepared
        .flash_completed(
            FlashTransport {
                reads: &mut reads,
                writes: &mut writes,
            },
            &mut runtime,
        )
        .map_err(|error| {
            let (phase, write_started) = match &error {
                mediatek_optical::drive::ExecutionError::Receiver(_) => {
                    ("receiver revalidation", false)
                }
                mediatek_optical::drive::ExecutionError::Flash(error) => failure_phase(error),
                // Future library failures retain conservative write evidence.
                _ => ("firmware update", true),
            };
            let firmware_payload_started = writes.payload_write_attempted();
            let operation_already_wrote = !completed_stages.is_empty();
            let progress = if operation_already_wrote {
                crate::backend::UpdateProgress::UploadComplete
            } else {
                match &error {
                    mediatek_optical::drive::ExecutionError::Receiver(_) => {
                        crate::backend::UpdateProgress::Preflight
                    }
                    mediatek_optical::drive::ExecutionError::Flash(
                        mediatek_optical::drive::FlashError::Entry(_),
                    ) if writes.empty_write_attempted() => {
                        crate::backend::UpdateProgress::EntryAttempted
                    }
                    mediatek_optical::drive::ExecutionError::Flash(
                        mediatek_optical::drive::FlashError::Entry(_),
                    ) => crate::backend::UpdateProgress::Preflight,
                    mediatek_optical::drive::ExecutionError::Flash(
                        mediatek_optical::drive::FlashError::Transfer { .. },
                    ) if runtime.payload_bytes_accepted == 0 => {
                        crate::backend::UpdateProgress::PayloadAttempted
                    }
                    mediatek_optical::drive::ExecutionError::Flash(
                        mediatek_optical::drive::FlashError::Transfer { .. },
                    ) => crate::backend::UpdateProgress::PayloadAccepted,
                    _ if runtime.upload_complete => crate::backend::UpdateProgress::UploadComplete,
                    _ if runtime.payload_bytes_accepted > 0 => {
                        crate::backend::UpdateProgress::PayloadAccepted
                    }
                    _ if writes.payload_write_attempted() => {
                        crate::backend::UpdateProgress::PayloadAttempted
                    }
                    _ if writes.empty_write_attempted() => {
                        crate::backend::UpdateProgress::EntryAttempted
                    }
                    _ => crate::backend::UpdateProgress::Preflight,
                }
            };
            let source = match error {
                mediatek_optical::drive::ExecutionError::Flash(error) => flash_error(error),
                error => anyhow::Error::new(error),
            };
            source
                .context("MediaTek update failed")
                .context(UpdateFailure {
                    phase: phase.into(),
                    write_started: (write_started
                        && progress != crate::backend::UpdateProgress::Preflight)
                        || operation_already_wrote,
                    progress,
                    payload_bytes_accepted: Some(runtime.payload_bytes_accepted),
                    temporary_firmware: temporary_firmware
                        && (firmware_payload_started || operation_already_wrote),
                    completed_stages,
                })
        })?;
    Ok(completion_evidence(completion))
}

pub(super) fn log_transfer(plan: &mediatek_optical::prepare::TransferPlan) {
    crate::diagnostics::record(format!(
        "MediaTek transfer plan: receiver={:?} provenance={:?} header={:?} body={:?} prepare={:?} image_sha256={} wire_sha256={}",
        plan.receiver().mode(), plan.receiver().provenance(), plan.encoding().header,
        plan.encoding().body, plan.prepare_command(), crate::mediatek_package::digest(plan.image()),
        crate::mediatek_package::digest(plan.transfer())
    ));
    if let Some(digest) = plan.receiver().reference_sha256() {
        let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        crate::diagnostics::record(format!("MediaTek receiver reference sha256={digest}; code provenance is the bound firmware file, not a live code read"));
    }
    crate::diagnostics::record(describe_sequence(&plan.steps(), true));
    if let Some(ranges) = plan.programmed_ranges() {
        crate::diagnostics::record(format!(
            "MediaTek programmed ranges (end exclusive): {ranges:x?}"
        ));
    }
    if let Some(ranges) = plan.preserved_ranges() {
        crate::diagnostics::record(format!(
            "MediaTek preserved ranges (end exclusive): {ranges:x?}"
        ));
    }
}

/// Retain transport sense and error sources beneath lifecycle metadata.
pub(super) fn flash_error(
    error: mediatek_optical::drive::FlashError<anyhow::Error>,
) -> anyhow::Error {
    use mediatek_optical::drive::FlashError;
    let detail = error.to_string();
    match error {
        FlashError::Entry(source) => crate::transport::mtk_err(source).context(detail),
        FlashError::Transfer {
            offset,
            length,
            source,
        } => crate::transport::mtk_err(source)
            .context(detail)
            .context(crate::user_error::TransferFailure { offset, length }),
        error => anyhow::Error::new(error),
    }
}

pub(super) fn failure_phase(
    error: &mediatek_optical::drive::FlashError<anyhow::Error>,
) -> (&'static str, bool) {
    use mediatek_optical::drive::FlashError;
    match error {
        FlashError::Entry(_) => ("update entry", true),
        FlashError::Transfer { .. } => ("firmware transfer", true),
        FlashError::Fault { .. } => ("programming status", true),
        FlashError::ReadyTimeout(_) => ("waiting for programming to finish", true),
        FlashError::Startup(_) => ("target startup confirmation", true),
        FlashError::Mismatch { .. } => ("firmware readback", true),
        _ => ("firmware update", true),
    }
}

/// Publish the post-flash INQUIRY vendor/product/revision and return it.
fn publish_running_identity(inquiry: &[u8]) -> String {
    let end = inquiry.len().min(36);
    let start = 8.min(end);
    let identity = crate::style::printable(String::from_utf8_lossy(&inquiry[start..end]).trim());
    crate::output::field("Firmware running", crate::report::Value::text(&identity));
    identity
}

pub(super) fn completion_evidence(
    completion: mediatek_optical::drive::FlashOutcome,
) -> UpdateEvidence {
    use mediatek_optical::drive::ReadbackQuality;
    let (verified_regions, unverified_regions) = match completion.readback {
        ReadbackQuality::Complete(verified) if verified.checked > 0 => (
            vec![format!(
                "{} protected bytes across {} ranges",
                verified.checked, verified.ranges
            )],
            vec![],
        ),
        ReadbackQuality::Complete(_) => (
            vec![],
            vec!["image has no protected regions for byte verification".into()],
        ),
        ReadbackQuality::Limited {
            checked,
            unverified,
        } => (
            if checked > 0 {
                vec![format!("{checked} protected bytes")]
            } else {
                vec![]
            },
            vec![format!("{unverified} protected chunks unreadable")],
        ),
        // A read-back quality this build does not recognize is treated as
        // uncertain, never a clean verification: claim nothing verified and
        // surface the gap as an unverified region.
        _ => (
            vec![],
            vec![
                "read-back verification quality is not recognized by this build; \
                  treating protected regions as unverified"
                    .into(),
            ],
        ),
    };
    for region in &unverified_regions {
        crate::output::field("Verification warning", region);
    }
    let identity = publish_running_identity(completion.startup.inquiry());
    UpdateEvidence {
        target_started: true,
        target_identity: identity,
        verified_regions,
        unverified_regions,
        completed_stages: vec![],
        temporary_firmware: false,
    }
}

/// The plan's crossflash lines: what changes, how to go back, and the hardware
/// family the image and the drive share.
fn crossflash_lines(live: &Identity, image: &[u8]) -> Result<Vec<PlanLine>> {
    let (from, to) = (Build::of_drive(live), crossflash::build_of_image(image)?);
    let family = mediatek_optical::envelope::family(image)
        .map(|f| f.to_string())
        .unwrap_or_else(|| "unknown".into());
    Ok(vec![
        PlanLine::Warning(format!(
            "CROSSFLASH: {} \u{2192} {} (same hardware family {family}; a readable backup \
             verifies the installed family and rollback, without one only the drive's platform \
             and boot banner are checked)",
            from.label(),
            to.label(),
        )),
        PlanLine::Warning(format!(
            "the drive will identify as {} after the flash",
            to.model()
        )),
        PlanLine::Warning(format!(
            "your backup restores {} under the same family gate",
            from.label()
        )),
    ])
}

/// `authorize` on bytes: the backup as the installed firmware (chip and family
/// gates), then a crossflash re-decided on the backup.
///
/// The hardware family, not the model name, decides compatibility (as on
/// Pioneer): a rebadged drive of the same family is a model/identity change,
/// not different hardware. Without a backup, a crossflash therefore gets the
/// same live-evidence gates as a same-model flash — chip from the boot banner,
/// plus the plan's descriptor platform and boot-banner match — and the operator
/// has already consented to losing the installed-family and rollback checks.
pub(super) fn authorize_bytes(
    live: &Identity,
    drive_product: &str,
    verdict: Verdict,
    image: &[u8],
    backup: Option<&[u8]>,
) -> Result<Prepared> {
    let installed = backup
        .map(|bytes| InstalledFirmware::new(live.clone(), bytes))
        .transpose()
        .map_err(refusal)
        .context("the pre-flash backup cannot serve as this drive's installed firmware")?;
    let prepared = match &installed {
        Some(installed) => ValidatedUpdate::prepare(image, installed),
        None => ValidatedUpdate::prepare_without_installed(image, live),
    }
    .map_err(|error| {
        if matches!(error, Refusal::FamilyMismatch { .. }) {
            crate::backend::HardwareMismatch {
                installed_model: drive_product.into(),
                target_model: crossflash::build_of_image(image)
                    .map(|build| build.product)
                    .unwrap_or_default(),
                source: refusal(error),
            }
            .into()
        } else {
            refusal(error)
        }
    })?;
    let _expect = match (verdict, backup) {
        (Verdict::Crossflash, Some(backup)) => {
            Some(authorize_crossflash(drive_product, verdict, backup, image)?)
        }
        // A same-model operation needs no crossflash rollback simulation.
        _ => None,
    };
    Ok(Prepared {
        prepared,
        #[cfg(test)]
        expect: _expect,
    })
}

/// A crossflash, re-decided on the backup's bytes: the plan's family decision
/// must still hold, and the backup must flash back once the drive runs the
/// target. Returns the model the drive must report afterwards.
fn authorize_crossflash(
    drive_product: &str,
    planned: Verdict,
    backup: &[u8],
    image: &[u8],
) -> Result<String> {
    let (installed, target) = (
        crossflash::build_of_image(backup)?,
        crossflash::build_of_image(image)?,
    );
    let now = crossflash::decide_authorized(drive_product, &installed, &target)?;
    crossflash::ensure_unchanged(planned, now)?;
    rollback(backup, image).context(crossflash::BACKUP_NOT_FLASHABLE_BACK)?;
    crossflash::decide_rollback(&installed, &target)?;
    Ok(target.product)
}

/// The gates on the image alone: size, integrity, and a stored boot page the
/// catalog knows.
fn check_image(image: &[u8]) -> Result<()> {
    if image.len() != IMAGE_SIZE {
        bail!(
            "firmware .bin must be exactly {} bytes, got {}",
            IMAGE_SIZE,
            image.len()
        );
    }
    crate::cmac::validate_flags(image)?;
    if !crate::cmac::verify(image) {
        bail!(
            "firmware image fails its AES-CMAC integrity check — refusing to flash. \
             A mis-signed or corrupted image is rejected by the drive's boot \
             authenticator and can brick the drive."
        );
    }
    ensure_flashable_boot_page(image)?;
    Ok(())
}

/// The drive identity a complete image (or backup) reports, as the gates see a
/// live drive running it. The INQUIRY is blank; the gates read the descriptor.
fn identity_of_image(image: &[u8]) -> Result<Identity> {
    Ok(mediatek_optical::envelope::identity(image))
}

/// The whole `flash` decision with no device: `installed` (a complete image)
/// stands in for both the live drive and its pre-flash backup. Runs the same
/// image, plan and authorize gates `flash` runs before any write.
pub(crate) fn decide_offline(installed: &[u8], image: &[u8]) -> Result<()> {
    check_image(image)?;
    let live = identity_of_image(installed)?;
    classify::check(image, &live).map_err(refusal)?;
    let drive_product = crossflash::build_of_image(installed)?.product;
    let verdict = crossflash::decide_plan(
        &drive_product,
        &Build::of_drive(&live),
        &crossflash::build_of_image(image)?,
    )?;
    authorize_bytes(&live, &drive_product, verdict, image, Some(installed)).map(|_| ())
}

/// The update gates for the backup as the update, with the drive running
/// `image`.
pub(super) fn rollback(backup: &[u8], image: &[u8]) -> Result<()> {
    let installed = InstalledFirmware::new(identity_of_image(image)?, image).map_err(refusal)?;
    ensure_flashable_boot_page(backup)?;
    ValidatedUpdate::prepare(backup, &installed).map_err(refusal)?;
    Ok(())
}

/// The drive's 16-byte boot banner at `0x3000`, for the crossflash gate's
/// loader check. One `READ BUFFER`; `None` on any short or failed read, which
/// leaves the banner blank and fails the crossflash closed.
fn read_drive_banner(dev: &mut ReadDevice<'_>) -> Option<[u8; crossflash::BANNER_LEN]> {
    let data = dev
        .command_in(
            &cdb::read_memory(ROM_003000_OFFSET, ROM_003000_LEN),
            ROM_003000_LEN as usize,
        )
        .ok()?;
    data.get(..crossflash::BANNER_LEN)?.try_into().ok()
}

/// The text of a crate command error, keeping the transport's own chain.
fn text(error: &DriveError<anyhow::Error>) -> String {
    match error {
        DriveError::Transport(e) => format!("{e:#}"),
        other => other.to_string(),
    }
}

/// Progress and diagnostics for the crate's flash, in the flasher's words.
pub(super) struct Runtime {
    start: crate::runtime_clock::Clock,
    progress: style::Progress,
    payload_bytes_accepted: usize,
    upload_complete: bool,
}

impl Runtime {
    pub(super) fn new() -> Self {
        Self {
            start: crate::runtime_clock::Clock::new(),
            progress: style::Progress::new("flashing firmware", 0),
            payload_bytes_accepted: 0,
            upload_complete: false,
        }
    }
    pub(super) fn payload_bytes_accepted(&self) -> usize {
        self.payload_bytes_accepted
    }
    pub(super) fn upload_complete(&self) -> bool {
        self.upload_complete
    }
}

impl ExecutionRuntime<anyhow::Error> for Runtime {
    fn operation_progress(&mut self, progress: mediatek_optical::Progress) {
        use mediatek_optical::{Component, Phase};
        crate::output::publish(crate::output::Event::Phase {
            phase: match progress.phase {
                Phase::Reading => "reading",
                Phase::Preparing => "preparing",
                Phase::Writing => "writing",
                Phase::Restarting => "restarting",
                Phase::Verifying => "verifying",
            },
            component: match progress.component {
                Component::Firmware => "filter.firmware",
                Component::Kernel => "domain.kernel",
                Component::Normal => "domain.normal",
            },
            done: progress.done,
            total: progress.total,
        });
    }
    fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
    fn sleep(&mut self, duration: std::time::Duration) {
        crate::runtime_clock::sleep(duration);
    }
    fn starting(&mut self, bytes: usize) {
        println!(
            "\n{}",
            style::bold("EXECUTING flash — do not power off or disconnect the drive...")
        );
        self.progress = style::Progress::new("flashing firmware", bytes);
    }
    fn progress(&mut self, written: usize, _total: usize) {
        self.progress.set(written);
        self.payload_bytes_accepted = written;
    }
    fn recovery_entry_failed(&mut self, error: &DriveError<anyhow::Error>) {
        let message = format!(
            "MediaTek Recovery PREPARE failed: {}; recovery policy continues with the selected image; PREPARE will not be retried",
            text(error)
        );
        crate::diagnostics::record(&message);
    }
    fn commit_failed(&mut self, error: &DriveError<anyhow::Error>) {
        crate::diagnostics::record(format!(
            "MediaTek commit trailer returned an error: {}; checking completion and read-back",
            text(error)
        ));
    }
    fn commit_not_ready(&mut self, error: &DriveError<anyhow::Error>) {
        crate::diagnostics::record(format!("MediaTek post-commit readiness: {}", text(error)));
    }
    fn status(&mut self, stage: Stage, status: Status<'_, anyhow::Error>) {
        match (stage, status) {
            (_, Status::Sense(_)) => {}
            (Stage::Commit, Status::Failed(error)) => {
                crate::diagnostics::record(format!(
                    "post-flash REQUEST SENSE failed: {}",
                    text(error)
                ));
                self.status(Stage::Commit, Status::Unparseable(0));
            }
            (Stage::Commit, Status::Unparseable(n)) => crate::diagnostics::record(format!(
                "warning: could not parse the post-flash REQUEST SENSE response ({n} bytes); \
                 relying on read-back verify"
            )),
            (Stage::Settled, Status::Failed(error)) => crate::diagnostics::record(format!(
                "warning: post-settle REQUEST SENSE errored ({}); relying on read-back verify — \
                 the drive settled but its final sense state is unknown.",
                text(error)
            )),
            (Stage::Settled, Status::Unparseable(0)) => {}
            (Stage::Settled, Status::Unparseable(n)) => crate::diagnostics::record(format!(
                "warning: post-settle REQUEST SENSE returned an unparseable {n}-byte reply; \
                 relying on read-back verify."
            )),
            // An unrecognized stage or status outcome is never counted as a
            // clean sense: record it as indeterminate and rely on read-back
            // verify, which is what confers success.
            (stage, status) => crate::diagnostics::record(format!(
                "warning: unrecognized post-flash status ({stage:?}, {status:?}); \
                 treating it as indeterminate and relying on read-back verify."
            )),
        }
    }
    fn uploaded(&mut self, bytes: usize) {
        self.payload_bytes_accepted = bytes;
        self.upload_complete = true;
        println!(
            "upload complete {}",
            style::dim(&format!(
                "({}); waiting for the drive to finish programming...",
                style::human_size(bytes)
            ))
        );
    }
    fn poll_failed(&mut self, _elapsed: std::time::Duration, error: &DriveError<anyhow::Error>) {
        crate::diagnostics::record(format!("MediaTek post-flash readiness: {}", text(error)));
    }
    fn verifying(&mut self) {
        println!("verifying...");
    }
    fn verification_unavailable(
        &mut self,
        offset: usize,
        length: usize,
        error: &DriveError<anyhow::Error>,
    ) {
        let reason = match error {
            DriveError::Short { expected, actual } => format!("short read: {actual}/{expected}"),
            other => text(other),
        };
        crate::diagnostics::record(format!(
            "read-back incomplete: offset={offset:#x} length={length} reason={reason}"
        ));
    }
}

/// A refusal before any write, in the flasher's words.
fn refusal(error: Refusal) -> anyhow::Error {
    use mediatek_optical::CodedError;
    let issue = crate::user_error::IssueCode::from(error.kind());
    if let Some(reason) = error.family_gate() {
        return anyhow::Error::new(error).context(reason).context(issue);
    }
    match error {
        Refusal::ChipMismatch { .. } => anyhow::Error::new(error)
            .context("This gate cannot be overridden.")
            .context(issue),
        Refusal::UnknownDriveChip => anyhow::Error::new(error)
            .context("refusing to flash")
            .context(issue),
        other => anyhow::Error::new(other)
            .context("refusing to flash")
            .context(issue),
    }
}

impl Mtk {
    /// Every gate that needs no backup (read-only): size, integrity, a stored
    /// boot page the catalog knows, then the chip against the live drive, then
    /// the model decision (same-model, or a same-family crossflash gated on the
    /// descriptor's platform and boot banner — the chip is already matched).
    /// The full family is re-checked once the backup is read. Returns the live
    /// identity and the verdict.
    pub(crate) fn validate_image(
        &self,
        dev: &mut ReadDevice<'_>,
        image: &[u8],
        drive_product: &str,
    ) -> Result<(Identity, Verdict)> {
        check_image(image)?;
        let (live, identity_read) = live_identity_checked(dev);
        classify::check(image, &live).map_err(|error| {
            let error = refusal(error);
            if identity_read {
                error
            } else {
                error
                    .context("the drive identity regions could not be read")
                    .context(crate::user_error::IssueCode::Connection)
            }
        })?;
        let target = crossflash::build_of_image(image)?;
        let mut drive = Build::of_drive(&live);
        // A crossflash gates on the boot banner too (its loader tells apart the
        // families that share a platform). `live_identity` skips the banner for
        // a tagged drive, so read it now; a same-model reflash needs none of
        // this, and reads nothing more than today.
        if drive.banner.iter().all(|&b| b == 0)
            && !crossflash::is_same_model(&target.product, drive_product)
        {
            if let Some(banner) = read_drive_banner(dev) {
                drive.banner = banner;
            }
        }
        let verdict = crossflash::decide_plan(drive_product, &drive, &target)?;
        Ok((live, verdict))
    }

    /// Read-only readiness handshake: PROBE must return the full ROM read;
    /// TEST UNIT READY must answer (benign no-medium included).
    pub(crate) fn readiness(&self, dev: &mut ReadDevice<'_>) -> Result<()> {
        let probe = dev.command_in(&cdb::probe(), cdb::PROBE_LEN)?;
        if probe.len() != cdb::PROBE_LEN {
            bail!(
                "short MediaTek preflight ROM read: got {} of {} bytes",
                probe.len(),
                cdb::PROBE_LEN
            );
        }
        let _ = dev.command_in(&cdb::test_unit_ready(), 0)?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn test_plan(dev: &mut dyn ScsiDevice, image: &[u8]) -> Result<FlashPlan> {
    let receiver = super::detect_receiver(&mut ReadDevice::without_unlocks(dev))?;
    Ok(FlashPlan::new(Plan {
        image: image.to_vec(),
        live: identity_of_image(image)?,
        drive_product: "BD-RE BU40N".into(),
        verdict: Verdict::SameModel,
        mode: PlanMode::Reference {
            receiver,
            following: Vec::new(),
        },
    }))
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;

#[cfg(test)]
#[path = "stage_tests.rs"]
mod stage_tests;

#[cfg(test)]
#[path = "oracle_tests.rs"]
mod oracle_tests;
