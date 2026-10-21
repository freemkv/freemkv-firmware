//! MediaTek lifecycle adapter: app backup/consent policy surrounds optical
//! receiver plans. Every packaged stage is prepared before writing; the optical
//! crate revalidates each receiver, executes its wire plan and confirms the
//! exact requested target. Verification quality remains part of the result.

use anyhow::{anyhow, bail, Context, Result};
use mediatek_optical::drive::Error as DriveError;
use mediatek_optical::update::{
    FlashRuntime, FlashTransport, InstalledFirmware, PrepareError, PreparedUpdate, Stage, Status,
};
use mediatek_optical::Identity;

use super::crossflash::{Build, Verdict};
use super::{
    backup, cdb, crossflash, describe_sequence, detect_receiver, ensure_flashable_boot_page,
    live_identity, Mtk, DESCRIPTOR, IMAGE_SIZE, ROM_003000_LEN, ROM_003000_OFFSET,
};
use crate::backend::{
    AuthorizedPlan, FlashFacet, FlashPlan, FlashRequest, FormatRole, PlanLine, ReadDevice,
    SavedBackup, UpdateEvidence, UpdateFailure, UpdateOutcome, WriteDevice,
};
use crate::platform::ScsiDevice;
use crate::style;
use crate::transport::{ScsiTransport, SharedDevice};

/// What `plan` decided, for `authorize`.
struct Plan {
    image: Vec<u8>,
    final_prepared: Option<Executable>,
    live: Identity,
    receiver: mediatek_optical::receiver::Receiver,
    drive_product: String,
    verdict: Verdict,
}

/// What `authorize` decided, for `execute`.
pub(super) struct Authorized {
    pub(super) prepared: PreparedUpdate,
    /// A crossflash's target model, which the drive must report afterwards.
    #[cfg(test)]
    pub(super) expect: Option<String>,
}

struct Executable {
    prepared: mediatek_optical::receiver::PreparedUpdate,
}

impl Authorized {
    fn bind(self, receiver: &mediatek_optical::receiver::Receiver) -> Result<Executable> {
        let prepared = receiver.bind_prepared(&self.prepared).map_err(refusal)?;
        Ok(Executable { prepared })
    }
}

impl FlashFacet for Mtk {
    fn accepts_current(&self) -> bool {
        true
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
                    notes.push(PlanLine::Text("Two-stage update: intermediate, confirm startup, then final firmware; use the just-installed intermediate for receiver analysis if live code reads are restricted".into()));
                    intermediate.to_vec()
                } else {
                    package.firmware().to_vec()
                }
            }
            FormatRole::Image => req.input.clone(),
        };
        let final_prepared = final_image
            .as_deref()
            .map(|target| prepare_next_stage(&image, target))
            .transpose()
            .context("preparing final-stage receiver plan before any firmware write")?;
        let (live, verdict) = self.validate_image(dev, &image, &req.drive_model)?;
        let receiver = match req.current.as_deref() {
            Some(current) => super::receiver_reference::detect(dev, current)?,
            None => detect_receiver(dev)
                .map_err(|source| crate::backend::CurrentFirmwareRequired { source })?,
        };
        let enc = receiver.encoding() == mediatek_optical::receiver::Encoding::Encrypted;
        if req.enc_override.is_some_and(|requested| requested != enc) {
            bail!("encoding override contradicts the active MediaTek receiver");
        }
        let mut block = vec![
            PlanLine::Header("== flash plan ==".into()),
            PlanLine::Field("device", dev.describe()),
            PlanLine::Field(
                "receiver",
                format!(
                    "{:?} ({:?}, signature at {:#x})",
                    receiver.mode(),
                    receiver.encoding(),
                    receiver.signature_address()
                ),
            ),
            PlanLine::Field("drive", style::ident_or_unknown(&req.drive_model).into()),
            PlanLine::Field(
                "firmware",
                format!(
                    "{} (wire layout selected from receiver code)",
                    style::human_size(image.len())
                ),
            ),
        ];
        if req.current.is_some() {
            block.push(PlanLine::Field("receiver code source", "Selected Current firmware; live identity and build metadata matched. Live receiver code was not compared.".into()));
        }
        if verdict == Verdict::Crossflash {
            block.extend(crossflash_lines(&live, &image)?);
        }
        block.extend([PlanLine::Backup, PlanLine::Text(String::new())]);
        block.push(PlanLine::Text(
            "The receiver-bound command sequence is validated before execution".into(),
        ));
        let mut plan = FlashPlan::new(Plan {
            image,
            final_prepared,
            live,
            receiver,
            drive_product: req.drive_model.clone(),
            verdict,
        });
        plan.notes = notes;
        plan.dry_run = block.clone();
        plan.after_backup = block;
        Ok(plan)
    }

    fn preflight(&self, dev: &mut ReadDevice<'_>, _plan: &FlashPlan) -> Result<Vec<PlanLine>> {
        if let Err(e) = self.readiness(dev) {
            bail!("read-only preflight failed: {e}");
        }
        Ok(vec![
            PlanLine::Ok(
                "preflight",
                "transport ready; backup capture is checked only on execute".into(),
            ),
            PlanLine::Spaced(Box::new(PlanLine::Warning(
                "DRY RUN: no firmware writes or backup capture. Execute may still fail if a \
                 complete rollback image cannot be read."
                    .into(),
            ))),
        ])
    }

    /// The installed firmware is the pre-flash backup: the image rebuilt from
    /// a complete drive read. Its family equals the read's, because the family
    /// reads no byte a rebuild replaces, and it is the artifact the user keeps.
    fn authorize(
        &self,
        _dev: &mut ReadDevice<'_>,
        plan: FlashPlan,
        backup: Option<&SavedBackup>,
    ) -> Result<AuthorizedPlan> {
        let state: &Plan = plan.state()?;
        // The optical executor revalidates the cached receiver immediately
        // before its first session command, after the confirmation window.
        if backup.is_none() {
            crate::output::field("Installed firmware evidence", "Unavailable; operator approved proceeding without a backup. Installed-family equality and rollback cannot be verified.");
        }
        let authorized = authorize_bytes(
            &state.live,
            &state.drive_product,
            state.verdict,
            &state.image,
            backup.map(|b| b.bytes()),
        )?
        .bind(&state.receiver)?;
        crate::output::field(
            "Receiver sequence",
            describe_sequence(&authorized.prepared.plan().steps(), false),
        );
        crate::output::field(
            "Transfer encoding",
            format!(
                "header {:?}; body {:?}",
                authorized.prepared.plan().encoding().header,
                authorized.prepared.plan().encoding().body
            ),
        );
        Ok(AuthorizedPlan::new(plan, authorized))
    }

    fn execute(
        &self,
        dev: &mut WriteDevice<'_>,
        authorized: &AuthorizedPlan,
    ) -> Result<UpdateOutcome> {
        let first: &Executable = authorized.state()?;
        let state: &Plan = authorized.plan.state()?;
        let mut evidence =
            execute_stage(dev, &first.prepared, state.final_prepared.is_some(), vec![])?;
        evidence.completed_stages.push(
            if state.final_prepared.is_some() {
                "intermediate"
            } else {
                "firmware"
            }
            .into(),
        );
        if let Some(next) = &state.final_prepared {
            let first_stages = evidence.completed_stages.clone();
            evidence = execute_stage(dev, &next.prepared, true, first_stages.clone())?;
            evidence.completed_stages = first_stages;
            evidence.completed_stages.push("final firmware".into());
        }
        Ok(UpdateOutcome::Completed(evidence))
    }
}

/// Compile every statically knowable second-stage check before stage one.
/// The prepared receiver revalidates the actual drive at the handoff.
fn prepare_next_stage(intermediate: &[u8], target: &[u8]) -> Result<Executable> {
    check_image(target)?;
    let envelope = mediatek_optical::envelope::Envelope::load(intermediate)?;
    let receiver = mediatek_optical::receiver::Receiver::from_firmware(&envelope)
        .map_err(|e| anyhow!("{e}"))?;
    let live = identity_of_image(intermediate)?;
    let product = Build::of_image(intermediate)?.product;
    let verdict =
        crossflash::decide_plan(&product, &Build::of_drive(&live), &Build::of_image(target)?)?;
    authorize_bytes(&live, &product, verdict, target, Some(intermediate))?.bind(&receiver)
}

fn execute_stage(
    dev: &mut WriteDevice<'_>,
    prepared: &mediatek_optical::receiver::PreparedUpdate,
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
                mediatek_optical::receiver::ExecuteError::Receiver(_) => {
                    ("receiver revalidation", false)
                }
                mediatek_optical::receiver::ExecuteError::Flash(error) => failure_phase(error),
            };
            let firmware_payload_started = !matches!(
                &error,
                mediatek_optical::receiver::ExecuteError::Receiver(_)
                    | mediatek_optical::receiver::ExecuteError::Flash(
                        mediatek_optical::update::FlashError::Entry(_)
                    )
            );
            let operation_already_wrote = !completed_stages.is_empty();
            let source = match error {
                mediatek_optical::receiver::ExecuteError::Flash(error) => flash_error(error),
                error => anyhow::Error::new(error),
            };
            source
                .context("MediaTek update failed")
                .context(UpdateFailure {
                    phase: phase.into(),
                    write_started: write_started || operation_already_wrote,
                    temporary_firmware: temporary_firmware
                        && (firmware_payload_started || operation_already_wrote),
                    completed_stages,
                })
        })?;
    Ok(completion_evidence(completion))
}

pub(super) fn log_transfer(plan: &mediatek_optical::receiver::TransferPlan) {
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
    error: mediatek_optical::update::FlashError<anyhow::Error>,
) -> anyhow::Error {
    use mediatek_optical::update::FlashError;
    let detail = error.to_string();
    match error {
        FlashError::Entry(source) | FlashError::Transfer { source, .. } => {
            crate::transport::mtk_err(source).context(detail)
        }
        error => anyhow::Error::new(error),
    }
}

pub(super) fn failure_phase(
    error: &mediatek_optical::update::FlashError<anyhow::Error>,
) -> (&'static str, bool) {
    use mediatek_optical::update::FlashError;
    match error {
        FlashError::Entry(_) => ("update entry", true),
        FlashError::Transfer { .. } => ("firmware transfer", true),
        FlashError::Fault { .. } => ("programming status", true),
        FlashError::ReadyTimeout(_) => ("waiting for programming to finish", true),
        FlashError::Startup(_) => ("target startup confirmation", true),
        FlashError::Mismatch { .. } | FlashError::Incomplete { .. } => ("firmware readback", true),
        _ => ("firmware update", true),
    }
}

pub(super) fn completion_evidence(
    completion: mediatek_optical::update::Completion,
) -> UpdateEvidence {
    use mediatek_optical::update::ReadbackQuality;
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
    };
    let identity = String::from_utf8_lossy(&completion.startup.inquiry()[8..36])
        .trim()
        .to_owned();
    for region in &unverified_regions {
        crate::output::field("Verification warning", region);
    }
    crate::output::field("Firmware running", &identity);
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
    let (from, to) = (Build::of_drive(live), Build::of_image(image)?);
    let family = mediatek_optical::image::family(image)
        .map(|f| f.to_string())
        .unwrap_or_else(|| "unknown".into());
    Ok(vec![
        PlanLine::Warning(format!(
            "CROSSFLASH: {} \u{2192} {} (same hardware family {family}; installed-family and rollback \
             checks require a readable backup)",
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
pub(super) fn authorize_bytes(
    live: &Identity,
    drive_product: &str,
    verdict: Verdict,
    image: &[u8],
    backup: Option<&[u8]>,
) -> Result<Authorized> {
    if backup.is_none() && verdict == Verdict::Crossflash {
        bail!("crossflash requires installed firmware evidence to verify hardware-family equality and rollback; consent to proceed without a backup does not waive compatibility checks");
    }
    let installed = backup
        .map(|bytes| InstalledFirmware::new(live.clone(), bytes))
        .transpose()
        .map_err(refusal)
        .context("the pre-flash backup cannot serve as this drive's installed firmware")?;
    let prepared = match &installed {
        Some(installed) => PreparedUpdate::prepare(image, installed),
        None => PreparedUpdate::prepare_without_installed(image, live),
    }
    .map_err(refusal)?;
    let _expect = match (verdict, backup) {
        (Verdict::Crossflash, Some(backup)) => {
            Some(authorize_crossflash(drive_product, verdict, backup, image)?)
        }
        // A same-model operation needs no crossflash rollback simulation.
        _ => None,
    };
    Ok(Authorized {
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
    let (installed, target) = (Build::of_image(backup)?, Build::of_image(image)?);
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
    use mediatek_optical::layout;
    Identity::parse(
        &[0; mediatek_optical::INQUIRY_LEN],
        layout::BANNER.of(image).unwrap_or_default(),
        layout::DESCRIPTOR.of(image).unwrap_or_default(),
    )
    .context("an empty INQUIRY")
}

/// The whole `flash` decision with no device: `installed` (a complete image)
/// stands in for both the live drive and its pre-flash backup. Runs the same
/// image, plan and authorize gates `flash` runs before any write.
pub(crate) fn decide_offline(installed: &[u8], image: &[u8]) -> Result<()> {
    check_image(image)?;
    let live = identity_of_image(installed)?;
    PreparedUpdate::check(image, &live).map_err(refusal)?;
    let drive_product = Build::of_image(installed)?.product;
    let verdict = crossflash::decide_plan(
        &drive_product,
        &Build::of_drive(&live),
        &Build::of_image(image)?,
    )?;
    authorize_bytes(&live, &drive_product, verdict, image, Some(installed)).map(|_| ())
}

/// The update gates for the backup as the update, with the drive running
/// `image`.
pub(super) fn rollback(backup: &[u8], image: &[u8]) -> Result<()> {
    let installed = InstalledFirmware::new(identity_of_image(image)?, image).map_err(refusal)?;
    ensure_flashable_boot_page(backup)?;
    PreparedUpdate::prepare(backup, &installed).map_err(refusal)?;
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
}

impl Runtime {
    pub(super) fn new() -> Self {
        Self {
            start: crate::runtime_clock::Clock::new(),
            progress: style::Progress::new("flashing firmware", 0),
        }
    }
}

impl FlashRuntime<anyhow::Error> for Runtime {
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
    }
    fn recovery_entry_failed(&mut self, error: &DriveError<anyhow::Error>) {
        let message = format!(
            "MediaTek Recovery PREPARE failed: {}; recovery policy continues with the selected image; PREPARE will not be retried",
            text(error)
        );
        crate::diagnostics::record(&message);
        eprintln!("{message}");
    }
    fn commit_failed(&mut self, error: &DriveError<anyhow::Error>) {
        eprintln!(
            "MediaTek commit trailer returned an error: {}; checking completion and read-back",
            text(error)
        );
    }
    fn commit_not_ready(&mut self, error: &DriveError<anyhow::Error>) {
        crate::diagnostics::record(format!("MediaTek post-commit readiness: {}", text(error)));
    }
    fn status(&mut self, stage: Stage, status: Status<'_, anyhow::Error>) {
        match (stage, status) {
            (_, Status::Sense(_)) => {}
            (Stage::Commit, Status::Failed(error)) => {
                eprintln!("warning: post-flash REQUEST SENSE failed: {}", text(error));
                self.status(Stage::Commit, Status::Unparseable(0));
            }
            (Stage::Commit, Status::Unparseable(n)) => eprintln!(
                "warning: could not parse the post-flash REQUEST SENSE response ({n} bytes); \
                 relying on read-back verify"
            ),
            (Stage::Settled, Status::Failed(error)) => eprintln!(
                "warning: post-settle REQUEST SENSE errored ({}); relying on read-back verify — \
                 the drive settled but its final sense state is unknown.",
                text(error)
            ),
            (Stage::Settled, Status::Unparseable(0)) => {}
            (Stage::Settled, Status::Unparseable(n)) => eprintln!(
                "warning: post-settle REQUEST SENSE returned an unparseable {n}-byte reply; \
                 relying on read-back verify."
            ),
        }
    }
    fn uploaded(&mut self, bytes: usize) {
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
    fn unverified(&mut self, offset: usize, length: usize, error: &DriveError<anyhow::Error>) {
        let reason = match error {
            DriveError::Short { expected, actual } => format!("short read: {actual}/{expected}"),
            other => text(other),
        };
        crate::diagnostics::record(format!(
            "read-back incomplete: offset={offset:#x} length={length} reason={reason}"
        ));
    }
}

/// The hardware-family gate's refusal, worded like Pioneer's `family_gate`.
/// Both families must be known and equal; nothing overrides it.
pub(crate) fn family_gate(error: &PrepareError) -> Option<String> {
    Some(match error {
        PrepareError::FamilyMismatch { installed, target } => format!(
            "family mismatch: installed firmware is family {installed}, target is family \
             {target} (a different board line; not update-compatible)"
        ),
        PrepareError::UnknownInstalledFamily => "could not determine the installed firmware \
             family (the pre-flash backup has no hardware configuration record to profile); \
             flashing requires a known family"
            .to_string(),
        PrepareError::UnknownTargetFamily => "could not determine the target firmware family \
             (the image has no hardware configuration record to profile); flashing requires a \
             known family"
            .to_string(),
        _ => return None,
    })
}

/// A refusal before any write, in the flasher's words.
fn refusal(error: PrepareError) -> anyhow::Error {
    if let Some(reason) = family_gate(&error) {
        return anyhow!("{reason}");
    }
    match error {
        PrepareError::ChipMismatch { .. } => {
            anyhow!("{error}. This gate cannot be overridden.")
        }
        PrepareError::UnknownDriveChip => {
            anyhow!("{error}; refusing to flash")
        }
        other => anyhow!("{other}; refusing to flash"),
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
        let live = live_identity(dev);
        PreparedUpdate::check(image, &live).map_err(refusal)?;
        let target = Build::of_image(image)?;
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
    Ok(FlashPlan::new(Plan {
        image: image.to_vec(),
        final_prepared: None,
        live: identity_of_image(image)?,
        receiver: detect_receiver(&mut ReadDevice::without_unlocks(dev))?,
        drive_product: "BD-RE BU40N".into(),
        verdict: Verdict::SameModel,
    }))
}

#[cfg(test)]
#[path = "stage_tests.rs"]
mod stage_tests;
