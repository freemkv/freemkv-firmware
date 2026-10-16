//! The MediaTek update in the engine's two stages. `plan` validates the image
//! against the live drive before any backup, deciding a same-model reflash or a
//! same-hardware-family crossflash; `authorize` binds the pre-flash backup as
//! the installed firmware and lets `mediatek_optical` prepare the update,
//! refusing another hardware family, and re-decides a crossflash on the backup;
//! `execute` runs the prepared update and re-identifies the firmware, and for a
//! crossflash confirms the drive now reports the target model. The crate owns
//! the session.

use anyhow::{anyhow, bail, Context, Result};
use mediatek_optical::drive::Error as DriveError;
use mediatek_optical::update::{
    FlashError, FlashRuntime, FlashTransport, InstalledFirmware, PrepareError, PreparedUpdate,
    Stage, Status,
};
use mediatek_optical::Identity;

use super::crossflash::{Build, Verdict};
use super::{
    backup, cdb, crossflash, describe_sequence, detect_receiver, ensure_flashable_boot_page,
    live_identity, Mtk, DESCRIPTOR, IMAGE_SIZE, ROM_003000_LEN, ROM_003000_OFFSET,
};
use crate::backend::{
    AuthorizedPlan, DetailsFacet, FlashFacet, FlashPlan, FlashRequest, FormatRole, PlanLine,
    ReadDevice, SavedBackup, WriteDevice,
};
use crate::platform::ScsiDevice;
use crate::style;
use crate::transport::{mtk_err, ScsiTransport, SharedDevice};

/// What `plan` decided, for `authorize`.
struct Plan {
    image: Vec<u8>,
    final_image: Option<Vec<u8>>,
    live: Identity,
    receiver: mediatek_optical::receiver::Receiver,
    drive_product: String,
    verdict: Verdict,
}

/// What `authorize` decided, for `execute`.
pub(super) struct Authorized {
    pub(super) prepared: PreparedUpdate,
    installed: InstalledFirmware,
    /// A crossflash's target model, which the drive must report afterwards.
    pub(super) expect: Option<String>,
}

struct Executable {
    prepared: mediatek_optical::receiver::PreparedUpdate,
    expect: Option<String>,
}

impl Authorized {
    fn bind(self, receiver: &mediatek_optical::receiver::Receiver) -> Result<Executable> {
        let envelope = mediatek_optical::envelope::Envelope::load(self.prepared.image())
            .map_err(|e| anyhow!("{e}"))?;
        Ok(Executable {
            prepared: receiver
                .prepare(&envelope, &self.installed)
                .map_err(refusal)?,
            expect: self.expect,
        })
    }
}

impl FlashFacet for Mtk {
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
                    decide_offline(intermediate, package.firmware())
                        .context("checking intermediate-to-final transition before any write")?;
                    final_image = Some(package.firmware().to_vec());
                    notes.push(PlanLine::Text("Two-stage update: intermediate, confirm startup, then final firmware with freshly detected transfer encoding".into()));
                    intermediate.to_vec()
                } else {
                    package.firmware().to_vec()
                }
            }
            FormatRole::Image => req.input.clone(),
        };
        let (live, verdict) = self.validate_image(dev, &image, &req.drive_model)?;
        let steps = live
            .class()
            .context("the drive names no update dialect; refusing")?
            .steps();
        let receiver = detect_receiver(dev)?;
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
                    "{} ({} envelope)",
                    style::human_size(image.len()),
                    if enc { "encrypted" } else { "plaintext" }
                ),
            ),
        ];
        if verdict == Verdict::Crossflash {
            block.extend(crossflash_lines(&live, &image)?);
        }
        block.extend([PlanLine::Backup, PlanLine::Text(String::new())]);
        block.push(PlanLine::Block(describe_sequence(&steps, req.verbose)));
        let mut plan = FlashPlan::new(Plan {
            image,
            final_image,
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
        let authorized = authorize_bytes(
            &state.live,
            &state.drive_product,
            state.verdict,
            &state.image,
            backup.map(|b| b.bytes()),
        )?
        .bind(&state.receiver)?;
        Ok(AuthorizedPlan::new(plan, authorized))
    }

    fn execute(&self, dev: &mut WriteDevice<'_>, authorized: &AuthorizedPlan) -> Result<()> {
        let Executable { prepared, expect } = authorized.state()?;
        let state: &Plan = authorized.plan.state()?;
        execute_stage(self, dev, prepared, expect)?;
        if let Some(final_image) = &state.final_image {
            let reader = &mut ReadDevice::without_unlocks(dev);
            let inquiry = reader.command_in(&cdb::inquiry(36), 36)?;
            if inquiry.get(8..36) != state.image.get(0x1ec000..0x1ec01c) {
                bail!("intermediate firmware startup was not confirmed by INQUIRY; final stage not written");
            }
            let intermediate_live = live_identity(reader);
            let expected = &state.image[0x1ec000..0x1ec058];
            if &intermediate_live.descriptor_bytes()[..0x58] != expected {
                bail!("intermediate firmware startup was not confirmed; final stage not written");
            }
            let drive_product = Build::of_image(&state.image)?.product;
            let (live, verdict) = self.validate_image(reader, final_image, &drive_product)?;
            let receiver = detect_receiver(reader)?;
            if receiver.mode() != mediatek_optical::receiver::Mode::Firmware {
                bail!("drive remains in BOOT; final stage not written");
            }
            let next = authorize_bytes(
                &live,
                &drive_product,
                verdict,
                final_image,
                Some(&state.image),
            )?
            .bind(&receiver)?;
            execute_stage(self, dev, &next.prepared, &next.expect)?;
            let reader = &mut ReadDevice::without_unlocks(dev);
            let inquiry = reader.command_in(&cdb::inquiry(36), 36)?;
            if inquiry.get(8..36) != final_image.get(0x1ec000..0x1ec01c) {
                bail!("final firmware startup was not confirmed by INQUIRY");
            }
        }
        Ok(())
    }
}

fn execute_stage(
    backend: &Mtk,
    dev: &mut WriteDevice<'_>,
    prepared: &mediatek_optical::receiver::PreparedUpdate,
    expect: &Option<String>,
) -> Result<()> {
    let verified = {
        let shared = SharedDevice::new(dev);
        let (mut reads, mut writes) =
            (ScsiTransport::reads(&shared), ScsiTransport::flash(&shared));
        let io = FlashTransport {
            reads: &mut reads,
            writes: &mut writes,
        };
        let mut runtime = Runtime::new();
        prepared.flash(io, &mut runtime).map_err(|e| match e {
            mediatek_optical::receiver::ExecuteError::Receiver(e) => anyhow!("{e}"),
            mediatek_optical::receiver::ExecuteError::Flash(e) => {
                flash_error(e, prepared.plan().class())
            }
        })?
    };
    if verified.ranges == 0 {
        println!(
            "{}",
            style::dim_line(
                "  read-back cross-check: image carries no integrity table; \
                     relying on the drive's firmware identity below."
            )
        );
    } else {
        println!(
            "{}",
            style::status_line(
                "flash complete",
                &format!(
                    "{} of integrity-protected regions verified",
                    style::human_size(verified.checked)
                ),
                style::Status::Ok
            )
        );
    }
    println!(
        "{}",
        style::dim_line(
            "  Integrity is enforced on-device: the drive recomputes CMAC at boot and \
                 rejects a bad image. The firmware identity below is the real result."
        )
    );
    let reader = &mut ReadDevice::without_unlocks(dev);
    confirm_identity(backend, reader)?;
    match expect {
        Some(model) => confirm_crossflash(reader, model),
        None => Ok(()),
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
            "CROSSFLASH: {} \u{2192} {} (same hardware family {family}; confirmed against your \
             backup before any write)",
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
    // Without a backup (the operator consented to flash an un-backup-able drive)
    // the installed firmware is unavailable, so the target image stands in for it
    // to prepare the write. The chip/size/integrity gates inside
    // `PreparedUpdate::prepare` (via `check`) still run against the live drive;
    // only the installed-family equality and the crossflash rollback simulation —
    // both of which need the installed firmware — are skipped.
    let installed_bytes = backup.unwrap_or(image);
    let installed = InstalledFirmware::new(live.clone(), installed_bytes)
        .map_err(refusal)
        .context(if backup.is_some() {
            "the pre-flash backup cannot serve as this drive's installed firmware"
        } else {
            "the firmware image cannot be prepared for this drive"
        })?;
    let prepared = PreparedUpdate::prepare(image, &installed).map_err(refusal)?;
    let expect = match (verdict, backup) {
        (Verdict::Crossflash, Some(backup)) => {
            Some(authorize_crossflash(drive_product, verdict, backup, image)?)
        }
        // Same-model, or a crossflash the operator is taking without a backup:
        // there is no installed firmware to simulate the rollback against.
        _ => None,
    };
    Ok(Authorized {
        prepared,
        installed,
        expect,
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

/// After a crossflash the drive must identify as the target's model.
fn confirm_crossflash(dev: &mut ReadDevice<'_>, model: &str) -> Result<()> {
    let now = Build::of_drive(&live_identity(dev));
    // Confirm with the same model relation the pre-flash gate used to admit this
    // image (`crossflash::same_model`: the drive's reported product is contained
    // in the image model), not a raw string equality — `model` is the image's
    // chip-derived model while `now.product` is the drive's descriptor model, so
    // `!=` would false-fail a successful crossflash whose descriptor model is a
    // variant of the chip model. A genuine failure (the drive still reports the
    // old product) and a blank read both still refuse.
    if !crossflash::is_same_model(model, &now.product) {
        bail!(
            "drive did not take the crossflash image: it identifies as {:?}, not {:?}. \
             Physically re-verify the drive before using it.",
            crate::backend::sanitize_ascii(&now.product),
            crate::backend::sanitize_ascii(model)
        );
    }
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
    start: std::time::Instant,
    progress: style::Progress,
}

impl Runtime {
    pub(super) fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            progress: style::Progress::new("flashing firmware", 0),
        }
    }
}

impl FlashRuntime<anyhow::Error> for Runtime {
    fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
    fn sleep(&mut self, duration: std::time::Duration) {
        std::thread::sleep(duration);
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

/// A failed flash, with what the user must do about it.
fn flash_error(
    error: FlashError<anyhow::Error>,
    class: mediatek_optical::DriveClass,
) -> anyhow::Error {
    let describe = |(key, asc, ascq): (u8, u8, u8)| crate::platform::describe_sense(key, asc, ascq);
    match error {
        FlashError::Entry(e) => mtk_err(e).context(
            "MediaTek PROBE, TEST UNIT READY or PREPARE failed before any firmware data was \
             sent; if PREPARE was reached the drive may be in update mode — power-cycle it \
             before retrying",
        ),
        FlashError::Transfer {
            offset,
            length,
            source,
        } => mtk_err(source).context(format!(
            "firmware write failed at offset {offset:#x}, length {length}; drive may contain \
             partial firmware"
        )),
        FlashError::Fault {
            stage: Stage::Commit,
            sense,
        } => anyhow!(
            "drive reported an error after flash — {}; the flash may have FAILED",
            describe(sense)
        ),
        FlashError::Fault { sense, .. } => anyhow!(
            "post-settle sense reports a flash fault — {}; the flash may have FAILED. \
             Physically confirm the drive's firmware identity before shipping.",
            describe(sense)
        ),
        FlashError::ReadyTimeout(e) => anyhow!(
            "drive did not settle after the flash burn within {} s — TEST UNIT READY never came \
             back Ok. The flash may have FAILED, or the drive is hung; do NOT trust the exit \
             code as success. Physically power-cycle the drive and re-verify its firmware \
             identity before shipping. Last error: {}",
            class.ready_timeout().as_secs(),
            text(&e)
        ),
        FlashError::Mismatch {
            address,
            read,
            wrote,
            differing,
            checked,
        } => anyhow!(
            "read-back verify FAILED at 0x{address:06X}: an integrity-protected byte differs \
             (read 0x{read:02X}, wrote 0x{wrote:02X}) — the image did not program cleanly \
             ({differing} of {checked} protected bytes differ)."
        ),
        FlashError::Incomplete {
            unverified,
            checked,
        } => anyhow!(
            "flash complete but read-back INCOMPLETE: could not read back {unverified} \
             integrity-protected chunk(s) ({} verified). Do NOT trust the exit code as \
             success — physically confirm the drive's firmware identity before shipping.",
            style::human_size(checked),
        ),
        other => anyhow!("{other}"),
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

/// The re-read firmware identity is the authoritative proof that the new
/// image is resident and booted, so an unreadable identity fails the flash.
fn confirm_identity(mtk: &Mtk, dev: &mut ReadDevice<'_>) -> Result<()> {
    match mtk.post_flash_identity(dev) {
        Ok(Some(r)) => {
            let name = match r.matched {
                Some((desc, _)) => desc.to_string(),
                None => r.descriptor.unwrap_or_else(|| "unrecognized".into()),
            };
            println!(
                "{}",
                style::kv("firmware now", &format!("{name}  [{}]", r.fingerprint))
            );
            Ok(())
        }
        Ok(None) => bail!(
            "flash complete but drive did not report a firmware identity — the drive is \
             likely still re-enumerating or has failed to come back. Physically confirm \
             the drive is alive (`info /dev/sgX`) before treating this flash as successful."
        ),
        Err(e) => bail!(
            "flash complete but firmware-identity read-back errored ({e:#}); the drive \
             is not confirmed running the new image. Physically re-verify before \
             shipping."
        ),
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
        final_image: None,
        live: identity_of_image(image)?,
        receiver: detect_receiver(&mut ReadDevice::without_unlocks(dev))?,
        drive_product: "BD-RE BU40N".into(),
        verdict: Verdict::SameModel,
    }))
}

#[cfg(test)]
#[path = "stage_tests.rs"]
mod stage_tests;
