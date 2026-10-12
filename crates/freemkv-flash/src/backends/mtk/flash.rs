//! The MediaTek update in the engine's two stages. `plan` validates the image
//! against the live drive before any backup; `authorize` binds the pre-flash
//! backup as the installed firmware and lets `mediatek_optical` prepare the
//! update, refusing another hardware family; `execute` runs the prepared
//! update and re-identifies the firmware. The crate owns the session.

use anyhow::{anyhow, bail, Context, Result};
use mediatek_optical::drive::Error as DriveError;
use mediatek_optical::update::{
    FlashError, FlashRuntime, FlashTransport, InstalledFirmware, PrepareError, PreparedUpdate,
    Stage, Status,
};
use mediatek_optical::Identity;

use super::{
    backup, cdb, crossflash, describe_sequence, enc_needed, ensure_flashable_boot_page,
    live_identity, Mtk, DESCRIPTOR, IMAGE_SIZE,
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
    live: Identity,
    enc: bool,
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
            FormatRole::Image | FormatRole::Package => req.input.clone(),
        };
        let live = self.validate_image(dev, &image, &req.drive_model)?;
        let steps = live
            .class()
            .context("the drive names no update dialect; refusing")?
            .steps();
        let enc = req.enc_override.unwrap_or_else(|| enc_needed(dev));
        let mut block = vec![
            PlanLine::Header("== flash plan ==".into()),
            PlanLine::Field("device", dev.describe()),
            PlanLine::Field("drive", style::ident_or_unknown(&req.drive_model).into()),
            PlanLine::Field(
                "firmware",
                format!(
                    "{} ({} envelope)",
                    style::human_size(image.len()),
                    if enc { "encrypted" } else { "plaintext" }
                ),
            ),
            PlanLine::Backup,
            PlanLine::Text(String::new()),
        ];
        block.push(PlanLine::Block(describe_sequence(&steps, req.verbose)));
        let mut plan = FlashPlan::new(Plan { image, live, enc });
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
        backup: &SavedBackup,
    ) -> Result<AuthorizedPlan> {
        let state: &Plan = plan.state()?;
        let installed = InstalledFirmware::new(state.live.clone(), backup.bytes())
            .map_err(refusal)
            .context("the pre-flash backup cannot serve as this drive's installed firmware")?;
        let mut prepared = PreparedUpdate::prepare(&state.image, &installed).map_err(refusal)?;
        if state.enc {
            prepared = prepared.encrypted();
        }
        Ok(AuthorizedPlan::new(plan, prepared))
    }

    fn execute(&self, dev: &mut WriteDevice<'_>, authorized: &AuthorizedPlan) -> Result<()> {
        let prepared: &PreparedUpdate = authorized.state()?;
        let verified = {
            let shared = SharedDevice::new(dev);
            let (mut reads, mut writes) =
                (ScsiTransport::reads(&shared), ScsiTransport::flash(&shared));
            let io = FlashTransport {
                reads: &mut reads,
                writes: &mut writes,
            };
            let mut runtime = Runtime::new();
            prepared
                .flash(io, &mut runtime)
                .map_err(|e| flash_error(e, prepared))?
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
        confirm_identity(self, &mut ReadDevice::without_unlocks(dev))
    }
}

/// The text of a crate command error, keeping the transport's own chain.
fn text(error: &DriveError<anyhow::Error>) -> String {
    match error {
        DriveError::Transport(e) => format!("{e:#}"),
        other => other.to_string(),
    }
}

/// Progress and diagnostics for the crate's flash, in the flasher's words.
struct Runtime {
    start: std::time::Instant,
    progress: style::Progress,
}

impl Runtime {
    fn new() -> Self {
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
fn flash_error(error: FlashError<anyhow::Error>, prepared: &PreparedUpdate) -> anyhow::Error {
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
            prepared.class().ready_timeout().as_secs(),
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
        PrepareError::DriveDescriptor | PrepareError::UnknownDriveChip => {
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
    /// boot page the catalog knows, then the chip and hardware family against
    /// the live drive, then the model. Returns the live identity.
    pub(crate) fn validate_image(
        &self,
        dev: &mut ReadDevice<'_>,
        image: &[u8],
        drive_product: &str,
    ) -> Result<Identity> {
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
        let live = live_identity(dev);
        PreparedUpdate::check(image, &live).map_err(refusal)?;
        crossflash::ensure_image_matches_drive(image, drive_product)?;
        Ok(live)
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
