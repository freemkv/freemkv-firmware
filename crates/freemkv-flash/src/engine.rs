//! Generic command engine: `info` / `backup` / `flash`.
//!
//! This layer is **chip-agnostic**. It owns the workflow that does not depend
//! on a particular drive: the tray and safety gates, the mandatory pre-flash
//! backup, the order of the two read-only flash stages, and showing their
//! plans. It drives a [`Backend`] through its facets: read-only calls get a
//! [`ReadDevice`], and writes get a `WriteDevice` from [`gates`] only.
//!
//! Layering: `main` (CLI) → `engine` (this) → [`crate::backend`] (contract).

use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::backend::{
    read_identity, Backend, BackupNotice, Capabilities, Confirm, DeviceAccess, FlashFacet,
    FlashPlan, FlashRequest, InfoSoFar, PlanLine, ReadDevice, RecoveryTarget, SavedBackup,
    UNKNOWN_FAMILY,
};
use crate::platform::{MediumStatus, ScsiDevice};
use crate::report::{Group, Report, Row, Slot, Span, Tone, Value};
use crate::style;

pub(crate) mod backup;
pub mod gates;
#[cfg(test)]
use crate::backends::mtk::backup::BackupArtifact;
use backup::save_backup;

/// Run the `info` command: identify + classify (read-only). `drive` is the
/// matched backend, or `None` for a drive no backend recognizes.
pub fn info(dev: &mut dyn ScsiDevice, drive: Option<&dyn Backend>) -> Result<()> {
    let info = info_report(dev, drive);
    let (before, after) = info.report.rows.split_at(info.settings_at);
    crate::output::show(&Report {
        rows: before.to_vec(),
    });
    if let Some(settings) = info.settings {
        crate::output::publish(crate::output::Event::DeviceSettings(settings));
    }
    crate::output::show(&Report {
        rows: after.to_vec(),
    });
    Ok(())
}

/// A drive's `info` rows, without showing them.
pub struct InfoReport {
    /// Every row, in display order.
    pub report: Report,
    /// The drive settings the backend read, when it reads any.
    pub settings: Option<crate::output::device_settings::Settings>,
    /// Index of the first row after the settings were read.
    pub settings_at: usize,
}

/// Build the `info` report (read-only): the identity header, the standard
/// snapshot, and the backend's rows at their slots, issuing today's reads in
/// today's order.
pub fn info_report(dev: &mut dyn ScsiDevice, drive: Option<&dyn Backend>) -> InfoReport {
    let describe = dev.describe();
    let mut dev = match drive {
        Some(d) => ReadDevice::for_backend(dev, d),
        None => ReadDevice::without_unlocks(dev),
    };
    let dev = &mut dev;
    let id = match drive {
        Some(drive) => drive.identity(dev),
        None => read_identity(dev),
    };
    let family = drive.map_or(UNKNOWN_FAMILY, |d| d.descriptor().display_name);
    let caps = drive.map_or(Capabilities::NONE, Capabilities::of);
    let supported = |on: bool| Value::text(if on { "Supported" } else { "Unavailable" });
    let (tone, capability) = match (caps.backup, caps.flash) {
        (_, true) => (Tone::Ok, "live backup + flash supported"),
        (true, false) => (Tone::Warn, "live backup supported; live flash unavailable"),
        (false, false) => (Tone::Warn, "live backup/flash unavailable"),
    };
    let mut rows = vec![
        Row::cli("device", "device", Value::text(&describe)),
        Row::gui("vendor", "Manufacturer", Value::text(&id.vendor)),
        Row::gui("product", "Model", Value::text(&id.product)),
        Row::gui("revision", "Firmware version", Value::text(&id.revision)),
        Row::gui("family", "Drive family", Value::text(family)),
        Row::cli(
            "inquiry",
            "inquiry",
            Value::text(&format!(
                "vendor='{}' product='{}' rev='{}'",
                id.vendor, id.product, id.revision
            )),
        ),
        Row::cli(
            "banner",
            "banner",
            Value::text(id.banner.as_deref().unwrap_or("<none>")),
        ),
        Row::gui("backup", "Backup", supported(caps.backup)).in_group(Group::Operations),
        Row::gui("flash", "Firmware update", supported(caps.flash)).in_group(Group::Operations),
        Row::cli(
            "capability",
            "family",
            Value::Styled(vec![
                Span::new(Tone::Plain, &format!("{family} (")),
                Span::new(tone, capability),
                Span::new(Tone::Plain, ")"),
            ]),
        ),
    ];
    // The flash line appears only when the backend has a runnable recipe.
    if let Some(summary) = drive.and_then(|d| d.descriptor().flash_summary) {
        rows.push(Row::cli("flash_summary", "flash", Value::text(summary)));
    }
    let details = drive.and_then(|d| d.details());
    let slot = |slot: Slot, dev: &mut ReadDevice<'_>, read: &InfoSoFar<'_>, rows: &mut Vec<Row>| {
        if let Some(details) = details {
            rows.extend(details.rows(dev, read, slot));
        }
    };
    let standard = crate::standard::read(dev);
    let mut read = InfoSoFar {
        standard: &standard,
        settings: None,
    };
    slot(Slot::AfterIdentity, dev, &read, &mut rows);
    rows.extend(standard.interface_rows());
    slot(Slot::AfterInterface, dev, &read, &mut rows);
    rows.extend(standard.media_rows());
    slot(Slot::AfterMedia, dev, &read, &mut rows);
    rows.extend(crate::standard::region_rows(dev));
    let settings = drive.and_then(|d| d.settings()).map(|s| s.read(dev));
    read.settings = settings.as_ref();
    let settings_at = rows.len();
    slot(Slot::AfterRegion, dev, &read, &mut rows);
    slot(Slot::End, dev, &read, &mut rows);
    // Best-effort firmware identification; `info` never aborts on it.
    if let Some(Ok(Some(r))) = details.map(|d| d.post_flash_identity(dev)) {
        rows.extend(firmware_rows(&r));
    }
    InfoReport {
        report: Report { rows },
        settings: settings.and_then(Result::ok),
        settings_at,
    }
}

/// The CLI's installed-firmware lines.
fn firmware_rows(r: &crate::backend::FirmwareReport) -> Vec<Row> {
    let dim = |text: String| {
        Row::line(
            "firmware_detail",
            Value::Styled(vec![Span::new(Tone::Dim, &text)]),
        )
    };
    let mut rows = Vec::new();
    match r.matched {
        Some((desc, source)) => {
            rows.push(Row::cli("firmware", "firmware", Value::text(desc)));
            if !source.is_empty() {
                rows.push(dim(format!("          original image: {source}")));
            }
        }
        None => rows.push(Row::cli(
            "firmware",
            "firmware",
            Value::Styled(vec![
                Span::new(
                    Tone::Plain,
                    &format!("{} ", r.descriptor.as_deref().unwrap_or("unknown")),
                ),
                Span::new(Tone::Warn, "(unrecognized — not in the built-in catalog)"),
            ]),
        )),
    }
    rows.push(dim(format!("          fingerprint {}", r.fingerprint)));
    rows
}

/// Run the `info` command on a firmware FILE (read-only) — the file-side twin of
/// [`info`] on a device. Never writes and never needs a drive: it identifies the
/// chipset, capability, this tool's flash tier for it, and the image's CMAC
/// integrity, so a user can ask "what is this .bin and what can I do with it?"
/// and later know whether it matches a given drive (same family key both sides).
pub fn info_file(path: &Path) -> Result<()> {
    let image = crate::workflow::read_capped(path)
        .with_context(|| format!("reading firmware image {}", path.display()))?;
    println!("{}", style::kv("file", &path.display().to_string()));
    println!("{}", style::kv("size", &style::human_size(image.len())));
    crate::output::field("File", path.to_path_buf());
    crate::output::field("Size", style::human_size(image.len()));
    let mut hasher = Sha256::new();
    hasher.update(&image);
    let sha: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("{}", style::kv("sha256", &sha));

    if let Some((backend, recognized)) = crate::backend::registry::recognize(&image)? {
        if let Some(report) = backend
            .files()
            .and_then(|f| f.describe(&image, &recognized))
        {
            return report;
        }
    }
    info_file_other(&crate::imageid::identify(&image))
}

/// Report a firmware FILE that is NOT MediaTek MT19xx: a non-MTK family found by
/// the signature layer ([`crate::imageid`]), or an honest "unknown". Prints the
/// family, any model/rev extracted from the image (never the filename), the
/// honest flashability (offline planning is available for selected Pioneer
/// updater paths), and states
/// that these families carry no MT19xx-style signed CMAC table — so `info` never
/// prints INVALID for an image that simply has no integrity table.
fn info_file_other(id: &crate::imageid::ImageIdentity) -> Result<()> {
    use crate::imageid::ImageFamily;
    if id.family == ImageFamily::Unknown {
        println!(
            "{}",
            style::kv(
                "image",
                &style::amber(
                    "unrecognized — no known drive-family signature (truncated, packed, or an \
                     unsupported family)"
                )
            )
        );
        return Ok(());
    }
    println!("{}", style::kv("family", id.family.label()));
    let model = id.model.as_deref().unwrap_or("unknown (not in image)");
    let rev = id.rev.as_deref().unwrap_or("unknown");
    println!(
        "{}",
        style::kv("descriptor", &format!("model='{model}' rev='{rev}'"))
    );
    if let Some(note) = &id.note {
        println!("{}", style::dim_line(&format!("          {note}")));
    }
    println!("{}", style::kv("flash", &id.family.flash_summary()));
    println!(
        "{}",
        style::kv(
            "integrity",
            &style::amber("not applicable (this family has no MT19xx-style signed CMAC table)")
        )
    );
    Ok(())
}

/// Capture a complete firmware and per-unit rollback artifact. Any unreadable
/// firmware range makes the command fail without writing an archive.
pub fn backup(dev: &mut dyn ScsiDevice, drive: &dyn Backend, out: &Path, dump: bool) -> Result<()> {
    backup_with_replace(dev, drive, out, dump, false)
}

/// Capture a backup/dump and optionally replace a destination confirmed by the caller.
/// Replacement happens only after the new artifact is written and validated.
pub fn backup_with_replace(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    out: &Path,
    dump: bool,
    replace: bool,
) -> Result<()> {
    let id = drive.descriptor().id;
    let facet = drive.backup();
    if dump {
        drive
            .dump()
            .with_context(|| format!("no firmware dump capability for {id}"))?;
    } else if facet.is_none() {
        bail!("no firmware backup capability for {id}");
    }
    let infix = facet.map_or("dump", |f| f.format().infix);
    // Fail fast before the multi-minute capture if the output already exists.
    if !replace && out.symlink_metadata().is_ok() {
        bail!(
            "backup {} already exists (backups are never overwritten); choose another -o path or remove it",
            out.display()
        );
    }
    let target_model = drive
        .identity(&mut ReadDevice::for_backend(dev, drive))
        .product;
    println!(
        "{} {}",
        style::bold("Backing up"),
        style::dim(&format!(
            "{} \u{2192} {}",
            target_model.trim(),
            out.display()
        ))
    );
    let (bytes, facet) = match (dump, drive.dump(), facet) {
        // The `dump` command's salvage capture (never kernel mode). A dump that
        // declares writes gets a write grant limited to those commands.
        (true, Some(dump), _) => {
            let bytes = if dump.writes().is_empty() {
                dump.capture(DeviceAccess::Read(&mut ReadDevice::for_backend(dev, drive)))?
            } else {
                dump.capture(DeviceAccess::Write(&mut gates::dump(dev, dump.writes())))?
            };
            (bytes, None)
        }
        (false, _, Some(facet)) => (
            facet.capture(&mut ReadDevice::for_backend(dev, drive))?,
            Some(facet),
        ),
        _ => unreachable!("capabilities checked above"),
    };
    let saved_len = match facet {
        Some(facet) => backup::save_validated_with_replace(out, &bytes, replace, |candidate| {
            facet.validate(candidate, &target_model).map(|_| ())
        })?,
        // A raw memory image is saved verbatim as ONE file: it is not a backup
        // archive, so only require that something was read.
        None => backup::save_validated_with_replace(out, &bytes, replace, |b| {
            if b.is_empty() {
                bail!("dump is empty");
            }
            Ok(())
        })?,
    };
    println!(
        "{}",
        style::kv(
            &format!("{infix} sha256"),
            &format!("{:x}", Sha256::digest(&bytes))
        )
    );
    crate::output::field("Saved to", out.to_path_buf());
    println!(
        "{} {}",
        style::green("wrote"),
        style::dim(&format!(
            "{} ({}).",
            out.display(),
            style::human_size(saved_len)
        ))
    );
    // Provenance line, computed from the produced bytes: a byte-exact OEM
    // capture prints a green confirmation; anything reconstructed prints an
    // amber origin note describing the reconstructed update metadata.
    let Some(facet) = facet else {
        crate::output::field("Artifact", "Raw memory dump — not a flashable backup");
        println!(
            "{}",
            style::amber(
                "RAW DUMP: device memory and diagnostic sections; NOT a flashable backup."
            )
        );
        return Ok(());
    };
    match facet.notice(&bytes) {
        BackupNotice::VerifiedOem(msg) => {
            crate::output::field("Backup origin", &msg);
            println!("{}", style::green(&msg));
        }
        BackupNotice::Unverified(msg) => {
            crate::output::field("Backup origin", &msg);
            println!("{}", style::amber(&msg));
        }
        BackupNotice::None => {}
    }
    Ok(())
}

/// Run a backend's recovery: read-only on a dry run, through the recovery
/// write grant (execute + acknowledgement; no tray check, no backup) otherwise.
pub fn recover(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    current: Option<&[u8]>,
    target: &[u8],
    execute: bool,
    acknowledged_risk: bool,
) -> Result<crate::backend::UpdateOutcome> {
    recover_identified(
        dev,
        drive,
        None,
        current,
        target,
        execute,
        acknowledged_risk,
    )
}

/// [`recover`] for a receiver already identified (`receiver`), or identified
/// here when `None`. The recovery grant is checked before any I/O.
pub fn recover_identified(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    receiver: Option<RecoveryTarget>,
    current: Option<&[u8]>,
    target: &[u8],
    execute: bool,
    acknowledged_risk: bool,
) -> Result<crate::backend::UpdateOutcome> {
    let facet = drive
        .recovery()
        .with_context(|| format!("{} offers no recovery", drive.descriptor().id))?;
    let identify = |dev: &mut dyn ScsiDevice| -> Result<RecoveryTarget> {
        match receiver {
            Some(receiver) => Ok(receiver),
            None => facet
                .identify_with_current(&mut ReadDevice::for_backend(dev, drive), current)?
                .with_context(|| facet.unidentified()),
        }
    };
    if execute {
        let mut writer = gates::recovery(dev, execute, acknowledged_risk)?;
        let receiver = identify(&mut writer)?;
        facet.recover(DeviceAccess::Write(&mut writer), &receiver, current, target)
    } else {
        let receiver = identify(dev)?;
        let mut reader = ReadDevice::for_backend(dev, drive);
        facet.recover(DeviceAccess::Read(&mut reader), &receiver, current, target)
    }
}

/// Run the `flash` command in two read-only stages around the backup:
///
/// * dry run: tray warning, `plan`, the plan, the backend's preflight;
/// * execute: host output check, tray, `plan`, acknowledgement, readiness,
///   backup (saved, read back, and
///   covering the update), the plan, `authorize`, the front-end's `confirm`,
///   tray again, then the write through a `gates::flash` grant.
pub fn flash(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    req: &FlashRequest,
    confirm: &mut dyn Confirm,
) -> Result<crate::backend::UpdateOutcome> {
    let facet = flash_facet(drive)?;
    if req.execute {
        required_backup_path(req)?;
    }
    let plan = plan_flash(dev, drive, req)?;
    if !req.execute {
        return dry_run(dev, drive, facet, &plan).map(|_| crate::backend::UpdateOutcome::Planned);
    }
    if let Err(block) = check_safety(req.acknowledged_risk) {
        bail!("SAFETY GATE: {}", block.0);
    }
    facet.preflight(&mut ReadDevice::for_backend(dev, drive), &plan)?;
    let saved = capture_required_backup(dev, drive, facet, &plan, req, confirm)?;
    let backup_line = match &saved {
        Some(s) => s.summary().to_string(),
        None => {
            "NONE — flashing without a rollback backup (this drive cannot be rolled back)".into()
        }
    };
    emit_plan(&plan.after_backup, &backup_line);
    let reader = &mut ReadDevice::for_backend(dev, drive);
    let mut authorized = facet.authorize(reader, plan, saved.as_ref())?;
    authorized.set_backup(&backup_line);
    for warning in &authorized.warnings {
        eprintln!("{}", style::amber(warning));
    }
    if let Some(text) = &authorized.confirmation {
        println!("{}", style::bold(text));
    }
    let ask = authorized.confirmation.is_some() || confirm.asks_every_flash();
    if ask && !confirm.confirm(&authorized)? {
        bail!("flash aborted at confirmation prompt");
    }
    // The last tray check sits right before the first write: the backup and
    // the confirmation left a window for a disc to be loaded.
    guard_no_medium(dev, true)?;
    let mut writer = gates::flash(dev, req, saved.as_ref())?;
    facet.execute(&mut writer, &authorized)
}

/// The read-only first stage alone: the tray check (a warning on a dry run)
/// and the backend's plan, with its notes shown. Needs no backup.
pub fn plan_flash(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    req: &FlashRequest,
) -> Result<FlashPlan> {
    let facet = flash_facet(drive)?;
    if req.execute || facet.dry_run_uses_device() {
        guard_no_medium(dev, req.execute)?;
    }
    let plan = facet.plan(&mut ReadDevice::for_backend(dev, drive), req)?;
    emit_plan(&plan.notes, "");
    Ok(plan)
}

/// A dry run, for a front-end to show before asking for consent: the plan
/// and the preflight, as shown, rendered as text. No backup, no writes.
pub fn preview_flash(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    req: &FlashRequest,
) -> Result<Vec<String>> {
    if req.execute {
        bail!("a flash preview is a dry run");
    }
    let facet = flash_facet(drive)?;
    let plan = plan_flash(dev, drive, req)?;
    let lines = dry_run(dev, drive, facet, &plan)?;
    Ok(lines
        .iter()
        .map(|line| render_plan_line(line, DRY_RUN_BACKUP))
        .collect())
}

const DRY_RUN_BACKUP: &str = "not captured (dry run)";

/// Show the dry-run plan, then end with the backend's read-only preflight.
fn dry_run(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    facet: &dyn FlashFacet,
    plan: &FlashPlan,
) -> Result<Vec<PlanLine>> {
    emit_plan(&plan.dry_run, DRY_RUN_BACKUP);
    let tail = facet.preflight(&mut ReadDevice::for_backend(dev, drive), plan)?;
    emit_plan(&tail, "");
    Ok(plan
        .notes
        .iter()
        .chain(&plan.dry_run)
        .chain(&tail)
        .cloned()
        .collect())
}

fn flash_facet(drive: &dyn Backend) -> Result<&dyn FlashFacet> {
    drive.flash().with_context(|| {
        format!(
            "refusing to flash: {} has no executable flash capability",
            drive.descriptor().id
        )
    })
}

/// Print plan lines; `backup` fills the `backup:` line.
pub(crate) fn emit_plan(lines: &[PlanLine], backup: &str) {
    for line in lines {
        match line {
            PlanLine::Block(text) => print!("{text}"),
            line => println!("{}", render_plan_line(line, backup)),
        }
    }
}

/// One plan line as the terminal shows it.
pub fn render_plan_line(line: &PlanLine, backup: &str) -> String {
    match line {
        PlanLine::Header(text) => style::header(text),
        PlanLine::Field(label, value) => style::kv(label, value),
        PlanLine::Backup => style::kv("backup", backup),
        PlanLine::Text(text) => text.clone(),
        PlanLine::Warning(text) => style::amber(text),
        PlanLine::Ok(label, text) => style::status_line(label, text, style::Status::Ok),
        PlanLine::Block(text) => text.clone(),
        PlanLine::Spaced(line) => format!("\n{}", render_plan_line(line, backup)),
    }
}

/// Check host output before any potentially slow receiver reads; recheck before capture.
fn required_backup_path(req: &FlashRequest) -> Result<&Path> {
    let out = req
        .predump_out
        .as_deref()
        .context("no preflash backup path supplied")?;
    // Fail fast, before the multi-minute capture, if the destination is taken.
    if out.symlink_metadata().is_ok() {
        bail!(
            "pre-flash backup path {} already exists (existing backups are never overwritten). \
             Move/remove it or pass --backup <new-path>.",
            out.display()
        );
    }
    Ok(out)
}

/// Capture, save, read back and coverage-check the pre-flash backup.
///
/// `Ok(Some(_))`: a usable rollback was saved. `Ok(None)`: the backup could not
/// be produced (a drive whose firmware can't be read back, or a capture that is
/// not a usable rollback) AND the operator chose, at the prompt, to flash
/// anyway without one — every other safety gate still runs, there is just no
/// rollback. `Err`: no backup and the operator declined, or an environment
/// failure (missing path, disk) that is not the operator's to wave through.
fn capture_required_backup(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    flash: &dyn FlashFacet,
    plan: &FlashPlan,
    req: &FlashRequest,
    confirm: &mut dyn Confirm,
) -> Result<Option<SavedBackup>> {
    let out = required_backup_path(req)?;
    let backup = drive.backup().with_context(|| {
        format!(
            "no proven restorable firmware backup for {}",
            drive.descriptor().id
        )
    })?;
    // The drive-side backup problems (can't read the firmware back, or the read
    // isn't a usable rollback) are the ones the operator may consent past. A
    // missing path or a disk write failure is an environment error and still
    // hard-aborts.
    let bytes = match backup.capture(&mut ReadDevice::for_backend(dev, drive)) {
        Ok(bytes) => bytes,
        Err(error) => return offer_flash_without_backup(confirm, error),
    };
    let target_model = drive
        .identity(&mut ReadDevice::for_backend(dev, drive))
        .product;
    let saved_len = save_backup(out, &bytes, backup, &target_model)
        .context("pre-flash backup failed; aborting flash")?;
    // A partial capture stays saved, but cannot authorize writing a region it
    // does not cover. No update command has been issued at this point.
    if let Err(error) = flash.verify_backup(plan, &bytes) {
        let error = error.context(format!(
            "backup saved to {}, but it is not a usable rollback for this update",
            out.display()
        ));
        return offer_flash_without_backup(confirm, error);
    }
    Ok(Some(SavedBackup::new(out, bytes, saved_len)))
}

/// Ask the operator whether to flash without a rollback backup. `Ok(None)` on
/// yes (proceed, no backup); the original `error` on no.
fn offer_flash_without_backup(
    confirm: &mut dyn Confirm,
    error: anyhow::Error,
) -> Result<Option<SavedBackup>> {
    let reason = format!("{error:#}");
    if confirm.proceed_without_backup(&reason)? {
        eprintln!(
            "{}",
            style::amber(
                "Proceeding WITHOUT a rollback backup at your request. Every other safety check \
                 still applies.",
            )
        );
        Ok(None)
    } else {
        Err(error.context(
            "pre-flash backup failed and flashing without one was declined; aborting flash",
        ))
    }
}

/// Refuse to flash while a disc is loaded or the tray is open: reprogramming
/// while the drive services a medium can wedge the controller mid-program. On
/// `--execute` this aborts before any backup or write; a dry run warns.
pub(crate) fn guard_no_medium(dev: &mut dyn ScsiDevice, execute: bool) -> Result<()> {
    let status = dev.medium_status().context("could not check whether the tray is closed and empty; refusing before firmware writes. Check the drive connection and retry")?;
    let (condition, action) = match status {
        MediumStatus::ClosedEmpty => return Ok(()),
        MediumStatus::DiscPresent => (
            "a disc is loaded",
            "Eject the disc, close the empty tray, and retry.",
        ),
        MediumStatus::TrayOpen => ("the tray is OPEN", "Close the empty tray and retry."),
    };
    if execute {
        bail!("{condition} — refusing to flash. {action} This update pass has not started.");
    }
    println!(
        "{}",
        style::amber(&format!(
            "WARNING: {condition}. An actual flash requires a closed, empty tray."
        ))
    );
    Ok(())
}

// ---- Safety gate (generic) --------------------------------------------------

/// A blocked flash attempt, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyBlock(pub String);

/// Evaluate the pre-flash safety gate. `Ok(())` means the flash may proceed.
///
/// The write path is irreversible, so it requires the operator to have
/// acknowledged the bricking risk (`--i-understand-risk`).
pub fn check_safety(acknowledged_risk: bool) -> Result<(), SafetyBlock> {
    if !acknowledged_risk {
        return Err(SafetyBlock(
            "refusing to flash without --i-understand-risk (flashing can permanently brick the drive)"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
