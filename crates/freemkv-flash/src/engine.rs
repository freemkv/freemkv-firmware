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
    FlashPlan, FlashRequest, PlanLine, ReadDevice, SavedBackup, UNKNOWN_FAMILY,
};
use crate::platform::{MediumStatus, ScsiDevice};
use crate::style;

pub(crate) mod backup;
pub(crate) mod device_info;
pub mod gates;
#[cfg(test)]
use crate::backends::mtk::backup::BackupArtifact;
use backup::save_backup;

/// Run the `info` command: identify + classify (read-only). `drive` is the
/// matched backend, or `None` for a drive no backend recognizes.
pub fn info(dev: &mut dyn ScsiDevice, drive: Option<&dyn Backend>) -> Result<()> {
    println!("{}", style::kv("device", &dev.describe()));
    let unlocks = drive.map_or(&[][..], |d| d.allowed_data_out());
    let mut dev = ReadDevice::new(dev, unlocks);
    let dev = &mut dev;
    let id = match drive {
        Some(drive) => drive.identity(dev),
        None => read_identity(dev),
    };
    let family = drive.map_or(UNKNOWN_FAMILY, |d| d.descriptor().display_name);
    crate::output::field("Manufacturer", style::printable(&id.vendor));
    crate::output::field("Model", style::printable(&id.product));
    crate::output::field("Firmware version", style::printable(&id.revision));
    crate::output::field("Drive family", family);
    println!(
        "{}",
        style::kv(
            "inquiry",
            &format!(
                "vendor='{}' product='{}' rev='{}'",
                style::printable(&id.vendor),
                style::printable(&id.product),
                style::printable(&id.revision)
            )
        )
    );
    println!(
        "{}",
        style::kv(
            "banner",
            &id.banner
                .as_deref()
                .map(style::printable)
                .unwrap_or_else(|| "<none>".to_string())
        )
    );
    // What the backend's facets offer; the headline is which of backup/flash
    // are live.
    let caps = drive.map_or(Capabilities::NONE, Capabilities::of);
    crate::output::field(
        "Backup",
        if caps.backup {
            "Supported"
        } else {
            "Unavailable"
        },
    );
    crate::output::field(
        "Firmware update",
        if caps.flash {
            "Supported"
        } else {
            "Unavailable"
        },
    );
    let capability = match (caps.backup, caps.flash) {
        (_, true) => style::green("live backup + flash supported"),
        (true, false) => style::amber("live backup supported; live flash unavailable"),
        (false, false) => style::amber("live backup/flash unavailable"),
    };
    println!(
        "{}",
        style::kv("family", &format!("{family} ({capability})"))
    );
    // Show the flash line only when a runnable recipe exists for this family;
    // the capability label above already states flash availability otherwise.
    if let Some(summary) = drive.and_then(|d| d.descriptor().flash_summary) {
        println!("{}", style::kv("flash", summary));
    }
    let details = drive.and_then(|d| d.details());
    device_info::show(dev, details.is_some_and(|d| d.vendor_snapshot()));
    let Some(details) = details else {
        return Ok(());
    };
    details.print_fields(dev);
    // Best-effort firmware identification (read-only). `info` never aborts, so a
    // read failure here is simply omitted.
    if let Ok(Some(r)) = details.post_flash_identity(dev) {
        match r.matched {
            Some((desc, source)) => {
                println!("{}", style::kv("firmware", desc));
                if !source.is_empty() {
                    println!(
                        "{}",
                        style::dim_line(&format!("          original image: {source}"))
                    );
                }
            }
            None => println!(
                "{}",
                style::kv(
                    "firmware",
                    &format!(
                        "{} {}",
                        style::printable(r.descriptor.as_deref().unwrap_or("unknown")),
                        style::amber("(unrecognized — not in the built-in catalog)")
                    )
                )
            ),
        }
        println!(
            "{}",
            style::dim_line(&format!("          fingerprint {}", r.fingerprint))
        );
    }
    Ok(())
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
    crate::output::field("File", path.display().to_string());
    crate::output::field("Size", style::human_size(image.len()));
    let mut hasher = Sha256::new();
    hasher.update(&image);
    let sha: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("{}", style::kv("sha256", &sha));

    for backend in crate::backend::registry::file_backends() {
        if let Some(report) = backend.files().and_then(|f| f.describe(&image)) {
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
    let unlocks = drive.allowed_data_out();
    let target_model = drive.identity(&mut ReadDevice::new(dev, unlocks)).product;
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
                dump.capture(DeviceAccess::Read(&mut ReadDevice::new(dev, unlocks)))?
            } else {
                dump.capture(DeviceAccess::Write(&mut gates::dump(dev, dump.writes())))?
            };
            (bytes, None)
        }
        (false, _, Some(facet)) => (
            facet.capture(&mut ReadDevice::new(dev, unlocks))?,
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
    crate::output::field("Saved to", out.display().to_string());
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
    // amber "unverified" advisory naming what is not OEM.
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
            crate::output::field("Backup validation", &msg);
            println!("{}", style::green(&msg));
        }
        BackupNotice::Unverified(msg) => {
            crate::output::field("Backup warning", &msg);
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
) -> Result<()> {
    let facet = drive
        .recovery()
        .with_context(|| format!("{} offers no recovery", drive.descriptor().id))?;
    if execute {
        let mut writer = gates::recovery(dev, execute, acknowledged_risk)?;
        facet.recover(DeviceAccess::Write(&mut writer), current, target)
    } else {
        let mut reader = ReadDevice::new(dev, drive.allowed_data_out());
        facet.recover(DeviceAccess::Read(&mut reader), current, target)
    }
}

/// Run the `flash` command in two read-only stages around the backup:
///
/// * dry run: tray warning, `plan`, the plan, the backend's preflight;
/// * execute: tray, `plan`, acknowledgement, backup (saved, read back, and
///   covering the update), the plan, `authorize`, the front-end's `confirm`,
///   tray again, then the write through a `gates::flash` grant.
pub fn flash(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    req: &FlashRequest,
    confirm: &mut dyn Confirm,
) -> Result<()> {
    let facet = flash_facet(drive)?;
    let plan = plan_flash(dev, drive, req)?;
    if !req.execute {
        return dry_run(dev, drive, facet, &plan).map(drop);
    }
    if let Err(block) = check_safety(req.acknowledged_risk) {
        bail!("SAFETY GATE: {}", block.0);
    }
    let saved = capture_required_backup(dev, drive, facet, &plan, req)?;
    emit_plan(&plan.after_backup, saved.summary());
    let reader = &mut ReadDevice::new(dev, drive.allowed_data_out());
    let authorized = facet.authorize(reader, plan, &saved)?;
    for warning in &authorized.warnings {
        eprintln!("{}", style::amber(warning));
    }
    if let Some(text) = &authorized.confirmation {
        println!("{}", style::bold(text));
        if !confirm.confirm(&authorized)? {
            bail!("flash aborted at confirmation prompt");
        }
    }
    // The last tray check sits right before the first write: the backup and
    // the confirmation left a window for a disc to be loaded.
    guard_no_medium(dev, true)?;
    let mut writer = gates::flash(dev, req, &saved)?;
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
    let plan = facet.plan(&mut ReadDevice::new(dev, drive.allowed_data_out()), req)?;
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
    let tail = facet.preflight(&mut ReadDevice::new(dev, drive.allowed_data_out()), plan)?;
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

/// Capture, save, read back and coverage-check the mandatory pre-flash backup.
/// The proof carries the captured bytes (the installed firmware).
fn capture_required_backup(
    dev: &mut dyn ScsiDevice,
    drive: &dyn Backend,
    flash: &dyn FlashFacet,
    plan: &FlashPlan,
    req: &FlashRequest,
) -> Result<SavedBackup> {
    let out = req
        .predump_out
        .as_ref()
        .context("no preflash backup path supplied")?;
    // Fail fast, before the multi-minute capture, if the destination is taken.
    if out.symlink_metadata().is_ok() {
        bail!(
            "pre-flash backup path {} already exists (existing backups are never overwritten). \
             Move/remove it or pass --backup <new-path>.",
            out.display()
        );
    }
    let backup = drive.backup().with_context(|| {
        format!(
            "no proven restorable firmware backup for {}",
            drive.descriptor().id
        )
    })?;
    let unlocks = drive.allowed_data_out();
    let bytes = backup
        .capture(&mut ReadDevice::new(dev, unlocks))
        .context("pre-flash backup failed; aborting flash")?;
    let target_model = drive.identity(&mut ReadDevice::new(dev, unlocks)).product;
    let saved_len = save_backup(out, &bytes, backup, &target_model)
        .context("pre-flash backup failed; aborting flash")?;
    // A partial capture stays saved, but cannot authorize writing a region it
    // does not cover. No update command has been issued at this point.
    flash.verify_backup(plan, &bytes).with_context(|| {
        format!(
            "backup saved to {}, but it is not a usable rollback for this update; aborting flash",
            out.display()
        )
    })?;
    Ok(SavedBackup::new(out, bytes, saved_len))
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
