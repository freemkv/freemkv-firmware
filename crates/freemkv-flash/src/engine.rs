//! Generic command engine: `info` / `backup` / `flash`.
//!
//! This layer is **chip-agnostic**. It owns everything that does not depend on a
//! particular silicon: reading the input file, the pre-flash backup, the dry-run
//! plan, the streaming loop, read-back verification, and the safety gate. It
//! drives a [`DriveFamily`] purely through its trait primitives, so a new chip
//! (Pioneer, Renesas, …) reuses this loop unchanged — the engine calls
//! `drive.flash_stream(...)` without caring whose CDBs those are.
//!
//! Layering: `main` (CLI) → `engine` (this) → [`crate::drive`] (per-chip).

use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::drive::{BackupNotice, DriveFamily, FlashRequest, InputKind};
use crate::platform::{MediumStatus, ScsiDevice};
use crate::style;

pub(crate) mod backup;
pub(crate) mod device_info;
#[cfg(test)]
use crate::drive::mtk::backup::BackupArtifact;
use backup::save_backup;

/// Run the `info` command: identify + classify (read-only).
pub fn info(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily) -> Result<()> {
    println!("{}", style::kv("device", &dev.describe()));
    let id = drive.identity(dev);
    crate::output::field("Manufacturer", style::printable(&id.vendor));
    crate::output::field("Model", style::printable(&id.product));
    crate::output::field("Firmware version", style::printable(&id.revision));
    crate::output::field("Drive family", drive.family().to_string());
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
    // The single source of truth for what this family can do (see
    // drive::Capabilities). `info` is always on for a classified drive; the
    // headline is which of backup/flash are live.
    let caps = drive.capabilities();
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
        style::kv("family", &format!("{} ({})", drive.family(), capability))
    );
    // Show the flash line only when a runnable recipe exists for this family;
    // the capability label above already states flash availability otherwise.
    if let Some(set) = crate::flashset::FlashInstructionSet::for_family(drive.family()) {
        println!(
            "{}",
            style::kv("flash", &format!("{} — {}", set.name, set.status.label()))
        );
    }
    device_info::show(dev);
    drive.print_device_info(dev);
    // Best-effort firmware identification (read-only). `info` never aborts, so a
    // read failure here is simply omitted.
    if let Ok(Some(r)) = drive.firmware_report(dev) {
        match r.matched {
            Some(m) => {
                println!("{}", style::kv("firmware", m.desc));
                if !m.source.is_empty() {
                    println!(
                        "{}",
                        style::dim_line(&format!("          original image: {}", m.source))
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

    for backend in crate::drive::backends() {
        if let Some(report) = backend.describe_file(&image) {
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
pub fn backup(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    out: &Path,
    recover: bool,
    force: bool,
) -> Result<()> {
    backup_with_replace(dev, drive, out, recover, force, false)
}

/// Capture a backup/dump and optionally replace a destination confirmed by the caller.
/// Replacement happens only after the new artifact is written and validated.
pub fn backup_with_replace(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    out: &Path,
    recover: bool,
    force: bool,
    replace: bool,
) -> Result<()> {
    if !drive.capabilities().backup {
        bail!("no firmware backup capability for {}", drive.backend_name());
    }
    let kind = drive.backup_kind();
    // Fail fast before the multi-minute capture if the output already exists.
    if !replace && out.symlink_metadata().is_ok() {
        bail!(
            "backup {} already exists (backups are never overwritten); choose another -o path or remove it",
            out.display()
        );
    }
    let target_model = drive.identity(dev).product;
    println!(
        "{} {}",
        style::bold("Backing up"),
        style::dim(&format!(
            "{} \u{2192} {}",
            target_model.trim(),
            out.display()
        ))
    );
    // `recover` (the `dump` command) uses the family's salvage capture; `force`
    // tells it to stop trusting what the drive reports (never kernel mode).
    // Families without a distinct dump capture a normal backup.
    let bytes = if recover {
        drive.capture_dump(dev, force)?
    } else {
        drive.capture_backup(dev)?
    };
    let raw_dump = recover && drive.dump_is_raw();
    let saved_len = if raw_dump {
        // A raw memory image is saved verbatim as ONE file: it is not a backup
        // archive, so only require that something was read.
        backup::save_validated_with_replace(out, &bytes, replace, |b| {
            if b.is_empty() {
                bail!("dump is empty");
            }
            Ok(())
        })?
    } else {
        backup::save_validated_with_replace(out, &bytes, replace, |candidate| {
            drive.validate_backup(candidate, &target_model).map(|_| ())
        })?
    };
    println!(
        "{}",
        style::kv(
            &format!("{} sha256", kind.infix),
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
    if raw_dump {
        crate::output::field("Artifact", "Raw memory dump — not a flashable backup");
        println!(
            "{}",
            style::amber(
                "RAW DUMP: device memory and diagnostic sections; NOT a flashable backup."
            )
        );
        return Ok(());
    }
    match drive.backup_notice(&bytes) {
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

/// Run the `flash` command: `.bin` = full image, `.tar` = firmware rollback archive.
pub fn flash(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, req: &FlashRequest) -> Result<()> {
    if let Some(plan) = drive.offline_plan(req) {
        return plan;
    }
    guard_no_medium(dev, req.execute, req.force || req.recover)?;
    // Whole-package executors (e.g. a Pioneer OEM update session) own the
    // execute flow, but only AFTER the shared safety gate and a captured
    // pre-flash backup — the same invariants the image-chunk path enforces.
    if req.execute && drive.flash_is_bundle() {
        if let Err(block) = check_safety(req.acknowledged_risk) {
            bail!("SAFETY GATE: {}", block.0);
        }
        let (backup_summary, backup_bytes) = capture_preflash_backup(dev, drive, req)?;
        // Re-check the tray right before any write (the backup opened a
        // multi-round-trip window; a disc/tray change is the same hazard class).
        guard_no_medium(dev, req.execute, req.force || req.recover)?;
        println!("{}", style::kv("backup", &backup_summary));
        return drive
            .flash_bundle(dev, req, backup_bytes.as_deref())
            .unwrap_or_else(|| {
                bail!(
                    "{} declares a bundle flash but provides none",
                    drive.backend_name()
                )
            });
    }
    match req.input_kind {
        InputKind::Tar => flash_restore(dev, drive, req),
        InputKind::Bin => flash_bin(dev, drive, req),
        InputKind::PioneerBundle => bail!(
            "a Pioneer firmware bundle cannot be flashed to this {} drive",
            drive.backend_name()
        ),
    }
}

/// Capture the installed firmware unless force or skip-backup bypasses capture.
/// Forced flashes do not attempt backup reads, validation, or file creation.
/// Returns a summary and optional captured bytes for the bundle executor.
fn capture_preflash_backup(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    req: &FlashRequest,
) -> Result<(String, Option<Vec<u8>>)> {
    if req.force {
        let warning = "SKIPPED (--force): no pre-flash backup attempted; no rollback artifact";
        crate::output::field("Backup warning", warning);
        eprintln!("{warning}");
        return Ok((warning.to_string(), None));
    }
    capture_required_backup(dev, drive, req)
}

fn capture_required_backup(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    req: &FlashRequest,
) -> Result<(String, Option<Vec<u8>>)> {
    if req.skip_backup {
        eprintln!(
            "{}",
            style::amber(
                "WARNING: --skip-backup set; flashing with NO pre-flash backup. A failed \
                 write may be unrecoverable."
            )
        );
        return Ok((
            "SKIPPED (--skip-backup): no rollback artifact".to_string(),
            None,
        ));
    }
    let out = req
        .predump_out
        .as_ref()
        .context("no preflash backup path supplied")?;
    // Fail fast BEFORE the multi-minute capture read if the destination is taken
    // (backups are never overwritten) — far better than discovering it after.
    if out.symlink_metadata().is_ok() {
        bail!(
            "pre-flash backup path {} already exists (existing backups are never overwritten). \
             Move/remove it or pass --backup <new-path>.",
            out.display()
        );
    }
    let bytes = drive
        .capture_backup(dev)
        .context("pre-flash backup failed; aborting flash")?;
    let target_model = drive.identity(dev).product;
    let saved_len = save_backup(out, &bytes, drive, &target_model)
        .context("pre-flash backup failed; aborting flash")?;
    // Preserve a structurally valid capture before target-dependent checks.
    // A partial capture remains useful, but cannot authorize writing a region
    // it does not cover. No update command has been issued at this point.
    drive.verify_preflash_backup(&bytes, &req.input).with_context(|| {
        format!("backup saved to {}, but it is not a usable rollback for this update; aborting flash", out.display())
    })?;
    Ok((
        format!("saved {} ({} bytes)", out.display(), saved_len),
        Some(bytes),
    ))
}

/// Refuse to flash while a disc is loaded. Reprogramming the flash while the
/// drive is busy servicing a medium can wedge the controller mid-program (a
/// verify-mismatch / `DID_BAD_TARGET` brick that only a power-cycle clears), so
/// a firmware flash MUST run against an empty, closed tray. On `--execute` this
/// is a hard abort before any backup or write; on a dry run it is a prominent
/// warning so the operator ejects before committing.
///
/// `bypass` (set by `--force` OR `--recover`) means force: the medium/tray state
/// is reported as a warning but never blocks, and an UNREADABLE medium status is
/// tolerated too. A partially bricked drive routinely misreports its tray as open
/// / disc-present (or fails the status command outright); refusing on that would
/// lock the operator out of the recovery flash they explicitly asked for.
pub(crate) fn guard_no_medium(dev: &mut dyn ScsiDevice, execute: bool, force: bool) -> Result<()> {
    // Flashing is safe ONLY with a closed, empty tray. A loaded disc can wedge
    // the controller mid-program; an open tray is not a settled flash state.
    let status = match dev.medium_status() {
        Ok(status) => status,
        // Under --force a drive too degraded to even report medium status must
        // not be blocked from its recovery flash.
        Err(error) if force => {
            println!(
                "{}",
                style::amber(&format!(
                    "WARNING: could not read tray/medium status ({error:#}); \
                     proceeding anyway on --force."
                ))
            );
            return Ok(());
        }
        Err(error) => return Err(error).context("could not check whether the tray is closed and empty; refusing before firmware writes. Check the drive connection and retry"),
    };
    let (condition, action) = match status {
        MediumStatus::ClosedEmpty => return Ok(()),
        MediumStatus::DiscPresent => (
            "a disc is loaded",
            "Eject the disc, close the empty tray, and retry.",
        ),
        MediumStatus::TrayOpen => ("the tray is OPEN", "Close the empty tray and retry."),
    };
    if execute && !force {
        bail!("{condition} — refusing to flash. {action} This update pass has not started.");
    }
    let note = if force {
        "Proceeding because --force was supplied."
    } else {
        "An actual flash requires a closed, empty tray."
    };
    println!("{}", style::amber(&format!("WARNING: {condition}. {note}")));
    Ok(())
}

/// Flash a full `.bin` image VERBATIM: backup-first, stream, read-back verify.
///
/// Compare the decoded input against the backend's readable protected ranges.
/// Mutable per-unit regions and remapped boot bytes are excluded. A mismatch or
/// unavailable protected range fails verification; identity alone is insufficient.
fn flash_bin(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, req: &FlashRequest) -> Result<()> {
    // Image geometry, integrity, model, and any controller sub-family gate are
    // protocol decisions. The engine only enforces the common workflow.
    if req.force {
        drive.validate_forced_image(dev, &req.input)?;
    } else {
        drive.validate_image(dev, &req.input, &req.drive_model, req.allow_crossflash)?;
    }
    let (payload, enc) = drive.envelope(dev, &req.input, req.enc_override)?;

    // Unless explicitly bypassed, save a complete rollback before flash_stream.
    let backup_summary = if req.execute {
        if let Err(block) = check_safety(req.acknowledged_risk) {
            bail!("SAFETY GATE: {}", block.0);
        }
        capture_preflash_backup(dev, drive, req)?.0
    } else {
        "not captured (dry run)".to_string()
    };

    println!("{}", style::header("== flash plan =="));
    println!("{}", style::kv("device", &dev.describe()));
    println!(
        "{}",
        style::kv("drive", style::ident_or_unknown(&req.drive_model))
    );
    drive.print_flash_notes(&req.input, &req.drive_model, req.allow_crossflash);
    println!(
        "{}",
        style::kv(
            "firmware",
            &format!(
                "{} ({} envelope)",
                style::human_size(payload.len()),
                if enc { "encrypted" } else { "plaintext" }
            )
        )
    );
    println!("{}", style::kv("backup", &backup_summary));
    println!();
    print!("{}", drive.flash_plan(payload.len(), req.verbose)?);

    if !req.execute {
        // Read-only readiness handshake (PROBE + TEST UNIT READY) — issues NO
        // write — so a dry-run surfaces a not-ready drive up front, before the
        // operator commits to --execute. A benign no-disc drive passes.
        match drive.preflight(dev) {
            Ok(()) => println!(
                "{}",
                style::status_line(
                    "preflight",
                    "transport ready; backup capture is checked only on execute",
                    style::Status::Ok
                )
            ),
            Err(e) => bail!("read-only preflight failed: {e}"),
        }
        println!(
            "\n{}",
            style::amber("DRY RUN: no firmware writes or backup capture. Execute may still fail if a complete rollback image cannot be read.")
        );
        return Ok(());
    }

    // Execution-tier gate: a real (destructive) write is allowed ONLY for a
    // hardware-proven, issuable instruction set. Today that is MT1959 (the MTK
    // family); catalog-only / transport-gated families are dry-run/plan only and
    // must never issue a write, even with --execute.
    if !drive.capabilities().flash {
        bail!(
            "refusing to flash: {} has no executable flash capability",
            drive.backend_name()
        );
    }

    // Safety gate only on the write path.
    if let Err(block) = check_safety(req.acknowledged_risk) {
        bail!("SAFETY GATE: {}", block.0);
    }

    // Final tray/medium re-check: the top-of-function `guard_no_medium` runs
    // before the pre-flash dump, CMAC verify, crossflash gate, and plan
    // print — a multi-SCSI-round-trip window in which a user could
    // physically insert a disc or the drive could report a settling tray
    // as loaded. The write path is the whole reason the guard exists, so
    // re-probe RIGHT before `flash_stream`; a stale check is the same class
    // of hazard as no check at all (drive controller can wedge mid-program
    // when servicing a medium).
    guard_no_medium(dev, req.execute, req.force || req.recover)?;
    println!(
        "\n{}",
        style::bold("EXECUTING flash — do not power off or disconnect the drive...")
    );
    let chunk = drive.chunk_size();
    let mut progress = style::Progress::new("flashing firmware", payload.len());
    drive.flash_stream(dev, &payload, req.mode, &mut |sent| progress.set(sent))?;
    println!(
        "upload complete {}",
        style::dim(&format!(
            "({}); waiting for the drive to finish programming...",
            style::human_size(payload.len())
        ))
    );
    // The drive keeps programming its flash after the last chunk (it reports
    // NOT READY / LONG WRITE IN PROGRESS). Wait for it to finish before reading
    // back, so a SUCCESSFUL flash never surfaces a scary mid-program error.
    drive.wait_ready(dev)?;
    println!("verifying...");

    // The backend defines which image bytes can be compared after programming.
    // On MTK these are CMAC-covered ranges outside the remapped boot page.
    let protected = drive.verification_ranges(&req.input)?;
    let is_protected = |pos: usize| protected.iter().any(|&(s, e)| pos >= s && pos <= e);

    let mut checked = 0usize; // protected + readable bytes we compared
    let mut differing = 0usize; // of those, how many differed
    let mut unverified = 0usize; // protected chunks we could not read back
    let mut first_bad: Option<(usize, u8, u8)> = None;
    let mut offset = 0usize;
    for piece in req.input.chunks(chunk) {
        // Does this chunk cover any comparable (protected, past-boot) byte?
        let has_protected = (offset..offset + piece.len()).any(&is_protected);
        match drive.readback(dev, offset, piece.len()) {
            Ok(got) if got.len() == piece.len() => {
                for (i, (a, b)) in got.iter().zip(piece).enumerate() {
                    let pos = offset + i;
                    if !is_protected(pos) {
                        continue;
                    }
                    checked += 1;
                    if a != b {
                        differing += 1;
                        first_bad.get_or_insert((pos, *a, *b));
                    }
                }
            }
            // Errored or short read-back of a protected chunk: it stays
            // unverified, so the success message below must not claim it.
            result if has_protected => {
                unverified += 1;
                let reason = match result {
                    Ok(data) => format!("short read: {}/{}", data.len(), piece.len()),
                    Err(error) => format!("{error:#}"),
                };
                crate::diagnostics::record(format!(
                    "read-back incomplete: offset={offset:#x} length={} reason={reason}",
                    piece.len()
                ));
            }
            _ => {}
        }
        offset += piece.len();
    }
    if let Some((pos, read, wrote)) = first_bad {
        // A differing byte INSIDE a CMAC-protected range is genuine corruption:
        // these are exactly the bytes the drive authenticates at boot. Bytes
        // outside those ranges are drive-owned and never compared (see fn doc).
        bail!(
            "read-back verify FAILED at 0x{pos:06X}: an integrity-protected byte differs \
             (read 0x{read:02X}, wrote 0x{wrote:02X}) — the image did not program cleanly \
             ({differing} of {checked} protected bytes differ)."
        );
    }
    if protected.is_empty() {
        println!(
            "{}",
            style::dim_line(
                "  read-back cross-check: image carries no integrity table; \
                 relying on the drive's firmware identity below."
            )
        );
    } else if unverified > 0 {
        // Some protected chunks could not be read back — verification is
        // incomplete and the flash's success is NOT confirmed. On a "final
        // prod flash" workflow the caller has to know this before shipping,
        // so surface it as a hard error rather than a warning + exit 0. If
        // an operator explicitly wants to proceed with an incomplete
        // read-back, they can re-run `info` after the drive re-enumerates
        // and inspect the fingerprint themselves.
        bail!(
            "flash complete but read-back INCOMPLETE: could not read back {unverified} \
             integrity-protected chunk(s) ({} verified). Do NOT trust the exit code as \
             success — physically confirm the drive's firmware identity before shipping.",
            style::human_size(checked),
        );
    } else {
        println!(
            "{}",
            style::status_line(
                "flash complete",
                &format!(
                    "{} of integrity-protected regions verified",
                    style::human_size(checked)
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
    // Positive proof the new firmware is resident and booted. The
    // firmware-identity readback IS the authoritative "flash succeeded"
    // signal on this platform, so an unreadable identity here is not an
    // acceptable exit state — bail! rather than merely printing a dim line
    // and returning Ok. Callers that only care about "flash bytes shipped"
    // and not "drive is confirmed running the new firmware" can inspect
    // the error class; this at least stops the exit code from claiming
    // success on a drive that never came back cleanly.
    match drive.firmware_report(dev) {
        Ok(Some(r)) => match r.matched {
            Some(m) => println!(
                "{}",
                style::kv("firmware now", &format!("{}  [{}]", m.desc, r.fingerprint))
            ),
            None => println!(
                "{}",
                style::kv(
                    "firmware now",
                    &format!(
                        "{}  [{}]",
                        r.descriptor.as_deref().unwrap_or("unrecognized"),
                        r.fingerprint
                    )
                )
            ),
        },
        // The drive is still re-enumerating (or reports nothing): we can't
        // confirm the resident firmware here. Refuse to exit 0 on that.
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
    Ok(())
}

/// Restore per-unit regions from a `.tar` (targeted writes, not a full stream).
/// Refuse to flash an image whose drive-descriptor model does not name this
/// drive. Fails closed — unidentifiable image, unknown drive product, or model
/// mismatch all abort, with no override.
///
/// Family identification is delegated to the shared [`freemkv_chipset::detect_chip`]
/// — the SAME `MTEKMT19xx` pattern-search the modify tool uses — so the two tools
/// never disagree on a firmware image's family, and byte-shifted extractions
/// (where the old fixed-offset `0x1EC034` read missed) are still recognized. The
/// model-vs-drive cross-check is retained as a secondary guard.
fn flash_restore(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    req: &FlashRequest,
) -> Result<()> {
    let firmware = if req.force {
        drive.validate_forced_backup(&req.input, &req.drive_model)?
    } else {
        drive.validate_backup(&req.input, &req.drive_model)?
    };
    println!(
        "{}",
        style::header("== reflash backup firmware (per-unit data retained as reference) ==")
    );
    let mut firmware_req = req.clone();
    firmware_req.input = firmware;
    firmware_req.input_kind = InputKind::Bin;
    firmware_req.allow_crossflash = false;
    // The full image uses the same proven MTK update path. Per-unit members are
    // coherence/reference data, not separate post-reboot writes.
    flash_bin(dev, drive, &firmware_req)?;
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
