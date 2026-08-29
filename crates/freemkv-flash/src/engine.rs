//! Generic command engine: `info` / `dump` / `flash`.
//!
//! This layer is **chip-agnostic**. It owns everything that does not depend on a
//! particular silicon: reading the input file, the pre-flash backup, the dry-run
//! plan, the streaming loop, read-back verification, and the safety gate. It
//! drives a [`DriveFamily`] purely through its trait primitives, so a new chip
//! (Pioneer, Renesas, …) reuses this loop unchanged — the engine calls
//! `drive.flash_chunk(...)` without caring whose CDBs those are.
//!
//! Layering: `main` (CLI) → `engine` (this) → [`crate::drive`] (per-chip).

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::drive::{DriveFamily, FlashRequest, InputKind, UserDump};
use crate::platform::ScsiDevice;

/// Run the `info` command: identify + classify (read-only).
pub fn info(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily) -> Result<()> {
    println!("device:   {}", dev.describe());
    let id = drive.identity(dev);
    println!(
        "inquiry:  vendor='{}' product='{}' rev='{}'",
        id.vendor, id.product, id.revision
    );
    println!("banner:   {}", id.banner.as_deref().unwrap_or("<none>"));
    println!(
        "family:   {} ({})",
        drive.family(),
        if drive.is_supported() {
            "supported"
        } else {
            "NOT supported (MediaTek MT19xx only)"
        }
    );
    Ok(())
}

/// Run the `dump` command: capture the per-unit regions to an interoperable tar.
pub fn dump(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, out: &Path) -> Result<()> {
    println!("device: {}", dev.describe());
    println!("family: {}", drive.family());
    println!("dumping per-unit regions...");
    let dump = drive.read_dump(dev)?;
    for (name, data) in dump.members() {
        println!("  {name:<16} {} bytes", data.len());
    }
    let tar = dump.to_tar_bytes()?;
    std::fs::write(out, &tar).with_context(|| format!("writing {}", out.display()))?;
    if let Some(sn) = dump.serial() {
        println!("serial:  {sn}");
    }
    if let Some(fw) = dump.fw_date() {
        println!("fw-date: {fw}");
    }
    println!("wrote {} ({} bytes, 6 members).", out.display(), tar.len());
    Ok(())
}

/// Run the `flash` command: `.bin` = full verbatim stream, `.tar` = per-unit restore.
pub fn flash(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, req: &FlashRequest) -> Result<()> {
    match req.input_kind {
        InputKind::Tar => flash_restore(dev, drive, req),
        InputKind::Bin => flash_bin(dev, drive, req),
    }
}

/// Flash a full `.bin` image VERBATIM: backup-first, stream, read-back verify.
fn flash_bin(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, req: &FlashRequest) -> Result<()> {
    let image_size = drive.image_size();
    if req.input.len() != image_size {
        bail!(
            "firmware .bin must be exactly {image_size} bytes, got {}",
            req.input.len()
        );
    }

    // ALWAYS attempt a pre-flash backup dump (never spliced into the image). On
    // failure, abort unless --rescue-no-dump.
    let mut backup_summary = String::from("skipped (--rescue-no-dump)");
    match drive.read_dump(dev) {
        Ok(dump) => {
            if let Some(out) = &req.predump_out {
                let tar = dump.to_tar_bytes()?;
                std::fs::write(out, &tar)
                    .with_context(|| format!("saving pre-flash dump to {}", out.display()))?;
                backup_summary = format!("saved {} ({} bytes)", out.display(), tar.len());
            } else {
                backup_summary = "captured (not saved: no -o given)".to_string();
            }
        }
        Err(e) => {
            if !req.rescue_no_dump {
                bail!(
                    "pre-flash per-unit dump failed ({e}); aborting. \
                     Use --rescue-no-dump ONLY to flash a drive that can no longer be read."
                );
            }
            println!("WARNING: pre-flash dump failed ({e}); --rescue-no-dump: proceeding without a backup.");
        }
    }

    let (payload, enc) = drive.envelope(dev, &req.input, req.enc_override)?;

    println!("== flash plan (verbatim) ==");
    println!("device:         {}", dev.describe());
    println!("drive model:    {}", ident_or_unknown(&req.drive_model));
    println!("mode:           {:?}", req.mode);
    println!("pre-flash dump: {backup_summary}");
    println!(
        "envelope:       {}",
        if enc {
            "enc (AES-128-ECB)"
        } else {
            "plaintext"
        }
    );
    println!();
    print!("{}", drive.flash_plan(payload.len())?);

    if !req.execute {
        println!("\nDRY RUN: no SCSI writes issued. Re-run with --execute to flash.");
        return Ok(());
    }

    // Full safety gate only on the write path.
    let ctx = SafetyContext {
        drive_model: &req.drive_model,
        firmware_model: &req.firmware_model,
        acknowledged_risk: req.acknowledged_risk,
        allow_cross_flash: req.allow_cross_flash,
    };
    if let Err(block) = check_safety(&ctx) {
        bail!("SAFETY GATE: {}", block.0);
    }

    println!("\nEXECUTING flash — do not power off or disconnect the drive...");
    drive.flash_open(dev, req.mode)?;
    let chunk = drive.chunk_size();
    let mut offset = 0usize;
    for piece in payload.chunks(chunk) {
        drive.flash_chunk(dev, offset, piece)?;
        offset += piece.len();
    }
    drive.flash_close(dev, req.mode)?;
    println!(
        "flash sequence complete ({} bytes streamed); verifying...",
        payload.len()
    );

    // Read-back verify each streamed chunk against what was sent.
    let mut offset = 0usize;
    for piece in payload.chunks(chunk) {
        let got = drive.readback(dev, offset, piece.len())?;
        if got != piece {
            bail!(
                "read-back verify failed at 0x{offset:06X}: {} bytes differ",
                got.iter().zip(piece).filter(|(a, b)| a != b).count()
            );
        }
        offset += piece.len();
    }
    println!("flash complete and read-back verified.");
    Ok(())
}

/// Restore per-unit regions from a `.tar` (targeted writes, not a full stream).
fn flash_restore(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    req: &FlashRequest,
) -> Result<()> {
    let dump = UserDump::from_tar_bytes(&req.input).context("parsing .tar restore input")?;
    let regions = drive.restore_regions(&dump);
    println!("== flash plan (restore from .tar) ==");
    for r in &regions {
        println!(
            "restore {}: 0x{:06X} ({} B)",
            r.label,
            r.offset,
            r.bytes.len()
        );
    }

    if !req.execute {
        println!("\nDRY RUN: no SCSI writes issued. Re-run with --execute to restore.");
        return Ok(());
    }
    let ctx = SafetyContext {
        drive_model: &req.drive_model,
        firmware_model: &req.firmware_model,
        acknowledged_risk: req.acknowledged_risk,
        allow_cross_flash: req.allow_cross_flash,
    };
    if let Err(block) = check_safety(&ctx) {
        bail!("SAFETY GATE: {}", block.0);
    }

    println!("\nEXECUTING restore — do not power off or disconnect the drive...");
    for r in &regions {
        drive.write_region(dev, r.offset, r.bytes)?;
        let got = drive.readback(dev, r.offset as usize, r.bytes.len())?;
        if got != r.bytes {
            bail!("read-back verify failed for region 0x{:06X}", r.offset);
        }
    }
    println!("restore complete and verified.");
    Ok(())
}

fn ident_or_unknown(s: &str) -> &str {
    if s.is_empty() {
        "<unknown>"
    } else {
        s
    }
}

// ---- Safety gate (generic) --------------------------------------------------

/// A blocked flash attempt, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyBlock(pub String);

/// Inputs to the pre-flash safety gate.
#[derive(Debug, Clone)]
pub struct SafetyContext<'a> {
    /// Model reported by the connected drive (INQUIRY product).
    pub drive_model: &'a str,
    /// Model string detected in the firmware image (may be empty).
    pub firmware_model: &'a str,
    /// User acknowledged the bricking risk (`--i-understand-risk`).
    pub acknowledged_risk: bool,
    /// User allowed a model mismatch (`--allow-cross-flash`).
    pub allow_cross_flash: bool,
}

/// Evaluate the safety gate. `Ok(())` means the flash may proceed.
///
/// An empty `firmware_model` cannot be cross-checked, so cross-flash is only
/// blocked when a model was detected and it does not match the drive.
pub fn check_safety(ctx: &SafetyContext<'_>) -> Result<(), SafetyBlock> {
    if !ctx.acknowledged_risk {
        return Err(SafetyBlock(
            "refusing to flash without --i-understand-risk (flashing can permanently brick the drive)"
                .to_string(),
        ));
    }
    if !ctx.firmware_model.is_empty() && !ctx.allow_cross_flash {
        let matches = ctx.drive_model.eq_ignore_ascii_case(ctx.firmware_model)
            || ctx.drive_model.contains(ctx.firmware_model)
            || ctx.firmware_model.contains(ctx.drive_model);
        if !matches {
            return Err(SafetyBlock(format!(
                "drive model '{}' does not match firmware model '{}'; refuse cross-flash without --allow-cross-flash",
                ctx.drive_model, ctx.firmware_model
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
