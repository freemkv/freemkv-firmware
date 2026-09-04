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

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::cmac;
use crate::drive::{DriveFamily, FlashRequest, InputKind, UserDump};
use crate::platform::ScsiDevice;
use crate::style;

/// Run the `info` command: identify + classify (read-only).
pub fn info(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily) -> Result<()> {
    println!("{}", style::kv("device", &dev.describe()));
    let id = drive.identity(dev);
    println!(
        "{}",
        style::kv(
            "inquiry",
            &format!(
                "vendor='{}' product='{}' rev='{}'",
                id.vendor, id.product, id.revision
            )
        )
    );
    println!(
        "{}",
        style::kv("banner", id.banner.as_deref().unwrap_or("<none>"))
    );
    let supported = drive.is_supported();
    println!(
        "{}",
        style::kv(
            "family",
            &format!(
                "{} ({})",
                drive.family(),
                if supported {
                    style::green("supported")
                } else {
                    style::amber("NOT supported (MediaTek MT19xx only)")
                }
            )
        )
    );
    // Flash recipe / execution tier for this family (from the declarative catalog).
    let recipe = match crate::flashset::FlashInstructionSet::for_family(drive.family()) {
        Some(set) => format!("{} — {}", set.name, set.status.label()),
        None => format!(
            "no executable recipe ({} brand recipes catalogued)",
            crate::flashset::CATALOG.len()
        ),
    };
    println!("{}", style::kv("flash", &recipe));
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
                        r.descriptor.as_deref().unwrap_or("unknown"),
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

/// Run the `dump` command: capture the per-unit regions to an interoperable tar.
pub fn dump(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, out: &Path) -> Result<()> {
    println!("{}", style::kv("device", &dev.describe()));
    println!("{}", style::kv("family", &drive.family().to_string()));
    println!("{}", style::dim_line("dumping per-unit regions..."));
    let dump = drive.read_dump(dev)?;
    for (name, data) in dump.members() {
        println!(
            "{}",
            style::dim_line(&format!("  {name:<16} {} bytes", data.len()))
        );
    }
    let tar = dump.to_tar_bytes()?;
    std::fs::write(out, &tar).with_context(|| format!("writing {}", out.display()))?;
    if let Some(sn) = dump.serial() {
        println!("{}", style::kv("serial", &sn));
    }
    if let Some(fw) = dump.fw_date() {
        println!("{}", style::kv("fw-date", &fw));
    }
    println!(
        "{} {}",
        style::green("wrote"),
        style::dim(&format!(
            "{} ({} bytes, 6 members).",
            out.display(),
            tar.len()
        ))
    );
    Ok(())
}

/// Run `dump`: EVERYTHING readable — the full 2 MiB image (`firmware.bin`,
/// graceful) + the 6 per-unit regions + the read-surface map (`map.json` +
/// `map.md`) — bundled into one `.tar`. Read-only.
pub fn dump_everything(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    out: &Path,
) -> Result<()> {
    println!("{}", style::kv("device", &dev.describe()));
    println!("{}", style::kv("family", &drive.family().to_string()));
    println!(
        "{}",
        style::dim_line("dumping everything (full image + per-unit regions + map)...")
    );

    // Per-unit regions, full image, and read-surface map are all FAMILY-OPTIONAL:
    // MTK supplies all three, Pioneer/Renesas only the full image. A family that
    // reports "unsupported" for a part still dumps the rest (engine omits it).
    let dump = match drive.read_dump(dev) {
        Ok(d) => Some(d),
        Err(e) => {
            println!(
                "  per-unit regions {}",
                style::amber(&format!("unavailable ({e})"))
            );
            None
        }
    };
    let id = drive.identity(dev);

    let full = match drive.read_full_image(dev) {
        Ok(fi) => Some(fi),
        Err(e) => {
            println!(
                "  firmware.bin     {}",
                style::amber(&format!("unavailable ({e})"))
            );
            None
        }
    };
    // The map is derived from the already-read image, so it is only attempted
    // when the full image is available.
    let map = match &full {
        Some((image, _, gaps)) => drive.read_surface_map(dev, &id, image, gaps)?,
        None => None,
    };

    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        if let Some((image, ..)) = &full {
            tar_append(&mut b, "firmware.bin", image)?;
        }
        if let Some(dump) = &dump {
            for (name, data) in dump.members() {
                tar_append(&mut b, name, data)?;
            }
        }
        if let Some((map_json, map_md)) = &map {
            tar_append(&mut b, "map.json", map_json.as_bytes())?;
            tar_append(&mut b, "map.md", map_md.as_bytes())?;
        }
        b.into_inner()?.flush()?;
    }
    std::fs::write(out, &buf).with_context(|| format!("writing {}", out.display()))?;

    if let Some((image, readable, gaps)) = &full {
        println!(
            "  firmware.bin     {}",
            style::dim(&format!(
                "{} ({} readable{})",
                human_size(image.len()),
                human_size(*readable),
                if gaps.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", {} not read-exposed → 0xFF",
                        human_size(image.len() - readable)
                    )
                }
            ))
        );
        for (s, e) in gaps {
            println!(
                "{}",
                style::dim_line(&format!("      gap 0x{s:06X}..0x{e:06X}"))
            );
        }
    }
    if let Some(dump) = &dump {
        for (name, data) in dump.members() {
            println!(
                "{}",
                style::dim_line(&format!("  {name:<16} {} bytes", data.len()))
            );
        }
    }
    if map.is_some() {
        println!(
            "{}",
            style::dim_line("  map.json / map.md  (read-surface map)")
        );
    }
    if let Some((image, ..)) = &full {
        println!(
            "{}",
            style::dim_line(&format!("  firmware sha256: {:x}", Sha256::digest(image)))
        );
    }
    println!(
        "{} {}",
        style::green("wrote"),
        style::dim(&format!("{} ({}).", out.display(), human_size(buf.len())))
    );
    Ok(())
}

fn tar_append<W: Write>(b: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_path(name)?;
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_cksum();
    b.append(&h, data)?;
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
///
/// Post-flash verification treats the DRIVE as the authority, not a byte compare.
/// The MediaTek firmware recomputes AES-CMAC over its integrity-protected ranges
/// at boot and refuses to run a mismatched image, so the definitive proof of a
/// clean flash is that the drive re-enumerates and reports coherent firmware. A
/// raw byte-for-byte read-back is NOT authoritative and must never hard-fail on
/// its own — it manufactures false "programming failed" alarms on a good flash,
/// because the boot/vector page is decrypted+remapped into RAM, per-unit
/// calibration/config/NVRAM is owned and rewritten by the drive, and some
/// firmwares don't expose the flash to READ BUFFER at all. We therefore read back
/// ONLY the image's own CMAC-protected ranges as an informational cross-check;
/// bytes outside them are mutable by the firmware's own definition and are not
/// compared. A mismatch inside a protected range is a warning, not a hard failure
/// (even protected reads can hit the remapped boot page or a still-settling
/// drive) — the identity read decides.
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
            println!(
                "{}",
                style::amber(&format!(
                    "WARNING: pre-flash dump failed ({e}); --rescue-no-dump: proceeding without a backup."
                ))
            );
        }
    }

    let (payload, enc) = drive.envelope(dev, &req.input, req.enc_override)?;

    println!("{}", style::header("== flash plan =="));
    println!("{}", style::kv("device", &dev.describe()));
    println!("{}", style::kv("drive", ident_or_unknown(&req.drive_model)));
    println!(
        "{}",
        style::kv(
            "firmware",
            &format!(
                "{} ({} envelope)",
                human_size(payload.len()),
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
                    "OK — drive ready for flash (read-only handshake)",
                    style::Status::Ok
                )
            ),
            Err(e) => println!(
                "{}",
                style::status_line(
                    "preflight",
                    &format!("NOT READY — {e}"),
                    style::Status::Fail
                )
            ),
        }
        println!(
            "\n{}",
            style::amber("DRY RUN: no SCSI writes issued. Re-run with --execute to flash.")
        );
        return Ok(());
    }

    // Integrity gate (write path): the image's AES-CMAC must verify before any
    // destructive write. A mis-signed image is rejected by the drive's boot
    // authenticator and can brick it — refuse unconditionally, no override.
    if !cmac::verify(&req.input) {
        bail!(
            "firmware image fails its AES-CMAC integrity check — refusing to flash. \
             A mis-signed or corrupted image is rejected by the drive's boot \
             authenticator and can brick the drive."
        );
    }

    // Model gate (write path): every MT19xx image CMAC-verifies for its OWN
    // model, so CMAC alone can't stop a wrong-model write. Require the image's
    // drive-descriptor model to name this drive's INQUIRY product.
    ensure_image_matches_drive(&req.input, &req.drive_model, drive.family())?;

    // Execution-tier gate: a real (destructive) write is allowed ONLY for a
    // hardware-proven, issuable instruction set. Today that is MT1959 (the MTK
    // family); catalog-only / transport-gated families are dry-run/plan only and
    // must never issue a write, even with --execute.
    match crate::flashset::FlashInstructionSet::for_family(drive.family()) {
        Some(set) if set.status.is_executable() => {}
        other => {
            let tier = other
                .map(|s| s.status.label())
                .unwrap_or("no executable flash recipe (catalog-only)");
            bail!(
                "refusing to flash: the {} family is {} — freemkv-flash executes real \
                 writes only on the hardware-proven MT1959 path (dry-run/plan only here)",
                drive.family(),
                tier
            );
        }
    }

    // Safety gate only on the write path.
    if let Err(block) = check_safety(req.acknowledged_risk) {
        bail!("SAFETY GATE: {}", block.0);
    }

    println!(
        "\n{}",
        style::bold("EXECUTING flash — do not power off or disconnect the drive...")
    );
    drive.flash_open(dev, req.mode)?;
    let chunk = drive.chunk_size();
    let mut offset = 0usize;
    for piece in payload.chunks(chunk) {
        drive.flash_chunk(dev, offset, piece)?;
        offset += piece.len();
    }
    drive.flash_close(dev, req.mode)?;
    println!(
        "upload complete {}",
        style::dim(&format!(
            "({}); waiting for the drive to finish programming...",
            human_size(payload.len())
        ))
    );
    // The drive keeps programming its flash after the last chunk (it reports
    // NOT READY / LONG WRITE IN PROGRESS). Wait for it to finish before reading
    // back, so a SUCCESSFUL flash never surfaces a scary mid-program error.
    drive.wait_ready(dev)?;
    println!("verifying...");

    // Post-flash verification (see the fn doc): the drive is the authority. Read
    // back ONLY the image's CMAC-protected ranges as an informational cross-check;
    // bytes outside them are drive-owned and not compared. Mismatch = warning.
    const BOOT_SKIP: usize = 0x1000; // silicon-remapped; reads RAM, not flash
    let protected: Vec<(usize, usize)> = cmac::parse_table(&payload)
        .map(|entries| {
            entries
                .iter()
                .filter(|e| e.is_active())
                .map(|e| (e.start as usize, e.end as usize)) // inclusive end
                .collect()
        })
        .unwrap_or_default();
    let is_protected = |pos: usize| protected.iter().any(|&(s, e)| pos >= s && pos <= e);

    let mut checked = 0usize; // protected + readable bytes we compared
    let mut differing = 0usize; // of those, how many differed
    let mut first_bad: Option<(usize, u8, u8)> = None;
    let mut offset = 0usize;
    for piece in payload.chunks(chunk) {
        if let Ok(got) = drive.readback(dev, offset, piece.len()) {
            if got.len() == piece.len() {
                for (i, (a, b)) in got.iter().zip(piece).enumerate() {
                    let pos = offset + i;
                    if pos < BOOT_SKIP || !is_protected(pos) {
                        continue;
                    }
                    checked += 1;
                    if a != b {
                        differing += 1;
                        first_bad.get_or_insert((pos, *a, *b));
                    }
                }
            }
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
    } else {
        println!(
            "{}",
            style::status_line(
                "flash complete",
                &format!(
                    "{} of integrity-protected regions verified",
                    human_size(checked)
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
    // Positive proof the new firmware is resident and booted.
    if let Ok(Some(r)) = drive.firmware_report(dev) {
        match r.matched {
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
        }
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
fn ensure_image_matches_drive(
    image: &[u8],
    drive_product: &str,
    drive_family: crate::drive::Family,
) -> Result<()> {
    let chip = freemkv_chipset::detect_chip(image)
        .context("input is not a recognizable MT19xx firmware image — refusing to flash")?;

    // Family cross-gate: an MT19xx image (ChipFamily::Mt1959/Mt1939 are both
    // MediaTek silicon) must be flashed onto a drive that classified as MediaTek.
    // Refuse flashing across silicon families outright.
    if drive_family != crate::drive::Family::Mtk {
        bail!(
            "image is {} (MediaTek) firmware but this drive classified as {} — \
             refusing to flash across silicon families",
            chip.family.label(),
            drive_family
        );
    }

    let product = drive_product.trim();
    if product.is_empty() {
        bail!(
            "drive model is unknown (empty INQUIRY product) — refusing to flash \
             without confirming the image matches this drive"
        );
    }

    let image_model = chip.model;
    if !image_model
        .to_ascii_uppercase()
        .contains(&product.to_ascii_uppercase())
    {
        bail!(
            "image is built for model {image_model:?} but this drive reports \
             {product:?} — refusing to flash a wrong-model image"
        );
    }
    Ok(())
}

fn flash_restore(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
    req: &FlashRequest,
) -> Result<()> {
    let dump = UserDump::from_tar_bytes(&req.input).context("parsing .tar restore input")?;
    let regions = drive.restore_regions(&dump);
    println!("{}", style::header("== flash plan (restore from .tar) =="));
    for r in &regions {
        println!(
            "{}",
            style::dim_line(&format!(
                "restore {}: 0x{:06X} ({} B)",
                r.label,
                r.offset,
                r.bytes.len()
            ))
        );
    }

    if !req.execute {
        println!(
            "\n{}",
            style::amber("DRY RUN: no SCSI writes issued. Re-run with --execute to restore.")
        );
        return Ok(());
    }
    if let Err(block) = check_safety(req.acknowledged_risk) {
        bail!("SAFETY GATE: {}", block.0);
    }

    println!(
        "\n{}",
        style::bold("EXECUTING restore — do not power off or disconnect the drive...")
    );
    for r in &regions {
        drive.write_region(dev, r.offset, r.bytes)?;
        let got = drive.readback(dev, r.offset as usize, r.bytes.len())?;
        if got != r.bytes {
            bail!("read-back verify failed for region 0x{:06X}", r.offset);
        }
    }
    println!(
        "{}",
        style::status_line("restore", "complete and verified", style::Status::Ok)
    );
    Ok(())
}

fn ident_or_unknown(s: &str) -> &str {
    if s.is_empty() {
        "<unknown>"
    } else {
        s
    }
}

/// Format a byte count as a friendly size (`2 MiB`, `16 KiB`, `2.00 MiB`, …).
pub(crate) fn human_size(bytes: usize) -> String {
    const K: usize = 1 << 10;
    const M: usize = 1 << 20;
    if bytes >= M {
        if bytes.is_multiple_of(M) {
            format!("{} MiB", bytes / M)
        } else {
            format!("{:.2} MiB", bytes as f64 / M as f64)
        }
    } else if bytes >= K {
        if bytes.is_multiple_of(K) {
            format!("{} KiB", bytes / K)
        } else {
            format!("{:.1} KiB", bytes as f64 / K as f64)
        }
    } else {
        format!("{bytes} B")
    }
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
