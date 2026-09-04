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

/// AES-CMAC integrity summary for a firmware image.
pub(crate) enum CmacSummary {
    /// Every active CMAC region's stored digest matches a fresh compute.
    Valid { regions: usize },
    /// One or more region digests mismatch — corrupt image or an unsigned edit.
    Invalid { ok: usize, total: usize },
    /// No active CMAC table found — unsigned or a non-standard image.
    Unsigned,
}

/// What `info` reports for a firmware FILE. Kept separate from the printing in
/// [`info_file`] so the classification can be unit-tested without capturing
/// stdout. Uses the SAME [`freemkv_chipset::detect_chip`] the flash cross-gate
/// uses, so `info <file>` and the flash `image-matches-drive` gate never
/// disagree on a family.
pub(crate) struct FileClass {
    /// `None` when the bytes are not a recognizable MT19xx image.
    pub chip: Option<freemkv_chipset::ChipInfo>,
    /// Media/AACS/region capability of the recognized model (`None` when
    /// unrecognized).
    pub capability: Option<freemkv_chipset::Capability>,
    /// This tool's flash recipe for the family — `(name, tier)` — if any.
    pub flash: Option<(&'static str, crate::flashset::FlashStatus)>,
    /// CMAC integrity of the image bytes.
    pub cmac: CmacSummary,
}

/// Classify a firmware image the way `info` reports it (read-only, no drive).
pub(crate) fn classify_file(image: &[u8]) -> FileClass {
    let chip = freemkv_chipset::detect_chip(image).ok();
    let capability = chip
        .as_ref()
        .map(|c| freemkv_chipset::capability_for(&c.model, c.family));
    let flash = chip.as_ref().and_then(|c| {
        // Both MT1959 and MT1939 are MediaTek silicon → the MediaTek recipe.
        let fam = match c.family {
            freemkv_chipset::ChipFamily::Mt1959 | freemkv_chipset::ChipFamily::Mt1939 => {
                crate::drive::Family::Mtk
            }
        };
        crate::flashset::FlashInstructionSet::for_family(fam).map(|s| (s.name, s.status))
    });
    let cmac = match cmac::verify_detailed(image) {
        Ok(v) if v.is_empty() => CmacSummary::Unsigned,
        Ok(v) => {
            let ok = v.iter().filter(|e| e.matches).count();
            if ok == v.len() {
                CmacSummary::Valid { regions: v.len() }
            } else {
                CmacSummary::Invalid { ok, total: v.len() }
            }
        }
        Err(_) => CmacSummary::Unsigned,
    };
    FileClass {
        chip,
        capability,
        flash,
        cmac,
    }
}

/// Run the `info` command on a firmware FILE (read-only) — the file-side twin of
/// [`info`] on a device. Never writes and never needs a drive: it identifies the
/// chipset, capability, this tool's flash tier for it, and the image's CMAC
/// integrity, so a user can ask "what is this .bin and what can I do with it?"
/// and later know whether it matches a given drive (same family key both sides).
pub fn info_file(path: &Path) -> Result<()> {
    let image = std::fs::read(path)
        .with_context(|| format!("reading firmware image {}", path.display()))?;
    println!("{}", style::kv("file", &path.display().to_string()));
    println!("{}", style::kv("size", &human_size(image.len())));
    let mut hasher = Sha256::new();
    hasher.update(&image);
    let sha: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("{}", style::kv("sha256", &sha));

    let fc = classify_file(&image);
    let Some(chip) = fc.chip.as_ref() else {
        println!(
            "{}",
            style::kv(
                "image",
                &style::amber(
                    "not a recognizable MT19xx firmware image (truncated, packed, or non-MediaTek)"
                )
            )
        );
        return Ok(());
    };

    let conf = match chip.confidence {
        freemkv_chipset::Confidence::TagString => "identity string",
        freemkv_chipset::Confidence::BannerFallback => "banner (fallback)",
    };
    println!(
        "{}",
        style::kv(
            "chipset",
            &format!(
                "MediaTek {} (via {}; tag {})",
                chip.family.label(),
                conf,
                chip.tag_string.as_deref().unwrap_or("<none>")
            )
        )
    );
    println!(
        "{}",
        style::kv(
            "banner",
            if chip.banner.is_empty() {
                "<none>"
            } else {
                chip.banner.as_str()
            }
        )
    );
    println!(
        "{}",
        style::kv(
            "descriptor",
            &format!(
                "vendor='{}' model='{}' rev='{}'",
                ident_or_unknown(&chip.vendor),
                ident_or_unknown(&chip.model),
                ident_or_unknown(&chip.rev)
            )
        )
    );

    if let Some(cap) = fc.capability {
        let mut parts = vec![cap.media_class.label().to_string()];
        if cap.region_lockable {
            parts.push("region-lockable".to_string());
        }
        if cap.bd_aacs {
            parts.push("AACS content".to_string());
        }
        println!("{}", style::kv("capability", &parts.join(", ")));
    }

    let flash = match fc.flash {
        Some((name, status)) => format!("{name} — {}", status.label()),
        None => format!(
            "not flashable by this tool ({} brand recipes catalogued)",
            crate::flashset::CATALOG.len()
        ),
    };
    println!("{}", style::kv("flash", &flash));

    let integrity = match fc.cmac {
        CmacSummary::Valid { regions } => {
            style::green(&format!("valid ({regions} CMAC regions OK)"))
        }
        CmacSummary::Invalid { ok, total } => style::red(&format!(
            "INVALID ({ok}/{total} CMAC regions OK — corrupt or unsigned edit)"
        )),
        CmacSummary::Unsigned => {
            style::amber("no signed CMAC table (unsigned or non-standard image)")
        }
    };
    println!("{}", style::kv("integrity", &integrity));

    println!(
        "{}",
        style::kv(
            "built for",
            &format!(
                "{} {} ({})",
                ident_or_unknown(&chip.vendor),
                ident_or_unknown(&chip.model),
                chip.family.label()
            )
        )
    );
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
    if let Some(info) = preview_crossflash(
        &req.input,
        &req.drive_model,
        drive.family(),
        req.allow_crossflash,
    ) {
        print_crossflash_banner(&info);
    }
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
    // drive-descriptor model to name this drive's INQUIRY product — unless
    // --allow-crossflash was passed, which waives the MODEL match (but never the
    // chipset-family gate). For crossflash we read the drive's CURRENT firmware to
    // confirm its exact silicon (MT1959 vs MT1939) from real bytes.
    let drive_fine_family = if req.allow_crossflash {
        drive
            .read_full_image(dev)
            .ok()
            .and_then(|(bytes, _, _)| freemkv_chipset::detect_chip(&bytes).ok())
            .map(|c| c.family)
    } else {
        None
    };
    // `Ok(Some(..))` = an authorized crossflash (its banner + warnings were already
    // printed in the plan above); `Ok(None)` = normal same-model flash; `Err` refuses.
    let _crossflash = ensure_image_matches_drive(
        &req.input,
        &req.drive_model,
        drive.family(),
        req.allow_crossflash,
        drive_fine_family,
    )?;

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
/// Details of an authorized CROSSFLASH (a deliberate flash of a DIFFERENT
/// same-chipset model's firmware). Present only when `--allow-crossflash` waived
/// a model mismatch; carries the brick-risk warnings to surface prominently.
#[derive(Debug)]
pub(crate) struct CrossflashInfo {
    pub image_model: String,
    pub drive_product: String,
    pub image_family: freemkv_chipset::ChipFamily,
    /// Loud warnings (DE-not-set / capability mismatch / unverified sub-family).
    pub warnings: Vec<String>,
}

/// The crossflash gate decision core (pure — unit-testable without a device).
///
/// `drive_fine_family` is the drive's CURRENT silicon family (from reading its
/// own firmware) when known. Returns `Ok(None)` for a normal same-model flash,
/// `Ok(Some(..))` for an authorized crossflash, and `Err` when it must refuse.
/// The chipset-family gate is NON-overridable: even with `allow_crossflash`, a
/// known drive silicon that differs from the image's is refused.
fn decide_crossflash(
    image_family: freemkv_chipset::ChipFamily,
    image_model: &str,
    drive_product: &str,
    drive_fine_family: Option<freemkv_chipset::ChipFamily>,
    de_enabled: bool,
    allow_crossflash: bool,
) -> Result<Option<CrossflashInfo>> {
    // Non-overridable sub-family gate: MT1959 image onto MT1939 silicon (or vice
    // versa) is an instant brick — refuse even with --allow-crossflash.
    if let Some(df) = drive_fine_family {
        if df != image_family {
            bail!(
                "image is {} firmware but this drive is {} silicon — refusing to \
                 flash across chip families (instant brick). --allow-crossflash does \
                 NOT override the chipset-family gate.",
                image_family.label(),
                df.label()
            );
        }
    }

    let product = drive_product.trim();
    let model_matches = !product.is_empty()
        && image_model
            .to_ascii_uppercase()
            .contains(&product.to_ascii_uppercase());
    if model_matches {
        return Ok(None); // normal same-model flash
    }

    if !allow_crossflash {
        if product.is_empty() {
            bail!(
                "drive model is unknown (empty INQUIRY product) — refusing to flash \
                 without confirming the image matches this drive"
            );
        }
        bail!(
            "image is built for model {image_model:?} but this drive reports \
             {product:?} — refusing to flash a wrong-model image (pass \
             --allow-crossflash for a deliberate same-chipset crossflash)"
        );
    }

    // Crossflash authorized — collect brick-risk warnings.
    let mut warnings = Vec::new();
    if !de_enabled {
        warnings.push(
            "image is NOT downgrade-enabled (0x1EC056 != 0xDE) — the target drive will \
             likely REJECT a foreign image. Run the modify tool first (it sets the \
             downgrade byte)."
                .to_string(),
        );
    }
    let icap = freemkv_chipset::capability_for(image_model, image_family);
    if product.is_empty() {
        warnings.push(
            "drive model is unknown — cannot check media-capability compatibility; \
             proceed only if you are certain the drives are compatible."
                .to_string(),
        );
    } else {
        let dcap = freemkv_chipset::capability_for(product, image_family);
        if icap.media_class != dcap.media_class {
            warnings.push(format!(
                "media-class MISMATCH: image is {} but the drive model is {} — \
                 crossflashing across capability tiers can BRICK the drive.",
                icap.media_class.label(),
                dcap.media_class.label()
            ));
        }
    }
    if drive_fine_family.is_none() {
        warnings.push(
            "could not read the drive's current firmware to confirm its exact chipset \
             (MT1959 vs MT1939); the sub-family gate is verified at execute time — \
             ensure the image chipset matches the drive."
                .to_string(),
        );
    }

    Ok(Some(CrossflashInfo {
        image_model: image_model.to_string(),
        drive_product: product.to_string(),
        image_family,
        warnings,
    }))
}

/// Enforce the image↔drive match on the write path. Returns `Ok(Some(..))` when
/// an authorized crossflash is in effect (for labeling), `Ok(None)` for a normal
/// same-model flash, `Err` to refuse. See [`decide_crossflash`] for the gate.
fn ensure_image_matches_drive(
    image: &[u8],
    drive_product: &str,
    drive_family: crate::drive::Family,
    allow_crossflash: bool,
    drive_fine_family: Option<freemkv_chipset::ChipFamily>,
) -> Result<Option<CrossflashInfo>> {
    let chip = freemkv_chipset::detect_chip(image)
        .context("input is not a recognizable MT19xx firmware image — refusing to flash")?;

    // Family cross-gate: an MT19xx image (ChipFamily::Mt1959/Mt1939 are both
    // MediaTek silicon) must be flashed onto a drive that classified as MediaTek.
    // Refuse flashing across silicon families outright — never overridable.
    if drive_family != crate::drive::Family::Mtk {
        bail!(
            "image is {} (MediaTek) firmware but this drive classified as {} — \
             refusing to flash across silicon families",
            chip.family.label(),
            drive_family
        );
    }

    let de_enabled = image
        .get(freemkv_chipset::DESCRIPTOR_OFFSET + 0x56)
        .copied()
        == Some(0xDE);
    decide_crossflash(
        chip.family,
        &chip.model,
        drive_product,
        drive_fine_family,
        de_enabled,
        allow_crossflash,
    )
}

/// Best-effort crossflash preview for the (non-enforcing) flash plan / dry-run:
/// swallows every error so an unrecognizable image still prints a plan. Returns
/// `Some` only for a genuine authorized crossflash.
fn preview_crossflash(
    image: &[u8],
    drive_product: &str,
    drive_family: crate::drive::Family,
    allow_crossflash: bool,
) -> Option<CrossflashInfo> {
    if !allow_crossflash || drive_family != crate::drive::Family::Mtk {
        return None;
    }
    // drive_fine_family = None here: the plan is informational; the real
    // sub-family gate runs at execute time in ensure_image_matches_drive.
    ensure_image_matches_drive(image, drive_product, drive_family, true, None)
        .ok()
        .flatten()
}

/// Render the CROSSFLASH banner + warnings into the plan (shared by dry-run and
/// execute so the label is identical).
fn print_crossflash_banner(info: &CrossflashInfo) {
    println!(
        "{}",
        style::amber(&format!(
            "CROSSFLASH: {} <- {} ({} chipset) — EXPERIMENTAL, hardware-unvalidated",
            ident_or_unknown(&info.drive_product),
            info.image_model,
            info.image_family.label()
        ))
    );
    for w in &info.warnings {
        println!("{}", style::amber(&format!("  ! {w}")));
    }
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
