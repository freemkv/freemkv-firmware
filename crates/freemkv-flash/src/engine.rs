//! Generic command engine: `info` / `backup` / `flash`.
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
use sha2::{Digest, Sha256};

use crate::cmac;
use crate::drive::{DriveFamily, FlashRequest, InputKind};
use crate::platform::{MediumStatus, ScsiDevice};
use crate::style;

pub(crate) mod backup;
use backup::save_backup;
#[cfg(test)]
use backup::BackupArtifact;

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
                    style::amber("live flash/backup unavailable")
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
    /// The full drive-family identity: MT19xx OR any other family found in the
    /// hoard (Pioneer, Renesas, legacy HL-DT-ST, …), by in-image signature.
    pub identity: crate::imageid::ImageIdentity,
}

/// Classify a firmware image the way `info` reports it (read-only, no drive).
pub(crate) fn classify_file(image: &[u8]) -> FileClass {
    let identity = crate::imageid::identify(image);
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
        identity,
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

    if let Ok(bundle) = crate::pioneer_bundle::Bundle::from_tar_bytes(&image) {
        println!("{}", style::kv("family", "Pioneer"));
        if !bundle.source_name.is_empty() {
            println!("{}", style::kv("source", &bundle.source_name));
        }
        if let Some(model) = &bundle.public_model {
            println!("{}", style::kv("listed model", model));
        }
        if let Some(model) = &bundle.embedded_model {
            println!("{}", style::kv("firmware model", model));
        }
        if let Some(hardware) = bundle
            .components
            .first()
            .and_then(|c| c.hardware.as_deref())
        {
            println!("{}", style::kv("hardware", hardware));
        }
        println!(
            "{}",
            style::kv("components", &bundle.components.len().to_string())
        );
        for component in &bundle.components {
            println!(
                "{}",
                style::kv(
                    "component",
                    &format!(
                        "{:?} {} ({} bytes)",
                        component.role,
                        component.path,
                        component.bytes.len()
                    )
                )
            );
        }
        println!(
            "{}",
            style::kv("flash", "offline dry-run only; live backup/flash blocked")
        );
        return Ok(());
    }

    let fc = classify_file(&image);
    let Some(chip) = fc.chip.as_ref() else {
        // Not MT19xx: report whichever other family the signature layer found
        // (Pioneer, Renesas, legacy HL-DT-ST, …) — or an honest "unknown".
        return info_file_other(&fc.identity);
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
        // MT1959 is the hardware-proven executable path; an MT1939 image shares the
        // MediaTek recipe but is not itself proven, so say so rather than overclaim.
        Some((name, status)) => {
            let mut s = format!("{name} — {}", status.label());
            if chip.family == freemkv_chipset::ChipFamily::Mt1939 {
                s.push_str(" (image is MT1939 — recognized; only the MT1959 path is proven)");
            }
            s
        }
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
pub fn backup(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, out: &Path) -> Result<()> {
    backup_with_template(dev, drive, out, None)
}

/// Save a firmware backup using optional backend-specific envelope templates.
pub fn backup_with_template(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, out: &Path, template: Option<&[u8]>) -> Result<()> {
    drive.validate_backup_template(template)?;
    if drive.backup_extension().is_none() {
        bail!(
            "no proven restorable firmware backup for {}",
            drive.backend_name()
        );
    }
    let target_model = drive.identity(dev).product;
    let bytes = drive.capture_backup_with_template(dev, template)?;
    let saved_len = save_backup(out, &bytes, drive, &target_model)?;
    println!(
        "{}",
        style::kv("backup sha256", &format!("{:x}", Sha256::digest(&bytes)))
    );
    println!(
        "{} {}",
        style::green("wrote"),
        style::dim(&format!("{} ({}).", out.display(), human_size(saved_len)))
    );
    Ok(())
}

/// Run the `flash` command: `.bin` = full image, `.tar` = firmware rollback archive.
pub fn flash(dev: &mut dyn ScsiDevice, drive: &dyn DriveFamily, req: &FlashRequest) -> Result<()> {
    if let Some(plan) = drive.offline_plan(req) {
        return plan;
    }
    guard_no_medium(dev, req.execute)?;
    match req.input_kind {
        InputKind::Tar => flash_restore(dev, drive, req),
        InputKind::Bin => flash_bin(dev, drive, req),
        InputKind::PioneerBundle => bail!("Pioneer firmware bundles cannot use the MTK flash path"),
    }
}

/// Pioneer accepts a variable-size OEM Normal envelope in the host updater.
/// This path is deliberately offline: even `--execute` returns before touching
/// the device, since a restorable backup, drive acceptance, and completion
/// status behavior are not established.
pub fn plan_pioneer_offline(
    image: &[u8],
    input_kind: InputKind,
    model: &str,
    allow_crossflash: bool,
    verbose: bool,
    execute: bool,
    _drive: &dyn DriveFamily,
) -> Result<()> {
    if execute {
        bail!("Pioneer flash execution is blocked: restorable backup, drive acceptance, and completion status rules are unverified; no SCSI writes issued");
    }
    let bundle = match input_kind {
        InputKind::PioneerBundle => Some(crate::pioneer_bundle::Bundle::from_tar_bytes(image)?),
        InputKind::Bin => None,
        InputKind::Tar => bail!("Pioneer offline flash planning requires a Normal envelope or Pioneer envelope tar, not an MTK backup archive"),
    };
    if let Some(bundle) = &bundle {
        if bundle.components.len() > 1 {
            return plan_pioneer_bounded_bundle(bundle, model, verbose);
        }
    }
    let image = match &bundle {
        Some(bundle) => bundle.sole_normal_only()?.bytes.as_slice(),
        None => image,
    };
    let banner = crate::drive::pioneer::parse_banner(image).ok_or_else(|| {
        anyhow::anyhow!("Pioneer offline plan requires a Normal .enc envelope with a valid banner")
    })?;
    if image.len() < crate::drive::pioneer::IMAGE_MIN
        || image.len() > crate::drive::pioneer::IMAGE_MAX
        || !image.len().is_multiple_of(0x100)
    {
        bail!("Pioneer envelope length {} is outside the supported offline planning range or not 256-byte aligned", image.len());
    }
    if model.trim().is_empty() {
        bail!("Pioneer offline plan requires a nonempty stated drive model");
    }
    let drive_model = model.to_ascii_uppercase();
    if !allow_crossflash
        && !drive_model
            .split_whitespace()
            .any(|part| part == banner.model.to_ascii_uppercase())
    {
        bail!(
            "Pioneer envelope model {:?} does not match stated drive model {:?}",
            banner.model,
            model
        );
    }
    use crate::drive::pioneer::{
        offline_oem_transcript, select_oem_profile, EnvelopeEvidence, TransferStage,
    };
    let profile = select_oem_profile(model, image)?;
    let transcript = offline_oem_transcript(profile, image)?;
    let profile_name = match profile {
        crate::drive::pioneer::OemUpdateProfile::Ud04V111Normal => "UD04 1.11",
        crate::drive::pioneer::OemUpdateProfile::S09V130Normal => "S09 1.30",
    };
    println!(
        "{}",
        style::header("== Pioneer offline transfer plan (OEM host shape) ==")
    );
    if let Some(bundle) = &bundle {
        println!("{}", style::kv("bundle source", &bundle.source_name));
        println!(
            "{}",
            style::kv(
                "bundle selection",
                "unresolved; unique Normal-only profile selected by flasher"
            )
        );
        println!(
            "{}",
            style::kv("bundle component", &bundle.components[0].path)
        );
    }
    println!("{}", style::kv("stated model", ident_or_unknown(model)));
    println!(
        "{}",
        style::kv(
            "envelope",
            &format!(
                "{} bytes, banner model {}, banner revision {}",
                image.len(),
                banner.model,
                banner.revision
            )
        )
    );
    println!(
        "{}",
        style::kv("SHA-256", &format!("{:x}", Sha256::digest(image)))
    );
    let evidence = profile.evidence();
    println!("{}", style::kv("OEM host source", evidence.source));
    println!("{}", style::kv("OEM components", "Normal envelope only"));
    println!(
        "{}",
        style::kv("OEM updater SHA-256", evidence.updater_sha256)
    );
    if let Some(hash) = evidence.alternate_updater_sha256 {
        println!("{}", style::kv("OEM alternate updater SHA-256", hash));
    }
    println!(
        "{}",
        style::kv("OEM envelope SHA-256", evidence.reference_envelope_sha256)
    );
    let status = match profile.envelope_evidence(image) {
        EnvelopeEvidence::ExactOemReference => "exact audited OEM envelope",
        EnvelopeEvidence::UncertifiedCandidate => {
            "uncertified same-model offline candidate (OEM command shape only)"
        }
    };
    println!("{}", style::kv("input evidence", status));
    println!(
        "{}",
        style::kv(
            &format!("{profile_name} host entry/finish control SHA-256"),
            &format!("{:x}", Sha256::digest(&transcript[0].data))
        )
    );
    println!(
        "{profile_name} OEM offline transcript: {} raw-envelope chunks of at most {} B via 3B 07 F0, bracketed by 3B 04 FF entry and 3B 05 FF finish (256 B control each). Execution is blocked: restorable backup, full F1 identity/preflight, drive acceptance, and status handling are unverified.",
        transcript.len() - 2,
        crate::drive::pioneer::FLASH_CHUNK
    );
    if verbose {
        for transfer in &transcript {
            let label = match transfer.stage {
                TransferStage::Entry => "entry",
                TransferStage::KernelPrefix => "kernel",
                TransferStage::KernelFe => "kernel FE",
                TransferStage::Normal => "chunk",
                TransferStage::Finish => "finish",
            };
            println!(
                "  {label:6} {:02X?}  {} B",
                transfer.cdb,
                transfer.data.len()
            );
        }
    }
    println!(
        "{}",
        style::kv(
            "decoded payload revision",
            "unknown (payload not decoded by this planner)"
        )
    );
    println!(
        "{}",
        style::amber(
            "Banner may come from an older encoding template. Profile selection checks model, hardware, destination, and size; modified-envelope integrity and drive acceptance are not established."
        )
    );
    println!(
        "{}",
        style::amber("OFFLINE ONLY: no SCSI commands issued; --execute remains blocked.")
    );
    Ok(())
}

fn plan_pioneer_bounded_bundle(
    bundle: &crate::pioneer_bundle::Bundle,
    model: &str,
    verbose: bool,
) -> Result<()> {
    let stated_matches = |candidate: &str| {
        model
            .to_ascii_uppercase()
            .split_whitespace()
            .any(|part| part == candidate.to_ascii_uppercase())
    };
    if let [first, second] = bundle.components.as_slice() {
        use crate::pioneer_bundle::Role;
        let pair = match (first.role, second.role) {
            (Role::Kernel, Role::Main) => Some((first, second)),
            (Role::Main, Role::Kernel) => Some((second, first)),
            _ => None,
        };
        if let Some((kernel, normal)) = pair {
            let kernel_hash = format!("{:x}", Sha256::digest(&kernel.bytes));
            let normal_hash = format!("{:x}", Sha256::digest(&normal.bytes));
            if kernel_hash == "36996326ae5eaa369ef34a8434514ca137b31a3f144af0955c2d12f4a8b2ea83"
                && normal_hash == "8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141"
            {
                if !stated_matches("BDR-UD04")
                    && !bundle.public_model.as_deref().is_some_and(stated_matches)
                {
                    bail!("stated drive model {model:?} matches neither the listed model nor the supplied UD04 resource");
                }
                let steps = crate::drive::pioneer::offline_ud04_autoflasher_data_out(
                    &kernel.bytes,
                    &normal.bytes,
                )?;
                println!(
                    "{}",
                    style::header("== Pioneer UD04 Autoflasher offline data-out ==")
                );
                if !bundle.source_name.is_empty() {
                    println!("{}", style::kv("bundle source", &bundle.source_name));
                }
                println!("{}", style::kv("stated model", model));
                println!("{}", style::kv("Kernel SHA-256", &kernel_hash));
                println!("{}", style::kv("Normal SHA-256", &normal_hash));
                println!(
                    "{}",
                    style::kv(
                        "entry/finish control",
                        "PIONEER BDR-US04 + FD236642 + 236 zero bytes"
                    )
                );
                println!("Data-out shape: 04/FF entry; three 07/FE Kernel chunks; {} 07/F0 Normal chunks; 05/FF finish.", steps.iter().filter(|step| step.stage == crate::drive::pioneer::TransferStage::Normal).count());
                println!("OFFLINE ONLY: alternate entry-state branch, preflight, status/completion, drive acceptance, and restorable backup are unverified; no device I/O or live writes.");
                if verbose {
                    for step in &steps {
                        println!("  {:?} {:02X?} {} B", step.stage, step.cdb, step.data.len());
                    }
                }
                return Ok(());
            }
        }
    }
    let (profile, kernel, normal) = bundle.select_bounded_profile()?;
    let banner = crate::drive::pioneer::parse_banner(&normal.bytes)
        .ok_or_else(|| anyhow::anyhow!("Normal component lacks Pioneer banner"))?;
    if model.trim().is_empty()
        || (!stated_matches(&banner.model)
            && !bundle.public_model.as_deref().is_some_and(stated_matches))
    {
        bail!(
            "stated drive model {:?} matches neither listed model nor resource banner model {:?}",
            model,
            banner.model
        );
    }
    use crate::drive::pioneer::{offline_bounded_oem_data_out, TransferStage};
    // A deterministic example seed checks every profile-specific control and
    // resource invariant. The actual updater seed is runtime GetTickCount.
    let sample = offline_bounded_oem_data_out(profile, &kernel.bytes, &normal.bytes, 0)?;
    let normal_chunks = sample
        .iter()
        .filter(|step| step.stage == TransferStage::Normal)
        .count();
    println!(
        "{}",
        style::header("== Pioneer bounded OEM offline plan (parameterized) ==")
    );
    println!("{}", style::kv("bundle source", &bundle.source_name));
    println!("{}", style::kv("stated model", model));
    println!("{}", style::kv("resource model", &banner.model));
    println!("{}", style::kv("resource revision", &banner.revision));
    println!("{}", style::kv("resource hardware", &banner.hardware));
    println!("{}", style::kv("updater member", profile.updater_member));
    println!("{}", style::kv("updater SHA-256", profile.updater_sha256));
    println!("{}", style::kv("Kernel SHA-256", profile.kernel_sha256));
    println!("{}", style::kv("Normal SHA-256", profile.normal_sha256));
    println!("{}", style::kv("control SHA-256", profile.control_sha256));
    println!(
        "{}",
        style::kv(
            "clock seed",
            "GetTickCount at runtime; not present in bundle"
        )
    );
    println!("Data-out shape: 04/FF entry; 07/F0 Kernel prefix 0x1200 B; generated 0x200 B from seeded CRT rand; four 07/FE Kernel slices; {normal_chunks} 07/F0 Normal chunks; 05/FF finish.");
    println!("OFFLINE ONLY: data-out example validated with seed 0, but preflight, READ/WRITE BUFFER 02/A0 setup, polling, completion, restorable backup, and drive acceptance are not established; no device I/O or live writes.");
    if verbose {
        for (index, step) in sample.iter().enumerate() {
            let stage = match step.stage {
                TransferStage::Entry => "entry",
                TransferStage::KernelPrefix => "kernel-prefix",
                TransferStage::KernelFe => "kernel-FE",
                TransferStage::Normal => "normal",
                TransferStage::Finish => "finish",
            };
            println!(
                "  {index:3} {stage:13} {:02X?} {} B",
                step.cdb,
                step.data.len()
            );
        }
    }
    Ok(())
}

/// Refuse to flash while a disc is loaded. Reprogramming the flash while the
/// drive is busy servicing a medium can wedge the controller mid-program (a
/// verify-mismatch / `DID_BAD_TARGET` brick that only a power-cycle clears), so
/// a firmware flash MUST run against an empty, closed tray. On `--execute` this
/// is a hard abort before any backup or write; on a dry run it is a prominent
/// warning so the operator ejects before committing.
fn guard_no_medium(dev: &mut dyn ScsiDevice, execute: bool) -> Result<()> {
    // Flashing is safe ONLY with a closed, empty tray. A loaded disc can wedge
    // the controller mid-program; an open tray is not a settled flash state.
    let msg = match dev.medium_status()? {
        MediumStatus::ClosedEmpty => return Ok(()),
        MediumStatus::DiscPresent => {
            "a disc is loaded — refusing to flash. Eject the disc and retry with a \
             closed, EMPTY tray. Flashing while a medium is loaded can wedge the \
             drive mid-program."
        }
        MediumStatus::TrayOpen => {
            "the tray is OPEN — refusing to flash. Close the empty tray and retry \
             (flashing requires a closed, empty tray)."
        }
    };
    if execute {
        bail!("{msg}");
    }
    println!("{}", style::amber(&format!("WARNING: {msg}")));
    Ok(())
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
    // Image geometry, integrity, model, and any controller sub-family gate are
    // protocol decisions. The engine only enforces the common workflow.
    drive.validate_image(dev, &req.input, &req.drive_model, req.allow_crossflash)?;
    let (payload, enc) = drive.envelope(dev, &req.input, req.enc_override)?;

    // A firmware write requires a saved, self-checking full rollback artifact.
    // The mapped read often has holes; that condition fails before flash_open.
    let mut backup_summary = String::from("not captured (dry run)");
    if req.execute {
        let out = req
            .predump_out
            .as_ref()
            .context("no preflash backup path supplied")?;
        let bytes = drive.capture_backup(dev)?;
        let target_model = drive.identity(dev).product;
        let saved_len = save_backup(out, &bytes, drive, &target_model)?;
        backup_summary = format!("saved {} ({} bytes)", out.display(), saved_len);
    }

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
    if !drive.is_supported() || drive.backup_extension().is_none() {
        bail!(
            "refusing to flash: {} has no executable protocol and proven restorable backup",
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
    // re-probe RIGHT before `flash_open`; a stale check is the same class
    // of hazard as no check at all (drive controller can wedge mid-program
    // when servicing a medium).
    guard_no_medium(dev, req.execute)?;
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

    // The backend defines which image bytes can be compared after programming.
    // On MTK these are CMAC-covered ranges outside the remapped boot page.
    let protected = drive.verification_ranges(&payload)?;
    let is_protected = |pos: usize| protected.iter().any(|&(s, e)| pos >= s && pos <= e);

    let mut checked = 0usize; // protected + readable bytes we compared
    let mut differing = 0usize; // of those, how many differed
    let mut unverified = 0usize; // protected chunks we could not read back
    let mut first_bad: Option<(usize, u8, u8)> = None;
    let mut offset = 0usize;
    for piece in payload.chunks(chunk) {
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
            _ if has_protected => unverified += 1,
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
            human_size(checked),
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
pub(crate) fn ensure_image_matches_drive(
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
    let firmware = drive.validate_backup(&req.input, &req.drive_model)?;
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
