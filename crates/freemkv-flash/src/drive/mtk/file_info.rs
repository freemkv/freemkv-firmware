//! `info <file>` for a MediaTek MT19xx image: chip, descriptor, capability,
//! flash tier and AES-CMAC integrity.

use crate::cmac;
use crate::style::{self, ident_or_unknown};

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
/// [`crate::engine::info_file`] so the classification can be unit-tested without capturing
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

/// Print the MT19xx report for `image`, or `None` when it is not MT19xx.
pub(crate) fn describe(image: &[u8]) -> Option<anyhow::Result<()>> {
    let fc = classify_file(image);
    let chip = fc.chip.as_ref()?;

    crate::output::field("Chipset", chip.family.label());
    crate::output::field("Model", ident_or_unknown(&chip.model));
    crate::output::field("Firmware version", ident_or_unknown(&chip.rev));
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
    crate::output::field("Integrity", &integrity);
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
    Some(Ok(()))
}
