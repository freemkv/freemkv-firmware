//! Media-capability taxonomy — the **step-2 scope gate**.
//!
//! Step 1 ([`crate::detect_chip`]) says *which chipset*. Step 2 asks *what can
//! this specific drive/firmware receive* — which of the modify features (levers)
//! are even in scope for its media class. A DVD-only drive has a region lever but
//! no AACS/VID lever; a BD/UHD drive has both. The per-image "is the signature
//! present" question is answered later by the levers themselves; this table only
//! bounds *what's applicable in principle*.
//!
//! The [`BD_UHD_UNLOCK`] table is **baked from** the corpus capability map
//! (`research/hoard-campaign-2026-09-03/reports/capability-map.json`, the 88
//! `BD/UHD-unlock` models — MediaTek + Pioneer/Renesas). It is keyed by the
//! model's primary token (matched as an uppercase substring of the detected
//! model), so `detect_chip` model strings like `"BD-RE BU40N"` resolve via
//! `"BU40N"`. Regenerate from the map rather than hand-editing. Models not in the
//! table fall back to a family default (every `MTEKMT19xx` part is a BD/UHD
//! writer, so the AACS + region levers are in scope; the levers self-gate on
//! their own signatures regardless).

use crate::detect::ChipFamily;

/// Media capability class, ordered `Cd < Dvd < Bd < UhdBd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediaClass {
    /// CD-only.
    Cd,
    /// DVD (may carry an RPC region lever).
    Dvd,
    /// Blu-ray (AACS content in scope).
    Bd,
    /// 4K UHD Blu-ray.
    UhdBd,
}

impl MediaClass {
    /// Short display label.
    pub fn label(self) -> &'static str {
        match self {
            MediaClass::Cd => "CD",
            MediaClass::Dvd => "DVD",
            MediaClass::Bd => "BD",
            MediaClass::UhdBd => "BD/UHD",
        }
    }
}

/// What a given drive/firmware can receive — the step-2 gate the levers consult.
/// (Chipset property + media class; the OEM-vs-MK distinction is a per-image
/// property handled by the levers, not here.)
#[derive(Debug, Clone)]
pub struct Capability {
    /// Chip family.
    pub family: ChipFamily,
    /// Media capability class.
    pub media_class: MediaClass,
    /// AACS content lever (VID / raw-read) in scope.
    pub bd_aacs: bool,
    /// RPC region lever in scope.
    pub region_lockable: bool,
}

/// `(model-primary-token, media_class, region_lockable)` for every `BD/UHD-unlock`
/// model in the corpus capability map. All are AACS-capable (`bd_aacs = true`).
/// Baked from `capability-map.json`; regenerate rather than hand-edit.
const BD_UHD_UNLOCK: &[(&str, MediaClass, bool)] = {
    use MediaClass::{Bd, UhdBd};
    &[
        ("BC-12B1ST", Bd, true),
        ("BC-12D2HT", UhdBd, true),
        ("BD-5300S", Bd, true),
        ("BDC-202", Bd, true),
        ("BDC-S02", Bd, true),
        ("BDR-202", Bd, true),
        ("BDR-203", Bd, true),
        ("BDR-205", Bd, true),
        ("BDR-206", Bd, true),
        ("BDR-206DBK", Bd, true),
        ("BDR-206MBK", Bd, true),
        ("BDR-207DBK", Bd, true),
        ("BDR-207M", Bd, true),
        ("BDR-208DBK", Bd, true),
        ("BDR-209D", Bd, true),
        ("BDR-209EBK", Bd, true),
        ("BDR-209JBK", Bd, true),
        ("BDR-211EBK", UhdBd, true),
        ("BDR-211JBK", UhdBd, true),
        ("BDR-212EBK", UhdBd, true),
        ("BDR-213JBK", UhdBd, true),
        ("BDR-2205", Bd, true),
        ("BDR-2206", Bd, true),
        ("BDR-S03", Bd, true),
        ("BDR-S05J-BK", Bd, true),
        ("BDR-S06J", Bd, true),
        ("BDR-S06XLB", Bd, true),
        ("BDR-S07", Bd, true),
        ("BDR-S07XLT", Bd, true),
        ("BDR-S08XLT", Bd, true),
        ("BDR-S09JBK", Bd, true),
        ("BDR-S09JX", Bd, true),
        ("BDR-S09XLT", Bd, true),
        ("BDR-S11J-BK", Bd, true),
        ("BDR-S11J-X", Bd, true),
        ("BDR-S12JBK", UhdBd, true),
        ("BDR-S12JX", UhdBd, true),
        ("BDR-S12UHT", UhdBd, true),
        ("BDR-S12XLT", UhdBd, true),
        ("BDR-S13J-X", UhdBd, true),
        ("BDR-S13JBK", UhdBd, true),
        ("BDR-WFS05J", Bd, true),
        ("BDR-X12EBK", UhdBd, true),
        ("BDR-X12J-UHD", UhdBd, true),
        ("BDR-X12JBK", UhdBd, true),
        ("BDR-X13J-S", UhdBd, true),
        ("BDR-XD04", Bd, true),
        ("BDR-XD04J", Bd, true),
        ("BDR-XD04T", Bd, true),
        ("BDR-XD05J", Bd, true),
        ("BDR-XS05J", Bd, true),
        ("BDR-XU02J", Bd, true),
        ("BE14NU40", Bd, true),
        ("BE16NU50", UhdBd, true),
        ("BH14NS40", UhdBd, true),
        ("BH14NS50", Bd, true),
        ("BH14NS58", UhdBd, true),
        ("BH16NS40", UhdBd, true),
        ("BH16NS50", UhdBd, true),
        ("BH16NS55", UhdBd, true),
        ("BH16NS58", UhdBd, true),
        ("BP50NB40", UhdBd, true),
        ("BP55EB40", Bd, true),
        ("BP60NB10", UhdBd, true),
        ("BR-04B2T", Bd, true),
        ("BRUHD-PU3", UhdBd, true),
        ("BU40N", UhdBd, true),
        ("BU50N", UhdBd, true),
        ("BW-16D1H-U", UhdBd, true),
        ("BW-16D1HT", UhdBd, true),
        ("BW-16D1X-U", UhdBd, true),
        ("BWU-100A", Bd, true),
        ("BWU-500S", Bd, true),
        ("CH12NS40", Bd, true),
        ("IHBS112", Bd, true),
        ("IHBS212", Bd, true),
        ("IHBS312", Bd, true),
        ("SH-B083L", Bd, true),
        ("SH-B123A", Bd, true),
        ("SH-B123L", Bd, true),
        ("UH12NS40", Bd, true),
        ("WH14NS40", UhdBd, true),
        ("WH16NS40", Bd, true),
        ("WH16NS58", UhdBd, true),
        ("WH16NS60", UhdBd, true),
        ("WP50NB40", UhdBd, true),
    ]
};

/// Resolve the capability for a model/family.
///
/// Looks the model's primary token up in the baked [`BD_UHD_UNLOCK`] table
/// (uppercase substring match, longest token first so `BW-16D1HT` wins over a
/// hypothetical `BW-16`). A hit gives the mapped media class + AACS/region
/// scope. A miss falls back to the family default: every `MTEKMT19xx` part is a
/// BD/UHD writer, so both levers are in scope (the levers still self-gate on
/// their own signatures, so an over-broad default cannot mis-patch).
pub fn capability_for(model: &str, family: ChipFamily) -> Capability {
    let up = model.to_ascii_uppercase();
    let hit = BD_UHD_UNLOCK
        .iter()
        .filter(|(token, _, _)| up.contains(token))
        .max_by_key(|(token, _, _)| token.len());
    match hit {
        Some(&(_, media_class, region_lockable)) => Capability {
            family,
            media_class,
            bd_aacs: true,
            region_lockable,
        },
        None => Capability {
            family,
            media_class: MediaClass::UhdBd,
            bd_aacs: true,
            region_lockable: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bd_model_resolves_from_table() {
        let cap = capability_for("BD-RE BU40N", ChipFamily::Mt1959);
        assert_eq!(cap.media_class, MediaClass::UhdBd);
        assert!(cap.bd_aacs && cap.region_lockable);
    }

    #[test]
    fn unknown_model_falls_back_to_bd_uhd_default() {
        let cap = capability_for("SOME-FUTURE-DRIVE", ChipFamily::Mt1939);
        assert_eq!(cap.media_class, MediaClass::UhdBd);
        assert!(cap.bd_aacs && cap.region_lockable);
    }

    #[test]
    fn longest_token_wins() {
        // "BW-16D1HT" is UHD; make sure a shorter accidental token can't shadow it.
        let cap = capability_for("ASUS BW-16D1HT", ChipFamily::Mt1939);
        assert_eq!(cap.media_class, MediaClass::UhdBd);
    }

    #[test]
    fn media_class_is_ordered() {
        assert!(MediaClass::Cd < MediaClass::Dvd);
        assert!(MediaClass::Dvd < MediaClass::Bd);
        assert!(MediaClass::Bd < MediaClass::UhdBd);
    }
}
