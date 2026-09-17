//! Per-lineage build parameters — the DATA that distinguishes the MT19xx code
//! generations, so the finders and build core stay single-bodied and select
//! behaviour by profile instead of `_classic`-suffixed method forks.
//!
//! Three lineages share one dumb toolkit; they differ only in a handful of
//! parameters (where the dispatch table lives, which register caches the CDB,
//! how sense is raised, which boot-init shape to hook). Those parameters live
//! here as `&'static LineageProfile` constants; [`for_image`] IDs the image and
//! returns the right one — "engine IDs, loads the right one."

use crate::family::{self, ChipFamily};

/// A flash-offset window `[lo, hi)` a windowed finder scans.
pub type Window = (usize, usize);

/// The MT19xx code generation an image belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lineage {
    /// MT1959 silicon (LG BU40N/BU50N, …). The reference lineage.
    Mt1959,
    /// MT1939 JB8 / JBP6 / JBC6 — MT1959-lineage code on MT1939 silicon (banner
    /// `"MT1959 Boot …"`). The MT1959 hook points transfer; a few dispatch/commit
    /// tables are relocated, expressed as extra finder windows below.
    Mt1939Modern,
    /// MT1939 "classic" (banner `"MT1939 Boot Code"`) — its own scanner (CDB in
    /// r5), dispatch table (~0x1a4000), inline sense, and a hardware-gated
    /// boot-init helper.
    Mt1939Classic,
}

/// The parameters a single build core reads instead of branching on `_classic`.
#[derive(Debug, Clone, Copy)]
pub struct LineageProfile {
    pub lineage: Lineage,
    /// Dispatch-table windows for [`super::mt1959_build::Mt1959Engine::find_live_record`],
    /// tried in order (original-first). Modern lineages list the MT1959 window
    /// then the relocated JBC6 window; classic lists only its own.
    pub live_record_windows: &'static [Window],
    /// Response-commit windows for `find_response_commit`, tried in order.
    pub commit_windows: &'static [Window],
}

// --- MT1959 / MT1939-modern share the same windowed finder inputs -----------
// The JBC6 window is an original-first FALLBACK: MT1959 images resolve in the
// first window and never consult it, so their emit is byte-identical.
const MODERN_LIVE_RECORD_WINDOWS: &[Window] =
    &[(0x0014_0000, 0x0016_0000), (0x0018_0000, 0x0019_0000)];
const MODERN_COMMIT_WINDOWS: &[Window] = &[(0x0009_0000, 0x000a_0000), (0x000a_0000, 0x000b_0000)];

// --- MT1939 classic ---------------------------------------------------------
const CLASSIC_LIVE_RECORD_WINDOWS: &[Window] = &[(0x001a_0000, 0x001a_8000)];
const CLASSIC_COMMIT_WINDOWS: &[Window] = &[(0x0009_0000, 0x000a_0000)];

const MT1959: LineageProfile = LineageProfile {
    lineage: Lineage::Mt1959,
    live_record_windows: MODERN_LIVE_RECORD_WINDOWS,
    commit_windows: MODERN_COMMIT_WINDOWS,
};
const MT1939_MODERN: LineageProfile = LineageProfile {
    lineage: Lineage::Mt1939Modern,
    live_record_windows: MODERN_LIVE_RECORD_WINDOWS,
    commit_windows: MODERN_COMMIT_WINDOWS,
};
const MT1939_CLASSIC: LineageProfile = LineageProfile {
    lineage: Lineage::Mt1939Classic,
    live_record_windows: CLASSIC_LIVE_RECORD_WINDOWS,
    commit_windows: CLASSIC_COMMIT_WINDOWS,
};

/// The classic generation carries the `"MT1939 Boot Code"` banner at
/// [`freemkv_chipset::BANNER_OFFSET`]; JB8/JBC6 carry `"MT1959 Boot …"`.
fn is_classic_banner(image: &[u8]) -> bool {
    let b = freemkv_chipset::BANNER_OFFSET;
    image
        .get(b..b + 16)
        .map(|s| s.starts_with(b"MT1939 Boot"))
        .unwrap_or(false)
}

/// Identify an image's lineage. MT1959 vs MT1939 comes from the chip family
/// (the authoritative in-image detector); within MT1939, the boot banner splits
/// modern (JB8/JBC6) from classic. On an unidentifiable family we default to the
/// MT1959/modern profile — the historical behaviour (the MT1959 windows are the
/// primary path), never a wrong-guess refusal here.
pub fn detect_lineage(image: &[u8]) -> Lineage {
    match family::detect_chip(image).map(|c| c.family) {
        Ok(ChipFamily::Mt1959) => Lineage::Mt1959,
        Ok(ChipFamily::Mt1939) => {
            if is_classic_banner(image) {
                Lineage::Mt1939Classic
            } else {
                Lineage::Mt1939Modern
            }
        }
        Err(_) => Lineage::Mt1959,
    }
}

/// The build profile for a lineage.
pub fn profile_for(lineage: Lineage) -> &'static LineageProfile {
    match lineage {
        Lineage::Mt1959 => &MT1959,
        Lineage::Mt1939Modern => &MT1939_MODERN,
        Lineage::Mt1939Classic => &MT1939_CLASSIC,
    }
}

/// The build profile for an image (detect + look up).
pub fn for_image(image: &[u8]) -> &'static LineageProfile {
    profile_for(detect_lineage(image))
}
