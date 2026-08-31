//! Chipset-agnostic firmware-integrity schemes.
//!
//! `freemkv-fw` verifies and re-signs the integrity structures embedded in
//! optical-drive firmware images. Different chipset families use different
//! integrity constructions, so the CLI never talks to a concrete construction
//! directly: it selects an [`IntegrityScheme`] (by auto-detection or an explicit
//! `--family`) and speaks a neutral report vocabulary — [`RegionVerdict`] and
//! [`RegionChange`] — regardless of which scheme answered.
//!
//! Today the only implemented scheme is [`MtkCmac`], a thin adapter over the
//! AES-CMAC integrity engine in [`freemkv_flash::cmac`]. No crypto is
//! reimplemented here; this module only maps that engine's types onto the
//! neutral vocabulary and applies conservative image detection.

use anyhow::{anyhow, Result};

use freemkv_flash::cmac;

/// The verdict for one integrity-protected region of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionVerdict {
    /// Index of the region within its scheme's table.
    pub index: usize,
    /// Inclusive start file offset of the covered range.
    pub start: u32,
    /// Inclusive end file offset of the covered range.
    pub end: u32,
    /// Whether the stored digest matched a fresh compute.
    pub ok: bool,
    /// Digest as stored in the image.
    pub stored: [u8; 16],
    /// Digest computed over the current image bytes.
    pub computed: [u8; 16],
}

/// A region whose stored digest was rewritten by a signing pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionChange {
    /// Index of the region within its scheme's table.
    pub index: usize,
    /// Inclusive start file offset of the covered range.
    pub start: u32,
    /// Inclusive end file offset of the covered range.
    pub end: u32,
    /// Digest before re-signing.
    pub before: [u8; 16],
    /// Digest after re-signing.
    pub after: [u8; 16],
}

/// A firmware-integrity construction for one chipset family.
pub trait IntegrityScheme {
    /// Short human-readable name of the scheme (e.g. `MediaTek MT19xx CMAC`).
    fn name(&self) -> &'static str;

    /// Conservatively decide whether this scheme recognizes `image`.
    fn detect(&self, image: &[u8]) -> bool;

    /// Verify every active region, returning a per-region verdict list.
    fn verify(&self, image: &[u8]) -> Result<Vec<RegionVerdict>>;

    /// Recompute and write back every active region's digest.
    ///
    /// Returns the new image bytes and the list of regions whose stored digest
    /// actually changed.
    fn sign(&self, image: &[u8]) -> Result<(Vec<u8>, Vec<RegionChange>)>;
}

/// MediaTek MT19xx AES-CMAC integrity table (delegates to [`freemkv_flash::cmac`]).
pub struct MtkCmac;

impl IntegrityScheme for MtkCmac {
    fn name(&self) -> &'static str {
        "MediaTek MT19xx CMAC"
    }

    fn detect(&self, image: &[u8]) -> bool {
        // Must be big enough to hold the table itself.
        let table_end = cmac::TABLE_OFFSET + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE;
        if image.len() < table_end {
            return false;
        }
        // Require at least one active, well-formed entry whose range is
        // in-bounds and non-inverted — an all-zero or unrelated buffer of the
        // right size must not be mistaken for an MTK image.
        let entries = match cmac::parse_table(image) {
            Ok(e) => e,
            Err(_) => return false,
        };
        entries
            .iter()
            .any(|e| e.is_active() && e.start <= e.end && (e.end as usize) < image.len())
    }

    fn verify(&self, image: &[u8]) -> Result<Vec<RegionVerdict>> {
        let verdicts = cmac::verify_detailed(image).map_err(|e| anyhow!(e))?;
        Ok(verdicts
            .into_iter()
            .map(|v| RegionVerdict {
                index: v.entry.index,
                start: v.entry.start,
                end: v.entry.end,
                ok: v.matches,
                stored: v.entry.stored,
                computed: v.computed,
            })
            .collect())
    }

    fn sign(&self, image: &[u8]) -> Result<(Vec<u8>, Vec<RegionChange>)> {
        // Snapshot the active entries before signing so we can diff digests.
        let before = cmac::parse_table(image).map_err(|e| anyhow!(e))?;
        let signed = cmac::resign(image).map_err(|e| anyhow!(e))?;
        let after = cmac::parse_table(&signed).map_err(|e| anyhow!(e))?;

        let mut changes = Vec::new();
        for (b, a) in before.iter().zip(after.iter()) {
            if b.is_active() && b.stored != a.stored {
                changes.push(RegionChange {
                    index: a.index,
                    start: a.start,
                    end: a.end,
                    before: b.stored,
                    after: a.stored,
                });
            }
        }
        Ok((signed, changes))
    }
}

/// A chipset family the user may force with `--family`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// MediaTek MT19xx AES-CMAC integrity table.
    Mtk,
}

impl Family {
    /// The concrete scheme for this family.
    fn scheme(self) -> Box<dyn IntegrityScheme> {
        match self {
            Family::Mtk => Box::new(MtkCmac),
        }
    }
}

/// Every scheme forge knows about, in detection-priority order.
fn all_schemes() -> Vec<Box<dyn IntegrityScheme>> {
    vec![Box::new(MtkCmac)]
}

/// Select an integrity scheme for `image`.
///
/// With `forced = Some(family)` the named scheme is used unconditionally; with
/// `None` every known scheme is offered the image and the first to
/// [`detect`](IntegrityScheme::detect) it wins. If nothing recognizes the image
/// a clean error is returned — this never panics.
pub fn select_scheme(image: &[u8], forced: Option<Family>) -> Result<Box<dyn IntegrityScheme>> {
    if let Some(family) = forced {
        return Ok(family.scheme());
    }
    for scheme in all_schemes() {
        if scheme.detect(image) {
            return Ok(scheme);
        }
    }
    Err(anyhow!(
        "no integrity scheme recognizes this image (only MediaTek MT19xx supported today)"
    ))
}

#[cfg(test)]
#[path = "scheme_tests.rs"]
mod tests;
