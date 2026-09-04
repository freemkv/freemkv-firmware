//! Chip-family + model/rev detection from image bytes.
//!
//! `forge` auto-detects the target chip family from the firmware blob itself
//! (never from a live device — forge only ever reads `.bin` files). The
//! authoritative family key is the ASCII **`MTEKMT19xx`** identity string, found
//! by *pattern-searching* the whole image (`MTEKMT19` + two digits):
//!
//! * `MTEKMT1959` → [`ChipFamily::Mt1959`], `MTEKMT1939` → [`ChipFamily::Mt1939`].
//!   The string appears both as the drive-reported identity and mirrored near the
//!   descriptor at [`DESCRIPTOR_OFFSET`] (`0x1EC034`); pattern-searching finds it
//!   even when the descriptor page is byte-shifted (some ASUS extractions), where
//!   a fixed-offset read would miss.
//!
//! Two things that *look* like family signals are deliberately NOT used to gate
//! the family (proven across a 149-image scan, `research/hoard-campaign-2026-09-03`):
//!
//! * the boot **banner** near [`BANNER_OFFSET`] (`0x3000`), e.g. `"MT1959 Boot
//!   JB8 "`, labels the *bootloader generation*, not the silicon — it reads
//!   `MT1959 Boot` even on `MTEKMT1939` parts (ASUS BW-16D1HT, LG BH16NS58, …).
//!   It is used only as a *fallback* when no `MTEKMT19xx` string exists at all
//!   (e.g. some Samsung MT1939 images), and otherwise is display-only;
//! * the descriptor **marker byte** at `+0x50` takes `0x78/0x58/0x18/0x38` within
//!   a single family (a variant/region/downgrade flag beside the DE byte at
//!   `+0x56`) — display-only, never a gate.
//!
//! Detection is fail-open on family but still refuses cleanly on truly
//! unidentifiable input (no `MTEKMT19xx` string and no family banner): callers
//! then abort with a clear message rather than guessing.

use anyhow::{bail, Result};

/// File offset of the boot-banner ASCII string.
pub const BANNER_OFFSET: usize = 0x3000;
/// Bytes scanned for the boot banner (generous vs. the ~16-byte strings seen).
const BANNER_LEN: usize = 32;

/// File offset of the ASCII drive descriptor.
pub const DESCRIPTOR_OFFSET: usize = 0x1EC000;
/// Bytes of the descriptor record consumed by parsing.
const DESCRIPTOR_LEN: usize = 0x40;
/// Offset of the descriptor's `MTEKMT19..` family tag within the record.
const DESCRIPTOR_TAG_OFF: usize = 0x34;
/// Offset of the display-only marker byte within the descriptor record.
const DESCRIPTOR_MARKER_OFF: usize = 0x50;

/// A chip family forge can identify. Forge only *modifies* [`ChipFamily::Mt1959`]
/// images with the full engine today; [`ChipFamily::Mt1939`] is recognized so it
/// can be named (and, where possible, partially modified — e.g. the downgrade
/// byte) instead of refused opaquely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipFamily {
    /// MediaTek MT1959.
    Mt1959,
    /// MediaTek MT1939.
    Mt1939,
}

impl ChipFamily {
    /// Map the two trailing digits of an `MTEKMT19xx` / `MT19xx` tag to a family.
    fn from_digits(d0: u8, d1: u8) -> Option<Self> {
        match (d0, d1) {
            (b'5', b'9') => Some(ChipFamily::Mt1959),
            (b'3', b'9') => Some(ChipFamily::Mt1939),
            _ => None,
        }
    }

    /// Recognize a family named anywhere in a short banner string.
    fn from_banner(banner: &str) -> Option<Self> {
        if banner.contains("MT1959") {
            Some(ChipFamily::Mt1959)
        } else if banner.contains("MT1939") {
            Some(ChipFamily::Mt1939)
        } else {
            None
        }
    }

    /// Short human-readable label (`"MT1959"` / `"MT1939"`).
    pub fn label(&self) -> &'static str {
        match self {
            ChipFamily::Mt1959 => "MT1959",
            ChipFamily::Mt1939 => "MT1939",
        }
    }
}

impl std::fmt::Display for ChipFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// How the family was decided — for display/audit and to tell a strong
/// identity (the `MTEKMT19xx` string) from a weak one (banner fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Decided by the authoritative `MTEKMT19xx` identity string.
    TagString,
    /// No identity string present; decided by the (bootloader-generation) banner.
    BannerFallback,
}

/// Everything forge could read off the image about its chip identity. The
/// `banner`, `vendor`, `model`, `rev`, and `marker_0x50` fields are display /
/// corroboration only — the `family` is decided by [`ChipFamily::from_digits`]
/// over the `MTEKMT19xx` pattern (or the banner fallback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChipInfo {
    /// The chip family (from the `MTEKMT19xx` string, or the banner fallback).
    pub family: ChipFamily,
    /// How `family` was decided.
    pub confidence: Confidence,
    /// The trimmed boot-banner string (e.g. `"MT1959 Boot BU5"`). Display only.
    pub banner: String,
    /// Trimmed vendor field from the descriptor (e.g. `"HL-DT-ST"`). May be empty
    /// if the image has no well-formed identity page.
    pub vendor: String,
    /// Trimmed model field from the descriptor (e.g. `"BD-RE BU40N"`).
    pub model: String,
    /// Trimmed revision field from the descriptor (e.g. `"1.00"`).
    pub rev: String,
    /// The matched `MTEKMT19xx` identity string, if any (display/audit).
    pub tag_string: Option<String>,
    /// The display-only marker byte at descriptor `+0x50`, if present. NEVER
    /// gates the family (see module docs).
    pub marker_0x50: Option<u8>,
    /// Whether the image carries a well-formed MTEK identity page at
    /// [`DESCRIPTOR_OFFSET`] (tag `MTEKMT19..` present). Gates identity-page
    /// edits such as the downgrade-enable byte.
    pub descriptor_present: bool,
}

/// Trim NUL padding and surrounding whitespace from a lossily-decoded ASCII
/// field.
fn ascii_trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string()
}

/// Scan `image` for every distinct `MTEKMT19` + two-ASCII-digit occurrence,
/// returning the matched 10-byte strings (deduplicated, in first-seen order).
fn scan_mtek_tags(image: &[u8]) -> Vec<String> {
    const PREFIX: &[u8] = b"MTEKMT19";
    let mut seen: Vec<String> = Vec::new();
    if image.len() < PREFIX.len() + 2 {
        return seen;
    }
    let mut i = 0;
    while i + PREFIX.len() + 2 <= image.len() {
        if &image[i..i + PREFIX.len()] == PREFIX {
            let d0 = image[i + PREFIX.len()];
            let d1 = image[i + PREFIX.len() + 1];
            if d0.is_ascii_digit() && d1.is_ascii_digit() {
                let tag = String::from_utf8_lossy(&image[i..i + PREFIX.len() + 2]).into_owned();
                if !seen.contains(&tag) {
                    seen.push(tag);
                }
                i += PREFIX.len() + 2;
                continue;
            }
        }
        i += 1;
    }
    seen
}

/// Detect the chip family + model/rev from `image`.
///
/// Family is decided by the authoritative `MTEKMT19xx` identity string
/// (pattern-searched), falling back to the boot banner only when no such string
/// exists. Fails **only** when the image is truly unidentifiable (no identity
/// string and no family banner) or carries two conflicting `MTEKMT19xx` families
/// (a corrupt image) — the caller then aborts cleanly instead of guessing.
pub fn detect_chip(image: &[u8]) -> Result<ChipInfo> {
    // --- Family key: the MTEKMT19xx identity string (authoritative). ---
    let tags = scan_mtek_tags(image);
    let mut families: Vec<(ChipFamily, String)> = Vec::new();
    for tag in &tags {
        let b = tag.as_bytes();
        if let Some(fam) = ChipFamily::from_digits(b[b.len() - 2], b[b.len() - 1]) {
            if !families.iter().any(|(f, _)| *f == fam) {
                families.push((fam, tag.clone()));
            }
        }
    }
    if families.len() > 1 {
        bail!(
            "image carries conflicting chip-family identity strings ({}) — corrupt or spliced; \
             refusing to guess",
            families
                .iter()
                .map(|(_, t)| t.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // --- Banner (display; also the fallback family source). ---
    let banner = read_banner(image);
    let banner_family = banner.as_deref().and_then(ChipFamily::from_banner);

    let (family, confidence, tag_string) = match families.first() {
        Some((fam, tag)) => (*fam, Confidence::TagString, Some(tag.clone())),
        None => match banner_family {
            Some(fam) => (fam, Confidence::BannerFallback, None),
            None => {
                if tags.is_empty() {
                    bail!(
                        "undetectable — no MTEKMT19xx identity string and no MT19xx boot banner \
                         (unpack packed/truncated dumps first)"
                    );
                }
                bail!(
                    "image names an unsupported MT19xx variant ({}) — freemkv-fw handles MT1959 \
                     and MT1939 only",
                    tags.join(", ")
                );
            }
        },
    };

    // --- Descriptor parse (display-only + DE anchor). ---
    let (vendor, model, rev, marker_0x50, descriptor_present) = parse_descriptor(image);

    Ok(ChipInfo {
        family,
        confidence,
        banner: banner.unwrap_or_default(),
        vendor,
        model,
        rev,
        tag_string,
        marker_0x50,
        descriptor_present,
    })
}

/// Read + trim the boot banner at [`BANNER_OFFSET`], or `None` if the image is
/// too small to contain it.
fn read_banner(image: &[u8]) -> Option<String> {
    if image.len() < BANNER_OFFSET + BANNER_LEN {
        return None;
    }
    let banner_bytes = &image[BANNER_OFFSET..BANNER_OFFSET + BANNER_LEN];
    let nul = banner_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(banner_bytes.len());
    let s = ascii_trim(&banner_bytes[..nul]);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Parse the display-only descriptor fields and detect a well-formed identity
/// page. Returns `(vendor, model, rev, marker_0x50, descriptor_present)`; all
/// strings empty and `descriptor_present == false` when no identity page exists.
fn parse_descriptor(image: &[u8]) -> (String, String, String, Option<u8>, bool) {
    if image.len() < DESCRIPTOR_OFFSET + DESCRIPTOR_LEN {
        return (String::new(), String::new(), String::new(), None, false);
    }
    let desc = &image[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN];
    let tag_present = desc[DESCRIPTOR_TAG_OFF..].starts_with(b"MTEKMT19");
    let vendor = ascii_trim(&desc[0x00..0x08]);
    let model = ascii_trim(&desc[0x08..0x18]);
    let rev = ascii_trim(&desc[0x18..0x1C]);
    // The marker byte lives at descriptor `+0x50`, PAST the 0x40-byte record, so
    // it is read from the image directly (with a bounds check), not the slice.
    let marker = image
        .get(DESCRIPTOR_OFFSET + DESCRIPTOR_MARKER_OFF)
        .copied();
    if tag_present {
        (vendor, model, rev, marker, true)
    } else {
        // No identity page: still expose the marker byte for audit, but report
        // no descriptor and empty display fields (they'd be garbage).
        (String::new(), String::new(), String::new(), marker, false)
    }
}

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

/// Resolve the capability for a model/family.
///
/// Minimal built-in table: every MT19xx target freemkv-fw handles today is a
/// BD/UHD writer with the AACS + region levers in scope. The full model-keyed
/// capability map (`capability-map.json`, incl. DVD-region-only parts) lands with
/// the `freemkv-chipset` extraction; the downgrade-enable lever is family-agnostic
/// and does not depend on this table.
pub fn capability_for(_model: &str, family: ChipFamily) -> Capability {
    Capability {
        family,
        media_class: MediaClass::UhdBd,
        bd_aacs: true,
        region_lockable: true,
    }
}

#[cfg(test)]
#[path = "family_tests.rs"]
mod tests;
