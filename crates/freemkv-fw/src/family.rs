//! Chip-family + model/rev detection from image bytes.
//!
//! `forge` auto-detects the target chip family from two independent locations
//! baked into the firmware blob itself (never from a live device — forge only
//! ever reads `.bin` files):
//!
//! * the boot banner near file offset [`BANNER_OFFSET`] (`0x3000`), e.g.
//!   `"MT1959 Boot BU5 "`;
//! * the ASCII drive descriptor at file offset [`DESCRIPTOR_OFFSET`]
//!   (`0x1EC000`), which encodes vendor / model / revision and a trailing
//!   `"MTEKMT19xx"` family tag.
//!
//! Both probes must independently decode to the same known family or
//! [`detect_chip`] fails closed. This is what backs forge's two safety
//! guarantees: it refuses to operate on an unidentified/unsupported family,
//! and (via the family check `plan_and_apply` re-runs on its own output) it
//! never emits an image whose detected family differs from the input's.

use anyhow::{anyhow, bail, Result};

/// File offset of the boot-banner ASCII string.
pub const BANNER_OFFSET: usize = 0x3000;
/// Bytes scanned for the boot banner (generous vs. the ~16-byte strings seen).
const BANNER_LEN: usize = 32;

/// File offset of the ASCII drive descriptor.
pub const DESCRIPTOR_OFFSET: usize = 0x1EC000;
/// Bytes of the descriptor record consumed by parsing.
const DESCRIPTOR_LEN: usize = 0x40;

/// A chip family forge can identify. Forge only *modifies* [`ChipFamily::Mt1959`]
/// images today (see `modify::validate_patchable`); [`ChipFamily::Mt1939`] is
/// recognized so it can be named in a clean refusal instead of an opaque one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipFamily {
    /// MediaTek MT1959.
    Mt1959,
    /// MediaTek MT1939.
    Mt1939,
}

impl ChipFamily {
    fn from_tag(tag: &str) -> Option<Self> {
        if tag.contains("MT1959") {
            Some(ChipFamily::Mt1959)
        } else if tag.contains("MT1939") {
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

/// Everything forge could read off the image about its chip identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChipInfo {
    /// The chip family, agreed on by the boot banner and the descriptor.
    pub family: ChipFamily,
    /// The trimmed boot-banner string (e.g. `"MT1959 Boot BU5"`).
    pub banner: String,
    /// Trimmed vendor field from the descriptor (e.g. `"HL-DT-ST"`).
    pub vendor: String,
    /// Trimmed model field from the descriptor (e.g. `"BD-RE BU40N"`).
    pub model: String,
    /// Trimmed revision field from the descriptor (e.g. `"1.00"`).
    pub rev: String,
}

/// Trim NUL padding and surrounding whitespace from a lossily-decoded ASCII
/// field.
fn ascii_trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string()
}

/// Detect the chip family + model/rev from `image`.
///
/// Fails closed: errors if the image is too small to hold either probe, if
/// either probe doesn't decode to a known family tag, or if the boot banner
/// and the descriptor's family tag disagree — a strong signal something is
/// wrong (a corrupted image, an unsupported family, or bytes forge doesn't yet
/// understand) that forge refuses to paper over with a guess.
pub fn detect_chip(image: &[u8]) -> Result<ChipInfo> {
    if image.len() < BANNER_OFFSET + BANNER_LEN {
        bail!(
            "image too small ({} bytes) to contain the boot banner at 0x{BANNER_OFFSET:x}",
            image.len()
        );
    }
    if image.len() < DESCRIPTOR_OFFSET + DESCRIPTOR_LEN {
        bail!(
            "image too small ({} bytes) to contain the drive descriptor at 0x{DESCRIPTOR_OFFSET:x}",
            image.len()
        );
    }

    let banner_bytes = &image[BANNER_OFFSET..BANNER_OFFSET + BANNER_LEN];
    let nul = banner_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(banner_bytes.len());
    let banner = ascii_trim(&banner_bytes[..nul]);
    let banner_family = banner
        .split_whitespace()
        .next()
        .and_then(ChipFamily::from_tag)
        .or_else(|| ChipFamily::from_tag(&banner))
        .ok_or_else(|| {
            anyhow!(
                "boot banner at 0x{BANNER_OFFSET:x} does not name a supported chip family: {banner:?}"
            )
        })?;

    let desc = &image[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + DESCRIPTOR_LEN];
    let vendor = ascii_trim(&desc[0x00..0x08]);
    let model = ascii_trim(&desc[0x08..0x18]);
    let rev = ascii_trim(&desc[0x18..0x1C]);
    let family_tag = ascii_trim(&desc[0x34..0x3E]);
    let desc_family = ChipFamily::from_tag(&family_tag).ok_or_else(|| {
        anyhow!(
            "drive descriptor at 0x{DESCRIPTOR_OFFSET:x} does not name a supported chip family: {family_tag:?}"
        )
    })?;

    if banner_family != desc_family {
        bail!(
            "boot banner ({banner_family}) and descriptor ({desc_family}) disagree on chip \
             family — refusing to guess"
        );
    }

    Ok(ChipInfo {
        family: desc_family,
        banner,
        vendor,
        model,
        rev,
    })
}

#[cfg(test)]
#[path = "family_tests.rs"]
mod tests;
