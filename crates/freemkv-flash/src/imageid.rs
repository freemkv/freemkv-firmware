//! Drive-family identification for a firmware IMAGE (signature-driven).
//!
//! `freemkv-flash` is the generic flasher for many drive families, but the
//! shared [`freemkv_chipset`] kernel only knows MediaTek `MTEKMT19xx` silicon.
//! Every other family in our firmware hoard (Pioneer, legacy Hitachi-LG,
//! Renesas, MediaTek bridge dumps, encrypted MediaTek envelopes, and ASCII
//! Intel-HEX images) therefore fell through `info` as "not a recognizable
//! MT19xx image". This module closes that gap: it tries each known family's
//! **in-image magic / signature** in turn and returns a structured
//! [`ImageIdentity`] — never keying on the filename.
//!
//! It lives here (not in `freemkv-chipset`) on purpose: `freemkv-chipset` is the
//! *shared* step-1 identity both the modify and flash tools must agree on, kept
//! deliberately MTK-only and dependency-light. Only the flash tool needs to
//! classify the whole hoard, and only it owns the brand [`crate::flashset::CATALOG`]
//! this wires into, so multi-family identification belongs on the flash side.
//!
//! Fingerprints (sources: our own hoard sweep + two recon passes over
//! `firmware-hoard/organized/**`):
//! * MT19xx — delegated to [`freemkv_chipset::detect_chip`] (unchanged);
//! * MediaTek encrypted envelope — a constant 16-byte header on the otherwise
//!   opaque HL-DT-ST distribution images (no plaintext tag/banner);
//! * Pioneer — `****` + `"Pioneer Corporation"` (raw), or the stable zlib
//!   deflate prefix of the packaged updater;
//! * 0x418000 (4 292 608-byte) full-flash dumps — split by the `"Hitachi-LG"`
//!   ASCII marker and the big-endian word at offset 4;
//! * Intel-HEX — the leading `:NNAAAATT…` record.

use crate::flashset::{brand_recipe, FlashStatus};

/// Size of the legacy full-flash dumps (Hitachi-LG / Renesas / MTK bridge).
const DUMP_SIZE: usize = 4_292_608;

/// Constant 16-byte header prefix of the encrypted MediaTek (HL-DT-ST) images.
/// Byte-identical across every such 2 MiB envelope in the hoard; the rest of the
/// image (banner, descriptor) is ciphertext, so no `MTEKMT19xx` tag survives.
const MTEK_ENC_MAGIC: [u8; 16] = [
    0xa9, 0xcc, 0xe8, 0x47, 0x2c, 0x0f, 0x30, 0x86, 0xb7, 0x44, 0xf5, 0x62, 0x19, 0xfa, 0x94, 0xa3,
];

/// Stable leading bytes of the zlib/deflate-compressed Pioneer updater package.
/// The first ~512 bytes it compresses (the `****`/copyright header) are constant
/// across models, so the deflate stream's prefix is a reliable signature.
const PIONEER_PACKED_MAGIC: [u8; 6] = [0x78, 0x01, 0x63, 0x60, 0x18, 0x05];

/// The drive family an image belongs to, decided by in-image signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFamily {
    /// MediaTek MT19xx (MT1959 / MT1939) — the one flashable family.
    MediaTekMt19xx,
    /// MediaTek image in the encrypted distribution envelope (sub-family opaque).
    MediaTekEncrypted,
    /// Pioneer firmware — raw `.fw.bin` or the zlib-packaged updater.
    Pioneer,
    /// Legacy Hitachi-LG (HL-DT-ST) 0x418000 full-flash dump (cleartext).
    LgLegacy,
    /// Renesas-based (Pioneer-made) 0x418000 full-flash dump (scrambled).
    Renesas,
    /// MediaTek external-bridge 0x418000 full-flash dump (scrambled).
    MediaTekBridge,
    /// ASCII Intel-HEX text firmware.
    IntelHex,
    /// No known family signature matched.
    Unknown,
}

impl ImageFamily {
    /// Human label for `info` output.
    pub fn label(self) -> &'static str {
        match self {
            ImageFamily::MediaTekMt19xx => "MediaTek MT19xx",
            ImageFamily::MediaTekEncrypted => "MediaTek (encrypted image)",
            ImageFamily::Pioneer => "Pioneer",
            ImageFamily::LgLegacy => "Hitachi-LG (legacy)",
            ImageFamily::Renesas => "Renesas",
            ImageFamily::MediaTekBridge => "MediaTek (external bridge)",
            ImageFamily::IntelHex => "Intel-HEX firmware",
            ImageFamily::Unknown => "unknown",
        }
    }

    /// The [`crate::flashset::CATALOG`] brand this family maps to, if any, so a
    /// recognized brand can surface its recipe + status. Legacy HL-DT-ST maps to
    /// LG and the bridge dump to Asus (both catalogued), even though neither is
    /// executable by this tool.
    fn catalog_brand(self) -> Option<&'static str> {
        match self {
            ImageFamily::Pioneer => Some("Pioneer"),
            ImageFamily::LgLegacy => Some("LG"),
            ImageFamily::MediaTekBridge => Some("Asus"),
            _ => None,
        }
    }

    /// Honest one-line flashability summary for the non-MT19xx families (the
    /// MT19xx arm keeps its own richer reporting). Every family here is
    /// identify-only; where a brand recipe is catalogued it is named for context,
    /// with the clear caveat that this tool does not execute it.
    pub fn flash_summary(self) -> String {
        let base = "identify-only — not flashable by this tool";
        match self.catalog_brand().and_then(brand_recipe) {
            Some(r) => {
                let tier = match r.status {
                    FlashStatus::Executable => "executable",
                    FlashStatus::CatalogOnly => "catalog-only",
                    FlashStatus::TransportGated => "transport-gated",
                };
                format!(
                    "{base} (catalogued {} recipe: {} — {}; not executed by freemkv-flash)",
                    r.brand, r.note, tier
                )
            }
            None => base.to_string(),
        }
    }
}

/// The structured identity of a firmware image: family + best-effort model/rev
/// pulled from the image bytes (never the filename), plus a display note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageIdentity {
    /// The detected family.
    pub family: ImageFamily,
    /// Model string extracted from the image, if the family carries one.
    pub model: Option<String>,
    /// Revision string extracted from the image, if present.
    pub rev: Option<String>,
    /// Extra display detail (e.g. "updater-packaged", "unrecognized variant").
    pub note: Option<String>,
}

impl ImageIdentity {
    fn bare(family: ImageFamily) -> Self {
        ImageIdentity {
            family,
            model: None,
            rev: None,
            note: None,
        }
    }
}

/// Identify a firmware image's family by signature (read-only, never panics).
///
/// Tries each family's in-image magic in priority order and returns the first
/// match; truly unrecognizable bytes yield [`ImageFamily::Unknown`] rather than
/// an error, so `info` can always report *something* honest.
pub fn identify(image: &[u8]) -> ImageIdentity {
    // MT19xx first: its MTEKMT19xx / banner signature is the strongest and is the
    // only flashable family, so it must win over any weaker heuristic.
    if let Ok(chip) = freemkv_chipset::detect_chip(image) {
        return ImageIdentity {
            family: ImageFamily::MediaTekMt19xx,
            model: non_empty(&chip.model),
            rev: non_empty(&chip.rev),
            note: None,
        };
    }
    if image.starts_with(&MTEK_ENC_MAGIC) {
        return ImageIdentity {
            note: Some("encrypted distribution envelope; model/rev not extractable".into()),
            ..ImageIdentity::bare(ImageFamily::MediaTekEncrypted)
        };
    }
    if is_pioneer_raw(image) {
        let (model, rev) = pioneer_model_rev(image);
        return ImageIdentity {
            family: ImageFamily::Pioneer,
            model,
            rev,
            note: None,
        };
    }
    if image.starts_with(&PIONEER_PACKED_MAGIC) {
        return ImageIdentity {
            note: Some("updater-packaged (zlib); model/rev in the sibling .fw.json".into()),
            ..ImageIdentity::bare(ImageFamily::Pioneer)
        };
    }
    if image.len() == DUMP_SIZE {
        return identify_dump(image);
    }
    if is_intel_hex(image) {
        return ImageIdentity {
            note: Some("ASCII Intel-HEX records".into()),
            ..ImageIdentity::bare(ImageFamily::IntelHex)
        };
    }
    ImageIdentity::bare(ImageFamily::Unknown)
}

/// Classify a 0x418000-byte full-flash dump: HL-DT-ST cleartext, else split by
/// the big-endian word at offset 4 (Renesas / MediaTek bridge / unrecognized).
fn identify_dump(image: &[u8]) -> ImageIdentity {
    if contains(image, b"Hitachi-LG Data Storage,Inc.") {
        let (model, rev) = lg_legacy_model_rev(image);
        return ImageIdentity {
            family: ImageFamily::LgLegacy,
            model,
            rev,
            note: None,
        };
    }
    let word = u32::from_be_bytes([image[4], image[5], image[6], image[7]]);
    match word {
        0x00DC_5D5D => ImageIdentity {
            note: Some("scrambled bridge dump; model/rev not extractable".into()),
            ..ImageIdentity::bare(ImageFamily::MediaTekBridge)
        },
        0x005A_80E2 | 0x0093_87DF => ImageIdentity {
            note: Some("scrambled dump; model/rev not extractable".into()),
            ..ImageIdentity::bare(ImageFamily::Renesas)
        },
        _ => ImageIdentity {
            note: Some("unrecognized 0x418000 full-flash dump variant".into()),
            ..ImageIdentity::bare(ImageFamily::Renesas)
        },
    }
}

/// A Pioneer raw image: eight `*` then `"Pioneer Corporation"` in the header.
fn is_pioneer_raw(image: &[u8]) -> bool {
    image.starts_with(&[b'*'; 8]) && contains(header(image, 0x200), b"Pioneer Corporation")
}

/// An ASCII Intel-HEX image: a `:` record mark followed by hex digits (the
/// byte-count + address of the first record).
fn is_intel_hex(image: &[u8]) -> bool {
    image.first() == Some(&b':')
        && image
            .get(1..9)
            .is_some_and(|b| b.iter().all(u8::is_ascii_hexdigit))
}

/// Pioneer model (@0x70, NUL-terminated) and revision (after "Revision Level : ").
fn pioneer_model_rev(image: &[u8]) -> (Option<String>, Option<String>) {
    let h = header(image, 0x200);
    let model = image
        .get(0x70..0x90)
        .map(|s| clean(s.split(|&b| b == 0).next().unwrap_or(s)));
    let rev = label_value(h, b"Revision Level : ");
    (model.filter(|s| !s.is_empty()), rev)
}

/// Legacy HL-DT-ST model (the `HL-DT-ST…` descriptor run) and revision (the
/// `y217.08.06.09a`-style build token), scanned from anywhere in the image since
/// the offsets vary per model.
fn lg_legacy_model_rev(image: &[u8]) -> (Option<String>, Option<String>) {
    let model = find(image, b"HL-DT-ST").map(|i| clean(printable_run(&image[i..], 40)));
    (model.filter(|s| !s.is_empty()), find_lg_rev(image))
}

/// Find the `<letter>NNN.NN.NN.NN[<letter>]` HL-DT-ST build/rev token.
fn find_lg_rev(image: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 12 <= image.len() {
        let w = &image[i..];
        let ok = w[0].is_ascii_alphabetic()
            && w[1..4].iter().all(u8::is_ascii_digit)
            && w[4] == b'.'
            && w[5..7].iter().all(u8::is_ascii_digit)
            && w[7] == b'.'
            && w[8..10].iter().all(u8::is_ascii_digit)
            && w[10] == b'.'
            && w[11].is_ascii_digit();
        if ok {
            let end = printable_run(w, 14).len();
            return Some(clean(&w[..end]));
        }
        i += 1;
    }
    None
}

/// Read the printable value after a `<label>` literal, up to a NUL / CR / LF.
fn label_value(hay: &[u8], label: &[u8]) -> Option<String> {
    let i = find(hay, label)? + label.len();
    let rest = &hay[i..];
    let end = rest
        .iter()
        .position(|&b| b == 0 || b == 0x0d || b == 0x0a)
        .unwrap_or(rest.len());
    let v = clean(&rest[..end]);
    (!v.is_empty()).then_some(v)
}

/// The leading `n` bytes of `image` (or all of it, if shorter).
fn header(image: &[u8], n: usize) -> &[u8] {
    &image[..image.len().min(n)]
}

/// The run of printable ASCII (0x20..=0x7e) at the start of `s`, capped at `max`.
fn printable_run(s: &[u8], max: usize) -> &[u8] {
    let end = s
        .iter()
        .take(max)
        .position(|&b| !(0x20..=0x7e).contains(&b))
        .unwrap_or(s.len().min(max));
    &s[..end]
}

/// Trim, keep only printable bytes, and collapse to a display string.
fn clean(s: &[u8]) -> String {
    String::from_utf8_lossy(s)
        .chars()
        .filter(|&c| ('\u{20}'..='\u{7e}').contains(&c))
        .collect::<String>()
        .trim()
        .to_string()
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find(hay, needle).is_some()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[path = "imageid_tests.rs"]
mod tests;
