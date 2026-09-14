//! Unit tests for [`super`] — family detection from SMALL synthetic headers.
//!
//! Every fixture is a hand-built header (not a hoard binary): the classifier is
//! signature-driven, so a few hundred bytes at the right offsets exercise it
//! exactly as a multi-MB image would, without committing the (out-of-repo) hoard.

use super::*;

/// A minimal MT19xx image: the `MTEKMT1959` descriptor tag + a model/rev field
/// at the descriptor offset, sized so [`freemkv_chipset::detect_chip`] accepts it.
fn mt19xx(model: &str, rev: &str, tag: &str) -> Vec<u8> {
    let desc = freemkv_chipset::DESCRIPTOR_OFFSET;
    let mut img = vec![0u8; desc + 0x100];
    img[desc + 0x08..desc + 0x08 + model.len()].copy_from_slice(model.as_bytes());
    img[desc + 0x18..desc + 0x18 + rev.len()].copy_from_slice(rev.as_bytes());
    img[desc + 0x34..desc + 0x34 + tag.len()].copy_from_slice(tag.as_bytes());
    img
}

/// A minimal Pioneer raw header: `****`, the copyright marker, model @0x70, and
/// the "Revision Level : " label.
fn pioneer(model: &str, rev: &str) -> Vec<u8> {
    let mut img = vec![0u8; 0x200];
    img[..8].fill(b'*');
    img[0x0a..0x0a + 21].copy_from_slice(b"Copyright(c) 2000 Pio");
    img[0x1e..0x1e + 21].copy_from_slice(b"Pioneer Corporation  ");
    img[0x70..0x70 + model.len()].copy_from_slice(model.as_bytes());
    let lbl = b"Revision Level : ";
    img[0x7f..0x7f + lbl.len()].copy_from_slice(lbl);
    img[0x7f + lbl.len()..0x7f + lbl.len() + rev.len()].copy_from_slice(rev.as_bytes());
    img
}

#[test]
fn detects_mt19xx_and_prefers_it() {
    let id = identify(&mt19xx("BD-RE BU40N", "1.05", "MTEKMT1959"));
    assert_eq!(id.family, ImageFamily::MediaTekMt19xx);
    assert_eq!(id.model.as_deref(), Some("BD-RE BU40N"));
    assert_eq!(id.rev.as_deref(), Some("1.05"));
}

#[test]
fn detects_encrypted_mediatek_envelope() {
    let mut img = vec![0u8; 0x2000];
    img[..16].copy_from_slice(&MTEK_ENC_MAGIC);
    let id = identify(&img);
    assert_eq!(id.family, ImageFamily::MediaTekEncrypted);
    assert!(id.model.is_none(), "ciphertext exposes no model");
    assert!(id.note.is_some());
}

#[test]
fn detects_pioneer_raw_with_model_and_rev() {
    let id = identify(&pioneer("BDR-209D", "1.51"));
    assert_eq!(id.family, ImageFamily::Pioneer);
    assert_eq!(id.model.as_deref(), Some("BDR-209D"));
    assert_eq!(id.rev.as_deref(), Some("1.51"));
}

#[test]
fn pioneer_needs_the_copyright_marker_not_just_asterisks() {
    // Eight asterisks alone must NOT be read as Pioneer.
    let mut img = vec![0u8; 0x200];
    img[..8].fill(b'*');
    assert_eq!(identify(&img).family, ImageFamily::Unknown);
}

#[test]
fn detects_pioneer_packed() {
    let mut img = vec![0u8; 0x1000];
    img[..6].copy_from_slice(&PIONEER_PACKED_MAGIC);
    let id = identify(&img);
    assert_eq!(id.family, ImageFamily::Pioneer);
    assert!(id.note.as_deref().unwrap().contains("packaged"));
}

/// Build a 0x418000 dump with `marker` bytes at some offset and `word` at +4.
fn dump(word: u32, marker: Option<(&[u8], &str, &str)>) -> Vec<u8> {
    let mut img = vec![0u8; DUMP_SIZE];
    img[4..8].copy_from_slice(&word.to_be_bytes());
    if let Some((tag, model, rev)) = marker {
        let mut off = 0x100;
        img[off..off + tag.len()].copy_from_slice(tag);
        off = 0x400;
        img[off..off + model.len()].copy_from_slice(model.as_bytes());
        off = 0x800;
        img[off..off + rev.len()].copy_from_slice(rev.as_bytes());
    }
    img
}

#[test]
fn detects_lg_legacy_dump_with_model_and_rev() {
    let id = identify(&dump(
        0x0041_0140,
        Some((
            b"Hitachi-LG Data Storage,Inc.",
            "HL-DT-STBD-RE  GGW-H20N",
            "y217.08.06.09a",
        )),
    ));
    assert_eq!(id.family, ImageFamily::LgLegacy);
    assert_eq!(id.model.as_deref(), Some("HL-DT-STBD-RE  GGW-H20N"));
    assert_eq!(id.rev.as_deref(), Some("y217.08.06.09a"));
}

#[test]
fn detects_renesas_and_bridge_dumps_by_word() {
    assert_eq!(
        identify(&dump(0x005A_80E2, None)).family,
        ImageFamily::Renesas
    );
    assert_eq!(
        identify(&dump(0x0093_87DF, None)).family,
        ImageFamily::Renesas
    );
    assert_eq!(
        identify(&dump(0x00DC_5D5D, None)).family,
        ImageFamily::MediaTekBridge
    );
}

#[test]
fn unrecognized_0x418000_variant_is_named_not_unknown() {
    let id = identify(&dump(0x0000_0000, None));
    assert_eq!(id.family, ImageFamily::Renesas);
    assert!(id.note.as_deref().unwrap().contains("unrecognized"));
}

#[test]
fn detects_intel_hex() {
    let img = b":020000020000FC\r\n:10000000000167626C01200007".to_vec();
    assert_eq!(identify(&img).family, ImageFamily::IntelHex);
}

#[test]
fn genuinely_unknown_blob_is_unknown_not_a_panic() {
    assert_eq!(identify(&[0u8; 64]).family, ImageFamily::Unknown);
    assert_eq!(identify(&vec![0xAAu8; 0x2000]).family, ImageFamily::Unknown);
    assert_eq!(identify(&[]).family, ImageFamily::Unknown);
}

#[test]
fn flash_summary_is_identify_only_and_wires_the_catalog() {
    let p = ImageFamily::Pioneer.flash_summary();
    assert!(p.contains("identify-only"));
    assert!(p.contains("Pioneer"), "catalog recipe surfaced: {p}");
    // A family with no catalog brand is a bare identify-only line.
    assert_eq!(
        ImageFamily::Renesas.flash_summary(),
        "identify-only — not flashable by this tool"
    );
}
