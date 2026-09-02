use super::*;

/// A minimal buffer with a valid MT1959 banner + descriptor at the right
/// offsets, everything else zeroed.
fn synthetic(banner: &str, family_tag: &str, model: &str, rev: &str) -> Vec<u8> {
    let mut img = vec![0u8; DESCRIPTOR_OFFSET + DESCRIPTOR_LEN + 0x100];
    img[BANNER_OFFSET..BANNER_OFFSET + banner.len()].copy_from_slice(banner.as_bytes());

    let desc = DESCRIPTOR_OFFSET;
    img[desc..desc + 0x40].fill(b' ');
    img[desc..desc + 8].copy_from_slice(b"HL-DT-ST");
    let m = model.as_bytes();
    img[desc + 0x08..desc + 0x08 + m.len()].copy_from_slice(m);
    let r = rev.as_bytes();
    img[desc + 0x18..desc + 0x18 + r.len()].copy_from_slice(r);
    let t = family_tag.as_bytes();
    img[desc + 0x34..desc + 0x34 + t.len()].copy_from_slice(t);
    img
}

#[test]
fn detects_mt1959() {
    let img = synthetic("MT1959 Boot BU5", "MTEKMT1959", "BD-RE BU40N", "1.00");
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, ChipFamily::Mt1959);
    assert_eq!(chip.vendor, "HL-DT-ST");
    assert_eq!(chip.model, "BD-RE BU40N");
    assert_eq!(chip.rev, "1.00");
    assert_eq!(chip.family.label(), "MT1959");
}

#[test]
fn detects_mt1939() {
    let img = synthetic("MT1939 Boot XX1", "MTEKMT1939", "SOME MODEL", "2.01");
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, ChipFamily::Mt1939);
}

#[test]
fn disagreement_between_banner_and_descriptor_is_refused() {
    let img = synthetic("MT1959 Boot BU5", "MTEKMT1939", "X", "1.00");
    let err = detect_chip(&img).unwrap_err().to_string();
    assert!(err.contains("disagree"), "got: {err}");
}

#[test]
fn unknown_family_tag_is_refused() {
    let img = synthetic("XX9999 Boot", "MTEKXX9999", "X", "1.00");
    let err = detect_chip(&img).unwrap_err().to_string();
    assert!(
        err.contains("does not name a supported chip family"),
        "got: {err}"
    );
}

#[test]
fn too_small_image_is_refused() {
    let img = vec![0u8; 0x100];
    assert!(detect_chip(&img).is_err());
}

/// The real BU40N 1.00 stock image, if present, must resolve to MT1959. The
/// fixture path comes from `FREEMKV_KAT_BASE` (env only — no owned path is baked
/// into this public repo); unset skips the test.
#[test]
fn real_stock_1_00_is_mt1959() {
    let Ok(path) = std::env::var("FREEMKV_KAT_BASE") else {
        eprintln!("skipping: FREEMKV_KAT_BASE unset (OEM BU40N 1.00 image)");
        return;
    };
    let Ok(img) = std::fs::read(&path) else {
        eprintln!("skipping: stock 1.00 image not present at {path}");
        return;
    };
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, ChipFamily::Mt1959);
    assert_eq!(chip.rev, "1.00");
    assert!(chip.model.contains("BU40N"), "got model: {:?}", chip.model);
}

/// The real MK-signed BU40N 1.03 image, if present, must also resolve to
/// MT1959 (same family — the MK re-signer does not cross-flash families).
#[test]
fn real_mk_1_03_is_mt1959() {
    let Ok(path) = std::env::var("FREEMKV_KAT_MK103") else {
        eprintln!("skipping: FREEMKV_KAT_MK103 unset (MK-signed BU40N 1.03 image)");
        return;
    };
    let Ok(img) = std::fs::read(&path) else {
        eprintln!("skipping: MK 1.03 image not present at {path}");
        return;
    };
    let chip = detect_chip(&img).unwrap();
    assert_eq!(chip.family, ChipFamily::Mt1959);
    assert_eq!(chip.rev, "1.03");
}
