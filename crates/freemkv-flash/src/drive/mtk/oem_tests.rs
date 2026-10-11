//! Unit tests for [`super`] (embedded MediaTek OEM catalog).

use super::*;
use mediatek_optical::layout;

#[test]
fn embedded_catalog_parses_with_both_chip_defaults() {
    let catalog = parse(MTK_OEM).expect("embedded oem.bin parses");
    assert!(catalog.len() >= 200, "{} builds", catalog.len());
    for chip in [Chip::Mt1959, Chip::Mt1939] {
        let f = catalog.default_for(chip).expect("chip default");
        // Every LG/HP/ASUS build in the hoard stores the same boot page.
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(f.boot_page()))[..8],
            *"b75bb1b7"
        );
    }
    // Defaults hold written contents; rebuild keeps an erased region erased.
    for chip in [Chip::Mt1959, Chip::Mt1939] {
        let f = catalog.default_for(chip).unwrap();
        assert!(f.regions()[1..].iter().all(|r| !layout::is_erased(r)));
    }
}

#[test]
fn malformed_tables_are_errors() {
    assert!(parse(b"not gzip").is_err());
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut enc, br#"{"blobs":{},"builds":[],"defaults":{"MT1969":{"boot":"x","regions":["a","b","c","d"]}}}"#).unwrap();
    assert!(parse(&enc.finish().unwrap()).is_err());
}

use sha2::Digest as _;

/// Known answers for the embedded defaults: a regenerated, corrupted or
/// truncated table changes a digest. The MT1959 and MT1939 defaults are
/// currently byte-identical.
#[test]
fn embedded_chip_defaults_match_their_known_digests() {
    const BOOT: &str = "b75bb1b78c075f8aa549eb38a244fa280e6e22d3ea242a6a0177ae67a430daba";
    const REGIONS: [(&str, usize); 4] = [
        (
            "eeb6214694e593a979a96e03f11989994938d07c80eca4c986b549a9db5d031a",
            0x8000,
        ),
        (
            "411afd40ec6f30073717c1aad551d07b3dcfa178ca0a78794616026de6981126",
            0x8000,
        ),
        (
            "6eec8c356c635ec60225964f4ace5e59154b4838c89ce5f856562de28c41f20d",
            0x4000,
        ),
        (
            "41d8a8e70d96d09bebaf703b65d9b87cd95f86b189517f74a8adb6cd0bbe10dd",
            0x1_0000,
        ),
    ];
    let catalog = parse(MTK_OEM).expect("embedded oem.bin parses");
    for chip in [Chip::Mt1959, Chip::Mt1939] {
        let f = catalog.default_for(chip).expect("chip default");
        assert_eq!(format!("{:x}", sha2::Sha256::digest(f.boot_page())), BOOT);
        for (i, (want, len)) in REGIONS.iter().enumerate() {
            let region = &f.regions()[i];
            assert_eq!(region.len(), *len, "{chip:?} region {i} length");
            assert_eq!(
                format!("{:x}", sha2::Sha256::digest(region)),
                *want,
                "{chip:?} region {i}"
            );
        }
    }
}
