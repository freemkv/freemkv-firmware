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
