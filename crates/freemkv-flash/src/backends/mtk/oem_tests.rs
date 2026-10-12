//! Unit tests for [`super`] (embedded MediaTek OEM catalog).

use super::*;
use mediatek_optical::layout;

#[test]
fn embedded_catalog_parses_with_both_chip_defaults() {
    let catalog = parse(MTK_OEM).expect("embedded oem.bin parses");
    assert_eq!(catalog.len(), 69, "OEM builds");
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

/// Content keys of modified builds the catalog once listed as OEM: their
/// backups must read as reconstructions, never as a vendor file.
const MODIFIED: [(&str, &str); 14] = [
    (
        "538deee75487afd4686941f3ab6fb1758a76defaf2dc9d539c8f849105444e86",
        "DE-patched WH16NS40 1.01",
    ),
    (
        "18571e6932ac129a7c84c09b79d14f2f5e4be36843935e14ecb69d04bea4283e",
        "DE-patched WH16NS40 1.02",
    ),
    (
        "72a35c0fcfd71e6f7d2383c2bb4bf344dbf7d05e562b57db63a5a310491245c3",
        "DE-patched BW-16D1HT 1.01, a unit's calibration",
    ),
    (
        "be95f4b4f166fca07d7908c860367629cd695fa1effe5d38fb342852eb86a2ae",
        "freemkv-fw BU40N 1.00",
    ),
    (
        "bddaf2b31680ff077f2227d014b64afe22c50b68e0bed60eb1d227deb1796dfe",
        "freemkv-fw BU40N 1.00 (gated)",
    ),
    (
        "4a2a98dd7210419d7668167bbb99a59685e934bcd3fcaf128ef5e80208009420",
        "CMAC-invalid unMK BH16NS40 1.05",
    ),
    (
        "f885042147673a9d8052a0650620c5102e1242966f8245d5e8d451e87fcdb5d3",
        "BH16NS55 1.01 drive dump",
    ),
    (
        "58ba2b5bed6bab0c602de6de54e871d0c8e4a6dae97b4603f1868c4e7adf4ef7",
        "MakeMKV-patched BH16NS40 1.03",
    ),
    (
        "53954d69366b5b387402169a96688b51827376aef931a0e94efe4d545bbbad33",
        "loose image, no vendor updater: BD-RE BH40N B7C6",
    ),
    (
        "3f98f96fc47eab363f8c1d50d3cd3a417c75107f5fad05d49dd51d5f00e70485",
        "loose image, no vendor updater: BD-RE WH16NS48 1.D3",
    ),
    (
        "869ac24570f53a10521a7d6b16112476e6ea131588846a1897a0b0bbb59e89b8",
        "loose image, no vendor updater: BD-RE WH16NS58 1.V5",
    ),
    (
        "d84a2392f48d00edf8fe81220d8a8725a86dadb988ac4fffb56f60eb47ebdf80",
        "loose image, no vendor updater: BD-RE BU40N 1.00",
    ),
    (
        "d4d2f7bd49e3dc47be8528314fe8b8782df12b09b9721a6434ed984e03a86396",
        "loose image, no vendor updater: BDRE BU50N BW51",
    ),
    (
        "04716d0e244efa6c0ed458598908915d9c6dab4005eae5fdb4b59e4e6c7edc94",
        "loose image, no vendor updater: BW-16D1HT 3.01",
    ),
];

#[test]
fn catalog_lists_no_modified_build() {
    let catalog = parse(MTK_OEM).unwrap();
    for (key, what) in MODIFIED {
        let key: Digest = hex_decode(key).unwrap().try_into().unwrap();
        assert!(catalog.build(&key).is_none(), "{what} is cataloged as OEM");
    }
}
