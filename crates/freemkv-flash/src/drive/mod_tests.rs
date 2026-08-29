//! Unit tests for [`super`] (classification, input sniffing, the MTK-gate).

use super::*;
use crate::platform::MockScsiDevice;
use std::path::Path;

#[test]
fn classify_mtk_from_get_config_010c() {
    let mut dev = MockScsiDevice::mtk();
    assert_eq!(classify(&mut dev), Family::Mtk);
}

#[test]
fn classify_pioneer_from_read_buffer_f1() {
    let mut dev = MockScsiDevice::pioneer();
    assert_eq!(classify(&mut dev), Family::Pioneer);
}

#[test]
fn classify_unknown_when_no_discriminator() {
    let mut dev = MockScsiDevice::new();
    assert_eq!(classify(&mut dev), Family::Unknown);
}

#[test]
fn sniff_picks_tar_vs_bin() {
    assert_eq!(sniff_input(Path::new("dump.tar")), InputKind::Tar);
    assert_eq!(sniff_input(Path::new("fw.bin")), InputKind::Bin);
    assert_eq!(sniff_input(Path::new("image")), InputKind::Bin);
}

#[test]
fn mtk_gate_blocks_non_mtk_families() {
    for fam in [Family::Pioneer, Family::Renesas, Family::Unknown] {
        let handler = for_family(fam);
        assert!(!handler.is_supported());
        let mut dev = MockScsiDevice::new();
        // Every drive-touching primitive errors, and none issues a write CDB.
        assert!(handler.read_dump(&mut dev).is_err());
        assert!(handler
            .flash_open(&mut dev, crate::manifest::FlashMode::Full)
            .is_err());
        assert!(handler.write_region(&mut dev, 0x1000, &[0u8; 4]).is_err());
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn for_family_reports_the_expected_family() {
    assert_eq!(for_family(Family::Mtk).family(), Family::Mtk);
    assert_eq!(for_family(Family::Pioneer).family(), Family::Pioneer);
    assert_eq!(for_family(Family::Renesas).family(), Family::Renesas);
    assert_eq!(for_family(Family::Unknown).family(), Family::Unknown);
}

#[test]
fn read_identity_parses_boot_banner_from_32b_region() {
    // The banner read must ask for exactly the 32-byte region — a real drive
    // rejects a larger read (ILLEGAL REQUEST), which used to leave banner empty.
    let mut banner = b"MT1959 Boot BU5 ".to_vec();
    banner.push(0x00); // NUL ends the printable run
    banner.resize(32, 0x00);
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x3C) && cdb.get(3..6) == Some(&[0x00, 0x30, 0x00][..]),
        banner,
    );
    let id = read_identity(&mut dev);
    assert_eq!(id.banner.as_deref(), Some("MT1959 Boot BU5"));
}

#[test]
fn sanitize_ascii_strips_control_and_escape_bytes() {
    // A malicious/garbled drive string with an ANSI escape, NUL and BEL: all
    // non-printable bytes become '.', printable ASCII is preserved.
    let clean = sanitize_ascii("OK\u{1b}[31mRED\u{0}\u{7}END");
    assert!(!clean.contains('\u{1b}'));
    assert!(!clean.contains('\u{0}'));
    assert!(!clean.contains('\u{7}'));
    assert_eq!(
        sanitize_ascii("HL-DT-ST BD-RE BU40N"),
        "HL-DT-ST BD-RE BU40N"
    );
}
