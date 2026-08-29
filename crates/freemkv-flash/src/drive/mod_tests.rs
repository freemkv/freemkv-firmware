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
