//! Unit tests for [`super`] (classification, input sniffing, the MTK-gate).

use super::*;
use crate::platform::MockScsiDevice;
use std::path::Path;

#[test]
fn classify_mtk_from_get_config_010c() {
    let mut dev = MockScsiDevice::mtk();
    assert_eq!(classify(&mut dev), Family::Mtk);
    let matched = resolve_backend(&mut dev).unwrap().unwrap();
    assert_eq!(matched.evidence.backend_name, "mtk19xx");
    assert_eq!(matched.evidence.family, Family::Mtk);
    assert!(dev.writes.is_empty());
}

#[test]
fn registry_rejects_overlapping_protocol_matches() {
    let mut inq = vec![0u8; 96];
    inq[8..16].copy_from_slice(b"PIONEER ");
    inq[16..24].copy_from_slice(b"BDR-UD04");
    let mut dev = MockScsiDevice::mtk()
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            vec![0xA5; 8],
        )
        .on(|cdb| cdb.first() == Some(&0x12), inq);
    let error = resolve_backend(&mut dev).unwrap_err().to_string();
    assert!(error.contains("ambiguous firmware protocol"));
    assert!(error.contains("mtk19xx"));
    assert!(error.contains("pioneer-oem"));
    assert_eq!(classify(&mut dev), Family::Unknown);
    assert!(dev.writes.is_empty());
}

#[test]
fn f1_without_positive_identity_does_not_select_pioneer() {
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
        vec![0xA5; 8],
    );
    assert_eq!(classify(&mut dev), Family::Unknown);
    assert!(dev.writes.is_empty());
}

#[test]
fn f1_with_failed_inquiry_does_not_select_pioneer() {
    let mut dev = MockScsiDevice::new()
        .on_fail(|cdb| cdb.first() == Some(&0x12), "INQUIRY transport failed")
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            vec![0xA5; 8],
        );
    assert!(resolve_backend(&mut dev).unwrap().is_none());
    assert!(dev.writes.is_empty());
}

#[test]
fn f1_with_unrelated_vendor_does_not_select_pioneer() {
    let mut inq = vec![0u8; 96];
    inq[8..16].copy_from_slice(b"ACME    ");
    inq[16..24].copy_from_slice(b"BDR-UD04");
    let mut dev = MockScsiDevice::new()
        .on(|cdb| cdb.first() == Some(&0x12), inq)
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            vec![0xA5; 8],
        );
    assert!(resolve_backend(&mut dev).unwrap().is_none());
    assert!(dev.writes.is_empty());
}

#[test]
fn mt19_banner_without_mmc_feature_does_not_match() {
    let mut boot_rom = vec![0u8; 32];
    boot_rom[..15].copy_from_slice(b"MT1959 Boot BU5");
    let mut dev = MockScsiDevice::new().on(
        |cdb| {
            cdb.first() == Some(&0x3C)
                && cdb.get(1).map(|m| m & 0x1f) == Some(0x06)
                && cdb.get(3..6) == Some(&[0x00, 0x30, 0x00][..])
        },
        boot_rom,
    );
    assert!(resolve_backend(&mut dev).unwrap().is_none());
    assert!(dev.writes.is_empty());
}

#[test]
fn protocol_match_keeps_device_identity_separate() {
    let mut dev = MockScsiDevice::renesas();
    assert!(resolve_backend(&mut dev).unwrap().is_none());
    let identity = read_identity(&mut dev);
    assert_eq!(identity.vendor, "RENESAS");
    assert!(dev.writes.is_empty());
}

/// Regression guard: a drive that answers GET CONFIG 0x010C with the standard
/// MMC "Firmware Information" descriptor (as any compliant non-MTK drive
/// implementing feature 0x010C would) but does NOT carry the MT19 boot banner
/// at `0x003000` MUST classify as [`Family::Unknown`] — never MTK. This is
/// exactly the mis-classification the `has_mt19_banner` gate was added to
/// prevent (0x010C alone is not authoritative; the banner is the hardware
/// signature that anchors the MTK identification).
#[test]
fn classify_unknown_when_010c_matches_but_mt19_banner_absent() {
    let mut fd = vec![0u8; 28];
    fd[8] = 0x01;
    fd[9] = 0x0C;
    // Only the 0x010C echo is wired; the 0x003000 boot-ROM read falls to the
    // mock's zero-fill default, so `has_mt19_banner` sees no `MT19` substring
    // and returns false. Without the banner gate this would incorrectly
    // classify MTK.
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x46) && cdb.get(2..4) == Some(&[0x01, 0x0C][..]),
        fd,
    );
    assert_eq!(
        classify(&mut dev),
        Family::Unknown,
        "0x010C echo alone must NOT be enough to classify as MTK — the MT19 boot banner is \
         a required second gate. A compliant non-MTK drive that also implements 0x010C would \
         otherwise be misclassified and become a `flash --allow-crossflash` target."
    );
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
    assert_eq!(
        sniff_input(Path::new("UD04.firmware.tar")),
        InputKind::PioneerBundle
    );
    assert_eq!(sniff_input(Path::new("fw.bin")), InputKind::Bin);
    assert_eq!(sniff_input(Path::new("image")), InputKind::Bin);
}

#[test]
fn dump_only_families_stay_read_only() {
    // Unknown is inert. Pioneer is exercised by its own tests.
    {
        let handler = for_family(Family::Unknown);
        assert!(!handler.is_supported());
        let mut dev = MockScsiDevice::new();
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
