//! Unit tests for [`super`] (protocol probes, input formats, drive identity).

use super::*;
use crate::backend::{sanitize_ascii, try_read_identity};
use crate::platform::MockScsiDevice;

/// The id of the uniquely matching backend, if any.
fn matched(dev: &mut dyn ScsiDevice) -> Option<&'static str> {
    resolve(dev).ok().flatten().map(|r| r.matched.backend.0)
}

fn f1_sat() -> Vec<u8> {
    let mut response = vec![0u8; 48];
    response[16..24].copy_from_slice(b"SAT 8A10");
    response
}

#[test]
fn classify_mtk_from_get_config_010c() {
    let mut dev = MockScsiDevice::mtk();
    assert_eq!(matched(&mut dev), Some("mtk19xx"));
    let matched = resolve(&mut dev).unwrap().unwrap();
    assert_eq!(matched.matched.backend.0, "mtk19xx");
    assert_eq!(Some(matched.matched.backend.0), Some("mtk19xx"));
    assert!(dev.writes.is_empty());
}

#[test]
fn pioneer_identity_prevents_mtk_vendor_probe_even_if_standard_feature_matches() {
    let mut inq = vec![0u8; 96];
    inq[8..16].copy_from_slice(b"PIONEER ");
    inq[16..24].copy_from_slice(b"BDR-UD04");
    let mut dev = MockScsiDevice::mtk()
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            f1_sat(),
        )
        .on(|cdb| cdb.first() == Some(&0x12), inq);
    let matched = resolve(&mut dev).unwrap().unwrap();
    assert_eq!(Some(matched.matched.backend.0), Some("pioneer-oem"));
    assert!(!dev
        .reads
        .iter()
        .any(|cdb| { cdb.first() == Some(&0x3C) && cdb.get(3..6) == Some(&[0, 0x30, 0][..]) }));
    assert!(dev.writes.is_empty());
}

#[test]
fn f1_without_positive_identity_does_not_select_pioneer() {
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
        f1_sat(),
    );
    assert_eq!(matched(&mut dev), None);
    assert!(dev.writes.is_empty());
}

#[test]
fn f1_with_failed_inquiry_does_not_select_pioneer() {
    let mut dev = MockScsiDevice::new()
        .on_fail(|cdb| cdb.first() == Some(&0x12), "INQUIRY transport failed")
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            f1_sat(),
        );
    assert!(resolve(&mut dev).unwrap().is_none());
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
            f1_sat(),
        );
    assert!(resolve(&mut dev).unwrap().is_none());
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
    assert!(resolve(&mut dev).unwrap().is_none());
    assert!(dev.writes.is_empty());
}

#[test]
fn protocol_match_keeps_device_identity_separate() {
    let mut dev = MockScsiDevice::renesas();
    assert!(resolve(&mut dev).unwrap().is_none());
    let identity = read_identity(&mut dev);
    assert_eq!(identity.vendor, "RENESAS");
    assert!(dev.writes.is_empty());
}

/// Regression guard: a drive that answers GET CONFIG 0x010C with the standard
/// MMC "Firmware Information" descriptor (as any compliant non-MTK drive
/// implementing feature 0x010C would) but does NOT carry the MT19 boot banner
/// at `0x003000` MUST match no backend — never MTK. This is
/// exactly the mis-classification the `has_mt19_banner` gate was added to
/// prevent (0x010C alone is not authoritative; the banner is the hardware
/// signature that anchors the MTK identification).
#[test]
fn classify_unknown_when_010c_matches_but_mt19_banner_absent() {
    let mut fd = vec![0u8; 28];
    fd[8] = 0x01;
    fd[9] = 0x0C;
    // Only 0x010C is wired; the zero-filled boot ROM has no `MT19` banner, so
    // the banner gate keeps this drive unclassified.
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x46) && cdb.get(2..4) == Some(&[0x01, 0x0C][..]),
        fd,
    );
    assert_eq!(
        matched(&mut dev),
        None,
        "0x010C echo alone must NOT be enough to classify as MTK — the MT19 boot banner is \
         a required second gate. A compliant non-MTK drive that also implements 0x010C would \
         otherwise be misclassified and become a `flash --allow-crossflash` target."
    );
}

#[test]
fn classify_pioneer_from_read_buffer_f1() {
    let mut dev = MockScsiDevice::pioneer();
    assert_eq!(matched(&mut dev), Some("pioneer-oem"));
}

#[test]
fn real_pioneer_inquiry_product_tokens_classify_without_mtk_rom_read() {
    for product in [
        "BD-RW   BDR-UD04",
        "BD-ROM  BDC-S02",
        "DVD-RW  DVR-216",
        "BDE-PR1EP  PP100",
        "BDW-PR1EPDVPP100",
        "BDR-PR1EPA PP100",
        "NEW-MODEL PP200",
        "",
    ] {
        let mut inq = vec![b' '; 96];
        inq[0] = 0x05;
        inq[8..16].copy_from_slice(b"PIONEER ");
        inq[16..32].copy_from_slice(format!("{product:<16}").as_bytes());
        let mut dev = MockScsiDevice::new()
            .on(|cdb| cdb.first() == Some(&0x12), inq)
            .on(
                |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
                f1_sat(),
            );
        let matched = resolve(&mut dev).unwrap().unwrap();
        assert_eq!(
            Some(matched.matched.backend.0),
            Some("pioneer-oem"),
            "{product}"
        );
        assert!(dev.reads.iter().any(|cdb| {
            cdb.first() == Some(&0x3C)
                && cdb.get(1) == Some(&0x02)
                && cdb.get(2) == Some(&0xF1)
                && cdb.get(6..9) == Some(&[0, 0, 48][..])
        }));
        assert!(!dev
            .reads
            .iter()
            .any(|cdb| { cdb.first() == Some(&0x3C) && cdb.get(3..6) == Some(&[0, 0x30, 0][..]) }));
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn publisher_drive_identity_still_requires_pioneer_hardware_response() {
    for vendor in [b"PIONEER ", b"ACME    "] {
        for response in [f1_sat(), vec![0xA5; 48], vec![0; 8]] {
            let mut inquiry = vec![b' '; 96];
            inquiry[0] = 0x05;
            inquiry[8..16].copy_from_slice(vendor);
            inquiry[16..32].copy_from_slice(b"BDE-PR1EP  PP100");
            let mut dev = MockScsiDevice::new()
                .on(|cdb| cdb.first() == Some(&0x12), inquiry)
                .on(
                    |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
                    response.clone(),
                );
            let result = resolve(&mut dev).unwrap();
            assert_eq!(
                result.is_some(),
                vendor == b"PIONEER " && response == f1_sat()
            );
            assert_eq!(
                dev.reads.iter().any(|cdb| cdb.first() == Some(&0x3C)),
                vendor == b"PIONEER "
            );
            assert!(dev.writes.is_empty());
        }
    }
}

#[test]
fn old_pioneer_hardware_is_classified_but_malformed_f1_is_not() {
    let mut inq = vec![b' '; 96];
    inq[0] = 0x05;
    inq[8..16].copy_from_slice(b"PIONEER ");
    inq[16..32].copy_from_slice(b"DVD-RW  DVR-216 ");
    for hardware in [b"ATA 0009", b"SCSI0001"] {
        let mut f1 = vec![0u8; 48];
        f1[16..24].copy_from_slice(hardware);
        let mut dev = MockScsiDevice::new()
            .on(|cdb| cdb.first() == Some(&0x12), inq.clone())
            .on(
                |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
                f1,
            );
        assert_eq!(
            resolve(&mut dev).unwrap().unwrap().matched.backend.0,
            "pioneer-oem"
        );
        assert!(dev.writes.is_empty());
    }
    let mut dev = MockScsiDevice::new()
        .on(|cdb| cdb.first() == Some(&0x12), inq)
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            vec![0xA5; 8],
        );
    assert!(resolve(&mut dev).unwrap().is_none());
    assert!(dev.writes.is_empty());
}

#[test]
fn classify_unknown_when_no_discriminator() {
    let mut dev = MockScsiDevice::new();
    assert_eq!(matched(&mut dev), None);
}

#[test]
fn flash_input_formats_follow_the_drive_and_foreign_package_names() {
    let path = std::path::Path::new;
    let format = |b: &dyn Backend, p| flash_input_format(b, path(p), b"").unwrap().unwrap().id;
    assert_eq!(format(&MTK, "dump.tar"), "mtk-package");
    assert_eq!(format(&MTK, "fw.bin"), "mtk-image");
    assert_eq!(format(&MTK, "image"), "mtk-image");
    // A Pioneer package name is a Pioneer package even on a MediaTek drive.
    assert_eq!(format(&MTK, "UD04.firmware.tar"), "pioneer-package");
    assert_eq!(format(&MTK, "UD04.INSTALLER.TAR"), "pioneer-package");
    assert_eq!(format(&PIONEER, "x.tar"), "pioneer-package");
    assert_eq!(format(&PIONEER, "normal.enc"), "pioneer-envelope");
}

#[test]
fn mtk_identity_parses_boot_banner_from_32b_region() {
    // The banner read must ask for exactly the 32-byte region — a real drive
    // rejects a larger read (ILLEGAL REQUEST), which used to leave banner empty.
    let mut banner = b"MT1959 Boot BU5 ".to_vec();
    banner.push(0x00); // NUL ends the printable run
    banner.resize(32, 0x00);
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x3C) && cdb.get(3..6) == Some(&[0x00, 0x30, 0x00][..]),
        banner,
    );
    let id = MTK.identity(&mut ReadDevice::without_unlocks(&mut dev));
    assert_eq!(id.banner.as_deref(), Some("MT1959 Boot BU5"));
}

#[test]
fn unknown_identity_uses_only_standard_inquiry_before_protocol_probes() {
    let mut dev = MockScsiDevice::new();
    let id = read_identity(&mut dev);
    assert!(id.banner.is_none());
    assert_eq!(dev.reads.len(), 1);
    assert_eq!(dev.reads[0][0], 0x12);
    assert!(dev.writes.is_empty());
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

#[test]
fn failed_inquiry_is_an_error_not_an_empty_identity() {
    struct Broken;
    impl ScsiDevice for Broken {
        fn command_in(&mut self, _cdb: &[u8], _alloc: usize) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("permission denied")
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "broken".into()
        }
    }
    let err = try_read_identity(&mut Broken).unwrap_err();
    assert!(format!("{err:#}").contains("permission denied"));
    // The infallible wrapper still returns an empty identity.
    assert!(read_identity(&mut Broken).product.is_empty());
}

#[test]
fn short_inquiry_is_an_error_not_an_unknown_model() {
    struct Short;
    impl ScsiDevice for Short {
        fn command_in(&mut self, _cdb: &[u8], _alloc: usize) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0; 35])
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> anyhow::Result<()> {
            panic!("identity must not write")
        }
        fn describe(&self) -> String {
            "short inquiry".into()
        }
    }
    assert!(try_read_identity(&mut Short)
        .unwrap_err()
        .to_string()
        .contains("short INQUIRY identity: 35"));
}

#[test]
fn truncated_feature_header_is_not_protocol_evidence() {
    let mut reply = vec![0; 10];
    reply[8..10].copy_from_slice(&[1, 12]);
    let mut dev = MockScsiDevice::new().on(|cdb| cdb.first() == Some(&0x46), reply);
    assert!(!mtk::get_config_is_mtk(&mut dev));
}

#[test]
fn truncated_boot_rom_is_not_protocol_evidence() {
    let mut dev = MockScsiDevice::new().on(|cdb| cdb.first() == Some(&0x3c), b"MT1959".to_vec());
    assert!(!mtk::has_mt19_banner(&mut dev));
}
