//! Unit tests for [`super`] (protocol probes, input formats, drive identity).

use super::*;
use crate::backend::{read_identity, sanitize_ascii, try_read_identity, FlashRequest, ReadDevice};
use crate::platform::MockScsiDevice;

/// The id of the uniquely matching backend, if any.
fn matched(dev: &mut dyn ScsiDevice) -> Option<&'static str> {
    resolve(dev).ok().flatten().map(|r| r.matched.backend.0)
}

fn f1_sat() -> Vec<u8> {
    let mut response = vec![0u8; 48];
    response[16..24].copy_from_slice(b"SAT 8A10");
    response[24..28].copy_from_slice(b"ID40");
    response[32..36].copy_from_slice(b"ID40");
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
fn conflicting_protocol_evidence_is_ambiguous_regardless_of_name() {
    let mut inq = vec![0; 96];
    inq[0] = 5;
    inq[8..16].copy_from_slice(b"PIONEER ");
    let mut dev = MockScsiDevice::mtk()
        .on(|c| c.first() == Some(&0x12), inq)
        .on(|c| c.get(..3) == Some(&[0x3c, 2, 0xf1]), f1_sat());
    assert!(resolve(&mut dev)
        .err()
        .unwrap()
        .to_string()
        .contains("ambiguous"));
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
    assert!(resolve(&mut dev)
        .err()
        .unwrap()
        .is::<crate::backend::detection::Unavailable>());
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

fn pioneer_capture_device(hardware: &[u8]) -> MockScsiDevice {
    let mut inquiry = vec![b' '; 96];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"BD-RW BDR-L08SHB");
    inquiry[32..36].copy_from_slice(b"1.00");
    let mut f1 = vec![b' '; 48];
    f1[16..24].copy_from_slice(hardware);
    f1[24..28].copy_from_slice(b"ID40");
    f1[32..36].copy_from_slice(b"ID40");
    MockScsiDevice::new()
        .on(|c| c.first() == Some(&0x12), inquiry)
        .on(|c| c.get(..3) == Some(&[0x3c, 2, 0xf1]), f1)
}

#[test]
fn rec_and_new_pioneer_identities_offer_dump_without_oem_write_facets() {
    for hardware in [b"REC 8301", b"REC 8800", b"REC 8C00", b"NEW 1234"] {
        let mut dev = pioneer_capture_device(hardware);
        let resolved = resolve(&mut dev).unwrap().expect("Pioneer dump route");
        let caps = crate::backend::Capabilities::of(resolved.backend);
        assert!(caps.dump);
        assert!(!caps.backup && !caps.flash && !caps.recovery && !caps.flash_current);
        assert!(resolved.backend.files().is_none());
        assert!(dev.writes.is_empty());
        assert!(crate::workflow::classify_gated(&mut dev).is_err());
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn rec_dump_reaches_existing_memory_capture_and_saves_raw_bytes() {
    for hardware in [b"REC 8301", b"REC 8800", b"REC 8C00"] {
        let mut dev = pioneer_capture_device(hardware)
            .on(|c| c.get(..3) == Some(&[0x3c, 2, 0xb0]), vec![0x5a; 0x8000]);
        let resolved = resolve(&mut dev).unwrap().expect("Pioneer dump route");
        let out = std::env::temp_dir().join(format!(
            "rec-dump-{}-{}.bin",
            std::process::id(),
            String::from_utf8_lossy(hardware)
        ));
        crate::engine::backup(&mut dev, resolved.backend, &out, true).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(&bytes[0x410000..0x418000], &[0x5a; 0x8000]);
        assert!(crate::backends::pioneer::dump::directory(&bytes)
            .unwrap()
            .is_some());
        assert_eq!(
            dev.writes,
            [(pioneer_optical::cdb::knock().to_vec(), vec![])]
        );
        std::fs::remove_file(&out).unwrap();
        let reads = dev.reads.len();
        assert!(crate::engine::backup(&mut dev, resolved.backend, &out, false).is_err());
        assert!(!out.exists());
        assert_eq!(dev.reads.len(), reads);
    }
}

#[test]
fn dump_fallback_does_not_accept_empty_or_nonprintable_hardware() {
    for hardware in [
        b"        ",
        b"REC \0\0\0\0",
        b"\xff\xff\xff\xff\xff\xff\xff\xff",
    ] {
        let mut dev = pioneer_capture_device(hardware);
        assert!(resolve(&mut dev).unwrap().is_none());
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn real_pioneer_inquiry_product_tokens_do_not_select_the_protocol() {
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
        assert!(dev
            .reads
            .iter()
            .any(|cdb| cdb.get(..6) == Some(&[0x3c, 6, 0, 0, 0x30, 0])));
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
            let result = resolve(&mut dev);
            if response.len() < 44 {
                assert!(result
                    .err()
                    .unwrap()
                    .is::<crate::backend::detection::Unavailable>());
            } else {
                assert_eq!(result.unwrap().is_some(), response == f1_sat());
            }
            assert!(dev.reads.iter().any(|cdb| cdb.first() == Some(&0x3C)));
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
        f1[24..28].copy_from_slice(b"ID40");
        f1[32..36].copy_from_slice(b"ID40");
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
    assert!(resolve(&mut dev)
        .err()
        .unwrap()
        .is::<crate::backend::detection::Unavailable>());
    assert!(dev.writes.is_empty());
}

#[test]
fn classify_unknown_when_no_discriminator() {
    let mut dev = MockScsiDevice::new();
    assert_eq!(matched(&mut dev), None);
}

#[test]
fn update_input_formats_follow_the_drive_and_foreign_package_names() {
    let path = std::path::Path::new;
    let format = |b: &dyn Backend, p| update_input_format(b, path(p), b"").unwrap().unwrap().id;
    assert_eq!(format(&MTK, "dump.tar"), "mtk-package");
    assert_eq!(format(&MTK, "fw.bin"), "mtk-image");
    assert_eq!(format(&MTK, "image"), "mtk-image");
    // A Pioneer package name is a Pioneer package even on a MediaTek drive.
    assert_eq!(format(&MTK, "UD04.firmware.tar"), "pioneer-package");
    assert_eq!(format(&MTK, "UD04.INSTALLER.TAR"), "pioneer-package");
    assert_eq!(format(&PIONEER, "x.tar"), "pioneer-package");
    assert!(update_input_format(&PIONEER, path("normal.enc"), b"").is_err());
}

#[test]
fn unrecognized_tar_is_not_evidence_of_pioneer_firmware() {
    let mut tar = tar::Builder::new(Vec::new());
    let manifest = br#"{"format":"freemkv-mediatek-package","version":1,"components":[]}"#;
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "manifest.json", &manifest[..])
        .unwrap();
    let bytes = tar.into_inner().unwrap();
    assert!(recognize(&bytes).unwrap().is_none());
    let format = update_input_format(&MTK, Path::new("WH16NS58_1.V9-patched.tar"), &bytes)
        .unwrap()
        .unwrap();
    assert_eq!(format.id, "mtk-package");
    let mut dev = MockScsiDevice::mtk();
    let request = FlashRequest {
        current: None,
        input: bytes,
        input_format: format,
        mode: crate::manifest::FlashMode::Full,
        execute: false,
        acknowledged_risk: false,
        enc_override: None,
        drive_model: "BD-RE WH16NS58".into(),
        verbose: false,
        predump_out: None,
    };
    let error = MTK
        .flash()
        .unwrap()
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &request)
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("package needs one final image"),
        "{error:#}"
    );
    assert!(!error.to_string().contains("Pioneer"));
    assert!(dev.writes.is_empty());
}

#[test]
fn mtk_identity_parses_boot_banner_from_32b_region() {
    // The banner read must ask for exactly the 32-byte region — a real drive
    // rejects a larger read (ILLEGAL REQUEST), which used to leave banner empty.
    let mut banner = b"MT1959 Boot BU5 ".to_vec();
    banner.push(0x00); // NUL ends the printable run
    banner.resize(32, 0x00);
    struct BannerDrive(Vec<u8>);
    impl ScsiDevice for BannerDrive {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
            if cdb.first() == Some(&0x3c) && cdb.get(3..6) == Some(&[0, 0x30, 0][..]) {
                assert_eq!(cdb.get(6..9), Some(&[0, 0, 32][..]), "32-byte CDB transfer");
                assert_eq!(len, 32, "32-byte host allocation");
                return Ok(self.0.clone());
            }
            Ok(vec![0; len])
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> anyhow::Result<()> {
            panic!("identity must not write");
        }
        fn describe(&self) -> String {
            "strict 32-byte boot region".into()
        }
    }
    let mut dev = BannerDrive(banner);
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
    assert!(mtk::Acquire::GetConfig {
        feature: mtk::FEATURE_FWDATE,
        alloc: 32
    }
    .run(&mut dev)
    .is_err());
}

#[test]
fn truncated_boot_rom_is_not_protocol_evidence() {
    let mut inquiry = [0; 36];
    inquiry[0] = 5;
    assert!(mediatek_optical::protocol::Evidence::parse(&inquiry, b"MT1959").is_err());
}

#[test]
fn asus_report_8591_id22_resolves_without_branding() {
    let mut inquiry = vec![b' '; 96];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(b"ASUS    ");
    inquiry[16..32].copy_from_slice(b"SBC-06D2X-U     ");
    inquiry[32..36].copy_from_slice(b"1.10");
    let mut f1 = vec![b' '; 48];
    f1[..12].copy_from_slice(b"LJDL050094WL");
    f1[16..24].copy_from_slice(b"SAT 8591");
    f1[24..28].copy_from_slice(b"ID22");
    f1[32..36].copy_from_slice(b"ID22");
    f1[40..44].copy_from_slice(b"0000");
    let mut dev = MockScsiDevice::new()
        .on(|c| c.first() == Some(&0x12), inquiry)
        .on(|c| c.get(..3) == Some(&[0x3c, 2, 0xf1]), f1);
    let result = resolve(&mut dev)
        .unwrap()
        .expect("ASUS report has Pioneer protocol evidence");
    assert_eq!(result.matched.backend.0, "pioneer-oem");
    assert_eq!(result.identity.vendor, "ASUS");
    assert!(dev.writes.is_empty());
}

#[test]
fn protocol_transport_failure_is_not_an_unsupported_drive() {
    let mut inquiry = vec![0; 96];
    inquiry[0] = 5;
    let mut dev = MockScsiDevice::new()
        .on(|c| c.first() == Some(&0x12), inquiry)
        .on_fail(|c| c.get(..3) == Some(&[0x3c, 2, 0xf1]), "USB disconnected");
    let error = resolve(&mut dev)
        .err()
        .expect("transport error must survive");
    assert!(error.is::<crate::backend::detection::Unavailable>());
    assert!(dev
        .reads
        .iter()
        .any(|c| c.get(..6) == Some(&[0x3c, 6, 0, 0, 0x30, 0])));
    assert!(dev.writes.is_empty());
}

#[test]
fn rejected_other_protocol_probe_does_not_hide_a_valid_signature() {
    let mut dev =
        MockScsiDevice::mtk().on_sense(|c| c.get(..3) == Some(&[0x3c, 2, 0xf1]), 5, 0x24, 0);
    assert_eq!(
        resolve(&mut dev).unwrap().unwrap().matched.backend.0,
        "mtk19xx"
    );
    assert_eq!(dev.reads.len(), 3);
    assert!(dev.writes.is_empty());
}

#[test]
fn failed_foreign_probe_does_not_hide_either_native_protocol() {
    let devices = [
        (
            MockScsiDevice::mtk().on_fail(
                |c| c.get(..3) == Some(&[0x3c, 2, 0xf1]),
                "bridge rejected foreign CDB",
            ),
            "mtk19xx",
        ),
        (
            MockScsiDevice::pioneer().on_fail(
                |c| c.get(..6) == Some(&[0x3c, 6, 0, 0, 0x30, 0]),
                "bridge rejected foreign CDB",
            ),
            "pioneer-oem",
        ),
    ];
    for (mut dev, expected) in devices {
        assert_eq!(
            resolve(&mut dev).unwrap().unwrap().matched.backend.0,
            expected
        );
        assert_eq!(dev.reads.len(), 3);
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn real_boot_code_windows_restore_oem_profiles_and_picker_formats() {
    // Exact boot windows from BH14NS40 1.02 and BH16NS40 NS50 1.05.
    // Their executable bytes after the NUL were rejected by 0.14.5 discovery.
    for window in [
        b"MT1939 Boot Code\0\0\0\xea\x7e\x15\0\xea\x28\0\x8f\xe2\0\x0c\x90\xe8",
        b"MT1959 Boot JB8 \0\0\0\xea\xa9\x15\0\xea\x28\0\x8f\xe2\0\x0c\x90\xe8",
    ] {
        let bytes = window.to_vec();
        for vendor in ["HL-DT-ST", "ASUS", "LITE-ON", "PLEXTOR", "OEM"] {
            let mut inquiry = vec![b' '; 96];
            inquiry[..8].fill(0);
            inquiry[0] = 5;
            inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
            let mut dev = MockScsiDevice::new()
                .on(|c| c.first() == Some(&0x12), inquiry)
                .on(
                    |c| c.get(..6) == Some(&[0x3c, 6, 0, 0, 0x30, 0]),
                    bytes.clone(),
                );
            let profile = crate::workflow::profile_on(&mut dev).unwrap();
            assert_eq!(profile.backend.as_ref().unwrap().1.backend.0, "mtk19xx");
            assert!(!profile.flash_formats.is_empty());
            assert!(profile
                .firmware_picker_formats()
                .extensions()
                .unwrap()
                .contains(&"bin"));
            assert!(dev.writes.is_empty());
        }
    }
}

#[test]
fn banner_identification_needs_no_firmware_date_feature_or_vendor_name() {
    let mut inquiry = vec![0; 96];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    let mut dev = MockScsiDevice::mtk()
        .on(|c| c.first() == Some(&0x12), inquiry)
        .on_fail(
            |c| c.first() == Some(&0x46),
            "metadata should not be queried during discovery",
        );
    assert_eq!(
        resolve(&mut dev).unwrap().unwrap().matched.backend.0,
        "mtk19xx"
    );
    assert!(!dev.reads.iter().any(|c| c.first() == Some(&0x46)));
}

#[test]
fn incomplete_signature_cannot_authorize_normal_backend() {
    let mut inquiry = vec![0; 96];
    inquiry[0] = 5;
    let mut dev = MockScsiDevice::new()
        .on(|c| c.first() == Some(&0x12), inquiry)
        .on(
            |c| c.get(..3) == Some(&[0x3c, 2, 0xf1]),
            f1_sat()[..24].to_vec(),
        );
    let error = resolve(&mut dev)
        .err()
        .expect("incomplete identification is inconclusive");
    assert!(error.is::<crate::backend::detection::Unavailable>());
    assert!(dev.writes.is_empty());
}
