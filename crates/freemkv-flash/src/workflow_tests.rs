use super::*;

#[test]
fn current_detection_error_keeps_transport_diagnostics_out_of_user_guidance() {
    let error = anyhow::Error::new(crate::backend::CurrentFirmwareRequired {
        source: anyhow::anyhow!("SCSI invalid field in CDB at 0x98000 [E4000]"),
    });
    assert!(error_message(&error).contains("Specify the firmware currently installed"));
    assert!(!error_message(&error).contains("E4000"));
    assert!(format!("{error:#}").contains("SCSI invalid field in CDB at 0x98000 [E4000]"));
    let other = anyhow::anyhow!("original cause").context("operation failed");
    assert_eq!(error_message(&other), "operation failed: original cause");
}

#[test]
fn mediatek_boot_without_mmc_feature_still_offers_independent_recovery() {
    use crate::{backends::mtk, platform::MockScsiDevice};
    let mut image = mtk::fixture::image(&mtk::fixture::BU3, "BU40N", 1);
    let signature = image[0x9a300..0x9a30e].to_vec();
    image[0x3500..0x350e].copy_from_slice(&signature);
    let mut inquiry = vec![0; 36];
    inquiry[0] = 5;
    inquiry[4] = 31;
    inquiry[8..16].copy_from_slice(b"ASUS    ");
    inquiry[16..32].fill(b' ');
    inquiry[16..25].copy_from_slice(b"BW-16D1HT");
    inquiry[32..36].copy_from_slice(b"BOOT");
    let mut dev = MockScsiDevice::new()
        .with_firmware_image(image)
        .on(|c| c.first() == Some(&0x12), inquiry)
        // Exact header from the user's BOOT log: no feature descriptor.
        .on(|c| c.first() == Some(&0x46), vec![0, 0, 0, 4, 0, 0, 0, 0]);
    let profile = profile_on(&mut dev).unwrap();
    assert!(profile.backend.is_none());
    assert_eq!(profile.capabilities, crate::backend::Capabilities::NONE);
    assert_eq!(profile.recovery.map(|d| d.id), Some(mtk::DESCRIPTOR.id));
    assert!(!recovery_requires_current(&profile));
    assert!(dev.writes.is_empty());
}

#[test]
fn automatic_backup_path_does_not_reuse_an_existing_backup() {
    let input = std::env::temp_dir().join(format!("fmkv-workflow-{}.bin", std::process::id()));
    let first = default_backup_path(&input, "tar").unwrap();
    std::fs::write(&first, b"previous rollback").unwrap();
    let second = default_backup_path(&input, "tar").unwrap();
    std::fs::remove_file(&first).unwrap();
    assert_ne!(
        first, second,
        "a second flash should not be blocked by the automatic backup name"
    );
}

#[test]
fn regular_file_routes_to_file_info() {
    let path = std::env::temp_dir().join(format!("fmkv-route-{}.bin", std::process::id()));
    std::fs::write(&path, b"firmware").unwrap();
    assert!(is_firmware_file(path.to_str().unwrap()));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn oversized_input_is_rejected_before_opening_a_drive() {
    let path = std::env::temp_dir().join(format!("fmkv-size-{}.bin", std::process::id()));
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024 + 1).unwrap();
    drop(file);
    let error = read_capped(&path).unwrap_err();
    std::fs::remove_file(path).unwrap();
    assert!(error.to_string().contains("exceeds"));
}

fn drive(path: &str, name: &str) -> DriveChoice {
    DriveChoice {
        path: path.into(),
        name: name.into(),
        label: "HL-DT-ST BD-RE BU40N (rev 1.04)".into(),
    }
}

#[test]
fn a_drive_name_resolves_to_its_id() {
    let drives = [drive(r"\\.\CdRom0", "D:"), drive(r"\\.\CdRom1", "E:")];
    assert_eq!(resolve_from(Some("E:"), &drives).unwrap(), r"\\.\CdRom1");
}

#[test]
fn anything_else_is_used_as_the_id() {
    let drives = [drive(r"\\.\CdRom0", "D:"), drive(r"\\.\CdRom1", "E:")];
    assert_eq!(
        resolve_from(Some(r"\\.\CdRom0"), &drives).unwrap(),
        r"\\.\CdRom0"
    );
    assert_eq!(resolve_from(Some("/dev/sg9"), &drives).unwrap(), "/dev/sg9");
    // Only the exact name; list numbers and name variants are not selectors.
    assert_eq!(resolve_from(Some("2"), &drives).unwrap(), "2");
    assert_eq!(resolve_from(Some("e:"), &drives).unwrap(), "e:");
}

#[test]
fn omitted_selector_picks_the_only_drive() {
    let drives = [drive("/dev/sg3", "/dev/sr1")];
    assert_eq!(resolve_from(None, &drives).unwrap(), "/dev/sg3");
}

#[test]
fn several_drives_require_a_name_or_id_and_list_both() {
    let drives = [drive(r"\\.\CdRom0", "D:"), drive("ioreg:42", "ioreg:42")];
    let error = resolve_from(None, &drives).unwrap_err().to_string();
    assert!(error.contains("pass a drive name or id"), "{error}");
    assert!(
        error.contains(r"  D:  HL-DT-ST BD-RE BU40N (rev 1.04)  \\.\CdRom0"),
        "{error}"
    );
    // A drive without an OS name is shown once, by its id.
    assert!(
        error.contains("  ioreg:42  HL-DT-ST BD-RE BU40N (rev 1.04)\n")
            || error.ends_with("  ioreg:42  HL-DT-ST BD-RE BU40N (rev 1.04)"),
        "{error}"
    );
}

fn oem_receiver(vendor: &str) -> crate::platform::MockScsiDevice {
    let mut inquiry = vec![b' '; 36];
    inquiry[..8].fill(0);
    inquiry[0] = 5;
    inquiry[4] = 31;
    inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
    inquiry[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
    inquiry[32..36].copy_from_slice(b"1.00");
    let mut f1 = vec![b' '; 48];
    f1[16..24].copy_from_slice(b"SAT FFFE");
    f1[24..32].copy_from_slice(b"GENERAL ");
    f1[32..40].copy_from_slice(b"GENERAL ");
    crate::platform::MockScsiDevice::new()
        .on(|c| c.first() == Some(&0x12), inquiry)
        .on(|c| c.first() == Some(&0x3c) && c.get(2) == Some(&0xf1), f1)
}

fn is_receiver_identity_read(cdb: &[u8]) -> bool {
    cdb.first() == Some(&0x3c) && cdb.get(2) == Some(&0xf1)
}

#[test]
fn current_file_offers_oem_recovery_without_granting_normal_flash_capabilities() {
    for vendor in ["PLEXTOR", "TEAC", "SONY", "ASUS", "ACME"] {
        let mut dev = oem_receiver(vendor);
        let unknown = profile_on(&mut dev).unwrap();
        assert!(unknown.backend.is_none() && unknown.recovery.is_none());
        assert!(!dev.reads.iter().any(|c| is_receiver_identity_read(c)));
        let current = crate::backends::pioneer::test_oem_recovery_package(vendor);
        let profile = profile_on_with_current(&mut dev, &current).unwrap();
        assert!(profile.backend.is_none());
        assert_eq!(profile.capabilities, Capabilities::NONE);
        assert_eq!(
            profile.recovery.map(|d| d.id),
            Some(crate::backends::pioneer::DESCRIPTOR.id),
            "{vendor}: {:?}",
            profile.recovery_errors
        );
        assert_eq!(
            dev.reads
                .iter()
                .filter(|c| is_receiver_identity_read(c))
                .count(),
            1
        );
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn unrelated_or_invalid_current_never_authorizes_oem_service_probing() {
    let current = crate::backends::pioneer::test_oem_recovery_package("TEAC");
    let mut wrong_vendor = oem_receiver("ASUS");
    let profile = profile_on_with_current(&mut wrong_vendor, &current).unwrap();
    assert!(profile.recovery.is_none());
    assert!(!wrong_vendor
        .reads
        .iter()
        .any(|c| is_receiver_identity_read(c)));
    assert!(wrong_vendor.writes.is_empty());

    let mut invalid = oem_receiver("TEAC");
    assert!(profile_on_with_current(&mut invalid, b"not a firmware file").is_err());
    assert!(invalid.reads.is_empty() && invalid.writes.is_empty());
}

#[test]
fn current_backend_routing_preserves_raw_mediatek_references() {
    let current =
        crate::backends::mtk::fixture::image(&crate::backends::mtk::fixture::BU3, "BD-RE BU40N", 1);
    assert_eq!(
        current_recovery_backend(&current).unwrap().descriptor().id,
        crate::backends::mtk::DESCRIPTOR.id
    );
}

#[test]
fn replaced_current_revokes_recovery_even_for_a_normally_recognized_drive() {
    for vendor in ["PIONEER", "ASUS"] {
        let mut dev = oem_receiver(vendor);
        let current = crate::backends::pioneer::test_oem_recovery_package(vendor);
        let accepted = profile_on_with_current(&mut dev, &current).unwrap();
        assert!(accepted.recovery.is_some());
        dev.reads.clear();
        let wrong = crate::backends::pioneer::test_oem_recovery_package("TEAC");
        let refused = profile_on_with_current(&mut dev, &wrong).unwrap();
        assert!(refused.backend.is_none() && refused.recovery.is_none());
        assert_eq!(refused.capabilities, Capabilities::NONE);
        assert!(
            dev.reads.iter().all(|c| c.first() == Some(&0x12)),
            "only standard identity may be read before Current is bound: {:?}",
            dev.reads
        );
        assert!(dev.writes.is_empty());
    }
}
