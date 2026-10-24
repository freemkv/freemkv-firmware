use super::*;

#[test]
fn desktop_faults_localize_without_exposing_native_details_or_guessing_write_effects() {
    for read_only in [true, false] {
        let issue = application_failure("private native status 0x1234", read_only);
        assert_eq!(issue.id, "errors.unexpected");
        assert_eq!(
            issue.consequence,
            read_only.then_some("errors.no_firmware_write")
        );
        for language in crate::localization::Language::ALL {
            assert!(!issue.render(language).contains("0x1234"));
        }
    }
}

#[test]
fn packaging_errors_keep_file_causes_and_prove_no_firmware_write() {
    let dir = std::env::temp_dir().join(format!("freemkv-package-{}", new_operation_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("invalid.bin");
    let output = dir.join("result.tar");
    let missing = package_image(&input, &output).unwrap_err();
    let issue = user_error(&missing);
    assert_eq!(issue.id, "errors.file_missing");
    assert_eq!(issue.consequence, Some("errors.no_firmware_write"));
    std::fs::write(&input, b"not a firmware image").unwrap();
    let invalid = package_image(&input, &output).unwrap_err();
    let issue = user_error(&invalid);
    assert_eq!(issue.id, "errors.firmware_invalid");
    assert_eq!(issue.consequence, Some("errors.no_firmware_write"));
    assert!(!output.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

mod prepared_recovery {
    use super::*;
    use crate::backend::{Descriptor, Identity, PreparedRecoveryUpdate, WriteDevice};
    use crate::platform::MockScsiDevice;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct BindingBackend;
    static BACKEND: BindingBackend = BindingBackend;
    static DESCRIPTOR: Descriptor = Descriptor {
        id: BackendId("prepared-test"),
        display_name: "Test protocol",
        flash_summary: None,
        formats: &[],
    };
    impl Backend for BindingBackend {
        fn descriptor(&self) -> &'static Descriptor {
            &DESCRIPTOR
        }
        fn probe(&self, _: &mut ReadDevice<'_>, _: &Identity) -> Result<Option<Match>> {
            Ok(None)
        }
    }
    struct LoadedUpdate(Arc<AtomicUsize>);
    impl PreparedRecoveryUpdate for LoadedUpdate {
        fn execute(&self, _: &mut WriteDevice<'_>) -> Result<UpdateOutcome> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(UpdateOutcome::Planned)
        }
    }
    fn session(calls: Arc<AtomicUsize>) -> PreparedRecovery {
        PreparedRecovery(Arc::new(std::sync::Mutex::new(Some(RecoverySession {
            selector: "synthetic".into(),
            backend: &BACKEND,
            identity: Identity {
                vendor: "TEST".into(),
                product: "Original".into(),
                revision: "1.00".into(),
                banner: None,
            },
            update: Box::new(LoadedUpdate(calls)),
        }))))
    }
    fn device(product: &str) -> MockScsiDevice {
        device_identity("TEST", product, "1.00")
    }
    fn device_identity(vendor: &str, product: &str, revision: &str) -> MockScsiDevice {
        let mut inquiry = vec![b' '; 96];
        inquiry[..8].fill(0);
        inquiry[4] = 91;
        inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
        inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
        inquiry[32..32 + revision.len()].copy_from_slice(revision.as_bytes());
        MockScsiDevice::new().on(|c| c.first() == Some(&0x12), inquiry)
    }
    #[test]
    fn confirmation_consumes_loaded_state_with_only_one_identity_read() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prepared = session(calls.clone());
        let duplicate = prepared.clone();
        let mut dev = device("Original");
        execute_recovery_on(&mut dev, prepared.take().unwrap()).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            dev.reads.len(),
            1,
            "confirmation must not acquire firmware again"
        );
        assert!(dev.writes.is_empty());
        let error = match duplicate.take() {
            Err(error) => error,
            Ok(_) => panic!("plan reused"),
        };
        assert!(error.is::<crate::user_error::IssueCode>());
        assert!(error_message(&error).contains("No firmware was written"));
    }
    #[test]
    fn drive_replacement_cannot_execute_the_retained_envelope() {
        for (case, vendor, product, revision) in [
            ("vendor", "OTHER", "Original", "1.00"),
            ("product", "TEST", "Replacement", "1.00"),
            ("revision", "TEST", "Original", "2.00"),
            ("missing vendor", "", "Original", "1.00"),
            ("missing product", "TEST", "", "1.00"),
            ("banner", "TEST", "Original", "1.00"),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut bound = session(calls.clone()).take().unwrap();
            if case == "missing vendor" {
                bound.identity.vendor.clear();
            }
            if case == "missing product" {
                bound.identity.product.clear();
            }
            if case == "banner" {
                bound.identity.banner = Some("original boot label".into());
            }
            let mut dev = device_identity(vendor, product, revision);
            let error = execute_recovery_on(&mut dev, bound).unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), 0, "{case}");
            assert!(dev.writes.is_empty(), "{case}");
            assert_eq!(user_error(&error).id, "errors.drive_changed", "{case}");
            assert!(error_message(&error).contains("No firmware was written"));
        }
    }
}

#[test]
fn recovery_requires_tar_for_standalone_pioneer_components() {
    let package = crate::backends::pioneer::test_oem_recovery_package("PIONEER");
    assert_eq!(recovery_target(&package, None).unwrap(), package);
    let mut archive = tar::Archive::new(package.as_slice());
    for entry in archive.entries().unwrap() {
        use std::io::Read;
        let mut bytes = Vec::new();
        entry.unwrap().read_to_end(&mut bytes).unwrap();
        assert!(recovery_target(&bytes, None).is_err());
    }
}

#[test]
fn hardware_mismatch_guidance_keeps_models_but_not_family_hashes() {
    let source =
        anyhow::anyhow!("family mismatch: installed cf3183a51bc41e42, target 31ce81c2dbb0fdb");
    let error = UpdateFailure::before_write(
        "compatibility checks",
        crate::backend::HardwareMismatch {
            installed_model: "BDE-PR1EP PP100".into(),
            target_model: "BDX-PR1MLA".into(),
            source,
        }
        .into(),
    );
    let message = error_message(&error);
    assert!(message.contains("The underlying hardware for these firmwares is not compatible."));
    assert!(message.contains("Installed firmware: BDE-PR1EP PP100."));
    assert!(message.contains("Selected firmware: BDX-PR1MLA."));
    assert!(message.contains("No firmware was written."));
    assert!(!message.contains("cf3183a51bc41e42"));
    assert!(!message.contains("31ce81c2dbb0fdb"));
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("cf3183a51bc41e42"));
    assert!(diagnostic.contains("31ce81c2dbb0fdb"));
    let evidence = error.downcast_ref::<UpdateFailure>().unwrap();
    assert_eq!(evidence.phase, "compatibility checks");
    assert!(!evidence.write_started);
}

#[test]
fn family_override_requires_typed_hardware_mismatch_evidence() {
    let mismatch = UpdateFailure::before_write(
        "compatibility checks",
        crate::backend::HardwareMismatch {
            installed_model: "installed model".into(),
            target_model: "target model".into(),
            source: anyhow::anyhow!("family mismatch: installed hash, target hash"),
        }
        .into(),
    );
    assert!(crate::workflow::is_hardware_mismatch(&mismatch));

    for error in [
        anyhow::anyhow!("family mismatch: installed hash, target hash"),
        anyhow::anyhow!("firmware family is unknown"),
        anyhow::anyhow!("SCSI transport failed while reading firmware"),
    ] {
        assert!(!crate::workflow::is_hardware_mismatch(&error));
    }
}

#[test]
fn supplied_current_family_mismatch_precedes_even_device_resolution() {
    use crate::backends::mtk::fixture;
    let current = fixture::image(&fixture::BU3, "BU40N", 1);
    let target = fixture::image(&fixture::JB7, "BH16NS40", 1);
    let dir = std::env::temp_dir().join(format!("freemkv-early-family-{}", new_operation_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let current_path = dir.join("current.bin");
    let target_path = dir.join("target.bin");
    std::fs::write(&current_path, current).unwrap();
    std::fs::write(&target_path, target).unwrap();
    let error = match open_flash(&FlashOptions {
        current: Some(current_path),
        input: target_path,
        device: Some("nonexistent-device-must-never-be-opened".into()),
        ..Default::default()
    }) {
        Err(error) => error,
        Ok(_) => panic!("incompatible Current was accepted"),
    };
    assert!(error.is::<HardwareMismatch>(), "{error:#}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn precheck_evidence_never_overwrites_an_execution_failure() {
    let evidence = UpdateFailure {
        phase: "target upload".into(),
        write_started: true,
        progress: crate::backend::UpdateProgress::PayloadAttempted,
        payload_bytes_accepted: Some(0),
        temporary_firmware: true,
        completed_stages: vec!["intermediate".into()],
    };
    let error = anyhow::anyhow!("write rejected").context(evidence.clone());
    let error = UpdateFailure::before_write("precheck", error);
    assert_eq!(error.downcast_ref::<UpdateFailure>(), Some(&evidence));
    assert!(error_message(&error).contains("Keep the drive"));
    assert!(format!("{error:#}").contains("write rejected"));
}

#[test]
fn current_detection_error_keeps_transport_diagnostics_out_of_user_guidance() {
    let error = anyhow::Error::new(crate::backend::CurrentFirmwareRequired {
        source: anyhow::anyhow!("SCSI invalid field in CDB at 0x98000 [E4000]"),
    });
    assert!(
        error_message(&error).contains("Select a file matching the firmware currently installed")
    );
    assert!(!error_message(&error).contains("E4000"));
    assert!(format!("{error:#}").contains("SCSI invalid field in CDB at 0x98000 [E4000]"));
    let other = anyhow::anyhow!("original cause").context("operation failed");
    assert!(error_message(&other).contains("Save a diagnostic report"));
    assert!(format!("{other:#}").contains("original cause"));
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
    assert!(format!("{error:#}").contains("exceeds"));
    assert_eq!(user_error(&error).id, "errors.firmware_invalid");
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
    let error = resolve_from(None, &drives).unwrap_err();
    assert_eq!(user_error(&error).id, "errors.choose_drive");
    let error = format!("{error:#}");
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
fn validated_oem_protocol_offers_same_capabilities_independent_of_brand() {
    for vendor in ["PLEXTOR", "TEAC", "SONY", "ASUS", "ACME"] {
        let mut dev = oem_receiver(vendor);
        let unknown = profile_on(&mut dev).unwrap();
        assert!(unknown.backend.is_some() && unknown.recovery.is_some());
        assert!(dev.reads.iter().any(|c| is_receiver_identity_read(c)));
        let current = crate::backends::pioneer::test_oem_recovery_package(vendor);
        let profile = profile_on_with_current(&mut dev, &current).unwrap();
        assert!(profile.backend.is_some());
        assert!(profile.capabilities.flash && profile.capabilities.backup);
        assert_eq!(
            profile.recovery.map(|d| d.id),
            Some(crate::backends::pioneer::DESCRIPTOR.id),
            "{vendor}: {:?}",
            profile.recovery_errors
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
    assert!(wrong_vendor
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
            dev.reads
                .iter()
                .all(|c| matches!(c.first(), Some(0x12 | 0x3c))),
            "only identification reads before Current is bound: {:?}",
            dev.reads
        );
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn firmware_read_capability_comes_from_normal_or_recovery_backend_without_io() {
    let mut profile = DriveProfile {
        identity: crate::backend::Identity {
            vendor: "UNRELATED".into(),
            product: "A model name must not decide policy".into(),
            revision: "1.00".into(),
            banner: None,
        },
        backend: None,
        recovery: None,
        capabilities: Capabilities::NONE,
        backup_format: None,
        flash_formats: &[],
        recovery_errors: Vec::new(),
    };
    assert_eq!(profile.can_read(), None);
    profile.recovery = Some(&crate::backends::mtk::DESCRIPTOR);
    assert_eq!(profile.can_read(), Some(false));
    profile.recovery = Some(&crate::backends::pioneer::DESCRIPTOR);
    assert_eq!(profile.can_read(), Some(true));
}
