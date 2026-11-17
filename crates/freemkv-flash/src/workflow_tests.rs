use super::*;

#[test]
fn check_file_rejects_unrecognized_input_with_localized_file_guidance() {
    let dir = std::env::temp_dir().join(format!("freemkv-check-{}", new_operation_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("modified_firmware.tar");
    std::fs::write(&path, b"not a supported firmware archive").unwrap();
    let error = check_file(&path).expect_err("unrecognized input is not a successful check");
    let issue = user_error(&error);
    assert_eq!(issue.id, "errors.firmware_invalid");
    assert_eq!(issue.consequence, Some("errors.no_firmware_write"));
    for language in crate::localization::Language::ALL {
        assert!(!issue.render(language).contains("errors.firmware_invalid"));
    }
    // Informational inspection retains its ability to describe unknown bytes.
    engine::info_file(&path).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

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

#[test]
fn failed_package_write_leaves_no_partial_output() {
    let dir = std::env::temp_dir().join(format!("freemkv-package-fail-{}", new_operation_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("result.tar");
    let error = write_new_file(&output, |_| Err(std::io::Error::other("disk full")));
    assert!(error.is_err());
    assert!(!output.exists());
    let existing = dir.join("existing.tar");
    std::fs::write(&existing, b"keep").unwrap();
    assert!(write_new_file(&existing, |_| Ok(())).is_err());
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
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
    assert!(message.contains("The installed and selected firmware are for different hardware."));
    assert!(message.contains("Installed: BDE-PR1EP PP100."));
    assert!(message.contains("Selected: BDX-PR1MLA."));
    assert!(message.contains("No firmware was written."));
    assert!(!message.contains("cf3183a51bc41e42"));
    assert!(!message.contains("31ce81c2dbb0fdb"));
    for language in crate::localization::Language::ALL {
        let translated = crate::user_error::UserError::of(&error).render(language);
        assert!(
            translated.contains("BDE-PR1EP PP100"),
            "{language:?}: {translated}"
        );
        assert!(
            translated.contains("BDX-PR1MLA"),
            "{language:?}: {translated}"
        );
        assert!(
            !translated.contains("{installed}") && !translated.contains("{selected}"),
            "{language:?}: {translated}"
        );
    }
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
    f1[16..24].copy_from_slice(b"SAT 8600");
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

#[test]
fn backup_failure_guidance_does_not_request_dumps_for_prerequisites_or_connection_errors() {
    use crate::localization::{self, Language};
    use crate::user_error::{IssueCode, NoFirmwareWrite};
    for cause in [IssueCode::UnsupportedDrive, IssueCode::Connection] {
        let error = backup_error(anyhow::Error::new(cause), false).context(NoFirmwareWrite);
        let issue = user_error(&error);
        assert_eq!(issue.id, cause.message_id());
        assert_eq!(issue.consequence, Some("errors.no_firmware_write"));
        for language in Language::ALL {
            let text = issue.render(language);
            assert!(text.contains(localization::get(language, cause.message_id())));
            assert!(!text.contains(localization::get(language, "action.submit_dump")));
            assert!(text.contains(localization::get(language, "errors.no_firmware_write")));
            assert!(!text.contains("{cause}") && !text.contains("{submit_dump}"));
        }
    }
    let error = backup_error(
        std::io::Error::from(std::io::ErrorKind::PermissionDenied).into(),
        false,
    )
    .context(NoFirmwareWrite);
    assert!(user_error(&error)
        .render(Language::En)
        .contains(localization::get(Language::En, "errors.permission_denied")));
}

#[test]
fn failed_dump_does_not_request_another_dump() {
    use crate::user_error::{IssueCode, NoFirmwareWrite};
    let error =
        backup_error(anyhow::Error::new(IssueCode::Connection), true).context(NoFirmwareWrite);
    let issue = user_error(&error);
    assert_eq!(issue.id, "errors.connection");
    assert_eq!(issue.consequence, Some("errors.no_firmware_write"));
}

#[test]
fn confirmation_cleanup_preserves_nested_warnings_unknown_rows_and_terminal_text() {
    use crate::backend::{FlashPlan, PlanLine};
    let lines = vec![
        PlanLine::Detail(Box::new(PlanLine::Spaced(Box::new(PlanLine::Warning(
            "nested compatibility warning".into(),
        ))))),
        PlanLine::Spaced(Box::new(PlanLine::Detail(Box::new(PlanLine::Warning(
            "nested rollback warning".into(),
        ))))),
        PlanLine::Field("new requirement", "unknown rows remain visible".into()),
        PlanLine::Detail(Box::new(PlanLine::Field(
            "receiver",
            "signature at 0x1234".into(),
        ))),
        PlanLine::Backup,
    ];
    let mut plan = FlashPlan::new(());
    plan.after_backup = lines.clone();
    plan.notes.push(PlanLine::Text(
        "required stage must start before continuing".into(),
    ));
    let mut authorized = AuthorizedPlan::new(plan, ());
    // A legacy human string is not evidence that an artifact was saved.
    authorized.set_backup("saved /invented/path (3 bytes)");
    let sheet = FlashSheet::of(&authorized);
    assert!(sheet.saved_backup.is_none());
    assert!(!sheet.backup_waived);
    assert_eq!(
        sheet.warnings,
        ["nested compatibility warning", "nested rollback warning"]
    );
    assert_eq!(
        sheet.notices,
        [
            "required stage must start before continuing",
            "new requirement: unknown rows remain visible"
        ]
    );
    assert_eq!(sheet.technical_details, ["receiver: signature at 0x1234"]);
    assert!(sheet
        .plan
        .iter()
        .any(|s| s == "backup: saved /invented/path (3 bytes)"));
    for line in lines {
        assert_eq!(
            engine::render_plan_line(&line, "backup"),
            engine::render_plan_line(&PlanLine::Detail(Box::new(line)), "backup")
        );
    }
    authorized.set_backup_evidence(None);
    let waived = FlashSheet::of(&authorized);
    assert!(waived.saved_backup.is_none() && waived.backup_waived);
}

#[cfg(unix)]
#[test]
fn selected_file_metadata_rejects_fifo_and_accepts_a_regular_file() {
    use std::ffi::CString;
    let dir = std::env::temp_dir().join(format!("freemkv-selected-file-{}", new_operation_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("not-a-file.bin");
    let name = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    let requested = fifo.clone();
    let worker = std::thread::spawn(move || {
        tx.send(selected_file_info(&requested)).unwrap();
    });
    assert!(rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("a FIFO must not block the selected-file worker")
        .is_err());
    worker.join().unwrap();
    let regular = dir.join("regular.bin");
    std::fs::write(&regular, b"unrecognized firmware").unwrap();
    let result = selected_file_info(&regular).unwrap();
    assert_eq!(result.origin, FileOrigin::Unknown);
    assert!(result.members.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn firmware_input_collector_keeps_the_bytes_used_before_failed_validation() {
    let dir = std::env::temp_dir().join(format!("freemkv-inputs-{}", new_operation_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("target.bin");
    std::fs::write(&path, b"original consumed bytes").unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let result = capture_firmware_inputs(
        {
            let seen = seen.clone();
            move |input| seen.lock().unwrap().push(input)
        },
        || {
            let bytes = read_firmware_input("target", &path, Some("normal")).unwrap();
            std::fs::write(&path, b"later replacement").unwrap();
            assert_eq!(bytes, b"original consumed bytes");
            Err::<(), _>(anyhow::anyhow!("later validation failure"))
        },
    );
    assert!(result.is_err());
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].bytes.as_ref(), b"original consumed bytes");
    assert_eq!(seen[0].role, "target");
    assert_eq!(seen[0].member.as_deref(), Some("normal"));
    std::fs::remove_dir_all(dir).unwrap();
}

const BU40N: &[u8] = include_bytes!("../tests/fixtures/HL-DT-ST_BU40N_N1.02_2017-12-08.bin");

fn workflow_scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("freemkv-{tag}-{}", new_operation_id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn file_origin_ids_labels_and_explanations_are_distinct() {
    let all = [
        FileOrigin::OemLikely,
        FileOrigin::UserBackupLikely,
        FileOrigin::Unknown,
    ];
    let labels: Vec<_> = all.iter().map(|origin| origin.label()).collect();
    assert_eq!(labels, ["OEM likely", "User provided", "Origin unknown"]);
    let mut ids: Vec<_> = all.iter().map(|origin| origin.label_id()).collect();
    ids.extend(all.iter().map(|origin| origin.explanation_id()));
    let mut text: Vec<_> = all.iter().map(|origin| origin.explanation()).collect();
    for id in &ids {
        assert!(id.starts_with("domain."), "{id}");
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 6);
    text.sort();
    text.dedup();
    assert_eq!(text.len(), 3);
}

#[test]
fn drive_choice_shows_the_id_only_when_it_differs_from_the_name() {
    let same = drive("/dev/sg3", "/dev/sg3");
    assert_eq!(same.display(), "/dev/sg3  HL-DT-ST BD-RE BU40N (rev 1.04)");
    assert_eq!(same.list_line(), same.display());
    let named = drive("/dev/sg3", "/dev/sr1");
    assert_eq!(named.display(), "/dev/sr1  HL-DT-ST BD-RE BU40N (rev 1.04)");
    assert_eq!(
        named.list_line(),
        "/dev/sr1  HL-DT-ST BD-RE BU40N (rev 1.04)  /dev/sg3"
    );
}

#[test]
fn discovery_and_listing_work_without_a_drive() {
    let _ = drives();
    let _ = discover();
    list().unwrap();
    assert_eq!(resolve_device(Some("selector-x")).unwrap(), "selector-x");
}

#[test]
fn picker_formats_never_export_an_empty_or_unsafe_list() {
    let preferred = FirmwarePickerFormats::prefer(vec!["bin", "tar.gz"]);
    assert_eq!(preferred.extensions(), Some(["bin", "tar.gz"].as_slice()));
    let mut expected = update_file_extensions();
    expected.retain(|extension| FirmwarePickerFormats::valid_suffix(extension));
    let fallback = FirmwarePickerFormats::prefer(vec!["bad/ext", "", "a..b", "x*"]);
    assert_eq!(
        fallback.extensions().map(<[_]>::to_vec),
        (!expected.is_empty()).then_some(expected)
    );
    assert_eq!(
        FirmwarePickerFormats::default(),
        FirmwarePickerFormats::prefer(Vec::new())
    );
    for good in ["bin", "tar.gz", "a_b-c", "7z"] {
        assert!(FirmwarePickerFormats::valid_suffix(good), "{good}");
    }
    for bad in ["", ".bin", "bin.", "a..b", "a/b", "a*", "a\0", "a b"] {
        assert!(!FirmwarePickerFormats::valid_suffix(bad), "{bad:?}");
    }
}

#[test]
fn extension_lists_are_deduplicated_in_first_seen_order() {
    let formats: Vec<_> = registry::backends()
        .flat_map(|backend| backend.descriptor().formats)
        .collect();
    let once = extensions(formats.iter().copied());
    let twice = extensions(formats.iter().copied().chain(formats.iter().copied()));
    assert_eq!(once, twice);
    let mut unique = once.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), once.len());
    assert_eq!(file_extensions(), once);
    for extension in update_file_extensions() {
        assert!(once.contains(&extension));
    }
}

#[test]
fn default_names_carry_model_revision_and_kind() {
    let id = crate::backend::Identity {
        vendor: "HL-DT-ST".into(),
        product: "BD-RE BU40N".into(),
        revision: "1.02".into(),
        banner: None,
    };
    let format = || crate::backend::BackupFormat {
        extension: "tar",
        infix: "backup",
    };
    assert_eq!(
        default_backup_name(&id, Some(format()), false).unwrap(),
        PathBuf::from("BD-RE_BU40N_1.02.backup.tar")
    );
    for given in [Some(format()), None] {
        assert_eq!(
            default_backup_name(&id, given, true).unwrap(),
            PathBuf::from("BD-RE_BU40N_1.02.dump.bin")
        );
    }
    assert!(default_backup_name(&id, None, false).is_err());
    assert_eq!(
        default_backup_path(Path::new("/tmp/nonexistent-dir/fw.bin"), "tar"),
        Some(PathBuf::from(
            "/tmp/nonexistent-dir/fw.bin.preflash.backup.tar"
        ))
    );
    assert_eq!(default_backup_path(Path::new("/"), "tar"), None);
}

#[test]
fn bounded_reads_and_selected_file_checks_report_their_failures() {
    let dir = workflow_scratch("bounded-reads");
    let path = dir.join("fw.bin");
    std::fs::write(&path, b"bytes").unwrap();
    assert_eq!(read_capped(&path).unwrap(), b"bytes");
    assert!(read_capped(&dir.join("missing.bin")).is_err());
    assert!(selected_file_info(&dir).is_err());
    assert!(selected_file_info(&dir.join("missing.bin")).is_err());
    assert_eq!(selected_file_origin(&path).unwrap(), FileOrigin::Unknown);
    assert!(recovery_members(&path).unwrap().is_empty());
    assert!(recovery_members(&dir.join("missing.bin")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn flash_refuses_before_any_drive_access() {
    let dir = workflow_scratch("flash-refusals");
    let missing = dir.join("missing.bin");
    let garbage = dir.join("garbage.bin");
    std::fs::write(&garbage, b"not firmware").unwrap();
    let error = flash(
        FlashOptions {
            execute: true,
            input: missing.clone(),
            ..Default::default()
        },
        &mut Preconfirmed,
    )
    .unwrap_err();
    assert!(error.downcast_ref::<UpdateFailure>().is_some());
    assert!(format!("{error:#}").contains("without acknowledging the risk"));
    for input in [missing, garbage] {
        let options = FlashOptions {
            input,
            device: Some("nonexistent-device-must-never-be-opened".into()),
            ..Default::default()
        };
        let error = flash(options.clone(), &mut Preconfirmed).unwrap_err();
        assert!(error.downcast_ref::<UpdateFailure>().is_some());
        assert!(preview_flash(&options).is_err());
        assert!(plan_flash(&options).is_err());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn flash_input_checks_run_in_order_before_opening_the_device() {
    use crate::backends::mtk::fixture;
    let dir = workflow_scratch("flash-order");
    let image = fixture::image(&fixture::BU3, "BU40N", 1);
    let input = dir.join("target.bin");
    std::fs::write(&input, &image).unwrap();
    let error = match open_flash(&FlashOptions {
        input: input.clone(),
        current_member: Some("firmware.bin".into()),
        ..Default::default()
    }) {
        Err(error) => error,
        Ok(_) => panic!("a Current member without Current was accepted"),
    };
    assert!(format!("{error:#}").contains("--current-member requires --current"));
    let error = match open_flash(&FlashOptions {
        current: Some(input.clone()),
        input,
        device: Some("nonexistent-device-must-never-be-opened".into()),
        ..Default::default()
    }) {
        Err(error) => error,
        Ok(_) => panic!("an unopenable device was accepted"),
    };
    assert!(!error.is::<HardwareMismatch>(), "{error:#}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn supplied_family_check_accepts_matching_and_unrecognized_files_only() {
    let package = crate::backends::pioneer::test_oem_recovery_package("TEAC");
    check_supplied_family(b"unrecognized", BU40N).unwrap();
    check_supplied_family(BU40N, b"unrecognized").unwrap();
    check_supplied_family(BU40N, BU40N).unwrap();
    assert!(check_supplied_family(BU40N, &package).is_err());
    assert!(check_supplied_family(&package, BU40N).is_err());
}

#[test]
fn current_references_reject_member_misuse_and_malformed_packages() {
    let error = current_firmware_image(b"raw image bytes", Some("firmware.bin")).unwrap_err();
    assert!(format!("{error:#}").contains("--current-member requires a Current TAR"));
    let mut tar = vec![0u8; 512];
    tar[257..262].copy_from_slice(b"ustar");
    assert!(current_firmware_image(&tar, Some("firmware.bin")).is_err());
    assert!(is_hardware_mismatch(&anyhow::Error::new(
        HardwareMismatch {
            installed_model: "a".into(),
            target_model: "b".into(),
            source: anyhow::anyhow!("family"),
        }
    )));
    assert!(!is_hardware_mismatch(&anyhow::anyhow!("other")));
}

#[test]
fn recovery_refuses_without_acknowledgement_or_input_and_never_reuses_a_session() {
    let options = |execute, acknowledged_risk| RecoveryOptions {
        device: Some("nonexistent-device-must-never-be-opened".into()),
        input: PathBuf::from("/nonexistent/recovery-input.bin"),
        member: None,
        current: CurrentFirmware::NotRequired,
        current_member: None,
        execute,
        acknowledged_risk,
        bypass_family_check: false,
    };
    for (execute, acknowledged) in [(true, false), (false, false), (true, true)] {
        assert!(recover(options(execute, acknowledged)).is_err());
        assert!(prepare_recovery(options(execute, acknowledged)).is_err());
    }
    let session = PreparedRecovery::default();
    assert_eq!(session, session.clone());
    assert_ne!(session, PreparedRecovery::default());
    assert!(format!("{session:?}").contains("PreparedRecovery"));
    for acknowledged in [false, true] {
        let error = execute_recovery(session.clone(), acknowledged).unwrap_err();
        assert!(error.downcast_ref::<UpdateFailure>().is_some());
    }
}

#[test]
fn drive_actions_on_an_unknown_selector_fail_without_writing() {
    let selector = "nonexistent-device-must-never-be-opened";
    assert!(info(Some(selector)).is_err());
    assert!(profile(selector).is_err());
    assert!(details(selector).is_err());
    assert!(backup(Some(selector), None, false).is_err());
    assert!(backup(Some(selector), None, true).is_err());
    assert!(profile_with_current(selector, Path::new("/nonexistent/current.bin"), None).is_err());
}

#[test]
fn unidentified_drives_are_profiled_but_not_offered_any_operation() {
    let mut dev = crate::platform::MockScsiDevice::new();
    assert!(classify_gated(&mut dev).is_err());
    let profile = profile_on(&mut dev).unwrap();
    assert_eq!(profile.capabilities, crate::backend::Capabilities::NONE);
    assert!(profile.flash_formats.is_empty());
    assert!(profile.backup_format.is_none());
    assert!(dev.writes.is_empty());
    let mut receiver = oem_receiver("ACME");
    let profile = profile_on(&mut receiver).unwrap();
    assert!(profile.firmware_picker_formats().extensions().is_some());
    let _ = profile.read_notice();
    let _ = recovery_requires_current(&profile);
    let _ = recovery_supports_family_override(&profile);
    assert!(receiver.writes.is_empty());
}

#[test]
fn inspection_entry_points_forward_sources_and_cancellation() {
    let dir = workflow_scratch("inspection");
    let path = dir.join("fw.bin");
    std::fs::write(&path, BU40N).unwrap();
    let source = Source::File(path.clone());
    let analysis = inspect(&source, &Control::default()).unwrap();
    let report = compare(
        &Source::Analyzed(analysis.clone()),
        &source,
        &Control::default(),
    );
    assert!(report.is_ok());
    let cancelled = Control::default();
    cancelled.cancel();
    assert!(inspect(&source, &cancelled).is_err());
    let live = |name: &str| Source::Drive {
        device: "nonexistent-device-must-never-be-opened".into(),
        capture: dir.join(name),
        as_backup: false,
    };
    assert!(compare(&live("a.bin"), &live("b.bin"), &Control::default()).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn packaging_a_recognized_image_creates_one_new_file() {
    let dir = workflow_scratch("package-ok");
    let input = dir.join("fw.bin");
    let output = dir.join("fw.tar");
    std::fs::write(&input, BU40N).unwrap();
    package_image(&input, &output).unwrap();
    assert!(std::fs::metadata(&output).unwrap().len() > 0);
    assert!(package_image(&input, &output).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn error_helpers_and_file_info_render_without_a_drive() {
    let error = anyhow::anyhow!("detail");
    assert!(!error_message(&error).is_empty());
    let dir = workflow_scratch("file-info");
    let path = dir.join("fw.bin");
    std::fs::write(&path, BU40N).unwrap();
    info(Some(path.to_str().unwrap())).unwrap();
    check_file(&path).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
