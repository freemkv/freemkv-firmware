use super::*;

#[test]
fn unverified_cli_result_uses_typed_consequence_instead_of_generic_retry() {
    let outcome = freemkv_flash::workflow::UpdateOutcome::Completed(
        freemkv_flash::workflow::UpdateEvidence {
            target_started: false,
            target_identity: String::new(),
            verified_regions: Vec::new(),
            unverified_regions: Vec::new(),
            completed_stages: vec!["first stage".into()],
            temporary_firmware: true,
        },
    );
    let error = report_update("Flash", outcome).unwrap_err();
    assert!(error.is::<freemkv_flash::backend::UnverifiedUpdateOutcome>());
    let guidance = freemkv_flash::workflow::error_message(&error);
    assert!(guidance.contains("Temporary firmware may remain"));
    assert!(!guidance.contains("then try again"));
    assert!(format!("{error:#}").contains("first stage"));
}
#[test]
fn flash_current_is_optional_and_paired_member_requires_an_explicit_file() {
    let base = ["freemkv-flash", "flash", "-i", "modified.bin"];
    for suffix in [vec![], vec!["--read-from-drive"]] {
        let Some(Command::Flash(args)) = Cli::try_parse_from(base.into_iter().chain(suffix))
            .unwrap()
            .command
        else {
            panic!("flash command")
        };
        let options: freemkv_flash::workflow::FlashOptions = args.into();
        assert!(options.current.is_none());
        assert!(!options.execute);
    }
    let Some(Command::Flash(args)) = Cli::try_parse_from(base.into_iter().chain([
        "--current",
        "oem.tar",
        "--current-member",
        "firmware.bin",
    ]))
    .unwrap()
    .command
    else {
        panic!("flash command")
    };
    let options: freemkv_flash::workflow::FlashOptions = args.into();
    assert_eq!(options.current.unwrap(), PathBuf::from("oem.tar"));
    assert_eq!(options.current_member.as_deref(), Some("firmware.bin"));
    assert!(
        Cli::try_parse_from(base.into_iter().chain(["--current-member", "firmware.bin"])).is_err()
    );
    assert!(Cli::try_parse_from(base.into_iter().chain([
        "--current",
        "oem.bin",
        "--read-from-drive"
    ]))
    .is_err());
}
#[test]
fn obsolete_flash_switches_are_rejected() {
    for flag in [
        "--force",
        "--mode",
        "--enc",
        "--no-enc",
        "--allow-crossflash",
        "--recover",
        "--skip-backup",
        "--verbose",
    ] {
        assert!(
            Cli::try_parse_from(["freemkv-flash", "flash", "-i", "fw.bin", flag]).is_err(),
            "obsolete flag accepted: {flag}"
        );
    }
    assert!(
        Cli::try_parse_from(["freemkv-flash", "flash", "-i", "fw.bin", "--mode", "main"]).is_err()
    );
    assert!(Cli::try_parse_from(["freemkv-flash", "dump", "--force"]).is_err());
}
#[test]
fn check_file_needs_no_drive_and_flash_keeps_safety_gates() {
    assert!(Cli::try_parse_from(["freemkv-flash", "check", "fw.bin"]).is_ok());
    match Cli::try_parse_from(["freemkv-flash", "flash", "-i", "fw.bin"])
        .unwrap()
        .command
    {
        Some(Command::Flash(a)) => {
            let options: freemkv_flash::workflow::FlashOptions = a.into();
            assert!(!options.execute);
            assert!(!options.acknowledged_risk);
        }
        _ => panic!("expected flash"),
    }
}

#[test]
fn recovery_allows_no_current_but_rejects_conflicting_sources() {
    let base = ["freemkv-flash", "recover", "-i", "target.tar"];
    assert!(Cli::try_parse_from(base).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--current", "current.tar"])).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--read-from-drive"])).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain([
        "--current",
        "current.tar",
        "--read-from-drive"
    ]))
    .is_err());
}

#[test]
fn family_override_is_only_a_recovery_cli_option() {
    assert!(Cli::try_parse_from([
        "freemkv-flash",
        "recover",
        "-i",
        "target.tar",
        "--bypass-family-check"
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "freemkv-flash",
        "flash",
        "-i",
        "target.tar",
        "--bypass-family-check"
    ])
    .is_err());
}
