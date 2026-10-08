use super::*;
#[test]
fn obsolete_flash_switches_are_rejected() {
    for flag in [
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
fn check_file_needs_no_drive_and_force_is_the_only_override() {
    assert!(Cli::try_parse_from(["freemkv-flash", "check", "fw.bin"]).is_ok());
    match Cli::try_parse_from(["freemkv-flash", "flash", "-i", "fw.bin", "--force"])
        .unwrap()
        .command
    {
        Some(Command::Flash(a)) => assert!(a.force),
        _ => panic!("expected flash"),
    }
}

#[test]
fn recovery_requires_exactly_one_current_source() {
    let base = ["freemkv-flash", "recover", "-i", "target.tar"];
    assert!(Cli::try_parse_from(base).is_err());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--current", "current.tar"])).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--read-from-drive"])).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain([
        "--current",
        "current.tar",
        "--read-from-drive"
    ]))
    .is_err());
}
