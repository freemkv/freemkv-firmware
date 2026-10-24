//! Every executable uses the shared localized guidance, including offline tools.
use freemkv_flash::localization::{get, Preferences};
use std::process::Command;

#[test]
fn offline_crossflash_help_exits_successfully_and_shows_the_supported_commands() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_freemkv-crossflash"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("freemkv-crossflash <package directory>"));
        assert!(stdout.contains("--why [--json] <installed> <target>"));
        assert!(!String::from_utf8_lossy(&output.stderr)
            .contains(get(Preferences::user().load(), "errors.command_options")));
    }
}

#[test]
fn offline_crossflash_usage_errors_are_localized_and_cannot_imply_a_drive_write() {
    let output = Command::new(env!("CARGO_BIN_EXE_freemkv-crossflash"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let language = Preferences::user().load();
    for key in ["errors.command_options", "errors.no_firmware_write"] {
        assert!(stderr.contains(get(language, key)), "{stderr}");
    }
    assert!(!stderr.contains("usage: freemkv-crossflash"), "{stderr}");
}
