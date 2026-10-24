//! Every executable uses the shared localized guidance, including offline tools.
use freemkv_flash::localization::{get, Preferences};
use std::process::Command;

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
