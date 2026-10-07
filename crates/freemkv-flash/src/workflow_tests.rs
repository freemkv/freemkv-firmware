use super::*;

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
