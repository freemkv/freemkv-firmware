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
