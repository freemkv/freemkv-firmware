use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn failed_authoring_operation_has_named_log_with_image_evidence() {
    let path = Arc::new(Mutex::new(None));
    let captured = path.clone();
    let result = capture_events(
        move |event| {
            if let Event::Report(report) = event {
                for (label, value) in report.gui_fields() {
                    if label == "Diagnostic log" {
                        *captured.lock().unwrap() = Some(std::path::PathBuf::from(value));
                    }
                }
            }
        },
        || {
            run("verify", || {
                crate::api::verify(b"not a firmware image", None)
            })
        },
    );
    assert!(result.is_err());
    let path = path.lock().unwrap().clone().unwrap();
    assert!(path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("freemkv-fw-"));
    let text = std::fs::read_to_string(&path).unwrap();
    for expected in [
        "freemkv-fw=",
        "operation=\"verify\"",
        "input image: bytes=20 sha256=",
        "RESULT: error:",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert_eq!(text.matches("operation=\"verify\"").count(), 1);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn output_replacement_is_exact_and_failed_publication_preserves_destination() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("firmware.bin");
    std::fs::write(&path, b"old image with longer data").unwrap();
    write(&path, b"new image").unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"new image");
    let directory = dir.path().join("existing-directory");
    std::fs::create_dir(&directory).unwrap();
    assert!(write(&directory, b"firmware").is_err());
    assert!(directory.is_dir());
}

#[cfg(unix)]
#[test]
fn created_output_is_not_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("firmware.bin");
    write(&path, b"image").unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_ne!(mode & 0o044, 0, "mode {mode:o}");
}

#[cfg(unix)]
#[test]
fn overwritten_output_keeps_its_previous_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("firmware.bin");
    std::fs::write(&path, b"old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    write(&path, b"new").unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o664);
}
