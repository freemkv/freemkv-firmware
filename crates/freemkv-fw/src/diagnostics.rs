//! Automatic authoring diagnostics shared by CLI and GUI.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

pub use freemkv_flash::diagnostics::record;
pub use freemkv_flash::output::{capture_events, Event};

/// Run an authoring operation with an automatic log, reusing an outer operation.
pub fn run<T>(operation: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    freemkv_flash::diagnostics::run_named("freemkv-fw", operation, work)
}

/// Record the size and complete SHA-256 digest without logging firmware payloads.
pub fn image(label: &str, bytes: &[u8]) {
    record(format!(
        "{label}: bytes={} sha256={:x}",
        bytes.len(),
        Sha256::digest(bytes)
    ));
}

/// Read a bounded image and log its path, size and fingerprint.
pub fn read(path: &Path) -> Result<Vec<u8>> {
    freemkv_flash::workflow::read_capped(path)
        .with_context(|| format!("reading {}", path.display()))
}

/// Publish output atomically after syncing and comparing the staged bytes.
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    record(format!("output: staging path={path:?}"));
    image("output image", bytes);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent).context("creating staged output")?;
    staged.write_all(bytes).context("writing staged output")?;
    staged
        .as_file()
        .sync_all()
        .context("syncing staged output")?;
    anyhow::ensure!(
        std::fs::read(staged.path())? == bytes,
        "staged output differs from generated image"
    );
    record("output: staged bytes verified; publishing");
    staged
        .persist(path)
        .with_context(|| format!("publishing {}", path.display()))?;
    anyhow::ensure!(
        std::fs::read(path)? == bytes,
        "published output differs from generated image"
    );
    record(format!("output: published and byte-verified path={path:?}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn failed_authoring_operation_has_named_log_with_image_evidence() {
        let path = Arc::new(Mutex::new(None));
        let captured = path.clone();
        let result = capture_events(
            move |event| {
                if let Event::Field { label, value } = event {
                    if label == "Diagnostic log" {
                        *captured.lock().unwrap() = Some(std::path::PathBuf::from(value));
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
}
