//! Automatic authoring diagnostics shared by CLI and GUI.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

pub use freemkv_flash::diagnostics::record;
pub use freemkv_flash::output::{capture_events, Event};

/// Run an authoring operation with an automatic log, reusing an outer operation.
pub fn run<T>(operation: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    freemkv_flash::user_error::read_only(freemkv_flash::diagnostics::run_named(
        "freemkv-fw",
        operation,
        work,
    ))
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

/// Best effort: mounts that reject chmod must not fail the write.
#[cfg(unix)]
fn preserve_mode(mode: u32, set: impl FnOnce(std::fs::Permissions) -> std::io::Result<()>) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = set(std::fs::Permissions::from_mode(mode)) {
        record(format!("output: could not preserve mode {mode:o}: {e}"));
    }
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
    #[cfg(unix)]
    let existing = std::fs::metadata(path).ok();
    #[cfg(unix)]
    let mut staged = {
        use std::os::unix::fs::PermissionsExt;
        // New files: open(2) with 0666 so the umask applies, no chmod.
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o666))
            .tempfile_in(parent)
            .context("creating staged output")?
    };
    #[cfg(not(unix))]
    let mut staged = tempfile::NamedTempFile::new_in(parent).context("creating staged output")?;
    #[cfg(unix)]
    if let Some(meta) = existing {
        use std::os::unix::fs::PermissionsExt;
        preserve_mode(meta.permissions().mode() & 0o7777, |p| {
            staged.as_file().set_permissions(p)
        });
    }
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
#[path = "diagnostics_tests.rs"]
mod tests;
