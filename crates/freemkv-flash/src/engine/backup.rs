//! Family-neutral backup publishing: validate, write, read back, and publish a
//! backup without ever replacing an existing file. Each backend owns its own
//! format (`drive::mtk::backup`, `drive::pioneer::backup`).

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::drive::DriveFamily;

pub(super) fn save_backup(
    path: &Path,
    bytes: &[u8],
    drive: &dyn DriveFamily,
    target_model: &str,
) -> Result<usize> {
    save_validated(path, bytes, |candidate| {
        drive
            .validate_backup(candidate, target_model)
            .map(|_| ())
            .context("validating rollback archive")
    })
}

/// Publish validated bytes without ever replacing an existing destination.
/// The validator determines whether the artifact is a proven rollback or a
/// clearly labeled research candidate; this function claims neither.
pub(super) fn save_validated(
    path: &Path,
    bytes: &[u8],
    validate: impl Fn(&[u8]) -> Result<()>,
) -> Result<usize> {
    save_validated_with_replace(path, bytes, false, validate)
}

pub(super) fn save_validated_with_replace(
    path: &Path,
    bytes: &[u8],
    replace: bool,
    validate: impl Fn(&[u8]) -> Result<()>,
) -> Result<usize> {
    validate(bytes)?;
    if !replace && path.symlink_metadata().is_ok() {
        bail!(
            "backup {} already exists (existing backups are never overwritten)",
            path.display()
        );
    }
    static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut temp_name = path
        .file_name()
        .context("backup path has no filename")?
        .to_os_string();
    temp_name.push(format!(
        ".partial-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let temp = path.with_file_name(temp_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .with_context(|| format!("creating temporary backup {}", temp.display()))?;
    let result = (|| -> Result<usize> {
        crate::diagnostics::record(format!(
            "artifact: writing {} bytes to temporary file {:?}",
            bytes.len(),
            temp
        ));
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let saved = std::fs::read(&temp)?;
        if saved != bytes {
            bail!(
                "saved artifact {} differs from the captured bytes",
                temp.display()
            );
        }
        validate(&saved).context("saved artifact failed read-back validation")?;
        if replace {
            std::fs::rename(&temp, path).context("replacing the confirmed destination")?;
        } else {
            publish_no_clobber(&temp, path, |a, b| std::fs::hard_link(a, b))?;
        }
        let published = std::fs::read(path).context("reading back the published artifact")?;
        if published != bytes {
            bail!(
                "published artifact {} differs from the captured bytes; do not use this file",
                path.display()
            );
        }
        crate::diagnostics::record(format!(
            "artifact: published and read-back verified {} bytes at {:?}",
            published.len(),
            path
        ));
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::File::open(parent)
                .with_context(|| format!("opening backup directory {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("syncing backup directory {}", parent.display()))?;
        }
        Ok(saved.len())
    })();
    let _ = std::fs::remove_file(&temp);
    result
}

/// Hard links publish atomically; filesystems without them use exclusive creation.
fn publish_no_clobber(
    temp: &Path,
    path: &Path,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    if link(temp, path).is_ok() {
        return Ok(());
    }
    let mut destination = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "creating backup {} (existing backups are never overwritten)",
                path.display()
            )
        })?;
    let result = (|| -> Result<()> {
        let mut source = std::fs::File::open(temp)?;
        std::io::copy(&mut source, &mut destination)?;
        destination.sync_all()?;
        Ok(())
    })();
    drop(destination);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
