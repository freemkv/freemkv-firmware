//! Durable full-bank evidence, acknowledged only after published readback.
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use pioneer_optical::startup::bank::backup::{BackupReceipt, BankBackup};

pub(super) fn persist_bridge(pair: &pioneer_optical::envelope::Update) -> Result<()> {
    use sha2::{Digest, Sha256};
    let bytes = super::backup::assemble_tar(&[
        pair.kernel_transfer().to_vec(),
        pair.normal_transfer().to_vec(),
    ])?;
    let directory = backup_directory()?;
    std::fs::create_dir_all(&directory).context("creating persistent drive backup directory")?;
    let path = directory.join(format!(
        "pioneer-bridge-{:x}-{}.tar",
        Sha256::digest(&bytes),
        crate::diagnostics::new_operation_id()
    ));
    persist_bridge_at(&path, &bytes, pair)?;
    crate::firmware_capture::retain("intermediate", &path, None, &bytes);
    crate::diagnostics::record(format!(
        "Pioneer temporary firmware retained: path={path:?} sha256={:x}",
        Sha256::digest(&bytes)
    ));
    crate::output::field("Temporary firmware backup", path.display().to_string());
    Ok(())
}

pub(super) fn persist_bridge_at(
    path: &Path,
    bytes: &[u8],
    expected: &pioneer_optical::envelope::Update,
) -> Result<()> {
    crate::engine::backup::save_validated(path, bytes, |saved| {
        let (kernel, normal) = super::classify_flash_input(saved)?;
        let pair = pioneer_optical::envelope::Update::load(
            &kernel.context("temporary firmware archive has no Kernel")?,
            &normal.context("temporary firmware archive has no Normal")?,
        )?;
        ensure!(
            pair.kernel_transfer() == expected.kernel_transfer()
                && pair.normal_transfer() == expected.normal_transfer(),
            "temporary firmware archive differs from the prepared bridge"
        );
        Ok(())
    })?;
    sync_ancestors(path)?;
    ensure!(
        std::fs::read(path)? == bytes,
        "temporary firmware final readback differs"
    );
    Ok(())
}

pub(super) fn persist(backup: &BankBackup) -> Result<BackupReceipt> {
    let directory = backup_directory()?;
    std::fs::create_dir_all(&directory).context("creating persistent drive backup directory")?;
    let digest: String = backup.digest().iter().map(|b| format!("{b:02x}")).collect();
    let path = directory.join(format!(
        "pioneer-banks-{digest}-{}.bin",
        crate::diagnostics::new_operation_id()
    ));
    let receipt = persist_at(&path, backup)?;
    crate::diagnostics::record(format!(
        "Pioneer persistent-bank backup: path={path:?} sha256={digest} bytes={}",
        backup.bytes().len()
    ));
    crate::output::field("Drive data backup", path.display().to_string());
    Ok(receipt)
}

pub(super) fn persist_at(path: &Path, backup: &BankBackup) -> Result<BackupReceipt> {
    crate::engine::backup::save_validated(path, backup.bytes(), |readback| {
        ensure!(
            backup.confirm_persisted(readback).is_some(),
            "persistent-bank backup differs from the captured drive data"
        );
        Ok(())
    })?;
    sync_ancestors(path)?;
    let saved = std::fs::read(path).context("reading the durable persistent-bank backup")?;
    backup
        .confirm_persisted(&saved)
        .context("published persistent-bank backup failed final verification")
}

fn sync_ancestors(_path: &Path) -> Result<()> {
    // New directory entries above the publisher's immediate parent must also
    // be durable before the dependency receives an acknowledgement.
    #[cfg(unix)]
    for directory in _path.parent().into_iter().flat_map(Path::ancestors) {
        if !directory.as_os_str().is_empty() {
            std::fs::File::open(directory)
                .with_context(|| format!("opening backup directory {}", directory.display()))?
                .sync_all()
                .with_context(|| format!("syncing backup directory {}", directory.display()))?;
        }
    }
    Ok(())
}

fn backup_directory() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(concat!(".", "local/share")))
        });
    let root =
        root.context("persistent user data location is unavailable; no bank data was changed")?;
    ensure!(root.is_absolute(), "drive backup location must be absolute");
    Ok(root.join("freemkv/drive-backups"))
}
