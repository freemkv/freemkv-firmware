//! MTK firmware backups: an OEM-format 2 MiB image rebuilt from the drive, plus
//! decoding of the 0.10.x rollback archives they replace.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ensure_image_matches_drive;
use crate::cmac;
use crate::drive::{DriveFamily, Family, UserDump};
use crate::platform::ScsiDevice;

/// A 0.10.x MTK rollback archive (`backup.toml` + raw `firmware.bin` + per-unit
/// files). Still accepted for restore; new backups are OEM-format images.
pub(super) struct BackupArtifact {
    pub(super) firmware: Vec<u8>,
    pub(super) per_unit: UserDump,
    pub(super) drive_product: String,
}

#[derive(Serialize, Deserialize)]
struct BackupManifest {
    format: String,
    firmware_size: usize,
    firmware_sha256: String,
    per_unit_sha256: String,
    drive_product: String,
    chip_family: String,
    completeness: String,
}

impl BackupArtifact {
    fn validate_coherence(&self) -> Result<()> {
        let descriptor = 0x1ec000usize;
        let nvram = 0x1f0000usize;
        if self
            .firmware
            .get(descriptor..descriptor + self.per_unit.rom_1ec000.len())
            != Some(self.per_unit.rom_1ec000.as_slice())
            || self
                .firmware
                .get(nvram..nvram + self.per_unit.rom_1f0000.len())
                != Some(self.per_unit.rom_1f0000.as_slice())
        {
            bail!("backup per-unit writable regions disagree with firmware image; no byte-coherent rollback image exists");
        }
        ensure_image_matches_drive(
            &self.firmware,
            &self.drive_product,
            Family::Mtk,
            false,
            None,
        )
        .context("backup image model/family does not match current drive")?;
        Ok(())
    }
    fn per_unit_hash(&self) -> String {
        let mut h = Sha256::new();
        for (name, data) in self.per_unit.members() {
            h.update(name.as_bytes());
            h.update((data.len() as u64).to_le_bytes());
            h.update(data);
        }
        format!("{:x}", h.finalize())
    }
    #[cfg(test)]
    pub(super) fn to_tar_bytes(&self) -> Result<Vec<u8>> {
        let manifest = BackupManifest {
            format: "freemkv-mtk-complete-backup-v1".into(),
            firmware_size: self.firmware.len(),
            firmware_sha256: format!("{:x}", Sha256::digest(&self.firmware)),
            per_unit_sha256: self.per_unit_hash(),
            drive_product: self.drive_product.clone(),
            chip_family: freemkv_chipset::detect_chip(&self.firmware)?
                .family
                .label()
                .into(),
            completeness: "all-firmware-bytes-read".into(),
        };
        let mut buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut buf);
            tar_append(
                &mut tar,
                "backup.toml",
                toml::to_string(&manifest)?.as_bytes(),
            )?;
            tar_append(&mut tar, "firmware.bin", &self.firmware)?;
            for (name, data) in self.per_unit.members() {
                tar_append(&mut tar, name, data)?;
            }
            tar.into_inner()?.flush()?;
        }
        Ok(buf)
    }

    pub(super) fn from_tar_bytes(bytes: &[u8], expected_size: usize) -> Result<Self> {
        let mut archive = tar::Archive::new(bytes);
        let mut firmware = None;
        let mut manifest = None;
        let mut regions = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let name = entry
                .path()?
                .to_str()
                .context("non-UTF8 backup member")?
                .to_owned();
            if entry.size() > expected_size as u64 + 4096 {
                bail!("backup member {name} exceeds size limit");
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            match name.as_str() {
                "backup.toml" if manifest.is_none() => {
                    manifest = Some(toml::from_str::<BackupManifest>(std::str::from_utf8(
                        &data,
                    )?)?)
                }
                "firmware.bin" if firmware.is_none() => firmware = Some(data),
                "rom_003000.bin" | "rom_1EC000.bin" | "rom_1F0000.bin" | "inq.bin"
                | "fd_fwdate.bin" | "fd_sn.bin" => regions.push((name, data)),
                _ => bail!("unexpected or duplicate backup member {name}"),
            }
        }
        let manifest = manifest.context("missing backup.toml")?;
        let firmware = firmware.context("missing firmware.bin")?;
        if manifest.format != "freemkv-mtk-complete-backup-v1"
            || manifest.completeness != "all-firmware-bytes-read"
            || manifest.firmware_size != expected_size
            || firmware.len() != expected_size
            || manifest.firmware_sha256 != format!("{:x}", Sha256::digest(&firmware))
            || freemkv_chipset::detect_chip(&firmware)?.family.label() != manifest.chip_family
            || !cmac::verify(&firmware)
        {
            bail!("backup firmware is incomplete, altered, or not a valid MTK update image");
        }
        let borrowed = regions
            .iter()
            .map(|(name, data)| (name.as_str(), data.clone()))
            .collect();
        let per_unit = UserDump::from_members(borrowed)?;
        let artifact = Self {
            firmware,
            per_unit,
            drive_product: manifest.drive_product,
        };
        if artifact.per_unit_hash() != manifest.per_unit_sha256 {
            bail!("backup per-unit regions do not match manifest hash");
        }
        artifact.validate_coherence()?;
        Ok(artifact)
    }
}

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

/// MTK's format-specific backup capture, called only by its protocol backend:
/// read every firmware byte, then rebuild the OEM-format image from it.
pub(crate) fn capture_mtk_backup(
    dev: &mut dyn ScsiDevice,
    drive: &dyn DriveFamily,
) -> Result<Vec<u8>> {
    let (read, readable, gaps) = drive
        .read_full_image(dev)
        .context("reading the drive's firmware")?;
    if read.len() != drive.image_size() || readable != read.len() || !gaps.is_empty() {
        bail!(
            "backup needs every firmware byte, but read {} of {}; unreadable ranges {:#x?}. \
             `dump` saves what the drive returned",
            readable,
            drive.image_size(),
            gaps
        );
    }
    let (image, report) = crate::drive::mtk_oem::rebuild(&read)?;
    crate::diagnostics::record(format!(
        "MTK backup rebuild: boot_page_restored={} factory_regions={:?}",
        report.boot_page_restored, report.regions_reset
    ));
    let product = drive.identity(dev).product;
    validate_mtk_image(&image, Some(&product))?;
    Ok(image)
}

/// Decode a backup without imposing its model on the target (forced restore).
pub(crate) fn decode_mtk_backup(bytes: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    let image = backup_image(bytes, expected_size)?;
    validate_mtk_image(&image, None)?;
    Ok(image)
}

/// MTK's format-specific backup validation, called only by its backend.
pub(crate) fn validate_mtk_backup(
    bytes: &[u8],
    target_model: &str,
    expected_size: usize,
) -> Result<Vec<u8>> {
    let image = backup_image(bytes, expected_size)?;
    validate_mtk_image(&image, Some(target_model))?;
    Ok(image)
}

/// The flashable image inside a backup: an OEM-format `.bin`, or the raw
/// capture of a 0.10.x archive rebuilt the same way, so its in-place-decrypted
/// boot page is never written back.
fn backup_image(bytes: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    if bytes.len() == expected_size {
        return Ok(bytes.to_vec());
    }
    let legacy = BackupArtifact::from_tar_bytes(bytes, expected_size)
        .context("not a MediaTek firmware backup")?;
    Ok(crate::drive::mtk_oem::rebuild(&legacy.firmware)
        .context("rebuilding the archived firmware")?
        .0)
}

fn validate_mtk_image(image: &[u8], target_model: Option<&str>) -> Result<()> {
    if !crate::drive::mtk_oem::has_encrypted_boot_page(image) {
        bail!("backup boot page is not in its stored (encrypted) form; refusing to treat it as flashable");
    }
    if !cmac::verify(image) {
        bail!("backup firmware fails AES-CMAC; it is not a valid MTK update image");
    }
    if let Some(model) = target_model {
        ensure_image_matches_drive(image, model, Family::Mtk, false, None)
            .context("backup image model/family does not match the target drive")?;
    }
    Ok(())
}

#[cfg(test)]
fn tar_append<W: Write>(b: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_path(name)?;
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_cksum();
    b.append(&h, data)?;
    Ok(())
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
