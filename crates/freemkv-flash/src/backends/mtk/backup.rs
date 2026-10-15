//! MediaTek backups: the flashable OEM image rebuilt from a complete drive read
//! by [`mediatek_optical::oem::rebuild`] against the embedded catalog
//! ([`super::oem`]), plus decoding of the 0.10.x rollback archives they
//! replace.
//!
//! A recognized OEM build backs up byte-identical to the vendor file. An
//! unknown build (a revision missing from the hoard, or a modified image) gets
//! its chip generation's factory contents and is reported as a reconstruction.
//! Either way the backup carries no per-unit data.

use std::io::Read;
#[cfg(test)]
use std::io::Write;

use anyhow::{bail, Context, Result};
use mediatek_optical::oem::{self, BootPage, Provenance, Source};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::crossflash::ensure_image_matches_drive;
use super::UserDump;
use crate::backend::{Backend, BackupNotice, ReadDevice};
use crate::cmac;

/// A 0.10.x MTK rollback archive (`backup.toml` + raw `firmware.bin` + per-unit
/// files). Still accepted for restore; new backups are OEM-format images.
pub(crate) struct BackupArtifact {
    pub(crate) firmware: Vec<u8>,
    pub(crate) per_unit: UserDump,
    pub(crate) drive_product: String,
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
        ensure_image_matches_drive(&self.firmware, &self.drive_product)
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
    pub(crate) fn to_tar_bytes(&self) -> Result<Vec<u8>> {
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

    pub(crate) fn from_tar_bytes(bytes: &[u8], expected_size: usize) -> Result<Self> {
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
                bail!(
                    "backup member {} exceeds size limit",
                    crate::backend::sanitize_ascii(&name)
                );
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
                _ => bail!(
                    "unexpected or duplicate backup member {}",
                    crate::backend::sanitize_ascii(&name)
                ),
            }
        }
        let manifest = manifest.context("missing backup.toml")?;
        let firmware = firmware.context("missing firmware.bin")?;
        if manifest.format != "freemkv-mtk-complete-backup-v1"
            || manifest.completeness != "all-firmware-bytes-read"
            || manifest.firmware_size != expected_size
            || firmware.len() != expected_size
            || manifest.firmware_sha256 != format!("{:x}", Sha256::digest(&firmware))
            || !chip_family_matches(&firmware, &manifest.chip_family)?
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

/// Read every firmware byte, then rebuild the flashable OEM image from it.
///
/// The read source depends on the drive: a drive already running freemkv
/// firmware is read through its injected `DumpAll` command (stock MediaTek
/// firmware exposes no full-flash read — see [`super::fwdump`]); any other drive
/// is read through the OEM `READ BUFFER` path. Both return the same bytes, so
/// everything afterward — `oem::rebuild` (boot page from the catalog,
/// drive-written regions reset to factory) and validation — is identical.
pub(crate) fn capture(dev: &mut ReadDevice<'_>) -> Result<Vec<u8>> {
    let (read, readable, gaps) = if super::fwdump::is_freemkv(dev) {
        crate::diagnostics::record("MTK backup: drive runs freemkv firmware; reading via DumpAll");
        super::fwdump::capture_full_image(dev)
            .context("reading the drive's firmware via the freemkv dump command")?
    } else {
        crate::probe::read_full_image(dev).context("reading the drive's firmware")?
    };
    if read.len() != super::IMAGE_SIZE || readable != read.len() || !gaps.is_empty() {
        return Err(incomplete_read(readable, &gaps));
    }
    let rebuilt = oem::rebuild(&read, super::oem::catalog())
        .context("rebuilding the OEM image from the drive read")?;
    crate::diagnostics::record(format!(
        "MTK backup rebuild: {}",
        describe(&rebuilt.provenance)
    ));
    let product = super::Mtk.identity(dev).product;
    validate_image(&rebuilt.image, Some(&product))?;
    Ok(rebuilt.image)
}

/// Why a backup cannot be built from an incomplete drive read. When the boot
/// banner itself did not answer, the firmware does not expose its flash to the
/// read command we use at all (some drives answer only their calibration area),
/// which is a different problem from a few unreadable spans.
fn incomplete_read(readable: usize, gaps: &[(usize, usize)]) -> anyhow::Error {
    let banner = mediatek_optical::layout::BANNER.start;
    if gaps
        .iter()
        .any(|&(start, end)| (start..end).contains(&banner))
    {
        anyhow::anyhow!(
            "this drive's firmware does not expose its flash to the read command freemkv \
             uses (only {readable} of {} bytes answered: {gaps:#x?}), so a backup is not \
             possible on this drive. `freemkv-flash dump` saves what the drive returns",
            super::IMAGE_SIZE
        )
    } else {
        anyhow::anyhow!(
            "backup needs every firmware byte, but read {readable} of {}; unreadable ranges \
             {gaps:#x?}. `dump` saves what the drive returned",
            super::IMAGE_SIZE
        )
    }
}

/// One-line provenance for logs and the backup notice.
fn describe(p: &Provenance) -> String {
    let source = match &p.source {
        Source::Exact { model, revision } => format!("OEM {model} {revision}"),
        Source::ChipDefault => format!("unknown {} build, {} factory defaults", p.chip, p.chip),
    };
    let boot = match p.boot_page {
        BootPage::Stored => "boot page stored",
        BootPage::Restored => "boot page restored",
    };
    let regions: Vec<String> = p
        .regions_reset
        .iter()
        .map(|(name, n)| format!("{name} ({n} B)"))
        .collect();
    format!(
        "{source}; {boot}; reset: {}",
        if regions.is_empty() {
            "none".into()
        } else {
            regions.join(", ")
        }
    )
}

/// What a saved backup is: a byte-exact vendor image, or a reconstruction.
pub(crate) fn notice(bytes: &[u8]) -> BackupNotice {
    let catalog = super::oem::catalog();
    let exact = oem::content_key(bytes).and_then(|key| catalog.build(&key));
    match exact {
        Some(build) if oem::rebuild(bytes, catalog).is_ok_and(|r| r.image == bytes) => {
            BackupNotice::VerifiedOem(format!(
                "byte-identical to the OEM {} {} image: per-drive settings, calibration and \
                 revocation lists are factory contents; safe to share and flash back",
                build.model, build.revision
            ))
        }
        _ => BackupNotice::Unverified(
            "this firmware build is not in the OEM catalog (a revision we lack, or a modified \
             image), so the backup is a reconstruction: the boot page and per-drive regions use \
             this chip's factory contents. It carries no personal data and restores the \
             installed firmware code, but it is not a known vendor file"
                .into(),
        ),
    }
}

/// Decode and validate a backup for the target drive model.
pub(crate) fn validate(bytes: &[u8], target_model: &str, expected_size: usize) -> Result<Vec<u8>> {
    let image = backup_image(bytes, expected_size)?;
    validate_image(&image, Some(target_model))?;
    Ok(image)
}

/// The flashable image inside a backup: an OEM-format `.bin`, or the raw
/// capture of a 0.10.x archive rebuilt the same way, so its read-back boot page
/// is never written to flash.
pub(super) fn backup_image(bytes: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    if bytes.len() == expected_size {
        return Ok(bytes.to_vec());
    }
    let legacy = BackupArtifact::from_tar_bytes(bytes, expected_size)
        .context("not a MediaTek firmware backup")?;
    Ok(oem::rebuild(&legacy.firmware, super::oem::catalog())
        .context("rebuilding the archived firmware")?
        .image)
}

fn validate_image(image: &[u8], target_model: Option<&str>) -> Result<()> {
    let boot = image
        .get(..mediatek_optical::layout::BOOT_PAGE.len)
        .context("backup is shorter than a boot page")?;
    if !super::oem::catalog().knows_boot_page(boot) {
        bail!(
            "backup boot page is not a known stored boot page; refusing to treat it as flashable"
        );
    }
    if !cmac::verify(image) {
        bail!("backup firmware fails AES-CMAC; it is not a valid MTK update image");
    }
    if let Some(model) = target_model {
        ensure_image_matches_drive(image, model)
            .context("backup image model/family does not match the target drive")?;
    }
    Ok(())
}

/// Whether `firmware`'s chip family matches the `stored` label from an existing
/// backup's `backup.toml`.
///
/// New backups store the banner chip (the authoritative generation). Backups
/// written before the banner became authoritative stored the drive's stale
/// `MTEKMT19xx` identity tag instead, so for the JB8/JBC6/JBP6/BUP1 drives (tag
/// `MTEK MT1939`, banner/code MT1959) an old backup says "MT1939" where the
/// banner says "MT1959". Accept both: the banner chip, or — as a legacy alias —
/// the firmware's own identity-tag chip. This keeps existing user backups
/// restorable; the chip gate is still enforced (an unrelated label is rejected).
fn chip_family_matches(firmware: &[u8], stored: &str) -> Result<bool> {
    let banner = freemkv_chipset::detect_chip(firmware)?.family.label();
    if stored == banner {
        return Ok(true);
    }
    // Legacy alias: the stale identity-tag chip an older backup recorded.
    let legacy_tag_chip = mediatek_optical::Chip::from_tag(firmware).map(|c| c.label());
    Ok(legacy_tag_chip == Some(stored))
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
