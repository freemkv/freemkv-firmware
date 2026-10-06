//! Rebuild an OEM-exact MT1959 flash image from a live READ BUFFER capture.
//!
//! The mapped 2 MiB read equals the flashed image except for:
//! * the boot page `0x0..0x400`, which the mask ROM decrypts in place, so the
//!   read returns plaintext while flash holds the encrypted page;
//! * drive-written regions the update path never overwrites: the UHD/BD host
//!   revocation lists, the NVRAM settings page and the per-unit `VENDOR_INFO`
//!   calibration block.
//!
//! A backup restores the encrypted boot page and replaces the drive-written
//! regions with their factory contents, so it carries no per-unit data and, for
//! the common factory tables, hashes identical to the vendor's update image.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

#[path = "mtk_oem_data.rs"]
mod data;

/// Length of the boot page the mask ROM decrypts in place.
pub const BOOT_PAGE_LEN: usize = 0x400;

/// SHA-256 of the boot page as READ BUFFER returns it once the mask ROM has
/// decrypted [`data::ENCRYPTED_BOOT_PAGE`] (captured on a BU40N 1.00 drive).
const DECRYPTED_BOOT_PAGE_SHA256: [u8; 32] = [
    0x2e, 0x40, 0x0d, 0x24, 0x9d, 0xd7, 0x39, 0x1f, 0x0a, 0xaf, 0x6d, 0xf0, 0xb7, 0x5d, 0xa2, 0x7a,
    0x01, 0x13, 0x9e, 0x2f, 0x07, 0xbe, 0xe8, 0xf1, 0xc6, 0x75, 0x94, 0x49, 0xe2, 0x12, 0xc2, 0x8c,
];

/// A drive-written region and its factory contents.
struct FactoryRegion {
    name: &'static str,
    start: usize,
    len: usize,
    runs: &'static [(u32, u32, u8)],
    /// Keep an erased (all-`0xFF`) region as read: BD-only builds ship no UHD list.
    keep_if_erased: bool,
}

const FACTORY_REGIONS: [FactoryRegion; 4] = [
    FactoryRegion {
        name: "UHD revocation list",
        start: 0x1D_8000,
        len: 0x8000,
        runs: data::UHD_HRL,
        keep_if_erased: true,
    },
    FactoryRegion {
        name: "BD revocation list",
        start: 0x1E_0000,
        len: 0x8000,
        runs: data::BD_HRL,
        keep_if_erased: false,
    },
    FactoryRegion {
        name: "NVRAM settings",
        start: 0x1E_8000,
        len: 0x4000,
        runs: data::NVRAM,
        keep_if_erased: false,
    },
    FactoryRegion {
        name: "vendor calibration",
        start: 0x1F_0000,
        len: 0x1_0000,
        runs: data::VENDOR_INFO,
        keep_if_erased: false,
    },
];

/// What the rebuild changed, for the backup log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RebuildReport {
    /// Whether the decrypted boot page was replaced with the encrypted page.
    pub boot_page_restored: bool,
    /// Drive-written regions reset to factory contents: `(name, bytes changed)`.
    pub regions_reset: Vec<(&'static str, usize)>,
}

fn expand(runs: &[(u32, u32, u8)], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for &(offset, count, byte) in runs {
        debug_assert_eq!(offset as usize, out.len());
        out.resize(out.len() + count as usize, byte);
    }
    debug_assert_eq!(out.len(), len);
    out
}

/// Rebuild an OEM-format image from a complete 2 MiB capture. Fails on an
/// unrecognized boot page: an image is never produced with a boot page whose
/// stored form is unknown.
pub fn rebuild(read: &[u8]) -> Result<(Vec<u8>, RebuildReport)> {
    rebuild_with(read, &DECRYPTED_BOOT_PAGE_SHA256)
}

fn rebuild_with(read: &[u8], decrypted_sha256: &[u8; 32]) -> Result<(Vec<u8>, RebuildReport)> {
    if read.len() != super::mtk::IMAGE_SIZE {
        bail!(
            "MediaTek capture is {} bytes; an OEM image needs exactly {}",
            read.len(),
            super::mtk::IMAGE_SIZE
        );
    }
    let mut image = read.to_vec();
    let mut report = RebuildReport::default();
    let boot = &read[..BOOT_PAGE_LEN];
    if boot != data::ENCRYPTED_BOOT_PAGE.as_slice() {
        if Sha256::digest(boot).as_slice() != decrypted_sha256 {
            bail!(
                "unrecognized boot page (sha256 {:x}); no restorable backup can be built for this firmware",
                Sha256::digest(boot)
            );
        }
        image[..BOOT_PAGE_LEN].copy_from_slice(&data::ENCRYPTED_BOOT_PAGE);
        report.boot_page_restored = true;
    }
    for region in &FACTORY_REGIONS {
        let current = &read[region.start..region.start + region.len];
        if region.keep_if_erased && current.iter().all(|&b| b == 0xFF) {
            continue;
        }
        let factory = expand(region.runs, region.len);
        let changed = current.iter().zip(&factory).filter(|(a, b)| a != b).count();
        if changed > 0 {
            image[region.start..region.start + region.len].copy_from_slice(&factory);
            report.regions_reset.push((region.name, changed));
        }
    }
    Ok((image, report))
}

/// Whether `image` stores the boot page in its encrypted, flashable form.
pub fn has_encrypted_boot_page(image: &[u8]) -> bool {
    image.get(..BOOT_PAGE_LEN) == Some(data::ENCRYPTED_BOOT_PAGE.as_slice())
}

/// The encrypted boot page, for building test images.
#[cfg(test)]
pub(crate) fn encrypted_boot_page() -> &'static [u8] {
    &data::ENCRYPTED_BOOT_PAGE
}

#[cfg(test)]
#[path = "mtk_oem_tests.rs"]
mod tests;
