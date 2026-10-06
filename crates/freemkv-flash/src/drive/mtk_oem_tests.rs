//! Unit tests for [`super`] (OEM-format MT1959 image rebuild).

use super::*;
use crate::drive::mtk::IMAGE_SIZE;

const PLAINTEXT: [u8; BOOT_PAGE_LEN] = [0x5A; BOOT_PAGE_LEN];

fn plaintext_sha() -> [u8; 32] {
    Sha256::digest(PLAINTEXT).into()
}

/// A drive capture: decrypted boot page, code pattern, and per-unit data in
/// every drive-written region.
fn capture() -> Vec<u8> {
    let mut read: Vec<u8> = (0..IMAGE_SIZE).map(|i| (i % 253) as u8).collect();
    read[..BOOT_PAGE_LEN].copy_from_slice(&PLAINTEXT);
    for region in &FACTORY_REGIONS {
        read[region.start..region.start + region.len].fill(0x52);
    }
    read
}

#[test]
fn factory_tables_cover_their_regions_exactly() {
    for region in &FACTORY_REGIONS {
        assert_eq!(
            expand(region.runs, region.len).len(),
            region.len,
            "{}",
            region.name
        );
    }
}

#[test]
fn rebuild_restores_boot_page_and_factory_regions_only() {
    let read = capture();
    let (image, report) = rebuild_with(&read, &plaintext_sha()).unwrap();
    assert!(report.boot_page_restored);
    assert!(has_encrypted_boot_page(&image));
    assert_eq!(report.regions_reset.len(), FACTORY_REGIONS.len());
    let mut untouched = vec![true; IMAGE_SIZE];
    untouched[..BOOT_PAGE_LEN].fill(false);
    for region in &FACTORY_REGIONS {
        assert_eq!(
            image[region.start..region.start + region.len],
            expand(region.runs, region.len)[..],
            "{}",
            region.name
        );
        untouched[region.start..region.start + region.len].fill(false);
    }
    assert!((0..IMAGE_SIZE).all(|i| !untouched[i] || image[i] == read[i]));
}

#[test]
fn erased_uhd_list_stays_erased_for_bd_only_builds() {
    let mut read = capture();
    read[0x1D_8000..0x1E_0000].fill(0xFF);
    let (image, report) = rebuild_with(&read, &plaintext_sha()).unwrap();
    assert!(image[0x1D_8000..0x1E_0000].iter().all(|&b| b == 0xFF));
    assert!(!report
        .regions_reset
        .iter()
        .any(|(name, _)| *name == "UHD revocation list"));
}

#[test]
fn encrypted_boot_page_is_kept_as_is() {
    let mut read = capture();
    read[..BOOT_PAGE_LEN].copy_from_slice(&data::ENCRYPTED_BOOT_PAGE);
    let (image, report) = rebuild_with(&read, &plaintext_sha()).unwrap();
    assert!(!report.boot_page_restored);
    assert!(has_encrypted_boot_page(&image));
}

#[test]
fn unrecognized_boot_page_is_refused() {
    let mut read = capture();
    read[0] ^= 1;
    let error = rebuild_with(&read, &plaintext_sha()).unwrap_err();
    assert!(error.to_string().contains("unrecognized boot page"));
}

#[test]
fn wrong_size_capture_is_refused() {
    assert!(rebuild(&[0u8; 0x1000]).is_err());
}

/// Every OEM image whose factory tables match ours must rebuild byte-exact from
/// a simulated drive read. Set `FREEMKV_MTK_IMAGES` to a directory of images.
#[test]
#[ignore = "needs FREEMKV_MTK_IMAGES pointing at OEM MT1959 images"]
fn oem_images_rebuild_byte_exact() {
    let dir = std::env::var("FREEMKV_MTK_IMAGES").expect("FREEMKV_MTK_IMAGES");
    let mut checked = 0;
    for entry in walk(std::path::Path::new(&dir)) {
        let image = std::fs::read(&entry).unwrap();
        if image.len() != IMAGE_SIZE || !has_encrypted_boot_page(&image) {
            continue;
        }
        let standard = FACTORY_REGIONS.iter().all(|region| {
            let slice = &image[region.start..region.start + region.len];
            slice == expand(region.runs, region.len).as_slice()
                || (region.keep_if_erased && slice.iter().all(|&b| b == 0xFF))
        });
        if !standard {
            continue;
        }
        let mut read = image.clone();
        read[..BOOT_PAGE_LEN].copy_from_slice(&PLAINTEXT);
        for region in &FACTORY_REGIONS {
            let slice = &mut read[region.start..region.start + region.len];
            if !(region.keep_if_erased && slice.iter().all(|&b| b == 0xFF)) {
                slice.fill(0x52);
            }
        }
        let (rebuilt, _) = rebuild_with(&read, &plaintext_sha()).unwrap();
        assert!(rebuilt == image, "{}", entry.display());
        checked += 1;
    }
    assert!(checked > 0, "no OEM MT1959 images found");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "bin") {
            out.push(path);
        }
    }
    out
}
