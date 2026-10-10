//! Unit tests for [`super`] (MediaTek backup capture, notice and validation).

use super::*;
use crate::drive::mtk::{Mtk, IMAGE_SIZE};
use crate::platform::MockScsiDevice;
use mediatek_optical::{layout, Chip};

/// A signed image of `chip` carrying the cataloged stored boot page.
fn stored_image(chip: &[u8; 10], model: &str, code: u8) -> Vec<u8> {
    let mut img: Vec<u8> = (0..IMAGE_SIZE).map(|i| (i % 251) as u8 ^ code).collect();
    let boot = super::super::oem::catalog()
        .default_for(Chip::Mt1959)
        .unwrap()
        .boot_page()
        .to_vec();
    img[..layout::BOOT_PAGE.len].copy_from_slice(&boot);
    let d = layout::DESCRIPTOR.start;
    img[d + 0x08..d + 0x18].fill(b' ');
    img[d + 0x08..d + 0x08 + model.len()].copy_from_slice(model.as_bytes());
    img[d + 0x34..d + 0x3E].copy_from_slice(chip);
    let t = cmac::TABLE_OFFSET;
    for i in 0..cmac::ENTRY_COUNT {
        img[t + i * cmac::ENTRY_SIZE..t + (i + 1) * cmac::ENTRY_SIZE].fill(0xFF);
    }
    img[t..t + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[t + 4..t + 8].copy_from_slice(&0x11000u32.to_le_bytes());
    img[t + 8..t + 12].copy_from_slice(&0x1FFFFu32.to_le_bytes());
    cmac::resign(&img).unwrap()
}

/// What the drive returns: the boot page mirrored from 0x10000 and per-unit
/// bytes in every drive-written region.
fn drive_read(image: &[u8]) -> Vec<u8> {
    let mut read = image.to_vec();
    let mirror = read[layout::BOOT_MIRROR.start..layout::BOOT_MIRROR.end()].to_vec();
    read[..layout::BOOT_PAGE.len].copy_from_slice(&mirror);
    for range in layout::DRIVE_WRITTEN {
        read[range.start..range.start + 16].fill(0x52);
    }
    read
}

#[test]
fn unknown_mt1939_build_backs_up_as_a_labelled_reconstruction() {
    // The reported failure: an MT1939 drive whose build the catalog lacks.
    let installed = stored_image(b"MTEKMT1939", "BD-RE BE14NU40", 7);
    let mut dev = MockScsiDevice::new()
        .with_firmware_image(drive_read(&installed))
        .with_product("BD-RE BE14NU40");
    let backup = capture(&mut dev, &Mtk).unwrap();
    assert_eq!(
        backup[..layout::BOOT_PAGE.len],
        installed[..layout::BOOT_PAGE.len]
    );
    // Code is the installed firmware's; no per-unit byte survives.
    assert_eq!(backup[0x2_0000..0x1D_0000], installed[0x2_0000..0x1D_0000]);
    for range in layout::DRIVE_WRITTEN {
        assert!(!backup[range.start..range.start + 16]
            .iter()
            .all(|&b| b == 0x52));
    }
    assert!(matches!(notice(&backup), BackupNotice::Unverified(_)));
    validate(&backup, "BD-RE BE14NU40", IMAGE_SIZE).unwrap();
}

#[test]
fn unknown_boot_page_is_refused() {
    let installed = stored_image(b"MTEKMT1959", "BD-RE BU40N", 3);
    let mut read = drive_read(&installed);
    read[0] ^= 1;
    let mut dev = MockScsiDevice::new().with_firmware_image(read);
    let error = format!("{:#}", capture(&mut dev, &Mtk).unwrap_err());
    assert!(error.contains("boot page"), "{error}");
}

#[test]
fn validation_requires_a_known_stored_boot_page() {
    let mut image = stored_image(b"MTEKMT1959", "BD-RE BU40N", 3);
    validate(&image, "BD-RE BU40N", IMAGE_SIZE).unwrap();
    image[..layout::BOOT_PAGE.len].fill(0x18);
    assert!(validate(&image, "BD-RE BU40N", IMAGE_SIZE).is_err());
}

/// Every OEM image in a corpus rebuilds byte-exact from a simulated drive
/// read. Set `FREEMKV_MTK_IMAGES` to a directory of images.
#[test]
#[ignore = "needs FREEMKV_MTK_IMAGES pointing at OEM MT1959/MT1939 images"]
fn corpus_rebuilds_byte_exact() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let dir = std::env::var("FREEMKV_MTK_IMAGES").expect("FREEMKV_MTK_IMAGES");
    let mut paths = Vec::new();
    walk(std::path::Path::new(&dir), &mut paths);
    let catalog = super::super::oem::catalog();
    let mut checked = 0;
    for path in paths {
        let image = std::fs::read(&path).unwrap();
        if image.len() != IMAGE_SIZE
            || mediatek_optical::image::is_drive_read(&image)
            || mediatek_optical::image::detect_chip(&image).is_err()
        {
            continue;
        }
        let rebuilt = oem::rebuild(&drive_read(&image), catalog).unwrap();
        assert!(rebuilt.provenance.is_exact(), "{}", path.display());
        assert!(rebuilt.image == image, "{}", path.display());
        checked += 1;
    }
    assert!(checked > 0);
}

/// A real drive capture (`FREEMKV_MTK_LIVE`, a raw 2 MiB `dump`) rebuilds to a
/// flashable image: stored boot page, valid CMAC, no read-back boot page.
#[test]
#[ignore = "needs FREEMKV_MTK_LIVE pointing at a raw MediaTek drive dump"]
fn live_capture_rebuilds_flashable() {
    let path = std::env::var("FREEMKV_MTK_LIVE").expect("FREEMKV_MTK_LIVE");
    let read = std::fs::read(path).unwrap();
    assert!(mediatek_optical::image::is_drive_read(&read));
    let rebuilt = oem::rebuild(&read, super::super::oem::catalog()).unwrap();
    assert_eq!(rebuilt.provenance.boot_page, BootPage::Restored);
    validate_image(&rebuilt.image, None).unwrap();
    eprintln!("{}", describe(&rebuilt.provenance));
}
