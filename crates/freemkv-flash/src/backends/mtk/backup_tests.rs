//! Unit tests for [`super`] (MediaTek backup capture, notice and validation).

use super::*;
use crate::backends::mtk::IMAGE_SIZE;
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
    let board = if chip == b"MTEKMT1939" {
        crate::backends::mtk::fixture::JB7
    } else {
        crate::backends::mtk::fixture::BU3
    };
    crate::backends::mtk::fixture::stamp(&mut img, &board);
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
    let backup = capture(&mut crate::backend::ReadDevice::without_unlocks(&mut dev)).unwrap();
    assert_eq!(
        backup[..layout::BOOT_PAGE.len],
        installed[..layout::BOOT_PAGE.len]
    );
    // Code is the installed firmware's; no per-unit byte survives.
    assert_eq!(backup[0x2_0000..0x1D_0000], installed[0x2_0000..0x1D_0000]);
    let defaults = super::super::oem::catalog()
        .default_for(Chip::Mt1939)
        .unwrap();
    for (range, want) in layout::DRIVE_WRITTEN.iter().zip(defaults.regions()) {
        let got = &backup[range.start..range.start + range.len];
        assert!(!layout::is_erased(got));
        assert!(got == &want[..], "region at {:#x} differs", range.start);
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
    let error = format!(
        "{:#}",
        capture(&mut crate::backend::ReadDevice::without_unlocks(&mut dev)).unwrap_err()
    );
    assert!(error.contains("boot page"), "{error}");
}

#[test]
fn validation_requires_a_known_stored_boot_page() {
    let mut image = stored_image(b"MTEKMT1959", "BD-RE BU40N", 3);
    validate(&image, "BD-RE BU40N", IMAGE_SIZE).unwrap();
    image[..layout::BOOT_PAGE.len].fill(0x18);
    assert!(validate(&image, "BD-RE BU40N", IMAGE_SIZE).is_err());
}

/// Across a corpus (`FREEMKV_MTK_IMAGES`), a drive running a cataloged OEM
/// build backs up byte-exact to it; a drive running anything else (a modified,
/// community or dumped build) backs up as a reconstruction, never labelled
/// byte-identical to an OEM image.
#[test]
#[ignore = "needs FREEMKV_MTK_IMAGES pointing at OEM MT1959/MT1939 images"]
fn corpus_backups_are_exact_only_for_oem_builds() {
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
    let (mut exact, mut reconstructed) = (0, 0);
    for path in paths {
        let image = std::fs::read(&path).unwrap();
        if image.len() != IMAGE_SIZE
            || mediatek_optical::image::is_drive_read(&image)
            || mediatek_optical::image::detect_chip(&image).is_err()
        {
            continue;
        }
        let cataloged = catalog.build(&oem::content_key(&image).unwrap()).is_some();
        let Ok(rebuilt) = oem::rebuild(&drive_read(&image), catalog) else {
            assert!(!cataloged, "{}", path.display());
            continue;
        };
        let verified = matches!(notice(&rebuilt.image), BackupNotice::VerifiedOem(_));
        assert_eq!(
            rebuilt.provenance.is_exact(),
            cataloged,
            "{}",
            path.display()
        );
        assert_eq!(verified, cataloged, "{}", path.display());
        if cataloged {
            assert!(rebuilt.image == image, "{}", path.display());
            exact += 1;
        } else {
            reconstructed += 1;
        }
    }
    assert!(
        exact > 0 && reconstructed > 0,
        "{exact} exact, {reconstructed} reconstructed"
    );
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

/// Backup compatibility for the stale-tag drives. A JB8 build carries the
/// descriptor tag `MTEKMT1939` but an "MT1959 Boot" banner, so it is MT1959.
/// An existing backup of such a drive recorded `chip_family = "MT1939"` (the
/// old tag label); restore must still accept it as a legacy alias of the banner
/// chip, while an unrelated label is still rejected.
#[test]
fn legacy_backups_accept_the_old_tag_label_as_an_alias() {
    // stored_image(MTEKMT1939) stamps the JB7 (classic MT1939) board; re-stamp
    // the JB8 board so the banner reads "MT1959 Boot JB8" while the tag stays
    // MTEKMT1939 — the real stale-tag shape.
    let mut img = stored_image(b"MTEKMT1939", "BD-RE  WH16NS58", 5);
    crate::backends::mtk::fixture::stamp(&mut img, &crate::backends::mtk::fixture::JB8);
    let img = cmac::resign(&img).unwrap();
    assert_eq!(
        freemkv_chipset::detect_chip(&img).unwrap().family,
        Chip::Mt1959,
        "the banner decides: MT1959"
    );
    assert_eq!(
        mediatek_optical::Chip::from_tag(&img),
        Some(Chip::Mt1939),
        "the stale descriptor tag names MT1939"
    );
    // The authoritative banner label matches, and so does the legacy tag label.
    assert!(
        chip_family_matches(&img, "MT1959").unwrap(),
        "banner chip label"
    );
    assert!(
        chip_family_matches(&img, "MT1939").unwrap(),
        "legacy tag label accepted as an alias"
    );
    // An unrelated label is still rejected — the gate is not disabled.
    assert!(!chip_family_matches(&img, "MT1805").unwrap());
}

#[test]
fn a_drive_that_hides_its_flash_is_told_so_not_asked_for_every_byte() {
    // The reported WH16NS58: only the calibration area (0x1F0000..) answered.
    let error = super::incomplete_read(0x1_0000, &[(0, 0x1F_0000)]);
    assert!(crate::workflow::error_message(&error).contains("normal for many MediaTek drives"));
    let err = format!("{error:#}");
    assert!(err.contains("does not expose its flash"), "{err}");
    assert!(!err.contains("needs every firmware byte"), "{err}");
}

#[test]
fn a_few_unreadable_spans_keep_the_partial_read_message() {
    // Banner readable; a span elsewhere failed: a genuine partial read.
    let err = super::incomplete_read(0x20_0000 - 0x1000, &[(0x80_000, 0x81_000)]).to_string();
    assert!(err.contains("needs every firmware byte"), "{err}");
    assert!(!err.contains("does not expose its flash"), "{err}");
}
