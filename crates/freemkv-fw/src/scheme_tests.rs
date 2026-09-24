use super::*;

/// Build a synthetic MTK image with one active entry over `[start..=end]`,
/// its stored digest correctly filled; the other 15 entries are `0xFF`.
fn synthetic_image() -> (Vec<u8>, u32, u32) {
    let mut img = vec![0u8; 0x20000];
    // Some non-trivial payload in the covered range.
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    // All entries start as unused (0xFF...).
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        for b in &mut img[off..off + cmac::ENTRY_SIZE] {
            *b = 0xFF;
        }
    }
    // Entry 0: active, covering a small in-bounds range well clear of the table.
    let start: u32 = 0x1000;
    let end: u32 = 0x1FFF;
    let off = cmac::TABLE_OFFSET;
    img[off..off + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[off + 4..off + 8].copy_from_slice(&start.to_le_bytes());
    img[off + 8..off + 12].copy_from_slice(&end.to_le_bytes());
    let digest = cmac::compute_stored_digest(&img, start, end).unwrap();
    img[off + 12..off + 28].copy_from_slice(&digest);
    (img, start, end)
}

#[test]
fn verify_passes_on_valid_image() {
    let (img, _, _) = synthetic_image();
    let scheme = MtkCmac;
    assert!(scheme.detect(&img));
    let verdicts = scheme.verify(&img).unwrap();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts.iter().all(|v| v.ok));
}

#[test]
fn verify_reports_mismatch_after_corruption() {
    let (mut img, _, _) = synthetic_image();
    img[0x1234] ^= 0xFF; // flip a covered byte
    let verdicts = MtkCmac.verify(&img).unwrap();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts.iter().any(|v| !v.ok));
}

#[test]
fn sign_repairs_corruption_with_one_change() {
    let (mut img, _, _) = synthetic_image();
    img[0x1234] ^= 0xFF;
    let (signed, changes) = MtkCmac.sign(&img).unwrap();
    assert_eq!(changes.len(), 1);
    let verdicts = MtkCmac.verify(&signed).unwrap();
    assert!(!verdicts.is_empty());
    assert!(verdicts.iter().all(|v| v.ok));
}

#[test]
fn detect_false_on_all_zero_buffer() {
    let zeros = vec![0u8; 0x20000];
    assert!(!MtkCmac.detect(&zeros));
}

/// A buffer whose every table entry is `0xFF` except entry 0, which is written
/// by the caller. Used by the `detect` boundary tests below.
fn image_with_one_entry(len: usize, enabled: u32, start: u32, end: u32) -> Vec<u8> {
    let mut img = vec![0u8; len];
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        img[off..off + cmac::ENTRY_SIZE].fill(0xFF);
    }
    let off = cmac::TABLE_OFFSET;
    img[off..off + 4].copy_from_slice(&enabled.to_le_bytes());
    img[off + 4..off + 8].copy_from_slice(&start.to_le_bytes());
    img[off + 8..off + 12].copy_from_slice(&end.to_le_bytes());
    img
}

/// The scheme name is part of the human report and the `--family` UX; a drive
/// owner reading "which construction signed my image?" must get the real answer.
#[test]
fn scheme_name_is_the_mediatek_cmac_label() {
    assert_eq!(
        MtkCmac.name(),
        "MediaTek MT19xx CMAC",
        "the scheme name identifies the integrity construction in every report"
    );
}

/// The size guard in `detect` is `image.len() < table_end` — **strictly** less.
/// An image that is exactly as long as the table requires is a legitimate MTK
/// image and must be recognized; an off-by-one there (`==` / `<=`) would make
/// forge refuse to sign the smallest valid image, and a refused sign is a drive
/// that never gets its firmware.
#[test]
fn detect_accepts_an_image_exactly_as_long_as_the_integrity_table_requires() {
    let table_end = cmac::TABLE_OFFSET + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE;
    let img = image_with_one_entry(table_end, cmac::ENABLED, 0, (table_end - 1) as u32);
    assert_eq!(img.len(), table_end, "fixture is exactly table-sized");
    assert!(
        MtkCmac.detect(&img),
        "an image of exactly table_end bytes with one well-formed active entry is an MTK image"
    );
}

/// The in-bounds test on a region's inclusive `end` is `end < image.len()`. An
/// entry ending exactly ON `image.len()` covers one byte past the buffer, so the
/// digest can never be computed: accepting it (`<=`) would hand a truncated /
/// mis-described image to the signing path instead of refusing it here.
#[test]
fn detect_rejects_an_entry_whose_end_is_one_past_the_last_byte() {
    let len = 0x20000usize;
    let img = image_with_one_entry(len, cmac::ENABLED, 0x1000, len as u32);
    assert!(
        !MtkCmac.detect(&img),
        "end == image.len() is out of bounds (ranges are inclusive) and must not detect"
    );
    // Sanity: the same entry one byte shorter IS well-formed, so the rejection
    // above is about the bound, not about the fixture being malformed.
    let ok = image_with_one_entry(len, cmac::ENABLED, 0x1000, (len - 1) as u32);
    assert!(
        MtkCmac.detect(&ok),
        "end == len-1 is the last in-bounds byte"
    );
}

/// `sign` reports a `RegionChange` only for entries whose digest ACTUALLY moved.
/// Re-signing an already-valid image must report **zero** changes: the change
/// list is what the CLI prints as "these regions were repaired", and a scheme
/// that claims a repair it did not make hides a real no-op behind a green line.
#[test]
fn sign_on_an_already_valid_image_reports_no_changed_regions() {
    let (img, _, _) = synthetic_image();
    assert!(cmac::verify(&img), "fixture is already correctly signed");
    let (signed, changes) = MtkCmac.sign(&img).unwrap();
    assert_eq!(signed, img, "re-signing a valid image is byte-identical");
    assert!(
        changes.is_empty(),
        "an already-valid image has no changed digests, got {changes:?}"
    );
}

// EQUIVALENT MUTANTS (documented, not chased):
//
// `detect`'s `let table_end = cmac::TABLE_OFFSET + cmac::ENTRY_COUNT *
// cmac::ENTRY_SIZE;` admits three arithmetic mutations (`+`→`-`, `*`→`+`,
// `*`→`/`). All three make `table_end` SMALLER, and the only use of the value
// is the early-return size guard. Any image that slips past a smaller guard is
// then handed to `cmac::parse_table`, which applies the *same* size test itself
// and returns `Err` → `detect` returns `false` anyway. The guard is a
// redundant fast path, so no input can distinguish the mutants from the
// original: they are behaviourally equivalent and are left unkilled.
