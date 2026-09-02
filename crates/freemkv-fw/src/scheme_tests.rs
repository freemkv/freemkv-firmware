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
