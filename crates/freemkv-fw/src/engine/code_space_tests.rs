//! Window arithmetic and integrity-table comparison of the code-space policy.

use super::*;

#[test]
fn subtraction_keeps_only_the_unblocked_pieces() {
    assert_eq!(subtract(vec![0..20], &[0..5]), vec![5..20]);
    assert_eq!(subtract(vec![0..20], &[15..20]), vec![0..15]);
    assert_eq!(subtract(vec![0..20], &[5..10]), vec![0..5, 10..20]);
    assert_eq!(subtract(vec![0..20], &[0..20]), Vec::<Range<usize>>::new());
    assert_eq!(subtract(vec![10..20], &[0..10]), vec![10..20]);
    assert_eq!(subtract(vec![10..20], &[20..30]), vec![10..20]);
    assert_eq!(subtract(vec![0..30], &[0..5, 25..30]), vec![5..25]);
}

fn entry_at(index: usize) -> usize {
    cmac::TABLE_OFFSET + index * cmac::ENTRY_SIZE
}

#[test]
fn table_descriptors_compare_every_record_and_its_erased_tail() {
    let size = entry_at(cmac::ENTRY_COUNT) + 16;
    let base = vec![0u8; size];
    assert!(descriptors_equal(&base, &base));
    assert!(!descriptors_equal(&base, &base[..size - 1]));
    for index in [0, 1, cmac::ENTRY_COUNT - 1] {
        let at = entry_at(index);
        for off in [0, 4, 11] {
            let mut out = base.clone();
            out[at + off] ^= 1;
            assert!(!descriptors_equal(&base, &out), "entry {index} +{off}");
        }
        let mut tail = base.clone();
        tail[at + 12] ^= 1;
        assert!(
            descriptors_equal(&base, &tail),
            "an in-use record ignores bytes past its 12-byte head"
        );
        let mut erased = base.clone();
        erased[at..at + 4].fill(0xff);
        let mut changed = erased.clone();
        changed[at + cmac::ENTRY_SIZE - 1] ^= 1;
        assert!(descriptors_equal(&erased, &erased));
        assert!(
            !descriptors_equal(&erased, &changed),
            "an erased record is compared whole"
        );
    }
    let last = entry_at(cmac::ENTRY_COUNT - 1);
    let cut = &base[..last + 11];
    assert!(
        !descriptors_equal(cut, cut),
        "a truncated table is not equal"
    );
}

#[test]
fn unplanned_table_changes_are_an_internal_error() {
    let base = vec![0u8; 0x20_0000];
    validate_metadata(&base, &base).unwrap();
    let mut changed = base.clone();
    changed[cmac::TABLE_OFFSET] ^= 1;
    let error = validate_metadata(&base, &changed).unwrap_err();
    assert!(format!("{error:#}").contains("unplanned integrity-table change"));
}
