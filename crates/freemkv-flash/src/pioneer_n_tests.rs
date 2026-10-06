use super::*;

#[test]
fn embedded_table_is_populated_and_resolves_a_known_normal() {
    // A truncated/corrupt/empty pioneer_n.bin would silently degrade every
    // normal to the zero sentinel; assert the shipped table actually loads.
    let n = table().len();
    assert!(n > 100, "expected the full OEM normal table, got {n}");
    // The UD04 1.14 OEM normal (decoded-image hash) must resolve to its
    // real seed + a full 0x50 signature.
    let e = lookup("87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1")
        .expect("UD04 1.14 normal must be in the table");
    assert_eq!(e.seed, 0x47D001);
    assert_eq!(e.signature.len(), 0x50);
}

#[test]
fn unknown_normal_is_a_miss() {
    assert!(lookup(&"0".repeat(64)).is_none());
}

#[test]
fn every_row_has_a_full_signature_block() {
    for e in table().values() {
        assert!(!e.revision.is_empty() && !e.date.is_empty());
        assert_eq!(e.signature.len(), 0x50);
    }
}
