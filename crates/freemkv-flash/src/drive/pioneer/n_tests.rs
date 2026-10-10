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

#[test]
fn xd06u_111_normal_keeps_its_oem_encoding_metadata() {
    let e = lookup("7c1175169d33c37e296103569ba5ead98b492bd9d668e850a99cf1a44ed82679")
        .expect("held XD06U 1.11 Normal must not fall back to a zero seed/signature");
    assert_eq!(e.seed, 0x47d001);
    assert_eq!(e.revision, "1.11");
    assert_eq!(e.date, "17/06/22");
    assert_eq!(e.signature, hex_decode("968ff684aa7b7af7ef94b7dde4b4dbe4de64c961271bd2951daf9b7fdc695adbe3e7abaacdb7f3785d98ef7b0ba8c2cb0c55aa0c9b90533f2d7444b97c94ed9827787dc11aba2c5b82b0480ad3c380f0").unwrap());
}
