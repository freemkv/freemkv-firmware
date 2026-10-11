use super::*;

#[test]
fn embedded_table_is_populated() {
    let n = table().len();
    assert!(n > 800, "expected the full controller-id table, got {n}");
}

#[test]
fn ud04_controller_resolves_to_oem_descriptor_and_general_key() {
    let e = lookup(0x8A10).expect("0x8A10 must be in the table");
    assert_eq!(&e.descriptor, b"PIONEER BDR-US04");
    assert_eq!(e.key_for_tag(DEFAULT_TAG), Some(0xFD23_6642));
    // The autoflasher fallback (unmatched OEM tag) for this controller.
    assert_eq!(e.fallback, 0x6123_789A);
}

#[test]
fn control_payload_has_descriptor_then_le_key_then_zero_tail() {
    let e = lookup(0x8A10).unwrap();
    let payload = e.control_payload(e.key_for_tag(DEFAULT_TAG).unwrap());
    assert_eq!(&payload[..16], b"PIONEER BDR-US04");
    assert_eq!(&payload[16..20], &[0x42, 0x66, 0x23, 0xFD]);
    assert!(payload[20..].iter().all(|&b| b == 0));
}

#[test]
fn sat_tag_and_bare_hex_both_resolve_the_controller_id() {
    assert_eq!(controller_id_from_sat("SAT 8A10"), Some(0x8A10));
    assert_eq!(controller_id_from_sat("8A10"), Some(0x8A10));
    assert_eq!(controller_id_from_sat("SAT 8600"), Some(0x8600));
    assert_eq!(controller_id_from_sat("nonsense"), None);
}

#[test]
fn unknown_controller_is_a_miss() {
    assert!(lookup(0xFFFF).is_none());
}

#[test]
fn s09_controller_carries_the_id43_rebadge_key() {
    // S09 (SAT 8600) uses its ID43 destination tag, not GENERAL.
    let e = lookup(0x8600).expect("0x8600 must be in the table");
    assert_eq!(&e.descriptor, b"PIONEER  BDR-209");
    assert_eq!(e.key_for_tag("ID43"), Some(0xCE1F_2B98));
}
