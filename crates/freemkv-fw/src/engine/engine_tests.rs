use super::*;

#[test]
fn for_family_selects_or_refuses() {
    // MT1959 resolves to its engine.
    let e = for_family(ChipFamily::Mt1959).expect("mt1959 engine");
    assert_eq!(e.name(), "MT1959");
    // MT1939 has no engine yet — a clean refusal, not a wrong-address guess.
    assert!(for_family(ChipFamily::Mt1939).is_err());
}

#[test]
fn create_refuses_a_non_image() {
    // A buffer that isn't a real MT1959 image has no scanner signature, so the
    // grounded find fails loudly rather than emitting a wrong patch.
    let junk = vec![0u8; 0x20_0000];
    assert!(mt1959::Mt1959Engine.create(&junk).is_err());
}
