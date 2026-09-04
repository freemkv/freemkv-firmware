use super::*;

#[test]
fn for_family_selects_engines() {
    // MT1959 resolves to its full engine.
    let e = for_family(ChipFamily::Mt1959).expect("mt1959 engine");
    assert_eq!(e.name(), "MT1959");
    // MT1939 now resolves to its (partial) engine — DE-only today. `create` (the
    // strict full build) still refuses, but the engine exists so `modify` can
    // apply the family-agnostic downgrade byte rather than opaquely refusing.
    let m = for_family(ChipFamily::Mt1939).expect("mt1939 engine");
    assert_eq!(m.name(), "MT1939");
    assert!(
        m.create(&[0u8; 0x20_0000]).is_err(),
        "MT1939 full create is pending"
    );
}

#[test]
fn create_refuses_a_non_image() {
    // A buffer that isn't a real MT1959 image has no scanner signature, so the
    // grounded find fails loudly rather than emitting a wrong patch.
    let junk = vec![0u8; 0x20_0000];
    assert!(mt1959::Mt1959Engine.create(&junk).is_err());
}
