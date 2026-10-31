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

#[test]
fn populated_nv_record_uses_native_copy_and_requires_reserved_erased_prefix() {
    let mut image = vec![0xff; 0x200000];
    image[0x196000..0x197000].copy_from_slice(include_bytes!(
        "../../tests/fixtures/classic-nv-program-3f436c31.bin"
    ));
    image[0xa7c00..0xa7e00].copy_from_slice(include_bytes!(
        "../../tests/fixtures/classic-nv-copy-helper-3f436c31.bin"
    ));
    image[0x1ea4b0..0x1ea4b3].copy_from_slice(&[1, 4, 4]);
    image[0x1ea4b3] = 0; // A used record need not retain factory padding.
    let core = mt1959::Mt1959Engine;
    assert_eq!(core.find_nv_block(&image).unwrap(), 0x1ea000);
    let mut busy = image.clone();
    busy[0x1ea000] = 0;
    assert!(core.find_nv_block(&busy).is_err());
    image[0x196ca4..0x196ca8].copy_from_slice(&0x1ea4b1u32.to_le_bytes());
    assert!(core.find_nv_block(&image).is_err());
}
