use super::*;

#[test]
fn live_patched_oem_fixture_when_configured() {
    let Ok(path) = std::env::var("PIONEER_PATCHED_KERNEL_FIXTURE") else {
        return;
    };
    let image = std::fs::read(path).unwrap();
    let matched = recognize(&image).expect("patched OEM kernel recognized");
    assert!(matched.generation_patched);
    assert_eq!(matched.original_marker, 0xff);
    assert_eq!(receiver_generation(&image), Some(false));
}

#[test]
fn receiver_generation_keeps_unknown_distinct() {
    let mut image = vec![0; 0x10000];
    assert_eq!(receiver_generation(&image), Some(false));
    image[0xfe] = 1;
    assert_eq!(receiver_generation(&image), Some(true));
    image[0xfe] = 0x55;
    assert_eq!(receiver_generation(&image), None);
    assert_eq!(receiver_generation(&[]), None);
}

#[test]
fn generation_patch_requires_exact_compensation_and_no_other_changes() {
    use sha2::{Digest, Sha256};
    for marker in [0xff, 0x00] {
        let mut original = vec![0x55; 0x10000];
        original[0xfe] = marker;
        original[0x1020..0x1024].copy_from_slice(&0xffff_ff00u32.to_be_bytes());
        let hash = format!("{:x}", Sha256::digest(&original));
        let entry = KernelEntry {
            revision: "1.00".into(),
            date: "17/02/10".into(),
            key: KeyMaterial::Seed(0),
        };
        let resolve = |h: &str| (h == hash).then_some(&entry);
        let (patched, _) = pioneer_optical::envelope::downgrade_patch(&original).unwrap();
        assert!(
            !recognize_with(&original, resolve)
                .unwrap()
                .generation_patched
        );
        assert!(
            recognize_with(&patched, resolve)
                .unwrap()
                .generation_patched
        );
        assert_eq!(
            recognize_with(&patched, resolve).unwrap().original_marker,
            marker
        );
        let mut bad = patched.clone();
        bad[0x1022] ^= 1;
        assert!(recognize_with(&bad, resolve).is_none());
        let mut bad = patched.clone();
        bad[0x2000] ^= 1;
        assert!(recognize_with(&bad, resolve).is_none());
        assert!(recognize_with(&patched[..0x1023], resolve).is_none());
        assert_eq!(original[0xfe], marker);
    }
}

#[test]
fn embedded_table_parses_and_has_entries() {
    let n = table().len();
    assert!(n > 100, "expected the full OEM kernel table, got {n}");
}

#[test]
fn ud04_kernel_resolves_to_real_oem_label_and_raw_key() {
    // The UD04 kernel is the carried-forward 2017 build: its real label is
    // 1.00 / 17/02/10 (not its Normal's 1.14), and it uses a non-LCG raw key.
    let e = lookup("ba8547d3da87fc32d8d14a8eb2f39fdea9c6c0ac7e6ba91ff3ecd174f8e45e41")
        .expect("UD04 kernel must be in the table");
    assert_eq!(e.revision, "1.00");
    assert_eq!(e.date, "17/02/10");
    match &e.key {
        KeyMaterial::Raw(b) => assert_eq!(b.len(), 0x1000, "UD04 front key is 4 KiB"),
        KeyMaterial::Seed(_) => panic!("UD04 kernel must carry a raw key, not a seed"),
    }
}

#[test]
fn unknown_kernel_is_a_miss() {
    assert!(lookup(&"0".repeat(64)).is_none());
}

#[test]
fn every_row_has_well_formed_key_material() {
    for e in table().values() {
        assert!(!e.revision.is_empty() && !e.date.is_empty());
        if let KeyMaterial::Raw(b) = &e.key {
            assert_eq!(b.len(), 0x1000);
        }
    }
}
