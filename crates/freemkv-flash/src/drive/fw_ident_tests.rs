use super::*;

#[test]
fn fingerprint_is_deterministic_sha256() {
    // sha256("") over two empty regions == the empty-input digest.
    assert_eq!(
        fingerprint(&[], &[]),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // Both regions contribute and their content order matters.
    assert_ne!(fingerprint(b"a", b"b"), fingerprint(b"b", b"a"));
    // It is a hash of the concatenation, so the split point is irrelevant —
    // harmless here because the two regions are always fixed lengths.
    assert_eq!(fingerprint(b"ab", b""), fingerprint(b"a", b"b"));
}

#[test]
fn identify_matches_and_misses() {
    let cat = [
        FwEntry {
            fp: "aa",
            desc: "X 1.0 (MK)",
            image_sha256: "",
            source: "",
        },
        FwEntry {
            fp: "bb",
            desc: "Y 2.0 (OEM)",
            image_sha256: "",
            source: "",
        },
    ];
    assert_eq!(identify_in("bb", &cat).map(|e| e.desc), Some("Y 2.0 (OEM)"));
    assert!(identify_in("cc", &cat).is_none());
}

#[test]
fn catalog_has_no_duplicate_fingerprints() {
    for (i, a) in CATALOG.iter().enumerate() {
        for b in &CATALOG[i + 1..] {
            assert_ne!(a.fp, b.fp, "duplicate fingerprint: {} / {}", a.desc, b.desc);
        }
        assert_eq!(a.fp.len(), 64, "not a sha256 hex: {}", a.desc);
    }
}

#[test]
fn descriptor_extracts_ascii_prefix() {
    let mut region = b"HL-DT-ST BD-RE BU40N 1.03  MT1959".to_vec();
    region.push(0x00); // binary tail is ignored
    region.extend_from_slice(&[0xDE, 0xAD]);
    let d = descriptor(&region).unwrap();
    assert!(d.starts_with("HL-DT-ST BD-RE BU40N 1.03"));
    assert!(d.contains("MT1959"));
    // Non-descriptor / empty input yields None.
    assert!(descriptor(&[0x00, 0x01, 0x02]).is_none());
}
