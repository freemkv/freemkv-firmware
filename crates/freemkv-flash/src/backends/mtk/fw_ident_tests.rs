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

/// Fingerprints of downgrade-enabled copies (a `0xDE` byte in the identity
/// descriptor) once labelled OEM: the OEM builds carry another fingerprint.
const DE_PATCHED: [&str; 7] = [
    "b9adb37a560d",
    "d88e939f89a7",
    "3e05d733d374",
    "41baece3ed42",
    "d3c8e06ff841",
    "e02261a17737",
    "f479cf997d05",
];

#[test]
fn downgrade_enabled_copies_are_not_labelled_oem() {
    for prefix in DE_PATCHED {
        let entry = CATALOG.iter().find(|e| e.fp.starts_with(prefix)).unwrap();
        assert!(entry.desc.ends_with("(DE-patched)"), "{}", entry.desc);
    }
}

#[test]
fn catalog_builds_carry_their_image_digest() {
    let recorded: Vec<&FwEntry> = CATALOG
        .iter()
        .filter(|e| !e.image_sha256.is_empty())
        .collect();
    assert_eq!(recorded.len(), 42);
    for (i, a) in recorded.iter().enumerate() {
        assert!(a.desc.ends_with("(OEM)"), "{}", a.desc);
        assert_eq!(a.image_sha256.len(), 64, "{}", a.desc);
        assert!(recorded[i + 1..]
            .iter()
            .all(|b| b.image_sha256 != a.image_sha256));
    }
}

/// Every MT1939 OEM build in a corpus (`FREEMKV_MTK_IMAGES`) that the embedded
/// catalog holds is identified by its fingerprint after a flash.
#[test]
#[ignore = "needs FREEMKV_MTK_IMAGES pointing at OEM MT1959/MT1939 images"]
fn corpus_mt1939_catalog_builds_are_identified() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    walk(
        std::path::Path::new(&std::env::var("FREEMKV_MTK_IMAGES").unwrap()),
        &mut paths,
    );
    let catalog = super::super::oem::catalog();
    let mut identified = 0;
    for path in paths {
        let image = std::fs::read(&path).unwrap();
        let Some(key) = mediatek_optical::oem::content_key(&image) else {
            continue;
        };
        let Some(build) = catalog.build(&key) else {
            continue;
        };
        if mediatek_optical::image::detect_chip(&image).map(|c| c.family.label()) != Ok("MT1939") {
            continue;
        }
        let r = report(&image[0x3000..0x3020], &image[0x1E_C000..0x1E_C100]);
        let entry = r.matched.unwrap_or_else(|| panic!("{}", path.display()));
        let model = build
            .model
            .split_whitespace()
            .find(|w| w.len() >= 4 && !w.starts_with("BD"))
            .unwrap();
        assert!(entry.desc.contains(model), "{} vs {model}", entry.desc);
        // LG's "original flasher" packages carry an `INTM` descriptor revision
        // and are named for their release.
        assert!(
            build.revision == "INTM" || entry.desc.contains(&build.revision),
            "{}",
            entry.desc
        );
        identified += 1;
    }
    assert!(identified >= 58, "{identified}");
}
