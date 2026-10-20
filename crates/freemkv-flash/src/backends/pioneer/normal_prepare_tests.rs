//! Reproduce with PIONEER_AUTH_CAPTURE_MANIFEST pointing to a three-column TSV:
//! case, Current TAR path, Normal-only TAR path. Resolve the exact package hashes
//! listed in tests/golden/pioneer_signing_subset.tsv from the held corpus (the
//! same package hashes are pinned in pioneer_corpus_subset.tsv). Set
//! PIONEER_AUTH_EXPECT_STABLE=1 to require byte-for-byte prepared equality.
//! No firmware files are committed and no drive is opened.

use super::*;
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires held pinned Current/Normal-only manifest; no hardware"]
fn held_signing_is_valid_and_changes_only_recorded_authentication_bytes() {
    let manifest =
        std::fs::read_to_string(std::env::var_os("PIONEER_AUTH_CAPTURE_MANIFEST").unwrap())
            .unwrap();
    let expected: Vec<Vec<&str>> = include_str!("../../../tests/golden/pioneer_signing_subset.tsv")
        .lines()
        .map(|line| line.split('\t').collect())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut cases = 0;
    for row in manifest.lines() {
        let columns: Vec<_> = row.split('\t').collect();
        assert_eq!(columns.len(), 3);
        let pins = expected
            .iter()
            .find(|pin| pin[0] == columns[0])
            .expect("case must have committed input hashes");
        assert!(seen.insert(columns[0]), "duplicate case");
        let read = |path: &str, expected_hash: &str| {
            let bytes = std::fs::read(path).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected_hash);
            bytes
        };
        let current = read(columns[1], pins[1]);
        let target = read(columns[2], pins[2]);
        let (kernel, _) = super::super::classify_flash_input(&current).unwrap();
        let (_, normal) = super::super::classify_flash_input(&target).unwrap();
        let receiver = Envelope::load(&kernel.unwrap()).unwrap();
        let normal = normal.unwrap();
        let source = Envelope::load_with_kernel(&normal, &receiver).unwrap();
        let first = prepare(&receiver, &source, &normal).unwrap();
        let second = prepare(&receiver, &source, &normal).unwrap();
        assert!(normal_authentication_valid(&first, &receiver.image));
        assert!(normal_authentication_valid(&second, &receiver.image));
        assert_eq!(first.len(), second.len());
        assert_eq!(&first[..0x170], &second[..0x170]);
        assert_eq!(&first[0x1c0..], &second[0x1c0..]);
        assert_eq!(
            Envelope::load_with_kernel(&first, &receiver).unwrap().image,
            source.image
        );
        assert_eq!(
            Envelope::load_with_kernel(&second, &receiver)
                .unwrap()
                .image,
            source.image
        );
        let policy = format!(
            "{:?}",
            normal_authentication_from_kernel(&receiver.image).unwrap()
        );
        let mut hash = Sha256::new();
        hash.update(policy.as_bytes());
        hash.update(&first[..0x170]);
        hash.update(&first[0x1c0..]);
        let signature: String = first[0x170..0x1c0]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let chunk_hashes = first
            .chunks(0x8000)
            .map(|chunk| format!("{:x}", Sha256::digest(chunk)))
            .collect::<Vec<_>>()
            .join("\n");
        let writes_digest = format!("{:x}", Sha256::digest(chunk_hashes.as_bytes()));
        let auth_changed = first[0x170..0x1c0] != second[0x170..0x1c0];
        if std::env::var_os("PIONEER_AUTH_EXPECT_STABLE").is_some() {
            assert_eq!(first, second, "{} full transfer must be stable", columns[0]);
        }
        eprintln!(
            "AUTH_FIXTURE {}",
            serde_json::json!({"case": columns[0], "policy": policy, "hash": format!("{:x}", hash.finalize()), "signature": signature, "writes_digest": writes_digest, "auth_changed": auth_changed})
        );
        cases += 1;
    }
    assert_eq!(cases, expected.len(), "all committed cases must be covered");
    eprintln!("Proved {cases} held transfers: fresh authentication valid; every non-auth byte and decoded body identical");
}
