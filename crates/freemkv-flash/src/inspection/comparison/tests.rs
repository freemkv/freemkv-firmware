use super::engine::{Accounting, Change, RegionComparison};
use super::*;
use sha2::{Digest, Sha256};

fn analysis(bytes: &[u8]) -> FirmwareAnalysis {
    FirmwareAnalysis {
        identity: Identity {
            component: "Test component".into(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            family: None,
            family_scheme: "test".into(),
        },
        complete: true,
        regions: vec![Region {
            id: 0,
            name: "Data".into(),
            address: None,
            metadata: Vec::new(),
            representation: Representation::Decoded,
            pairing_key: "data".into(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            tables: Vec::new(),
            references: Vec::new(),
            bytes: bytes.to_vec(),
        }],
    }
}
fn accounted(c: &RegionComparison) {
    assert_eq!(
        c.equal_bytes + c.changes.iter().map(|c| c.left.len()).sum::<usize>(),
        c.left_size
    );
    assert_eq!(
        c.equal_bytes + c.changes.iter().map(|c| c.right.len()).sum::<usize>(),
        c.right_size
    );
}
#[test]
fn identical_and_inserted_content_conserve_both_sides() {
    let a: Vec<_> = (0..8192)
        .map(|i| ((i * 17 + i / 251) % 256) as u8)
        .collect();
    let mut b = a.clone();
    b.splice(1024..1024, [1, 2, 3, 4, 5]);
    let aa = analysis(&a);
    let bb = analysis(&b);
    let same = aa
        .compare(&aa, Options::default(), &Control::default())
        .unwrap();
    assert!(same.identical_decoded);
    for c in &same.regions {
        accounted(c);
    }
    let diff = aa
        .compare(&bb, Options::default(), &Control::default())
        .unwrap();
    assert!(!diff.identical_decoded);
    for c in &diff.regions {
        accounted(c);
    }
    let reverse = bb
        .compare(&aa, Options::default(), &Control::default())
        .unwrap();
    for c in &reverse.regions {
        accounted(c);
    }
}
#[test]
fn constants_and_address_like_values_are_never_blindly_masked() {
    let a = [0x5e, 0x40, 0, 0x10, 0x7a, 0, 0, 0, 0x20, 0];
    let b = [0x5e, 0x40, 0, 0x20, 0x7a, 0, 0, 0, 0x10, 0];
    let diff = analysis(&a)
        .compare(&analysis(&b), Options::default(), &Control::default())
        .unwrap();
    assert!(!diff.regions[0].changes.is_empty());
    accounted(&diff.regions[0]);
}
#[test]
fn budgets_report_unresolved_without_losing_bytes() {
    let a = [0xa5; 1024];
    let b = [0x5a; 2048];
    let options = Options {
        work: 0,
        findings: 1,
    };
    let result = analysis(&a)
        .compare(&analysis(&b), options, &Control::default())
        .unwrap();
    assert!(!result.complete);
    assert_eq!(result.regions[0].changes[0].kind, ChangeKind::Unresolved);
    accounted(&result.regions[0]);
}
#[test]
fn different_families_are_comparable_and_unknown_is_not_same() {
    let mut a = analysis(b"abcd");
    let mut b = analysis(b"abce");
    assert_eq!(
        a.compare(&b, Options::default(), &Control::default())
            .unwrap()
            .same_family,
        None
    );
    a.identity.family = Some("a".into());
    b.identity.family = Some("b".into());
    assert_eq!(
        a.compare(&b, Options::default(), &Control::default())
            .unwrap()
            .same_family,
        Some(false)
    );
}
#[test]
fn direct_call_relocation_requires_matching_target() {
    let mut a = [0x0c, 0x88].repeat(256);
    a[260..264].copy_from_slice(&[0x5e, 0x40, 0x01, 0x80]);
    for (i, b) in a[384..].iter_mut().enumerate() {
        *b = (i * 13 + i / 11) as u8;
    }
    let mut b = a.clone();
    b.splice(384..384, [0x12, 0x34]);
    b[263] = 0x82;
    let mut left = analysis(&a);
    let mut right = analysis(&b);
    left.identity.component = "Test component".into();
    right.identity.component = "Test component".into();
    left.regions[0].address = Some(0x400000);
    left.regions[0].references.push(Reference {
        instruction: 260..264,
        operand: 261..264,
        target: 0x400180,
    });
    right.regions[0].address = Some(0x400000);
    right.regions[0].references.push(Reference {
        instruction: 260..264,
        operand: 261..264,
        target: 0x400182,
    });
    let result = left
        .compare(&right, Options::default(), &Control::default())
        .unwrap();
    assert!(
        result.regions[0]
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::RelocatedReference),
        "{:?}",
        result.regions[0].changes
    );
    accounted(&result.regions[0]);
    b[263] = 0x84;
    let mut wrong = analysis(&b);
    wrong.identity.component = "Test component".into();
    wrong.regions[0].address = Some(0x400000);
    wrong.regions[0].references.push(Reference {
        instruction: 260..264,
        operand: 261..264,
        target: 0x400184,
    });
    assert!(!left
        .compare(&wrong, Options::default(), &Control::default())
        .unwrap()
        .regions[0]
        .changes
        .iter()
        .any(|c| c.kind == ChangeKind::RelocatedReference));
}

#[test]
fn table_comparison_preserves_order_duplicates_and_additions() {
    fn table(values: &[&str]) -> super::Table {
        super::Table {
            format: "test.text".into(),
            record_width: 8,
            records: values.iter().map(|v| (*v).into()).collect(),
        }
    }
    let a = table(&["AAA", "BBB", "AAA", "CCC"]);
    let b = table(&["BBB", "AAA", "AAA", "CCC", "DDD"]);
    let result = super::tables::compare(std::slice::from_ref(&a), std::slice::from_ref(&b));
    assert_eq!(result[0].unchanged_records, 2);
    assert_eq!(result[0].changes.len(), 3);
    assert_eq!(result[0].changes[2].left, None);
    assert_eq!(result[0].changes[2].right.as_deref(), Some("DDD"));
    let reverse = super::tables::compare(&[b], &[a]);
    assert_eq!(reverse[0].changes[2].left.as_deref(), Some("DDD"));
    assert_eq!(reverse[0].changes[2].right, None);
}

#[test]
fn percentages_exclude_metadata_relocations_and_unresolved_work() {
    let region = RegionComparison {
        left: Some(0),
        right: Some(0),
        left_size: 100,
        right_size: 120,
        equal_bytes: 70,
        tables: Vec::new(),
        changes: vec![
            Change {
                kind: ChangeKind::DataChanged,
                left: 70..80,
                right: 70..80,
                targets: None,
            },
            Change {
                kind: ChangeKind::Metadata,
                left: 80..85,
                right: 80..85,
                targets: None,
            },
            Change {
                kind: ChangeKind::RelocatedReference,
                left: 85..90,
                right: 85..90,
                targets: Some((1, 2)),
            },
            Change {
                kind: ChangeKind::Unresolved,
                left: 90..100,
                right: 90..100,
                targets: None,
            },
            Change {
                kind: ChangeKind::Added,
                left: 100..100,
                right: 100..120,
                targets: None,
            },
        ],
    };
    accounted(&region);
    let counts = region.accounting();
    assert_eq!(counts.total, 220);
    assert_eq!(counts.changed, 40);
    assert_eq!(counts.unresolved, 20);
    assert!((counts.difference_percent().unwrap() - 100.0 * 40.0 / 220.0).abs() < 1e-10);
    assert_eq!(Accounting::default().difference_percent(), None);
}

#[test]
fn cancellation_is_not_an_empty_success() {
    let control = Control::default();
    control.cancel();
    let error = analysis(b"a")
        .compare(&analysis(b"b"), Options::default(), &control)
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<super::super::InspectionError>(),
        Some(super::super::InspectionError::Cancelled)
    ));
}

#[test]
fn reversing_inputs_preserves_all_counts_and_mirrors_findings() {
    let mut a: Vec<u8> = (0..8192).map(|i| ((i * 19 + i / 31) % 256) as u8).collect();
    let mut b = a.clone();
    b.splice(713..715, [0, 1, 2, 3, 4, 5, 6]);
    b[4000..4020].fill(0xff);
    a[6500..6510].fill(0x11);
    let (left, right) = (analysis(&a), analysis(&b));
    let ab = left
        .compare(&right, Options::default(), &Control::default())
        .unwrap();
    let ba = right
        .compare(&left, Options::default(), &Control::default())
        .unwrap();
    for (a, b) in ab.regions.iter().zip(&ba.regions) {
        accounted(a);
        accounted(b);
        assert_eq!(a.accounting().changed, b.accounting().changed);
        assert_eq!(a.equal_bytes, b.equal_bytes);
        for (x, y) in a.changes.iter().zip(&b.changes) {
            assert_eq!(x.left, y.right);
            assert_eq!(x.right, y.left);
        }
    }
}

#[test]
fn local_alignment_recovers_short_shifted_runs_between_long_anchors() {
    let mut a: Vec<u8> = (0..1200).map(|i| ((i * 37 + i / 17) % 256) as u8).collect();
    // Changes every 12 bytes defeat the sampled global 16-byte anchors.
    let mut b = a.clone();
    for i in (200..800).step_by(12) {
        b[i] ^= 0x55;
    }
    b.splice(211..211, [0xfe, 0xfa]);
    a[900] ^= 0x33;
    let ab = analysis(&a)
        .compare(&analysis(&b), Options::default(), &Control::default())
        .unwrap();
    accounted(&ab.regions[0]);
    assert!(
        ab.regions[0].equal_bytes > 1100,
        "matched {}",
        ab.regions[0].equal_bytes
    );
}

#[test]
fn isolated_target_bytes_are_not_relocation_evidence() {
    let mut a = analysis(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    let mut b = analysis(&[1, 3, 3, 4, 5, 6, 7, 8, 9, 99, 98, 97]);
    a.regions[0].address = Some(0x1000);
    b.regions[0].address = Some(0x2000);
    a.regions[0].references.push(Reference {
        instruction: 0..2,
        operand: 1..2,
        target: 0x1008,
    });
    b.regions[0].references.push(Reference {
        instruction: 0..2,
        operand: 1..2,
        target: 0x2008,
    });
    let result = a
        .compare(&b, Options::default(), &Control::default())
        .unwrap();
    assert!(!result.regions[0]
        .changes
        .iter()
        .any(|c| c.kind == ChangeKind::RelocatedReference));
    accounted(&result.regions[0]);
}
