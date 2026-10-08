use super::*;
use crate::platform::MockScsiDevice;

fn package(revision: &str, change: bool) -> Vec<u8> {
    use pioneer_optical::{
        envelope::{build_header, HeaderInfo, HeaderOpaque},
        ComponentKind,
    };
    let header = build_header(
        &HeaderInfo {
            id: "PIONEER TEST".into(),
            model: "TEST".into(),
            revision: revision.into(),
            hardware_version: "SAT TEST".into(),
            kernel_version: "ID01".into(),
            destination: "ID01".into(),
            generated_date: "26/10/08".into(),
            kernel_version2: "0000".into(),
            kind: Some(ComponentKind::Normal),
        },
        &HeaderOpaque {
            id_left_padding: 0,
            prevalidation: [0; 16],
            validation: [0; 80],
            extension: [0; 48],
            filename: [0; 16],
        },
    )
    .unwrap();
    let mut bytes = vec![0xff; 0x10100];
    bytes[..header.len()].copy_from_slice(&header);
    bytes[0x10000..0x10008].copy_from_slice(b"TESTDATA");
    if change {
        bytes[0x10080] = 0x11;
    }
    let checksum = bytes[0x10000..]
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |sum, w| sum.wrapping_sub(u32::from_le_bytes(*w)));
    bytes[0x8000..0x8004].copy_from_slice(&checksum.to_le_bytes());
    let mut builder = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "normal.enc", bytes.as_slice())
        .unwrap();
    builder.into_inner().unwrap()
}
#[test]
fn inspection_and_compare_share_decoded_content_and_ignore_envelope_headers() {
    let a = Arc::new(
        pioneer::inspect_file("a.tar".into(), &package("1.00", false), &Control::default())
            .unwrap(),
    );
    let b = Arc::new(
        pioneer::inspect_file("b.tar".into(), &package("2.00", false), &Control::default())
            .unwrap(),
    );
    let result = compare_inspections(a.clone(), b, &Control::default()).unwrap();
    assert_eq!(result.family, FamilyRelationship::Unknown);
    assert!(result
        .sections
        .iter()
        .find(|s| s.name == "Normal")
        .unwrap()
        .fields
        .iter()
        .any(|f| f.label == "Decoded content" && f.value == "Identical"));
    assert!(a.live.is_none());
    assert!(a.text().starts_with("Hardware family:"));
    let retained = inspect(&Source::Analyzed(a.clone()), &Control::default()).unwrap();
    assert!(Arc::ptr_eq(&a, &retained));
    assert!(!a.json().unwrap().contains("analyses"));
    let c = Arc::new(
        pioneer::inspect_file("c.tar".into(), &package("1.00", true), &Control::default()).unwrap(),
    );
    assert!(compare_inspections(a, c, &Control::default())
        .unwrap()
        .sections
        .iter()
        .find(|s| s.name == "Normal")
        .unwrap()
        .fields
        .iter()
        .any(|f| f.label == "Decoded content" && f.value == "Different"));
}
#[test]
fn rpc_reads_state_without_any_write_and_failure_is_optional() {
    let mut dev = MockScsiDevice::new().on(
        |c| c == pioneer_optical::rpc::report_key(),
        vec![0, 6, 0, 0, 0x64, 0xfd, 1, 0],
    );
    let state = pioneer::live_state(&mut dev);
    assert!(state
        .fields
        .iter()
        .any(|f| f.label == "DVD region" && f.value == "2"));
    assert!(state
        .fields
        .iter()
        .any(|f| f.label == "Vendor region resets remaining" && f.value == "4"));
    assert!(dev.writes.is_empty());
    assert_eq!(dev.reads.len(), 1);
    let mut dev = MockScsiDevice::new().on_fail(|_| true, "unsupported");
    let state = pioneer::live_state(&mut dev);
    assert_eq!(state.diagnostics.len(), 1);
    assert!(state.fields.is_empty());
    assert!(dev.writes.is_empty());
}
#[test]
fn unsupported_and_corrupt_inputs_have_different_errors() {
    let error =
        pioneer::inspect_file("unknown.bin".into(), b"unknown", &Control::default()).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<InspectionError>(),
        Some(InspectionError::UnrecognizedFormat)
    ));
    let mut broken = package("1.00", false);
    broken[0] = 0;
    let error = pioneer::inspect_file("bad.tar".into(), &broken, &Control::default()).unwrap_err();
    assert!(error.downcast_ref::<InspectionError>().is_none());
}
#[test]
fn cancellation_and_two_drives_stop_before_io() {
    let control = Control::default();
    control.cancel();
    let error = inspect(&Source::File("does-not-exist".into()), &control).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<InspectionError>(),
        Some(InspectionError::Cancelled)
    ));
    let source = Source::Drive {
        device: "not-a-drive".into(),
        capture: "not-a-file".into(),
    };
    assert!(matches!(
        compare(&source, &source, &Control::default())
            .unwrap_err()
            .downcast_ref::<InspectionError>(),
        Some(InspectionError::TwoDrives)
    ));
}

#[test]
fn comparison_summary_is_readable_and_details_remain_in_json() {
    let a = Arc::new(
        pioneer::inspect_file("a.tar".into(), &package("1.00", false), &Control::default())
            .unwrap(),
    );
    let b = Arc::new(
        pioneer::inspect_file("b.tar".into(), &package("2.00", true), &Control::default()).unwrap(),
    );
    let result = compare_inspections(a.clone(), b, &Control::default()).unwrap();
    let text = result.text();
    assert!(text.starts_with("Hardware family:"));
    assert!(text.contains("Content changes are confined to main firmware."));
    assert!(!text.contains("DataChanged"));
    assert!(!text.contains("region-relative"));
    let json: serde_json::Value = serde_json::from_str(&result.json().unwrap()).unwrap();
    assert_eq!(json["left"]["sha256"], a.sha256);
    assert!(
        json["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "Normal")
            .unwrap()["details"]
            .as_array()
            .unwrap()
            .len()
            > 1
    );
    assert!(json["left"].get("analyses").is_none());
}

#[test]
fn partial_summary_never_claims_only_relocation_changes() {
    let regions = vec![RegionSummary {
        name: "Main firmware".into(),
        left_changed: 0,
        right_changed: 0,
        unresolved: true,
        total_bytes: 200,
        unresolved_bytes: 200,
        difference_percent: Some(0.0),
        table_changes: 0,
        table_records: 0,
    }];
    let summary = compare_report::summarize(&regions, false, false).join(" ");
    assert!(summary.contains("partial"));
    assert!(!summary.contains("Only packaging"));
    assert!(!summary.contains("no content changes"));
}

#[test]
fn absent_kernel_is_visible_in_inspection_and_comparison() {
    let a = Arc::new(
        pioneer::inspect_file(
            "normal-only.tar".into(),
            &package("1.00", false),
            &Control::default(),
        )
        .unwrap(),
    );
    assert_eq!(a.missing_components, ["Kernel"]);
    assert!(a.text().contains("Kernel: Not included"));
    let result = compare_inspections(a.clone(), a, &Control::default()).unwrap();
    let kernel = result.sections.iter().find(|s| s.name == "Kernel").unwrap();
    assert!(kernel
        .summary
        .iter()
        .any(|s| s.contains("Source A") && s.contains("not included")));
    assert!(kernel
        .summary
        .iter()
        .any(|s| s.contains("Source B") && s.contains("not included")));
    assert!(kernel.regions.is_empty());
}
