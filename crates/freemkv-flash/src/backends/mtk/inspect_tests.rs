//! Unit tests for [`super`] (MediaTek inspect provider) over the committed
//! stock BU40N N1.02 image and drive reads derived from it.

use std::sync::Arc;

use super::*;
use crate::platform::MockScsiDevice;

fn stock() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/HL-DT-ST_BU40N_N1.02_2017-12-08.bin");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// What the drive returns for `image`: the boot mirror in place of the boot
/// page, and this unit's own data in the drive-written regions.
fn drive_read(image: &[u8], unit: u8) -> Vec<u8> {
    let mut read = image.to_vec();
    let mirror = layout::BOOT_MIRROR.start..layout::BOOT_MIRROR.end();
    read.copy_within(mirror, layout::BOOT_PAGE.start);
    for (i, range) in layout::DRIVE_WRITTEN.iter().enumerate() {
        for k in 0..16 {
            read[range.start + 64 * k + i] = unit.wrapping_add(k as u8);
        }
    }
    read
}

fn inspect(name: &str, bytes: &[u8]) -> Inspection {
    inspect_file(name.into(), bytes, &Control::default())
        .expect("recognized as MediaTek")
        .expect("inspects")
}

fn component(i: &Inspection) -> &ComponentView {
    assert_eq!(i.components.len(), 1);
    &i.components[0]
}

fn field<'a>(fields: &'a [Field], label: &str) -> &'a str {
    fields
        .iter()
        .find(|f| f.label == label)
        .unwrap_or_else(|| panic!("no field {label}"))
        .value
        .as_str()
}

fn region<'a>(i: &'a Inspection, name: &str) -> &'a RegionView {
    component(i)
        .regions
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no region {name}"))
}

/// Region ranges from the inspection's comparison input, by region name.
fn ranges(i: &Inspection) -> Vec<(String, Range<usize>, RegionRole)> {
    i.analyses[0]
        .regions
        .iter()
        .map(|r| {
            let start = r.address.unwrap() as usize;
            (r.name.clone(), start..start + r.size(), r.role)
        })
        .collect()
}

#[test]
fn stored_image_roles_and_identity() {
    let i = inspect("stock.bin", &stock());
    let c = component(&i);
    assert_eq!(field(&c.fields, "Image type"), "Stored image");
    assert_eq!(field(&c.fields, "Chip"), "MT1959");
    assert_eq!(field(&c.fields, "Model"), "BD-RE BU40N");
    assert_eq!(field(&c.fields, "Revision"), "1.02");
    assert!(
        field(&c.fields, "Provenance").starts_with("OEM build "),
        "{}",
        field(&c.fields, "Provenance")
    );
    assert_eq!(field(&c.fields, "Integrity"), "Verified (4 of 4 entries)");
    assert_eq!(region(&i, "Boot page").role, RegionRole::Code);
    assert_eq!(region(&i, "Boot mirror").role, RegionRole::Code);
    assert_eq!(region(&i, "Integrity table").role, RegionRole::Integrity);
    assert_eq!(region(&i, "Boot banner").role, RegionRole::Identity);
    assert_eq!(region(&i, "Identity descriptor").role, RegionRole::Identity);
    for name in [
        "UHD revocation list",
        "BD revocation list",
        "Settings",
        "Calibration",
    ] {
        assert_eq!(region(&i, name).role, RegionRole::PerUnit, "{name}");
        assert_eq!(
            field(&region(&i, name).fields, "Factory contents"),
            "Identical"
        );
    }
    let descriptor = &region(&i, "Identity descriptor").fields;
    assert_eq!(field(descriptor, "Identity tag"), "MTEKMT1959");
    assert_eq!(field(descriptor, "SKU"), "N080100");
    // Every CMAC-covered byte outside the fixed layout is Code.
    let covered = region(&i, "Integrity-covered code 0");
    assert_eq!(covered.role, RegionRole::Code);
    assert_eq!(field(&covered.fields, "Integrity"), "Verified");
    assert_eq!(
        field(&covered.fields, "Stored range"),
        "0x11000..0x1a000 (image offset)"
    );
    assert_eq!(
        region(&i, "Integrity-covered code 1").role,
        RegionRole::Code
    );
    assert_eq!(
        region(&i, "Integrity-covered code 2").role,
        RegionRole::Code
    );
}

#[test]
fn regions_cover_every_byte_once_and_match_the_views() {
    for image in [stock(), drive_read(&stock(), 1)] {
        let i = inspect("x.bin", &image);
        let mut at = 0;
        for (name, range, role) in ranges(&i) {
            assert_eq!(range.start, at, "{name} starts where the previous ends");
            at = range.end;
            assert_ne!(role, RegionRole::Unknown, "{name}");
            assert_eq!(region(&i, &name).role, role, "{name}");
        }
        assert_eq!(at, IMAGE_SIZE);
    }
}

#[test]
fn drive_read_boot_page_is_read_back() {
    let read = drive_read(&stock(), 7);
    let i = inspect("read.bin", &read);
    let c = component(&i);
    assert_eq!(field(&c.fields, "Image type"), "Drive read");
    // The content key ignores the boot page and per-unit data: same build.
    assert_eq!(
        field(&c.fields, "Provenance"),
        field(
            &component(&inspect("stock.bin", &stock())).fields,
            "Provenance"
        )
    );
    assert_eq!(region(&i, "Boot page").role, RegionRole::ReadBack);
    assert!(field(&region(&i, "Boot page").fields, "Form").starts_with("Read back"));
    assert_eq!(
        field(&region(&i, "Calibration").fields, "Factory contents"),
        "16 bytes differ"
    );
    // Everything else keeps its stored-image role.
    assert_eq!(region(&i, "Boot mirror").role, RegionRole::Code);
    assert_eq!(region(&i, "Integrity table").role, RegionRole::Integrity);
    assert_eq!(region(&i, "Settings").role, RegionRole::PerUnit);
}

#[test]
fn unknown_build_has_unknown_provenance() {
    let mut image = stock();
    image[0x11000] ^= 0xff;
    let i = inspect("modified.bin", &image);
    let c = component(&i);
    assert_eq!(
        field(&c.fields, "Provenance"),
        "Unknown build (not in the OEM catalog)"
    );
    assert_eq!(field(&c.fields, "Integrity"), "1 of 4 entries mismatch");
    assert_eq!(c.diagnostics.len(), 1);
}

#[test]
fn integrity_table_lists_every_entry_in_order() {
    let i = inspect("stock.bin", &stock());
    let table = &region(&i, "Integrity table");
    assert_eq!(field(&table.fields, "Active entries"), "4");
    let [t] = table.tables.as_slice() else {
        panic!("one table")
    };
    assert_eq!(t.records.len(), 16);
    let active = [
        (0, "0x11000..=0x19fff"),
        (1, "0x1a000..=0x1b001f"),
        (2, "0x105c0..=0x105cf"),
        (15, "0x10400..=0x105af"),
    ];
    for (n, record) in t.records.iter().enumerate() {
        assert_eq!(record.index, n);
        assert_eq!(record.range, n * 28..n * 28 + 28);
        match active.iter().find(|(i, _)| *i == n) {
            Some((_, covers)) => {
                assert_eq!(field(&record.fields, "Status"), "Active");
                assert_eq!(field(&record.fields, "Covers"), *covers);
                assert_eq!(field(&record.fields, "Check"), "Match");
                assert_eq!(field(&record.fields, "Stored digest").len(), 32);
            }
            None => {
                assert_eq!(field(&record.fields, "Status"), "Unused");
                assert_eq!(record.fields.len(), 1);
            }
        }
    }
    assert_eq!(
        field(&t.records[0].fields, "Stored digest"),
        "f93fda32e5dba3e62520ba61b176b74d"
    );
}

fn compare(a: &[u8], b: &[u8]) -> ComparisonReport {
    compare_inspections(
        Arc::new(inspect("a.bin", a)),
        Arc::new(inspect("b.bin", b)),
        &Control::default(),
    )
    .unwrap()
}

#[test]
fn two_reads_of_one_build_differ_only_as_expected() {
    let image = stock();
    let report = compare(&drive_read(&image, 1), &drive_read(&image, 9));
    assert_eq!(report.unexpected_regions(), 0);
    let section = &report.sections[0];
    let differing: Vec<_> = section.regions.iter().filter(|r| r.differs()).collect();
    assert_eq!(differing.len(), 4, "{differing:?}");
    assert!(differing
        .iter()
        .all(|r| r.expected && r.role == RegionRole::PerUnit));
    let summary = section.summary.join(" ");
    assert!(summary.contains("No unexpected differences."), "{summary}");
    assert!(summary.contains("0.00% different"), "{summary}");
    assert!(summary.contains("Expected differences"), "{summary}");
    let text = report.text();
    assert!(!text.contains("Hardware family"), "{text}");
    assert!(!text.contains("Unknown"), "{text}");
}

#[test]
fn stored_image_against_its_drive_read_differs_only_as_expected() {
    let image = stock();
    let report = compare(&image, &drive_read(&image, 3));
    assert_eq!(report.unexpected_regions(), 0);
    let boot = report.sections[0]
        .regions
        .iter()
        .find(|r| r.name == "Boot page")
        .unwrap();
    assert!(boot.differs() && boot.expected);
}

#[test]
fn a_code_byte_difference_is_unexpected() {
    let image = stock();
    let mut changed = drive_read(&image, 9);
    changed[0x12345] ^= 0x01;
    let report = compare(&drive_read(&image, 1), &changed);
    assert_eq!(report.unexpected_regions(), 1);
    let code = report.sections[0]
        .regions
        .iter()
        .find(|r| r.differs() && !r.expected)
        .unwrap();
    assert_eq!(code.name, "Integrity-covered code 0");
    assert_eq!(code.role, RegionRole::Code);
    let summary = report.sections[0].summary.join(" ");
    assert!(
        summary.contains("Content changes are confined to integrity-covered code 0."),
        "{summary}"
    );
    assert!(!summary.contains("No unexpected differences"), "{summary}");
}

#[test]
fn other_files_are_not_claimed_and_short_images_are_errors() {
    assert!(inspect_file("x".into(), b"not firmware", &Control::default()).is_none());
    assert!(inspect_file("x".into(), &vec![0xff; IMAGE_SIZE], &Control::default()).is_none());
    let short = &stock()[..IMAGE_SIZE - 1];
    let error = inspect_file("x".into(), short, &Control::default())
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("exactly"), "{error}");
}

#[test]
fn live_state_reads_only() {
    let mut mock = MockScsiDevice::mtk();
    let state = live_state(&mut ReadDevice::without_unlocks(&mut mock));
    assert_eq!(field(&state.fields, "Chipset"), "MT1959");
    assert!(mock.writes.is_empty());
    assert!(Mtk.raw_capture());
}

#[test]
fn text_omits_the_family_line_mediatek_does_not_derive() {
    // A chip generation is not a compatibility family, so no family line at
    // all rather than "Unknown" for a recognized image.
    let mut inspection = inspect("stock.bin", &stock());
    assert!(inspection.family.is_none() && !inspection.derives_family);
    let text = inspection.text();
    assert!(text.starts_with("Source: stock.bin\nSHA-256: "), "{text}");
    assert!(!text.contains("Hardware family"), "{text}");
    // A provider that derives families still reports an unknown one.
    inspection.derives_family = true;
    assert!(inspection
        .text()
        .starts_with("Hardware family: Unknown\nSource: stock.bin\n"));
}
