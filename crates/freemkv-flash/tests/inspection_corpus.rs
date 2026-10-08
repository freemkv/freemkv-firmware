//! Optional local corpus acceptance; firmware is not embedded in this repository.
use freemkv_flash::{
    inspection::{self, Control, Source},
    output,
};

#[test]
#[ignore = "set FREEMKV_INSPECTION_CORPUS to a newline-separated package list"]
fn every_package_inspects_and_compares_identically_to_itself() {
    let list = std::env::var("FREEMKV_INSPECTION_CORPUS").expect("package list path");
    let paths = std::fs::read_to_string(list).expect("read package list");
    let mut count = 0;
    for path in paths.lines().filter(|p| !p.is_empty()) {
        let inspected = output::capture(
            |_| {},
            || inspection::inspect(&Source::File(path.into()), &Control::default()),
        )
        .unwrap_or_else(|error| panic!("{path}: {error:#}"));
        let report =
            inspection::compare_inspections(inspected.clone(), inspected, &Control::default())
                .unwrap_or_else(|error| panic!("{path}: {error:#}"));
        for section in report.sections {
            for region in section.regions {
                assert_eq!(region.left_changed, 0, "{path}: {}", region.name);
                assert_eq!(region.right_changed, 0, "{path}: {}", region.name);
                assert!(!region.unresolved, "{path}: {}", region.name);
                assert_eq!(region.table_changes, 0, "{path}: {}", region.name);
            }
        }
        count += 1;
    }
    assert!(count > 0, "empty corpus");
}
