use super::*;
use pioneer_optical::drive::settings::{Codec, VendorF4};

/// A Vendor F4 settings block: Quiet active and saved, every other field
/// as the drive leaves it unreported.
fn quiet_settings() -> Settings {
    let mut block = [255u8; 256];
    block[..2].copy_from_slice(&[1, 1]);
    block[2] = 2;
    block[3] = 2;
    VendorF4.decode(&block).expect("a decodable F4 block")
}

#[test]
fn mode_rows_list_every_choice_with_its_marks_for_the_gui_only() {
    let rows = settings_rows(&Ok(quiet_settings()));
    let modes = rows
        .iter()
        .find(|r| r.gui_label.as_deref() == Some("Quiet Drive modes"))
        .expect("a Quiet Drive modes row");
    assert_eq!(modes.cli_label, None, "the CLI never listed modes");
    assert_eq!(
        modes.value.plain(),
        "Standard · Performance · Quiet (active, saved) · Persistent quiet"
    );
    // The CLI rows are the 0.11.x ones.
    let cli: Vec<_> = rows.iter().filter_map(|r| r.cli_line()).collect();
    assert_eq!(
        cli,
        [
            "Quiet Drive: Quiet (active and saved)",
            "PureRead: Not reported"
        ]
    );
}

#[test]
fn optional_settings_errors_are_clean_in_the_report_and_complete_in_diagnostics() {
    use std::sync::{Arc, Mutex};
    let events = Arc::new(Mutex::new(Vec::new()));
    let received = events.clone();
    let rows = crate::output::capture_events(
        move |event| received.lock().unwrap().push(event),
        || {
            crate::diagnostics::run("optional-settings-error-test", || {
                Ok(settings_rows(&Err(anyhow!(
                    "SCSI E4000 cdb=[3c,06,00] offset=0x98000"
                ))))
            })
            .unwrap()
        },
    );
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.value.plain() == "Unavailable"));
    let path = events
        .lock()
        .unwrap()
        .iter()
        .find_map(|event| {
            let crate::output::Event::Report(report) = event else {
                return None;
            };
            report.rows.iter().find_map(|row| match &row.value {
                crate::report::Value::Path(path)
                    if row.gui_label.as_deref() == Some("Diagnostic log") =>
                {
                    Some(path.clone())
                }
                _ => None,
            })
        })
        .expect("saved diagnostic log");
    let diagnostic = std::fs::read_to_string(&path).unwrap();
    assert!(diagnostic.contains("SCSI E4000 cdb=[3c,06,00] offset=0x98000"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn failed_production_parameters_read_is_recorded_in_diagnostics() {
    use std::sync::{Arc, Mutex};
    let events = Arc::new(Mutex::new(Vec::new()));
    let received = events.clone();
    let mut mock = crate::platform::MockScsiDevice::new().on_fail(|_| true, "parameters lost");
    let read = crate::output::capture_events(
        move |event| received.lock().unwrap().push(event),
        || {
            crate::diagnostics::run("production-parameters-error-test", || {
                let mut b = [0; production::PARAMETERS_LEN];
                let mut dev = ReadDevice::without_unlocks(&mut mock);
                Ok(read_parameters(&mut dev, &mut b))
            })
            .unwrap()
        },
    );
    assert_eq!(read, None);
    let path = events
        .lock()
        .unwrap()
        .iter()
        .find_map(|event| {
            let crate::output::Event::Report(report) = event else {
                return None;
            };
            report.rows.iter().find_map(|row| match &row.value {
                crate::report::Value::Path(path)
                    if row.gui_label.as_deref() == Some("Diagnostic log") =>
                {
                    Some(path.clone())
                }
                _ => None,
            })
        })
        .expect("saved diagnostic log");
    let diagnostic = std::fs::read_to_string(&path).unwrap();
    assert!(
        diagnostic.contains("production parameters read failed"),
        "{diagnostic}"
    );
    std::fs::remove_file(path).unwrap();
}
