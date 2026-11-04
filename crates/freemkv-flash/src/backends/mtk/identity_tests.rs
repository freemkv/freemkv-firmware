//! The post-flash identity row carries sanitized drive text.
use super::*;

#[test]
fn running_identity_is_published_as_sanitized_text() {
    let mut inquiry = [b' '; 96];
    inquiry[8..36].copy_from_slice(b"\x1b[31mHL-DT-ST BD-RE BU40N 1.");
    let rows = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = rows.clone();
    let identity = crate::output::capture_events(
        move |event| {
            if let crate::output::Event::Report(report) = event {
                seen.borrow_mut().extend(report.rows);
            }
        },
        || publish_running_identity(&inquiry),
    );
    assert!(!identity.chars().any(char::is_control), "{identity:?}");
    let rows = rows.borrow();
    let row = rows
        .iter()
        .find(|row| row.gui_label.as_deref() == Some("Firmware running"))
        .unwrap();
    assert!(matches!(row.value, crate::report::Value::Text(_)));
}
