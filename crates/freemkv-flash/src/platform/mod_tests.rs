use super::*;

#[test]
fn no_medium_is_only_not_ready_asc_3a() {
    // The exact sense the BU40N returns to TEST UNIT READY with no disc.
    assert!(is_no_medium(0x2, 0x3A));
    // Other NOT-READY reasons are NOT "no medium" (must still fail the flash).
    assert!(!is_no_medium(0x2, 0x04)); // becoming ready / spinning up
    assert!(!is_no_medium(0x2, 0x00));
    // Wrong key, right ASC — not a no-medium condition.
    assert!(!is_no_medium(0x4, 0x3A)); // hardware error
    assert!(!is_no_medium(0x0, 0x3A));
}

#[test]
fn medium_status_from_sense_maps_tray_open_vs_closed_empty() {
    // Tray open (3A/02) is distinct from closed-empty (3A/00, 3A/01).
    assert_eq!(
        medium_status_from_sense(0x2, 0x3A, 0x02),
        Some(MediumStatus::TrayOpen)
    );
    assert_eq!(
        medium_status_from_sense(0x2, 0x3A, 0x00),
        Some(MediumStatus::ClosedEmpty)
    );
    assert_eq!(
        medium_status_from_sense(0x2, 0x3A, 0x01),
        Some(MediumStatus::ClosedEmpty)
    );
    // Not a no-medium sense => None (caller treats conservatively).
    assert_eq!(medium_status_from_sense(0x2, 0x04, 0x01), None); // spinning up
    assert_eq!(medium_status_from_sense(0x0, 0x3A, 0x02), None); // wrong key
}

#[test]
fn describe_sense_is_human_readable() {
    let s = describe_sense(0x2, 0x3A, 0x01);
    assert!(s.contains("NOT READY"), "{s}");
    assert!(s.contains("medium not present"), "{s}");
    assert!(s.contains("3Ah/01h"), "{s}");
    // A hard error decodes its key name too.
    assert!(describe_sense(0x4, 0x0C, 0x00).contains("HARDWARE ERROR"));
    assert!(describe_sense(0x3, 0x0C, 0x00).contains("write error"));
}
