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

fn scsi_err(status: u8, sense: Option<(u8, u8, u8)>) -> libfreemkv::error::Error {
    libfreemkv::error::Error::ScsiError {
        opcode: 0x3b,
        status,
        sense: sense.map(|(sense_key, asc, ascq)| libfreemkv::scsi::ScsiSense {
            sense_key,
            asc,
            ascq,
        }),
    }
}

#[test]
fn scsi_error_transport_wedge_is_no_reply() {
    let s = describe_scsi_error(&scsi_err(0xff, None));
    assert!(
        s.starts_with("no reply from the drive (transport/link failure)"),
        "{s}"
    );
    assert!(s.contains("/0xff"), "raw code kept: {s}");
}

#[test]
fn scsi_error_check_condition_with_sense_is_decoded() {
    let s = describe_scsi_error(&scsi_err(0x02, Some((0x5, 0x24, 0x00))));
    assert!(
        s.starts_with("CHECK CONDITION (0x02): ILLEGAL REQUEST"),
        "{s}"
    );
    assert!(s.contains("24h/00h"), "{s}");
    assert!(s.contains("0x3b/0x02/0x05/0x24/0x00"), "raw code kept: {s}");
    assert!(!s.contains("transport"), "{s}");
}

#[test]
fn scsi_error_check_condition_no_sense_is_a_rejection() {
    let s = describe_scsi_error(&scsi_err(0x02, Some((0, 0, 0))));
    assert!(
        s.starts_with("CHECK CONDITION (0x02): sense details unavailable or invalid"),
        "{s}"
    );
    assert!(s.contains("0x3b/0x02/0x00/0x00/0x00"), "raw code kept: {s}");
    assert!(!s.contains("transport"), "{s}");
}

#[test]
fn opening_a_missing_drive_never_blames_a_missing_firmware_file() {
    use crate::user_error::UserError;
    for (kind, expected) in [
        (std::io::ErrorKind::NotFound, "errors.connection"),
        (std::io::ErrorKind::PermissionDenied, "errors.drive_access"),
    ] {
        let error = super::open_error(std::io::Error::from(kind).into());
        assert_eq!(UserError::of(&error).id, expected);
    }
}

#[test]
fn sense_key_and_status_names_cover_every_documented_code() {
    let keys = [
        (0x0, "NO SENSE"),
        (0x1, "RECOVERED ERROR"),
        (0x2, "NOT READY"),
        (0x3, "MEDIUM ERROR"),
        (0x4, "HARDWARE ERROR"),
        (0x5, "ILLEGAL REQUEST"),
        (0x6, "UNIT ATTENTION"),
        (0x7, "DATA PROTECT"),
        (0x8, "BLANK CHECK"),
        (0xA, "COPY ABORTED"),
        (0xB, "ABORTED COMMAND"),
        (0xD, "VOLUME OVERFLOW"),
        (0xE, "MISCOMPARE"),
        (0x9, "UNKNOWN SENSE KEY"),
        (0xF, "UNKNOWN SENSE KEY"),
    ];
    for (key, name) in keys {
        assert_eq!(sense_key_name(key), name, "{key:#x}");
    }
    let statuses = [
        (0x00, "GOOD"),
        (0x02, "CHECK CONDITION"),
        (0x04, "CONDITION MET"),
        (0x08, "BUSY"),
        (0x18, "RESERVATION CONFLICT"),
        (0x28, "TASK SET FULL"),
        (0x30, "ACA ACTIVE"),
        (0x40, "TASK ABORTED"),
        (0xFF, "no status (transport)"),
        (0x01, "unknown status"),
    ];
    for (status, name) in statuses {
        assert_eq!(scsi_status_name(status), name, "{status:#x}");
    }
}

#[test]
fn additional_sense_pairs_have_distinct_plain_language_meanings() {
    let pairs = [
        (0x00, 0x00, "no additional sense information"),
        (0x03, 0x00, "peripheral device write fault"),
        (0x04, 0x00, "logical unit not ready, cause not reportable"),
        (0x04, 0x01, "logical unit not ready, becoming ready"),
        (
            0x04,
            0x02,
            "logical unit not ready, initializing command required",
        ),
        (0x08, 0x05, "logical unit communication failure"),
        (0x0C, 0x02, "write error"),
        (0x11, 0x01, "unrecovered read error"),
        (0x20, 0x00, "invalid command operation code"),
        (0x21, 0x00, "logical block address out of range"),
        (0x24, 0x00, "invalid field in CDB"),
        (0x26, 0x03, "invalid field in parameter list"),
        (
            0x28,
            0x00,
            "not-ready to ready change (medium may have changed)",
        ),
        (0x29, 0x01, "power-on / reset / bus-device-reset occurred"),
        (0x30, 0x02, "incompatible medium installed"),
        (0x31, 0x00, "medium format corrupted"),
        (0x3A, 0x00, "medium not present (no disc)"),
        (0x3A, 0x01, "medium not present — tray closed (no disc)"),
        (0x3A, 0x02, "medium not present — tray open"),
        (0x40, 0x80, "diagnostic / hardware component failure"),
        (0x44, 0x00, "internal target failure"),
        (0x51, 0x00, "erase failure"),
        (0x7F, 0x7F, "(see ASC/ASCQ)"),
        (0x24, 0x01, "(see ASC/ASCQ)"),
    ];
    for (asc, ascq, meaning) in pairs {
        assert_eq!(asc_meaning(asc, ascq), meaning, "{asc:#x}/{ascq:#x}");
    }
}

#[test]
fn scsi_errors_without_decodable_sense_are_called_a_rejection() {
    let s = describe_scsi_error(&scsi_err(0x08, None));
    assert!(
        s.starts_with("BUSY (0x08): sense details unavailable or invalid"),
        "{s}"
    );
    let s = describe_scsi_error(&scsi_err(0x02, Some((0x3, 0x0C, 0x02))));
    assert!(s.contains("MEDIUM ERROR: write error"), "{s}");
}

#[test]
fn structured_sense_survives_anyhow_context() {
    let error = anyhow::Error::new(ScsiSenseError::new(0x5, 0x24, 0x00, "invalid field"))
        .context("while identifying");
    assert_eq!(sense_triplet(&error), Some((0x5, 0x24, 0x00)));
    assert_eq!(sense_triplet(&anyhow::anyhow!("no sense")), None);
    assert_eq!(ScsiSenseError::new(1, 2, 3, "detail").to_string(), "detail");
}

#[test]
fn transport_defaults_delegate_and_assume_a_flash_safe_tray() {
    struct Plain(Vec<&'static str>);
    impl ScsiDevice for Plain {
        fn command_in(&mut self, _: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
            self.0.push("in");
            Ok(vec![0; alloc_len])
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
            self.0.push("out");
            Ok(())
        }
        fn describe(&self) -> String {
            "plain".into()
        }
    }
    let mut dev = Plain(Vec::new());
    assert_eq!(dev.diagnostic_in(&[0x12], 4, 100).unwrap().len(), 4);
    dev.command_out_strict(&[0x3b], &[1]).unwrap();
    dev.command_out_directed(&[0x3b], &[]).unwrap();
    assert_eq!(dev.0, ["in", "out", "out"]);
    assert_eq!(dev.medium_status().unwrap(), MediumStatus::ClosedEmpty);
    assert_eq!(MediumStatus::default(), MediumStatus::ClosedEmpty);
    assert_eq!(dev.describe(), "plain");
}

#[test]
fn typed_open_errors_keep_their_issue_and_unknown_selectors_fail_to_open() {
    use crate::user_error::{IssueCode, UserError};
    let typed = super::open_error(anyhow::Error::new(IssueCode::FirmwareInvalid));
    assert_eq!(UserError::of(&typed).id, "errors.firmware_invalid");
    assert!(open("nonexistent-device-must-never-be-opened", false).is_err());
    let _ = list_drives();
}
