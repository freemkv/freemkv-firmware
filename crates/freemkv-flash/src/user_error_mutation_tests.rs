//! Classification of file errors and of update causes drawn from SCSI sense.

use super::*;
use crate::backend::{UpdateFailure, UpdateProgress};
use crate::platform::ScsiSenseError;

#[test]
fn file_errors_classify_by_kind() {
    use std::io::ErrorKind::*;
    for (kind, id) in [
        (NotFound, "errors.file_missing"),
        (PermissionDenied, "errors.permission_denied"),
        (AlreadyExists, "errors.file_exists"),
        (WriteZero, "errors.save_failed"),
        (StorageFull, "errors.save_failed"),
        (TimedOut, "errors.connection"),
        (NotConnected, "errors.connection"),
        (ConnectionAborted, "errors.connection"),
        (ConnectionReset, "errors.connection"),
        (BrokenPipe, "errors.connection"),
        (InvalidData, "errors.file_access"),
    ] {
        let error = anyhow::Error::new(std::io::Error::new(kind, "x"));
        assert_eq!(UserError::of(&error).id, id, "{kind:?}");
    }
}

fn started(error: anyhow::Error) -> anyhow::Error {
    error.context(UpdateFailure {
        phase: "firmware transfer".into(),
        write_started: true,
        progress: UpdateProgress::PayloadAttempted,
        payload_bytes_accepted: Some(0),
        temporary_firmware: false,
        completed_stages: Vec::new(),
    })
}

fn cause(error: &anyhow::Error) -> Option<String> {
    let issue = UserError::of(error);
    (issue.id == "errors.update_cause").then(|| {
        issue
            .arguments
            .iter()
            .find(|(k, _)| *k == "cause")
            .map(|(_, v)| v.clone())
            .unwrap()
    })
}

#[test]
fn rejected_transfers_need_the_exact_invalid_field_sense() {
    let rejected = || localization::message("errors.transfer_rejected", &args());
    let stopped = || localization::message("errors.transfer_stopped", &args());
    fn args() -> [(&'static str, String); 2] {
        [("offset", "4096".into()), ("length", "16".into())]
    }
    for ((key, asc, ascq), want) in [
        ((5, 0x26, 2), rejected()),
        ((5, 0x26, 3), stopped()),
        ((5, 0x25, 2), stopped()),
        ((4, 0x26, 2), stopped()),
    ] {
        let error = started(
            anyhow::Error::new(ScsiSenseError::new(key, asc, ascq, "device")).context(
                TransferFailure {
                    offset: 4096,
                    length: 16,
                },
            ),
        );
        assert_eq!(cause(&error), Some(want), "{key}/{asc:#x}/{ascq}");
    }
}

#[test]
fn communication_errors_need_the_exact_hardware_sense() {
    let comm = |key, asc, ascq| {
        cause(&started(anyhow::Error::new(ScsiSenseError::new(
            key, asc, ascq, "device",
        ))))
    };
    assert_eq!(
        comm(4, 8, 1),
        Some("errors.update_communication".to_string())
    );
    for (key, asc, ascq) in [(4, 8, 2), (4, 9, 1), (5, 8, 1), (3, 8, 1)] {
        assert_eq!(comm(key, asc, ascq), None, "{key}/{asc}/{ascq}");
    }
}

#[test]
fn transfer_and_backup_markers_describe_themselves() {
    assert_eq!(
        TransferFailure {
            offset: 7,
            length: 9
        }
        .to_string(),
        "firmware transfer stopped at byte 7, block length 9"
    );
    assert_eq!(BackupAttempt.to_string(), "backup did not complete");
}
