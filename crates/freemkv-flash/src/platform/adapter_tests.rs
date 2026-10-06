use super::*;
use libfreemkv::error::Error as FError;
use libfreemkv::scsi::{ScsiResult, ScsiSense};

/// A transport that surfaces a CHECK CONDITION as `Err(ScsiError)` with a
/// caller-chosen sense — exactly how libfreemkv's real Linux SG_IO / Windows
/// SPTI backends report one (they do NOT return `Ok { status: CC }`).
struct SenseErrTransport {
    sense: ScsiSense,
}
impl ScsiTransport for SenseErrTransport {
    fn execute(
        &mut self,
        _cdb: &[u8],
        _dir: DataDirection,
        _buf: &mut [u8],
        _timeout_ms: u32,
    ) -> libfreemkv::error::Result<ScsiResult> {
        Err(FError::ScsiError {
            opcode: 0x00,
            status: CHECK_CONDITION,
            sense: Some(self.sense),
        })
    }
}

fn dev_with(sense: ScsiSense) -> TransportDevice {
    TransportDevice {
        inner: Box::new(SenseErrTransport { sense }),
        path: "test".to_string(),
    }
}

/// Scripts TEST UNIT READY replies in order (None = GOOD, Some(k,a,q) =
/// CHECK CONDITION) and acks START STOP UNIT (0x1B), so the multi-step
/// medium detection (probe → spin-up → re-probe) is deterministic.
struct ScriptedTransport {
    tur: std::collections::VecDeque<Option<(u8, u8, u8)>>,
}
fn fixed_sense(k: u8, a: u8, q: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x70;
    s[2] = k;
    s[12] = a;
    s[13] = q;
    s
}
impl ScsiTransport for ScriptedTransport {
    fn execute(
        &mut self,
        cdb: &[u8],
        _dir: DataDirection,
        _buf: &mut [u8],
        _timeout_ms: u32,
    ) -> libfreemkv::error::Result<ScsiResult> {
        if cdb.first() == Some(&0x1B) {
            // START STOP UNIT ack (spin-up).
            return Ok(ScsiResult {
                status: 0,
                bytes_transferred: 0,
                sense: [0u8; 32],
            });
        }
        match self.tur.pop_front().flatten() {
            None => Ok(ScsiResult {
                status: 0,
                bytes_transferred: 0,
                sense: [0u8; 32],
            }),
            Some((k, a, q)) => Ok(ScsiResult {
                status: CHECK_CONDITION,
                bytes_transferred: 0,
                sense: fixed_sense(k, a, q),
            }),
        }
    }
}
fn dev_scripted(tur: impl IntoIterator<Item = Option<(u8, u8, u8)>>) -> TransportDevice {
    TransportDevice {
        inner: Box::new(ScriptedTransport {
            tur: tur.into_iter().collect(),
        }),
        path: "test".to_string(),
    }
}

#[test]
fn strict_no_data_write_rejects_no_medium_error() {
    let mut dev = dev_with(ScsiSense {
        sense_key: 2,
        asc: 0x3a,
        ascq: 0,
    });
    assert!(dev.command_out_strict(&[0x3b, 0, 0, 0, 0, 0], &[]).is_err());
}

/// THE INCIDENT: a loaded-but-spun-down disc first reports "medium not
/// present" (0x3A) to TEST UNIT READY, then GOOD after a spin-up. It MUST be
/// classified DiscPresent so the flash guard refuses — never flash with a
/// disc in.
#[test]
fn spun_down_disc_becomes_present_after_spinup() {
    let mut dev = dev_scripted([Some((0x2, 0x3A, 0x00)), None]);
    assert!(matches!(
        dev.medium_status().unwrap(),
        MediumStatus::DiscPresent
    ));
}

/// A genuinely empty tray reports no-medium on BOTH probes (spin-up finds
/// nothing) → ClosedEmpty, so an empty-tray drive can still be flashed.
#[test]
fn truly_empty_tray_is_closed_empty_after_spinup() {
    let mut dev = dev_scripted([Some((0x2, 0x3A, 0x00)), Some((0x2, 0x3A, 0x00))]);
    assert!(matches!(
        dev.medium_status().unwrap(),
        MediumStatus::ClosedEmpty
    ));
}

/// A ready, loaded disc (GOOD) is present immediately — no spin-up needed.
#[test]
fn ready_disc_is_present() {
    let mut dev = dev_scripted([None]);
    assert!(matches!(
        dev.medium_status().unwrap(),
        MediumStatus::DiscPresent
    ));
}

/// An open tray (ASCQ 0x02) is reported as TrayOpen (the guard refuses that too).
#[test]
fn open_tray_is_tray_open() {
    let mut dev = dev_scripted([Some((0x2, 0x3A, 0x02))]);
    assert!(matches!(
        dev.medium_status().unwrap(),
        MediumStatus::TrayOpen
    ));
}

/// After spin-up a disc may still be BECOMING READY (0x04/0x01) — that is a
/// loaded disc, so it must be DiscPresent (fail-closed), not empty.
#[test]
fn becoming_ready_after_spinup_is_present() {
    let mut dev = dev_scripted([Some((0x2, 0x3A, 0x00)), Some((0x2, 0x04, 0x01))]);
    assert!(matches!(
        dev.medium_status().unwrap(),
        MediumStatus::DiscPresent
    ));
}

/// REGRESSION GUARD (0.5.0→0.6.0 backend swap): a discless drive answers
/// TEST UNIT READY with NOT READY / MEDIUM NOT PRESENT (key 0x2 ASC 0x3A),
/// which libfreemkv surfaces as `Err`. Firmware is flashed with NO disc, so
/// this MUST be tolerated (0 bytes) — otherwise an empty-tray drive can never
/// be flashed, exactly the bug this test pins.
#[test]
fn no_medium_err_is_tolerated_so_empty_tray_can_flash() {
    let mut dev = dev_with(ScsiSense {
        sense_key: 0x2,
        asc: 0x3A,
        ascq: 0x01,
    });
    let out = dev
        .command_in(&crate::drive::mtk::cdb_test_unit_ready(), 0)
        .expect("no-medium must be tolerated, not fatal");
    assert!(out.is_empty(), "no-medium yields 0 bytes");
}

#[test]
fn no_medium_data_transfers_preserve_the_real_error() {
    for mut dev in [
        dev_with(ScsiSense {
            sense_key: 2,
            asc: 0x3a,
            ascq: 0,
        }),
        dev_status(CHECK_CONDITION, (2, 0x3a, 0)),
    ] {
        for error in [
            dev.command_in(&[0x3c], 4).unwrap_err(),
            dev.command_out(&[0x3b], &[1; 4]).unwrap_err(),
        ] {
            assert_eq!(super::super::sense_triplet(&error), Some((2, 0x3a, 0)));
        }
    }
}

#[test]
fn strict_writes_never_retry_unit_attention_even_without_payload() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Attention(Arc<AtomicUsize>);
    impl ScsiTransport for Attention {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            _buf: &mut [u8],
            _timeout: u32,
        ) -> libfreemkv::error::Result<ScsiResult> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(FError::ScsiError {
                opcode: 0x3b,
                status: CHECK_CONDITION,
                sense: Some(ScsiSense {
                    sense_key: 6,
                    asc: 0x29,
                    ascq: 0,
                }),
            })
        }
    }
    for payload in [&[][..], &[1, 2, 3, 4][..]] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut dev = TransportDevice {
            inner: Box::new(Attention(calls.clone())),
            path: "test".into(),
        };
        assert!(dev.command_out_strict(&[0x3b], payload).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn read_unit_attention_retries_once_then_returns_data() {
    struct AttentionOnce(bool);
    impl ScsiTransport for AttentionOnce {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            buf: &mut [u8],
            _timeout: u32,
        ) -> libfreemkv::error::Result<ScsiResult> {
            if !std::mem::replace(&mut self.0, true) {
                return Err(FError::ScsiError {
                    opcode: 0x3c,
                    status: CHECK_CONDITION,
                    sense: Some(ScsiSense {
                        sense_key: 6,
                        asc: 0x29,
                        ascq: 0,
                    }),
                });
            }
            buf.fill(0x5a);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: buf.len(),
                sense: [0; 32],
            })
        }
    }
    let mut dev = TransportDevice {
        inner: Box::new(AttentionOnce(false)),
        path: "test".into(),
    };
    assert_eq!(dev.command_in(&[0x3c], 4).unwrap(), [0x5a; 4]);
}

#[test]
fn impossible_transfer_count_is_rejected_instead_of_truncated() {
    struct Overrun;
    impl ScsiTransport for Overrun {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            buf: &mut [u8],
            _timeout: u32,
        ) -> libfreemkv::error::Result<ScsiResult> {
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: buf.len() + 1,
                sense: [0; 32],
            })
        }
    }
    let mut dev = TransportDevice {
        inner: Box::new(Overrun),
        path: "test".into(),
    };
    assert!(dev
        .command_in(&[0x3c], 4)
        .unwrap_err()
        .to_string()
        .contains("invalid SCSI transfer count"));
}

/// A genuine fault (HARDWARE ERROR) surfaced as `Err` must STILL be fatal —
/// the no-medium tolerance must not swallow real errors.
#[test]
fn genuine_error_err_still_fails() {
    let mut dev = dev_with(ScsiSense {
        sense_key: 0x4, // HARDWARE ERROR
        asc: 0x44,
        ascq: 0x00,
    });
    assert!(
        dev.command_in(&crate::drive::mtk::cdb_test_unit_ready(), 0)
            .is_err(),
        "a real error must not be tolerated"
    );
}

/// A transport that answers with a chosen SCSI status + raw sense as an
/// `Ok(ScsiResult)` (how a status-only, no-data command like TEST UNIT READY
/// comes back), for exercising [`TransportDevice::medium_status`].
struct StatusTransport {
    status: u8,
    sense: [u8; 32],
}
impl ScsiTransport for StatusTransport {
    fn execute(
        &mut self,
        _cdb: &[u8],
        _dir: DataDirection,
        _buf: &mut [u8],
        _timeout_ms: u32,
    ) -> libfreemkv::error::Result<ScsiResult> {
        Ok(ScsiResult {
            status: self.status,
            bytes_transferred: 0,
            sense: self.sense,
        })
    }
}
fn dev_status(status: u8, kaa: (u8, u8, u8)) -> TransportDevice {
    // Fixed-format sense buffer (0x70): key at [2], ASC at [12], ASCQ at [13].
    let mut sense = [0u8; 32];
    sense[0] = 0x70;
    sense[2] = kaa.0;
    sense[12] = kaa.1;
    sense[13] = kaa.2;
    TransportDevice {
        inner: Box::new(StatusTransport { status, sense }),
        path: "test".to_string(),
    }
}

#[test]
fn transport_sense_survives_context_without_changing_display() {
    let sense = ScsiSense {
        sense_key: 0x5,
        asc: 0x24,
        ascq: 0,
    };
    let expected = format!(
            "SCSI transport failure on test: {} (cdb=[3c], direction=FromDevice, requested=1, attempt=1)",
            FError::ScsiError {
                opcode: 0,
                status: CHECK_CONDITION,
                sense: Some(sense),
            }
        );
    let error = dev_with(sense).command_in(&[0x3c], 1).unwrap_err();
    assert_eq!(error.to_string(), expected);
    assert_eq!(super::super::sense_triplet(&error), Some((5, 0x24, 0)));
    let error = error.context("reading Kernel").context("creating backup");
    assert_eq!(super::super::sense_triplet(&error), Some((5, 0x24, 0)));
}

#[test]
fn check_condition_preserves_fixed_and_descriptor_sense() {
    for format in [0x70, 0x71, 0xf0, 0xf1, 0x72, 0x73] {
        let mut sense = fixed_sense(5, 0x24, 0);
        sense[0] = format;
        if format == 0x72 || format == 0x73 {
            sense[1] = 5;
            sense[2] = 0x24;
            sense[3] = 0;
        }
        let expected = format!(
            "SCSI command failed on test: {} (status 0x02, raw sense {:02x?})",
            super::super::describe_sense(5, 0x24, 0),
            sense
        );
        let mut dev = TransportDevice {
            inner: Box::new(StatusTransport {
                status: CHECK_CONDITION,
                sense,
            }),
            path: "test".into(),
        };
        let error = dev.command_in(&[0x3c], 1).unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(super::super::sense_triplet(&error), Some((5, 0x24, 0)));
    }
}

#[test]
fn unknown_or_non_check_condition_sense_is_not_classified() {
    for (status, sense) in [(CHECK_CONDITION, [0; 32]), (8, fixed_sense(5, 0x24, 0))] {
        let mut dev = TransportDevice {
            inner: Box::new(StatusTransport { status, sense }),
            path: "test".into(),
        };
        let error = dev.command_in(&[0x3c], 1).unwrap_err();
        assert_eq!(super::super::sense_triplet(&error), None);
    }
    // Text which resembles sense data must not authorize a recovery command.
    let error = anyhow!("SCSI transport failure 05/24/00").context("backup");
    assert_eq!(super::super::sense_triplet(&error), None);
}

#[test]
fn senseless_transport_error_is_not_classified() {
    struct FailedTransport;
    impl ScsiTransport for FailedTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            _buf: &mut [u8],
            _timeout_ms: u32,
        ) -> libfreemkv::error::Result<ScsiResult> {
            Err(FError::ScsiError {
                opcode: 0x3c,
                status: 0xff,
                sense: None,
            })
        }
    }
    let mut dev = TransportDevice {
        inner: Box::new(FailedTransport),
        path: "test".into(),
    };
    let error = dev.command_in(&[0x3c], 1).unwrap_err();
    assert!(error
        .to_string()
        .starts_with("SCSI transport failure on test:"));
    assert_eq!(super::super::sense_triplet(&error), None);
}

/// GOOD status to TEST UNIT READY => a disc is loaded => flash must be refused.
#[test]
fn medium_status_disc_present_on_good_status() {
    let mut dev = dev_status(0x00, (0, 0, 0));
    assert_eq!(dev.medium_status().unwrap(), MediumStatus::DiscPresent);
}

/// Closed-empty "no medium" (key 0x2 ASC 0x3A, ASCQ 0x00/0x01), whether
/// surfaced as `Err` (real SG_IO/SPTI) or as `Ok { status: CC }`, is the
/// flash-safe state.
#[test]
fn medium_status_closed_empty_on_no_medium() {
    let mut e = dev_with(ScsiSense {
        sense_key: 0x2,
        asc: 0x3A,
        ascq: 0x01,
    });
    assert_eq!(
        e.medium_status().unwrap(),
        MediumStatus::ClosedEmpty,
        "closed-empty via Err"
    );
    let mut o = dev_status(CHECK_CONDITION, (0x2, 0x3A, 0x00));
    assert_eq!(
        o.medium_status().unwrap(),
        MediumStatus::ClosedEmpty,
        "closed-empty via Ok(CC)"
    );
}

/// Tray open (key 0x2 ASC 0x3A ASCQ 0x02) is distinct — refuse until closed.
#[test]
fn medium_status_tray_open_on_ascq_02() {
    let mut e = dev_with(ScsiSense {
        sense_key: 0x2,
        asc: 0x3A,
        ascq: 0x02,
    });
    assert_eq!(
        e.medium_status().unwrap(),
        MediumStatus::TrayOpen,
        "tray-open via Err"
    );
    let mut o = dev_status(CHECK_CONDITION, (0x2, 0x3A, 0x02));
    assert_eq!(
        o.medium_status().unwrap(),
        MediumStatus::TrayOpen,
        "tray-open via Ok(CC)"
    );
}

/// "Becoming ready" (key 0x2 ASC 0x04 — a disc spinning up) is NOT a proven
/// closed-empty tray, so it is conservatively treated as DiscPresent (block).
#[test]
fn medium_status_disc_present_when_spinning_up() {
    let mut dev = dev_status(CHECK_CONDITION, (0x2, 0x04, 0x01));
    assert_eq!(dev.medium_status().unwrap(), MediumStatus::DiscPresent);
}
