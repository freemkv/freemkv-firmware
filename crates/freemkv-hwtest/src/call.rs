//! The ONE call primitive.
//!
//! Every test step — knock, DumpAll, OEM passthrough, disc read, wedge probe —
//! goes through [`call_cdb`]. It is the single place that decides the data
//! direction, allocation length and timeout for a SCSI command, so the framing
//! bug that motivated this harness (a knock issued with NO data-in phase
//! desyncs the transfer → ABORTED COMMAND → the drive wedges) cannot recur:
//! there is exactly one framing, expressed once.

pub use libfreemkv::scsi::{DataDirection, ScsiTransport};

/// SCSI status byte: GOOD.
pub const STATUS_GOOD: u8 = 0x00;
/// SCSI status byte: CHECK CONDITION (sense data present).
pub const STATUS_CHECK_CONDITION: u8 = 0x02;

/// The outcome of one [`call_cdb`], normalised across every platform backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResult {
    /// SCSI status byte (`0x00` GOOD, `0x02` CHECK CONDITION). Meaningless when
    /// [`wedged`](Self::wedged) is set (no status was ever delivered).
    pub status: u8,
    /// Decoded `(sense_key, asc, ascq)` when the command CHECK-CONDITIONed.
    pub sense: Option<(u8, u8, u8)>,
    /// The data-in bytes actually transferred (truncated to the transfer count).
    pub data: Vec<u8>,
    /// True when the transport never delivered a SCSI reply — a kernel timeout,
    /// USB-bridge wedge or dead bus (`DID_BAD_TARGET`). This is the 0.6.0
    /// failure mode and is classified DISTINCTLY from any drive-returned status.
    pub wedged: bool,
}

impl CallResult {
    /// `true` if the command returned GOOD status and did not wedge.
    #[allow(dead_code)] // convenience predicate used by tests / external callers
    pub fn is_good(&self) -> bool {
        !self.wedged && self.status == STATUS_GOOD
    }
}

/// Extract `(key, ASC, ASCQ)` from a fixed- (0x70/0x71) or descriptor-format
/// (0x72/0x73) raw sense buffer; `None` if too short / unknown format.
fn parse_raw_sense(sense: &[u8]) -> Option<(u8, u8, u8)> {
    match *sense.first()? {
        0x70 | 0x71 if sense.len() >= 14 => Some((sense[2] & 0x0F, sense[12], sense[13])),
        0x72 | 0x73 if sense.len() >= 4 => Some((sense[1] & 0x0F, sense[2], sense[3])),
        _ => None,
    }
}

/// Issue `cdb` through the real transport with a single explicit framing.
///
/// * `dir` — the data phase. For a knock this MUST be [`DataDirection::FromDevice`].
/// * `alloc` — the data-in buffer size (bytes to read). For a knock: 64.
/// * `timeout_ms` — per-command watchdog; a hang classifies as `wedged`.
///
/// Never panics: a transport failure or timeout returns `wedged: true` rather
/// than propagating an error, so the runner can print an ABORT and exit 2.
pub fn call_cdb(
    scsi: &mut dyn ScsiTransport,
    cdb: &[u8],
    dir: DataDirection,
    alloc: usize,
    timeout_ms: u32,
) -> CallResult {
    let mut buf = vec![0u8; alloc];
    match scsi.execute(cdb, dir, &mut buf, timeout_ms) {
        Ok(r) => {
            let n = r.bytes_transferred.min(buf.len());
            buf.truncate(n);
            let sense = if r.status == STATUS_CHECK_CONDITION {
                parse_raw_sense(&r.sense)
            } else {
                None
            };
            CallResult {
                status: r.status,
                sense,
                data: buf,
                wedged: false,
            }
        }
        Err(e) => {
            // A transport-layer failure (kernel timeout / bridge wedge / dead
            // bus) is the wedge we must flag distinctly.
            if e.is_scsi_transport_failure() {
                return CallResult {
                    status: libfreemkv::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                    sense: None,
                    data: Vec::new(),
                    wedged: true,
                };
            }
            // A drive-delivered CHECK CONDITION surfaced as Err (Linux SG_IO /
            // Windows SPTI report it this way): preserve the sense triple.
            if let Some(s) = e.scsi_sense() {
                return CallResult {
                    status: STATUS_CHECK_CONDITION,
                    sense: Some((s.sense_key, s.asc, s.ascq)),
                    data: Vec::new(),
                    wedged: false,
                };
            }
            // No sense and not a classified transport failure — treat any other
            // error conservatively as a wedge so the run aborts rather than
            // reporting a phantom pass.
            CallResult {
                status: libfreemkv::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                sense: None,
                data: Vec::new(),
                wedged: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockTransport;

    #[test]
    fn good_data_in_is_returned_and_truncated() {
        let mut t = MockTransport::new().on_data(|cdb| cdb[0] == 0x3C, b"freemkv 0.6.6".to_vec());
        let r = call_cdb(&mut t, &[0x3C, 0x0E], DataDirection::FromDevice, 64, 1000);
        assert!(r.is_good());
        assert_eq!(&r.data, b"freemkv 0.6.6");
        assert!(!r.wedged);
    }

    #[test]
    fn check_condition_via_ok_status_parses_sense() {
        let mut t = MockTransport::new().on_check_condition(|_| true, (0x05, 0x24, 0x00));
        let r = call_cdb(&mut t, &[0xAD], DataDirection::FromDevice, 32, 1000);
        assert_eq!(r.status, STATUS_CHECK_CONDITION);
        assert_eq!(r.sense, Some((0x05, 0x24, 0x00)));
        assert!(!r.wedged);
    }

    #[test]
    fn check_condition_via_err_parses_sense() {
        // Linux SG_IO / Windows SPTI surface a CHECK CONDITION as Err(ScsiError)
        // carrying the sense triple — not as Ok{status:2}. Both must decode.
        let mut t = MockTransport::new().on_check_condition_err(|_| true, (0x0B, 0x00, 0x00));
        let r = call_cdb(&mut t, &[0x3C], DataDirection::FromDevice, 64, 1000);
        assert_eq!(r.status, STATUS_CHECK_CONDITION);
        assert_eq!(r.sense, Some((0x0B, 0x00, 0x00)));
        assert!(!r.wedged);
    }

    #[test]
    fn transport_failure_is_wedged() {
        let mut t = MockTransport::new().on_wedge(|_| true);
        let r = call_cdb(&mut t, &[0x3C], DataDirection::FromDevice, 64, 1000);
        assert!(r.wedged);
        assert!(!r.is_good());
    }
}
