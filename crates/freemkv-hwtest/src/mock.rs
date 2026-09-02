//! A programmable in-memory [`ScsiTransport`] for host-independent tests.
//!
//! Lets a test answer specific CDBs with canned data-in bytes, a CHECK
//! CONDITION (either as `Ok{status:2}` — how macOS IOKit reports it — or as
//! `Err(ScsiError)` — how Linux SG_IO / Windows SPTI report it), or a transport
//! wedge, so the whole runner can be exercised on any OS without real hardware.

use libfreemkv::error::{Error, Result};
use libfreemkv::scsi::{
    DataDirection, ScsiResult, ScsiSense, ScsiTransport, SCSI_STATUS_TRANSPORT_FAILURE,
};

type Matcher = Box<dyn Fn(&[u8]) -> bool + Send>;

enum Outcome {
    Data(Vec<u8>),
    CheckConditionOk((u8, u8, u8)),
    CheckConditionErr((u8, u8, u8)),
    Wedge,
}

struct Rule {
    matcher: Matcher,
    outcome: Outcome,
}

/// A transport driven by an ordered list of CDB-matching rules. The first
/// matching rule wins; an unmatched CDB returns GOOD with a zero-filled buffer.
#[derive(Default)]
pub struct MockTransport {
    rules: Vec<Rule>,
}

impl MockTransport {
    /// Create an empty mock (all commands GOOD, zero-filled).
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer a matching command with GOOD status and these data-in bytes.
    pub fn on_data<F>(mut self, matcher: F, data: Vec<u8>) -> Self
    where
        F: Fn(&[u8]) -> bool + Send + 'static,
    {
        self.rules.push(Rule {
            matcher: Box::new(matcher),
            outcome: Outcome::Data(data),
        });
        self
    }

    /// Answer a matching command with a CHECK CONDITION delivered as `Ok{status:2}`.
    pub fn on_check_condition<F>(mut self, matcher: F, kaq: (u8, u8, u8)) -> Self
    where
        F: Fn(&[u8]) -> bool + Send + 'static,
    {
        self.rules.push(Rule {
            matcher: Box::new(matcher),
            outcome: Outcome::CheckConditionOk(kaq),
        });
        self
    }

    /// Answer a matching command with a CHECK CONDITION delivered as `Err(ScsiError)`.
    pub fn on_check_condition_err<F>(mut self, matcher: F, kaq: (u8, u8, u8)) -> Self
    where
        F: Fn(&[u8]) -> bool + Send + 'static,
    {
        self.rules.push(Rule {
            matcher: Box::new(matcher),
            outcome: Outcome::CheckConditionErr(kaq),
        });
        self
    }

    /// Wedge (transport failure) on a matching command.
    pub fn on_wedge<F>(mut self, matcher: F) -> Self
    where
        F: Fn(&[u8]) -> bool + Send + 'static,
    {
        self.rules.push(Rule {
            matcher: Box::new(matcher),
            outcome: Outcome::Wedge,
        });
        self
    }
}

/// Build a fixed-format (0x70) sense buffer carrying `(key, asc, ascq)`.
fn fixed_sense(kaq: (u8, u8, u8)) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x70;
    s[2] = kaq.0 & 0x0F;
    s[7] = 10; // additional sense length
    s[12] = kaq.1;
    s[13] = kaq.2;
    s
}

impl ScsiTransport for MockTransport {
    fn execute(
        &mut self,
        cdb: &[u8],
        _dir: DataDirection,
        data: &mut [u8],
        _timeout_ms: u32,
    ) -> Result<ScsiResult> {
        for rule in &self.rules {
            if !(rule.matcher)(cdb) {
                continue;
            }
            return match &rule.outcome {
                Outcome::Data(d) => {
                    let n = d.len().min(data.len());
                    data[..n].copy_from_slice(&d[..n]);
                    Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: n,
                        sense: [0u8; 32],
                    })
                }
                Outcome::CheckConditionOk(kaq) => Ok(ScsiResult {
                    status: 0x02,
                    bytes_transferred: 0,
                    sense: fixed_sense(*kaq),
                }),
                Outcome::CheckConditionErr(kaq) => Err(Error::ScsiError {
                    opcode: cdb.first().copied().unwrap_or(0),
                    status: 0x02,
                    sense: Some(ScsiSense {
                        sense_key: kaq.0,
                        asc: kaq.1,
                        ascq: kaq.2,
                    }),
                }),
                Outcome::Wedge => Err(Error::ScsiError {
                    opcode: cdb.first().copied().unwrap_or(0),
                    status: SCSI_STATUS_TRANSPORT_FAILURE,
                    sense: None,
                }),
            };
        }
        // Unmatched: GOOD, zero-filled full buffer.
        let n = data.len();
        Ok(ScsiResult {
            status: 0,
            bytes_transferred: n,
            sense: [0u8; 32],
        })
    }
}
