//! A programmable in-memory [`ScsiDevice`] for host-independent tests.
//!
//! `MockScsiDevice` lets tests answer specific CDBs with canned data or errors
//! and records every command_out (write) it receives, so the drive/flash logic
//! can be exercised on any OS (including macOS CI) without real hardware.

use anyhow::{bail, Result};

use super::ScsiDevice;

type Matcher = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

enum Outcome {
    /// Return these exact bytes (as-is, ignoring alloc_len).
    Data(Vec<u8>),
    /// Fail the command with this message.
    Fail(String),
}

struct Rule {
    matcher: Matcher,
    outcome: Outcome,
}

/// A mock SCSI device driven by a list of CDB-matching rules.
///
/// Unmatched `command_in` calls return an all-zero buffer of the requested
/// length; unmatched `command_out` calls succeed and are recorded in
/// [`MockScsiDevice::writes`].
#[derive(Default)]
pub struct MockScsiDevice {
    rules: Vec<Rule>,
    /// Every `(cdb, data)` pair received via `command_out`, in order.
    pub writes: Vec<(Vec<u8>, Vec<u8>)>,
    /// Every CDB received via `command_in`, in order.
    pub reads: Vec<Vec<u8>>,
}

impl MockScsiDevice {
    /// Create an empty mock (all reads zero-fill, all writes recorded).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule: when `matcher(cdb)` is true on a data-in command, return `data`.
    pub fn on<F>(mut self, matcher: F, data: Vec<u8>) -> Self
    where
        F: Fn(&[u8]) -> bool + Send + Sync + 'static,
    {
        self.rules.push(Rule {
            matcher: Box::new(matcher),
            outcome: Outcome::Data(data),
        });
        self
    }

    /// Add a rule: when `matcher(cdb)` is true, fail the command with `msg`.
    pub fn on_fail<F>(mut self, matcher: F, msg: &str) -> Self
    where
        F: Fn(&[u8]) -> bool + Send + Sync + 'static,
    {
        self.rules.push(Rule {
            matcher: Box::new(matcher),
            outcome: Outcome::Fail(msg.to_string()),
        });
        self
    }

    /// A mock that classifies as MediaTek: GET CONFIGURATION 0x010C echoes the
    /// `01 0C` feature descriptor. All other reads zero-fill.
    pub fn mtk() -> Self {
        let mut fd = vec![0u8; 28];
        // GET CONFIG header (8) + feature descriptor: feature code at bytes 8..10.
        fd[8] = 0x01;
        fd[9] = 0x0C;
        Self::new().on(
            |cdb| cdb.first() == Some(&0x46) && cdb.get(2..4) == Some(&[0x01, 0x0C][..]),
            fd,
        )
    }

    /// A mock that classifies as Pioneer/Renesas: READ BUFFER buffer-id 0xF1
    /// succeeds with non-zero data; GET CONFIGURATION 0x010C does not echo `01 0C`.
    pub fn pioneer() -> Self {
        Self::new().on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            vec![0xA5; 8],
        )
    }
}

impl ScsiDevice for MockScsiDevice {
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
        self.reads.push(cdb.to_vec());
        for rule in &self.rules {
            if (rule.matcher)(cdb) {
                return match &rule.outcome {
                    Outcome::Data(d) => Ok(d.clone()),
                    Outcome::Fail(m) => bail!("{m}"),
                };
            }
        }
        Ok(vec![0u8; alloc_len])
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        for rule in &self.rules {
            if (rule.matcher)(cdb) {
                if let Outcome::Fail(m) = &rule.outcome {
                    bail!("{m}");
                }
            }
        }
        self.writes.push((cdb.to_vec(), data.to_vec()));
        Ok(())
    }

    fn describe(&self) -> String {
        "mock://in-memory".to_string()
    }
}
