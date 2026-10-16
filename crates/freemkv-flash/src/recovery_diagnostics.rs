//! Bounded read-only evidence after MediaTek recovery fails before uploading.
//!
//! This is deliberately not an arbitrary command runner. The entry-failure
//! caller proves that no firmware data has been sent. Later failures need a
//! receiver-specific settle contract before a diagnostic sweep is safe.
use std::time::{Duration, Instant};

use crate::{diagnostics::record, platform::ScsiDevice};

const MAX_COMMANDS: usize = 50;
const BUDGET: Duration = Duration::from_secs(20);
const TIMEOUT_MS: u32 = 1500;
const MAX_REPLY: usize = 1024;

struct Probe {
    name: &'static str,
    cdb: Vec<u8>,
    allocation: usize,
    minimum: usize,
}

fn probes() -> Vec<Probe> {
    use mediatek_optical::cdb;
    let mut probes = vec![
        // Sense must precede INQUIRY and other commands which may clear it.
        Probe {
            name: "pending sense",
            cdb: vec![3, 0, 0, 0, 18, 0],
            allocation: 18,
            minimum: 4,
        },
        Probe {
            name: "INQUIRY",
            cdb: cdb::inquiry(36).to_vec(),
            allocation: 36,
            minimum: 36,
        },
        Probe {
            name: "GET CONFIGURATION header",
            cdb: cdb::get_configuration(0, 8).to_vec(),
            allocation: 8,
            minimum: 8,
        },
        Probe {
            name: "serial feature",
            cdb: cdb::get_configuration(0x108, 64).to_vec(),
            allocation: 64,
            minimum: 8,
        },
        Probe {
            name: "date feature",
            cdb: cdb::get_configuration(0x10c, 32).to_vec(),
            allocation: 32,
            minimum: 8,
        },
    ];
    for (name, address, length) in [
        ("BOOT banner", 0x3000, 32),
        ("BOOT receiver", 0x3400, 1024),
        ("BOOT AES helper", 0x5510, 46),
        ("image marker", 0x105c0, 16),
        ("application descriptor", 0x1ec000, 96),
    ] {
        probes.push(Probe {
            name,
            cdb: cdb::read_memory(address, length).to_vec(),
            allocation: length as usize,
            minimum: length as usize,
        });
    }
    probes
}

/// Diagnose only an entry failure, where no firmware payload was transmitted.
/// This function never replaces the original operation error with its result.
pub(crate) fn entry_failure(dev: &mut dyn ScsiDevice, original: &str) {
    record(format!(
        "Recovery original failure (no firmware payload sent): {original}"
    ));
    let start = Instant::now();
    sweep(dev, &probes(), || start.elapsed());
    record("Recovery diagnostics do not establish update readiness or successful recovery");
}

fn sweep(dev: &mut dyn ScsiDevice, probes: &[Probe], elapsed: impl Fn() -> Duration) {
    for (index, probe) in probes.iter().enumerate() {
        let remaining = BUDGET.saturating_sub(elapsed());
        if index >= MAX_COMMANDS || remaining.is_zero() {
            record(format!(
                "Recovery diagnostics: skipped {} remaining probes (budget)",
                probes.len() - index
            ));
            break;
        }
        // Defensive allowlist: never admit WRITE BUFFER, reset, unlock, MODE
        // SELECT, START STOP UNIT or an undocumented register read here.
        if !matches!(probe.cdb.first(), Some(0x03 | 0x12 | 0x46 | 0x3c))
            || probe.allocation > MAX_REPLY
            || probe.minimum > probe.allocation
        {
            record(format!(
                "Recovery diagnostic {}: skipped invalid probe",
                probe.name
            ));
            continue;
        }
        let timeout = TIMEOUT_MS.min(remaining.as_millis().max(1) as u32);
        record(format!("Recovery diagnostic {}: cdb={:02x?} direction=FromDevice requested={} timeout_ms={timeout}", probe.name, probe.cdb, probe.allocation));
        let before = elapsed();
        match dev.diagnostic_in(&probe.cdb, probe.allocation, timeout) {
            Ok(bytes) => {
                let classification =
                    if bytes.len() < probe.minimum || bytes.len() > probe.allocation {
                        "short/invalid count"
                    } else {
                        "response received; content validation required"
                    };
                record(format!("Recovery diagnostic {}: {classification}; returned={} raw={bytes:02x?} elapsed_ms={}", probe.name, bytes.len(), elapsed().saturating_sub(before).as_millis()));
            }
            Err(error) => record(format!(
                "Recovery diagnostic {}: rejected or transport failure: {error:#}; elapsed_ms={}",
                probe.name,
                elapsed().saturating_sub(before).as_millis()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, Result};
    use std::cell::Cell;

    #[derive(Default)]
    struct Device {
        seen: Vec<(Vec<u8>, usize, u32)>,
    }
    impl ScsiDevice for Device {
        fn command_in(&mut self, _: &[u8], _: usize) -> Result<Vec<u8>> {
            panic!("must use bounded diagnostic transport")
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
            panic!("diagnostics must never write")
        }
        fn describe(&self) -> String {
            "test".into()
        }
        fn diagnostic_in(&mut self, cdb: &[u8], n: usize, timeout: u32) -> Result<Vec<u8>> {
            self.seen.push((cdb.to_vec(), n, timeout));
            bail!("rejected without sense")
        }
    }
    #[test]
    fn failed_probes_are_not_retried_and_sense_is_first() {
        let mut dev = Device::default();
        sweep(&mut dev, &probes(), || Duration::ZERO);
        assert_eq!(dev.seen.len(), probes().len());
        assert_eq!(dev.seen[0].0, [3, 0, 0, 0, 18, 0]);
        assert!(dev
            .seen
            .iter()
            .all(|(_, n, t)| *n <= MAX_REPLY && *t == TIMEOUT_MS));
    }
    #[test]
    fn count_and_time_budgets_stop_scheduling() {
        let mut dev = Device::default();
        let many: Vec<_> = (0..100).map(|_| probes().remove(0)).collect();
        sweep(&mut dev, &many, || Duration::ZERO);
        assert_eq!(dev.seen.len(), MAX_COMMANDS);
        dev.seen.clear();
        let ticks = Cell::new(0);
        sweep(&mut dev, &many, || {
            let n = ticks.get();
            ticks.set(n + 1);
            Duration::from_secs(n)
        });
        assert!(!dev.seen.is_empty());
        assert!(dev.seen.len() < 20);
    }
    #[test]
    fn refuses_mutating_commands_and_oversize_replies() {
        let mut dev = Device::default();
        let invalid = [
            Probe {
                name: "PREPARE",
                cdb: mediatek_optical::cdb::enter_update().to_vec(),
                allocation: 0,
                minimum: 0,
            },
            Probe {
                name: "oversize",
                cdb: vec![0x12],
                allocation: MAX_REPLY + 1,
                minimum: 0,
            },
        ];
        sweep(&mut dev, &invalid, || Duration::ZERO);
        assert!(dev.seen.is_empty());
    }
}
