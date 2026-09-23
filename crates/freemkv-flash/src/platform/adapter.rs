//! Adapter: freemkv-flash's [`ScsiDevice`] over libfreemkv's `ScsiTransport`.
//!
//! The per-OS SCSI backends (SG_IO / IOKit / SPTI + the macOS shim) live once,
//! in libfreemkv's `scsi` feature. This adapter is the only place that bridges
//! them to flash's [`ScsiDevice`] contract, folding in the sense-handling and
//! self-clearing UNIT ATTENTION retry that used to be duplicated across the
//! three deleted backends.

use anyhow::{anyhow, bail, Result};

use libfreemkv::scsi::{self, DataDirection, ScsiTransport};

use super::{Direction, MediumStatus, ScsiDevice};

/// Per-command timeout (matches the deleted SG_IO backend's `DEFAULT_TIMEOUT_MS`).
const TIMEOUT_MS: u32 = 30_000;

/// Spin-up (START STOP UNIT, IMMED off) blocks until the medium is ready; a cold
/// BD/UHD can take a while to spin up, so allow generously beyond a normal cmd.
const SPINUP_TIMEOUT_MS: u32 = 60_000;
/// SCSI status byte: CHECK CONDITION (sense data available).
const CHECK_CONDITION: u8 = 0x02;

/// A [`ScsiDevice`] backed by a libfreemkv platform transport.
pub struct TransportDevice {
    inner: Box<dyn ScsiTransport>,
    path: String,
}

impl TransportDevice {
    /// Open the platform transport for `path` (libfreemkv opens O_RDWR, so the
    /// old `writable` distinction is moot — write access is always available,
    /// which the read-only `info`/`dump` paths simply never exercise).
    pub fn open(path: &str) -> Result<Self> {
        let inner = scsi::open(std::path::Path::new(path)).map_err(|e| anyhow!("{e}"))?;
        Ok(Self {
            inner,
            path: path.to_string(),
        })
    }

    /// Execute `cdb`, applying the same sense/retry policy the SG_IO backend did:
    /// a transport failure always fails; a self-clearing UNIT ATTENTION is
    /// retried exactly once (never for a data-OUT write); RECOVERED, an un-retried
    /// UNIT ATTENTION on a non-read, and the benign "no medium present" state are
    /// tolerated; every other CHECK CONDITION fails. Returns the byte count.
    fn run(&mut self, cdb: &[u8], dir: Direction, buf: &mut [u8]) -> Result<usize> {
        let ldir = match dir {
            Direction::None => DataDirection::None,
            Direction::FromDevice => DataDirection::FromDevice,
            Direction::ToDevice => DataDirection::ToDevice,
        };
        let mut transferred = 0usize;
        for attempt in 0..2 {
            let r = match self.inner.execute(cdb, ldir, buf, TIMEOUT_MS) {
                Ok(r) => r,
                // libfreemkv transports surface CHECK CONDITION as `Err`. Preserve
                // the old backend's tolerance of benign "no medium" (flashed with
                // no disc) and its one UNIT-ATTENTION retry on reads; else fatal.
                Err(e) => {
                    if let Some(s) = e.scsi_sense() {
                        // Benign no-disc (key 0x2 / ASC 0x3A): tolerate as 0 bytes.
                        // A read needing medium yields 0 bytes, caught by the
                        // caller's length check — no garbage smuggled upward.
                        if super::is_no_medium(s.sense_key, s.asc) {
                            return Ok(0);
                        }
                        // Self-clearing UNIT ATTENTION (key 0x6): retry once, but
                        // never on a data-OUT write (re-sending a burn-triggering
                        // chunk could re-arm the program).
                        if s.sense_key == 0x6 && attempt == 0 && dir != Direction::ToDevice {
                            continue;
                        }
                    }
                    return Err(anyhow!("SCSI transport failure on {}: {e}", self.path));
                }
            };
            transferred = r.bytes_transferred;
            if r.status == 0 {
                break;
            }
            let sense = &r.sense[..];
            let key = sense_key(sense);
            // Self-clearing UNIT ATTENTION: retry once, but never a data-OUT write
            // (re-sending a burn-triggering chunk could re-arm the program). On a
            // read the retry is mandatory — the first attempt's data is untrusted.
            if r.status == CHECK_CONDITION
                && key == Some(0x6)
                && attempt == 0
                && dir != Direction::ToDevice
            {
                continue;
            }
            // Tolerate only RECOVERED (0x1), an un-retried UNIT ATTENTION on a
            // non-read, and benign no-medium. A data-IN read that still
            // CHECK-CONDITIONs is never tolerated — its data is invalid.
            let no_medium = sense_kaa(sense).is_some_and(|(k, a, _)| super::is_no_medium(k, a));
            let tolerable = r.status == CHECK_CONDITION
                && (no_medium
                    || key == Some(0x1)
                    || (dir != Direction::FromDevice && key == Some(0x6)));
            if !tolerable {
                bail!(
                    "SCSI command failed on {}: {} (status 0x{:02x}, raw sense {:02x?})",
                    self.path,
                    describe_sense(sense),
                    r.status,
                    r.sense
                );
            }
            break;
        }
        Ok(transferred)
    }
}

impl ScsiDevice for TransportDevice {
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; alloc_len];
        let n = self.run(cdb, Direction::FromDevice, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        let mut buf = data.to_vec();
        let dir = if buf.is_empty() {
            Direction::None
        } else {
            Direction::ToDevice
        };
        let n = self.run(cdb, dir, &mut buf)?;
        if n != data.len() {
            bail!(
                "short WRITE_BUFFER: drive accepted {} of {} bytes",
                n,
                data.len()
            );
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("{} (libfreemkv SCSI transport)", self.path)
    }

    fn medium_status(&mut self) -> Result<MediumStatus> {
        // FAIL-CLOSED: TEST UNIT READY alone can't tell an empty tray from a
        // loaded-but-SPUN-DOWN disc (both answer "medium not present", 0x3A), so
        // a first no-medium verdict is re-checked after a spin-up (see below).
        match self.probe_tur()? {
            Tur::Present => Ok(MediumStatus::DiscPresent),
            Tur::TrayOpen => Ok(MediumStatus::TrayOpen),
            Tur::NoMedium => {
                self.spin_up_best_effort();
                match self.probe_tur()? {
                    // Still no medium after spin-up → genuinely empty. Anything
                    // else (became ready / unsettled) is a loaded disc — never
                    // flash unless empty is PROVEN.
                    Tur::NoMedium => Ok(MediumStatus::ClosedEmpty),
                    _ => Ok(MediumStatus::DiscPresent),
                }
            }
        }
    }
}

/// TEST UNIT READY verdict, collapsed to the three states the flash guard cares
/// about. `Present` also covers becoming-ready / spinning-up / unparsable — any
/// non-empty, unsettled state — so the caller fails closed (never flashes).
enum Tur {
    Present,
    NoMedium,
    TrayOpen,
}

impl TransportDevice {
    /// One TEST UNIT READY (opcode 0x00), classified into [`Tur`]. A self-
    /// clearing UNIT ATTENTION (key 0x6) is retried once. A senseless transport
    /// failure (dead bus) propagates as `Err`.
    fn probe_tur(&mut self) -> Result<Tur> {
        let cdb = [0u8; 6];
        for attempt in 0..2 {
            let mut none: [u8; 0] = [];
            let sense = match self
                .inner
                .execute(&cdb, DataDirection::None, &mut none, TIMEOUT_MS)
            {
                Ok(r) if r.status == 0 => return Ok(Tur::Present),
                Ok(r) => sense_kaa(&r.sense),
                Err(e) => match e.scsi_sense() {
                    Some(s) => Some((s.sense_key, s.asc, s.ascq)),
                    None => {
                        return Err(anyhow!(
                            "TEST UNIT READY transport failure on {}: {e}",
                            self.path
                        ));
                    }
                },
            };
            match sense {
                Some((k, a, q)) => {
                    match super::medium_status_from_sense(k, a, q) {
                        Some(MediumStatus::TrayOpen) => return Ok(Tur::TrayOpen),
                        Some(_) => return Ok(Tur::NoMedium),
                        None => {}
                    }
                    if k == 0x6 && attempt == 0 {
                        continue; // self-clearing UNIT ATTENTION — retry once
                    }
                    // becoming-ready / initializing / unparsable → treat as present
                    return Ok(Tur::Present);
                }
                None => return Ok(Tur::Present),
            }
        }
        Ok(Tur::Present)
    }

    /// Best-effort spin-up: START STOP UNIT (0x1B) with START=1, IMMED=0 so the
    /// drive blocks until the medium is spun up. Errors are ignored — an empty
    /// tray simply has nothing to start; the point is that a loaded disc becomes
    /// ready before the re-probe, closing the spun-down-disc fail-open.
    fn spin_up_best_effort(&mut self) {
        // [0]=0x1B opcode, [1]=0 (IMMED off, block until ready), [4]=0x01 START.
        let cdb = [0x1B, 0x00, 0x00, 0x00, 0x01, 0x00];
        let mut none: [u8; 0] = [];
        let _ = self
            .inner
            .execute(&cdb, DataDirection::None, &mut none, SPINUP_TIMEOUT_MS);
    }
}

/// Extract the SCSI sense key from a fixed- (0x70/0x71) or descriptor-format
/// (0x72/0x73) sense buffer; `None` if too short or an unknown format.
fn sense_key(sense: &[u8]) -> Option<u8> {
    match *sense.first()? {
        0x70 | 0x71 => sense.get(2).map(|&b| b & 0x0F),
        0x72 | 0x73 => sense.get(1).map(|&b| b & 0x0F),
        _ => None,
    }
}

/// Extract (key, ASC, ASCQ) from a fixed- or descriptor-format sense buffer.
fn sense_kaa(sense: &[u8]) -> Option<(u8, u8, u8)> {
    match *sense.first()? {
        0x70 | 0x71 if sense.len() >= 14 => Some((sense[2] & 0x0F, sense[12], sense[13])),
        0x72 | 0x73 if sense.len() >= 4 => Some((sense[1] & 0x0F, sense[2], sense[3])),
        _ => None,
    }
}

/// One-line human-readable description of a raw sense buffer via the shared
/// platform sense tables.
fn describe_sense(sense: &[u8]) -> String {
    match sense_kaa(sense) {
        Some((key, asc, ascq)) => super::describe_sense(key, asc, ascq),
        None => format!("unparsable sense {sense:02x?}"),
    }
}

#[cfg(test)]
mod tests {
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
}
