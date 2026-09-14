//! Adapter: freemkv-flash's [`ScsiDevice`] over libfreemkv's `ScsiTransport`.
//!
//! The per-OS SCSI backends (SG_IO / IOKit / SPTI + the macOS shim) live once,
//! in libfreemkv's `scsi` feature. This adapter is the only place that bridges
//! them to flash's [`ScsiDevice`] contract, folding in the sense-handling and
//! self-clearing UNIT ATTENTION retry that used to be duplicated across the
//! three deleted backends.

use anyhow::{anyhow, bail, Result};

use libfreemkv::scsi::{self, DataDirection, ScsiTransport};

use super::{Direction, ScsiDevice};

/// Per-command timeout (matches the deleted SG_IO backend's `DEFAULT_TIMEOUT_MS`).
const TIMEOUT_MS: u32 = 30_000;
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

    fn medium_present(&mut self) -> Result<bool> {
        // Standard TEST UNIT READY (opcode 0x00, 6-byte CDB), no data phase.
        //   GOOD (status 0)                     => unit ready WITH a medium loaded.
        //   NOT READY / medium not present       => empty tray (the ONLY positive
        //     (key 0x2 ASC 0x3A)                    "no disc" answer; safe to flash).
        //   self-clearing UNIT ATTENTION (0x6)   => stale power-on/reset notice;
        //                                           retried once, then re-judged.
        //   any other decoded sense              => treated as "medium present"
        //                                           (spinning up, incompatible
        //                                           medium, …) so we NEVER flash
        //                                           unless the empty tray is proven.
        // A senseless transport failure (dead bus) propagates as Err.
        let cdb = [0u8; 6];
        for attempt in 0..2 {
            let mut none: [u8; 0] = [];
            match self.inner.execute(&cdb, DataDirection::None, &mut none, TIMEOUT_MS) {
                Ok(r) => {
                    if r.status == 0 {
                        return Ok(true);
                    }
                    match sense_kaa(&r.sense) {
                        Some((k, a, _)) if super::is_no_medium(k, a) => return Ok(false),
                        Some((0x6, _, _)) if attempt == 0 => continue,
                        _ => return Ok(true),
                    }
                }
                Err(e) => {
                    if let Some(s) = e.scsi_sense() {
                        if super::is_no_medium(s.sense_key, s.asc) {
                            return Ok(false);
                        }
                        if s.sense_key == 0x6 && attempt == 0 {
                            continue;
                        }
                        return Ok(true);
                    }
                    return Err(anyhow!(
                        "TEST UNIT READY transport failure on {}: {e}",
                        self.path
                    ));
                }
            }
        }
        Ok(true)
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
    /// comes back), for exercising [`TransportDevice::medium_present`].
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

    /// GOOD status to TEST UNIT READY => a medium is loaded => flash must be refused.
    #[test]
    fn medium_present_true_on_good_status() {
        let mut dev = dev_status(0x00, (0, 0, 0));
        assert_eq!(dev.medium_present().unwrap(), true);
    }

    /// Positive "no medium" (key 0x2 ASC 0x3A), whether surfaced as `Err` (real
    /// SG_IO/SPTI) or as `Ok { status: CC }`, is the ONLY empty-tray answer.
    #[test]
    fn medium_present_false_on_no_medium() {
        let mut e = dev_with(ScsiSense {
            sense_key: 0x2,
            asc: 0x3A,
            ascq: 0x01,
        });
        assert_eq!(e.medium_present().unwrap(), false, "no-medium via Err");
        let mut o = dev_status(CHECK_CONDITION, (0x2, 0x3A, 0x00));
        assert_eq!(o.medium_present().unwrap(), false, "no-medium via Ok(CC)");
    }

    /// "Becoming ready" (key 0x2 ASC 0x04 — a disc spinning up) is NOT a positive
    /// empty tray, so it is conservatively treated as medium-present (block flash).
    #[test]
    fn medium_present_true_when_spinning_up() {
        let mut dev = dev_status(CHECK_CONDITION, (0x2, 0x04, 0x01));
        assert_eq!(dev.medium_present().unwrap(), true);
    }
}
