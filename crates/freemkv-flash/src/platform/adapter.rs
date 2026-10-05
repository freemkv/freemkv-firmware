//! Adapter: freemkv-flash's [`ScsiDevice`] over libfreemkv's `ScsiTransport`.
//!
//! The per-OS SCSI backends (SG_IO / IOKit / SPTI + the macOS shim) live once,
//! in libfreemkv's `scsi` feature. This adapter is the only place that bridges
//! them to flash's [`ScsiDevice`] contract, folding in the sense-handling and
//! self-clearing UNIT ATTENTION retry that used to be duplicated across the
//! three deleted backends.

use anyhow::{anyhow, bail, Result};

use libfreemkv::scsi::{self, DataDirection, ScsiTransport};

use super::{Direction, MediumStatus, ScsiDevice, ScsiSenseError};

/// Per-command timeout (matches the deleted SG_IO backend's `DEFAULT_TIMEOUT_MS`).
const TIMEOUT_MS: u32 = 30_000;

/// Spin-up (START STOP UNIT, IMMED off) blocks until the medium is ready; a cold
/// BD/UHD can take a while to spin up, so allow generously beyond a normal cmd.
const SPINUP_TIMEOUT_MS: u32 = 60_000;
/// SCSI status byte: CHECK CONDITION (sense data available).
const CHECK_CONDITION: u8 = 0x02;

thread_local! {
    static TRACE_COMMANDS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Trace a diagnostic operation without flooding subsequent firmware transfers.
pub(crate) fn trace_commands<T>(operation: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            TRACE_COMMANDS.set(self.0);
        }
    }
    let _restore = Restore(TRACE_COMMANDS.replace(true));
    operation()
}

fn diagnostic(visible: bool, text: &str) {
    if visible || crate::style::trace_enabled() {
        eprintln!("{text}");
    } else {
        crate::diagnostics::record(text);
    }
}

/// A [`ScsiDevice`] backed by a libfreemkv platform transport.
pub struct TransportDevice {
    inner: Box<dyn ScsiTransport>,
    path: String,
}

/// Turn a raw libfreemkv open error (e.g. `E1005: ioreg:… 0xe00002c5`) into a
/// friendly, actionable message, keeping the raw text dimmed for debugging.
fn friendly_open_error(path: &str, raw: &str) -> anyhow::Error {
    let low = raw.to_ascii_lowercase();
    let hint = if raw.contains("0xe00002c5") || low.contains("exclusive") {
        "the drive is already open by another process — close other freemkv commands or disc/eject utilities and retry"
    } else if raw.contains("0xe00002bc") || low.contains("not found") || low.contains("no such") {
        "no drive matches that selector — run `freemkv-flash list` to see connected drives"
    } else if raw.contains("0xe00002c1")
        || low.contains("not permitted")
        || low.contains("permission")
    {
        "permission denied opening the drive — grant the terminal/app disk access and retry"
    } else {
        return anyhow!("could not open drive {path}: {raw}");
    };
    anyhow!("could not open drive {path}: {hint} ({raw})")
}

impl TransportDevice {
    /// Open the platform transport for `path` (libfreemkv opens O_RDWR, so the
    /// old `writable` distinction is moot — write access is always available,
    /// which the read-only `info`/`dump` paths simply never exercise).
    pub fn open(path: &str) -> Result<Self> {
        crate::diagnostics::record(format!("SCSI open: device={path:?}"));
        let inner = scsi::open(std::path::Path::new(path))
            .map_err(|e| friendly_open_error(path, &e.to_string()))?;
        crate::diagnostics::record(format!(
            "SCSI opened: max_transfer_bytes={}",
            inner.max_transfer_bytes()
        ));
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
        self.run_inner(cdb, dir, buf, false)
    }

    /// As [`Self::run`], but `strict == true` tolerates NO nonzero status at all
    /// (not even RECOVERED / un-retried UNIT ATTENTION): any CHECK CONDITION is
    /// fatal. Used by the OEM firmware-write path, where the host aborts on any
    /// nonzero result.
    fn run_inner(
        &mut self,
        cdb: &[u8],
        dir: Direction,
        buf: &mut [u8],
        strict: bool,
    ) -> Result<usize> {
        let ldir = match dir {
            Direction::None => DataDirection::None,
            Direction::FromDevice => DataDirection::FromDevice,
            Direction::ToDevice => DataDirection::ToDevice,
        };
        let mut transferred = 0usize;
        for attempt in 0..2 {
            let trace = TRACE_COMMANDS.get();
            let request = format!(
                    "SCSI request: device={} cdb={cdb:02x?} direction={dir:?} requested={} attempt={} strict={strict} timeout_ms={TIMEOUT_MS}",
                    self.path, buf.len(), attempt + 1
                );
            diagnostic(trace, &request);
            let result = self.execute_logged(cdb, ldir, buf, TIMEOUT_MS);
            let r = match result {
                Ok(r) => r,
                // libfreemkv transports surface CHECK CONDITION as `Err`. Preserve
                // the old backend's tolerance of benign "no medium" (flashed with
                // no disc) and its one UNIT-ATTENTION retry on reads; else fatal.
                Err(e) => {
                    if let Some(s) = e.scsi_sense() {
                        // No-disc is benign only for a no-data command. Keep
                        // the real sense for reads/writes instead of masking
                        // it as a short successful transfer.
                        if !strict && buf.is_empty() && super::is_no_medium(s.sense_key, s.asc) {
                            diagnostic(
                                trace,
                                "SCSI policy: no-medium sense tolerated for a no-data command",
                            );
                            return Ok(0);
                        }
                        // Self-clearing UNIT ATTENTION (key 0x6): retry once, but
                        // never on a data-OUT write (re-sending a burn-triggering
                        // chunk could re-arm the program).
                        if !strict
                            && s.sense_key == 0x6
                            && attempt == 0
                            && dir != Direction::ToDevice
                        {
                            diagnostic(trace, "SCSI policy: retrying UNIT ATTENTION");
                            continue;
                        }
                    }
                    let detail = format!("SCSI transport failure on {}: {e} (cdb={cdb:02x?}, direction={dir:?}, requested={}, attempt={})", self.path, buf.len(), attempt + 1);
                    return Err(match e.scsi_sense() {
                        Some(s) => ScsiSenseError::new(s.sense_key, s.asc, s.ascq, detail).into(),
                        None => anyhow!(detail),
                    });
                }
            };
            if r.bytes_transferred > buf.len() {
                bail!(
                    "invalid SCSI transfer count on {}: cdb={cdb:02x?} reported={} requested={}",
                    self.path,
                    r.bytes_transferred,
                    buf.len()
                );
            }
            transferred = r.bytes_transferred;
            if r.status == 0 {
                break;
            }
            let sense = &r.sense[..];
            let key = sense_key(sense);
            // Self-clearing UNIT ATTENTION: retry once, but never a data-OUT write
            // (re-sending a burn-triggering chunk could re-arm the program). On a
            // read the retry is mandatory — the first attempt's data is untrusted.
            if !strict
                && r.status == CHECK_CONDITION
                && key == Some(0x6)
                && attempt == 0
                && dir != Direction::ToDevice
            {
                diagnostic(trace, "SCSI policy: retrying UNIT ATTENTION");
                continue;
            }
            // Tolerate only RECOVERED (0x1), an un-retried UNIT ATTENTION on a
            // non-read, and benign no-medium. A data-IN read that still
            // CHECK-CONDITIONs is never tolerated — its data is invalid.
            let no_medium = sense_kaa(sense).is_some_and(|(k, a, _)| super::is_no_medium(k, a));
            // Strict mode (OEM firmware write) tolerates nothing: any nonzero
            // status aborts, matching the OEM host's "abort on any result" rule.
            let tolerable = !strict
                && r.status == CHECK_CONDITION
                && ((no_medium && buf.is_empty())
                    || key == Some(0x1)
                    || (dir != Direction::FromDevice && key == Some(0x6)));
            if !tolerable {
                let detail = format!(
                    "SCSI command failed on {}: {} (status 0x{:02x}, raw sense {:02x?})",
                    self.path,
                    describe_sense(sense),
                    r.status,
                    r.sense
                );
                return Err(match (r.status, sense_kaa(sense)) {
                    (CHECK_CONDITION, Some((key, asc, ascq))) => {
                        ScsiSenseError::new(key, asc, ascq, detail).into()
                    }
                    _ => anyhow!(detail),
                });
            }
            diagnostic(trace, "SCSI policy: nonzero status tolerated");
            break;
        }
        Ok(transferred)
    }

    /// Log every native execution, including readiness and spin-up paths.
    fn execute_logged(
        &mut self,
        cdb: &[u8],
        dir: DataDirection,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> libfreemkv::error::Result<scsi::ScsiResult> {
        let start = std::time::Instant::now();
        crate::diagnostics::record(format!("SCSI execute: device={:?} cdb={cdb:02x?} direction={dir:?} requested={} timeout_ms={timeout_ms}", self.path, buf.len()));
        let result = self.inner.execute(cdb, dir, buf, timeout_ms);
        let text = match &result {
            Ok(r) => format!(
                "SCSI result: status=0x{:02x} transferred={} sense={:02x?}",
                r.status, r.bytes_transferred, r.sense
            ),
            Err(e) => format!("SCSI result: error={e:?}"),
        };
        diagnostic(
            TRACE_COMMANDS.get(),
            &format!("{text} elapsed_ms={}", start.elapsed().as_millis()),
        );
        result
    }

    /// Shared data-OUT send with a full-acceptance check; `strict` forbids any
    /// nonzero-status tolerance (OEM firmware write).
    fn data_out(&mut self, cdb: &[u8], data: &[u8], strict: bool) -> Result<()> {
        let mut buf = data.to_vec();
        let dir = if buf.is_empty() {
            Direction::None
        } else {
            Direction::ToDevice
        };
        let n = self.run_inner(cdb, dir, &mut buf, strict)?;
        if n != data.len() {
            bail!(
                "short WRITE_BUFFER: drive accepted {} of {} bytes",
                n,
                data.len()
            );
        }
        Ok(())
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
        self.data_out(cdb, data, false)
    }

    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.data_out(cdb, data, true)
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
            let sense = match self.execute_logged(&cdb, DataDirection::None, &mut none, TIMEOUT_MS)
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
        let _ = self.execute_logged(&cdb, DataDirection::None, &mut none, SPINUP_TIMEOUT_MS);
    }
}

/// Extract the SCSI sense key from a fixed- (0x70/0x71) or descriptor-format
/// (0x72/0x73) sense buffer; `None` if too short or an unknown format.
fn sense_key(sense: &[u8]) -> Option<u8> {
    match *sense.first()? & 0x7f {
        0x70 | 0x71 => sense.get(2).map(|&b| b & 0x0F),
        0x72 | 0x73 => sense.get(1).map(|&b| b & 0x0F),
        _ => None,
    }
}

/// Extract (key, ASC, ASCQ) from a fixed- or descriptor-format sense buffer.
fn sense_kaa(sense: &[u8]) -> Option<(u8, u8, u8)> {
    match *sense.first()? & 0x7f {
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
}
