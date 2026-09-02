//! The test runner: turns a [`Script`] into calls through the ONE primitive,
//! evaluates each step's expectations, and enforces the wedge-guard invariant
//! after every step (re-issue the identity knock; a dead bus aborts the run).

use crate::call::{
    call_cdb, CallResult, DataDirection, ScsiTransport, STATUS_CHECK_CONDITION, STATUS_GOOD,
};
use crate::cdb::{self, subfn, KNOCK_ALLOC};
use crate::script::{
    AkeConfig, Dir, ExecExpect, ExecSpec, Expect, Knock, Num, Pacing, Phase, Script, StatusExp,
    Step,
};

/// The overall result of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// Every executed step passed → exit 0.
    AllPass,
    /// At least one step failed (no wedge) → exit 1.
    Failure,
    /// The drive stopped answering → exit 2.
    Wedged,
}

impl RunOutcome {
    /// Process exit code for this outcome.
    pub fn exit_code(self) -> i32 {
        match self {
            RunOutcome::AllPass => 0,
            RunOutcome::Failure => 1,
            RunOutcome::Wedged => 2,
        }
    }
}

/// One line of PASS/FAIL detail within a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Whether this individual assertion passed.
    pub pass: bool,
    /// Human-readable detail.
    pub detail: String,
}

/// The outcome of executing ONE command (a knock or raw CDB) via
/// [`Runner::exec_command`]: its per-assertion checks and whether it wedged.
struct ExecOutcome {
    /// Per-assertion checks produced by this command.
    checks: Vec<Check>,
    /// True if the drive wedged mid-command (or on a flag readback).
    wedged: bool,
    /// Where the wedge happened, if it did.
    wedge_at: Option<String>,
}

/// The result of running one step.
#[derive(Debug, Clone)]
pub struct StepReport {
    /// The step name.
    pub name: String,
    /// The phase it ran in.
    pub phase: Phase,
    /// Per-assertion checks.
    pub checks: Vec<Check>,
    /// True if the drive wedged on this step (main call or guard).
    pub wedged: bool,
    /// What the guard message was, if the drive wedged.
    pub wedge_at: Option<String>,
    /// True if the step was skipped (e.g. an `exec` cert step with no AKE helper
    /// configured). A skip is neither a pass nor a fail.
    pub skipped: bool,
    /// Why the step was skipped, if it was.
    pub skip_reason: Option<String>,
}

impl StepReport {
    /// A normal (issued, not skipped/wedged) report.
    fn issued(name: String, phase: Phase, checks: Vec<Check>) -> Self {
        Self {
            name,
            phase,
            checks,
            wedged: false,
            wedge_at: None,
            skipped: false,
            skip_reason: None,
        }
    }

    /// A wedged report (aborts the run with exit 2).
    fn wedged(name: String, phase: Phase, checks: Vec<Check>, wedge_at: String) -> Self {
        Self {
            name,
            phase,
            checks,
            wedged: true,
            wedge_at: Some(wedge_at),
            skipped: false,
            skip_reason: None,
        }
    }

    /// A skipped report (config absent — neither pass nor fail).
    fn skipped(name: String, phase: Phase, reason: String) -> Self {
        Self {
            name,
            phase,
            checks: Vec::new(),
            wedged: false,
            wedge_at: None,
            skipped: true,
            skip_reason: Some(reason),
        }
    }

    /// True when every check passed and the drive did not wedge (a skipped step
    /// is NOT counted as passed — see [`RunResult`] accounting).
    pub fn passed(&self) -> bool {
        !self.wedged && !self.skipped && self.checks.iter().all(|c| c.pass)
    }
}

/// A completed run: the executed step reports and the overall outcome.
#[derive(Debug)]
pub struct RunResult {
    /// One report per executed step (a wedge aborts mid-list).
    pub steps: Vec<StepReport>,
    /// The overall outcome.
    pub outcome: RunOutcome,
}

/// The outcome of a bounded TEST UNIT READY poll before a disc read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyState {
    /// The drive reported GOOD (or polling was disabled).
    Ready,
    /// The drive never became ready within the retry budget (proceed best-effort).
    NotReady,
    /// The transport wedged during the poll — abort.
    Wedged,
}

/// Liveness of the drive, per the shell `alive` helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Alive {
    /// Answers the identity knock with the freemkv magic.
    Freemkv,
    /// Answers INQUIRY but not the freemkv knock (live, non-freemkv/other fw).
    Other,
    /// Dead bus — DID_BAD_TARGET / timeout.
    Wedged,
}

/// The stateful runner over a real (or mock) transport.
pub struct Runner<'a> {
    scsi: &'a mut dyn ScsiTransport,
    flag_base: u32,
    timeout_ms: u32,
    /// Command pacing (delays / TUR polling). Default all-zero = no pacing, which
    /// is what the unit tests use so `cargo test` stays instant.
    pacing: Pacing,
    /// Host-side AKE helper + cert material for `exec` steps.
    ake: AkeConfig,
    /// Named data windows captured by earlier steps (for `equals_capture`).
    captures: std::collections::HashMap<String, Vec<u8>>,
    /// Optional cap on a step's `iterations` (a fast run caps this low; a `--soak`
    /// run leaves it `None` so the script's full 20× reliability count applies).
    max_iters: Option<usize>,
    /// Run a READ CAPACITY disc-presence precheck before the first disc step (skip
    /// all disc steps on an empty tray). Off by default so the unit-test mocks —
    /// which don't model READ CAPACITY — behave as before; `main` turns it on for
    /// real hardware.
    disc_precheck: bool,
    /// Kill an `exec` helper (the cert-AKE `cert_vid`) after this many ms. A real
    /// AKE that hangs (e.g. a 1.0 cert against a 2.0 disc) would otherwise stall
    /// the whole suite. 0 = no timeout (the unit tests use fast local helpers).
    exec_timeout_ms: u32,
}

impl<'a> Runner<'a> {
    /// Create a runner bound to a transport with the script's flag base / timeout.
    /// Pacing defaults to zero (no delays); use [`Runner::with_pacing`] for real
    /// hardware.
    pub fn new(scsi: &'a mut dyn ScsiTransport, flag_base: u32, timeout_ms: u32) -> Self {
        Self {
            scsi,
            flag_base,
            timeout_ms,
            pacing: Pacing::default(),
            ake: AkeConfig::default(),
            captures: std::collections::HashMap::new(),
            max_iters: None,
            disc_precheck: false,
            exec_timeout_ms: 0,
        }
    }

    /// Kill an `exec` helper after `ms` (0 disables). Real hardware sets this so a
    /// hung cert-AKE can't stall the run.
    pub fn with_exec_timeout(mut self, ms: u32) -> Self {
        self.exec_timeout_ms = ms;
        self
    }

    /// Cap every step's `iterations` at `max` (a fast run). `None` (the default)
    /// runs each step's full declared count — used by `--soak`.
    pub fn with_max_iters(mut self, max: Option<usize>) -> Self {
        self.max_iters = max;
        self
    }

    /// Enable the READ CAPACITY disc-presence precheck (real hardware).
    pub fn with_disc_precheck(mut self, on: bool) -> Self {
        self.disc_precheck = on;
        self
    }

    /// Set the command pacing (inter-command delay, post-toggle settle, TUR poll).
    pub fn with_pacing(mut self, pacing: Pacing) -> Self {
        self.pacing = pacing;
        self
    }

    /// Set the AKE helper + cert config used by `exec` steps.
    pub fn with_ake(mut self, ake: AkeConfig) -> Self {
        self.ake = ake;
        self
    }

    /// Sleep `ms` milliseconds unless zero (zero keeps the mock tests instant).
    fn sleep(ms: u32) {
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms as u64));
        }
    }

    /// True if this CDB is a disc read that should be preceded by a TUR poll.
    fn is_disc_read(cdb: &[u8]) -> bool {
        matches!(cdb.first(), Some(0xAD) | Some(0x28))
    }

    /// True if this CDB is a flag-toggle knock (`02` Speed / `03` Region / `04`
    /// Raw Read) — the writes that need an extra settle before the next read.
    fn is_flag_toggle(cdb: &[u8]) -> bool {
        cdb.first() == Some(&cdb::READ_BUFFER_OPCODE)
            && cdb.get(1) == Some(&cdb::KNOCK_MODE)
            && matches!(cdb.get(4), Some(0x02) | Some(0x03) | Some(0x04))
    }

    /// Poll TEST UNIT READY (`00 00 00 00 00 00`) until GOOD, bounded by
    /// `pacing.tur_retries` with a linear backoff. Returns whether the drive is
    /// ready; a transport wedge is reported separately so the caller can abort.
    /// With `tur_retries == 0` polling is disabled (returns ready immediately).
    fn wait_ready(&mut self) -> ReadyState {
        if self.pacing.tur_retries == 0 {
            return ReadyState::Ready;
        }
        for attempt in 0..self.pacing.tur_retries {
            let r = call_cdb(
                self.scsi,
                &[0, 0, 0, 0, 0, 0],
                DataDirection::None,
                0,
                self.timeout_ms,
            );
            if r.wedged {
                return ReadyState::Wedged;
            }
            if r.status == STATUS_GOOD {
                return ReadyState::Ready;
            }
            // Not ready (spinning up) — back off (linear) and retry.
            Self::sleep(self.pacing.tur_backoff_ms.saturating_mul(attempt + 1));
        }
        ReadyState::NotReady
    }

    /// Build the CDB and (dir, read-length) from a command's parts (shared by a
    /// top-level step and a `sequence` sub-step).
    fn build_cmd(
        &self,
        name: &str,
        knock: &Option<Knock>,
        raw: &Option<String>,
        dir_in: Dir,
        alloc_in: Option<Num>,
    ) -> anyhow::Result<(Vec<u8>, DataDirection, usize)> {
        let dir = match dir_in {
            Dir::FromDevice => DataDirection::FromDevice,
            Dir::None => DataDirection::None,
            Dir::ToDevice => DataDirection::ToDevice,
        };
        if let Some(k) = knock {
            let alloc = alloc_in.map(|n| n.as_usize()).unwrap_or(KNOCK_ALLOC);
            let cdb = if let Some(addr) = k.addr {
                cdb::assemble_dumpall(addr.as_u32()).to_vec()
            } else {
                let state = k.state.map(|n| n.as_u8()).unwrap_or(0);
                cdb::assemble_knock(k.subfn.as_u8(), state, alloc).to_vec()
            };
            Ok((cdb, dir, alloc))
        } else if let Some(raw) = raw {
            let alloc = alloc_in.map(|n| n.as_usize()).unwrap_or(0);
            Ok((cdb::parse_hex_cdb(raw)?, dir, alloc))
        } else {
            anyhow::bail!("command {name:?}: no knock or raw CDB")
        }
    }

    /// DumpAll the 64-byte window at the flag base.
    fn read_flag_window(&mut self) -> CallResult {
        let c = cdb::assemble_dumpall(self.flag_base);
        call_cdb(
            self.scsi,
            &c,
            DataDirection::FromDevice,
            KNOCK_ALLOC,
            self.timeout_ms,
        )
    }

    /// Whether a disc is loaded, via READ CAPACITY(10) (`25 …`). GOOD with a
    /// nonzero capacity → a disc is present; CHECK CONDITION (typically NOT READY
    /// / medium-not-present) → the tray is empty; a transport wedge is reported so
    /// the caller can abort. This is the precheck that stops disc-phase steps from
    /// being fired at an empty drive (where a 0xAD would time out and look like a
    /// firmware wedge).
    fn disc_present(&mut self) -> ReadyState {
        // Spin-up grace first (a freshly-inserted disc may report NOT READY).
        if let ReadyState::Wedged = self.wait_ready() {
            return ReadyState::Wedged;
        }
        let cdb = [0x25u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let r = call_cdb(
            self.scsi,
            &cdb,
            DataDirection::FromDevice,
            8,
            self.timeout_ms,
        );
        if r.wedged {
            return ReadyState::Wedged;
        }
        let cap_ok = r.status == STATUS_GOOD && r.data.len() >= 8 && r.data.iter().any(|&b| b != 0);
        if cap_ok {
            ReadyState::Ready
        } else {
            ReadyState::NotReady
        }
    }

    /// The shell `alive` invariant: identity knock → freemkv magic; otherwise
    /// distinguish a live non-freemkv drive from a wedge via INQUIRY.
    fn alive(&mut self) -> Alive {
        let c = cdb::assemble_knock(subfn::IDENTITY, 0, KNOCK_ALLOC);
        let r = call_cdb(
            self.scsi,
            &c,
            DataDirection::FromDevice,
            KNOCK_ALLOC,
            self.timeout_ms,
        );
        if r.wedged {
            return Alive::Wedged;
        }
        if r.data.starts_with(cdb::RESP_MAGIC) {
            return Alive::Freemkv;
        }
        // No magic — INQUIRY (any working drive answers) tells wedge from live.
        let inq = [0x12u8, 0x00, 0x00, 0x00, 0x24, 0x00];
        let ir = call_cdb(
            self.scsi,
            &inq,
            DataDirection::FromDevice,
            0x24,
            self.timeout_ms,
        );
        if ir.wedged {
            Alive::Wedged
        } else {
            Alive::Other
        }
    }

    /// The `[offset, offset+len)` window of `data` (or all of it if no slice),
    /// or an error string when the window is out of range.
    fn slice_of<'d>(data: &'d [u8], de: &crate::script::DataExp) -> Result<&'d [u8], String> {
        match de.slice {
            Some(s) => {
                let end = s.offset.saturating_add(s.len);
                data.get(s.offset..end).ok_or_else(|| {
                    format!(
                        "slice [{}..{end}] out of range (data len {})",
                        s.offset,
                        data.len()
                    )
                })
            }
            None => Ok(data),
        }
    }

    /// Evaluate a step's data-in assertions across every read (`datas` is one
    /// entry per repeat; whole-response checks use the first read, field checks
    /// use the sliced window, `stable` compares the window across all reads).
    fn eval_data(
        &mut self,
        datas: &[Vec<u8>],
        expect: &Expect,
        version: Option<&str>,
        checks: &mut Vec<Check>,
    ) {
        let Some(de) = &expect.data else { return };
        let first = &datas[0];

        // Whole-response checks.
        if let Some(want) = &de.starts_with_ascii {
            checks.push(Check {
                pass: first.starts_with(want.as_bytes()),
                detail: format!("data starts with ascii {want:?}"),
            });
        }
        if let Some(hex) = &de.starts_with_hex {
            match cdb::parse_hex_cdb(hex) {
                Ok(bytes) => checks.push(Check {
                    pass: first.starts_with(&bytes),
                    detail: format!("data starts with hex {hex:?}"),
                }),
                Err(e) => checks.push(Check {
                    pass: false,
                    detail: format!("bad starts_with_hex: {e}"),
                }),
            }
        }
        if let Some(sub) = &de.contains_ascii {
            checks.push(Check {
                pass: first.windows(sub.len().max(1)).any(|w| w == sub.as_bytes()),
                detail: format!("data contains ascii {sub:?}"),
            });
        }
        if de.contains_version.unwrap_or(false) {
            match version {
                Some(v) => checks.push(Check {
                    pass: first.windows(v.len().max(1)).any(|w| w == v.as_bytes()),
                    detail: format!("data contains version {v:?}"),
                }),
                None => checks.push(Check {
                    pass: false,
                    detail: "contains_version set but no expected version given".into(),
                }),
            }
        }

        // Field checks operate on the sliced window of the first read.
        let field = match Self::slice_of(first, de) {
            Ok(w) => w,
            Err(e) => {
                checks.push(Check {
                    pass: false,
                    detail: e,
                });
                return;
            }
        };
        if de.nonzero.unwrap_or(false) {
            checks.push(Check {
                pass: field.iter().any(|&b| b != 0),
                detail: format!("field nonzero (len {})", field.len()),
            });
        }
        if let Some(min) = de.min_len {
            checks.push(Check {
                pass: field.len() >= min,
                detail: format!("field len {} >= {min}", field.len()),
            });
        }
        if de.stable.unwrap_or(false) {
            let mut all_ok = true;
            for d in &datas[1..] {
                match Self::slice_of(d, de) {
                    Ok(w) if w == field => {}
                    _ => all_ok = false,
                }
            }
            checks.push(Check {
                pass: all_ok,
                detail: format!("field identical across {} read(s)", datas.len()),
            });
        }
        if let Some(name) = &de.equals_capture {
            let ok = self.captures.get(name).map(|v| v.as_slice()) == Some(field);
            checks.push(Check {
                pass: ok,
                detail: format!("field equals earlier capture {name:?}"),
            });
        }
        if let Some(name) = &de.capture {
            self.captures.insert(name.clone(), field.to_vec());
            checks.push(Check {
                pass: true,
                detail: format!("captured {} byte(s) as {name:?}", field.len()),
            });
        }
    }

    /// Run one step, dispatching on its command form. A plain `knock`/`raw` step
    /// with no `iterations` is a single command (original behaviour); a
    /// `sequence` and/or `iterations` step runs the iterated path.
    fn run_step(&mut self, step: &Step, version: Option<&str>) -> StepReport {
        if step.sequence.is_some() || step.iterations.is_some() {
            return self.run_iterated(step, version);
        }
        let out = self.run_command(
            &step.name,
            &step.knock,
            &step.raw,
            &step.exec,
            step.dir,
            step.alloc,
            step.repeat,
            step.report.unwrap_or(false),
            &step.expect,
            &step.expect_exec,
            version,
        );
        if out.wedged {
            return StepReport::wedged(
                step.name.clone(),
                step.phase,
                out.checks,
                out.wedge_at.unwrap_or_else(|| step.name.clone()),
            );
        }
        StepReport::issued(step.name.clone(), step.phase, out.checks)
    }

    /// Dispatch one command by its form: an `exec` helper, else a SCSI command.
    #[allow(clippy::too_many_arguments)]
    fn run_command(
        &mut self,
        name: &str,
        knock: &Option<Knock>,
        raw: &Option<String>,
        exec: &Option<ExecSpec>,
        dir: Dir,
        alloc: Option<Num>,
        repeat: Option<usize>,
        report: bool,
        expect: &Expect,
        expect_exec: &ExecExpect,
        version: Option<&str>,
    ) -> ExecOutcome {
        if let Some(ex) = exec {
            self.exec_helper(name, ex, expect_exec, version)
        } else {
            self.exec_command(
                name, knock, raw, dir, alloc, repeat, report, expect, version,
            )
        }
    }

    /// The reason a step must be skipped (its `exec` needs AKE config that isn't
    /// present), or `None` to run it. A `sequence` skips if ANY sub-step does.
    fn step_skip_reason(&self, step: &Step) -> Option<String> {
        if let Some(ex) = &step.exec {
            return self.exec_skip_reason(&step.name, ex);
        }
        if let Some(seq) = &step.sequence {
            for sub in seq {
                if let Some(ex) = &sub.exec {
                    if let Some(r) = self.exec_skip_reason(&sub.name, ex) {
                        return Some(r);
                    }
                }
            }
        }
        None
    }

    /// The skip reason for one `exec`, or `None` if it can run. Only `cert`-based
    /// execs can skip (a missing helper/cert/dev); an explicit `program` never
    /// skips (schema guarantees it is present).
    fn exec_skip_reason(&self, name: &str, ex: &ExecSpec) -> Option<String> {
        let Some(kind) = &ex.cert else { return None };
        let Some(helper) = &self.ake.helper else {
            return Some(format!(
                "exec {name:?}: AKE_HELPER not set (cert AKE skipped)"
            ));
        };
        if !std::path::Path::new(helper).exists() {
            return Some(format!(
                "exec {name:?}: AKE_HELPER {helper:?} not found (cert AKE skipped)"
            ));
        }
        if self.ake.cert_pair(kind).is_none() {
            let up = kind.to_uppercase();
            return Some(format!(
                "exec {name:?}: {up}_CERT/{up}_KEY not configured (cert AKE skipped)"
            ));
        }
        if self.ake.dev.is_none() {
            return Some(format!(
                "exec {name:?}: no --dev for the AKE helper (skipped)"
            ));
        }
        None
    }

    /// Resolve an `exec` into a concrete `(program, args)`. For a `cert` exec the
    /// runner supplies `AKE_HELPER --dev <dev> --cert <hex> --key <hex>` plus any
    /// extra args; otherwise it runs the explicit `program`.
    fn resolve_exec(&self, ex: &ExecSpec) -> anyhow::Result<(String, Vec<String>)> {
        if let Some(kind) = &ex.cert {
            let helper = self
                .ake
                .helper
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no AKE_HELPER configured"))?;
            let (cert, key) = self
                .ake
                .cert_pair(kind)
                .ok_or_else(|| anyhow::anyhow!("no cert pair for {kind:?}"))?;
            let dev = self
                .ake
                .dev
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no --dev for the AKE helper"))?;
            let mut args = vec![
                "--dev".to_string(),
                dev,
                "--cert".to_string(),
                cert.to_string(),
                "--key".to_string(),
                key.to_string(),
            ];
            if let Some(extra) = &ex.args {
                args.extend(extra.iter().cloned());
            }
            Ok((helper, args))
        } else {
            let program = ex
                .program
                .clone()
                .ok_or_else(|| anyhow::anyhow!("exec needs `cert` or `program`"))?;
            Ok((program, ex.args.clone().unwrap_or_default()))
        }
    }

    /// Parse the hex VID token following `"VID"` in the helper's stdout, e.g.
    /// `"VID 00112233..."` → 16 bytes.
    fn parse_vid(stdout: &str) -> Option<Vec<u8>> {
        let idx = stdout.find("VID")?;
        let tok = stdout[idx + 3..].split_whitespace().next()?.trim();
        if tok.is_empty() || !tok.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(tok.len() / 2);
        let mut i = 0;
        while i < tok.len() {
            out.push(u8::from_str_radix(&tok[i..i + 2], 16).ok()?);
            i += 2;
        }
        Some(out)
    }

    /// Spawn `program args`, returning `(exit_code, stdout)`. With a nonzero
    /// `exec_timeout_ms` the child is polled and KILLED past the deadline (a hung
    /// cert-AKE must not stall the suite); 0 = plain blocking capture. stdout is
    /// small (a VID line) so it is read after exit — no reader thread needed.
    fn run_with_timeout(&self, program: &str, args: &[String]) -> Result<(i32, String), String> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        if self.exec_timeout_ms == 0 {
            let out = Command::new(program)
                .args(args)
                .output()
                .map_err(|e| format!("launch failed: {e}"))?;
            return Ok((
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).to_string(),
            ));
        }
        let mut child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("launch failed: {e}"))?;
        let deadline = Instant::now() + Duration::from_millis(self.exec_timeout_ms as u64);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut s = String::new();
                    if let Some(mut o) = child.stdout.take() {
                        let _ = o.read_to_string(&mut s);
                    }
                    return Ok((status.code().unwrap_or(-1), s));
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!(
                            "timed out after {}ms — killed",
                            self.exec_timeout_ms
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(format!("wait failed: {e}")),
            }
        }
    }

    /// Run a host-side helper (the AACS cert AKE) and evaluate its exit code /
    /// stdout against [`ExecExpect`]. The helper owns the bus for its own
    /// transport, so this never sets a harness wedge — a `TRANSPORT` result is a
    /// normal (expected-or-not) outcome, not a runner abort.
    fn exec_helper(
        &mut self,
        name: &str,
        ex: &ExecSpec,
        expect: &ExecExpect,
        version: Option<&str>,
    ) -> ExecOutcome {
        let mut checks = Vec::new();
        let (program, args) = match self.resolve_exec(ex) {
            Ok(v) => v,
            Err(e) => {
                return ExecOutcome {
                    checks: vec![Check {
                        pass: false,
                        detail: format!("exec {name:?} config error: {e}"),
                    }],
                    wedged: false,
                    wedge_at: None,
                }
            }
        };
        let (code, stdout) = match self.run_with_timeout(&program, &args) {
            Ok(v) => v,
            Err(e) => {
                return ExecOutcome {
                    checks: vec![Check {
                        pass: false,
                        detail: format!("exec {name:?} ({program:?}): {e}"),
                    }],
                    wedged: false,
                    wedge_at: None,
                }
            }
        };

        // Single expected result (exit code + stdout marker).
        if let Some(want) = expect.result {
            let (ec, mk) = want.contract();
            checks.push(Check {
                pass: code == ec && stdout.contains(mk),
                detail: format!("exec result {want:?} (exit {code}, want {ec}+{mk:?})"),
            });
        }
        // Any-of results (disc-type ambiguity, e.g. AACS-1.0 cert on a 2.0 disc).
        if let Some(list) = &expect.any_of {
            let ok = list.iter().any(|r| {
                let (ec, mk) = r.contract();
                code == ec && stdout.contains(mk)
            });
            checks.push(Check {
                pass: ok,
                detail: format!("exec result any_of {list:?} (exit {code})"),
            });
        }
        // Raw exit-code / stdout assertions (generic helpers).
        if let Some(ec) = expect.exit_code {
            checks.push(Check {
                pass: code == ec,
                detail: format!("exit code {code} (want {ec})"),
            });
        }
        if let Some(sub) = &expect.stdout_contains {
            checks.push(Check {
                pass: stdout.contains(sub),
                detail: format!("stdout contains {sub:?}"),
            });
        }
        // VID field checks — parse the hex and reuse the data-assertion engine so
        // a cert-AKE VID can be `equals_capture`d against the bare-read VID.
        let want_vid = expect.vid.is_some() || expect.result == Some(crate::script::AkeResult::Vid);
        if want_vid {
            match Self::parse_vid(&stdout) {
                Some(bytes) => {
                    if let Some(vexp) = &expect.vid {
                        let e = Expect {
                            data: Some(vexp.clone()),
                            ..Default::default()
                        };
                        self.eval_data(&[bytes], &e, version, &mut checks);
                    }
                }
                None => {
                    if expect.vid.is_some() {
                        checks.push(Check {
                            pass: false,
                            detail: "expected a VID in stdout, none parsed".into(),
                        });
                    }
                }
            }
        }

        ExecOutcome {
            checks,
            wedged: false,
            wedge_at: None,
        }
    }

    /// Execute ONE command (a knock or raw CDB) `repeat` times, collecting every
    /// reply, and evaluate its `expect`ations. Returns the per-assertion checks
    /// plus whether the drive wedged. Shared by plain steps, iterated steps and
    /// sequence sub-steps — the single evaluation core.
    #[allow(clippy::too_many_arguments)]
    fn exec_command(
        &mut self,
        name: &str,
        knock: &Option<Knock>,
        raw: &Option<String>,
        dir_in: Dir,
        alloc_in: Option<Num>,
        repeat_in: Option<usize>,
        report: bool,
        expect: &Expect,
        version: Option<&str>,
    ) -> ExecOutcome {
        let mut checks = Vec::new();
        let (cdb_bytes, dir, alloc) = match self.build_cmd(name, knock, raw, dir_in, alloc_in) {
            Ok(v) => v,
            Err(e) => {
                return ExecOutcome {
                    checks: vec![Check {
                        pass: false,
                        detail: format!("build error: {e}"),
                    }],
                    wedged: false,
                    wedge_at: None,
                }
            }
        };
        // Before a disc read (0xAD / READ(10)), poll TEST UNIT READY so a
        // spun-down disc spins up instead of causing a false timeout — the
        // spin-down was itself a source of the intermittent 0xAD hangs.
        let is_disc_read = Self::is_disc_read(&cdb_bytes);
        if is_disc_read {
            match self.wait_ready() {
                ReadyState::Ready => {}
                ReadyState::NotReady => checks.push(Check {
                    pass: true,
                    detail: format!(
                        "TEST UNIT READY not GOOD after {} poll(s) — reading anyway",
                        self.pacing.tur_retries
                    ),
                }),
                ReadyState::Wedged => {
                    return ExecOutcome {
                        checks: vec![Check {
                            pass: false,
                            detail: "WEDGED polling TEST UNIT READY".into(),
                        }],
                        wedged: true,
                        wedge_at: Some(format!("{name} (TEST UNIT READY)")),
                    };
                }
            }
        }

        // Issue the command `repeat` times (default 1), collecting each reply.
        let repeat = repeat_in.unwrap_or(1).max(1);
        let is_toggle = Self::is_flag_toggle(&cdb_bytes);
        let mut datas: Vec<Vec<u8>> = Vec::with_capacity(repeat);
        let mut first_status = 0u8;
        let mut first_sense = None;
        let mut status_ok = true;
        for i in 0..repeat {
            let r = call_cdb(self.scsi, &cdb_bytes, dir, alloc, self.timeout_ms);
            if r.wedged {
                // A timeout/hang is a hard wedge — surfaced as a failing, wedged
                // outcome, never a silent skip. This is what catches the
                // deny→approve→read hang.
                return ExecOutcome {
                    checks: vec![Check {
                        pass: false,
                        detail: format!("command WEDGED (no SCSI reply) on read {}", i + 1),
                    }],
                    wedged: true,
                    wedge_at: Some(name.to_string()),
                };
            }
            if i == 0 {
                first_status = r.status;
                first_sense = r.sense;
            }
            let ok = match expect.status {
                StatusExp::Good => r.status == STATUS_GOOD,
                StatusExp::CheckCondition => r.status == STATUS_CHECK_CONDITION,
                StatusExp::Any => true,
            };
            status_ok &= ok;
            datas.push(r.data);
            // Pace: don't fire the next command back-to-back. A flag toggle gets
            // a longer settle so the flag write + engine state land first.
            if is_toggle {
                Self::sleep(self.pacing.settle_ms);
            } else {
                Self::sleep(self.pacing.delay_ms);
            }
        }

        // Informational report step: print the first reply, never assert.
        if report {
            let hex: String = datas[0].iter().map(|b| format!("{b:02x}")).collect();
            checks.push(Check {
                pass: true,
                detail: format!(
                    "report: status 0x{first_status:02x}, {} bytes: {hex}",
                    datas[0].len()
                ),
            });
            return ExecOutcome {
                checks,
                wedged: false,
                wedge_at: None,
            };
        }

        // Status expectation (across all reads).
        let sense_note = match first_sense {
            Some((k, a, q)) => format!(" (sense {k:02x}/{a:02x}/{q:02x})"),
            None => String::new(),
        };
        let rep_note = if repeat > 1 {
            format!(" x{repeat}")
        } else {
            String::new()
        };
        checks.push(Check {
            pass: status_ok,
            detail: format!(
                "status 0x{first_status:02x}{rep_note} vs {:?}{sense_note}",
                expect.status
            ),
        });

        // Sense-key expectation (e.g. ILLEGAL REQUEST on a denied read).
        if let Some(want) = expect.sense_key {
            let got = first_sense.map(|(k, _, _)| k);
            checks.push(Check {
                pass: got == Some(want.as_u8()),
                detail: match got {
                    Some(k) => format!("sense key 0x{k:02x} (want 0x{:02x})", want.as_u8()),
                    None => format!("no sense (want key 0x{:02x})", want.as_u8()),
                },
            });
        }

        // Data expectations.
        self.eval_data(&datas, expect, version, &mut checks);

        // Flag-table persistence.
        if let Some(flag) = &expect.flag {
            let fw = self.read_flag_window();
            if fw.wedged {
                return ExecOutcome {
                    checks,
                    wedged: true,
                    wedge_at: Some(format!("{name} (flag readback)")),
                };
            }
            let off = flag.subfn.as_usize();
            let got = fw.data.get(off).copied();
            let want = flag.equals.as_u8();
            let ok = got == Some(want);
            checks.push(Check {
                pass: ok,
                detail: match got {
                    Some(b) => format!("flag[{off}]=0x{b:02x} (want 0x{want:02x})"),
                    None => format!("flag[{off}] unreadable (want 0x{want:02x})"),
                },
            });
        }

        ExecOutcome {
            checks,
            wedged: false,
            wedge_at: None,
        }
    }

    /// Run one iteration of a step's command form: either the ordered `sequence`
    /// of sub-commands, or the single top-level command. Returns the iteration's
    /// checks and whether it wedged (a wedge short-circuits the sequence).
    fn run_one_iteration(
        &mut self,
        step: &Step,
        version: Option<&str>,
    ) -> (Vec<Check>, bool, Option<String>) {
        if let Some(seq) = &step.sequence {
            let mut checks = Vec::new();
            for sub in seq {
                let ExecOutcome {
                    checks: sub_checks,
                    wedged,
                    wedge_at,
                } = self.run_command(
                    &sub.name,
                    &sub.knock,
                    &sub.raw,
                    &sub.exec,
                    sub.dir,
                    sub.alloc,
                    sub.repeat,
                    false,
                    &sub.expect,
                    &sub.expect_exec,
                    version,
                );
                for c in sub_checks {
                    checks.push(Check {
                        pass: c.pass,
                        detail: format!("{}: {}", sub.name, c.detail),
                    });
                }
                if wedged {
                    return (checks, true, wedge_at);
                }
            }
            (checks, false, None)
        } else {
            let out = self.run_command(
                &step.name,
                &step.knock,
                &step.raw,
                &step.exec,
                step.dir,
                step.alloc,
                step.repeat,
                step.report.unwrap_or(false),
                &step.expect,
                &step.expect_exec,
                version,
            );
            (out.checks, out.wedged, out.wedge_at)
        }
    }

    /// Run an iterated / sequence step: the command form runs `iterations` times
    /// (default 1), each iteration evaluated independently. Reports `X/N` passed
    /// and passes only when `X == N`. Between iterations the identity wedge-guard
    /// is re-asserted; a wedge (mid-command or on the guard) aborts with a wedged
    /// report so the caller exits 2 rather than hammering a dead drive.
    fn run_iterated(&mut self, step: &Step, version: Option<&str>) -> StepReport {
        let declared = step.iterations.unwrap_or(1).max(1);
        let iters = self.max_iters.map_or(declared, |m| declared.min(m.max(1)));
        let mut checks = Vec::new();
        let mut passed = 0usize;

        for it in 1..=iters {
            let (iter_checks, wedged, wedge_at) = self.run_one_iteration(step, version);
            let ok = !wedged && iter_checks.iter().all(|c| c.pass);
            if ok {
                passed += 1;
            } else {
                // Surface only the failing detail lines, tagged with the iteration.
                for c in iter_checks.iter().filter(|c| !c.pass) {
                    checks.push(Check {
                        pass: false,
                        detail: format!("iter {it}/{iters}: {}", c.detail),
                    });
                }
            }
            if wedged {
                checks.insert(
                    0,
                    Check {
                        pass: false,
                        detail: format!(
                            "{passed}/{iters} iteration(s) passed (WEDGED on iter {it})"
                        ),
                    },
                );
                return StepReport::wedged(
                    step.name.clone(),
                    step.phase,
                    checks,
                    wedge_at.unwrap_or_else(|| format!("{} (iter {it})", step.name)),
                );
            }
            // Between-iteration hygiene: re-assert the wedge guard, abort (exit 2)
            // if the drive stopped answering — don't hammer a wedged drive.
            if it < iters {
                if let Alive::Wedged = self.alive() {
                    checks.insert(
                        0,
                        Check {
                            pass: false,
                            detail: format!(
                                "{passed}/{iters} iteration(s) passed (guard WEDGED after iter {it})"
                            ),
                        },
                    );
                    return StepReport::wedged(
                        step.name.clone(),
                        step.phase,
                        checks,
                        format!("{} (guard after iter {it})", step.name),
                    );
                }
            }
        }

        checks.insert(
            0,
            Check {
                pass: passed == iters,
                detail: format!("{passed}/{iters} iteration(s) passed"),
            },
        );
        StepReport::issued(step.name.clone(), step.phase, checks)
    }

    /// Run the whole script (batch): collect every [`StepReport`] and return them.
    /// `run_disc` includes disc-phase steps. Used by the unit tests; the CLI uses
    /// [`Runner::run_live`] for streamed output + the disc-insertion pause.
    #[allow(dead_code)] // exercised by the unit tests; the bin uses run_live.
    pub fn run(&mut self, script: &Script, run_disc: bool, version: Option<&str>) -> RunResult {
        self.run_live(script, run_disc, version, |_| {}, || {})
    }

    /// Run the whole script with two callbacks: `on_step` fires as each
    /// [`StepReport`] is produced (so the CLI can print it LIVE and flush), and
    /// `pause_before_disc` fires ONCE, immediately before the first disc-phase step
    /// actually runs (so the CLI can prompt the operator to insert a disc). Both
    /// are no-ops in the batch [`Runner::run`] path.
    pub fn run_live(
        &mut self,
        script: &Script,
        run_disc: bool,
        version: Option<&str>,
        mut on_step: impl FnMut(&StepReport),
        mut pause_before_disc: impl FnMut(),
    ) -> RunResult {
        let mut reports = Vec::new();
        let mut any_fail = false;
        let mut paused = false;
        // Set once the first disc step is reached: Some(true) = disc present,
        // Some(false) = tray empty (skip all disc steps with a clear reason).
        let mut disc_present: Option<bool> = None;

        for step in &script.steps {
            if step.phase == Phase::Disc && !run_disc {
                continue;
            }
            // First disc step we are about to run: let the caller pause and prompt
            // for a disc before any disc command is issued.
            if step.phase == Phase::Disc && !paused {
                pause_before_disc();
                paused = true;
            }
            // Disc-presence precheck (once, before the first disc command). An
            // empty tray skips every disc step with a reason instead of firing a
            // 0xAD that would time out and masquerade as a firmware wedge.
            if self.disc_precheck && step.phase == Phase::Disc && disc_present.is_none() {
                match self.disc_present() {
                    ReadyState::Ready => disc_present = Some(true),
                    ReadyState::NotReady => disc_present = Some(false),
                    ReadyState::Wedged => {
                        let r = StepReport::wedged(
                            "disc precheck (READ CAPACITY)".into(),
                            Phase::Disc,
                            vec![Check {
                                pass: false,
                                detail: "WEDGED on READ CAPACITY precheck".into(),
                            }],
                            "disc precheck".into(),
                        );
                        on_step(&r);
                        reports.push(r);
                        return RunResult {
                            steps: reports,
                            outcome: RunOutcome::Wedged,
                        };
                    }
                }
            }
            if step.phase == Phase::Disc && disc_present == Some(false) {
                let r = StepReport::skipped(
                    step.name.clone(),
                    step.phase,
                    "no disc loaded (READ CAPACITY reports empty tray)".into(),
                );
                on_step(&r);
                reports.push(r);
                continue;
            }
            // Skip an `exec` step gracefully when its AKE config is absent —
            // neither pass nor fail, no hardware touched, no wedge guard.
            if let Some(reason) = self.step_skip_reason(step) {
                let r = StepReport::skipped(step.name.clone(), step.phase, reason);
                on_step(&r);
                reports.push(r);
                continue;
            }
            let report = self.run_step(step, version);
            on_step(&report);
            if report.wedged {
                reports.push(report);
                return RunResult {
                    steps: reports,
                    outcome: RunOutcome::Wedged,
                };
            }
            if !report.passed() {
                any_fail = true;
            }
            reports.push(report);

            // Wedge guard after every step.
            if let Alive::Wedged = self.alive() {
                if let Some(last) = reports.last_mut() {
                    last.wedged = true;
                    last.wedge_at = Some(format!("after {}", step.name));
                    on_step(last);
                }
                return RunResult {
                    steps: reports,
                    outcome: RunOutcome::Wedged,
                };
            }
        }

        let outcome = if any_fail {
            RunOutcome::Failure
        } else {
            RunOutcome::AllPass
        };
        RunResult {
            steps: reports,
            outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockTransport;

    fn is_knock(cdb: &[u8], sub: u8) -> bool {
        cdb.len() >= 5 && cdb[0..4] == [0x3C, 0x0E, 0xC0, 0xDE] && cdb[4] == sub
    }

    /// A mock that answers identity with a version, and DumpAll at the flag base
    /// with a 64-byte window whose byte[subfn] mirrors the last toggled state —
    /// here pre-seeded so flag[2]=0xFF and flag[4]=0x01.
    fn healthy_drive(version: &str) -> MockTransport {
        let mut window = vec![0u8; 64];
        window[2] = 0xFF; // Speed flag
        window[3] = 0x01; // Region flag
        window[4] = 0x01; // Raw Read flag
        let id = format!("freemkv {version}").into_bytes();
        MockTransport::new()
            .on_data(|c| is_knock(c, 0x09), window) // DumpAll window
            .on_data(move |c| is_knock(c, 0x01), id.clone()) // identity
    }

    fn script() -> Script {
        Script::from_yaml(
            r#"
expect_version: "freemkv 0.6.6"
steps:
  - name: identity
    phase: discless
    knock: { subfn: 0x01 }
    expect:
      status: good
      data: { starts_with_ascii: "freemkv", contains_version: true }
  - name: speed
    phase: discless
    knock: { subfn: 0x02, state: 0xFF }
    expect:
      flag: { subfn: 0x02, equals: 0xFF }
  - name: rawread
    phase: discless
    knock: { subfn: 0x04, state: 0x01 }
    expect:
      flag: { subfn: 0x04, equals: 0x01 }
  - name: disc-only
    phase: disc
    raw: "28 00 00 00 00 00 00 00 01 00"
    alloc: 2048
    expect:
      data: { nonzero: true }
"#,
        )
        .unwrap()
    }

    #[test]
    fn healthy_discless_run_all_pass() {
        let s = script();
        let mut t = healthy_drive("0.6.6");
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, Some("freemkv 0.6.6"));
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
        // disc step skipped in discless mode.
        assert_eq!(res.steps.len(), 3);
        assert!(res.steps.iter().all(|s| s.passed()));
    }

    #[test]
    fn wrong_flag_is_failure_not_wedge() {
        let s = script();
        // Window byte[2]=0x00 → Speed flag mismatch.
        let mut window = vec![0u8; 64];
        window[4] = 0x01;
        let mut t = MockTransport::new()
            .on_data(|c| is_knock(c, 0x09), window)
            .on_data(|c| is_knock(c, 0x01), b"freemkv 0.6.6".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, Some("freemkv 0.6.6"));
        assert_eq!(res.outcome, RunOutcome::Failure);
    }

    #[test]
    fn wedge_on_command_aborts_with_exit_2() {
        let s = script();
        // Identity works once (for early steps) but Speed knock wedges the bus.
        let mut t = MockTransport::new()
            .on_wedge(|c| is_knock(c, 0x02))
            .on_data(|c| is_knock(c, 0x09), vec![0u8; 64])
            .on_data(|c| is_knock(c, 0x01), b"freemkv 0.6.6".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, Some("freemkv 0.6.6"));
        assert_eq!(res.outcome, RunOutcome::Wedged);
        assert_eq!(res.outcome.exit_code(), 2);
        assert!(res.steps.last().unwrap().wedged);
    }

    #[test]
    fn guard_detects_wedge_after_step() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: oem
    phase: discless
    raw: "3c 00 00 00 00 00 00 00 00 00"
    dir: none
    expect: { status: any }
"#,
        )
        .unwrap();
        // The OEM passthrough "succeeds", but the drive is dead afterwards:
        // identity knock AND INQUIRY both wedge → guard trips.
        let mut t = MockTransport::new()
            .on_wedge(|c| is_knock(c, 0x01))
            .on_wedge(|c| c.first() == Some(&0x12));
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, None);
        assert_eq!(res.outcome, RunOutcome::Wedged);
    }

    #[test]
    fn disc_phase_included_with_flag() {
        let s = script();
        let mut t =
            healthy_drive("0.6.6").on_data(|c| c.first() == Some(&0x28), vec![0xABu8; 2048]); // READ(10)
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, Some("freemkv 0.6.6"));
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
        assert_eq!(res.steps.len(), 4);
    }

    /// A bare `0xAD` reply framed like the real drive: `00 22 00 00 <16 VID>
    /// <16 MAC>`, so the VID is the window at [4..20].
    fn ad_reply(vid: u8) -> Vec<u8> {
        let mut r = vec![0x00, 0x22, 0x00, 0x00];
        r.extend_from_slice(&[vid; 16]); // VID
        r.extend_from_slice(&[0xEE; 16]); // MAC (ignored)
        r
    }

    /// The full disc-phase Raw Read contract: deny → unlock (capture VID) →
    /// idempotent repeat (stable + equals) → revert (deny) → re-enable (same VID).
    #[test]
    fn disc_rawread_contract_passes_against_stateful_mock() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: deny-off
    phase: disc
    knock: { subfn: 0x04, state: 0x00 }
    expect: { status: good }
  - name: deny-ad
    phase: disc
    raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
    alloc: 36
    expect: { status: check_condition, sense_key: 0x05 }
  - name: unlock-on
    phase: disc
    knock: { subfn: 0x04, state: 0x01 }
    expect: { status: good }
  - name: unlock-ad
    phase: disc
    raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
    alloc: 36
    expect:
      status: good
      data: { slice: { offset: 4, len: 16 }, nonzero: true, min_len: 16, capture: vid }
  - name: idempotent-ad
    phase: disc
    raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
    alloc: 36
    repeat: 4
    expect:
      status: good
      data: { slice: { offset: 4, len: 16 }, stable: true, equals_capture: vid }
"#,
        )
        .unwrap();

        // Stateful mock: an OFF/ON flag (byte in the flag window) drives whether
        // the bare 0xAD denies or returns the VID.
        struct Drive {
            raw_on: bool,
        }
        impl ScsiTransport for Drive {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _t: u32,
            ) -> libfreemkv::error::Result<libfreemkv::scsi::ScsiResult> {
                use libfreemkv::scsi::ScsiResult;
                // Knock 04 <state>: latch the flag, GOOD, 64-byte reply.
                if cdb.first() == Some(&0x3C) && cdb.get(4) == Some(&0x04) {
                    self.raw_on = cdb.get(5) == Some(&0x01);
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: 0,
                        sense: [0; 32],
                    });
                }
                // Identity knock (wedge guard): answer with the magic.
                if cdb.first() == Some(&0x3C) && cdb.get(4) == Some(&0x01) {
                    let m = b"freemkv 0.6.6";
                    let n = m.len().min(data.len());
                    data[..n].copy_from_slice(&m[..n]);
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: n,
                        sense: [0; 32],
                    });
                }
                // Bare 0xAD: VID when unlocked, else ILLEGAL REQUEST.
                if cdb.first() == Some(&0xAD) {
                    if self.raw_on {
                        let r = ad_reply(0x9A);
                        let n = r.len().min(data.len());
                        data[..n].copy_from_slice(&r[..n]);
                        return Ok(ScsiResult {
                            status: 0,
                            bytes_transferred: n,
                            sense: [0; 32],
                        });
                    }
                    let mut sense = [0u8; 32];
                    sense[0] = 0x70;
                    sense[2] = 0x05; // ILLEGAL REQUEST
                    return Ok(ScsiResult {
                        status: 0x02,
                        bytes_transferred: 0,
                        sense,
                    });
                }
                let n = data.len();
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0; 32],
                })
            }
        }

        let mut t = Drive { raw_on: false };
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
    }

    #[test]
    fn equals_capture_mismatch_fails() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: capture
    phase: discless
    raw: "ad"
    alloc: 36
    expect: { status: any, data: { slice: { offset: 4, len: 4 }, capture: vid } }
  - name: compare
    phase: discless
    raw: "ad"
    alloc: 36
    expect: { status: any, data: { slice: { offset: 4, len: 4 }, equals_capture: vid } }
"#,
        )
        .unwrap();
        // First AD returns VID 0x11.., second returns 0x22.. → equals_capture fails.
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Flip {
            n: AtomicUsize,
        }
        impl ScsiTransport for Flip {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _t: u32,
            ) -> libfreemkv::error::Result<libfreemkv::scsi::ScsiResult> {
                use libfreemkv::scsi::ScsiResult;
                if cdb.first() == Some(&0xAD) {
                    let v = if self.n.fetch_add(1, Ordering::SeqCst) == 0 {
                        0x11
                    } else {
                        0x22
                    };
                    let r = ad_reply(v);
                    let k = r.len().min(data.len());
                    data[..k].copy_from_slice(&r[..k]);
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: k,
                        sense: [0; 32],
                    });
                }
                // Wedge-guard identity: keep alive.
                if cdb.first() == Some(&0x3C) && cdb.get(4) == Some(&0x01) {
                    let m = b"freemkv";
                    let k = m.len().min(data.len());
                    data[..k].copy_from_slice(&m[..k]);
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: k,
                        sense: [0; 32],
                    });
                }
                let k = data.len();
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: k,
                    sense: [0; 32],
                })
            }
        }
        let mut t = Flip {
            n: AtomicUsize::new(0),
        };
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, None);
        assert_eq!(res.outcome, RunOutcome::Failure);
    }

    #[test]
    fn report_step_always_passes_and_never_asserts() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: capacity
    phase: discless
    raw: "25 00 00 00 00 00 00 00 00 00"
    alloc: 8
    report: true
    expect: { status: check_condition }
"#,
        )
        .unwrap();
        // Even though the mock returns GOOD (violating the declared expect), a
        // report step ignores expectations and passes.
        let mut t = MockTransport::new();
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, None);
        assert_eq!(res.outcome, RunOutcome::AllPass);
        assert!(res.steps[0].checks[0].detail.contains("report:"));
    }

    #[test]
    fn slice_out_of_range_is_a_failure() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: short
    phase: discless
    raw: "ad"
    alloc: 4
    expect: { status: any, data: { slice: { offset: 4, len: 16 }, nonzero: true } }
"#,
        )
        .unwrap();
        // Response is only 4 bytes (zero-filled) → the [4..20] window is out of range.
        let mut t = MockTransport::new();
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, None);
        assert_eq!(res.outcome, RunOutcome::Failure);
    }

    /// A drive that models the `04 01` bare-read intermittency bug: once a bare
    /// `0xAD` has been DENIED under OEM enforce (i.e. after a `04 00` deny), the
    /// drive is "armed" and the *next* `04 01`+`0xAD` HANGS (wedges) instead of
    /// returning the VID. With `buggy: false` it is the fixed firmware — the
    /// unlock read always returns the VID regardless of a prior deny.
    struct RawReadDrive {
        raw_on: bool,
        armed: bool,
        buggy: bool,
    }
    impl RawReadDrive {
        fn new(buggy: bool) -> Self {
            Self {
                raw_on: false,
                armed: false,
                buggy,
            }
        }
    }
    impl ScsiTransport for RawReadDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _t: u32,
        ) -> libfreemkv::error::Result<libfreemkv::scsi::ScsiResult> {
            use libfreemkv::scsi::ScsiResult;
            // Raw Read knock 04 <state>: latch the flag; GOOD, empty reply.
            if cdb.first() == Some(&0x3C) && cdb.get(4) == Some(&0x04) {
                self.raw_on = cdb.get(5) == Some(&0x01);
                return Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: 0,
                    sense: [0; 32],
                });
            }
            // Identity knock (wedge guard): answer with the magic.
            if cdb.first() == Some(&0x3C) && cdb.get(4) == Some(&0x01) {
                let m = b"freemkv 0.6.6";
                let n = m.len().min(data.len());
                data[..n].copy_from_slice(&m[..n]);
                return Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0; 32],
                });
            }
            // Bare 0xAD read.
            if cdb.first() == Some(&0xAD) {
                if !self.raw_on {
                    // OEM enforce → deny, and ARM the latent hang.
                    self.armed = true;
                    let mut sense = [0u8; 32];
                    sense[0] = 0x70;
                    sense[2] = 0x05; // ILLEGAL REQUEST
                    return Ok(ScsiResult {
                        status: 0x02,
                        bytes_transferred: 0,
                        sense,
                    });
                }
                if self.buggy && self.armed {
                    // THE BUG: unlocked, but a prior deny wedges this read.
                    return Err(libfreemkv::error::Error::ScsiError {
                        opcode: 0xAD,
                        status: libfreemkv::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                        sense: None,
                    });
                }
                let r = ad_reply(0x9A);
                let n = r.len().min(data.len());
                data[..n].copy_from_slice(&r[..n]);
                return Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0; 32],
                });
            }
            let n = data.len();
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0; 32],
            })
        }
    }

    /// The deny→approve→read hang repro sequence (small `iterations` for speed).
    fn disc_bug_repro_script(iterations: usize) -> Script {
        Script::from_yaml(&format!(
            r#"
steps:
  - name: "DISC bug-repro deny→approve→read"
    phase: disc
    iterations: {iterations}
    sequence:
      - name: "unlock 04 01"
        knock: {{ subfn: 0x04, state: 0x01 }}
        expect: {{ status: good }}
      - name: "0xAD returns VID"
        raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
        alloc: 36
        expect:
          status: good
          data: {{ slice: {{ offset: 4, len: 16 }}, nonzero: true }}
      - name: "deny 04 00"
        knock: {{ subfn: 0x04, state: 0x00 }}
        expect: {{ status: good }}
      - name: "0xAD denied"
        raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
        alloc: 36
        expect: {{ status: check_condition, sense_key: 0x05 }}
      - name: "re-unlock 04 01"
        knock: {{ subfn: 0x04, state: 0x01 }}
        expect: {{ status: good }}
      - name: "0xAD returns VID again (the hang point)"
        raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
        alloc: 36
        expect:
          status: good
          data: {{ slice: {{ offset: 4, len: 16 }}, nonzero: true }}
"#
        ))
        .unwrap()
    }

    #[test]
    fn disc_bug_repro_hang_is_caught_as_wedge_exit_2() {
        let s = disc_bug_repro_script(3);
        let mut t = RawReadDrive::new(true); // buggy firmware
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        // The deny→approve→read hang MUST surface as a wedge (exit 2), never a
        // silent pass/skip. This is the test that would have caught the bug.
        assert_eq!(res.outcome, RunOutcome::Wedged, "{:#?}", res.steps);
        assert_eq!(res.outcome.exit_code(), 2);
        assert!(res.steps.last().unwrap().wedged);
    }

    #[test]
    fn disc_bug_repro_passes_on_fixed_firmware() {
        let s = disc_bug_repro_script(3);
        let mut t = RawReadDrive::new(false); // fixed firmware
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
        // The summary check reports every iteration passed.
        assert!(res.steps[0].checks[0]
            .detail
            .contains("3/3 iteration(s) passed"));
    }

    #[test]
    fn reliability_reports_pass_rate_on_intermittent_drive() {
        // A single-command `iterations` step whose bare 0xAD alternates between a
        // nonzero VID (pass) and an all-zero reply (nonzero check fails), so the
        // pass-rate must read 3/5 rather than aborting on the first failure.
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Intermittent {
            n: AtomicUsize,
        }
        impl ScsiTransport for Intermittent {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _t: u32,
            ) -> libfreemkv::error::Result<libfreemkv::scsi::ScsiResult> {
                use libfreemkv::scsi::ScsiResult;
                if cdb.first() == Some(&0xAD) {
                    let k = self.n.fetch_add(1, Ordering::SeqCst);
                    let reply = if k.is_multiple_of(2) {
                        ad_reply(0x9A) // nonzero VID → pass
                    } else {
                        vec![0u8; 36] // all-zero → nonzero check fails
                    };
                    let n = reply.len().min(data.len());
                    data[..n].copy_from_slice(&reply[..n]);
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: n,
                        sense: [0; 32],
                    });
                }
                if cdb.first() == Some(&0x3C) && cdb.get(4) == Some(&0x01) {
                    let m = b"freemkv 0.6.6";
                    let n = m.len().min(data.len());
                    data[..n].copy_from_slice(&m[..n]);
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: n,
                        sense: [0; 32],
                    });
                }
                let n = data.len();
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0; 32],
                })
            }
        }
        let s = Script::from_yaml(
            r#"
steps:
  - name: "reliability bare 0xAD x5"
    phase: disc
    iterations: 5
    raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
    alloc: 36
    expect:
      status: good
      data: { slice: { offset: 4, len: 16 }, nonzero: true }
"#,
        )
        .unwrap();
        let mut t = Intermittent {
            n: AtomicUsize::new(0),
        };
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        // Intermittent ⇒ FAIL overall, but the pass-rate is surfaced (not aborted).
        assert_eq!(res.outcome, RunOutcome::Failure);
        assert!(
            res.steps[0].checks[0]
                .detail
                .contains("3/5 iteration(s) passed"),
            "summary was {:?}",
            res.steps[0].checks[0].detail
        );
    }

    #[test]
    fn reliability_all_pass_reports_full_count() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: "reliability 04 01 x4"
    phase: discless
    iterations: 4
    knock: { subfn: 0x04, state: 0x01 }
    expect: { status: good }
"#,
        )
        .unwrap();
        // Everything GOOD; identity answers the guard with the magic.
        let mut t = MockTransport::new().on_data(|c| is_knock(c, 0x01), b"freemkv 0.6.6".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, false, Some("freemkv 0.6.6"));
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
        assert!(res.steps[0].checks[0]
            .detail
            .contains("4/4 iteration(s) passed"));
    }

    #[test]
    fn between_iteration_guard_wedge_aborts_exit_2() {
        // The command itself succeeds every iteration, but the drive dies on the
        // identity wedge-guard between iterations → abort exit 2, don't hammer.
        let s = Script::from_yaml(
            r#"
steps:
  - name: "guard-wedge x3"
    phase: disc
    iterations: 3
    raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
    alloc: 36
    expect: { status: good, data: { slice: { offset: 4, len: 16 }, nonzero: true } }
"#,
        )
        .unwrap();
        let mut t = MockTransport::new()
            .on_data(|c| c.first() == Some(&0xAD), ad_reply(0x9A))
            .on_wedge(|c| is_knock(c, 0x01)) // identity guard wedges
            .on_wedge(|c| c.first() == Some(&0x12)); // INQUIRY wedges too
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::Wedged);
        assert_eq!(res.outcome.exit_code(), 2);
        assert!(res.steps.last().unwrap().wedged);
    }

    // ── exec (cert AKE) step tests ───────────────────────────────────────────

    use crate::script::{AkeConfig, Pacing};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Write an executable helper script to a unique temp path.
    fn write_helper(body: &str) -> std::path::PathBuf {
        static NONCE: AtomicUsize = AtomicUsize::new(0);
        let n = NONCE.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("hwtest_ake_{}_{n}.sh", std::process::id()));
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    #[test]
    fn run_with_timeout_kills_a_hung_helper() {
        // The concurrency safety net: a helper that never exits is killed at the
        // deadline and reported as a timeout, not left to stall the suite.
        let helper = write_helper("#!/bin/sh\nsleep 30\n");
        let mut t = MockTransport::new();
        let r = Runner::new(&mut t, 0, 1000).with_exec_timeout(200);
        let err = r
            .run_with_timeout(helper.to_str().unwrap(), &[])
            .unwrap_err();
        assert!(err.contains("timed out"), "got: {err}");
    }

    #[test]
    fn run_with_timeout_captures_a_fast_helper() {
        // The happy path still returns the child's exit code and stdout.
        let helper = write_helper("#!/bin/sh\necho hello\nexit 0\n");
        let mut t = MockTransport::new();
        let r = Runner::new(&mut t, 0, 1000).with_exec_timeout(5000);
        let (code, out) = r.run_with_timeout(helper.to_str().unwrap(), &[]).unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("hello"), "got: {out:?}");
    }

    #[test]
    fn exec_program_vid_result_passes_and_parses_vid() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: cert-vid
    phase: disc
    exec:
      program: /bin/sh
      args: ["-c", "echo VID 00112233445566778899aabbccddeeff; exit 0"]
    expect_exec:
      result: vid
      vid: { nonzero: true, min_len: 16, capture: cvid }
"#,
        )
        .unwrap();
        let mut t = MockTransport::new().on_data(|c| is_knock(c, 0x01), b"freemkv".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
    }

    #[test]
    fn exec_rejected_result_and_any_of() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: revoked-denied
    phase: disc
    exec: { program: /bin/sh, args: ["-c", "echo REJECTED; exit 2"] }
    expect_exec: { result: rejected }
  - name: revoked-any-of
    phase: disc
    exec: { program: /bin/sh, args: ["-c", "echo REJECTED; exit 2"] }
    expect_exec: { any_of: [vid, rejected] }
"#,
        )
        .unwrap();
        let mut t = MockTransport::new().on_data(|c| is_knock(c, 0x01), b"freemkv".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
    }

    #[test]
    fn exec_wrong_result_fails() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: expected-vid-got-reject
    phase: disc
    exec: { program: /bin/sh, args: ["-c", "echo REJECTED; exit 2"] }
    expect_exec: { result: vid }
"#,
        )
        .unwrap();
        let mut t = MockTransport::new().on_data(|c| is_knock(c, 0x01), b"freemkv".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::Failure);
    }

    #[test]
    fn exec_cert_matrix_via_ake_config_helper() {
        // The full cert-matrix shape: knock the raw-read mode, then the helper
        // (resolved from AKE config: helper + cert/key + --dev) returns a VID.
        let helper =
            write_helper("#!/bin/sh\necho \"VID aabbccddeeff00112233445566778899\"\nexit 0\n");
        let s = Script::from_yaml(
            r#"
steps:
  - name: "04 02 + revoked cert -> VID (forced accept), x2"
    phase: disc
    iterations: 2
    sequence:
      - name: "accept-any-cert 04 02"
        knock: { subfn: 0x04, state: 0x02 }
        expect: { status: good }
      - name: "cert AKE (revoked) still yields VID"
        exec: { cert: revoked }
        expect_exec:
          result: vid
          vid: { nonzero: true, min_len: 16 }
"#,
        )
        .unwrap();
        let ake = AkeConfig {
            helper: Some(helper.to_string_lossy().into_owned()),
            dev: Some("/dev/null".into()),
            revoked_cert: Some("de".into()),
            revoked_key: Some("ad".into()),
            ..Default::default()
        };
        let mut t = MockTransport::new().on_data(|c| is_knock(c, 0x01), b"freemkv".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms()).with_ake(ake);
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
        std::fs::remove_file(&helper).ok();
    }

    #[test]
    fn exec_cert_step_skipped_when_no_helper() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: cert-needs-helper
    phase: disc
    exec: { cert: valid }
    expect_exec: { result: vid }
"#,
        )
        .unwrap();
        // No AKE config → the cert step is SKIPPED (not failed), outcome AllPass.
        let mut t = MockTransport::new().on_data(|c| is_knock(c, 0x01), b"freemkv".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms());
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::AllPass);
        assert!(res.steps[0].skipped);
        assert!(!res.steps[0].passed());
        assert!(res.steps[0]
            .skip_reason
            .as_ref()
            .unwrap()
            .contains("AKE_HELPER"));
    }

    #[test]
    fn exec_sequence_skipped_when_helper_missing_path() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: matrix-skips
    phase: disc
    sequence:
      - name: mode
        knock: { subfn: 0x04, state: 0x00 }
        expect: { status: good }
      - name: ake
        exec: { cert: valid }
        expect_exec: { result: vid }
"#,
        )
        .unwrap();
        let ake = AkeConfig {
            helper: Some("/nonexistent/cert_vid".into()),
            dev: Some("/dev/null".into()),
            valid_cert: Some("aa".into()),
            valid_key: Some("bb".into()),
            ..Default::default()
        };
        let mut t = MockTransport::new().on_data(|c| is_knock(c, 0x01), b"freemkv".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms()).with_ake(ake);
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::AllPass);
        assert!(res.steps[0].skipped);
        assert!(res.steps[0]
            .skip_reason
            .as_ref()
            .unwrap()
            .contains("not found"));
    }

    // ── TEST UNIT READY polling + pacing tests ───────────────────────────────

    /// A drive that reports NOT READY on TEST UNIT READY until `ready_after`
    /// polls have elapsed (or never, if `never`), answers 0xAD with a VID, and
    /// answers the identity guard. Counts TUR polls for assertions.
    struct TurDrive {
        tur_calls: usize,
        ready_after: usize,
        never: bool,
    }
    impl ScsiTransport for TurDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _t: u32,
        ) -> libfreemkv::error::Result<libfreemkv::scsi::ScsiResult> {
            use libfreemkv::scsi::ScsiResult;
            // TEST UNIT READY: 6 zero bytes.
            if cdb.len() == 6 && cdb.iter().all(|&b| b == 0) {
                self.tur_calls += 1;
                let ready = !self.never && self.tur_calls > self.ready_after;
                if ready {
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: 0,
                        sense: [0; 32],
                    });
                }
                let mut sense = [0u8; 32];
                sense[0] = 0x70;
                sense[2] = 0x02; // NOT READY
                return Ok(ScsiResult {
                    status: 0x02,
                    bytes_transferred: 0,
                    sense,
                });
            }
            if cdb.first() == Some(&0x3C) && cdb.get(4) == Some(&0x01) {
                let m = b"freemkv 0.6.6";
                let n = m.len().min(data.len());
                data[..n].copy_from_slice(&m[..n]);
                return Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0; 32],
                });
            }
            if cdb.first() == Some(&0xAD) {
                let r = ad_reply(0x9A);
                let n = r.len().min(data.len());
                data[..n].copy_from_slice(&r[..n]);
                return Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0; 32],
                });
            }
            let n = data.len();
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0; 32],
            })
        }
    }

    fn ad_read_script() -> Script {
        Script::from_yaml(
            r#"
steps:
  - name: bare-0xAD
    phase: disc
    raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
    alloc: 36
    expect: { status: good, data: { slice: { offset: 4, len: 16 }, nonzero: true } }
"#,
        )
        .unwrap()
    }

    #[test]
    fn tur_polls_until_ready_then_reads() {
        let s = ad_read_script();
        let mut t = TurDrive {
            tur_calls: 0,
            ready_after: 2, // GOOD on the 3rd poll
            never: false,
        };
        {
            let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms()).with_pacing(Pacing {
                delay_ms: 0,
                settle_ms: 0,
                tur_retries: 5,
                tur_backoff_ms: 0,
            });
            let res = r.run(&s, true, None);
            assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
        }
        assert_eq!(t.tur_calls, 3, "should poll until ready");
    }

    #[test]
    fn tur_bounded_when_never_ready_then_proceeds() {
        let s = ad_read_script();
        let mut t = TurDrive {
            tur_calls: 0,
            ready_after: 0,
            never: true,
        };
        {
            let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms()).with_pacing(Pacing {
                delay_ms: 0,
                settle_ms: 0,
                tur_retries: 4,
                tur_backoff_ms: 0,
            });
            let res = r.run(&s, true, None);
            // Best-effort: proceed to the read anyway (which succeeds here).
            assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
            assert!(res.steps[0]
                .checks
                .iter()
                .any(|c| c.detail.contains("TEST UNIT READY not GOOD")));
        }
        assert_eq!(t.tur_calls, 4, "polling must be bounded by tur_retries");
    }

    #[test]
    fn tur_wedge_aborts_exit_2() {
        let s = ad_read_script();
        let mut t = MockTransport::new()
            .on_wedge(|c| c.len() == 6 && c.iter().all(|&b| b == 0)) // TUR wedges
            .on_data(|c| c.first() == Some(&0xAD), ad_reply(0x9A))
            .on_data(|c| is_knock(c, 0x01), b"freemkv 0.6.6".to_vec());
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms()).with_pacing(Pacing {
            delay_ms: 0,
            settle_ms: 0,
            tur_retries: 3,
            tur_backoff_ms: 0,
        });
        let res = r.run(&s, true, None);
        assert_eq!(res.outcome, RunOutcome::Wedged);
        assert_eq!(res.outcome.exit_code(), 2);
    }

    #[test]
    fn pacing_delays_execute_without_hanging() {
        // Tiny nonzero delays exercise the sleep paths; the run still completes.
        let s = script();
        let mut t = healthy_drive("0.6.6");
        let mut r = Runner::new(&mut t, s.flag_base(), s.timeout_ms()).with_pacing(Pacing {
            delay_ms: 1,
            settle_ms: 1,
            tur_retries: 0,
            tur_backoff_ms: 0,
        });
        let res = r.run(&s, false, Some("freemkv 0.6.6"));
        assert_eq!(res.outcome, RunOutcome::AllPass, "{:#?}", res.steps);
    }
}
