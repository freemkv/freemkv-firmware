//! The data-driven test-script schema (YAML) and its parser.
//!
//! The schema is small and documented at the top of `tests.yaml`. A step names
//! itself, declares its phase, supplies EITHER a structured `knock` OR a `raw`
//! hex CDB, fixes the data direction / allocation length, and lists its
//! expectations. Everything flows through the one call primitive at run time.

use serde::de::{self, Deserializer};
use serde::Deserialize;

/// The freemkv SRAM flag-table base (mirrors `mt1959_build.rs::FLAG_TABLE_BASE`).
pub const DEFAULT_FLAG_BASE: u32 = 0x0200_0E40;
/// Default per-command timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u32 = 30_000;
/// Default inter-command delay (ms) — rapid-fire is a known wedge trigger.
pub const DEFAULT_DELAY_MS: u32 = 200;
/// Default extra settle (ms) after a flag-toggle knock (`02`/`03`/`04`) before
/// the following read — the flag write + engine state need to land.
pub const DEFAULT_SETTLE_MS: u32 = 400;
/// Default TEST UNIT READY polls before a disc read (0 disables polling).
pub const DEFAULT_TUR_RETRIES: u32 = 10;
/// Default base backoff (ms) between TEST UNIT READY polls (grows linearly).
pub const DEFAULT_TUR_BACKOFF_MS: u32 = 150;

/// Command pacing knobs — resolved from the script / env / CLI. All-zero (the
/// [`Default`]) means "no pacing", which is what the mock unit tests use so
/// `cargo test` stays instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pacing {
    /// Sleep this long after every SCSI command.
    pub delay_ms: u32,
    /// Extra sleep after a flag-toggle knock (`02`/`03`/`04`).
    pub settle_ms: u32,
    /// TEST UNIT READY polls before a disc read (`0` = polling off).
    pub tur_retries: u32,
    /// Base backoff between TUR polls (grows linearly with the attempt).
    pub tur_backoff_ms: u32,
}

/// An integer field that accepts a YAML integer (`64`), a `0x`-prefixed hex
/// integer, or a hex/decimal string (`"0x40"`, `"64"`) — so a human can write
/// `0x02` for a sub-function without fighting the YAML int resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Num(pub u64);

impl Num {
    /// Value as `u32` (for addresses / flag base).
    pub fn as_u32(self) -> u32 {
        self.0 as u32
    }
    /// Value as `u8` (for sub-function / state bytes).
    pub fn as_u8(self) -> u8 {
        self.0 as u8
    }
    /// Value as `usize` (for allocation lengths).
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl<'de> Deserialize<'de> for Num {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(n) => Ok(Num(n)),
            Raw::Str(s) => {
                let t = s.trim();
                let v = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16)
                } else {
                    t.parse::<u64>()
                };
                v.map(Num)
                    .map_err(|e| de::Error::custom(format!("bad number {s:?}: {e}")))
            }
        }
    }
}

/// Which bring-up phase a step belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Runs with no medium loaded (P0..P5).
    Discless,
    /// Requires a disc; only runs when `--disc` is passed.
    Disc,
}

/// The data phase for a step's command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Dir {
    /// Data flows device -> host. The correct (and default) direction for a knock.
    #[default]
    FromDevice,
    /// No data phase.
    None,
    /// Data flows host -> device.
    ToDevice,
}

/// A structured freemkv knock: the runner assembles `3C 0E C0 DE <subfn> <state>
/// <alloc-24> 00`, or a DumpAll frame when `addr` is present.
#[derive(Debug, Clone, Deserialize)]
pub struct Knock {
    /// Sub-function selector (`cdb[4]`), e.g. `0x02` Speed.
    pub subfn: Num,
    /// Per-feature state byte (`cdb[5]`); defaults to `0x00`.
    #[serde(default)]
    pub state: Option<Num>,
    /// For DumpAll (subfn `0x09`): the 32-bit RAM address to read.
    #[serde(default)]
    pub addr: Option<Num>,
}

/// Expected SCSI status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StatusExp {
    /// GOOD (`0x00`) — the default when `status` is omitted.
    #[default]
    Good,
    /// CHECK CONDITION (`0x02`) with sense.
    CheckCondition,
    /// Accept any non-wedged status.
    Any,
}

/// A flag-table expectation: after the step, DumpAll at the flag base and assert
/// the byte at offset `subfn` equals `equals`.
#[derive(Debug, Clone, Deserialize)]
pub struct FlagExp {
    /// Flag-table offset (== the toggle's sub-function number).
    pub subfn: Num,
    /// The byte value the flag must hold.
    pub equals: Num,
}

/// A byte-window `[offset, offset+len)` within the response — e.g. the 16-byte
/// VID at `[4..20]` of a `READ DISC STRUCTURE` reply. When present on a
/// [`DataExp`], the `nonzero` / `min_len` / `stable` / `capture` /
/// `equals_capture` checks operate on this window instead of the whole response.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Slice {
    /// Start offset in the response.
    pub offset: usize,
    /// Window length in bytes.
    pub len: usize,
}

/// Assertions on the returned data-in bytes.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DataExp {
    /// Restrict the field-checks below to this window of the response.
    #[serde(default)]
    pub slice: Option<Slice>,
    /// Data must start with this ASCII string (whole response).
    #[serde(default)]
    pub starts_with_ascii: Option<String>,
    /// Data must start with these hex bytes (whole response).
    #[serde(default)]
    pub starts_with_hex: Option<String>,
    /// Data must contain this ASCII substring (whole response).
    #[serde(default)]
    pub contains_ascii: Option<String>,
    /// Data must contain the resolved expected version string (CLI
    /// `--expect-version` else the script's `expect_version`; whole response).
    #[serde(default)]
    pub contains_version: Option<bool>,
    /// The (sliced) data must contain at least one non-zero byte.
    #[serde(default)]
    pub nonzero: Option<bool>,
    /// The (sliced) data must be at least this many bytes.
    #[serde(default)]
    pub min_len: Option<usize>,
    /// With `repeat > 1`: the (sliced) data must be IDENTICAL across every read
    /// (proves a sticky/idempotent flag, not a single-use one).
    #[serde(default)]
    pub stable: Option<bool>,
    /// Store the (sliced) data under this name for later `equals_capture`.
    #[serde(default)]
    pub capture: Option<String>,
    /// The (sliced) data must equal a value stored earlier under this name.
    #[serde(default)]
    pub equals_capture: Option<String>,
}

/// The result a `cert`-driven [`ExecSpec`] expects from the AKE helper, mapped
/// by the runner to the helper's contract: `Vid` → exit 0 + `"VID <hex32>"`,
/// `Rejected` → exit 2 + `"REJECTED"`, `NoVid` → exit 3 + `"NO_VID"`,
/// `Transport` → exit 5 + `"TRANSPORT"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AkeResult {
    /// AKE succeeded, a VID was returned.
    Vid,
    /// The drive rejected the host cert (HRL revocation).
    Rejected,
    /// AKE completed but no VID was produced.
    NoVid,
    /// The transport wedged / timed out during AKE.
    Transport,
}

impl AkeResult {
    /// The `(exit_code, stdout_marker)` the helper emits for this result.
    pub fn contract(self) -> (i32, &'static str) {
        match self {
            AkeResult::Vid => (0, "VID"),
            AkeResult::Rejected => (2, "REJECTED"),
            AkeResult::NoVid => (3, "NO_VID"),
            AkeResult::Transport => (5, "TRANSPORT"),
        }
    }
}

/// A host-side helper invocation — the AACS cert AKE via libfreemkv's `cert_vid`
/// example. Either presents a configured cert pair (`cert: valid|revoked`, the
/// runner auto-supplies `AKE_HELPER` and `--dev <dev> --cert <hex> --key <hex>`)
/// or runs an explicit `program` with `args` (used by the mock unit tests).
#[derive(Debug, Clone, Deserialize)]
pub struct ExecSpec {
    /// Which configured cert pair to present: `"valid"` or `"revoked"`.
    #[serde(default)]
    pub cert: Option<String>,
    /// Explicit program to run (overrides `AKE_HELPER`); required when `cert` is
    /// absent.
    #[serde(default)]
    pub program: Option<String>,
    /// Extra args appended after any auto-supplied ones.
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

/// Expectations for an [`ExecSpec`] step.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExecExpect {
    /// Expected AKE result.
    #[serde(default)]
    pub result: Option<AkeResult>,
    /// Accept ANY of these results — for disc-type ambiguity, e.g. an AACS-1.0
    /// cert on a 2.0 disc may legitimately `REJECTED` where a 1.0 disc yields a
    /// `VID`. Set per disc-type instead of a single hard `result`.
    #[serde(default)]
    pub any_of: Option<Vec<AkeResult>>,
    /// Raw exit-code assertion (generic helpers / tests).
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// stdout must contain this substring (generic helpers / tests).
    #[serde(default)]
    pub stdout_contains: Option<String>,
    /// Field checks on the parsed 16-byte VID hex (`nonzero` / `min_len` /
    /// `stable` / `capture` / `equals_capture`) — reuses [`DataExp`], so a
    /// cert-AKE VID can be `equals_capture`d against the bare-read VID.
    #[serde(default)]
    pub vid: Option<DataExp>,
}

/// Host-side AKE helper + cert material. Populated from the script's optional
/// `ake:` block and overlaid by env (`AKE_HELPER`, `VALID_CERT`, `VALID_KEY`,
/// `REVOKED_CERT`, `REVOKED_KEY`); `dev` is filled from the CLI `--dev`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AkeConfig {
    /// Path to the AKE helper binary (`cert_vid`).
    #[serde(default)]
    pub helper: Option<String>,
    /// The SCSI device to hand the helper; set from `--dev`, never the YAML.
    #[serde(default, skip)]
    pub dev: Option<String>,
    /// Valid host cert (hex).
    #[serde(default)]
    pub valid_cert: Option<String>,
    /// Valid host key (hex).
    #[serde(default)]
    pub valid_key: Option<String>,
    /// Revoked host cert (hex).
    #[serde(default)]
    pub revoked_cert: Option<String>,
    /// Revoked host key (hex).
    #[serde(default)]
    pub revoked_key: Option<String>,
}

impl AkeConfig {
    /// The `(cert, key)` hex pair for `"valid"` / `"revoked"`, if both are set.
    pub fn cert_pair(&self, kind: &str) -> Option<(&str, &str)> {
        match kind {
            "valid" => Some((self.valid_cert.as_deref()?, self.valid_key.as_deref()?)),
            "revoked" => Some((self.revoked_cert.as_deref()?, self.revoked_key.as_deref()?)),
            _ => None,
        }
    }
}

/// Everything a step asserts.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Expect {
    /// Expected SCSI status (default GOOD).
    #[serde(default)]
    pub status: StatusExp,
    /// Optional expected sense key (only meaningful with a CHECK CONDITION),
    /// e.g. `0x05` ILLEGAL REQUEST for a denied bare `0xAD` read.
    #[serde(default)]
    pub sense_key: Option<Num>,
    /// Optional flag-table persistence check.
    #[serde(default)]
    pub flag: Option<FlagExp>,
    /// Optional data-in assertion.
    #[serde(default)]
    pub data: Option<DataExp>,
}

/// One command inside a [`Step::sequence`]. Like a step, it supplies EITHER a
/// `knock` OR a `raw` CDB with a data phase and expectations, but has no phase
/// gate of its own (it inherits the parent step's phase) and cannot nest.
#[derive(Debug, Clone, Deserialize)]
pub struct SubStep {
    /// Human-readable label (for per-command PASS/FAIL detail).
    pub name: String,
    /// Structured knock (mutually exclusive with `raw` / `exec`).
    #[serde(default)]
    pub knock: Option<Knock>,
    /// Raw hex CDB (mutually exclusive with `knock` / `exec`).
    #[serde(default)]
    pub raw: Option<String>,
    /// Host-side helper invocation (mutually exclusive with `knock` / `raw`) —
    /// the cert AKE. Assert on it with `expect_exec`.
    #[serde(default)]
    pub exec: Option<ExecSpec>,
    /// Data phase (default `from_device`).
    #[serde(default)]
    pub dir: Dir,
    /// Allocation / read length in bytes. Defaults to 64 for a knock, else 0.
    #[serde(default)]
    pub alloc: Option<Num>,
    /// Issue the command this many times within one iteration (default 1).
    #[serde(default)]
    pub repeat: Option<usize>,
    /// Expectations for a SCSI (`knock`/`raw`) sub-command.
    #[serde(default)]
    pub expect: Expect,
    /// Expectations for an `exec` sub-command.
    #[serde(default)]
    pub expect_exec: ExecExpect,
}

/// One test step. A step carries EXACTLY ONE command form: a structured `knock`,
/// a `raw` CDB, or an ordered `sequence` of sub-commands. With `iterations: N`
/// the command form is run N times, each iteration evaluated independently and a
/// pass-rate (`X/N`) reported — so an intermittent bug shows up as e.g. `17/20`
/// instead of one lucky/unlucky shot, and the deny→approve→read hang that
/// wedges only *after* an OEM-deny is reproduced by an N-times sequence.
#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    /// Human-readable step name.
    pub name: String,
    /// Phase gate.
    pub phase: Phase,
    /// Structured knock (mutually exclusive with `raw` / `sequence`).
    #[serde(default)]
    pub knock: Option<Knock>,
    /// Raw hex CDB, e.g. `"3c 00 00 00 00 00 00 00 00 00"` (mutually exclusive
    /// with `knock` / `sequence`).
    #[serde(default)]
    pub raw: Option<String>,
    /// An ordered list of sub-commands run as one logical unit (mutually
    /// exclusive with `knock` / `raw` / `exec`). Combine with `iterations` to
    /// repeat the whole ordered sequence and report how many iterations passed.
    #[serde(default)]
    pub sequence: Option<Vec<SubStep>>,
    /// Host-side helper invocation (mutually exclusive with the other forms) —
    /// the cert AKE. Assert on it with `expect_exec`.
    #[serde(default)]
    pub exec: Option<ExecSpec>,
    /// Data phase (default `from_device`).
    #[serde(default)]
    pub dir: Dir,
    /// Allocation / read length in bytes. Defaults to 64 for a knock, else 0.
    #[serde(default)]
    pub alloc: Option<Num>,
    /// Issue the command this many times (default 1). Use with `data.stable` to
    /// prove an idempotent, non-single-use flag. All reads are collected and the
    /// status/data checks are ANDed — distinct from `iterations` (below).
    #[serde(default)]
    pub repeat: Option<usize>,
    /// Run the command form (single command OR `sequence`) this many times
    /// (default 1), evaluating EACH iteration independently and reporting `X/N`
    /// passed instead of aborting on the first failure. Between iterations the
    /// runner re-asserts the identity wedge-guard; a wedge aborts with exit 2.
    /// The step passes only when every iteration passed (`X == N`).
    #[serde(default)]
    pub iterations: Option<usize>,
    /// Informational-only step: print the returned bytes (hex) and always pass,
    /// regardless of `expect`. Used for disc-type probes (READ CAPACITY / GET
    /// CONFIGURATION) that we record but never assert.
    #[serde(default)]
    pub report: Option<bool>,
    /// Expectations for a SCSI (`knock`/`raw`) command.
    #[serde(default)]
    pub expect: Expect,
    /// Expectations for an `exec` command.
    #[serde(default)]
    pub expect_exec: ExecExpect,
}

/// A whole test script.
#[derive(Debug, Clone, Deserialize)]
pub struct Script {
    /// Expected identity version string (CLI `--expect-version` overrides).
    #[serde(default)]
    pub expect_version: Option<String>,
    /// SRAM flag-table base (default [`DEFAULT_FLAG_BASE`]).
    #[serde(default)]
    pub flag_base: Option<Num>,
    /// Per-command timeout in ms (default [`DEFAULT_TIMEOUT_MS`]).
    #[serde(default)]
    pub timeout_ms: Option<u32>,
    /// Inter-command delay in ms (default [`DEFAULT_DELAY_MS`]).
    #[serde(default)]
    pub delay_ms: Option<u32>,
    /// Extra settle after a flag toggle in ms (default [`DEFAULT_SETTLE_MS`]).
    #[serde(default)]
    pub settle_ms: Option<u32>,
    /// TEST UNIT READY polls before a disc read (default [`DEFAULT_TUR_RETRIES`]).
    #[serde(default)]
    pub tur_retries: Option<u32>,
    /// Base backoff between TUR polls in ms (default [`DEFAULT_TUR_BACKOFF_MS`]).
    #[serde(default)]
    pub tur_backoff_ms: Option<u32>,
    /// Host-side AKE helper + cert material (overlaid by env at run time).
    #[serde(default)]
    pub ake: Option<AkeConfig>,
    /// The ordered steps.
    pub steps: Vec<Step>,
}

impl Script {
    /// Parse a script from YAML text, validating the knock/raw exclusivity.
    pub fn from_yaml(text: &str) -> anyhow::Result<Self> {
        let s: Script = serde_yaml::from_str(text)?;
        for step in &s.steps {
            let forms = step.knock.is_some() as u8
                + step.raw.is_some() as u8
                + step.sequence.is_some() as u8
                + step.exec.is_some() as u8;
            match forms {
                0 => anyhow::bail!(
                    "step {:?}: needs one of `knock`, `raw`, `sequence`, or `exec`",
                    step.name
                ),
                1 => {}
                _ => anyhow::bail!(
                    "step {:?}: has more than one of `knock`/`raw`/`sequence`/`exec` (pick one)",
                    step.name
                ),
            }
            if let Some(ex) = &step.exec {
                Self::validate_exec(&step.name, ex)?;
            }
            if let Some(seq) = &step.sequence {
                if seq.is_empty() {
                    anyhow::bail!("step {:?}: `sequence` is empty", step.name);
                }
                for sub in seq {
                    let subforms = sub.knock.is_some() as u8
                        + sub.raw.is_some() as u8
                        + sub.exec.is_some() as u8;
                    match subforms {
                        0 => anyhow::bail!(
                            "step {:?} sub-step {:?}: needs one of `knock`, `raw`, or `exec`",
                            step.name,
                            sub.name
                        ),
                        1 => {}
                        _ => anyhow::bail!(
                            "step {:?} sub-step {:?}: has more than one of `knock`/`raw`/`exec`",
                            step.name,
                            sub.name
                        ),
                    }
                    if let Some(ex) = &sub.exec {
                        Self::validate_exec(&sub.name, ex)?;
                    }
                }
            }
        }
        Ok(s)
    }

    /// An `exec` must name either a configured `cert` pair or an explicit
    /// `program`. `cert`, when present, must be `"valid"` or `"revoked"`.
    fn validate_exec(name: &str, ex: &ExecSpec) -> anyhow::Result<()> {
        match (&ex.cert, &ex.program) {
            (None, None) => anyhow::bail!("exec {name:?}: needs `cert` or `program`"),
            (Some(k), _) if k != "valid" && k != "revoked" => {
                anyhow::bail!("exec {name:?}: `cert` must be \"valid\" or \"revoked\", got {k:?}")
            }
            _ => Ok(()),
        }
    }

    /// Resolved flag-table base.
    pub fn flag_base(&self) -> u32 {
        self.flag_base.map(Num::as_u32).unwrap_or(DEFAULT_FLAG_BASE)
    }

    /// Resolved per-command timeout.
    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)
    }

    /// Resolved pacing knobs (script values, else the crate defaults). The CLI /
    /// env overlay happens in `main`.
    pub fn pacing(&self) -> Pacing {
        Pacing {
            delay_ms: self.delay_ms.unwrap_or(DEFAULT_DELAY_MS),
            settle_ms: self.settle_ms.unwrap_or(DEFAULT_SETTLE_MS),
            tur_retries: self.tur_retries.unwrap_or(DEFAULT_TUR_RETRIES),
            tur_backoff_ms: self.tur_backoff_ms.unwrap_or(DEFAULT_TUR_BACKOFF_MS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
expect_version: "freemkv 0.6.6"
flag_base: 0x02000e40
timeout_ms: 5000
steps:
  - name: identity
    phase: discless
    knock: { subfn: 0x01, state: 0x00 }
    dir: from_device
    alloc: 64
    expect:
      status: good
      data: { starts_with_ascii: "freemkv" }
  - name: speed-max
    phase: discless
    knock: { subfn: 0x02, state: 0xFF }
    expect:
      flag: { subfn: 0x02, equals: 0xFF }
  - name: oem-passthrough
    phase: discless
    raw: "3c 00 00 00 00 00 00 00 00 00"
    dir: none
    alloc: 0
    expect:
      status: any
"#;

    #[test]
    fn parses_sample_script() {
        let s = Script::from_yaml(SAMPLE).unwrap();
        assert_eq!(s.expect_version.as_deref(), Some("freemkv 0.6.6"));
        assert_eq!(s.flag_base(), 0x0200_0E40);
        assert_eq!(s.timeout_ms(), 5000);
        assert_eq!(s.steps.len(), 3);

        let id = &s.steps[0];
        assert_eq!(id.phase, Phase::Discless);
        let k = id.knock.as_ref().unwrap();
        assert_eq!(k.subfn.as_u8(), 0x01);
        assert_eq!(id.dir, Dir::FromDevice);
        assert_eq!(id.alloc.unwrap().as_usize(), 64);

        let speed = &s.steps[1];
        // dir defaults to from_device when omitted.
        assert_eq!(speed.dir, Dir::FromDevice);
        let f = speed.expect.flag.as_ref().unwrap();
        assert_eq!(f.subfn.as_u8(), 0x02);
        assert_eq!(f.equals.as_u8(), 0xFF);

        assert_eq!(s.steps[2].expect.status, StatusExp::Any);
    }

    #[test]
    fn num_accepts_hex_string_and_int() {
        #[derive(Deserialize)]
        struct W {
            a: Num,
            b: Num,
        }
        let w: W = serde_yaml::from_str("a: 64\nb: \"0x40\"\n").unwrap();
        assert_eq!(w.a.as_usize(), 64);
        assert_eq!(w.b.as_usize(), 64);
    }

    #[test]
    fn rejects_both_knock_and_raw() {
        let bad = r#"
steps:
  - name: bad
    phase: discless
    knock: { subfn: 0x01 }
    raw: "3c"
"#;
        assert!(Script::from_yaml(bad).is_err());
    }

    #[test]
    fn rejects_neither_knock_nor_raw() {
        let bad = r#"
steps:
  - name: bad
    phase: discless
"#;
        assert!(Script::from_yaml(bad).is_err());
    }

    #[test]
    fn parses_sequence_with_iterations() {
        let s = Script::from_yaml(
            r#"
steps:
  - name: seq
    phase: disc
    iterations: 20
    sequence:
      - name: unlock
        knock: { subfn: 0x04, state: 0x01 }
        expect: { status: good }
      - name: read
        raw: "ad 01 00 00 00 00 00 80 00 24 00 00"
        alloc: 36
        expect: { status: good, data: { slice: { offset: 4, len: 16 }, nonzero: true } }
"#,
        )
        .unwrap();
        let step = &s.steps[0];
        assert_eq!(step.iterations, Some(20));
        let seq = step.sequence.as_ref().unwrap();
        assert_eq!(seq.len(), 2);
        assert_eq!(seq[0].knock.as_ref().unwrap().subfn.as_u8(), 0x04);
        assert_eq!(seq[1].alloc.unwrap().as_usize(), 36);
    }

    #[test]
    fn rejects_more_than_one_command_form() {
        let bad = r#"
steps:
  - name: bad
    phase: disc
    raw: "ad"
    sequence:
      - name: x
        knock: { subfn: 0x04 }
"#;
        assert!(Script::from_yaml(bad).is_err());
    }

    #[test]
    fn rejects_empty_sequence() {
        let bad = r#"
steps:
  - name: bad
    phase: disc
    sequence: []
"#;
        assert!(Script::from_yaml(bad).is_err());
    }

    #[test]
    fn shipped_tests_yaml_parses_with_repro_steps() {
        let text = include_str!("../tests.yaml");
        let s = Script::from_yaml(text).expect("shipped tests.yaml must parse");
        // The bug-repro sequence and the per-mode reliability steps are present.
        assert!(s.steps.iter().any(|st| st.sequence.is_some()));
        assert!(s.steps.iter().any(|st| st.iterations == Some(20)));
        // The cert-AKE matrix (exec sub-steps) is present.
        assert!(s.steps.iter().any(|st| st
            .sequence
            .as_ref()
            .is_some_and(|seq| seq.iter().any(|sub| sub.exec.is_some()))));
    }

    #[test]
    fn rejects_substep_with_neither_knock_nor_raw() {
        let bad = r#"
steps:
  - name: bad
    phase: disc
    sequence:
      - name: empty
        expect: { status: good }
"#;
        assert!(Script::from_yaml(bad).is_err());
    }

    #[test]
    fn parses_exec_cert_matrix_step() {
        let s = Script::from_yaml(
            r#"
ake:
  helper: /usr/local/bin/cert_vid
  valid_cert: "aa"
  valid_key: "bb"
steps:
  - name: cert-matrix
    phase: disc
    iterations: 20
    sequence:
      - name: "04 02 accept-any"
        knock: { subfn: 0x04, state: 0x02 }
        expect: { status: good }
      - name: "revoked cert still yields VID"
        exec: { cert: revoked }
        expect_exec:
          result: vid
          vid: { nonzero: true, min_len: 16 }
"#,
        )
        .unwrap();
        let ake = s.ake.as_ref().unwrap();
        assert_eq!(ake.helper.as_deref(), Some("/usr/local/bin/cert_vid"));
        assert_eq!(ake.cert_pair("valid"), Some(("aa", "bb")));
        assert_eq!(ake.cert_pair("revoked"), None); // key missing
        let seq = s.steps[0].sequence.as_ref().unwrap();
        assert_eq!(
            seq[1].exec.as_ref().unwrap().cert.as_deref(),
            Some("revoked")
        );
        assert_eq!(seq[1].expect_exec.result, Some(AkeResult::Vid));
    }

    #[test]
    fn exec_requires_cert_or_program() {
        let bad = r#"
steps:
  - name: bad
    phase: disc
    exec: {}
"#;
        assert!(Script::from_yaml(bad).is_err());
    }

    #[test]
    fn exec_rejects_unknown_cert_kind() {
        let bad = r#"
steps:
  - name: bad
    phase: disc
    exec: { cert: bogus }
    expect_exec: { result: vid }
"#;
        assert!(Script::from_yaml(bad).is_err());
    }

    #[test]
    fn pacing_defaults_and_overrides() {
        let dflt = Script::from_yaml("steps: []").unwrap();
        assert_eq!(
            dflt.pacing(),
            Pacing {
                delay_ms: DEFAULT_DELAY_MS,
                settle_ms: DEFAULT_SETTLE_MS,
                tur_retries: DEFAULT_TUR_RETRIES,
                tur_backoff_ms: DEFAULT_TUR_BACKOFF_MS,
            }
        );
        let over = Script::from_yaml(
            "delay_ms: 10\nsettle_ms: 20\ntur_retries: 3\ntur_backoff_ms: 5\nsteps: []\n",
        )
        .unwrap();
        assert_eq!(
            over.pacing(),
            Pacing {
                delay_ms: 10,
                settle_ms: 20,
                tur_retries: 3,
                tur_backoff_ms: 5
            }
        );
    }
}
