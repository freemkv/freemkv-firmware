//! Golden behaviour tests (Phase 0 of the universal-flash refactor).
//!
//! Every test here drives the real engine / workflow entry points against the
//! in-memory mocks and records, in a readable text format, exactly what comes
//! out: the captured text, the ordered structured output events, the complete
//! SCSI transcript (every CDB, direction, length, and the SHA-256 of every
//! data-out payload) and the SHA-256 of every file the operation saved.
//!
//! The recorded files live in `tests/golden/*.txt`. A test fails on ANY byte of
//! difference and prints a line diff. After an INTENTIONAL behaviour change,
//! regenerate with `FREEMKV_BLESS=1 cargo test -p freemkv-flash golden` and
//! review the diff of the golden files like any other code change.
//!
//! Determinism: ANSI escapes, scratch-directory paths and the timestamped
//! diagnostic-log path and trailing display padding are normalized away;
//! everything else is raw.

#![allow(clippy::type_complexity)]

use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

use crate::backends::mtk::fixture;
use crate::backends::mtk::{Mtk, CHUNK, IMAGE_SIZE, ROM_1EC000_OFFSET};
// COMPAT: the module path differs in the 0.11.2 baseline copy of this file.
use crate::backend::{Backend, FlashRequest};
use crate::backend::{BackendId, BackupFacet, FileFormat, FlashFacet, ReadDevice};
use crate::backends::mtk::{IMAGE as MTK_IMAGE, LEGACY_TAR as MTK_LEGACY_TAR};
use crate::backends::pioneer::flash_plan;
use crate::backends::pioneer::Pioneer;
use crate::backends::pioneer::{ENVELOPE as PIONEER_ENVELOPE, PACKAGE as PIONEER_PACKAGE};
use crate::manifest::FlashMode;
use crate::output::{capture_events, Event};
use crate::platform::{MediumStatus, MockScsiDevice, ScsiDevice};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wraps any device and records every command, in order, with its direction.
struct Rec<D: ScsiDevice> {
    inner: D,
    log: Vec<String>,
}

impl<D: ScsiDevice> Rec<D> {
    fn new(inner: D) -> Self {
        Self {
            inner,
            log: Vec::new(),
        }
    }

    fn out(&mut self, kind: &str, cdb: &[u8], data: &[u8], ok: &Result<()>) {
        self.log.push(format!(
            "{kind} cdb={} len={} sha256={} -> {}",
            hex(cdb),
            data.len(),
            sha(data),
            if ok.is_ok() { "ok" } else { "err" }
        ));
    }

    fn transcript(&self) -> Vec<String> {
        self.log.clone()
    }
}

impl<D: ScsiDevice> ScsiDevice for Rec<D> {
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
        let result = self.inner.command_in(cdb, alloc_len);
        let outcome = match &result {
            Ok(data) => format!("ok {}", data.len()),
            Err(_) => "err".to_string(),
        };
        self.log.push(format!(
            "IN   cdb={} alloc={alloc_len} -> {outcome}",
            hex(cdb)
        ));
        result
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        let result = self.inner.command_out(cdb, data);
        self.out("OUT ", cdb, data, &result);
        result
    }

    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        let result = self.inner.command_out_strict(cdb, data);
        self.out("OUTS", cdb, data, &result);
        result
    }

    fn describe(&self) -> String {
        self.inner.describe()
    }

    fn medium_status(&mut self) -> Result<MediumStatus> {
        let status = self.inner.medium_status();
        self.log.push(format!(
            "MEDIUM -> {}",
            match &status {
                Ok(s) => format!("{s:?}"),
                Err(_) => "err".to_string(),
            }
        ));
        status
    }
}

/// Everything one operation printed, plus its result.
struct Outcome {
    events: Vec<String>,
    text: Vec<String>,
    result: String,
}

impl Outcome {
    /// Replace the 64-hex digest following `marker` (a value that legitimately
    /// varies, e.g. the hash of a file embedding the capture time).
    fn mask_digest(mut self, marker: &str) -> Self {
        for line in self.text.iter_mut().chain(self.events.iter_mut()) {
            if let Some(i) = line.find(marker) {
                let start = i + marker.len();
                if line.len() >= start + 64 {
                    line.replace_range(start..start + 64, "<MASKED-TIME-DEPENDENT-SHA256>");
                }
            }
        }
        self
    }
}

/// Run `op` with its output captured. `text` follows the exact rule of
/// `output::capture` (Message lines, Progress as `label: N%`); `events` is the
/// ordered structured stream.
fn run<T>(op: impl FnOnce() -> Result<T>) -> Outcome {
    let events = Rc::new(RefCell::new(Vec::<String>::new()));
    let text = Rc::new(RefCell::new(Vec::<String>::new()));
    let (ev, tx) = (events.clone(), text.clone());
    let mut result = None;
    capture_events(
        move |event| match event {
            Event::Message(m) => {
                ev.borrow_mut().push(format!("MSG      {m}"));
                tx.borrow_mut().push(m);
            }
            Event::Progress { label, done, total } => {
                ev.borrow_mut()
                    .push(format!("PROGRESS {label} {done}/{total}"));
                tx.borrow_mut().push(format!(
                    "{label}: {}%",
                    done.saturating_mul(100) / total.max(1)
                ));
            }
            Event::Report(report) => {
                for (label, value) in report.gui_fields() {
                    ev.borrow_mut().push(format!("FIELD    {label} = {value}"));
                }
            }
            Event::DeviceSettings(_) => ev.borrow_mut().push("SETTINGS (present)".to_string()),
            Event::Phase { .. } => {}
        },
        || result = Some(crate::runtime_clock::simulated(op)),
    );
    let result = match result.expect("operation ran") {
        Ok(_) => "OK".to_string(),
        Err(e) => {
            if e.is::<crate::backend::UpdateFailure>() {
                assert_ne!(
                    crate::workflow::user_error(&e).id,
                    "errors.unexpected",
                    "a known update failure needs an explicit user issue: {e:#}"
                );
            }
            format!("ERR {e:#}")
        }
    };
    let events = events.borrow().clone();
    let text = text.borrow().clone();
    Outcome {
        events,
        text,
        result,
    }
}

/// Accumulates one golden file.
#[derive(Default)]
struct Golden {
    body: String,
}

impl Golden {
    fn section(&mut self, title: &str) {
        let _ = writeln!(self.body, "\n=== {title} ===");
    }

    fn lines(&mut self, header: &str, lines: &[String]) {
        let _ = writeln!(self.body, "--- {header} ({}) ---", lines.len());
        for l in lines {
            let _ = writeln!(self.body, "{l}");
        }
    }

    fn kv(&mut self, key: &str, value: &str) {
        let _ = writeln!(self.body, "{key}: {value}");
    }

    /// One scenario: result, text, events (and transcript when a device was used).
    fn case(&mut self, title: &str, outcome: &Outcome, transcript: Option<&[String]>) {
        self.section(title);
        self.kv("result", &outcome.result);
        self.lines("text", &outcome.text);
        self.lines("events", &outcome.events);
        if let Some(t) = transcript {
            self.lines("scsi transcript", t);
        }
    }

    /// Record a file the operation saved.
    fn file(&mut self, label: &str, path: &Path) {
        match std::fs::read(path) {
            Ok(bytes) => self.kv(
                label,
                &format!("{} bytes sha256={}", bytes.len(), sha(&bytes)),
            ),
            Err(_) => self.kv(label, "<not created>"),
        }
    }
}

impl Golden {
    /// Record a Pioneer diagnostic dump. The dump embeds the capture start time
    /// and tool version in its trailing JSON directory, so the body and the
    /// directory are hashed separately with both masked.
    fn dump_file(&mut self, label: &str, path: &Path) {
        let bytes = std::fs::read(path).expect("dump saved");
        let n = bytes.len();
        let dir_len = u64::from_le_bytes(bytes[n - 40..n - 32].try_into().unwrap()) as usize;
        let offset = u64::from_le_bytes(bytes[n - 48..n - 40].try_into().unwrap()) as usize;
        let directory = String::from_utf8_lossy(&bytes[offset..offset + dir_len]).to_string();
        let masked = match directory.find("\"started_unix\":") {
            Some(i) => {
                let from = i + "\"started_unix\":".len();
                let digits = directory[from..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .count();
                format!(
                    "{}<TIME>{}",
                    &directory[..from],
                    &directory[from + digits..]
                )
            }
            None => directory,
        };
        let version = format!("\"tool_version\":\"{}\"", env!("CARGO_PKG_VERSION"));
        let masked = masked.replace(&version, "\"tool_version\":\"<VERSION>\"");
        self.kv(
            label,
            &format!(
                "{n} bytes; body sha256={} directory(time masked) sha256={}",
                sha(&bytes[..offset]),
                sha(masked.as_bytes())
            ),
        );
    }
}

/// A fresh scratch directory for one call, `freemkv-golden-<pid>-<n>-<tag>`:
/// unique per process and call, so parallel tests never share one and no
/// test relies on removing a leftover. [`normalize`] reduces it to `<TMP>/<tag>`.
fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("freemkv-golden-{}-{n}-{tag}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("creating {}: {e}", dir.display()),
        }
    }
}

/// The facts of this host and build that leak into recorded output.
struct Host {
    pid: u32,
    /// Spellings of the temp directory (as given, canonical, verbatim-free).
    temp: Vec<String>,
    /// This OS's wording of "file not found" (os error 2).
    not_found: String,
    /// The tool version, OS and arch as diagnostic lines print them.
    build: String,
}

impl Host {
    fn current() -> Self {
        let tmp = std::env::temp_dir();
        let mut temp = vec![tmp.display().to_string()];
        if let Ok(c) = tmp.canonicalize() {
            let c = c.display().to_string();
            if let Some(plain) = c.strip_prefix(r"\\?\") {
                temp.push(plain.to_string());
            }
            temp.push(c);
        }
        Self {
            pid: std::process::id(),
            temp,
            not_found: std::io::Error::from_raw_os_error(2).to_string(),
            build: format!(
                "freemkv-flash={} os={} arch={}",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        }
    }
}

/// Remove everything that legitimately varies between runs.
fn normalize(raw: &str) -> String {
    normalize_for(raw, &Host::current())
}

/// Replace each scratch path `<needle><n>-<tag><rest>` with `<TMP>/<tag><rest>`,
/// the separators of the path (up to whitespace) turned into `/`.
fn mask_scratch(text: &str, needle: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(needle) {
        out.push_str(&rest[..i]);
        out.push_str("<TMP>/");
        let mut tail = &rest[i + needle.len()..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && tail[digits..].starts_with('-') {
            tail = &tail[digits + 1..];
        }
        let end = tail.find(char::is_whitespace).unwrap_or(tail.len());
        out.push_str(&tail[..end].replace('\\', "/"));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// [`normalize`] for the given host facts.
fn normalize_for(raw: &str, host: &Host) -> String {
    // ANSI escape sequences.
    let mut plain = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for code in chars.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
        } else if c != '\r' {
            plain.push(c);
        }
    }
    // Scratch directories, longest spelling first (one may contain another).
    let mut bases: Vec<&str> = host
        .temp
        .iter()
        .map(|t| t.trim_end_matches(['/', '\\']))
        .collect();
    bases.sort_by_key(|b| std::cmp::Reverse(b.len()));
    for base in bases {
        for sep in ['/', '\\'] {
            let needle = format!("{base}{sep}freemkv-golden-{}-", host.pid);
            plain = mask_scratch(&plain, &needle);
        }
    }
    // OS wording and build and host facts.
    plain = plain.replace(&host.not_found, "No such file or directory (os error 2)");
    plain = plain.replace(&host.build, "freemkv-flash=<VERSION> os=<OS> arch=<ARCH>");
    // The per-run diagnostic log path.
    plain
        .lines()
        .map(|line| {
            let line = line.trim_end();
            if let Some(i) = line.find("Diagnostic log") {
                let rest = &line[i..];
                let cut = [": ", " = "]
                    .iter()
                    .filter_map(|m| rest.find(m).map(|k| k + m.len()))
                    .min();
                match cut {
                    Some(k) => format!("{}{}<LOG>", &line[..i], &rest[..k]),
                    None => line.to_string(),
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn normalize_masks_windows_and_unix_hosts_alike() {
    let windows = Host {
        pid: 7692,
        temp: vec![
            r"C:\Users\RUNNER~1\AppData\Local\Temp\".into(),
            r"C:\Users\runneradmin\AppData\Local\Temp".into(),
            r"\\?\C:\Users\runneradmin\AppData\Local\Temp".into(),
        ],
        not_found: "The system cannot find the file specified. (os error 2)".into(),
        build: "freemkv-flash=9.9.9 os=windows arch=x86_64".into(),
    };
    let raw = concat!(
        "wrote C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\freemkv-golden-7692-3-backup",
        "\\mtk_backup.tar (2 MiB).\r\n",
        "saved \\\\?\\C:\\Users\\runneradmin\\AppData\\Local\\Temp\\freemkv-golden-7692-12-x\\a\\b.bin\n",
        "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\freemkv-golden-7692-0-y\\c.bin: ",
        "The system cannot find the file specified. (os error 2)\n",
        "probe: freemkv-flash=9.9.9 os=windows arch=x86_64 device=x\n",
        "other pid C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\freemkv-golden-1-0-z\\d.bin\n",
    );
    let expected = concat!(
        "wrote <TMP>/backup/mtk_backup.tar (2 MiB).\n",
        "saved <TMP>/x/a/b.bin\n",
        "<TMP>/y/c.bin: No such file or directory (os error 2)\n",
        "probe: freemkv-flash=<VERSION> os=<OS> arch=<ARCH> device=x\n",
        "other pid C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\freemkv-golden-1-0-z\\d.bin\n",
    );
    assert_eq!(normalize_for(raw, &windows), expected);

    let macos = Host {
        pid: 42,
        temp: vec![
            "/var/folders/x/T/".into(),
            "/private/var/folders/x/T".into(),
        ],
        not_found: "No such file or directory (os error 2)".into(),
        build: "freemkv-flash=9.9.9 os=macos arch=aarch64".into(),
    };
    let raw = "a /private/var/folders/x/T/freemkv-golden-42-7-t/f.tar b /var/folders/x/T/freemkv-golden-42-8-u/g\n";
    assert_eq!(normalize_for(raw, &macos), "a <TMP>/t/f.tar b <TMP>/u/g\n");
}

/// Ordered line edits turning `a` into `b`: `('-', line)` / `('+', line)`.
/// Common prefix and suffix are trimmed; the middle is an LCS with a fixed
/// tie-break, so the result is deterministic.
fn diff_ops(a: &[&str], b: &[&str]) -> Vec<(char, String)> {
    let mut ops = diff_ops_full(a, b);
    ops.retain(|(sign, _)| *sign != ' ');
    ops
}

/// Like [`diff_ops`], but also yields `(' ', line)` for lines common to both
/// inside the differing region (context for a readable failure).
fn diff_ops_full(a: &[&str], b: &[&str]) -> Vec<(char, String)> {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ma, mb) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut ops = Vec::new();
    if ma.len().saturating_mul(mb.len()) > 25_000_000 {
        ops.extend(ma.iter().map(|l| ('-', l.to_string())));
        ops.extend(mb.iter().map(|l| ('+', l.to_string())));
        return ops;
    }
    let mut lcs = vec![vec![0u32; mb.len() + 1]; ma.len() + 1];
    for i in (0..ma.len()).rev() {
        for j in (0..mb.len()).rev() {
            lcs[i][j] = if ma[i] == mb[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < ma.len() || j < mb.len() {
        if i < ma.len() && j < mb.len() && ma[i] == mb[j] {
            ops.push((' ', ma[i].to_string()));
            i += 1;
            j += 1;
        } else if j >= mb.len() || (i < ma.len() && lcs[i + 1][j] >= lcs[i][j + 1]) {
            ops.push(('-', ma[i].to_string()));
            i += 1;
        } else {
            ops.push(('+', mb[j].to_string()));
            j += 1;
        }
    }
    ops
}

/// Readable rendering of the first differences between two texts.
fn diff(expected: &str, actual: &str) -> String {
    let a: Vec<&str> = expected.lines().collect();
    let b: Vec<&str> = actual.lines().collect();
    let pre = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut out = String::new();
    let _ = writeln!(out, "first difference at line {}", pre + 1);
    for l in &a[pre.saturating_sub(2)..pre] {
        let _ = writeln!(out, "  {l}");
    }
    let ops = diff_ops_full(&a, &b);
    let mut shown = 0;
    let mut quiet = 0;
    for (sign, line) in &ops {
        if shown >= 80 {
            let _ = writeln!(out, "... (diff truncated)");
            break;
        }
        if *sign == ' ' {
            quiet += 1;
            if quiet > 6 {
                continue;
            }
        } else {
            quiet = 0;
        }
        let _ = writeln!(out, "{sign} {line}");
        shown += 1;
    }
    out
}

/// Compare against (or with `FREEMKV_BLESS=1`, rewrite) `tests/golden/<name>.txt`.
fn check(name: &str, golden: Golden) {
    let actual = normalize(&golden.body);
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.txt"));
    if std::env::var_os("FREEMKV_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing golden {}; generate with FREEMKV_BLESS=1",
            path.display()
        )
    });
    // A Windows checkout may have turned the recorded line endings into CRLF.
    let expected = expected.replace("\r\n", "\n");
    if expected != actual {
        let actual_path = std::env::temp_dir().join(format!(
            "freemkv-golden-{}-{name}.actual.txt",
            std::process::id()
        ));
        std::fs::write(&actual_path, &actual).expect("save mismatched golden for inspection");
        panic!(
            "golden mismatch: {}\nactual output: {}\n(- recorded, + actual; regenerate only for an intentional change with FREEMKV_BLESS=1)\n{}",
            path.display(),
            actual_path.display(),
            diff(&expected, &actual)
        );
    }
}

// ---------------------------------------------------------------------------
// MediaTek fixtures (mirrors engine_tests.rs; its helpers are module-private)
// ---------------------------------------------------------------------------

fn stamp_descriptor(img: &mut [u8], model: &str) {
    let d = ROM_1EC000_OFFSET as usize;
    img[d..d + 0x08].copy_from_slice(b"HL-DT-ST");
    img[d + 0x08..d + 0x18].fill(b' ');
    img[d + 0x08..d + 0x08 + model.len()].copy_from_slice(model.as_bytes());
    img[d + 0x18..d + 0x1c].copy_from_slice(b"1.00");
    img[d + 0x34..d + 0x34 + 10].copy_from_slice(b"MTEKMT1959");
}

fn with_active_cmac_range(mut image: Vec<u8>, start: u32, end: u32) -> Vec<u8> {
    let off = 0x10400usize;
    image[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
    image[off + 4..off + 8].copy_from_slice(&start.to_le_bytes());
    image[off + 8..off + 12].copy_from_slice(&end.to_le_bytes());
    image
}

fn make_flashable(mut img: Vec<u8>, model: &str) -> Vec<u8> {
    assert_eq!(img.len(), IMAGE_SIZE);
    img[..0x400].copy_from_slice(&mtk_boot_page());
    stamp_descriptor(&mut img, model);
    fixture::stamp(&mut img, &fixture::BU3);
    let img = with_active_cmac_range(img, 0x11000, 0x1FFFF);
    crate::cmac::resign(&img).expect("resign a well-formed image")
}

/// A flashable MT1959 image of `model` on a different board line than BU3: the
/// same chip as a BU40N drive, a different hardware family, so a crossflash onto
/// a BU40N is refused by the family gate.
fn make_flashable_other_family(model: &str) -> Vec<u8> {
    let board = fixture::Board {
        platform: "BU9",
        ..fixture::BU3
    };
    let mut img = vec![0u8; IMAGE_SIZE];
    img[..0x400].copy_from_slice(&mtk_boot_page());
    stamp_descriptor(&mut img, model);
    fixture::stamp(&mut img, &board);
    let img = with_active_cmac_range(img, 0x11000, 0x1FFFF);
    crate::cmac::resign(&img).expect("resign a well-formed image")
}

/// The stored MT1959 boot page every cataloged build shares.
///
/// COMPAT: the only line that names the catalog; the 0.11.2 baseline differs.
fn mtk_boot_page() -> Vec<u8> {
    crate::backends::mtk::oem::catalog()
        .default_for(mediatek_optical::Chip::Mt1959)
        .expect("MT1959 default")
        .boot_page()
        .to_vec()
}

/// Report `product` as the INQUIRY product (vendor HL-DT-ST, revision 1.00).
fn with_inquiry_product(dev: MockScsiDevice, product: &str) -> MockScsiDevice {
    let mut inq = vec![0u8; 96];
    inq[0] = 5;
    inq[4] = 91;
    inq[8..16].copy_from_slice(b"HL-DT-ST");
    inq[16..32].fill(b' ');
    inq[16..16 + product.len()].copy_from_slice(product.as_bytes());
    inq[32..36].copy_from_slice(b"1.00");
    dev.on(|cdb| cdb.first() == Some(&0x12), inq)
}

/// Pioneer recovery as the workflow performs it once a device is open.
///
/// COMPAT: the 0.11.2 baseline has no `Backend::recover`; its copy of this
/// function inlines the body of `workflow::recover`.
fn recover_via(
    dev: &mut dyn ScsiDevice,
    current: Option<&[u8]>,
    target: &[u8],
    execute: bool,
) -> Result<()> {
    crate::engine::recover(dev, &Pioneer::new(), current, target, execute, true).map(drop)
}

/// The engine's flash with consent collected up front.
fn engine_flash(dev: &mut dyn ScsiDevice, drive: &dyn Backend, req: &FlashRequest) -> Result<()> {
    crate::engine::flash(dev, drive, req, &mut crate::workflow::Preconfirmed).map(drop)
}

/// A signed image of `chip` (`MTEKMT1959` / `MTEKMT1939`) with the stored boot
/// page and a patterned body.
fn stored_image(chip: &[u8; 10], model: &str, code: u8) -> Vec<u8> {
    let mut img: Vec<u8> = (0..IMAGE_SIZE).map(|i| (i % 251) as u8 ^ code).collect();
    img[..0x400].copy_from_slice(&mtk_boot_page());
    let d = ROM_1EC000_OFFSET as usize;
    stamp_descriptor(&mut img, model);
    img[d + 0x34..d + 0x3E].copy_from_slice(chip);
    let board = if chip == b"MTEKMT1939" {
        fixture::JB7
    } else {
        fixture::BU3
    };
    fixture::stamp(&mut img, &board);
    let t = 0x10400usize;
    for i in 0..16 {
        img[t + i * 28..t + (i + 1) * 28].fill(0xFF);
    }
    img[t..t + 4].copy_from_slice(&1u32.to_le_bytes());
    img[t + 4..t + 8].copy_from_slice(&0x11000u32.to_le_bytes());
    img[t + 8..t + 12].copy_from_slice(&0x1FFFFu32.to_le_bytes());
    crate::cmac::resign(&img).unwrap()
}

/// What a MediaTek drive returns for a full read: the boot page mirrored from
/// 0x10000 and per-unit bytes in every drive-written region.
fn drive_read(image: &[u8]) -> Vec<u8> {
    let mut read = image.to_vec();
    let mirror = read[0x10000..0x10400].to_vec();
    read[..0x400].copy_from_slice(&mirror);
    for (start, _len) in [
        (1933312usize, 32768usize),
        (1966080, 32768),
        (1998848, 16384),
        (2031616, 65536),
    ] {
        read[start..start + 16].fill(0x52);
    }
    read
}

/// A real 0.10.x/0.11.x MediaTek rollback archive (backup.toml + firmware.bin +
/// per-unit members), recorded once from the 0.11.2 writer.
fn legacy_mtk_tar() -> Vec<u8> {
    use std::io::Read;
    let gz = include_bytes!("../tests/golden/fixtures/legacy_0_10_backup.tar.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, *bytes).unwrap();
    }
    tar.into_inner().unwrap()
}

/// A 0x418000-byte full-flash dump with a signature word and optional markers.
fn flash_dump(word: u32, marker: Option<(&[u8], &str, &str)>) -> Vec<u8> {
    let mut img = vec![0u8; 0x418000];
    img[4..8].copy_from_slice(&word.to_be_bytes());
    if let Some((tag, model, rev)) = marker {
        img[0x100..0x100 + tag.len()].copy_from_slice(tag);
        img[0x400..0x400 + model.len()].copy_from_slice(model.as_bytes());
        img[0x800..0x800 + rev.len()].copy_from_slice(rev.as_bytes());
    }
    img
}

fn backup_firmware() -> Vec<u8> {
    make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N")
}

fn mtk_request(image: Vec<u8>, execute: bool, backup: Option<PathBuf>) -> FlashRequest {
    FlashRequest {
        current: None,
        input: image,
        input_format: &MTK_IMAGE,
        mode: FlashMode::Full,
        execute,
        acknowledged_risk: execute,
        enc_override: None,
        drive_model: "BU40N".into(),
        verbose: false,
        predump_out: backup,
    }
}

fn mtk_drive() -> MockScsiDevice {
    MockScsiDevice::new().with_firmware_image(backup_firmware())
}

/// Run `op` against a recording wrapper of `dev`, returning outcome + transcript.
fn drive_run<D: ScsiDevice, T>(
    dev: D,
    op: impl FnOnce(&mut Rec<D>) -> Result<T>,
) -> (Outcome, Vec<String>) {
    let mut rec = Rec::new(dev);
    let outcome = run(|| op(&mut rec));
    (outcome, rec.transcript())
}

// ---------------------------------------------------------------------------
// Pioneer fixtures (mirrors drive/pioneer/{recovery,prepared,backup}_tests.rs)
// ---------------------------------------------------------------------------

use pioneer_optical::envelope::{
    builder::{encode_encrypted_pair, BuildInputs, KernelBuild, NormalSignature},
    Envelope, Update,
};

// --- synthetic Pioneer packages (copied from recovery_tests.rs) ---
// Synthetic instruction fixtures, not extracted firmware images.
const UNGATED_FINALIZER: &[u8] = &[
    0x7a, 0x00, 0x00, 0x01, 0x12, 0x00, 0x1f, 0x81, 0x58, 0x60, 0x00, 0x94, 0x1a, 0x91, 0x01, 0x00,
    0x69, 0xc1, 0x01, 0x00, 0x6f, 0x41, 0x00, 0x08, 0x1a, 0xb3, 0xf3, 0x12, 0x0a, 0x93, 0x7a, 0x11,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x69, 0xf1, 0x1a, 0xd5, 0xf5, 0x10, 0x01, 0x00, 0x6f, 0xf5,
    0x00, 0x04, 0x0f, 0xf0, 0x79, 0x10, 0x00, 0x0c, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x08, 0x0f, 0xc0,
    0x7a, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xb1, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x46, 0x0e,
    0x18, 0x99, 0x0f, 0xc0, 0x5e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x0c, 0x01, 0x00,
    0x6f, 0x70, 0x00, 0x0c,
];

const GATED_FINALIZER: &[u8] = &[
    0x7a, 0x00, 0x00, 0x01, 0x12, 0x00, 0x1f, 0x81, 0x58, 0x60, 0x00, 0xa6, 0x1a, 0x91, 0x01, 0x00,
    0x69, 0xd1, 0x01, 0x00, 0x6f, 0x51, 0x00, 0x08, 0x1a, 0xb3, 0xf3, 0x12, 0x0a, 0x93, 0x7a, 0x11,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x69, 0xf1, 0x1a, 0xc4, 0xf4, 0x10, 0x01, 0x00, 0x6f, 0xf4,
    0x00, 0x04, 0x0f, 0xf0, 0x79, 0x10, 0x00, 0x0c, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x08, 0x0f, 0xd0,
    0x7a, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xb1, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x46, 0x0e,
    0x18, 0x99, 0x0f, 0xd0, 0x5e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x0c, 0x18, 0x99,
    0x0f, 0xd0, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x47, 0x44, 0x01, 0x00, 0x6f, 0x70, 0x00, 0x0c,
];

const MARKER_CHECK: &[u8] = &[
    0x01, 0x00, 0x6d, 0xf4, 0x1b, 0x87, 0x0f, 0x82, 0x01, 0x00, 0x6b, 0x24, 0x00, 0x41, 0x00, 0x14,
    0x01, 0x00, 0x6f, 0x00, 0x00, 0x08, 0x0c, 0x99, 0x46, 0x0a, 0x7a, 0x10, 0x00, 0x00, 0x12, 0xfe,
    0x0f, 0x81, 0x40, 0x0e, 0x01, 0x00, 0x6f, 0x21, 0x00, 0x0e, 0x0a, 0x81, 0x7a, 0x11, 0x00, 0x01,
    0x00, 0x28, 0x0f, 0xf0, 0x1a, 0xa2, 0xfa, 0x01, 0x5e, 0x00, 0x01, 0x90, 0x68, 0x78, 0xa8, 0xff,
    0x47, 0x08, 0x0c, 0x88, 0x47, 0x04, 0x18, 0x00, 0x40, 0x02, 0xf0, 0x01, 0x6a, 0x30, 0x00, 0x00,
    0x06, 0x7e, 0x77, 0x00, 0x44, 0x0a, 0x7a, 0x24, 0xff, 0xff, 0xff, 0xff, 0x46, 0x02, 0x18, 0x00,
    0x0c, 0x08, 0x0b, 0xf7, 0x01, 0x00, 0x6d, 0x74, 0x54, 0x70,
];

fn balance(bytes: &mut [u8]) {
    let at = bytes.len() - 4;
    bytes[at..].fill(0);
    let sum = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |sum, w| sum.wrapping_add(u32::from_be_bytes(*w)));
    bytes[at..].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
/// Recorded Normal signature blocks for the synthetic packages.
///
/// The library signs with a random nonce, so signing at test time would make
/// every package (and every hash derived from it) differ run to run. Each block
/// below was produced once by signing the (deterministic) package body and is
/// stamped verbatim, which yields a valid, reproducible signed package.
fn pair_signature(kind: &str, gated: bool, marker: u8) -> Vec<u8> {
    const SIGS: &[(&str, &str)] = &[
        ("prepared-false-0", "7e0fb87a8ea5a55f27852efec98386a0515200479efb265fe66f850a4fd0453ec12cd7b63d2a3eac0b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
        ("prepared-false-1", "46ec2e64062aab8fec15610d982085eae4676e19d550f8891557ca571e19122ed38d0fb8340813430b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
        ("prepared-true-1", "122f0f061321f44c4397e76c055e37cbad74684669b2a8f8d2f548a55fdc5b3b629a1b585f929f400b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
        ("recovery-false-0", "0ae0c342876bc56c5c7b22a3cbad27af2a9c40d1d005fac83ec41a4dcac9e977216b78533a3d99730b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
        ("ud04-false-0", "aba1c238f66b975894719ec1dcb6d775f519a3f759e97921ca84d4c8e1493da06953151817a1578a0b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
        ("ud04-true-1", "a6a5415bf199e26648cc663a675f15cd284169819d34180e42fb135118b03cdd64df43e65a03266e0b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
        ("ud04-id58-false-0", "0e65b6f79d1be3d7cd5d06fd798d594ea8379e03b58c9b403e530e77f8da04eaecb72ea17ff42eac0b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
        ("recovery-false-1", "2278bd5b92f436c734cc5fe2ab2556744ae26459520f2d36a905c6f11329795dbb5471f4aaecef980b168e124b15577167f694303e507938c30a76bd0d5f4b7e165c294b692d374c522e51ef99657a80"),
    ];
    let key = format!("{kind}-{gated}-{marker}");
    let (_, hex) = SIGS
        .iter()
        .find(|(k, _)| *k == key)
        .unwrap_or_else(|| panic!("no recorded signature for {key}"));
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn fixture_pair(gated: bool, marker: u8) -> Update {
    let mut kernel = vec![0; 0x10000];
    crate::kernel_handoff_fixture(&mut kernel);
    kernel[0x1000..0x1014].copy_from_slice(b"SAT FFFEGENERAL 0000");
    kernel[0x40..0x42].copy_from_slice(&[0xae, 0xfe]);
    kernel[0x46..0x48].copy_from_slice(&[0xae, 0xf0]);
    kernel[0x100..0x114].copy_from_slice(&[
        0x7a, 0x20, 0, 0, 1, 0, 0x47, 12, 0x7a, 0x20, 0, 0, 2, 0, 0x47, 4, 1, 0xf0, 0x65, 5,
    ]);
    // Forward-rotation decode loop after the XOR-skip branch; without it
    // pioneer-optical 0.15.0 returns UnknownRotation from Update::load.
    kernel[0x114..0x126].copy_from_slice(&[
        0x79, 0x63, 0, 0x1f, 0x0d, 0x31, 0x5e, 0x40, 0x01, 0x22, 1, 0xf0, 0x64, 0x40, 0x11, 0x70,
        0x54, 0x70,
    ]);
    let finalizer = if gated {
        GATED_FINALIZER
    } else {
        UNGATED_FINALIZER
    };
    kernel[0x300..0x300 + finalizer.len()].copy_from_slice(finalizer);
    for (offset, address) in [(0x349, [0x40, 0x20, 0]), (0x355, [0x40, 0x22, 0])] {
        kernel[offset..offset + 3].copy_from_slice(&address);
    }
    if gated {
        kernel[0x363..0x366].copy_from_slice(&[0x40, 0x30, 0]);
        kernel[0x3000..0x3000 + MARKER_CHECK.len()].copy_from_slice(MARKER_CHECK);
    }
    kernel[pioneer_optical::envelope::KERNEL_MARKER_OFFSET] = marker;
    balance(&mut kernel);
    let mut normal = vec![0; 0x2000];
    normal[..16].copy_from_slice(b"PIONEER TEST-NEW");
    normal[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    normal[0x400..0x408].copy_from_slice(&[0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36, 0, 0]);
    normal[0x500..0x510].copy_from_slice(&[
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, marker, 0x46, 0x4e,
    ]);
    balance(&mut normal);
    let encoded = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "26/10/07",
            kernel: KernelBuild::from_seed(7),
            normal_key_seed: 11,
        },
        NormalSignature::Oem(&pair_signature("recovery", gated, marker)),
    )
    .unwrap();
    Update::load(&encoded.kernel, &encoded.normal).unwrap()
}

fn archive(update: &Update, unsigned: bool) -> Vec<u8> {
    let kernel = update.kernel().repack(&update.kernel().image).unwrap();
    let mut normal = update.normal().repack(&update.normal().image).unwrap();
    if unsigned {
        normal[0x170..0x1c0].fill(0);
    }
    let mut tar = tar::Builder::new(Vec::new());
    for (name, data) in [("kernel.enc", kernel), ("normal.enc", normal)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, data.as_slice()).unwrap();
    }
    tar.into_inner().unwrap()
}

// --- stateful receivers (copied from recovery_tests.rs / prepared_tests.rs) ---
#[derive(Default)]
struct RecoveryDrive {
    kernel_wire: Vec<u8>,
    normal_wire: Vec<u8>,
    updating: bool,
    finished: bool,
    stuck: bool,
    fail_write: Option<usize>,
    attempts: usize,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
    startup_word: Option<u16>,
}
impl ScsiDevice for RecoveryDrive {
    fn describe(&self) -> String {
        "Recovery test".into()
    }
    fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; len];
        let kernel = (self.updating && !self.finished) || self.stuck;
        if command == pioneer_optical::cdb::read_parameter_word(0x9f).unwrap() {
            assert!(!kernel, "Normal parameter read in update mode");
            return Ok(self.startup_word.unwrap_or(0xffff).to_be_bytes().to_vec());
        } else if command == pioneer_optical::cdb::inquiry(len as u8) {
            bytes[0] = 5;
            bytes[8..16].copy_from_slice(b"PIONEER ");
            bytes[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
            bytes[32..36].copy_from_slice(if kernel { b"0000" } else { b"1.00" });
        } else if command == pioneer_optical::cdb::vendor_identity() {
            bytes[16..24].copy_from_slice(b"SAT FFFE");
            bytes[24..32].copy_from_slice(b"GENERAL ");
            if !kernel {
                bytes[32..40].copy_from_slice(b"GENERAL ");
            }
        } else if command == pioneer_optical::cdb::test_unit_ready() {
            return Err(crate::platform::ScsiSenseError::new(2, 0x3a, 0, "no medium").into());
        } else if command.len() == 10 && command[..3] == [0x3c, 2, 0xb0] {
            let address = u32::from_be_bytes([0, command[3], command[4], command[5]]) as usize;
            if !self.finished {
                assert_eq!(
                    address, 0x410000,
                    "only receiver descriptor reads before transfer"
                );
                return Ok(b"PIONEER TEST-NEW"[..len].to_vec());
            }
            let kernel = Envelope::load(&self.kernel_wire)?;
            let (base, image) = if address >= 0x410000 {
                (
                    0x410000,
                    Envelope::load_with_kernel(&self.normal_wire, &kernel)?.image,
                )
            } else {
                (0x400000, kernel.image)
            };
            let offset = address.checked_sub(base).expect("firmware address");
            return Ok(image[offset..offset + len].to_vec());
        } else if command == mediatek_optical::cdb::read_memory(0x3000, 32) {
            return Ok(vec![0; 32]);
        } else if command != pioneer_optical::cdb::get_event_status()
            && command != pioneer_optical::cdb::request_sense(18)
        {
            panic!("unexpected read: {command:02x?}");
        }
        Ok(bytes)
    }
    fn command_out(&mut self, command: &[u8], bytes: &[u8]) -> Result<()> {
        if command == pioneer_optical::cdb::knock() && bytes.is_empty() {
            return Ok(());
        }
        panic!("lenient write forbidden")
    }
    fn command_out_strict(&mut self, command: &[u8], bytes: &[u8]) -> Result<()> {
        self.attempts += 1;
        if self.fail_write == Some(self.attempts) {
            bail!("injected write failure");
        }
        if command == pioneer_optical::cdb::write_parameter_word(0x9f).unwrap() {
            assert!(!self.updating, "Normal parameter write in update mode");
            self.startup_word = Some(u16::from_be_bytes(bytes.try_into().unwrap()));
        }
        self.writes.push((command.to_vec(), bytes.to_vec()));
        if command == pioneer_optical::cdb::enter_update() {
            self.updating = true;
            self.finished = false;
            self.kernel_wire.clear();
            self.normal_wire.clear();
        } else if command.get(..3) == Some(&[0x3b, 0x07, 0xfe]) {
            self.kernel_wire.extend_from_slice(bytes);
        } else if command.get(..3) == Some(&[0x3b, 0x07, 0xf0]) {
            self.normal_wire.extend_from_slice(bytes);
        }
        if command == pioneer_optical::cdb::finish()
            && self.writes.iter().any(|(c, _)| c[2] == 0xf0)
        {
            self.finished = true;
        }
        Ok(())
    }
}

fn prepared_pair(gated: bool, marker: u8) -> Update {
    let mut kernel = vec![0; 0x10000];
    crate::kernel_handoff_fixture(&mut kernel);
    kernel[0x1000..0x1014].copy_from_slice(b"SAT FFFEGENERAL 0000");
    kernel[0x40..0x42].copy_from_slice(&[0xae, 0xfe]);
    kernel[0x46..0x48].copy_from_slice(&[0xae, 0xf0]);
    kernel[0x100..0x114].copy_from_slice(&[
        0x7a, 0x20, 0, 0, 1, 0, 0x47, 12, 0x7a, 0x20, 0, 0, 2, 0, 0x47, 4, 1, 0xf0, 0x65, 5,
    ]);
    // Forward-rotation decode loop after the XOR-skip branch; without it
    // pioneer-optical 0.15.0 returns UnknownRotation from Update::load.
    kernel[0x114..0x126].copy_from_slice(&[
        0x79, 0x63, 0, 0x1f, 0x0d, 0x31, 0x5e, 0x40, 0x01, 0x22, 1, 0xf0, 0x64, 0x40, 0x11, 0x70,
        0x54, 0x70,
    ]);
    let finalizer = if gated {
        GATED_FINALIZER
    } else {
        UNGATED_FINALIZER
    };
    kernel[0x300..0x300 + finalizer.len()].copy_from_slice(finalizer);
    for (offset, address) in [(0x349, [0x40, 0x20, 0]), (0x355, [0x40, 0x22, 0])] {
        kernel[offset..offset + 3].copy_from_slice(&address);
    }
    if gated {
        kernel[0x363..0x366].copy_from_slice(&[0x40, 0x30, 0]);
        kernel[0x3000..0x3000 + MARKER_CHECK.len()].copy_from_slice(MARKER_CHECK);
    }
    kernel[pioneer_optical::envelope::KERNEL_MARKER_OFFSET] = marker;
    balance(&mut kernel);
    let mut normal = vec![0; 0x2000];
    normal[..16].copy_from_slice(b"PIONEER TEST-NEW");
    normal[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    normal[0x400..0x408].copy_from_slice(&[0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36, 0, 0]);
    normal[0x500..0x510].copy_from_slice(&[
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, 4, 0x46, 0x4e,
    ]);
    balance(&mut normal);
    let encoded = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "26/10/07",
            kernel: KernelBuild::from_seed(7),
            normal_key_seed: 11,
        },
        NormalSignature::Oem(&pair_signature("prepared", gated, marker)),
    )
    .unwrap();
    Update::load(&encoded.kernel, &encoded.normal).unwrap()
}
fn bounded_backup_fixture() -> (Vec<u8>, Vec<u8>) {
    fn put(image: &mut [u8], offset: usize, hex: &str) {
        let bytes: Vec<_> = hex
            .split_whitespace()
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect();
        image[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }
    fn fix(image: &mut [u8]) {
        let end = image.len() - 4;
        image[end..].fill(0);
        let sum = image
            .as_chunks::<4>()
            .0
            .iter()
            .fold(0u32, |s, w| s.wrapping_add(u32::from_be_bytes(*w)));
        image[end..].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    }
    let mut kernel = vec![0; 0x10000];
    kernel[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    kernel[0x1008..0x1010].copy_from_slice(b"GENERAL ");
    kernel[0x1010..0x1014].copy_from_slice(b"0000");
    let id = b"PIONEER BD-RW   BDR-UD04";
    kernel[0x2000..0x2000 + id.len()].copy_from_slice(id);
    put(&mut kernel, 0x40, "ae fe 00 00 00 00 ae f0");
    put(
        &mut kernel,
        0x100,
        "7a 20 00 00 01 00 47 0c 7a 20 00 00 02 00 47 04 01 f0 65 05",
    );
    // Forward-rotation decode loop after the XOR-skip branch; without it
    // pioneer-optical 0.15.0 returns UnknownRotation from Update::load.
    put(
        &mut kernel,
        0x114,
        "79 63 00 1f 0d 31 5e 40 01 22 01 f0 64 40 11 70 54 70",
    );
    put(&mut kernel, 0x200, "18 bb 1a 91 0c b9 78 10 6a 2a 00 41 00 00 78 10 6a 28 00 40 20 00 1c 8a 47 04 5e 40 10 20 0a 0b ab 10 45 de");
    put(&mut kernel, 0x400, "1a a2 7a 01 00 40 00 00 01 00 6b 23 00 41 00 14 7a 13 00 41 00 00 40 06 01 00 6d 10 0a 82 1f b1 46 f6");
    fix(&mut kernel);
    let mut normal = vec![0; 0x2000];
    normal[..16].copy_from_slice(&id[..16]);
    normal[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    normal[24..32].copy_from_slice(b"GENERAL ");
    fix(&mut normal);
    (kernel, normal)
}

fn pioneer_pair(gated: bool, marker: u8) -> Update {
    fixture_pair(gated, marker)
}

/// Two header-only envelopes (`kernel.enc` + `normal.enc`) in a tar.
fn header_only_bundle() -> Vec<u8> {
    let envelope = |kind: &str| {
        let mut bytes = vec![0u8; 0x1000];
        let header = format!("********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   NEW-DRIVE\r\nRevision Level : 1.00\r\nHardware Version : SAT 8800\r\nKernel Version : ID60\r\nDestination : GENERAL\r\nFile Type : {kind}\r\n");
        bytes[..header.len()].copy_from_slice(header.as_bytes());
        bytes
    };
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("kernel.enc", envelope("Kernel")),
        ("normal.enc", envelope("Normal")),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    tar.into_inner().unwrap()
}

/// A Pioneer Normal envelope whose body also contains the MediaTek family tag.
fn pioneer_bundle_with_mtek_tag() -> Vec<u8> {
    let mut normal = vec![0u8; 0x1d7000];
    let head = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11 .\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
    normal[..head.len()].copy_from_slice(head);
    normal[0x1000..0x100A].copy_from_slice(b"MTEKMT1959");
    let mut tar_bytes = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut tar_bytes);
        let path = "components/normal.enc";
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_size(normal.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &normal[..]).unwrap();
        tar.finish().unwrap();
    }
    tar_bytes
}

/// A bare Normal-only UD04 envelope header padded to the OEM size.
fn ud04_normal_bin() -> Vec<u8> {
    let mut img = vec![0u8; 0x1D7000];
    let header = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nThis is microcode file.\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 9.99 .\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
    img[..header.len()].copy_from_slice(header);
    img
}

/// The firmware files `info <file>` / `check <file>` are recorded against.
fn info_files(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut unsigned = vec![0u8; IMAGE_SIZE];
    stamp_descriptor(&mut unsigned, "BD-RE BU40N");
    let mut bad_cmac = backup_firmware();
    bad_cmac[0x11000] ^= 1;
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("pioneer_bundle_header_only.tar", header_only_bundle()),
        (
            "pioneer_bundle_signed_pair.tar",
            archive(&pioneer_pair(false, 1), false),
        ),
        (
            "pioneer_bundle_mtek_tag.tar",
            pioneer_bundle_with_mtek_tag(),
        ),
        ("pioneer_normal_ud04.bin", ud04_normal_bin()),
        ("mtk_flashable.bin", backup_firmware()),
        ("mtk_bad_cmac.bin", bad_cmac),
        ("mtk_unsigned.bin", unsigned),
        ("zeros_2mib.bin", vec![0u8; IMAGE_SIZE]),
        (
            "mtk_drive_read_backup.bin",
            drive_read(&stored_image(b"MTEKMT1959", "BD-RE BU40N", 3)),
        ),
        (
            "mtk_mt1959_stored.bin",
            stored_image(b"MTEKMT1959", "BD-RE BU40N", 3),
        ),
        (
            "mtk_mt1939_stored.bin",
            stored_image(b"MTEKMT1939", "BD-RE BE14NU40", 7),
        ),
        ("mtk_legacy_0_10_backup.tar", legacy_mtk_tar()),
        ("pioneer_signed_normal.enc", {
            let update = pioneer_pair(false, 0);
            update.normal().repack(&update.normal().image).unwrap()
        }),
        ("pioneer_raw_header.bin", {
            let mut img = vec![0u8; 0x200];
            img[..8].fill(b'*');
            img[0x0a..0x0a + 21].copy_from_slice(b"Copyright(c) 2000 Pio");
            img[0x1e..0x1e + 21].copy_from_slice(b"Pioneer Corporation  ");
            img[0x70..0x70 + 7].copy_from_slice(b"BDR-212");
            let lbl = b"Revision Level : ";
            img[0x7f..0x7f + lbl.len()].copy_from_slice(lbl);
            img[0x7f + lbl.len()..0x7f + lbl.len() + 4].copy_from_slice(b"1.05");
            img
        }),
        ("pioneer_packed.bin", {
            let mut img = vec![0u8; 0x1000];
            img[..6].copy_from_slice(&[0x78, 0x01, 0x63, 0x60, 0x18, 0x05]);
            img
        }),
        ("mediatek_encrypted_envelope.bin", {
            let mut img = vec![0u8; 0x2000];
            img[..16].copy_from_slice(&[
                0xa9, 0xcc, 0xe8, 0x47, 0x2c, 0x0f, 0x30, 0x86, 0xb7, 0x44, 0xf5, 0x62, 0x19, 0xfa,
                0x94, 0xa3,
            ]);
            img
        }),
        (
            "lg_legacy_dump.bin",
            flash_dump(
                0x0041_0140,
                Some((
                    b"Hitachi-LG Data Storage,Inc.",
                    "HL-DT-STBD-RE  GGW-H20N",
                    "y217.08.06.09a",
                )),
            ),
        ),
        ("renesas_dump.bin", flash_dump(0x005A_80E2, None)),
        ("mediatek_bridge_dump.bin", flash_dump(0x00DC_5D5D, None)),
        (
            "garbage.bin",
            b"this is not firmware, just some text\n".to_vec(),
        ),
        ("empty.bin", Vec::new()),
    ];
    files
        .into_iter()
        .map(|(name, bytes)| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            (name.to_string(), path)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. info (device)
// ---------------------------------------------------------------------------

#[test]
fn golden_info_mtk() {
    let mut g = Golden::default();
    for (title, dev) in [
        (
            "MTK info: mock exposing a drive-read firmware image",
            mtk_drive(),
        ),
        (
            "MTK info: classify-only mock (MockScsiDevice::mtk)",
            MockScsiDevice::mtk(),
        ),
    ] {
        let (outcome, transcript) = drive_run(dev, |d| crate::engine::info(d, Some(&Mtk)));
        g.case(title, &outcome, Some(&transcript));
    }
    check("info_mtk", g);
}

#[test]
fn golden_info_pioneer() {
    let mut g = Golden::default();
    for (title, dev) in [
        (
            "Pioneer info: MockScsiDevice::pioneer",
            MockScsiDevice::pioneer(),
        ),
        (
            "Renesas info: MockScsiDevice::renesas (Pioneer backend)",
            MockScsiDevice::renesas(),
        ),
    ] {
        let (outcome, transcript) =
            drive_run(dev, |d| crate::engine::info(d, Some(&Pioneer::new())));
        g.case(title, &outcome, Some(&transcript));
    }
    check("info_pioneer", g);
}

// ---------------------------------------------------------------------------
// 2 + 7. info <file> and check <file>
// ---------------------------------------------------------------------------

#[test]
fn golden_info_file() {
    let dir = scratch("info-file");
    let mut g = Golden::default();
    for (name, path) in info_files(&dir) {
        let outcome = run(|| crate::engine::info_file(&path));
        g.case(&format!("info_file {name}"), &outcome, None);
    }
    check("info_file", g);
}

#[test]
fn golden_check_file() {
    let dir = scratch("check-file");
    let mut g = Golden::default();
    for (name, path) in info_files(&dir) {
        let outcome = run(|| crate::workflow::check_file(&path));
        g.case(&format!("check_file {name}"), &outcome, None);
    }
    let missing = dir.join("does-not-exist.bin");
    let outcome = run(|| crate::workflow::check_file(&missing));
    g.case("check_file missing file", &outcome, None);
    check("check_file", g);
}

// ---------------------------------------------------------------------------
// 3. flash dry run
// ---------------------------------------------------------------------------

fn pioneer_request(input: Vec<u8>, kind: &'static FileFormat, execute: bool) -> FlashRequest {
    FlashRequest {
        current: None,
        input,
        input_format: kind,
        mode: FlashMode::Full,
        execute,
        acknowledged_risk: execute,
        enc_override: None,
        drive_model: "BD-RW   BDR-TEST".into(),
        verbose: false,
        predump_out: None,
    }
}

#[test]
fn golden_flash_dry_run() {
    let mut g = Golden::default();
    let good = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");

    let mut verbose = mtk_request(good.clone(), false, None);
    verbose.verbose = true;
    let mut bad_cmac = good.clone();
    bad_cmac[0x11000] ^= 1;
    let wrong_family = make_flashable_other_family("WH16NS60");
    for (title, req) in [
        ("MTK dry run: .bin", mtk_request(good.clone(), false, None)),
        ("MTK dry run: .bin verbose", verbose),
        (
            "MTK dry run: bad CMAC refused",
            mtk_request(bad_cmac, false, None),
        ),
        (
            "MTK dry run: different family refused",
            mtk_request(wrong_family, false, None),
        ),
        (
            "MTK dry run: wrong size refused",
            mtk_request(vec![0u8; 1024], false, None),
        ),
    ] {
        let (outcome, transcript) = drive_run(mtk_drive(), |d| engine_flash(d, &Mtk, &req));
        g.case(title, &outcome, Some(&transcript));
    }

    let bundle = archive(&pioneer_pair(false, 0), false);
    let mut verbose = pioneer_request(bundle.clone(), &PIONEER_PACKAGE, false);
    verbose.verbose = true;
    for (title, req) in [
        (
            "Pioneer dry run: signed Kernel+Normal bundle",
            pioneer_request(bundle.clone(), &PIONEER_PACKAGE, false),
        ),
        ("Pioneer dry run: bundle verbose", verbose),
        (
            "Pioneer dry run: header-only bundle",
            pioneer_request(header_only_bundle(), &PIONEER_PACKAGE, false),
        ),
        (
            "Pioneer dry run: bare signed Normal .enc",
            pioneer_request(
                {
                    let update = pioneer_pair(false, 0);
                    update.normal().repack(&update.normal().image).unwrap()
                },
                &PIONEER_ENVELOPE,
                false,
            ),
        ),
        (
            "Pioneer dry run: UD04 Normal .bin",
            pioneer_request(ud04_normal_bin(), &PIONEER_ENVELOPE, false),
        ),
        (
            "Pioneer dry run: garbage .bin",
            pioneer_request(b"garbage".to_vec(), &PIONEER_ENVELOPE, false),
        ),
        (
            "Pioneer dry run: Tar kind refused",
            pioneer_request(bundle.clone(), &MTK_LEGACY_TAR, false),
        ),
    ] {
        let (outcome, transcript) = drive_run(MockScsiDevice::pioneer(), |d| {
            engine_flash(d, &Pioneer::new(), &req)
        });
        g.case(title, &outcome, Some(&transcript));
    }

    // A Pioneer bundle against an MTK drive and an MTK image against Pioneer.
    let req = pioneer_request(bundle, &PIONEER_PACKAGE, false);
    let (outcome, transcript) = drive_run(mtk_drive(), |d| engine_flash(d, &Mtk, &req));
    g.case(
        "MTK drive given a Pioneer bundle",
        &outcome,
        Some(&transcript),
    );
    check("flash_dry_run", g);
}

// ---------------------------------------------------------------------------
// 4. flash execute
// ---------------------------------------------------------------------------

#[test]
fn golden_flash_execute() {
    let dir = scratch("flash-execute");
    let mut g = Golden::default();

    // MTK: full execute with the mandatory pre-flash backup.
    let image = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    let rollback = dir.join("mtk_rollback.tar");
    let req = mtk_request(image.clone(), true, Some(rollback.clone()));
    let echoing = || MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    let (outcome, transcript) = drive_run(echoing(), |d| engine_flash(d, &Mtk, &req));
    g.case(
        "MTK execute: .bin with pre-flash backup",
        &outcome,
        Some(&transcript),
    );
    g.file("saved pre-flash backup", &rollback);
    g.kv(
        "image chunks streamed",
        &format!("{} x {CHUNK} bytes", IMAGE_SIZE / CHUNK),
    );

    // MTK: the drive does not echo what was written -> read-back verify fails.
    let mismatch = dir.join("mtk_rollback_mismatch.tar");
    let req_mismatch = mtk_request(image.clone(), true, Some(mismatch.clone()));
    let (outcome, transcript) = drive_run(mtk_drive(), |d| engine_flash(d, &Mtk, &req_mismatch));
    g.case(
        "MTK execute: read-back mismatch",
        &outcome,
        Some(&transcript),
    );
    g.file("saved pre-flash backup", &mismatch);

    // MTK: restore the archive that run just saved (rollback flow).
    let saved = std::fs::read(&rollback).unwrap();
    let second = dir.join("mtk_rollback_of_restore.tar");
    let mut restore = mtk_request(saved, true, Some(second.clone()));
    restore.input_format = &MTK_LEGACY_TAR;
    restore.drive_model = "BD-RE BU40N".into();
    let dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, &Mtk, &restore));
    g.case(
        "MTK execute: restore the saved .tar",
        &outcome,
        Some(&transcript),
    );
    g.file("saved pre-flash backup", &second);

    // MTK: refusals on the execute path.
    let mut no_ack = mtk_request(image.clone(), true, Some(dir.join("never.tar")));
    no_ack.acknowledged_risk = false;
    for (title, req, dev) in [
        ("MTK execute: no risk acknowledgement", no_ack, mtk_drive()),
        (
            "MTK execute: disc loaded",
            mtk_request(image.clone(), true, Some(dir.join("disc.tar"))),
            mtk_drive().with_medium_loaded(),
        ),
        (
            "MTK execute: tray open",
            mtk_request(image.clone(), true, Some(dir.join("tray.tar"))),
            mtk_drive().with_tray_open(),
        ),
    ] {
        let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, &Mtk, &req));
        g.case(title, &outcome, Some(&transcript));
    }
    g.file(
        "refused runs left a file at disc.tar",
        &dir.join("disc.tar"),
    );
    g.file(
        "refused runs left a file at never.tar",
        &dir.join("never.tar"),
    );

    // Pioneer: engine-level execute stops where the existing mocks allow.
    let target = archive(&pioneer_pair(false, 0), false);
    let mut no_ack = pioneer_request(target.clone(), &PIONEER_PACKAGE, true);
    no_ack.acknowledged_risk = false;
    no_ack.predump_out = Some(dir.join("pioneer_no_ack.tar"));
    let mut with_backup = pioneer_request(target.clone(), &PIONEER_PACKAGE, true);
    with_backup.predump_out = Some(dir.join("pioneer_rollback.tar"));
    let mut disc_loaded = pioneer_request(target.clone(), &PIONEER_PACKAGE, true);
    disc_loaded.predump_out = Some(dir.join("pioneer_disc.tar"));
    let mut wrong_family = pioneer_request(target.clone(), &PIONEER_PACKAGE, true);
    wrong_family.predump_out = Some(dir.join("pioneer_on_mtk.tar"));
    for (title, req, dev) in [
        (
            "Pioneer execute: no risk acknowledgement",
            no_ack,
            MockScsiDevice::pioneer(),
        ),
        (
            "Pioneer execute: pre-flash backup cannot be read",
            with_backup,
            MockScsiDevice::pioneer(),
        ),
        (
            "Pioneer execute: disc loaded",
            disc_loaded,
            MockScsiDevice::pioneer().with_medium_loaded(),
        ),
        (
            "MTK execute: Pioneer bundle sent to an MTK drive",
            wrong_family,
            mtk_drive(),
        ),
    ] {
        let family: Box<dyn Backend> = if title.contains("MTK drive") {
            Box::new(Mtk)
        } else {
            Box::new(Pioneer::new())
        };
        let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, family.as_ref(), &req));
        let expected_refusal = match title {
            "Pioneer execute: no risk acknowledgement" => "SAFETY GATE",
            "Pioneer execute: pre-flash backup cannot be read" => "errors.backup_required",
            "Pioneer execute: disc loaded" => "a disc is loaded",
            "MTK execute: Pioneer bundle sent to an MTK drive" => {
                "a Pioneer firmware bundle cannot be flashed to this mtk19xx drive"
            }
            _ => unreachable!(),
        };
        assert!(
            outcome.result.contains(expected_refusal),
            "{title}: {}",
            outcome.result
        );
        g.case(title, &outcome, Some(&transcript));
    }
    g.file(
        "failed Pioneer backup left a file",
        &dir.join("pioneer_rollback.tar"),
    );

    // MTK: images the write path refuses, on execute (the backup is not taken).
    for (title, image) in [
        (
            "MTK execute: MT1939 image on an MT1959 drive",
            stored_image(b"MTEKMT1939", "BD-RE BU40N", 3),
        ),
        (
            "MTK execute: raw drive read as input",
            drive_read(&stored_image(b"MTEKMT1959", "BD-RE BU40N", 3)),
        ),
    ] {
        let backup = dir.join(format!("refused_{}.tar", title.len()));
        let req = mtk_request(image, true, Some(backup.clone()));
        let (outcome, transcript) = drive_run(echoing(), |d| engine_flash(d, &Mtk, &req));
        g.case(title, &outcome, Some(&transcript));
        g.file("saved pre-flash backup", &backup);
    }
    check("flash_execute", g);
}

// ---------------------------------------------------------------------------
// 5. backup capture
// ---------------------------------------------------------------------------

/// Replays captured address space for the bounded Pioneer backup transaction.
struct BackupReplay {
    dump: Vec<u8>,
    knocks: usize,
}

impl BackupReplay {
    fn new() -> Self {
        let (kernel, normal) = bounded_backup_fixture();
        let mut dump = vec![0; 0x410000 + normal.len()];
        dump[0x400000..0x410000].copy_from_slice(&kernel);
        dump[0x410000..].copy_from_slice(&normal);
        Self { dump, knocks: 0 }
    }
}

impl ScsiDevice for BackupReplay {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb == [0x12, 0, 0, 0, len as u8, 0] && matches!(len, 36 | 96) {
            let mut data = vec![0; len];
            data[8..16].copy_from_slice(b"PIONEER ");
            data[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
            data[32..36].copy_from_slice(b"1.14");
            return Ok(data);
        }
        if cdb == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
            let mut data = vec![0; 48];
            data[16..24].copy_from_slice(b"SAT 8A10");
            return Ok(data);
        }
        if cdb == [0x3c, 0x06, 0, 0, 0x30, 0, 0, 0, 0x20, 0] {
            bail!("Pioneer does not implement the MTK identity buffer");
        }
        if self.knocks == 0 {
            return Err(
                crate::platform::ScsiSenseError::new(5, 0x24, 0, "read access locked").into(),
            );
        }
        if cdb.len() != 10 || cdb[..3] != [0x3c, 2, 0xb0] {
            bail!("unexpected read {}", hex(cdb));
        }
        let offset = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
        if offset < 0x400000 || offset + len > self.dump.len() {
            return Err(
                crate::platform::ScsiSenseError::new(5, 0x24, 0, "outside firmware").into(),
            );
        }
        Ok(self.dump[offset..offset + len].to_vec())
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        if cdb != [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0] || !data.is_empty() {
            bail!("unexpected write {}", hex(cdb));
        }
        self.knocks += 1;
        Ok(())
    }

    fn describe(&self) -> String {
        "saved capture replay; no hardware".into()
    }
}

#[test]
fn golden_backup_capture() {
    let dir = scratch("backup");
    let mut g = Golden::default();

    for (title, name, recover) in [
        ("MTK backup: drive-read image", "mtk_backup.tar", false),
        ("MTK dump (recover): raw memory", "mtk_dump.bin", true),
    ] {
        let out = dir.join(name);
        let (outcome, transcript) = drive_run(mtk_drive(), |d| {
            crate::engine::backup(d, &Mtk, &out, recover)
        });
        g.case(title, &outcome, Some(&transcript));
        g.file("saved file", &out);
    }

    // A second backup to the same path is refused and must not touch the file.
    let out = dir.join("mtk_backup.tar");
    let (outcome, transcript) =
        drive_run(mtk_drive(), |d| crate::engine::backup(d, &Mtk, &out, false));
    g.case(
        "MTK backup: destination exists",
        &outcome,
        Some(&transcript),
    );
    g.file("saved file", &out);

    let out = dir.join("pioneer_backup.tar");
    let (outcome, transcript) = drive_run(BackupReplay::new(), |d| {
        crate::engine::backup(d, &Pioneer::new(), &out, false)
    });
    g.case(
        "Pioneer backup: bounded replay of a UD04",
        &outcome,
        Some(&transcript),
    );
    g.file("saved file", &out);

    let out = dir.join("pioneer_dump.bin");
    let (outcome, transcript) = drive_run(BackupReplay::new(), |d| {
        crate::engine::backup(d, &Pioneer::new(), &out, true)
    });
    let outcome = outcome.mask_digest("candidate sha256: ");
    g.case(
        "Pioneer dump (recover): bounded replay",
        &outcome,
        Some(&transcript),
    );
    g.dump_file("saved file", &out);

    let out = dir.join("pioneer_unreadable.tar");
    let (outcome, transcript) = drive_run(MockScsiDevice::pioneer(), |d| {
        crate::engine::backup(d, &Pioneer::new(), &out, false)
    });
    g.case(
        "Pioneer backup: firmware unreadable",
        &outcome,
        Some(&transcript),
    );
    g.file("saved file", &out);
    check("backup_capture", g);
}

// ---------------------------------------------------------------------------
// 6. Pioneer recover
// ---------------------------------------------------------------------------

#[test]
fn golden_pioneer_recover() {
    let mut g = Golden::default();
    let current = archive(&fixture_pair(false, 1), false);
    let target = archive(&fixture_pair(false, 0), false);
    let unsigned_current = archive(&fixture_pair(false, 1), true);

    let cases: Vec<(&str, RecoveryDrive, Vec<u8>, Vec<u8>, bool)> = vec![
        (
            "Pioneer recover dry run: receiver in kernel mode",
            RecoveryDrive {
                updating: true,
                ..Default::default()
            },
            current.clone(),
            target.clone(),
            false,
        ),
        (
            "Pioneer recover dry run: receiver in normal mode",
            RecoveryDrive::default(),
            current.clone(),
            target.clone(),
            false,
        ),
        (
            "Pioneer recover dry run: unsigned Current backup",
            RecoveryDrive {
                updating: true,
                ..Default::default()
            },
            unsigned_current,
            target.clone(),
            false,
        ),
        (
            "Pioneer recover dry run: garbage Current",
            RecoveryDrive {
                updating: true,
                ..Default::default()
            },
            b"garbage".to_vec(),
            target.clone(),
            false,
        ),
        (
            "Pioneer recover execute: receiver in kernel mode",
            RecoveryDrive {
                updating: true,
                ..Default::default()
            },
            current.clone(),
            target.clone(),
            true,
        ),
        (
            "Pioneer recover execute: receiver in normal mode",
            RecoveryDrive::default(),
            current.clone(),
            target.clone(),
            true,
        ),
        (
            "Pioneer recover execute: write fails on the 2nd command",
            RecoveryDrive {
                updating: true,
                fail_write: Some(2),
                ..Default::default()
            },
            current.clone(),
            target.clone(),
            true,
        ),
    ];
    for (title, dev, cur, tgt, execute) in cases {
        let (outcome, transcript) = drive_run(dev, |d| recover_via(d, Some(&cur), &tgt, execute));
        g.case(title, &outcome, Some(&transcript));
    }

    // Unrecognized drive: refuses before any firmware read or write.
    let (outcome, transcript) = drive_run(MockScsiDevice::new(), |d| {
        recover_via(d, Some(&current), &target, true)
    });
    g.case(
        "Pioneer recover execute: unrecognized drive",
        &outcome,
        Some(&transcript),
    );
    // Without Current on an unrecognized drive.
    let (outcome, transcript) = drive_run(MockScsiDevice::new(), |d| {
        recover_via(d, None, &target, false)
    });
    g.case(
        "Pioneer recover dry run: no Current, unrecognized drive",
        &outcome,
        Some(&transcript),
    );
    check("pioneer_recover", g);
}

// ---------------------------------------------------------------------------
// Classification and `info` on drives that match no backend / more than one
// ---------------------------------------------------------------------------

fn ambiguous_drive() -> MockScsiDevice {
    let mut inq = vec![0u8; 96];
    inq[0] = 5;
    inq[8..16].copy_from_slice(b"PIONEER ");
    inq[16..24].copy_from_slice(b"BDR-UD04");
    let mut f1 = vec![0u8; 48];
    f1[16..24].copy_from_slice(b"SAT 8A10");
    f1[24..28].copy_from_slice(b"ID40");
    f1[32..36].copy_from_slice(b"ID40");
    MockScsiDevice::mtk()
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            f1,
        )
        .on(|cdb| cdb.first() == Some(&0x12), inq)
}

/// COMPAT: the pre-0.12 `Family` debug names these scenarios recorded.
fn family_label(id: Option<BackendId>) -> &'static str {
    match id.map(|id| id.0) {
        None => "Unknown",
        Some("mtk19xx") => "Mtk",
        Some("pioneer-oem") => "Pioneer",
        Some(other) => panic!("no recorded label for backend {other}"),
    }
}

#[test]
fn golden_classify_and_unknown_info() {
    let mut g = Golden::default();
    let drives: Vec<(&str, Box<dyn Fn() -> MockScsiDevice>)> = vec![
        (
            "blank mock (matches no backend)",
            Box::new(MockScsiDevice::new),
        ),
        ("MockScsiDevice::mtk", Box::new(MockScsiDevice::mtk)),
        ("MockScsiDevice::pioneer", Box::new(MockScsiDevice::pioneer)),
        ("MockScsiDevice::renesas", Box::new(MockScsiDevice::renesas)),
        (
            "ambiguous: MediaTek and Pioneer both match",
            Box::new(ambiguous_drive),
        ),
        ("MediaTek firmware-image mock", Box::new(mtk_drive)),
    ];
    for (title, make) in &drives {
        let mut rec = Rec::new(make());
        let outcome = run(|| {
            let classified = crate::backend::registry::resolve(&mut rec).ok().flatten();
            println!(
                "classify: {}",
                family_label(classified.map(|m| m.matched.backend))
            );
            match crate::backend::registry::resolve(&mut rec) {
                Ok(Some(m)) => println!(
                    "resolve_backend: {} backend={}",
                    family_label(Some(m.matched.backend)),
                    m.matched.backend
                ),
                Ok(None) => println!("resolve_backend: no match"),
                Err(e) => println!("resolve_backend: error {e:#}"),
            }
            match crate::workflow::classify_gated(&mut rec) {
                Ok(id) => println!("classify_gated: {}", family_label(Some(id))),
                Err(e) => println!("classify_gated: error {e:#}"),
            }
            Ok(())
        });
        g.case(
            &format!("classify {title}"),
            &outcome,
            Some(&rec.transcript()),
        );
    }
    for (title, make) in &drives {
        let (outcome, transcript) = drive_run(make(), |d| crate::engine::info(d, None));
        g.case(
            &format!("info with the Unknown handler on {title}"),
            &outcome,
            Some(&transcript),
        );
    }
    check("classify_and_unknown_info", g);
}

// ---------------------------------------------------------------------------
// MediaTek backup / dump variants and refusals
// ---------------------------------------------------------------------------

#[test]
fn golden_mtk_backup_variants() {
    let dir = scratch("mtk-backup");
    let mut g = Golden::default();
    let installed = stored_image(b"MTEKMT1959", "BD-RE BU40N", 3);
    let mut unknown_boot = drive_read(&installed);
    unknown_boot[0] ^= 1;
    let mt1939 = drive_read(&stored_image(b"MTEKMT1939", "BD-RE BE14NU40", 7));
    type Make<'a> = Box<dyn Fn() -> MockScsiDevice + 'a>;
    let drives: Vec<(&str, &str, Make)> = vec![
        (
            "MT1959 drive read",
            "mt1959.bak",
            Box::new(|| MockScsiDevice::new().with_firmware_image(drive_read(&installed))),
        ),
        (
            "MT1939 drive read (build not in the catalog)",
            "mt1939.bak",
            Box::new(|| {
                with_inquiry_product(
                    MockScsiDevice::new().with_firmware_image(mt1939.clone()),
                    "BD-RE BE14NU40",
                )
            }),
        ),
        (
            "unknown boot page",
            "unknown_boot.bak",
            Box::new(|| MockScsiDevice::new().with_firmware_image(unknown_boot.clone())),
        ),
        (
            "firmware read fails at 0x100000",
            "read_fail.bak",
            Box::new(|| {
                MockScsiDevice::new()
                    .with_firmware_image(drive_read(&installed))
                    .on_fail(
                        |cdb| {
                            cdb.first() == Some(&0x3C)
                                && cdb.get(1).map(|m| m & 0x1f) == Some(6)
                                && cdb.get(3..6) == Some(&[0x10, 0x00, 0x00][..])
                        },
                        "injected read failure",
                    )
            }),
        ),
    ];
    for (title, name, make) in &drives {
        for recover in [false, true] {
            let out = dir.join(format!("{}{name}", if recover { "dump_" } else { "" }));
            let (outcome, transcript) =
                drive_run(make(), |d| crate::engine::backup(d, &Mtk, &out, recover));
            g.case(
                &format!("MTK {}: {title}", if recover { "dump" } else { "backup" }),
                &outcome,
                Some(&transcript),
            );
            g.file("saved file", &out);
        }
    }
    check("mtk_backup_variants", g);
}

// ---------------------------------------------------------------------------
// MediaTek flash dry run: images the write path must refuse or flag
// ---------------------------------------------------------------------------

/// A same-model drive and image per board line, flashed through the real
/// engine: the family gate refuses across lines after the backup and before
/// any write, and refuses an unknown family; within a line the OEM session
/// runs unchanged.
#[test]
fn golden_mtk_family_gate() {
    let dir = scratch("mtk-family");
    let mut g = Golden::default();
    let model = "BD-RE  BH16NS40";
    let jb7 = fixture::image(&fixture::JB7, model, 3);
    let jb8 = fixture::image(&fixture::JB8, model, 5);
    let nameless = fixture::without_record(&jb7);
    let cases: [(&str, &[u8], &[u8]); 6] = [
        ("JB7 drive reflashed with its own build", &jb7, &jb7),
        ("JB8 drive reflashed with its own build", &jb8, &jb8),
        ("JB8 image onto a JB7 drive of the same model", &jb7, &jb8),
        ("JB7 image onto a JB8 drive of the same model", &jb8, &jb7),
        ("image without a hardware record", &jb7, &nameless),
        ("drive without a hardware record", &nameless, &jb7),
    ];
    for (i, (title, installed, target)) in cases.into_iter().enumerate() {
        let backup = dir.join(format!("backup_{i}.bin"));
        let mut req = mtk_request(target.to_vec(), true, Some(backup.clone()));
        req.drive_model = model.into();
        let dev = MockScsiDevice::echoing()
            .with_firmware_image(drive_read(installed))
            .with_product(model);
        let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, &Mtk, &req));
        g.case(
            &format!("MTK execute: {title}"),
            &outcome,
            Some(&transcript),
        );
        g.file("saved pre-flash backup", &backup);
    }
    check("mtk_family_gate", g);
}

#[test]
fn golden_mtk_flash_input_refusals() {
    let mut g = Golden::default();
    let mut unknown_boot = stored_image(b"MTEKMT1959", "BD-RE BU40N", 3);
    unknown_boot[0] ^= 1;
    let unknown_boot = crate::cmac::resign(&unknown_boot).unwrap();
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        (
            "raw drive read as input",
            drive_read(&stored_image(b"MTEKMT1959", "BD-RE BU40N", 3)),
        ),
        ("unknown boot page, validly signed", unknown_boot),
        (
            "MT1939 image on an MT1959 drive",
            stored_image(b"MTEKMT1939", "BD-RE BU40N", 3),
        ),
        ("unsigned image", {
            let mut img = vec![0u8; IMAGE_SIZE];
            stamp_descriptor(&mut img, "BD-RE BU40N");
            img
        }),
        ("all zeros", vec![0u8; IMAGE_SIZE]),
    ];
    for (title, image) in inputs {
        let req = mtk_request(image.clone(), false, None);
        let (outcome, transcript) = drive_run(mtk_drive(), |d| engine_flash(d, &Mtk, &req));
        g.case(
            &format!("MTK dry run: {title}"),
            &outcome,
            Some(&transcript),
        );
    }
    // Tray / medium state on a dry run is a warning, not a refusal.
    let good = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    for (title, dev) in [
        ("disc loaded", mtk_drive().with_medium_loaded()),
        ("tray open", mtk_drive().with_tray_open()),
    ] {
        let req = mtk_request(good.clone(), false, None);
        let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, &Mtk, &req));
        g.case(
            &format!("MTK dry run: {title}"),
            &outcome,
            Some(&transcript),
        );
    }
    let bundle = archive(&pioneer_pair(false, 0), false);
    for (title, dev) in [
        (
            "disc loaded",
            MockScsiDevice::pioneer().with_medium_loaded(),
        ),
        ("tray open", MockScsiDevice::pioneer().with_tray_open()),
    ] {
        let req = pioneer_request(bundle.clone(), &PIONEER_PACKAGE, false);
        let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, &Pioneer::new(), &req));
        g.case(
            &format!("Pioneer dry run: {title}"),
            &outcome,
            Some(&transcript),
        );
    }
    check("mtk_flash_input_refusals", g);
}

// ---------------------------------------------------------------------------
// Pioneer plan decisions, backup coverage, bundle gates, partial backups
// ---------------------------------------------------------------------------

/// A header-only Normal envelope (parses as a Normal; carries no body).
fn header_only_normal(sat: &str, date: &str, kernel_tag: &str) -> Vec<u8> {
    let mut img = vec![0u8; 0x200];
    let header = format!(
        "********  Copyright(c) 2000 Pioneer Corporation  ********\r\n\
         ID : PIONEER BD-RW   BDR-UD04\r\n\
         Revision Level : 1.11\r\n\
         Hardware Version : {sat}\r\n\
         Destination : GENERAL\r\n\
         Generated Date : {date}\r\n\
         Kernel Version : {kernel_tag}\r\n\
         File Type : Normal\r\n"
    );
    img[..header.len()].copy_from_slice(header.as_bytes());
    img
}

fn header_only_kernel(sat: &str, kernel_tag: &str) -> Vec<u8> {
    let mut img = vec![0u8; 0x1000];
    let header = format!(
        "********  Copyright(c) 2000 Pioneer Corporation  ********\r\n\
         ID : PIONEER BD-RW   BDR-UD04\r\n\
         Revision Level : 1.11\r\n\
         Hardware Version : {sat}\r\n\
         Destination : GENERAL\r\n\
         Kernel Version : {kernel_tag}\r\n\
         File Type : Kernel\r\n"
    );
    img[..header.len()].copy_from_slice(header.as_bytes());
    img
}

#[test]
fn golden_pioneer_plan_and_gates() {
    use crate::backends::pioneer::{resolve_flash_plan, routing_warnings};
    let mut g = Golden::default();

    // resolve_flash_plan / check_plan_executable over installed x target.
    let target = header_only_normal("SAT 8A10", "26/01/01", "ID58");
    let installed: Vec<(&str, Option<Vec<u8>>)> = vec![
        ("no backup", None),
        (
            "same-family Normal",
            Some(tar_of(&[(
                "normal.enc",
                &header_only_normal("SAT 8A10", "25/01/01", "ID58"),
            )])),
        ),
        (
            "other-family Normal",
            Some(tar_of(&[(
                "normal.enc",
                &header_only_normal("SAT 8800", "25/01/01", "ID58"),
            )])),
        ),
        ("garbage backup", Some(b"garbage".to_vec())),
    ];
    for (title, backup) in &installed {
        let outcome = run(|| {
            match resolve_flash_plan(backup.as_deref(), None, Some(&target)) {
                Ok(plan) => {
                    println!("plan: {plan:?}");
                    match routing_warnings(&plan) {
                        Ok(warnings) => {
                            for warning in warnings {
                                eprintln!("{}", crate::style::amber(&warning));
                            }
                            println!("executable: yes")
                        }
                        Err(e) => println!("executable: no: {e:#}"),
                    }
                }
                Err(e) => println!("plan error: {e:#}"),
            }
            Ok(())
        });
        g.case(
            &format!("resolve_flash_plan: installed={title}, plain"),
            &outcome,
            None,
        );
    }

    // Bundle self-consistency gate.
    let k = |sat: &str, tag: &str| header_only_kernel(sat, tag);
    let n = |sat: &str, tag: &str| header_only_normal(sat, "26/01/01", tag);
    let bundles: Vec<(&str, Option<Vec<u8>>, Option<Vec<u8>>)> = vec![
        (
            "matching pair",
            Some(k("SAT 8A10", "ID58")),
            Some(n("SAT 8A10", "ID58")),
        ),
        (
            "Kernel-tag mismatch",
            Some(k("SAT 8A10", "ID60")),
            Some(n("SAT 8A10", "ID58")),
        ),
        (
            "SAT mismatch",
            Some(k("SAT 8800", "ID58")),
            Some(n("SAT 8A10", "ID58")),
        ),
        ("Normal only", None, Some(n("SAT 8A10", "ID58"))),
        (
            "Kernel in the Normal slot",
            Some(k("SAT 8A10", "ID58")),
            Some(k("SAT 8A10", "ID58")),
        ),
        ("garbage Normal", None, Some(b"garbage".to_vec())),
    ];
    for (title, kernel, normal) in &bundles {
        let outcome = run(|| {
            match flash_plan::validate_bundle(kernel.as_deref(), normal.as_deref()) {
                Ok(()) => println!("validate_bundle: ok"),
                Err(e) => println!("validate_bundle: {e}"),
            }
            Ok(())
        });
        g.case(&format!("validate_bundle: {title}"), &outcome, None);
    }

    // Pre-flash backup coverage and notices for full / partial captures.
    let pair = pioneer_pair(false, 1);
    let kernel_enc = pair.kernel().repack(&pair.kernel().image).unwrap();
    let normal_enc = pair.normal().repack(&pair.normal().image).unwrap();
    let full = tar_of(&[("kernel.enc", &kernel_enc), ("normal.enc", &normal_enc)]);
    let kernel_only = tar_of(&[("kernel.enc", &kernel_enc)]);
    let normal_only = tar_of(&[("normal.enc", &normal_enc)]);
    let target_bundle = archive(&pioneer_pair(false, 0), false);
    let target_normal = pioneer_pair(false, 0)
        .normal()
        .repack(&pioneer_pair(false, 0).normal().image)
        .unwrap();
    for (title, backup) in [
        ("full backup", &full),
        ("Kernel-only (partial) backup", &kernel_only),
        ("Normal-only (partial) backup", &normal_only),
        ("garbage backup", &b"garbage".to_vec()),
    ] {
        for (input_title, input) in [
            ("Kernel+Normal bundle", &target_bundle),
            ("bare Normal", &target_normal),
        ] {
            let outcome = run(|| crate::backends::pioneer::verify_preflash_backup(backup, input));
            g.case(
                &format!("verify_preflash_backup: {title} vs {input_title}"),
                &outcome,
                None,
            );
        }
        let outcome = run(|| {
            match BackupFacet::notice(&Pioneer::new(), backup) {
                crate::backend::BackupNotice::VerifiedOem(m) => println!("VerifiedOem: {m}"),
                crate::backend::BackupNotice::Unverified(m) => println!("Unverified: {m}"),
                crate::backend::BackupNotice::None => println!("None"),
            }
            match BackupFacet::validate(&Pioneer::new(), backup, "BD-RW   BDR-TEST") {
                Ok(b) => println!("validate_backup: ok, {} bytes sha256={}", b.len(), sha(&b)),
                Err(e) => println!("validate_backup: {e:#}"),
            }
            Ok(())
        });
        g.case(
            &format!("backup_notice + validate_backup: {title}"),
            &outcome,
            None,
        );
    }
    check("pioneer_plan_and_gates", g);
}

// ---------------------------------------------------------------------------
// Pioneer execute end to end: the real engine on a replaying UD04
// ---------------------------------------------------------------------------

/// The UD04 backup fixture with Kernel tag `tag` and the synthetic receiver
/// code of [`prepared_pair`] grafted in: the real backup derives the Normal
/// layout from the former, and authorize needs the latter.
fn ud04_images(gated: bool, marker: u8, tag: &[u8; 8]) -> (Vec<u8>, Vec<u8>) {
    let (mut kernel, mut normal) = bounded_backup_fixture();
    crate::kernel_handoff_fixture(&mut kernel);
    kernel[0x1008..0x1010].copy_from_slice(tag);
    let finalizer = if gated {
        GATED_FINALIZER
    } else {
        UNGATED_FINALIZER
    };
    kernel[0x300..0x300 + finalizer.len()].copy_from_slice(finalizer);
    for (offset, address) in [(0x349, [0x40, 0x20, 0]), (0x355, [0x40, 0x22, 0])] {
        kernel[offset..offset + 3].copy_from_slice(&address);
    }
    if gated {
        kernel[0x363..0x366].copy_from_slice(&[0x40, 0x30, 0]);
        kernel[0x3000..0x3000 + MARKER_CHECK.len()].copy_from_slice(MARKER_CHECK);
    }
    kernel[pioneer_optical::envelope::KERNEL_MARKER_OFFSET] = marker;
    balance(&mut kernel);
    normal[24..32].copy_from_slice(tag);
    normal[0x400..0x408].copy_from_slice(&[0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36, 0, 0]);
    normal[0x500..0x510].copy_from_slice(&[
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, 4, 0x46, 0x4e,
    ]);
    balance(&mut normal);
    (kernel, normal)
}

/// A signed package of [`ud04_images`] (Kernel tag `GENERAL`, or `ID58`).
fn ud04_pair(gated: bool, marker: u8, id58: bool) -> Update {
    let tag = if id58 { b"ID58    " } else { b"GENERAL " };
    let (kernel, normal) = ud04_images(gated, marker, tag);
    let kind = if id58 { "ud04-id58" } else { "ud04" };
    let encoded = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BD-RW   BDR-UD04",
            normal_revision: "1.20",
            normal_date: "26/10/07",
            kernel: KernelBuild::from_seed(7),
            normal_key_seed: 11,
        },
        NormalSignature::Oem(&pair_signature(kind, gated, marker)),
    )
    .unwrap();
    Update::load(&encoded.kernel, &encoded.normal).unwrap()
}

/// The update flashed onto the UD04: Kernel+Normal, generation marker 0.
fn ud04_target() -> Update {
    ud04_pair(false, 0, false)
}

fn normal_enc(update: &Update) -> Vec<u8> {
    update.normal().repack(&update.normal().image).unwrap()
}

const UD04_KERNEL_BASE: usize = 0x400000;
const UD04_NORMAL_BASE: usize = 0x410000;

/// A UD04 on the bench: it replays its installed firmware for the pre-flash
/// backup (reads unlock after the knock, as [`BackupReplay`]), then takes the
/// OEM update (as the receiver mocks do). Each medium check answers the next
/// scripted tray state; the last one repeats.
struct Ud04Drive {
    memory: Vec<u8>,
    revision: [u8; 4],
    startup_word: u16,
    knocks: usize,
    updating: bool,
    kernel: Vec<u8>,
    normal: Vec<u8>,
    trays: Vec<MediumStatus>,
    tray_checks: usize,
    normal_unreadable: bool,
}

impl Ud04Drive {
    /// Installed: marker 1, with the gated (restoration-pass) receiver or not.
    fn new(gated: bool) -> Self {
        Self::installed(ud04_images(gated, 1, b"GENERAL "))
    }

    fn installed((kernel, normal): (Vec<u8>, Vec<u8>)) -> Self {
        Self {
            memory: [kernel, normal].concat(),
            revision: *b"1.14",
            startup_word: 0xffff,
            knocks: 0,
            updating: false,
            kernel: Vec::new(),
            normal: Vec::new(),
            trays: vec![MediumStatus::ClosedEmpty],
            tray_checks: 0,
            normal_unreadable: false,
        }
    }

    fn with_trays(mut self, trays: &[MediumStatus]) -> Self {
        self.trays = trays.to_vec();
        self
    }
}

impl ScsiDevice for Ud04Drive {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        let sense = |key, asc, what| -> Result<Vec<u8>> {
            Err(crate::platform::ScsiSenseError::new(key, asc, 0, what).into())
        };
        if cdb.first() == Some(&0x12) {
            let mut data = vec![0; len];
            if len >= 36 {
                data[0] = 0x05;
                data[8..16].copy_from_slice(b"PIONEER ");
                data[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
                data[32..36].copy_from_slice(if self.updating {
                    b"000 "
                } else {
                    &self.revision
                });
            }
            return Ok(data);
        }
        if cdb == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
            let mut data = vec![0; 48];
            data[16..24].copy_from_slice(b"SAT 8A10");
            data[24..32].copy_from_slice(&self.memory[0x1008..0x1010]);
            if !self.updating {
                data[32..40].copy_from_slice(&self.memory[0x1008..0x1010]);
            }
            return Ok(data);
        }
        if cdb == pioneer_optical::cdb::read_parameter_word(0x9f).unwrap() {
            assert!(!self.updating, "Normal A0 read in update mode");
            return Ok(self.startup_word.to_be_bytes().to_vec());
        }
        if cdb == [0x3c, 0x06, 0, 0, 0x30, 0, 0, 0, 0x20, 0] {
            bail!("Pioneer does not implement the MTK identity buffer");
        }
        if cdb == pioneer_optical::cdb::test_unit_ready()
            || cdb == pioneer_optical::cdb::get_event_status()
            || cdb == pioneer_optical::cdb::request_sense(18)
        {
            return Ok(vec![0; len]);
        }
        if self.knocks == 0 {
            return sense(5, 0x24, "read access locked");
        }
        if cdb.len() != 10 || cdb[..3] != [0x3c, 2, 0xb0] {
            bail!("unexpected read {}", hex(cdb));
        }
        let start = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
        let end = start + len;
        if start < UD04_KERNEL_BASE || end > UD04_KERNEL_BASE + self.memory.len() {
            return sense(5, 0x24, "outside firmware");
        }
        if self.normal_unreadable && end > UD04_NORMAL_BASE {
            return sense(3, 0x11, "unrecovered read error");
        }
        Ok(self.memory[start - UD04_KERNEL_BASE..end - UD04_KERNEL_BASE].to_vec())
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        if cdb != pioneer_optical::cdb::knock() || !data.is_empty() {
            bail!("unexpected write {}", hex(cdb));
        }
        self.knocks += 1;
        Ok(())
    }

    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        if cdb == pioneer_optical::cdb::write_parameter_word(0x9f).unwrap() {
            assert!(!self.updating, "Normal A0 write in update mode");
            self.startup_word = u16::from_be_bytes(data.try_into().unwrap());
        } else if cdb == pioneer_optical::cdb::enter_update() {
            self.updating = true;
            self.kernel.clear();
            self.normal.clear();
        } else if cdb[..3] == [0x3b, 0x07, 0xfe] {
            self.kernel.extend_from_slice(data);
        } else if cdb[..3] == [0x3b, 0x07, 0xf0] {
            self.normal.extend_from_slice(data);
        } else if cdb == pioneer_optical::cdb::finish() {
            if !self.kernel.is_empty() {
                let image = Envelope::load(&self.kernel)?.image;
                self.memory[..image.len()].copy_from_slice(&image);
            }
            if !self.normal.is_empty() {
                let kernel = if self.kernel.is_empty() {
                    let mut source = ud04_target().kernel().clone();
                    source.image = self.memory[..0x10000].to_vec();
                    source
                } else {
                    Envelope::load(&self.kernel)?
                };
                let image = Envelope::load_with_kernel(&self.normal, &kernel)?.image;
                let header = pioneer_optical::envelope::header_info(&self.normal)
                    .expect("transferred Normal header");
                self.revision.copy_from_slice(header.revision.as_bytes());
                self.memory.truncate(0x10000);
                self.memory.extend_from_slice(&image);
            }
            self.updating = false;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        "UD04 firmware replay; no hardware".into()
    }

    fn medium_status(&mut self) -> Result<MediumStatus> {
        let state = self.trays[self.tray_checks.min(self.trays.len() - 1)];
        self.tray_checks += 1;
        Ok(state)
    }
}

/// A live flash of `input` to the UD04, saving its backup to `backup`.
fn ud04_request(input: Vec<u8>, format: &'static FileFormat, backup: &Path) -> FlashRequest {
    let mut req = pioneer_request(input, format, true);
    req.drive_model = "BD-RW   BDR-UD04".into();
    req.predump_out = Some(backup.to_path_buf());
    req
}

/// Run the real engine flash with consent collected up front (as the GUI
/// does), then record the case and the backup it saved.
fn ud04_case(g: &mut Golden, title: &str, dev: Ud04Drive, req: &FlashRequest) {
    let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, &Pioneer::new(), req));
    g.case(title, &outcome, Some(&transcript));
    if let Some(backup) = &req.predump_out {
        g.file("saved pre-flash backup", backup);
    }
}

#[test]
fn golden_pioneer_execute() {
    let dir = scratch("pioneer-execute");
    let mut g = Golden::default();
    let target = archive(&ud04_target(), false);
    let disc_after_backup = [MediumStatus::ClosedEmpty, MediumStatus::DiscPresent];
    let cases: Vec<(&str, Ud04Drive, Vec<u8>, &'static FileFormat)> = vec![
        (
            "Kernel+Normal update",
            Ud04Drive::new(false),
            target.clone(),
            &PIONEER_PACKAGE,
        ),
        (
            "Kernel+Normal update with kernel restoration pass",
            Ud04Drive::new(true),
            target.clone(),
            &PIONEER_PACKAGE,
        ),
        (
            "Normal-only update",
            Ud04Drive::new(false),
            normal_enc(&ud04_target()),
            &PIONEER_ENVELOPE,
        ),
        (
            "Normal for another Kernel tag, refused after the backup",
            Ud04Drive::new(false),
            normal_enc(&ud04_pair(false, 0, true)),
            &PIONEER_ENVELOPE,
        ),
        (
            "disc inserted after the backup",
            Ud04Drive::new(false).with_trays(&disc_after_backup),
            target.clone(),
            &PIONEER_PACKAGE,
        ),
    ];
    for (i, (title, dev, input, format)) in cases.into_iter().enumerate() {
        let req = ud04_request(input, format, &dir.join(format!("backup_{i}.tar")));
        ud04_case(&mut g, &format!("Pioneer execute: {title}"), dev, &req);
    }
    let cli = cli_spawn("update", scratch("pioneer-cli-non-tty"), None);
    g.cli_case("Pioneer CLI execute: stdin is not a TTY", cli);
    check("pioneer_execute", g);
}

/// The CLI's confirmation on a terminal: the answer is typed into a
/// pseudo-terminal that is the child's stdin.
#[cfg(unix)]
#[test]
fn golden_pioneer_execute_tty() {
    let mut g = Golden::default();
    let runs = [
        ("TTY answers y", "update", "y\n", "tty-yes"),
        ("TTY answers n", "update", "n\n", "tty-no"),
        (
            "disc inserted after the backup, TTY answers y",
            "disc-after-backup",
            "y\n",
            "tty-disc",
        ),
    ]
    .map(|(title, scenario, answer, tag)| (title, cli_spawn(scenario, scratch(tag), Some(answer))));
    for (title, cli) in runs {
        g.cli_case(&format!("Pioneer CLI execute: {title}"), cli);
    }
    check("pioneer_execute_tty", g);
}

// ---- the CLI flash in a child process, with a real stdin ---------------------

const CLI_CHILD: &str = "FREEMKV_GOLDEN_CLI_CHILD";
const CLI_DIR: &str = "FREEMKV_GOLDEN_CLI_DIR";
const CLI_BEGIN: &str = "<<<golden cli begin>>>\n";
const CLI_END: &str = "<<<golden cli end>>>";

/// The UD04 and the input a CLI scenario flashes.
fn cli_scenario(name: &str) -> (Ud04Drive, Vec<u8>) {
    let target = archive(&ud04_target(), false);
    match name {
        "update" => (Ud04Drive::new(false), target),
        "disc-after-backup" => (
            Ud04Drive::new(false)
                .with_trays(&[MediumStatus::ClosedEmpty, MediumStatus::DiscPresent]),
            target,
        ),
        other => panic!("no CLI scenario {other}"),
    }
}

/// Child side of [`cli_spawn`] (a no-op in an ordinary run): the real engine
/// flash with the CLI's terminal confirmation, printing to the process's own
/// stdout and stderr between markers. Result and transcript go to a file.
#[test]
fn golden_cli_child() {
    let (Ok(name), Some(dir)) = (std::env::var(CLI_CHILD), std::env::var_os(CLI_DIR)) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let (dev, input) = cli_scenario(&name);
    let req = ud04_request(input, &PIONEER_PACKAGE, &dir.join("backup.tar"));
    let mut rec = Rec::new(dev);
    let marker = |text: &str| {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        out.write_all(text.as_bytes()).unwrap();
        out.flush().unwrap();
    };
    marker(CLI_BEGIN);
    let result = crate::engine::flash(
        &mut rec,
        &Pioneer::new(),
        &req,
        &mut crate::output::TerminalConfirm,
    );
    marker(CLI_END);
    let mut report = match result {
        Ok(_) => "result: OK\n".to_string(),
        Err(e) => format!("result: ERR {e:#}\n"),
    };
    for line in rec.transcript() {
        report.push_str(&line);
        report.push('\n');
    }
    std::fs::write(dir.join("report.txt"), report).unwrap();
}

/// A CLI scenario running in a child copy of this test binary. Its stdout and
/// stderr share one file, so they stay in order as one stream.
struct CliRun {
    child: std::process::Child,
    dir: PathBuf,
    _tty: Option<std::fs::File>,
}

/// Start CLI scenario `name` in `dir`, with stdin a pseudo-terminal holding
/// `answer`, or not a terminal at all.
fn cli_spawn(name: &str, dir: PathBuf, answer: Option<&str>) -> CliRun {
    let terminal = std::fs::File::create(dir.join("terminal.txt")).unwrap();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "golden_tests::golden_cli_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CLI_CHILD, name)
    .env(CLI_DIR, &dir)
    .stdout(terminal.try_clone().unwrap())
    .stderr(terminal);
    let tty = match answer {
        None => {
            cmd.stdin(std::process::Stdio::null());
            None
        }
        #[cfg(unix)]
        Some(answer) => {
            let (master, slave) = pty_holding(answer);
            cmd.stdin(slave);
            Some(master)
        }
        #[cfg(not(unix))]
        Some(_) => unreachable!("a typed answer needs a pseudo-terminal"),
    };
    let child = cmd.spawn().unwrap();
    CliRun {
        child,
        dir,
        _tty: tty,
    }
}

/// A pseudo-terminal whose input already holds `answer`: (master, slave).
#[cfg(unix)]
fn pty_holding(answer: &str) -> (std::fs::File, std::fs::File) {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty writes two fresh descriptors, owned by the Files below.
    let (mut master, slave) = unsafe {
        assert_eq!(
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            0,
            "openpty: {}",
            std::io::Error::last_os_error()
        );
        for fd in [master, slave] {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    };
    master.write_all(answer.as_bytes()).unwrap();
    (master, slave)
}

impl Golden {
    /// Record a finished CLI scenario: result, the terminal stream, the
    /// device transcript and the backup it saved.
    fn cli_case(&mut self, title: &str, mut run: CliRun) {
        let status = run.child.wait().unwrap();
        let terminal = std::fs::read_to_string(run.dir.join("terminal.txt")).unwrap();
        let report = std::fs::read_to_string(run.dir.join("report.txt")).unwrap_or_default();
        let shown = terminal
            .split_once(CLI_BEGIN)
            .and_then(|(_, rest)| rest.split_once(CLI_END))
            .map(|(shown, _)| shown);
        let (Some(shown), Some((result, transcript)), true) =
            (shown, report.split_once('\n'), status.success())
        else {
            panic!("CLI child {title:?} failed ({status}):\n{terminal}");
        };
        self.section(title);
        let _ = writeln!(self.body, "{result}");
        let lines: Vec<String> = shown.lines().map(str::to_owned).collect();
        self.lines("terminal", &lines);
        let transcript: Vec<String> = transcript.lines().map(str::to_owned).collect();
        self.lines("scsi transcript", &transcript);
        self.file("saved pre-flash backup", &run.dir.join("backup.tar"));
    }
}

// ---------------------------------------------------------------------------
// Pioneer execute failure paths, end to end on the replaying UD04
// ---------------------------------------------------------------------------

#[test]
fn golden_pioneer_flash_bundle_failures() {
    let dir = scratch("pioneer-failures");
    let mut g = Golden::default();
    let target = archive(&ud04_target(), false);
    let mut kernel_only = Ud04Drive::new(true);
    kernel_only.normal_unreadable = true;
    let cases: Vec<(&str, Ud04Drive, Vec<u8>)> = vec![
        (
            "installed backup is Kernel-only",
            kernel_only,
            target.clone(),
        ),
        (
            "target is a header-only bundle",
            Ud04Drive::new(true),
            header_only_bundle(),
        ),
        (
            "target is garbage",
            Ud04Drive::new(true),
            b"garbage".to_vec(),
        ),
        (
            "target is the installed firmware (no change)",
            Ud04Drive::new(true),
            archive(&ud04_pair(true, 1, false), false),
        ),
    ];
    for (i, (title, dev, input)) in cases.into_iter().enumerate() {
        let req = ud04_request(
            input,
            &PIONEER_PACKAGE,
            &dir.join(format!("backup_{i}.tar")),
        );
        ud04_case(&mut g, &format!("Pioneer execute: {title}"), dev, &req);
    }
    let mut req = pioneer_request(target, &PIONEER_PACKAGE, false);
    req.drive_model = "BD-RW   BDR-UD04".into();
    ud04_case(
        &mut g,
        "Pioneer flash: dry-run request",
        Ud04Drive::new(true),
        &req,
    );
    check("pioneer_flash_bundle_failures", g);
}

// ---- Parity with the v0.11.2 baseline (same harness, COMPAT shims only) ----

/// Reasons a MediaTek line may differ from v0.11.2. `tests/golden/v0.11.2/`
/// was recorded at that tag; a line may differ only where
/// `INTENDED_CHANGES.md` lists it.
const ALLOWED_REASONS: &[&str] = &[
    "FILE_VALIDATION",
    "F-OVERRIDE",
    "OPERATION_015",
    "PROTO",
    "CLI_INFO",
    "HUMAN_ERRORS",
    "PRECHECK",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "M-RS",
    "M-FAM",
    "M-CHIP",
    "M-BAK",
    "M-ENC",
    "M-LIFECYCLE",
    "FMT",
];

/// The only reasons a Pioneer line may differ from v0.11.2: P1, a package
/// that cannot be read is refused before the backup; P2, the last tray check
/// runs after the confirmation; P3, a refusal no longer carries
/// [`RECOVER_HINT`]; P4, the synthetic Kernel fixtures gained a 0.15.0 receiver
/// rotation decode-loop and startup/RAM-programmer handoff signatures, so only
/// fixture-derived digests differ (commands and messages unchanged).
const PIONEER_REASONS: &[&str] = &[
    "FILE_VALIDATION",
    "F-OVERRIDE",
    "OPERATION_015",
    "PROTO",
    "CLI_INFO",
    "HUMAN_ERRORS",
    "PRECHECK",
    "P1",
    "P2",
    "P3",
    "P4",
    "P5",
    "P6",
    "P7",
    "P8",
    "P9",
    "P10",
    "P11",
    "RECOVERY_TRAY",
    "FMT",
];

fn recovery_tray_scenario(file: &str, title: &str) -> bool {
    file == "pioneer_recover.txt"
        && matches!(
            title,
            "Pioneer recover execute: receiver in kernel mode"
                | "Pioneer recover execute: receiver in normal mode"
                | "Pioneer recover execute: write fails on the 2nd command"
        )
}

/// The `--recover` hint 954f51d dropped from the not-BD-or-DVR refusal.
/// v0.11.2 could not reach that flash mode either: its CLI and GUI always
/// passed `force: false`.
const RECOVER_HINT: &str = " (a guess is only made under --recover, for a recognised BD family)";

/// Whether `ops` only drop [`RECOVER_HINT`]: each `-` line holds the hint and
/// the matching `+` line is the same line without it. Nothing else may
/// differ, so the device commands are identical.
fn only_recover_hint_dropped(ops: &[String]) -> bool {
    let (old, new): (Vec<&String>, Vec<&String>) = ops.iter().partition(|op| op.starts_with('-'));
    !old.is_empty()
        && old.len() == new.len()
        && old.iter().zip(&new).all(|(o, n)| {
            n.starts_with('+')
                && o.contains(RECOVER_HINT)
                && o[1..].replace(RECOVER_HINT, "") == n[1..]
        })
}

/// Split a golden file into `(scenario title, lines)` sections.
fn sections(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        if let Some(title) = line
            .strip_prefix("=== ")
            .and_then(|t| t.strip_suffix(" ==="))
        {
            out.push((title.to_string(), Vec::new()));
        } else if let Some((_, lines)) = out.last_mut() {
            lines.push(line.to_string());
        }
    }
    out
}

/// Scenarios whose behaviour must be identical to v0.11.2.
fn is_pioneer_scenario(file: &str, title: &str) -> bool {
    let t = title.to_lowercase();
    file.starts_with("pioneer_")
        || ((t.contains("pioneer") || t.contains("renesas")) && !t.starts_with("mtk"))
}

#[derive(Default)]
struct Intended {
    /// (file, scenario) -> (reasons, signed lines)
    entries: std::collections::BTreeMap<(String, String), (Vec<String>, Vec<String>)>,
}

fn parse_intended(text: &str) -> Intended {
    let mut intended = Intended::default();
    let (mut file, mut title) = (String::new(), String::new());
    let mut reasons: Vec<String> = Vec::new();
    let mut in_fence = false;
    let mut lines: Vec<String> = Vec::new();
    for raw in text.lines() {
        if in_fence {
            if raw == "```" {
                in_fence = false;
                intended.entries.insert(
                    (file.clone(), title.clone()),
                    (reasons.clone(), lines.clone()),
                );
            } else {
                lines.push(raw.to_string());
            }
        } else if let Some(f) = raw.strip_prefix("## ") {
            file = f.trim().to_string();
        } else if let Some(t) = raw.strip_prefix("### ") {
            title = t.to_string();
            reasons.clear();
        } else if let Some(r) = raw.strip_prefix("reason: ") {
            reasons = r.split(',').map(|r| r.trim().to_string()).collect();
        } else if raw == "```diff" {
            in_fence = true;
            lines.clear();
        }
    }
    intended
}

/// Golden files of behaviour v0.11.2 does not have, so no baseline exists:
/// the hardware-family gate (INTENDED_CHANGES.md, M-FAM).
const NEW_SINCE_0_11_2: &[&str] = &["mtk_family_gate.txt"];

/// Every difference between the baseline and current goldens, as
/// `(file, scenario) -> signed lines` (`-` = only in v0.11.2, `+` = only now).
fn baseline_differences(root: &Path) -> std::collections::BTreeMap<(String, String), Vec<String>> {
    let mut out = std::collections::BTreeMap::new();
    let mut files: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".txt"))
        .collect();
    files.sort();
    for file in files {
        if NEW_SINCE_0_11_2.contains(&file.as_str()) {
            assert!(
                !root.join("v0.11.2").join(&file).exists(),
                "{file} has a v0.11.2 baseline; compare it"
            );
            continue;
        }
        let cur = std::fs::read_to_string(root.join(&file)).unwrap();
        let base = std::fs::read_to_string(root.join("v0.11.2").join(&file))
            .unwrap_or_else(|_| panic!("no v0.11.2 baseline for {file}"));
        let (cur, base) = (sections(&cur), sections(&base));
        let mut titles: Vec<&String> = cur.iter().chain(&base).map(|(t, _)| t).collect();
        titles.sort();
        titles.dedup();
        for title in titles {
            let find = |set: &'_ [(String, Vec<String>)]| -> Vec<String> {
                set.iter()
                    .find(|(t, _)| t == title)
                    .map(|(_, l)| l.clone())
                    .unwrap_or_default()
            };
            let (b, c) = (find(&base), find(&cur));
            let (br, cr): (Vec<&str>, Vec<&str>) = (
                b.iter().map(String::as_str).collect(),
                c.iter().map(String::as_str).collect(),
            );
            let ops: Vec<String> = diff_ops(&br, &cr)
                .into_iter()
                .map(|(sign, line)| format!("{sign}{line}"))
                .collect();
            if !ops.is_empty() {
                out.insert((file.clone(), title.clone()), ops);
            }
        }
    }
    out
}

#[test]
fn golden_parity_with_0_11_2() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let differences = baseline_differences(&root);
    let intended_path = root.join("INTENDED_CHANGES.md");

    if std::env::var_os("FREEMKV_BLESS_INTENDED").is_some() {
        // Regenerate the skeleton; reasons for new entries must then be set by hand.
        let old = parse_intended(&std::fs::read_to_string(&intended_path).unwrap_or_default());
        let header = std::fs::read_to_string(&intended_path)
            .unwrap_or_default()
            .split("\n## ")
            .next()
            .unwrap_or_default()
            .to_string();
        let mut md = header.trim_end().to_string();
        md.push('\n');
        let mut last_file = String::new();
        for ((file, title), ops) in &differences {
            if *file != last_file {
                let _ = write!(md, "\n## {file}\n");
                last_file = file.clone();
            }
            let reasons = old
                .entries
                .get(&(file.clone(), title.clone()))
                .map(|(r, _)| r.join(", "))
                .unwrap_or_else(|| "UNCLASSIFIED".to_string());
            let _ = write!(md, "\n### {title}\nreason: {reasons}\n```diff\n");
            for op in ops {
                let _ = writeln!(md, "{op}");
            }
            md.push_str("```\n");
        }
        std::fs::write(&intended_path, md).unwrap();
        return;
    }

    let intended = parse_intended(&std::fs::read_to_string(&intended_path).expect(
        "tests/golden/INTENDED_CHANGES.md is missing; every difference from v0.11.2 must be listed there",
    ));
    let mut problems = Vec::new();
    for ((file, title), ops) in &differences {
        let (kind, reasons_allowed) = if is_pioneer_scenario(file, title) {
            ("REGRESSION: Pioneer scenario", PIONEER_REASONS)
        } else {
            ("UNEXPLAINED MediaTek scenario", ALLOWED_REASONS)
        };
        match intended.entries.get(&(file.clone(), title.clone())) {
            None => problems.push(format!(
                "{kind} differs from v0.11.2 (not in INTENDED_CHANGES.md): {file} :: {title}\n  {}",
                ops.iter().take(6).cloned().collect::<Vec<_>>().join("\n  ")
            )),
            Some((reasons, allowed)) => {
                if reasons.is_empty()
                    || reasons
                        .iter()
                        .any(|r| !reasons_allowed.contains(&r.as_str()))
                {
                    problems.push(format!(
                        "{kind} {file} :: {title}: reason must be from {reasons_allowed:?}, got {reasons:?}"
                    ));
                }
                if reasons.iter().any(|r| r == "RECOVERY_TRAY")
                    && !recovery_tray_scenario(file, title)
                {
                    problems.push(format!(
                        "RECOVERY_TRAY is only valid for Pioneer Recovery execution goldens, got {file} :: {title}"
                    ));
                }
                if reasons.iter().any(|r| r == "FILE_VALIDATION") && file != "check_file.txt" {
                    problems.push(format!(
                        "FILE_VALIDATION only applies to check_file.txt, got {file} :: {title}"
                    ));
                }
                if reasons.iter().any(|r| r == "P3")
                    && (reasons.len() != 1 || !only_recover_hint_dropped(ops))
                {
                    problems.push(format!(
                        "{kind} {file} :: {title}: P3 allows only dropping {RECOVER_HINT:?} from a line, nothing else"
                    ));
                }
                for op in ops {
                    if !allowed.contains(op) {
                        problems.push(format!(
                            "{kind}: unexplained line in {file} :: {title}:\n  {op}"
                        ));
                    }
                }
                for line in allowed {
                    if !ops.contains(line) {
                        problems.push(format!(
                            "STALE INTENDED_CHANGES entry (no longer a difference) in {file} :: {title}:\n  {line}"
                        ));
                    }
                }
            }
        }
    }
    for (file, title) in intended.entries.keys() {
        if !differences.contains_key(&(file.clone(), title.clone())) {
            problems.push(format!(
                "STALE INTENDED_CHANGES section (scenario no longer differs): {file} :: {title}"
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

#[cfg(test)]
#[path = "flash_tripwire_tests.rs"]
mod flash_tripwires;

#[cfg(test)]
#[path = "report_tripwire_tests.rs"]
mod report_tripwires;

#[cfg(test)]
#[path = "golden_corpus_tests.rs"]
mod corpus;

#[cfg(test)]
#[path = "catalog_engine_tests.rs"]
mod catalog_engine;
