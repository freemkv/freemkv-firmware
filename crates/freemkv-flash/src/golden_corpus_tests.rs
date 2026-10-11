//! Pioneer corpus differential: the real engine on every Pioneer family.
//!
//! A family is a (hardware, Kernel tag, model) group of an OEM package corpus
//! (`index/packages.json` and the `.installer.tar` packages it lists) with a
//! package holding Kernel and Normal. A [`CorpusDrive`] reports the model's
//! identity and serves the newest such package's decoded images from 0x400000,
//! so the backup derives the Normal layout from a real Kernel; Finish installs
//! the decoded images sent. Each family runs backup, dry run, same-version,
//! downgrade, upgrade and Normal-only flashes, and recovery. Transcripts keep
//! every command; sequential reads and transfers collapse to one digest line.
//!
//! Firmware is not in this repository. With `FREEMKV_PIONEER_CORPUS` set to a
//! corpus root, `golden_pioneer_corpus` runs [`SUBSET`] (pinned by SHA-256)
//! against `tests/golden/pioneer_corpus.txt`; without it, CI checks that file's
//! parity with its v0.11.2 copy. The ignored `pioneer_corpus_full` writes every
//! family to `FREEMKV_PIONEER_CORPUS_OUT` and fails on any difference from a
//! v0.11.2 run in `FREEMKV_PIONEER_CORPUS_BASELINE` not in [`known_class`].
//!
//! ```text
//! FREEMKV_PIONEER_CORPUS=<corpus> cargo test --release -p freemkv-flash \
//!     golden_pioneer_corpus < /dev/null
//! FREEMKV_PIONEER_CORPUS=<corpus> FREEMKV_PIONEER_CORPUS_OUT=<dir> \
//!     FREEMKV_PIONEER_CORPUS_BASELINE=<v0.11.2 dir> cargo test --release \
//!     -p freemkv-flash pioneer_corpus_full -- --ignored < /dev/null
//! ```
//!
//! The v0.11.2 copy of this file differs only in its COMPAT lines.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use pioneer_optical::envelope::{self, Envelope, NormalLayout, Update};
use pioneer_optical::{cdb, ComponentKind};

use super::{
    check, diff_ops, drive_run, engine_flash, normalize, recover_via, scratch, sections, sha,
    Golden, Outcome,
};
use crate::manifest::FlashMode;
use crate::platform::{MediumStatus, ScsiDevice};

// COMPAT: the module paths and request fields differ in the 0.11.2 copy.
use crate::backend::FlashRequest;
use crate::backends::pioneer::{Pioneer, PACKAGE};

/// COMPAT: a flash request for an OEM package, as the CLI builds it.
fn request(input: Vec<u8>, execute: bool, model: &str, backup: Option<PathBuf>) -> FlashRequest {
    FlashRequest {
        input,
        input_format: &PACKAGE,
        mode: FlashMode::Full,
        execute,
        acknowledged_risk: execute,
        enc_override: None,
        drive_model: model.into(),
        verbose: false,
        predump_out: backup,
    }
}

/// COMPAT: the `backup` command once a device is open.
fn backup(dev: &mut dyn ScsiDevice, out: &Path) -> Result<()> {
    crate::engine::backup(dev, &Pioneer::new(), out, false)
}

const CORPUS: &str = "FREEMKV_PIONEER_CORPUS";
const OUT: &str = "FREEMKV_PIONEER_CORPUS_OUT";
const BASELINE: &str = "FREEMKV_PIONEER_CORPUS_BASELINE";

/// The pinned subset, one package set per family: `family<TAB>installed<TAB>
/// older<TAB>Normal-only` SHA-256s, `-` for none.
const SUBSET: &str = "tests/golden/pioneer_corpus_subset.tsv";

/// [`SUBSET`] as (family, installed, older, Normal-only).
fn subset() -> Vec<(String, String, Option<String>, Option<String>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(SUBSET);
    let text = std::fs::read_to_string(path).expect("pinned corpus subset");
    let some = |s: &str| (s != "-").then(|| s.to_string());
    text.lines()
        .map(|line| match line.split('\t').collect::<Vec<_>>()[..] {
            [family, installed, older, normal_only] => (
                family.to_string(),
                installed.to_string(),
                some(older),
                some(normal_only),
            ),
            _ => panic!("bad subset line {line:?}"),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Corpus index
// ---------------------------------------------------------------------------

/// One OEM package from `index/packages.json`.
#[derive(Clone, Debug)]
struct Package {
    path: PathBuf,
    sha256: String,
    hardware: String,
    tag: String,
    model: String,
    revision: String,
    date: String,
    kernel: bool,
    normal: bool,
}

impl Package {
    fn order(&self) -> (String, String, String) {
        (
            self.date.clone(),
            self.revision.clone(),
            self.sha256.clone(),
        )
    }

    fn label(&self) -> String {
        format!(
            "rev {} ({}) sha256={}",
            self.revision, self.date, self.sha256
        )
    }
}

fn index(root: &Path) -> Vec<Package> {
    let text = std::fs::read(root.join("index/packages.json")).expect("corpus index");
    let index: serde_json::Value = serde_json::from_slice(&text).expect("corpus index JSON");
    let field = |p: &serde_json::Value, k: &str| p[k].as_str().unwrap_or_default().to_string();
    index["packages"]
        .as_array()
        .expect("package list")
        .iter()
        .filter(|p| p["family"] == "pioneer")
        .map(|p| Package {
            path: root.join(field(p, "path")),
            sha256: field(p, "sha256"),
            hardware: field(p, "hardware"),
            tag: field(p, "kernel_version"),
            model: field(p, "embedded_model"),
            revision: field(p, "revision"),
            date: field(p, "generated_date"),
            kernel: p["kernel_sha256"].is_string(),
            normal: p["normal_sha256"].is_string(),
        })
        .collect()
}

/// A family's packages: installed (newest Kernel+Normal), the next older
/// Kernel+Normal, and the newest Normal-only package.
#[derive(Clone, Debug)]
struct Unit {
    name: String,
    installed: Package,
    older: Option<Package>,
    normal_only: Option<Package>,
}

/// Group the index into families; families without a Kernel+Normal package
/// are returned separately as `(name, reason)`.
fn units(packages: &[Package]) -> (Vec<Unit>, Vec<(String, String)>) {
    let mut groups: BTreeMap<(String, String, String), Vec<&Package>> = BTreeMap::new();
    for p in packages {
        groups
            .entry((p.hardware.clone(), p.tag.clone(), p.model.clone()))
            .or_default()
            .push(p);
    }
    let (mut units, mut skipped) = (Vec::new(), Vec::new());
    for ((hardware, tag, model), mut group) in groups {
        group.sort_by_key(|p| p.order());
        let name = format!("{hardware}/{tag} {model}");
        let pairs: Vec<&&Package> = group.iter().filter(|p| p.kernel && p.normal).collect();
        let Some(installed) = pairs.last() else {
            skipped.push((name, "no package with both Kernel and Normal".to_string()));
            continue;
        };
        units.push(Unit {
            name,
            installed: (**installed).clone(),
            older: pairs
                .iter()
                .rev()
                .skip(1)
                .find(|p| p.sha256 != installed.sha256)
                .map(|p| (**p).clone()),
            normal_only: group
                .iter()
                .rev()
                .find(|p| p.normal && !p.kernel)
                .map(|p| (*p).clone()),
        });
    }
    (units, skipped)
}

// ---------------------------------------------------------------------------
// Installed firmware and the mock drive
// ---------------------------------------------------------------------------

/// The Kernel and Normal envelopes of an OEM package, by header kind.
fn components(package: &[u8]) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let (mut kernel, mut normal) = (None, None);
    let mut archive = tar::Archive::new(package);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes)?;
        match envelope::header_info(&bytes).and_then(|h| h.kind) {
            Some(ComponentKind::Kernel) => kernel = Some(bytes),
            Some(ComponentKind::Normal) => normal = Some(bytes),
            _ => {}
        }
    }
    Ok((kernel, normal))
}

const KERNEL_BASE: usize = 0x400000;
const KERNEL_LEN: usize = 0x10000;

/// A package's decoded images, as a drive holds them from 0x400000.
struct Installed {
    kernel_envelope: Vec<u8>,
    memory: Vec<u8>,
    id: String,
    revision: String,
    normal_tag: String,
}

/// Decode a Kernel+Normal package into the memory a drive running it holds.
/// `Err` is the reason no faithful mock can be built from it.
fn installed(package: &[u8]) -> std::result::Result<Installed, String> {
    let (Some(kernel), Some(normal)) = components(package).map_err(|e| format!("{e:#}"))? else {
        return Err("package lacks a Kernel or a Normal envelope".into());
    };
    let update = Update::load(&kernel, &normal).map_err(|e| format!("decode: {e:?}"))?;
    let (k, n) = (&update.kernel().image, &update.normal().image);
    if k.len() != KERNEL_LEN || !k[0x1000..0x1008].starts_with(b"SAT ") {
        return Err(format!(
            "decoded Kernel is not a 64 KiB H8/SAT image ({:#x} bytes, hardware {:?})",
            k.len(),
            String::from_utf8_lossy(k.get(0x1000..0x1008).unwrap_or_default())
        ));
    }
    let layout = NormalLayout::from_kernel(k, KERNEL_BASE as u32)
        .map_err(|e| format!("Normal layout from Kernel: {e}"))?;
    let region = layout
        .resolve(n)
        .map_err(|e| format!("Normal header: {e}"))?;
    if region.address() as usize != KERNEL_BASE + KERNEL_LEN || region.length() != n.len() {
        return Err(format!(
            "Normal extent {:#x}+{:#x} differs from the decoded image ({:#x} bytes)",
            region.address(),
            region.length(),
            n.len()
        ));
    }
    layout
        .validate(n)
        .map_err(|e| format!("Normal image: {e}"))?;
    let header = envelope::header_info(&normal).ok_or("Normal header")?;
    // A drive's INQUIRY is the identity its images embed; the header ID is
    // used only when the images hold it.
    let (vendor, product) = header.id.split_at(8.min(header.id.len()));
    match pioneer_optical::ident::embedded_envelope_id(vendor, product, &[k, n]) {
        Ok(id) if id == header.id => {}
        found => {
            return Err(format!(
                "the images do not embed the envelope ID {:?} ({found:?}), so the drive's INQUIRY is unknown",
                header.id
            ))
        }
    }
    Ok(Installed {
        kernel_envelope: kernel,
        memory: [k.as_slice(), n.as_slice()].concat(),
        id: header.id,
        revision: header.revision,
        normal_tag: header.kernel_version,
    })
}

/// `text` left-aligned in `N` bytes, space padded.
fn padded<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [b' '; N];
    for (o, b) in out.iter_mut().zip(text.bytes()) {
        *o = b;
    }
    out
}

/// A Pioneer drive running a corpus package. INQUIRY carries the envelope ID
/// (vendor, product) and the Normal revision; the vendor identity carries the
/// Kernel's hardware, Kernel tag and code and the Normal's tag. Firmware reads
/// unlock after a knock; an update installs what Finish completes.
struct CorpusDrive {
    vendor: [u8; 8],
    product: [u8; 16],
    revision: [u8; 4],
    normal_tag: [u8; 8],
    memory: Vec<u8>,
    kernel_envelope: Vec<u8>,
    knocks: usize,
    updating: bool,
    sent: [Vec<u8>; 2],
}

impl CorpusDrive {
    fn new(fw: &Installed) -> Self {
        let id = fw.id.as_bytes();
        let text = |range: std::ops::Range<usize>| {
            String::from_utf8_lossy(id.get(range).unwrap_or_default()).to_string()
        };
        Self {
            vendor: padded(&text(0..8.min(id.len()))),
            product: padded(&text(8.min(id.len())..24.min(id.len()))),
            revision: padded(&fw.revision),
            normal_tag: padded(&fw.normal_tag),
            memory: fw.memory.clone(),
            kernel_envelope: fw.kernel_envelope.clone(),
            knocks: 0,
            updating: false,
            sent: [Vec::new(), Vec::new()],
        }
    }

    /// The same drive, already in an update session (as after a failed flash).
    fn in_update(mut self) -> Self {
        self.updating = true;
        self
    }

    fn product(&self) -> String {
        String::from_utf8_lossy(&self.product).trim().to_string()
    }

    fn inquiry(&self, len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        if len >= 36 {
            data[0] = 5;
            data[4] = (len - 5).min(255) as u8;
            data[8..16].copy_from_slice(&self.vendor);
            data[16..32].copy_from_slice(&self.product);
            data[32..36].copy_from_slice(if self.updating {
                b"0000"
            } else {
                &self.revision
            });
        }
        data
    }

    fn identity(&self, len: usize) -> Vec<u8> {
        let mut data = vec![0; len.max(48)];
        data[..16].copy_from_slice(b"CORPUSMOCK000001");
        data[16..32].copy_from_slice(&self.memory[0x1000..0x1010]);
        if !self.updating {
            data[32..40].copy_from_slice(&self.normal_tag);
        }
        data[40..44].copy_from_slice(&self.memory[0x1010..0x1014]);
        data.truncate(len);
        data
    }

    /// Finish: install the decoded Kernel and Normal that were sent.
    fn install(&mut self) -> Result<()> {
        let [kernel, normal] = std::mem::take(&mut self.sent);
        if !kernel.is_empty() {
            let decoded = Envelope::load(&kernel).context("drive cannot decode the Kernel sent")?;
            if decoded.image.len() != KERNEL_LEN {
                bail!("Kernel sent is {:#x} bytes", decoded.image.len());
            }
            self.memory[..KERNEL_LEN].copy_from_slice(&decoded.image);
            self.kernel_envelope = kernel;
        }
        if !normal.is_empty() {
            let running = Envelope::load(&self.kernel_envelope)?;
            let decoded = Envelope::load_with_kernel(&normal, &running)
                .context("drive cannot decode the Normal sent")?;
            let header = envelope::header_info(&normal).context("Normal sent has no header")?;
            self.memory.truncate(KERNEL_LEN);
            self.memory.extend_from_slice(&decoded.image);
            self.revision = padded(&header.revision);
            self.normal_tag = padded(&header.kernel_version);
        }
        Ok(())
    }
}

impl ScsiDevice for CorpusDrive {
    fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
        let sense = |key, asc, what| -> Result<Vec<u8>> {
            Err(crate::platform::ScsiSenseError::new(key, asc, 0, what).into())
        };
        if command.first() == Some(&0x12) {
            return Ok(self.inquiry(len));
        }
        if command == cdb::vendor_identity() {
            return Ok(self.identity(len));
        }
        if command == [0x3c, 0x06, 0, 0, 0x30, 0, 0, 0, 0x20, 0] {
            bail!("Pioneer does not implement the MTK identity buffer");
        }
        if command == cdb::test_unit_ready() || command == cdb::get_event_status() {
            return Ok(vec![0; len]);
        }
        if self.knocks == 0 {
            return sense(5, 0x24, "read access locked");
        }
        if command.len() != 10 || command[..3] != [0x3c, 2, 0xb0] {
            bail!("unexpected read {}", super::hex(command));
        }
        let start = u32::from_be_bytes([0, command[3], command[4], command[5]]) as usize;
        let end = start + len;
        if start < KERNEL_BASE || end > KERNEL_BASE + self.memory.len() {
            return sense(5, 0x24, "outside firmware");
        }
        Ok(self.memory[start - KERNEL_BASE..end - KERNEL_BASE].to_vec())
    }

    fn command_out(&mut self, command: &[u8], data: &[u8]) -> Result<()> {
        if command != cdb::knock() || !data.is_empty() {
            bail!("unexpected write {}", super::hex(command));
        }
        self.knocks += 1;
        Ok(())
    }

    fn command_out_strict(&mut self, command: &[u8], data: &[u8]) -> Result<()> {
        if command == cdb::enter_update() {
            self.updating = true;
            self.sent = [Vec::new(), Vec::new()];
        } else if command.len() == 10 && command[..2] == [0x3b, 0x07] {
            let slot = match command[2] {
                0xfe => 0,
                0xf0 => 1,
                _ => bail!("unexpected transfer {}", super::hex(command)),
            };
            let offset = u32::from_be_bytes([0, command[3], command[4], command[5]]) as usize;
            if !self.updating || offset != self.sent[slot].len() {
                bail!("transfer out of sequence {}", super::hex(command));
            }
            self.sent[slot].extend_from_slice(data);
        } else if command == cdb::finish() {
            if !self.updating {
                bail!("finish outside an update session");
            }
            self.install()?;
            self.updating = false;
        } else {
            bail!("unexpected write {}", super::hex(command));
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("{} corpus replay; no hardware", self.product())
    }

    fn medium_status(&mut self) -> Result<MediumStatus> {
        Ok(MediumStatus::ClosedEmpty)
    }
}

// ---------------------------------------------------------------------------
// Compact recording
// ---------------------------------------------------------------------------

/// The 24-bit address and length fields of a vendor read or transfer CDB.
fn span(line: &str, prefix: &str) -> Option<(String, usize, usize, String)> {
    let rest = line.strip_prefix(prefix)?;
    let (cdb, tail) = rest.split_once(' ')?;
    if cdb.len() != 20 {
        return None;
    }
    let field = |r: std::ops::Range<usize>| usize::from_str_radix(&cdb[r], 16).ok();
    Some((
        cdb[..6].to_string(),
        field(6..12)?,
        field(12..18)?,
        tail.to_string(),
    ))
}

const KNOCK: &str = "OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok";

/// Collapse each run of two or more knocked sequential reads, and of two or
/// more sequential transfers, into one line. Chunks are equal except the last;
/// a transfer run keeps the SHA-256 of its chunk digests.
fn compact_transcript(lines: &[String]) -> Vec<String> {
    let read = |i: usize| -> Option<(usize, usize)> {
        if lines.get(i).map(String::as_str) != Some(KNOCK) {
            return None;
        }
        let (op, addr, len, tail) = span(lines.get(i + 1)?, "IN   cdb=")?;
        (op == "3c02b0" && tail == format!("alloc={len} -> ok {len}")).then_some((addr, len))
    };
    let write = |i: usize| -> Option<(String, usize, usize, String)> {
        let (op, addr, len, tail) = span(lines.get(i)?, "OUTS cdb=")?;
        let digest = tail
            .strip_prefix(&format!("len={len} sha256="))?
            .strip_suffix(" -> ok")?;
        op.starts_with("3b07")
            .then(|| (op, addr, len, digest.to_string()))
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some((start, chunk)) = read(i) {
            let (mut j, mut end, mut n, mut last) = (i + 2, start + chunk, 1, chunk);
            while let Some((a, l)) = read(j) {
                if a != end || last != chunk || l > chunk {
                    break;
                }
                (j, end, n, last) = (j + 2, end + l, n + 1, l);
            }
            if n > 1 {
                out.push(format!(
                    "READS {start:#x}..{end:#x}: {n} x (knock, read <= {chunk:#x}) -> ok"
                ));
                i = j;
                continue;
            }
        }
        if let Some((op, start, chunk, digest)) = write(i) {
            let (mut j, mut end, mut last) = (i + 1, start + chunk, chunk);
            let mut digests = vec![digest];
            while let Some((o, a, l, d)) = write(j) {
                if o != op || a != end || last != chunk || l > chunk {
                    break;
                }
                (j, end, last) = (j + 1, end + l, l);
                digests.push(d);
            }
            if digests.len() > 1 {
                out.push(format!(
                    "WRITES {op} {start:#x}..{end:#x}: {} transfers <= {chunk:#x}, chunk digests sha256={} -> ok",
                    digests.len(),
                    sha(digests.join("\n").as_bytes())
                ));
                i = j;
                continue;
            }
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

/// Collapse each run of progress updates for one label into one line.
fn compact_progress(
    lines: &[String],
    parse: impl Fn(&str) -> Option<(String, String)>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut run: Option<(String, String, String, usize)> = None;
    let flush = |run: &mut Option<(String, String, String, usize)>, out: &mut Vec<String>| {
        if let Some((label, first, last, n)) = run.take() {
            out.push(if n == 1 {
                format!("{label}{first}")
            } else {
                format!("{label}{first} .. {last} ({n} updates)")
            });
        }
    };
    for line in lines {
        match parse(line) {
            Some((label, value)) => match &mut run {
                Some((l, _, last, n)) if *l == label => {
                    *last = value;
                    *n += 1;
                }
                _ => {
                    flush(&mut run, &mut out);
                    run = Some((label, value.clone(), value, 1));
                }
            },
            None => {
                flush(&mut run, &mut out);
                out.push(line.clone());
            }
        }
    }
    flush(&mut run, &mut out);
    out
}

fn compact_outcome(mut outcome: Outcome) -> Outcome {
    outcome.text = compact_progress(&outcome.text, |line| {
        let (label, pct) = line.rsplit_once(": ")?;
        (pct.ends_with('%') && pct[..pct.len() - 1].bytes().all(|b| b.is_ascii_digit()))
            .then(|| (format!("{label}: "), pct.to_string()))
    });
    outcome.events = compact_progress(&outcome.events, |line| {
        let rest = line.strip_prefix("PROGRESS ")?;
        let (label, count) = rest.rsplit_once(' ')?;
        count
            .contains('/')
            .then(|| (format!("PROGRESS {label} "), count.to_string()))
    });
    outcome
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Read a package, check its digest and note it under `role`.
fn load(g: &mut Golden, role: &str, package: &Package) -> Vec<u8> {
    let bytes =
        std::fs::read(&package.path).unwrap_or_else(|e| panic!("{}: {e}", package.path.display()));
    assert_eq!(sha(&bytes), package.sha256, "{}", package.path.display());
    g.kv(role, &package.label());
    bytes
}

/// Run one scenario on `dev` and record it compactly.
fn case(
    g: &mut Golden,
    title: &str,
    dev: CorpusDrive,
    op: impl FnOnce(&mut dyn ScsiDevice) -> Result<()>,
) {
    let (outcome, transcript) = drive_run(dev, |d| op(d));
    g.case(
        title,
        &compact_outcome(outcome),
        Some(&compact_transcript(&transcript)),
    );
}

/// Every scenario for one family, appended to `g`. Returns `Err(reason)` when
/// the installed package cannot be served faithfully.
fn family(g: &mut Golden, unit: &Unit, dir: &Path) -> std::result::Result<(), String> {
    let name = &unit.name;
    let mut pinned = Golden::default();
    let installed_bytes = load(&mut pinned, "installed", &unit.installed);
    let fw = installed(&installed_bytes)?;
    let older = unit.older.as_ref().map(|p| load(&mut pinned, "older", p));
    let older_fw = older.as_deref().map(installed);
    let normal_only = unit
        .normal_only
        .as_ref()
        .map(|p| load(&mut pinned, "Normal-only", p));
    g.section(&format!("{name} :: packages"));
    g.body.push_str(&pinned.body);
    let drive = || CorpusDrive::new(&fw);
    let model = drive().product();

    let out = dir.join("backup.tar");
    case(g, &format!("{name} :: backup"), drive(), |d| {
        backup(d, &out)
    });
    g.file("saved backup", &out);

    let dry = request(installed_bytes.clone(), false, &model, None);
    case(g, &format!("{name} :: flash dry run"), drive(), |d| {
        engine_flash(d, &Pioneer::new(), &dry)
    });

    let mut flashes: Vec<(&str, CorpusDrive, &[u8])> =
        vec![("flash same version", drive(), &installed_bytes)];
    if let Some(bytes) = &older {
        flashes.push(("flash downgrade to older", drive(), bytes));
        match &older_fw {
            Some(Ok(older_fw)) => flashes.push((
                "flash upgrade from older",
                CorpusDrive::new(older_fw),
                &installed_bytes,
            )),
            Some(Err(reason)) => g.kv("upgrade from older not run", reason),
            None => {}
        }
    }
    if let Some(bytes) = &normal_only {
        flashes.push(("flash Normal-only package", drive(), bytes));
    }
    for (i, (title, dev, input)) in flashes.into_iter().enumerate() {
        let backup = dir.join(format!("preflash_{i}.tar"));
        let req = request(input.to_vec(), true, &model, Some(backup.clone()));
        case(g, &format!("{name} :: {title}"), dev, |d| {
            engine_flash(d, &Pioneer::new(), &req)
        });
        g.file("saved pre-flash backup", &backup);
    }

    let target = installed_bytes.as_slice();
    case(
        g,
        &format!("{name} :: recover dry run, Current file"),
        drive(),
        |d| recover_via(d, Some(target), target, false),
    );
    case(
        g,
        &format!("{name} :: recover dry run, Current read from the drive"),
        drive(),
        |d| recover_via(d, None, target, false),
    );
    case(
        g,
        &format!("{name} :: recover execute from update mode, Current file"),
        drive().in_update(),
        |d| recover_via(d, Some(target), target, true),
    );
    Ok(())
}

/// The record of one family, or of why it is not covered.
fn family_record(unit: &Unit) -> String {
    let dir = scratch("corpus");
    let mut g = Golden::default();
    let outcome = family(&mut g, unit, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(reason) = outcome {
        g = Golden::default();
        g.section(&format!("{} :: not covered", unit.name));
        g.kv("installed", &unit.installed.label());
        g.kv("reason", &reason);
    }
    normalize(&g.body)
}

/// [`family_record`] of every unit, in order, run on all cores.
fn records(units: &[Unit]) -> Vec<String> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::Mutex::new(vec![String::new(); units.len()]);
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(unit) = units.get(i) else { break };
                let record = family_record(unit);
                done.lock().unwrap()[i] = record;
            });
        }
    });
    done.into_inner().unwrap()
}

fn corpus_root() -> Option<PathBuf> {
    std::env::var_os(CORPUS).map(PathBuf::from)
}

/// The pinned subset, against `tests/golden/pioneer_corpus.txt`.
#[test]
fn golden_pioneer_corpus() {
    let Some(root) = corpus_root() else {
        eprintln!("{CORPUS} not set; the pinned corpus subset was not run");
        return;
    };
    let packages = index(&root);
    let by_sha = |sha256: &str| {
        packages
            .iter()
            .find(|p| p.sha256 == sha256)
            .unwrap_or_else(|| panic!("corpus has no package {sha256}"))
            .clone()
    };
    let units: Vec<Unit> = subset()
        .into_iter()
        .map(|(name, installed, older, normal_only)| Unit {
            name,
            installed: by_sha(&installed),
            older: older.as_deref().map(by_sha),
            normal_only: normal_only.as_deref().map(by_sha),
        })
        .collect();
    let mut g = Golden::default();
    for record in records(&units) {
        g.body.push_str(&record);
    }
    check("pioneer_corpus", g);
}

/// Without the corpus: every pinned family, and only those, is recorded in
/// `pioneer_corpus.txt` with the pinned packages.
#[test]
fn pioneer_corpus_golden_matches_the_subset() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/pioneer_corpus.txt");
    let golden = std::fs::read_to_string(golden)
        .unwrap()
        .replace("\r\n", "\n");
    let mut recorded: Vec<(String, Vec<String>)> = sections(&golden)
        .into_iter()
        .filter_map(|(title, lines)| Some((title.strip_suffix(" :: packages")?.to_string(), lines)))
        .collect();
    recorded.sort();
    let mut pinned = subset();
    pinned.sort();
    assert_eq!(recorded.len(), pinned.len(), "families recorded vs pinned");
    for ((title, lines), (family, installed, older, normal_only)) in recorded.iter().zip(&pinned) {
        assert_eq!(title, family);
        let digests: Vec<Option<&str>> = ["installed: ", "older: ", "Normal-only: "]
            .iter()
            .map(|role| {
                lines
                    .iter()
                    .find_map(|l| l.strip_prefix(role)?.rsplit_once("sha256=").map(|(_, d)| d))
            })
            .collect();
        assert_eq!(
            digests,
            [
                Some(installed.as_str()),
                older.as_deref(),
                normal_only.as_deref()
            ],
            "{family}"
        );
    }
}

/// File name for a family's record.
fn file_name(unit: &str) -> String {
    let safe: String = unit
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.txt")
}

/// The known class of a scenario's difference from v0.11.2, if any (see
/// `INTENDED_CHANGES.md`): P2 when the only change drops one tray check; P3
/// when only the `--recover` hint 954f51d removed is gone from a refusal.
fn known_class(ops: &[String]) -> Option<&'static str> {
    let body: Vec<&String> = ops
        .iter()
        .filter(|op| !op[1..].starts_with("--- scsi transcript ("))
        .collect();
    if body.len() == 1 && body[0] == "-MEDIUM -> ClosedEmpty" {
        return Some("P2");
    }
    super::only_recover_hint_dropped(ops).then_some("P3")
}

/// Every family in the corpus, one file each; compared with a v0.11.2 run.
#[test]
#[ignore = "set FREEMKV_PIONEER_CORPUS and FREEMKV_PIONEER_CORPUS_OUT"]
fn pioneer_corpus_full() {
    let root = corpus_root().expect("FREEMKV_PIONEER_CORPUS");
    let out = PathBuf::from(std::env::var_os(OUT).expect("FREEMKV_PIONEER_CORPUS_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let packages = index(&root);
    let (units, skipped) = units(&packages);
    for (unit, record) in units.iter().zip(records(&units)) {
        std::fs::write(out.join(file_name(&unit.name)), record).unwrap();
    }
    let mut summary = String::new();
    for (name, reason) in &skipped {
        let _ = writeln!(summary, "{name}: not covered: {reason}");
    }
    std::fs::write(out.join("_families_without_kernel_and_normal.txt"), summary).unwrap();

    let Some(base) = std::env::var_os(BASELINE).map(PathBuf::from) else {
        return;
    };
    let mut report = String::new();
    let mut regressions = 0;
    for unit in &units {
        let file = file_name(&unit.name);
        let now = std::fs::read_to_string(out.join(&file)).unwrap();
        let then = std::fs::read_to_string(base.join(&file))
            .unwrap_or_else(|_| panic!("no baseline {file}"));
        let (now, then) = (sections(&now), sections(&then));
        let mut titles: Vec<&String> = now.iter().chain(&then).map(|(t, _)| t).collect();
        titles.sort();
        titles.dedup();
        for title in titles {
            let find = |set: &[(String, Vec<String>)]| -> Vec<String> {
                set.iter()
                    .find(|(t, _)| t == title)
                    .map(|(_, l)| l.clone())
                    .unwrap_or_default()
            };
            let (b, c) = (find(&then), find(&now));
            let b: Vec<&str> = b.iter().map(String::as_str).collect();
            let c: Vec<&str> = c.iter().map(String::as_str).collect();
            let ops: Vec<String> = diff_ops(&b, &c)
                .into_iter()
                .map(|(sign, line)| format!("{sign}{line}"))
                .collect();
            if ops.is_empty() {
                continue;
            }
            let class = known_class(&ops).unwrap_or_else(|| {
                regressions += 1;
                "UNEXPLAINED"
            });
            let _ = writeln!(report, "\n### {title}\nclass: {class}\n```diff");
            for op in &ops {
                let _ = writeln!(report, "{op}");
            }
            report.push_str("```\n");
        }
    }
    std::fs::write(out.join("_differences.md"), &report).unwrap();
    assert_eq!(
        regressions, 0,
        "differences from v0.11.2 of no known class:\n{report}"
    );
}
