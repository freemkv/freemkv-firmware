//! Corpus-wide proof that `freemkv-fw create` + `freemkv-fw verify` succeed on
//! every FORGEABLE firmware image we hold.
//!
//! This is deliberately NOT a unit test wired into the crate's internals
//! (`family`, `modify`, `scheme` are private to the `freemkv-fw` binary). It
//! drives the real, compiled `freemkv-fw` binary exactly the way an operator
//! would, and it classifies "is this image forgeable" with its OWN
//! independent, from-scratch reading of the raw bytes — NOT by asking
//! `freemkv-fw` whether it likes the image. That independence is the point:
//! if `freemkv-fw` regresses and starts wrongly refusing a genuinely
//! forgeable image, this harness must fail loudly instead of quietly folding
//! that refusal into "expected skip".
//!
//! Classification signals (independent of `crate::family`/`crate::modify`):
//! * a `MTEKMT1959` or `MTEKMT1939` ASCII tag in the drive descriptor at file
//!   offset `0x1EC000` (mirrors what the boot banner + descriptor encode, see
//!   `src/family.rs`'s doc comment) — BOTH families are modifiable, so either
//!   tag makes an image a forgeability candidate;
//! * Shannon entropy of the `0x1000..0x20000` window under ~6.7 bits/byte —
//!   above that, the image is almost certainly encrypted/wrapped (post-2020
//!   firmware) and no plaintext CMAC table can be forged;
//! * a valid MediaTek CMAC integrity table (`freemkv_flash::cmac::parse_table`)
//!   at `0x10400` with at least one active, in-bounds entry.
//!
//! Only images passing ALL THREE are FORGEABLE; every forgeable image must
//! both `create` and `verify` cleanly, or the run is a hard failure.
//!
//! Gated behind `FREEMKV_FW_CORPUS` (comma-separated directories to scan
//! recursively for `*.bin`) so it is skipped by a normal `cargo test` and only
//! runs in CI / when explicitly pointed at a local corpus:
//!
//! ```text
//! FREEMKV_FW_CORPUS=/path/to/hoard/organized,/path/to/hoard/incoming cargo test -p freemkv-fw --test corpus_create_verify -- --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use freemkv_flash::cmac;
use freemkv_fw::engine;

/// File offset of the ASCII drive descriptor (mirrors `family::DESCRIPTOR_OFFSET`).
const DESCRIPTOR_OFFSET: usize = 0x1EC000;
/// Offset within the descriptor of the family tag (mirrors `family.rs`).
const FAMILY_TAG_OFFSET: usize = 0x34;
const FAMILY_TAG_LEN: usize = 0x0A;

/// Entropy probe window (mirrors the task brief's independent signal, not
/// `modify::ENTROPY_PROBES` — deliberately a different probe so this harness
/// cannot share a blind spot with the code it is grading).
const ENTROPY_START: usize = 0x1000;
const ENTROPY_END: usize = 0x2_0000;
/// Ceiling in bits/byte; plaintext Thumb code sits comfortably under this,
/// AES/encrypted payloads sit close to 8.0.
const ENTROPY_MAX: f64 = 6.7;

const MT1959_TAG: &str = "MTEKMT1959";
const MT1939_TAG: &str = "MTEKMT1939";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Classification {
    Forgeable,
    Skip(String),
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Classify `image` as FORGEABLE or SKIP(reason), using signals independent
/// of `freemkv-fw`'s own internal detection.
fn classify(image: &[u8]) -> Classification {
    if image.len() < DESCRIPTOR_OFFSET + FAMILY_TAG_OFFSET + FAMILY_TAG_LEN {
        return Classification::Skip(format!(
            "too small ({} bytes) to hold the drive descriptor",
            image.len()
        ));
    }

    let tag_bytes = &image[DESCRIPTOR_OFFSET + FAMILY_TAG_OFFSET
        ..DESCRIPTOR_OFFSET + FAMILY_TAG_OFFSET + FAMILY_TAG_LEN];
    let tag = String::from_utf8_lossy(tag_bytes);

    // Both MT1959 and MT1939 are now modifiable families (MT1939 support landed
    // after this harness was first written). A recognized MTEKMT19xx tag is a
    // forgeability *candidate*; the entropy + CMAC gates below, and ultimately
    // `create`+`verify` itself, are the arbiters of whether modify actually works.
    // Anything else has no recognized family and is skipped.
    if !tag.contains(MT1959_TAG) && !tag.contains(MT1939_TAG) {
        return Classification::Skip(format!(
            "no recognized MTEKMT19xx family tag at 0x{:x} (got {:?})",
            DESCRIPTOR_OFFSET + FAMILY_TAG_OFFSET,
            tag.trim_matches(|c: char| c == '\0' || c.is_whitespace())
        ));
    }

    let end = ENTROPY_END.min(image.len());
    if ENTROPY_START < end {
        let h = shannon_entropy(&image[ENTROPY_START..end]);
        if h > ENTROPY_MAX {
            return Classification::Skip(format!(
                "high entropy ({h:.2} bits/byte over 0x{ENTROPY_START:x}-0x{end:x}) — \
                 looks encrypted/wrapped"
            ));
        }
    }

    match cmac::parse_table(image) {
        Ok(entries) => {
            let has_active = entries
                .iter()
                .any(|e| e.is_active() && e.start <= e.end && (e.end as usize) < image.len());
            if !has_active {
                return Classification::Skip(
                    "MTEKMT1959 tag present but no active in-bounds CMAC entry".into(),
                );
            }
        }
        Err(e) => {
            return Classification::Skip(format!("CMAC table did not parse: {e}"));
        }
    }

    Classification::Forgeable
}

/// Recursively collect every `*.bin` (case-insensitive) under `dir`.
fn collect_bins(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!("warning: cannot read corpus dir {}", dir.display());
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_bins(&path, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("bin"))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
}

struct Outcome {
    path: PathBuf,
    detail: String,
}

#[test]
fn corpus_create_verify_100_percent_of_forgeable_images() {
    let Ok(corpus_var) = std::env::var("FREEMKV_FW_CORPUS") else {
        eprintln!(
            "skipping corpus_create_verify_100_percent_of_forgeable_images: \
             set FREEMKV_FW_CORPUS (comma-separated dirs) to run it"
        );
        return;
    };

    let dirs: Vec<PathBuf> = corpus_var.split(',').map(PathBuf::from).collect();
    let mut bins = Vec::new();
    for dir in &dirs {
        if !dir.is_dir() {
            eprintln!(
                "warning: corpus dir does not exist or is not a dir: {}",
                dir.display()
            );
            continue;
        }
        collect_bins(dir, &mut bins);
    }
    bins.sort();
    bins.dedup();

    assert!(
        !bins.is_empty(),
        "FREEMKV_FW_CORPUS={corpus_var:?} resolved to zero .bin files — check the path(s)"
    );

    let fw_bin = PathBuf::from(env!("CARGO_BIN_EXE_freemkv-fw"));

    let mut skipped_other: Vec<(PathBuf, String)> = Vec::new();
    let mut passed: Vec<Outcome> = Vec::new();
    let mut failed: Vec<Outcome> = Vec::new();

    let tmp_root = std::env::temp_dir().join(format!(
        "freemkv-fw-corpus-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp_root).expect("create tmp root");

    for (i, path) in bins.iter().enumerate() {
        let image = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                skipped_other.push((path.clone(), format!("unreadable: {e}")));
                continue;
            }
        };

        match classify(&image) {
            Classification::Skip(reason) => {
                skipped_other.push((path.clone(), reason));
                continue;
            }
            Classification::Forgeable => {}
        }

        let out_path = tmp_root.join(format!("out-{i}.bin"));

        let create = Command::new(&fw_bin)
            .arg("create")
            .arg(path)
            .arg(&out_path)
            .output()
            .expect("spawn freemkv-fw create");

        if !create.status.success() {
            failed.push(Outcome {
                path: path.clone(),
                detail: format!(
                    "create failed (status {:?}):\nstdout: {}\nstderr: {}",
                    create.status.code(),
                    String::from_utf8_lossy(&create.stdout),
                    String::from_utf8_lossy(&create.stderr),
                ),
            });
            continue;
        }

        let verify = Command::new(&fw_bin)
            .arg("verify")
            .arg(&out_path)
            .output()
            .expect("spawn freemkv-fw verify");

        if !verify.status.success() {
            failed.push(Outcome {
                path: path.clone(),
                detail: format!(
                    "create OK but verify failed (status {:?}):\nstdout: {}\nstderr: {}",
                    verify.status.code(),
                    String::from_utf8_lossy(&verify.stdout),
                    String::from_utf8_lossy(&verify.stderr),
                ),
            });
            continue;
        }

        passed.push(Outcome {
            path: path.clone(),
            detail: "create+verify OK".into(),
        });

        // Keep the tmp dir small: each output is only needed to be verified once.
        let _ = std::fs::remove_file(&out_path);
    }

    let _ = std::fs::remove_dir_all(&tmp_root);

    // Publish gate: when `FREEMKV_FW_PUBLISH_OUT` names a file, emit the list of
    // images that modify PROVABLY handles (create+verify OK) — one absolute path
    // per line. This is the authoritative publish set: the
    // "hoard -> modify works? -> R2 -> website" pipeline consumes exactly these,
    // so a base is published if and only if `freemkv-fw` can forge it here.
    if let Ok(out) = std::env::var("FREEMKV_FW_PUBLISH_OUT") {
        let mut paths: Vec<String> = passed
            .iter()
            .map(|o| o.path.to_string_lossy().into_owned())
            .collect();
        paths.sort();
        let body = if paths.is_empty() {
            String::new()
        } else {
            format!("{}\n", paths.join("\n"))
        };
        std::fs::write(&out, body).expect("write publish set");
        println!("publish set: {} image(s) -> {out}", passed.len());
    }

    let total = bins.len();
    let forgeable = passed.len() + failed.len();

    println!("=== freemkv-fw corpus matrix ===");
    println!("total images scanned:      {total}");
    println!("forgeable (create+verify): {forgeable}");
    println!("  passed:                  {}", passed.len());
    println!("  FAILED:                  {}", failed.len());
    println!("skipped (unmodifiable):    {}", skipped_other.len());

    if !failed.is_empty() {
        println!("\n--- FAILURES ---");
        for f in &failed {
            println!("[FAIL] {}\n{}\n", f.path.display(), f.detail);
        }
    }

    if std::env::var("FREEMKV_FW_CORPUS_VERBOSE").is_ok() {
        println!("\n--- skipped (unmodifiable) ---");
        for (p, reason) in &skipped_other {
            println!("  {}: {reason}", p.display());
        }
        println!("\n--- passed ---");
        for p in &passed {
            println!("  {}", p.path.display());
        }
    }

    assert!(
        failed.is_empty(),
        "{} of {} forgeable image(s) failed create+verify — see failures above",
        failed.len(),
        forgeable
    );
}

/// Fleet-wide `create == modify` invariant: the strict all-or-nothing `create`
/// path and the never-abort `modify` path must produce BYTE-IDENTICAL images on
/// every corpus image where `create` succeeds. Extends the single-BU40N guard
/// (`create_and_modify_agree_on_base`) to the whole hoard, and catches any
/// capability-gate drift that would let `modify` skip levers `create` insists on.
///
/// Gated behind the same env var (`FREEMKV_FW_CORPUS`) as the outer create+verify
/// matrix so a laptop-side `cargo test` skips it cleanly; CI points it at the
/// full 118-image hoard. When `FREEMKV_FW_CORPUS` is unset, we also honour
/// `FREEMKV_KAT_HOARD` (a colon-separated list of directories) — the same env
/// var the engine-side finder tests use — so either wiring gets coverage.
#[test]
fn corpus_create_and_modify_agree_byte_for_byte() {
    let corpus = std::env::var("FREEMKV_FW_CORPUS").ok().or_else(|| {
        // `FREEMKV_KAT_HOARD` is colon-separated; the classify+collect logic here
        // expects comma-separated. Normalize the separator so either shape works.
        std::env::var("FREEMKV_KAT_HOARD")
            .ok()
            .map(|s| s.replace(':', ","))
    });
    let Some(corpus) = corpus else {
        eprintln!(
            "skipping corpus_create_and_modify_agree_byte_for_byte: \
             set FREEMKV_FW_CORPUS or FREEMKV_KAT_HOARD to run it"
        );
        return;
    };

    let dirs: Vec<PathBuf> = corpus
        .split(',')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let mut bins = Vec::new();
    for dir in &dirs {
        if !dir.is_dir() {
            eprintln!(
                "warning: corpus dir does not exist or is not a dir: {}",
                dir.display()
            );
            continue;
        }
        collect_bins(dir, &mut bins);
    }
    bins.sort();
    bins.dedup();

    assert!(
        !bins.is_empty(),
        "corpus env resolved to zero .bin files — check the path(s)"
    );

    let mut checked = 0usize;
    let mut disagree: Vec<(PathBuf, String)> = Vec::new();
    for path in &bins {
        let Ok(image) = std::fs::read(path) else {
            continue;
        };
        // Only assert the invariant on FORGEABLE images: on refused inputs, `create`
        // errors and there is nothing to compare. This mirrors the outer matrix.
        if !matches!(classify(&image), Classification::Forgeable) {
            continue;
        }
        // If the platform engine won't select this image at all, skip cleanly —
        // classify only reads bytes, so a rare mismatch (e.g. entropy just under
        // the bar but no MTK engine claims it) shouldn't fail here.
        let Ok(eng) = engine::detect(&image) else {
            continue;
        };
        // Every image where `create` succeeds must also `modify` cleanly and
        // produce the same bytes — this is what lets `modify` (the user-facing
        // never-abort driver) safely stand in for `create` in production paths.
        let Ok(cr) = eng.create(&image) else {
            // `create` refused: `modify` is allowed to still succeed with a
            // smaller lever set, so we skip this image (matches the intent of
            // testing the "on every image where create succeeds" invariant).
            continue;
        };
        let mr = match eng.modify(&image) {
            Ok(r) => r,
            Err(e) => {
                disagree.push((path.clone(), format!("create OK but modify errored: {e:#}")));
                continue;
            }
        };
        checked += 1;
        if cr.image != mr.image {
            // Find the first divergence + a short prefix, for triage.
            let first = cr
                .image
                .iter()
                .zip(mr.image.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(cr.image.len().min(mr.image.len()));
            disagree.push((
                path.clone(),
                format!(
                    "create/modify bytes differ (create.len={} modify.len={} first-diff=0x{first:x})",
                    cr.image.len(),
                    mr.image.len(),
                ),
            ));
        }
    }

    assert!(
        disagree.is_empty(),
        "{} image(s) failed the create==modify invariant (out of {checked} checked):\n{}",
        disagree.len(),
        disagree
            .iter()
            .map(|(p, d)| format!("  {}: {d}", p.display()))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    eprintln!("create==modify OK over {checked} corpus images");
}
