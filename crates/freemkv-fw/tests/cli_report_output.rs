//! End-to-end checks of what the `freemkv-fw` binary actually *tells the
//! operator* — the process exit code and the report it prints.
//!
//! The report printers (`print_verdicts`, `print_modify_report`,
//! `print_base_report`) and `main`'s exit-code mapping are welded to stdout and
//! to `ExitCode`, so they are only observable by running the real binary. That
//! is the point of this harness: the region table an operator reads before
//! flashing, and the exit code a publish pipeline gates on, are both load-bearing
//! — a silently empty table or a zero exit on a mismatching image is the failure
//! class that puts bad firmware on real hardware.
//!
//! Every case drives the committed OEM BU40N 1.00 fixture (third-party firmware
//! kept in-tree for interoperability testing — see `tests/fixtures/README.md`),
//! so no environment setup and no hardware is required.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The compiled CLI under test.
fn fw_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_freemkv-fw"))
}

fn fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("BU40N fixture must be present at {path}: {e}"))
}

/// A fresh, empty scratch directory unique to this process and `name`.
fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("freemkv-fw-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(fw_bin())
        .args(args)
        .output()
        .expect("the freemkv-fw binary must be runnable")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn verify_of_a_matching_image_prints_the_whole_region_table_and_exits_zero() {
    let dir = scratch_dir("verify-ok");
    let image = dir.join("BU40N.bin");
    std::fs::write(&image, fixture()).unwrap();

    let out = run(&["verify", &path_str(&image)]);
    let stdout = stdout_of(&out);

    assert!(
        out.status.success(),
        "an unmodified OEM image must verify clean (exit 0): {stdout}"
    );
    // The table itself: an operator decides whether an image is safe to flash
    // from these rows, so "printed nothing" must never read as "verified".
    for expect in ["idx", "range", "stored", "computed", "MATCH"] {
        assert!(
            stdout.contains(expect),
            "the per-region verdict table must print its {expect:?} column — an \
             empty table beside an 'OK' summary is indistinguishable from a \
             real verify: {stdout}"
        );
    }
    // Ranges are INCLUSIVE on both ends, so the size of 0x11000..=0x19fff is
    // 0x9000 bytes, not 0x8fff. An off-by-one here misreports how much of the
    // image the digest actually covers.
    assert!(
        stdout.contains("0x11000-0x19fff"),
        "the covered range must be printed verbatim: {stdout}"
    );
    assert!(
        stdout.contains("0x9000"),
        "an inclusive 0x11000..=0x19fff range is 0x9000 bytes; a size that is \
         one byte short understates the protected span: {stdout}"
    );
    assert!(
        stdout.contains("0x105c0-0x105cf"),
        "every active region gets a row, not just the first: {stdout}"
    );
    assert!(
        stdout.contains("4 region(s) OK"),
        "the summary must count the regions it actually verified: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_of_a_corrupted_image_exits_non_zero() {
    let dir = scratch_dir("verify-bad");
    let image = dir.join("BU40N-corrupt.bin");
    let mut bytes = fixture();
    bytes[0x0001_2000] ^= 0xFF; // inside the first CMAC-covered region
    std::fs::write(&image, &bytes).unwrap();

    let out = run(&["verify", &path_str(&image)]);
    let stdout = stdout_of(&out);

    assert!(
        !out.status.success(),
        "a corrupted image MUST exit non-zero — a publish pipeline gates purely \
         on this code, and a zero here ships tampered firmware: {stdout}"
    );
    assert!(
        stdout.contains("MISMATCH"),
        "the failing region must be named in the table: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_of_a_missing_path_exits_non_zero_and_explains_itself_on_stderr() {
    let missing = std::env::temp_dir().join("freemkv-fw-cli-absent-image.bin");
    let _ = std::fs::remove_file(&missing);

    let out = run(&["verify", &path_str(&missing)]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        !out.status.success(),
        "a path that could not even be read must not exit 0"
    );
    assert!(
        stderr.contains("error:") && stderr.contains("reading"),
        "the failure must be reported on stderr, naming what went wrong: {stderr}"
    );
}

/// NOT COVERABLE HERE: three shapes of `print_modify_report` stay unobserved.
///
/// * the `NotApplicable { reason }` and `SignatureNotFound { detail }` detail
///   lines — every lever the engine emits for the only real image in the repo
///   is `Applied` or `AlreadyPresent`, so those arms never run. Reaching them
///   needs a firmware image whose capability or signature set misses, which the
///   repo cannot ship.
/// * the `!l.facts.is_empty()` guard flipped to an unconditional `true` — every
///   lever this engine reports carries grounded facts, so the guard is never
///   false on any reachable input and the two forms print identically.
///
/// All three only ever change one *printed line*; asserting on them would need
/// either such a fixture or a production seam that returned the report text
/// instead of writing it to stdout. Neither is in scope for a tests-only change.
#[test]
fn create_with_audit_prints_the_audit_the_lever_facts_and_where_it_wrote() {
    let dir = scratch_dir("create-audit");
    let input = dir.join("BU40N.bin");
    let output = dir.join("out.bin");
    std::fs::write(&input, fixture()).unwrap();

    let out = run(&["create", &path_str(&input), &path_str(&output), "--audit"]);
    let stdout = stdout_of(&out);

    assert!(
        out.status.success(),
        "the audited MODIFY build must succeed on the OEM base: {stdout}"
    );
    assert!(
        stdout.contains("structural audit:") && stdout.contains("[PASS]"),
        "without --json the per-check audit result must be printed — it is the \
         only evidence the operator gets that each detour actually landed: {stdout}"
    );
    assert!(
        !stdout.contains("[FAIL]"),
        "no audit check may fail on the OEM base: {stdout}"
    );
    // The per-lever report: the grounded addresses are what makes the summary
    // checkable against the image instead of a fixed string.
    assert!(
        stdout.contains("Identity") && stdout.contains("applied"),
        "each lever's outcome must be reported: {stdout}"
    );
    assert!(
        stdout.contains("handler_va 0x153968"),
        "an applied lever must print its grounded facts — dropping them leaves \
         the report unfalsifiable against the image it describes: {stdout}"
    );
    assert!(
        stdout.contains("Wrote") && stdout.contains("CMAC region(s) OK"),
        "the report must say where it wrote and how many regions re-verified: {stdout}"
    );
    assert!(output.is_file(), "the built image must exist on disk");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_with_json_emits_only_machine_readable_output() {
    let dir = scratch_dir("create-json");
    let input = dir.join("BU40N.bin");
    let output = dir.join("out.bin");
    std::fs::write(&input, fixture()).unwrap();

    let out = run(&[
        "create",
        &path_str(&input),
        &path_str(&output),
        "--audit",
        "--json",
    ]);
    let stdout = stdout_of(&out);

    assert!(out.status.success(), "the build must succeed: {stdout}");
    assert!(
        stdout.trim_start().starts_with('{') && stdout.trim_end().ends_with('}'),
        "--json output must be a single JSON object a caller can pipe into a \
         parser: {stdout}"
    );
    assert!(
        !stdout.contains("structural audit:"),
        "the human audit table must be suppressed under --json, or it corrupts \
         the machine-readable stream: {stdout}"
    );
    assert!(
        stdout.contains("\"levers\":["),
        "the JSON report must carry the per-lever outcomes: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_base_prints_the_strict_summary_and_per_feature_availability() {
    let dir = scratch_dir("create-base");
    let input = dir.join("BU40N.bin");
    let output = dir.join("base.bin");
    std::fs::write(&input, fixture()).unwrap();

    let out = run(&["create", &path_str(&input), &path_str(&output), "--base"]);
    let stdout = stdout_of(&out);

    assert!(
        out.status.success(),
        "the STRICT base build must succeed on an image with a real freemkv \
         BASE: {stdout}"
    );
    assert!(
        stdout.contains("[STRICT base]"),
        "the human base report must identify itself as the strict build: {stdout}"
    );
    for feature in ["Speed", "Region", "UHD", "BD", "HRL", "Encryption"] {
        assert!(
            stdout.contains(feature),
            "every feature's resolved availability must be printed — this is \
             what the publish pipeline advertises: {stdout}"
        );
    }
    assert!(
        stdout.contains("available"),
        "each feature line carries an available/unavailable verdict: {stdout}"
    );
    assert!(
        stdout.contains("Wrote"),
        "the base report must say where it wrote the image: {stdout}"
    );
    assert!(output.is_file());
    let _ = std::fs::remove_dir_all(&dir);
}
