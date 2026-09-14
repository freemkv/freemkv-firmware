//! Idempotency + structural-audit tests.
//!
//! The synthetic tests run in CI unconditionally. The two heavy gates are
//! env-gated (skip clean when unset), mirroring the KAT hoard tests:
//!   * `FREEMKV_KAT_BASE` → a single OEM BU40N 1.00 image.
//!   * `FREEMKV_OEM_CORPUS` → a directory of OEM `.bin` images (the 63 plaintext
//!     MTK firmwares); every one that modifies must round-trip idempotently and
//!     pass the structural audit.

use super::{audit_image, AuditResult};
use crate::engine::mt1959_build::is_freemkv_patched;
use crate::engine::{self, lever::LeverOutcome};
use freemkv_flash::cmac;

fn fmt_failures(a: &AuditResult) -> String {
    a.failures()
        .map(|c| format!("    [{}] {}: {}", c.lever, c.what, c.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn resp_magic_marks_patched_not_stock() {
    let mut stock = vec![0u8; 4096];
    assert!(!is_freemkv_patched(&stock), "empty buffer is not patched");
    // Splice the identity magic anywhere → recognized as patched.
    stock[1000..1007].copy_from_slice(b"freemkv");
    assert!(is_freemkv_patched(&stock), "RESP_MAGIC must mark patched");
}

/// End-to-end on the real BU40N base: modify → structural audit passes, and a
/// second modify is byte-identical with every lever AlreadyPresent.
#[test]
fn kat_base_audits_and_is_idempotent() {
    let Ok(path) = std::env::var("FREEMKV_KAT_BASE") else {
        eprintln!("skipping: FREEMKV_KAT_BASE unset");
        return;
    };
    let image = std::fs::read(&path).expect("read KAT base");
    let engine = engine::detect(&image).expect("detect base");
    let r1 = engine.modify(&image).expect("modify base");

    // Structural audit: every Applied lever's detour landed.
    let audit = audit_image(&image, &r1);
    assert!(
        audit.ok(),
        "structural audit failed on KAT base:\n{}",
        fmt_failures(&audit)
    );
    assert!(
        r1.levers.iter().any(|l| l.outcome == LeverOutcome::Applied),
        "expected some Applied levers on the OEM base"
    );

    // Idempotency: re-modify our own output.
    let engine2 = engine::detect(&r1.image).expect("re-detect output");
    let r2 = engine2
        .modify(&r1.image)
        .expect("re-modify output must not error");
    assert_eq!(
        r2.image, r1.image,
        "modify is not idempotent (bytes differ)"
    );
    assert!(
        r2.levers
            .iter()
            .all(|l| !matches!(l.outcome, LeverOutcome::Applied)),
        "second pass must apply nothing"
    );
    assert!(cmac::verify(&r1.image), "output must self-verify");
}

/// Synthetic structural-audit checks for a classic Raw-read report: the Gate-A
/// `bl` check PASSES when the detour landed on a written stub, FAILS when the
/// stub is blank flash, and the "detour facts present" check FAILS when an
/// Applied lever carries none. Also exercises the classic-only `deny`
/// (byte-identical) and `scratch` (RAM-window) checks. No owned image needed.
#[test]
fn raw_read_audit_flags_blank_stub_and_missing_facts() {
    use crate::engine::lever::{LeverId, LeverReport, ModifyReport, Validation};
    use crate::thumb;

    fn report_with(image: Vec<u8>, lever: LeverReport) -> ModifyReport {
        ModifyReport {
            engine: "MT1939",
            family: "f".into(),
            vendor: "v".into(),
            model: "m".into(),
            rev: "r".into(),
            vendor_specific: String::new(),
            media: "BD".into(),
            levers: vec![lever],
            image,
            validation: Validation::StaticOnly,
        }
    }
    fn rr_check<'a>(a: &'a AuditResult, what: &str) -> &'a crate::engine::audit::AuditCheck {
        a.checks
            .iter()
            .find(|c| c.lever == "Raw read" && c.what == what)
            .unwrap_or_else(|| panic!("no Raw-read check {what:?}"))
    }

    let site = 0x1000u32;
    let stub = 0x2000u32;
    let deny = 0x0800u32;

    // --- landed: real bl at site, non-blank stub, deny untouched, scratch in RAM.
    let mut img = vec![0xFFu8; 0x4000];
    let bl = thumb::encode_bl(site as usize, stub).unwrap();
    thumb::write(&mut img, site as usize, &bl);
    thumb::write(&mut img, stub as usize, &[0x01u8; 16]); // non-blank stub
    let orig = img.clone(); // deny region identical
    let landed = report_with(
        img,
        LeverReport::applied(
            LeverId::RawRead,
            vec![
                ("gatea_gate", site),
                ("gatea_stub_va", stub),
                ("deny", deny),
                ("scratch", 0x0021_0c00),
            ],
        ),
    );
    let a = audit_image(&orig, &landed);
    assert!(rr_check(&a, "Gate-A detour bl").ok, "landed bl must pass");
    assert!(
        rr_check(&a, "deny block byte-identical to OEM").ok,
        "untouched deny must pass"
    );
    assert!(
        rr_check(&a, "scratch buffer in runtime RAM window").ok,
        "0x210c00 is in the RAM window"
    );

    // --- blank stub: bl present but the stub is still 0xFF → fail.
    let mut img = vec![0xFFu8; 0x4000];
    thumb::write(&mut img, site as usize, &bl); // stub left blank
    let orig = img.clone();
    let blank = report_with(
        img,
        LeverReport::applied(
            LeverId::RawRead,
            vec![("gatea_gate", site), ("gatea_stub_va", stub)],
        ),
    );
    assert!(
        !rr_check(&audit_image(&orig, &blank), "Gate-A detour bl").ok,
        "blank stub must fail"
    );

    // --- missing facts: Applied but no detour facts → the guard check fails.
    let img = vec![0xFFu8; 0x4000];
    let orig = img.clone();
    let empty = report_with(img, LeverReport::applied(LeverId::RawRead, vec![]));
    assert!(
        !rr_check(&audit_image(&orig, &empty), "detour facts present").ok,
        "missing facts must fail"
    );
}

fn corpus_files() -> Option<Vec<std::path::PathBuf>> {
    let dir = std::env::var("FREEMKV_OEM_CORPUS").ok()?;
    let mut out = Vec::new();
    fn walk(d: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().map(|x| x == "bin").unwrap_or(false) {
                    out.push(p);
                }
            }
        }
    }
    walk(std::path::Path::new(&dir), &mut out);
    out.sort();
    Some(out)
}

/// Every OEM image that modifies must be idempotent: modify(modify(x)) == modify(x),
/// the second pass applies nothing, and the output self-verifies.
#[test]
fn modify_is_idempotent_over_corpus() {
    let Some(files) = corpus_files() else {
        eprintln!("skipping: FREEMKV_OEM_CORPUS unset");
        return;
    };
    let mut checked = 0usize;
    let mut fails = Vec::new();
    for f in &files {
        let img = std::fs::read(f).unwrap();
        // Non-MTK / undetectable images are correctly refused — skip.
        let Ok(engine) = engine::detect(&img) else {
            continue;
        };
        let Ok(r1) = engine.modify(&img) else {
            continue;
        };
        if !r1.any_effective() {
            continue;
        }
        let name = f.file_name().unwrap().to_string_lossy();
        let Ok(engine2) = engine::detect(&r1.image) else {
            fails.push(format!("{name}: output no longer detects"));
            continue;
        };
        match engine2.modify(&r1.image) {
            Err(e) => fails.push(format!("{name}: re-modify errored: {e:#}")),
            Ok(r2) => {
                checked += 1;
                if r2.image != r1.image {
                    fails.push(format!("{name}: NOT idempotent (bytes differ)"));
                }
                if r2.levers.iter().any(|l| l.outcome == LeverOutcome::Applied) {
                    fails.push(format!("{name}: 2nd pass applied something"));
                }
                if !cmac::verify(&r1.image) {
                    fails.push(format!("{name}: output fails CMAC"));
                }
            }
        }
    }
    assert!(
        fails.is_empty(),
        "idempotency failures ({}/{} checked):\n{}",
        fails.len(),
        checked,
        fails.join("\n")
    );
    eprintln!("idempotency OK over {checked} modifiable corpus images");
}

/// Every OEM image that modifies must pass the structural detour audit.
#[test]
fn structural_audit_passes_over_corpus() {
    let Some(files) = corpus_files() else {
        eprintln!("skipping: FREEMKV_OEM_CORPUS unset");
        return;
    };
    let mut checked = 0usize;
    let mut fails = Vec::new();
    for f in &files {
        let img = std::fs::read(f).unwrap();
        let Ok(engine) = engine::detect(&img) else {
            continue;
        };
        let Ok(r) = engine.modify(&img) else { continue };
        if !r.any_effective() {
            continue;
        }
        checked += 1;
        let audit = audit_image(&img, &r);
        if !audit.ok() {
            let name = f.file_name().unwrap().to_string_lossy();
            fails.push(format!("{name}:\n{}", fmt_failures(&audit)));
        }
    }
    assert!(
        fails.is_empty(),
        "structural-audit failures ({}/{} checked):\n{}",
        fails.len(),
        checked,
        fails.join("\n")
    );
    eprintln!("structural audit OK over {checked} modifiable corpus images");
}
