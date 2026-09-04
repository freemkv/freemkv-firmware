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
