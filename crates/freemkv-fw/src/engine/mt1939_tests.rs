//! MT1939 engine tests.
//!
//! The synthetic tests always run. The corpus tests are env-gated (skip clean when
//! unset, mirroring the MT1959 KAT-hoard pattern):
//!   * `FREEMKV_MT1939_HOARD=<dir>`   — a directory of real MT1939 `.bin` images.
//!   * `FREEMKV_MT1939_CLASSIC=<file>` — one classic-generation image.

use super::*;
use crate::engine::lever::LeverOutcome;
use crate::engine::Engine;

#[test]
fn masked_matches_basic() {
    // Two halfwords: exact match then a masked (low-byte) match.
    let img = [0x11, 0x22, 0x34, 0x48, 0x11, 0x22, 0x99, 0x48];
    let sig = &[(0x2211u16, 0xFFFFu16), (0x4800u16, 0xFF00u16)][..];
    // matches at off 0 (0x2211,0x4834) and off 4 (0x2211,0x4899)
    assert_eq!(masked_matches(&img, sig, 0, img.len()), vec![0, 4]);
    // window that excludes the second match
    assert_eq!(masked_matches(&img, sig, 0, 4), vec![0]);
}

#[test]
fn is_classic_reads_the_banner() {
    let mut img = vec![0u8; 0x4000];
    img[0x3000..0x3000 + 16].copy_from_slice(b"MT1939 Boot Code");
    assert!(is_classic(&img));
    img[0x3000..0x3000 + 16].copy_from_slice(b"MT1959 Boot JB8 ");
    assert!(!is_classic(&img));
}

/// Classic VID/AKE gate signatures must each match EXACTLY ONCE on a classic image
/// (proven-unique in the engine-scope report; guards against a loose matcher).
#[test]
fn classic_signatures_are_unique_on_a_real_classic_image() {
    let Ok(path) = std::env::var("FREEMKV_MT1939_CLASSIC") else {
        eprintln!("skip: set FREEMKV_MT1939_CLASSIC to a classic MT1939 image");
        return;
    };
    let img = std::fs::read(&path).expect("read classic image");
    assert!(is_classic(&img), "{path} is not a classic-generation image");
    let vid = masked_matches(&img, VID_GATE_SIG_CLASSIC, 0x17_0000, 0x18_0000).len();
    let ake = masked_matches(&img, AKE_GATE_SIG_CLASSIC, 0x17_0000, 0x18_0000).len();
    assert_eq!(vid, 1, "VID_GATE_SIG_CLASSIC not unique (got {vid})");
    assert_eq!(ake, 1, "AKE_GATE_SIG_CLASSIC not unique (got {ake})");
}

/// Every real MT1939 image must produce a valid `ModifyReport` (never a hard
/// refuse) with the DE lever effective; JB8 images additionally get the full
/// MT1959-lineage lever set, classic images get DE only (rest reported pending).
#[test]
fn every_mt1939_image_modifies_with_the_expected_generation_outcome() {
    let Ok(dir) = std::env::var("FREEMKV_MT1939_HOARD") else {
        eprintln!("skip: set FREEMKV_MT1939_HOARD to a dir of MT1939 images");
        return;
    };
    let mut seen = 0usize;
    let mut jb8_full = 0usize;
    let mut jb8_degraded = 0usize;
    let mut classic = 0usize;
    let mut no_identity = 0usize;
    for entry in walk(std::path::Path::new(&dir)) {
        let Ok(img) = std::fs::read(&entry) else {
            continue;
        };
        if img.len() != 0x20_0000 {
            continue;
        }
        let Ok(chip) = crate::family::detect_chip(&img) else {
            continue;
        };
        if chip.family != crate::family::ChipFamily::Mt1939 {
            continue;
        }
        if !chip.descriptor_present {
            // MT1939-detected (banner fallback) but no MTEK identity page — e.g. the
            // TS-LB23L combo. Nothing is applicable (no DE slot, classic engine
            // pending), so a clean "nothing modifiable" refusal is correct.
            assert!(
                Mt1939Engine.modify(&img).is_err(),
                "expected a clean refusal for the no-identity image {}",
                entry.display()
            );
            no_identity += 1;
            continue;
        }
        seen += 1;
        let report = Mt1939Engine
            .modify(&img)
            .unwrap_or_else(|e| panic!("MT1939 modify hard-failed on {}: {e:#}", entry.display()));
        // DE must always be effective (applied or already present).
        let de = report
            .levers
            .iter()
            .find(|l| l.id == LeverId::DowngradeEnable)
            .expect("DE lever present");
        assert!(
            de.outcome.is_effective(),
            "DE not effective on {}",
            entry.display()
        );
        // Re-signed image self-verifies + is the right size.
        assert_eq!(report.image.len(), img.len());

        if is_classic(&img) {
            classic += 1;
            // Classic: the higher levers are reported pending (SignatureNotFound),
            // never silently applied.
            for id in [LeverId::RegionFree, LeverId::RawRead, LeverId::Speed] {
                let l = report.levers.iter().find(|l| l.id == id).unwrap();
                assert!(
                    matches!(l.outcome, LeverOutcome::SignatureNotFound { .. }),
                    "classic {} expected pending {:?}, got {:?}",
                    entry.display(),
                    id,
                    l.outcome
                );
            }
        } else {
            // JB8 / MT1959-lineage: the shared machinery engages on the mainstream
            // BD-writers (Identity lever present + effective = full modify). A few
            // JB8-banner BD-combos (e.g. ASUS BC-12B1ST) have a table shape the
            // shared build can't uniquely resolve and cleanly degrade to DE-only —
            // never a hard failure. Both outcomes are valid; assert consistency.
            match report.levers.iter().find(|l| l.id == LeverId::Identity) {
                Some(ident) => {
                    assert!(
                        ident.outcome.is_effective(),
                        "JB8 {} has an Identity lever but it is not effective ({:?})",
                        entry.display(),
                        ident.outcome
                    );
                    jb8_full += 1;
                }
                None => jb8_degraded += 1, // clean DE-only fallback
            }
        }
    }
    eprintln!(
        "MT1939 corpus: {seen} modifiable ({jb8_full} JB8 full, {jb8_degraded} JB8 DE-only, \
         {classic} classic DE-only) + {no_identity} no-identity (clean refuse)"
    );
    assert!(seen > 0, "no MT1939 images found under {dir}");
    assert!(
        jb8_full > 0,
        "expected the shared MT1959-lineage build to engage on at least one JB8 image"
    );
}

/// BETA classic emit: with `--beta`, a classic image gets Identity + Region-free
/// **applied and flagged beta** + an effective DE, RawRead/Speed reported pending,
/// and the re-signed image **self-verifies** (round-trip). Without `--beta`, the
/// classic path stays DE-only and emits no beta levers.
#[test]
fn classic_beta_emit_applies_identity_and_region_and_round_trips() {
    let Ok(path) = std::env::var("FREEMKV_MT1939_CLASSIC") else {
        eprintln!("skip: set FREEMKV_MT1939_CLASSIC to a classic MT1939 image");
        return;
    };
    let img = std::fs::read(&path).expect("read classic image");
    assert!(is_classic(&img), "{path} is not a classic-generation image");
    use crate::engine::ModifyOpts;
    use crate::scheme::{IntegrityScheme, MtkCmac};

    // No --beta → no beta levers (stable DE-only path).
    let stable = Mt1939Engine
        .modify_with(&img, &ModifyOpts { beta: false })
        .expect("stable modify");
    assert!(
        !stable.levers.iter().any(|l| l.beta),
        "no beta levers may be emitted without --beta"
    );

    // --beta → Identity + Region applied (beta), DE effective, RawRead/Speed pending.
    let beta = Mt1939Engine
        .modify_with(&img, &ModifyOpts { beta: true })
        .expect("beta classic modify");
    let get = |id| beta.levers.iter().find(|l| l.id == id).unwrap();
    let ident = get(LeverId::Identity);
    assert!(
        ident.outcome == LeverOutcome::Applied && ident.beta,
        "Identity must be applied+beta, got {:?} beta={}",
        ident.outcome,
        ident.beta
    );
    let region = get(LeverId::RegionFree);
    assert!(
        region.outcome == LeverOutcome::Applied && region.beta,
        "Region must be applied+beta, got {:?} beta={}",
        region.outcome,
        region.beta
    );
    assert!(
        get(LeverId::DowngradeEnable).outcome.is_effective(),
        "DE must be effective and is NOT beta"
    );
    assert!(
        !get(LeverId::DowngradeEnable).beta,
        "DE is proven, not beta"
    );
    assert!(
        matches!(
            get(LeverId::RawRead).outcome,
            LeverOutcome::SignatureNotFound { .. }
        ),
        "RawRead stays pending on classic (INFERRED deny path), even under beta"
    );

    // Round-trip: the re-signed beta image verifies clean and keeps its size.
    let v = MtkCmac.verify(&beta.image).expect("verify beta image");
    assert!(
        !v.is_empty() && v.iter().all(|r| r.ok),
        "beta classic image must self-verify (round-trip)"
    );
    assert_eq!(beta.image.len(), img.len());
}

/// BETA classic coverage sweep over the corpus: for every classic image, the beta
/// path must EITHER fully resolve (Identity + Region applied-beta, self-verifying)
/// OR cleanly degrade to the stable DE path — never emit a non-verifying image.
#[test]
fn classic_beta_sweep_over_corpus() {
    let Ok(dir) = std::env::var("FREEMKV_MT1939_HOARD") else {
        eprintln!("skip: set FREEMKV_MT1939_HOARD");
        return;
    };
    use crate::engine::ModifyOpts;
    use crate::scheme::{IntegrityScheme, MtkCmac};
    let (mut classic, mut beta_full, mut degraded) = (0usize, 0usize, 0usize);
    for entry in walk(std::path::Path::new(&dir)) {
        let Ok(img) = std::fs::read(&entry) else {
            continue;
        };
        if img.len() != 0x20_0000 || !is_classic(&img) {
            continue;
        }
        let Ok(chip) = crate::family::detect_chip(&img) else {
            continue;
        };
        if !chip.descriptor_present {
            continue;
        }
        classic += 1;
        let r = Mt1939Engine
            .modify_with(&img, &ModifyOpts { beta: true })
            .unwrap_or_else(|e| panic!("beta classic hard-failed on {}: {e:#}", entry.display()));
        // Whatever path ran, the image must self-verify.
        let v = MtkCmac.verify(&r.image).expect("verify");
        assert!(
            !v.is_empty() && v.iter().all(|x| x.ok),
            "non-verifying image from {}",
            entry.display()
        );
        let ident_beta = r
            .levers
            .iter()
            .any(|l| l.id == LeverId::Identity && l.beta && l.outcome == LeverOutcome::Applied);
        if ident_beta {
            beta_full += 1;
        } else {
            degraded += 1;
        }
    }
    eprintln!("MT1939 classic BETA sweep: {classic} classic → {beta_full} full beta (Identity+Region), {degraded} degraded-to-DE (all self-verify)");
    assert!(classic > 0, "no classic images under {dir}");
    assert!(
        beta_full > 0,
        "expected the beta classic path to resolve on at least one image"
    );
}

/// Minimal recursive `.bin` walk (std-only).
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else if p.extension().and_then(|s| s.to_str()) == Some("bin") {
            out.push(p);
        }
    }
    out
}
