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

/// `span` is `sig.len() * 2` (halfwords → bytes), and the walk is `off + span
/// <= hi`. A signature whose LAST halfword sits on the final halfword of the
/// window must still be found: an engine that silently loses matches at the tail
/// of a scan window picks the wrong anchor (or none) for a lever, which is a
/// wrong-image-for-this-drive bug.
#[test]
fn masked_matches_finds_a_match_in_the_final_halfword_of_the_window() {
    let img = [0xAAu8, 0xBB, 0x11, 0x22];
    let sig = &[(0x2211u16, 0xFFFFu16)][..];
    assert_eq!(
        masked_matches(&img, sig, 0, img.len()),
        vec![2],
        "the last halfword of the window is in scope (span = len*2, bound is `<=`)"
    );
}

/// The `lo + span > hi` fast-exit is an ADDITION: the window must be measured
/// from its start, never scaled by it. A window that begins deep in the image
/// (`lo` large) and is exactly wide enough for the signature must still be
/// scanned — the classic anchors live ~0x17_0000 into a 2 MiB image, so a
/// mis-scaled guard would blind the finder on exactly the real inputs.
#[test]
fn masked_matches_scans_a_window_that_starts_deep_into_the_image() {
    let mut img = vec![0u8; 8];
    img[6] = 0x11;
    img[7] = 0x22;
    let sig = &[(0x2211u16, 0xFFFFu16)][..];
    assert_eq!(
        masked_matches(&img, sig, 6, 8),
        vec![6],
        "lo=6, span=2, hi=8 → exactly one candidate offset, and it matches"
    );
}

/// Each signature halfword `i` is read at `off + i*2` — its own slot. Reading
/// them at any other stride would let an unrelated byte pattern satisfy a
/// multi-halfword signature, which is how a finder lands a detour on the wrong
/// instruction. The existing `masked_matches_basic` fixture masks its second
/// halfword's low byte, so it cannot see a stride bug; this one is fully exact.
#[test]
fn masked_matches_reads_each_signature_halfword_at_its_own_offset() {
    let img = [0x11u8, 0x22, 0x33, 0x44, 0x00, 0x00];
    let sig = &[(0x2211u16, 0xFFFFu16), (0x4433u16, 0xFFFFu16)][..];
    assert_eq!(
        masked_matches(&img, sig, 0, img.len()),
        vec![0],
        "halfword 1 must be read at off+2, not at any other stride"
    );
}

/// Lay a masked signature down as bytes that match it exactly (`val & mask`).
fn materialize(sig: &[(u16, u16)]) -> Vec<u8> {
    sig.iter()
        .flat_map(|&(val, mask)| (val & mask).to_le_bytes())
        .collect()
}

/// A 2 MiB zero image carrying one VID gate and one AKE gate at chosen offsets.
fn image_with_classic_gates(vid_at: Option<usize>, ake_at: &[usize]) -> Vec<u8> {
    let mut img = vec![0u8; 0x20_0000];
    if let Some(off) = vid_at {
        let bytes = materialize(VID_GATE_SIG_CLASSIC);
        img[off..off + bytes.len()].copy_from_slice(&bytes);
    }
    let bytes = materialize(AKE_GATE_SIG_CLASSIC);
    for &off in ake_at {
        img[off..off + bytes.len()].copy_from_slice(&bytes);
    }
    img
}

/// The classic raw-read anchors are the REAL matched offsets of the two gates,
/// not a constant and not `None`. These two addresses are where the classic
/// detour would be written, so returning anything else means emitting a branch
/// at an address that is not the gate — the bricking class.
#[test]
fn classic_rawread_anchors_reports_the_two_matched_gate_offsets() {
    let vid_off = 0x0017_1000usize;
    let ake_off = 0x0017_9000usize;
    let img = image_with_classic_gates(Some(vid_off), &[ake_off]);
    assert_eq!(
        classic_rawread_anchors(&img),
        Some((vid_off as u32, ake_off as u32)),
        "both gates are unique → their own offsets are reported verbatim"
    );
}

/// Uniqueness is the safety property: a gate that matches twice means the
/// signature does not pin a single site on this image, so no anchor may be
/// reported. Reporting one of them would be a coin flip over which gate the
/// detour lands on.
#[test]
fn classic_rawread_anchors_refuses_a_gate_that_matches_more_than_once() {
    let vid_off = 0x0017_1000usize;
    let img = image_with_classic_gates(Some(vid_off), &[0x0017_9000, 0x0018_9000]);
    assert_eq!(
        classic_rawread_anchors(&img),
        None,
        "two AKE matches → ambiguous, must not report an anchor"
    );
    let img = image_with_classic_gates(None, &[0x0017_9000]);
    assert_eq!(
        classic_rawread_anchors(&img),
        None,
        "no VID match → must not report an anchor"
    );
}

/// A synthetic classic-generation image: `"MT1939 Boot Code"` banner, an MTEK
/// identity page (so the DE byte has a home), and a parseable — but inactive —
/// CMAC table so the closing `resign` succeeds. Nothing else is present, so the
/// classic base finders miss and `modify` lands on its DE-only fallback, which
/// is the code path these tests pin.
fn synthetic_classic_de_only_image(de_byte: u8) -> Vec<u8> {
    let mut img = vec![0u8; 0x20_0000];
    img[freemkv_chipset::BANNER_OFFSET..freemkv_chipset::BANNER_OFFSET + 16]
        .copy_from_slice(b"MT1939 Boot Code");
    let desc = freemkv_chipset::DESCRIPTOR_OFFSET;
    img[desc..desc + 0x40].fill(b' ');
    img[desc..desc + 8].copy_from_slice(b"HL-DT-ST");
    img[desc + 0x08..desc + 0x08 + 11].copy_from_slice(b"BD-RE  X100");
    img[desc + 0x18..desc + 0x1C].copy_from_slice(b"1.00");
    img[desc + 0x34..desc + 0x3E].copy_from_slice(b"MTEKMT1939");
    img[desc + DE_OFF_IN_DESCRIPTOR] = de_byte;
    // Table entries all `0xFF` (unused): parse_table succeeds, nothing to sign.
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        img[off..off + cmac::ENTRY_SIZE].fill(0xFF);
    }
    img
}

/// The DE-only fallback writes `0xDE` at the identity page's `+0x56` slot — the
/// downgrade-enable byte — and reports THAT offset as its grounded fact. The
/// address is `DESCRIPTOR_OFFSET + 0x56`; any other arithmetic writes a stray
/// byte into an unrelated page of a firmware image that is about to be flashed.
#[test]
fn mt1939_de_only_fallback_sets_the_downgrade_byte_at_the_identity_page_offset() {
    let img = synthetic_classic_de_only_image(0x00);
    let want_off = (freemkv_chipset::DESCRIPTOR_OFFSET + DE_OFF_IN_DESCRIPTOR) as u32;
    let r = Mt1939Engine
        .modify(&img)
        .expect("a classic image with an identity page is always modifiable (DE at minimum)");
    let de = r
        .levers
        .iter()
        .find(|l| l.id == LeverId::DowngradeEnable)
        .expect("DE lever present");
    assert_eq!(
        de.outcome,
        LeverOutcome::Applied,
        "a 0x00 DE byte must be APPLIED, not reported as already set"
    );
    assert_eq!(
        de.facts,
        vec![("de_off", want_off)],
        "the grounded DE offset must be DESCRIPTOR_OFFSET + 0x56"
    );
    assert_eq!(
        r.image[want_off as usize], 0xDE,
        "the downgrade-enable byte itself must be 0xDE in the produced image"
    );
    assert_eq!(
        r.image[..want_off as usize],
        img[..want_off as usize],
        "the DE lever must touch nothing before its own byte"
    );
}

/// Idempotency at the byte level: an image whose DE byte is already `0xDE` is
/// reported `AlreadyPresent`, never re-applied. Mis-reading that byte would
/// make every re-run claim a fresh patch on an unchanged image.
#[test]
fn mt1939_de_only_fallback_reports_an_already_set_downgrade_byte_as_idempotent() {
    let img = synthetic_classic_de_only_image(0xDE);
    let r = Mt1939Engine.modify(&img).expect("modify");
    let de = r
        .levers
        .iter()
        .find(|l| l.id == LeverId::DowngradeEnable)
        .expect("DE lever present");
    assert_eq!(
        de.outcome,
        LeverOutcome::AlreadyPresent,
        "a DE byte already 0xDE is idempotent, not a fresh apply"
    );
}

/// An MT1939-banner image with NO MTEK identity page has no DE slot and no
/// classic base, so nothing at all is effective: `modify` must REFUSE cleanly
/// rather than hand back an image it did not change. The refusal is the signal
/// that the drive owner needs a different tool, not a green light.
#[test]
fn mt1939_refuses_an_image_with_nothing_effective_to_apply() {
    let mut img = vec![0u8; 0x20_0000];
    img[freemkv_chipset::BANNER_OFFSET..freemkv_chipset::BANNER_OFFSET + 16]
        .copy_from_slice(b"MT1939 Boot Code");
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        img[off..off + cmac::ENTRY_SIZE].fill(0xFF);
    }
    let err = Mt1939Engine
        .modify(&img)
        .expect_err("no identity page → nothing modifiable → clean refusal");
    assert!(
        err.to_string().contains("nothing modifiable"),
        "expected the 'nothing modifiable' refusal, got: {err:#}"
    );
}

/// A NON-classic (JB8 / MT1959-lineage) MT1939 image must be routed to the
/// shared MT1959 machinery, not to the DE-only fallback: the fallback applies
/// one byte and reports the other four levers pending, so a routing inversion
/// silently ships a drive a near-empty patch. Env-gated on a real image because
/// the shared build only succeeds on real MT1959-lineage geometry.
#[test]
fn mt1939_routes_a_non_classic_image_to_the_shared_mt1959_machinery() {
    let Ok(path) = std::env::var("FREEMKV_KAT_BASE") else {
        eprintln!("skip: set FREEMKV_KAT_BASE to an MT1959-lineage image");
        return;
    };
    let img = std::fs::read(&path).expect("read KAT base");
    assert!(!is_classic(&img), "{path} must be a non-classic image");
    let r = Mt1939Engine.modify(&img).expect("modify");
    assert!(
        r.levers
            .iter()
            .any(|l| l.id == LeverId::Identity && l.outcome.is_effective()),
        "the shared build must engage (Identity effective); the DE-only fallback \
         emits no Identity lever at all"
    );
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
            // Classic now emits unconditionally when its base is locatable: Identity
            // + Region-free + Raw-read (04 01/04 02) Applied. Speed stays unreversed
            // → always pending. On the DE-only degrade path Raw-read/Region report
            // pending instead — both outcomes are valid, so accept either.
            let speed = report
                .levers
                .iter()
                .find(|l| l.id == LeverId::Speed)
                .unwrap();
            assert!(
                matches!(speed.outcome, LeverOutcome::SignatureNotFound { .. }),
                "classic {} Speed expected pending, got {:?}",
                entry.display(),
                speed.outcome
            );
            let rawread = report
                .levers
                .iter()
                .find(|l| l.id == LeverId::RawRead)
                .unwrap();
            assert!(
                matches!(
                    rawread.outcome,
                    LeverOutcome::Applied | LeverOutcome::SignatureNotFound { .. }
                ),
                "classic {} RawRead must be Applied (full emit) or pending (degrade), got {:?}",
                entry.display(),
                rawread.outcome
            );
            let region = report
                .levers
                .iter()
                .find(|l| l.id == LeverId::RegionFree)
                .unwrap();
            assert!(
                matches!(
                    region.outcome,
                    LeverOutcome::Applied | LeverOutcome::SignatureNotFound { .. }
                ),
                "classic {} RegionFree must be Applied (full emit) or pending (degrade), got {:?}",
                entry.display(),
                region.outcome
            );
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

/// Classic emit (no flag): a classic image gets Identity, Region-free and
/// Raw-read (04 01 + 04 02) **applied**, an effective DE, and the re-signed
/// image **self-verifies** (round-trip). Classic modify is unconditional now —
/// being structurally valid, it just produces, carrying the static-only label.
#[test]
fn classic_emit_applies_identity_and_region_and_round_trips() {
    let Ok(path) = std::env::var("FREEMKV_MT1939_CLASSIC") else {
        eprintln!("skip: set FREEMKV_MT1939_CLASSIC to a classic MT1939 image");
        return;
    };
    let img = std::fs::read(&path).expect("read classic image");
    assert!(is_classic(&img), "{path} is not a classic-generation image");
    use crate::engine::lever::Validation;
    use crate::scheme::{IntegrityScheme, MtkCmac};

    let r = Mt1939Engine.modify(&img).expect("classic modify");
    assert_eq!(
        r.validation,
        Validation::StaticOnly,
        "uniform static-only label"
    );
    let get = |id| r.levers.iter().find(|l| l.id == id).unwrap();
    assert_eq!(
        get(LeverId::Identity).outcome,
        LeverOutcome::Applied,
        "Identity must be applied"
    );
    assert_eq!(
        get(LeverId::RegionFree).outcome,
        LeverOutcome::Applied,
        "Region-free must be applied"
    );
    assert!(
        get(LeverId::DowngradeEnable).outcome.is_effective(),
        "DE must be effective"
    );
    assert_eq!(
        get(LeverId::RawRead).outcome,
        LeverOutcome::Applied,
        "classic Raw-read (04 01 Gate-A + 04 02 AKE) must be applied"
    );

    // Round-trip: the re-signed image verifies clean and keeps its size.
    let v = MtkCmac.verify(&r.image).expect("verify classic image");
    assert!(
        !v.is_empty() && v.iter().all(|r| r.ok),
        "classic image must self-verify (round-trip)"
    );
    assert_eq!(r.image.len(), img.len());
}

/// Classic Raw-read (04 01 + 04 02) on a real classic image: the finder fix
/// (agid_struct via the CDB base, NOT the r7 heuristic) holds, the detours land,
/// the clear-VID scratch is the unique 0x210c00, and the full structural audit
/// passes — including that the deny block is byte-identical to OEM (no deny
/// detour). Env-gated on `FREEMKV_MT1939_CLASSIC`.
#[test]
fn classic_rawread_finder_fix_emit_and_audit() {
    let Ok(path) = std::env::var("FREEMKV_MT1939_CLASSIC") else {
        eprintln!("skip: set FREEMKV_MT1939_CLASSIC to a classic MT1939 image");
        return;
    };
    let img = std::fs::read(&path).expect("read classic image");
    assert!(is_classic(&img), "{path} is not a classic-generation image");
    let eng = Mt1959Engine;

    // Finder fix: classic AGID struct = CDB base (r5), distinct from the MT1959
    // `ldr r7,[pc]` heuristic cell (which is wrong on classic).
    let cdb = eng.find_cdb_base(&img).expect("cdb base");
    let classic_struct = eng
        .find_vid_agid_struct_classic(&img)
        .expect("classic agid struct");
    let r7 = eng.find_vid_agid_struct(&img).expect("r7 heuristic");
    assert_eq!(
        classic_struct, cdb,
        "classic agid struct must be the CDB base"
    );
    assert_ne!(
        classic_struct, r7,
        "classic must NOT reuse the r7 heuristic cell (the finder bug)"
    );

    let r = Mt1939Engine.modify(&img).expect("classic modify");
    let rr = r
        .levers
        .iter()
        .find(|l| l.id == LeverId::RawRead)
        .expect("RawRead lever");
    assert_eq!(rr.outcome, LeverOutcome::Applied, "RawRead must be applied");
    let f = |k: &str| rr.facts.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
    assert!(f("gatea_gate").is_some(), "gatea_gate fact present");
    assert!(f("ake_site").is_some(), "ake_site fact present");
    assert_eq!(f("scratch"), Some(0x0021_0c00), "unique clear-VID scratch");

    // The Gate-A `cmp r0,#6` site must be replaced by the detour `bl`.
    let gate = f("gatea_gate").unwrap() as usize;
    assert_eq!(
        u16::from_le_bytes([img[gate], img[gate + 1]]),
        0x2806,
        "OEM had cmp r0,#6 at the gate"
    );
    assert_ne!(
        u16::from_le_bytes([r.image[gate], r.image[gate + 1]]),
        0x2806,
        "gate site must be patched to a bl"
    );

    // Deny block byte-identical to OEM (we emit no deny detour).
    let deny = f("deny").unwrap() as usize;
    assert_eq!(
        img[deny..deny + 0x40],
        r.image[deny..deny + 0x40],
        "deny block must be untouched"
    );

    // Full structural audit passes.
    let audit = crate::engine::audit::audit_image(&img, &r);
    assert!(
        audit.ok(),
        "structural audit failed:\n{}",
        audit
            .failures()
            .map(|c| format!("  [{}] {}: {}", c.lever, c.what, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Classic coverage sweep over the corpus: every classic image resolves to the full
/// classic emit (Identity + Region applied), self-verifying — never a non-verifying
/// image, never a hard failure.
#[test]
fn classic_emit_sweep_over_corpus() {
    let Ok(dir) = std::env::var("FREEMKV_MT1939_HOARD") else {
        eprintln!("skip: set FREEMKV_MT1939_HOARD");
        return;
    };
    use crate::scheme::{IntegrityScheme, MtkCmac};
    let (mut classic, mut full, mut degraded) = (0usize, 0usize, 0usize);
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
            .modify(&img)
            .unwrap_or_else(|e| panic!("classic modify hard-failed on {}: {e:#}", entry.display()));
        let v = MtkCmac.verify(&r.image).expect("verify");
        assert!(
            !v.is_empty() && v.iter().all(|x| x.ok),
            "non-verifying image from {}",
            entry.display()
        );
        let full_emit = r
            .levers
            .iter()
            .any(|l| l.id == LeverId::Identity && l.outcome == LeverOutcome::Applied);
        if full_emit {
            full += 1;
        } else {
            degraded += 1;
        }
    }
    eprintln!("MT1939 classic sweep: {classic} classic → {full} full (Identity+Region), {degraded} degraded-to-DE (all self-verify)");
    assert!(classic > 0, "no classic images under {dir}");
    assert!(
        full > 0,
        "expected the classic emit path to resolve on at least one image"
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
