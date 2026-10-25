//! Tests for the typed library surface.
//!
//! These pin the *decisions* the wrappers make on a caller's behalf: whether an
//! image verified, whether a re-sign may be handed back, and whether a create
//! produced usable bytes. A GUI consumes only these booleans and slices, so a
//! wrapper that reports "OK" for an image that proved nothing is indistinguishable
//! from one that proved everything.

use super::*;
use freemkv_flash::cmac;

/// A well-formed MTK image with exactly one active, correctly-signed region.
fn synthetic_image() -> Vec<u8> {
    let mut img = vec![0u8; 0x20000];
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        for b in &mut img[off..off + cmac::ENTRY_SIZE] {
            *b = 0xFF;
        }
    }
    let (start, end): (u32, u32) = (0x1000, 0x1FFF);
    let off = cmac::TABLE_OFFSET;
    img[off..off + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[off + 4..off + 8].copy_from_slice(&start.to_le_bytes());
    img[off + 8..off + 12].copy_from_slice(&end.to_le_bytes());
    let digest = cmac::compute_stored_digest(&img, start, end).unwrap();
    img[off + 12..off + 28].copy_from_slice(&digest);
    img
}

/// An image whose integrity table exists but has **no active entry**, so
/// verification produces an empty verdict list. Auto-detection deliberately
/// refuses it, so callers must force the family (the `--family mtk` path).
fn no_active_region_image() -> Vec<u8> {
    let mut img = vec![0u8; 0x20000];
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i * 11 + 5) as u8;
    }
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        for b in &mut img[off..off + cmac::ENTRY_SIZE] {
            *b = 0xFF;
        }
    }
    img
}

/// The committed OEM BU40N 1.00 fixture (third-party firmware kept in-tree for
/// interoperability testing — see `tests/fixtures/README.md`).
fn bu40n_fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("BU40N fixture must be present at {path}: {e}"))
}

#[test]
fn create_diagnoses_legacy_freemkv_input_before_searching_for_oem_handlers() {
    let mut image = bu40n_fixture();
    let engine = engine::mt1959::Mt1959Engine;
    let record = engine
        .find_live_record(&image, abi::READ_BUFFER_OPCODE)
        .unwrap();
    let handler = engine.free_space(&image, 256).unwrap() as usize;
    // Model the reported 0.6.0 input: an injected handler with a literal load
    // instead of the OEM push-lr prologue, and the old embedded identity.
    image[handler..handler + 2].copy_from_slice(&0x4b00u16.to_le_bytes());
    let identity = b"freemkv 0.6.0";
    image[handler + 32..handler + 32 + identity.len()].copy_from_slice(identity);
    image[record.off + 4..record.off + 8].copy_from_slice(&((handler as u32) | 1).to_le_bytes());
    let image = cmac::resign(&image).unwrap();

    let error = match create(&image) {
        Ok(_) => panic!("a legacy freemkv build must not be patched again"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("already contains freemkv firmware"),
        "{error}"
    );
    assert!(error.contains("unmodified OEM image"), "{error}");
    assert!(!error.contains("coherent table"), "{error}");
}

#[test]
fn create_with_defaults_diagnoses_a_previous_production_build() {
    let built = create(&bu40n_fixture()).expect("clean OEM image builds");
    let error = match create_with_defaults(built.image(), &crate::boot::BootSettings::standard()) {
        Ok(_) => panic!("a production freemkv build must not be patched again"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("already contains freemkv firmware"),
        "{error}"
    );
    assert!(error.contains("unmodified OEM image"), "{error}");
}

#[test]
fn verify_reports_ok_only_when_every_active_region_matches() {
    let outcome = verify(&synthetic_image(), None).expect("a well-formed MTK image verifies");
    assert_eq!(outcome.verdicts.len(), 1);
    assert!(
        outcome.ok,
        "an image whose single active region matches must report ok — a \
         wrapper that never says ok makes `verify` useless as a gate"
    );

    let mut img = synthetic_image();
    img[0x1234] ^= 0xFF; // inside the active region
    let outcome = verify(&img, None).expect("still a recognizable MTK image");
    assert!(
        !outcome.ok,
        "a mismatching digest must report NOT ok — a GUI gates a flash on this \
         boolean, and a false ok writes a corrupt image to real hardware"
    );
}

#[test]
fn verify_reports_not_ok_when_the_image_has_no_active_regions() {
    // `all()` over an empty verdict list is vacuously true, so the non-empty
    // check is the only thing standing between "nothing was checked" and
    // "everything passed".
    let outcome = verify(&no_active_region_image(), Some(Family::Mtk))
        .expect("forcing the family skips detection");
    assert!(
        outcome.verdicts.is_empty(),
        "an all-inactive table yields no verdicts"
    );
    assert!(
        !outcome.ok,
        "zero active regions must NOT report ok — an empty verdict list proves \
         nothing about the image and must never pass as a clean verify"
    );
}

#[test]
fn sign_returns_a_self_verifying_image_for_a_normal_image() {
    let mut img = synthetic_image();
    img[0x1500] ^= 0xFF;
    let outcome = sign(&img, None).expect("re-signing a recognizable image must succeed");
    assert_eq!(
        outcome.changes.len(),
        1,
        "exactly the one active region's digest changed"
    );
    assert!(
        verify(&outcome.image, None)
            .expect("signed image verifies")
            .ok,
        "the returned bytes must self-verify — that guarantee is the whole \
         contract of `sign`"
    );
}

#[test]
fn sign_refuses_an_image_with_no_active_regions() {
    assert!(
        sign(&no_active_region_image(), Some(Family::Mtk)).is_err(),
        "re-signing must refuse when the produced image has zero active \
         regions: there is no digest standing behind those bytes, so handing \
         them back as 'signed' is a lie the caller cannot detect"
    );
}

#[test]
fn create_succeeds_on_the_oem_base_and_hands_back_the_report_image() {
    let base = bu40n_fixture();
    let outcome = create(&base).expect("create must succeed on the OEM BU40N base");

    assert_eq!(
        outcome.engine, "MT1959",
        "the engine that actually built the image must be reported"
    );
    assert!(
        !outcome.verdicts.is_empty() && outcome.verdicts.iter().all(|v| v.ok),
        "create refuses to return an image that does not re-verify, so every \
         verdict on a successful build must be OK"
    );
    assert_eq!(
        outcome.image(),
        &outcome.report.image[..],
        "`image()` must expose the report's real bytes — a caller writes \
         exactly these to flash"
    );
    assert_eq!(
        outcome.image().len(),
        base.len(),
        "the built image keeps the OEM image's size"
    );
    assert_ne!(
        outcome.image(),
        &base[..],
        "the built image must actually differ from the OEM input"
    );
}

// UNREACHABLE BRANCH: `create`'s `verdicts.is_empty() || ...` refusal can only
// fire on its right-hand half. Reaching the check at all means `engine::detect`
// accepted the image and the engine re-signed it, so the produced image always
// has at least one active CMAC entry and `MtkCmac::verify` never returns an
// empty list. `||` and `&&` are indistinguishable there for every input the
// engine accepts. The equivalent guard on the `sign` path IS reachable (a
// forced `--family` bypasses detection) and is covered above.
//
// NOT TESTABLE WITHOUT HARDWARE: `probe_device`'s
// `Ok(resp) if abi::verify_response(&resp)` guard — the detected-vs-not
// decision — sits behind `platform::open`, which takes a path and hands back a
// real transport. Without a live drive, or a production seam that accepted an
// injected `ScsiDevice`, no test can reach the guard. Its predicate is covered
// directly by `abi::tests::verify_response_matches_only_the_magic_lead`.

#[test]
fn create_refuses_an_image_no_engine_recognizes() {
    assert!(
        create(&synthetic_image()).is_err(),
        "a synthetic CMAC-only buffer is not a real firmware image; create must \
         refuse it rather than emit something unflashable"
    );
}

#[test]
fn old_modified_table_corruption_is_refused_before_modification() {
    let mut image = include_bytes!("../tests/fixtures/WH16NS58_OEM_1.V9.bin").to_vec();
    let entry = freemkv_flash::cmac::parse_table(&image)
        .unwrap()
        .into_iter()
        .find(|entry| entry.enabled == u32::MAX)
        .unwrap();
    image[entry.entry_off..entry.entry_off + 4].copy_from_slice(&0x02000e41u32.to_le_bytes());
    let image = freemkv_flash::cmac::resign(&image).unwrap();
    assert!(
        freemkv_flash::cmac::verify(&image),
        "the old host MAC check alone misses this corruption"
    );
    assert!(super::modify_with_defaults(&image, &crate::boot::BootSettings::standard()).is_err());
}
