//! Idempotency + structural-audit tests.
//!
//! The synthetic tests run in CI unconditionally. The two heavy gates are
//! env-gated (skip clean when unset), mirroring the KAT hoard tests:
//!   * `FREEMKV_KAT_BASE` → a single OEM BU40N 1.00 image.
//!   * `FREEMKV_OEM_CORPUS` → a directory of OEM `.bin` images (the 63 plaintext
//!     MTK firmwares); every one that modifies must round-trip idempotently and
//!     pass the structural audit.

use super::{audit_image, AuditResult};
use crate::engine::core::is_freemkv_patched;
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
    use thumb_asm as thumb;

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

/// The 9th lever (`Feature::Unrestricted` → auth-cell state-band widen) reports
/// `auth_cell_site` + `auth_cell_stub_va` when wired; the audit's `check_bl`
/// re-derives the expected `bl` and compares it to the bytes at the site. A
/// blank stub at the reported VA must fail the check; a well-formed `bl` +
/// non-blank stub must pass. Without this coverage the whole audit path for
/// the 9th lever runs untested — any regression in `check_bl` wiring would
/// silently emit "audit-green" builds where the widen bl is malformed.
#[test]
fn raw_read_audit_flags_blank_auth_cell_stub() {
    use crate::engine::lever::{LeverId, LeverReport, ModifyReport, Validation};
    use thumb_asm as thumb;

    fn report_with(image: Vec<u8>, lever: LeverReport) -> ModifyReport {
        ModifyReport {
            engine: "MT1959",
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

    // Landed: real bl at site + non-blank stub → passes.
    let mut img = vec![0xFFu8; 0x4000];
    let bl = thumb::encode_bl(site as usize, stub).unwrap();
    thumb::write(&mut img, site as usize, &bl);
    thumb::write(&mut img, stub as usize, &[0x11u8; 16]);
    let orig = img.clone();
    let landed = report_with(
        img,
        LeverReport::applied(
            LeverId::RawRead,
            vec![
                ("auth_cell_site", site),
                ("auth_cell_stub_va", stub),
                // The lever's audit-guard requires SOME other detour proof too.
                ("gatea_gate", 0x0800),
                ("gatea_stub_va", 0x0900),
            ],
        ),
    );
    let mut img2 = landed.image.clone();
    let bl_g = thumb::encode_bl(0x0800usize, 0x0900).unwrap();
    thumb::write(&mut img2, 0x0800, &bl_g);
    thumb::write(&mut img2, 0x0900, &[0x22u8; 16]);
    let landed = ModifyReport {
        image: img2,
        ..landed
    };
    assert!(
        rr_check(&audit_image(&orig, &landed), "auth-cell widen detour bl").ok,
        "landed auth-cell bl must pass"
    );

    // Blank stub at the reported VA → fails.
    let mut img = vec![0xFFu8; 0x4000];
    thumb::write(&mut img, site as usize, &bl); // stub left blank
    let orig = img.clone();
    let blank = report_with(
        img,
        LeverReport::applied(
            LeverId::RawRead,
            vec![("auth_cell_site", site), ("auth_cell_stub_va", stub)],
        ),
    );
    assert!(
        !rr_check(&audit_image(&orig, &blank), "auth-cell widen detour bl").ok,
        "blank auth-cell stub must fail"
    );
}

/// Synthetic negative case for the Identity lever's Reboot boot-function-entry
/// literal check: with a well-formed handler region (RESP_MAGIC present, record
/// repointed) plus the Thumb-tagged entry literal baked in, the check passes;
/// blanking the literal in the handler region flips the check to FAIL while
/// leaving the RESP_MAGIC / record-repoint checks passing. This is the
/// negative gate that closes the Reboot-arm-inert failure mode without
/// requiring the KAT base to be present.
#[test]
fn identity_audit_flags_missing_reboot_literal() {
    use crate::engine::lever::{LeverId, LeverReport, ModifyReport, Validation};

    fn report_with(image: Vec<u8>, lever: LeverReport) -> ModifyReport {
        ModifyReport {
            engine: "MT1959",
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
    fn id_check<'a>(a: &'a AuditResult, what: &str) -> &'a crate::engine::audit::AuditCheck {
        a.checks
            .iter()
            .find(|c| c.lever == "Identity" && c.what == what)
            .unwrap_or_else(|| panic!("no Identity check {what:?}"))
    }

    let handler_va = 0x0000_1000u32;
    let record_off = 0x0000_2000u32;
    // BU40N 1.00: boot_init_site - 0x10 = 0x0013D428 - 0x10 = 0x0013D418.
    let boot_entry = 0x0013_D418u32;

    // --- landed: RESP_MAGIC in handler, record repointed, literal baked.
    let mut img = vec![0xFFu8; 0x4000];
    // Record: keep flags at record_off+1 untouched (audit only reads the handler
    // pointer at record_off+4..+8); write handler_va|1 there.
    img[record_off as usize + 4..record_off as usize + 8]
        .copy_from_slice(&(handler_va | 1).to_le_bytes());
    // Handler bytes: place RESP_MAGIC + a Thumb-tagged boot_entry literal near the
    // start of the handler window (well within the +0x1000 scan).
    let ha = handler_va as usize;
    img[ha..ha + 7].copy_from_slice(crate::abi::RESP_MAGIC);
    img[ha + 8..ha + 12].copy_from_slice(&(boot_entry | 1).to_le_bytes());

    let baked = report_with(
        img.clone(),
        LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record_off),
                ("boot_function_entry", boot_entry),
            ],
        ),
    );
    let a = audit_image(&img, &baked);
    assert!(
        id_check(&a, "record repointed to injected handler").ok,
        "record repoint must pass in the well-formed baseline"
    );
    assert!(
        id_check(&a, "handler injected (RESP_MAGIC present)").ok,
        "RESP_MAGIC + non-blank handler must pass in the baseline"
    );
    assert!(
        id_check(&a, "Reboot boot-function-entry literal baked").ok,
        "baked Thumb-tagged entry literal must pass the check"
    );

    // --- Reboot literal blanked in the handler region: everything else stays
    // passing, only the Reboot-literal check flips to FAIL. The audit must not
    // silently accept a Reboot arm that dispatches but never invokes the boot
    // function, so this negative case is the load-bearing guard.
    let mut mutated = img.clone();
    mutated[ha + 8..ha + 12].fill(0xFF);
    let blanked = report_with(
        mutated,
        LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record_off),
                ("boot_function_entry", boot_entry),
            ],
        ),
    );
    let a = audit_image(&img, &blanked);
    assert!(
        id_check(&a, "record repointed to injected handler").ok,
        "record repoint still passes after literal mutation"
    );
    assert!(
        id_check(&a, "handler injected (RESP_MAGIC present)").ok,
        "RESP_MAGIC still present after literal mutation"
    );
    assert!(
        !id_check(&a, "Reboot boot-function-entry literal baked").ok,
        "missing Thumb-tagged entry literal must fail the check"
    );

    // --- boot_function_entry == 0 (classic geometry): the Reboot check is
    // intentionally NOT emitted at all, because the arm ships inert on classic.
    let inert = report_with(
        img,
        LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record_off),
                ("boot_function_entry", 0),
            ],
        ),
    );
    let a = audit_image(&vec![0xFFu8; 0x4000], &inert);
    assert!(
        !a.checks
            .iter()
            .any(|c| c.lever == "Identity" && c.what == "Reboot boot-function-entry literal baked"),
        "boot_function_entry == 0 emits no Reboot-literal check (classic geometry)"
    );
}

// ---------------------------------------------------------------------------
// Whole-image synthetic fixtures.
//
// The corpus/KAT gates above are env-gated, so without a hoard the audit was
// only ever exercised on tiny buffers whose CMAC check can never pass — i.e. it
// was never observed in its *passing* state. These fixtures build a 2 MiB image
// with a real, re-signed CMAC table, land every lever's detour in it, and then
// corrupt exactly one thing per test. That is the only shape that proves a check
// is a check: an audit that can only ever fail proves as little as one that can
// only ever pass.
// ---------------------------------------------------------------------------

use crate::engine::audit::AuditCheck;
use crate::engine::lever::{LeverId, LeverReport, ModifyReport, Validation};
use thumb_asm as thumb;

/// Synthetic image size — the real MTK part size, and comfortably past the
/// integrity table at `0x10400`.
const IMG_LEN: usize = 0x20_0000;

// Addresses for the "everything landed" fixture. All sit well clear of the
// CMAC table (`0x10400..0x105C0`) and of each other.
const HANDLER_VA: u32 = 0x0003_0000;
const RECORD_OFF: u32 = 0x0004_0000;
const BOOT_ENTRY: u32 = 0x0005_0000;
const SPEED_GATE: u32 = 0x0006_0000;
const SPEED_STUB: u32 = 0x0007_0000;
const REGION_EMITTER: u32 = 0x0008_0000;
const REGION_STUB: u32 = 0x0009_0000;
const AKE_SITE: u32 = 0x000A_0000;
const AKE_STUB: u32 = 0x000B_0000;
const GATEA_SITE: u32 = 0x000C_0000;
const GATEA_STUB: u32 = 0x000D_0000;
const DENY_BLOCK: u32 = 0x000E_0000;
const DE_OFF: u32 = 0x000F_0000;
/// The one runtime-RAM cell the clear-VID scratch must be.
const SCRATCH: u32 = 0x0021_0c00;

/// Erased-flash canvas.
fn blank() -> Vec<u8> {
    vec![0xFFu8; IMG_LEN]
}

/// Install a real, re-signed CMAC table covering everything above the table so
/// `cmac::verify` returns true on the result. The covered range deliberately
/// starts past the table itself: a self-covering entry could never round-trip.
fn signed(mut img: Vec<u8>) -> Vec<u8> {
    for i in 0..cmac::ENTRY_COUNT {
        let e = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        img[e..e + cmac::ENTRY_SIZE].fill(0xFF);
    }
    let e = cmac::TABLE_OFFSET;
    img[e..e + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[e + 4..e + 8].copy_from_slice(&0x0001_1000u32.to_le_bytes());
    img[e + 8..e + 12].copy_from_slice(&((IMG_LEN - 1) as u32).to_le_bytes());
    let out = cmac::resign(&img).expect("re-sign the synthetic image");
    assert!(cmac::verify(&out), "synthetic fixture must self-verify");
    out
}

/// Mark 16 bytes at `va` as a written (non-blank) stub.
fn write_stub(img: &mut [u8], va: u32) {
    thumb::write(img, va as usize, &[0x01u8; 16]);
}

fn install_bl(img: &mut [u8], site: u32, stub: u32) {
    let bl = thumb::encode_bl(site as usize, stub).expect("bl in range");
    thumb::write(img, site as usize, &bl);
}

fn install_bw(img: &mut [u8], site: u32, stub: u32) {
    let bw = thumb::encode_b_wide(site as usize, stub).expect("b.w in range");
    thumb::write(img, site as usize, &bw);
}

fn report_of(image: Vec<u8>, levers: Vec<LeverReport>) -> ModifyReport {
    ModifyReport {
        engine: "MT1959",
        family: "f".into(),
        vendor: "v".into(),
        model: "m".into(),
        rev: "r".into(),
        vendor_specific: String::new(),
        media: "BD".into(),
        levers,
        image,
        validation: Validation::StaticOnly,
    }
}

/// One lever's report, Applied with the given facts.
fn applied(id: LeverId, facts: Vec<(&'static str, u32)>) -> LeverReport {
    LeverReport::applied(id, facts)
}

/// The named check, cloned so callers can pass a temporary `AuditResult`.
fn find(a: &AuditResult, lever: &str, what: &str) -> AuditCheck {
    a.checks
        .iter()
        .find(|c| c.lever == lever && c.what == what)
        .unwrap_or_else(|| {
            panic!(
                "no [{lever}] {what:?} check; got {:?}",
                a.checks
                    .iter()
                    .map(|c| (c.lever, c.what.as_str()))
                    .collect::<Vec<_>>()
            )
        })
        .clone()
}

/// Every lever's detour landed correctly in a self-verifying image.
fn fully_landed() -> (Vec<u8>, ModifyReport) {
    let mut img = blank();
    for stub in [HANDLER_VA, SPEED_STUB, REGION_STUB, AKE_STUB, GATEA_STUB] {
        write_stub(&mut img, stub);
    }
    let ha = HANDLER_VA as usize;
    img[ha..ha + crate::abi::RESP_MAGIC.len()].copy_from_slice(crate::abi::RESP_MAGIC);
    img[ha + 8..ha + 12].copy_from_slice(&(BOOT_ENTRY | 1).to_le_bytes());
    let ro = RECORD_OFF as usize;
    img[ro + 4..ro + 8].copy_from_slice(&(HANDLER_VA | 1).to_le_bytes());
    install_bl(&mut img, SPEED_GATE + 4, SPEED_STUB);
    install_bl(&mut img, REGION_EMITTER + 6, REGION_STUB);
    install_bw(&mut img, AKE_SITE, AKE_STUB);
    install_bl(&mut img, GATEA_SITE, GATEA_STUB);
    img[DE_OFF as usize] = 0xDE;
    let img = signed(img);
    let original = img.clone(); // the deny block is untouched by construction
    let levers = vec![
        applied(
            LeverId::Identity,
            vec![
                ("handler_va", HANDLER_VA),
                ("record_off", RECORD_OFF),
                ("boot_function_entry", BOOT_ENTRY),
            ],
        ),
        applied(
            LeverId::Speed,
            vec![("speed_gate", SPEED_GATE), ("speed_stub_va", SPEED_STUB)],
        ),
        applied(
            LeverId::RegionFree,
            vec![
                ("region_emitter", REGION_EMITTER),
                ("region_stub_va", REGION_STUB),
            ],
        ),
        applied(
            LeverId::RawRead,
            vec![
                ("ake_site", AKE_SITE),
                ("ake_stub_va", AKE_STUB),
                ("gatea_gate", GATEA_SITE),
                ("gatea_stub_va", GATEA_STUB),
                ("deny", DENY_BLOCK),
                ("scratch", SCRATCH),
            ],
        ),
        applied(LeverId::DowngradeEnable, vec![("de_off", DE_OFF)]),
    ];
    (original, report_of(img, levers))
}

/// The baseline every negative case below is measured against: a correctly
/// built image passes EVERY check, `ok()` is true, and `failures()` is empty.
/// Without this the whole audit could be a tautology in the other direction
/// (always-fail proves nothing either) — and it is what makes a one-check
/// regression in any test below unambiguous.
#[test]
fn a_fully_landed_synthetic_image_passes_every_structural_audit_check() {
    let (original, report) = fully_landed();
    let a = audit_image(&original, &report);
    assert!(
        a.ok(),
        "a correctly built image must pass the structural audit:\n{}",
        fmt_failures(&a)
    );
    assert_eq!(
        a.failures().count(),
        0,
        "failures() must list the FAILING checks, and there are none here"
    );
    // Each lever's check must actually have been emitted — a silently absent
    // check is indistinguishable from a passing one in `ok()` alone.
    for (lever, what) in [
        ("Identity", "record repointed to injected handler"),
        ("Identity", "handler injected (RESP_MAGIC present)"),
        ("Identity", "Reboot boot-function-entry literal baked"),
        ("Speed", "speed detour bl"),
        ("Region Free", "region detour bl"),
        ("Raw read", "AKE detour branch"),
        ("Raw read", "Gate-A detour bl"),
        ("Raw read", "deny block byte-identical to OEM"),
        ("Raw read", "scratch buffer in runtime RAM window"),
        ("Downgrade (DE)", "DE byte set"),
        ("integrity", "CMAC tables verify"),
    ] {
        assert!(find(&a, lever, what).ok, "[{lever}] {what} must pass");
    }
    assert_eq!(
        a.checks.len(),
        11,
        "no check silently dropped or duplicated"
    );
    // The AKE install here is a `B.W`; the detail must say so, because that
    // string is how a failing audit tells an operator which shape it saw.
    assert!(
        find(&a, "Raw read", "AKE detour branch")
            .detail
            .contains("(b.w)"),
        "a B.W install must be reported as b.w, got: {}",
        find(&a, "Raw read", "AKE detour branch").detail
    );
}

/// The catastrophic case, stated directly: corrupt ONE byte inside a
/// CMAC-covered region and the audit must go red. It is also the only place
/// `failures()` is pinned to a single, named entry — an audit that reports the
/// wrong set of failures sends the operator to the wrong place.
#[test]
fn flipping_one_covered_byte_fails_only_the_integrity_check() {
    let (original, mut report) = fully_landed();
    report.image[0x0001_8000] ^= 0xFF; // covered by the table, no lever's site
    let a = audit_image(&original, &report);
    assert!(
        !a.ok(),
        "the audit MUST NOT pass on an image whose CMAC no longer verifies — \
         the drive recomputes it at boot and refuses to run"
    );
    let failures: Vec<_> = a.failures().collect();
    assert_eq!(
        failures.len(),
        1,
        "exactly one check should fail, got: {}",
        fmt_failures(&a)
    );
    assert_eq!(failures[0].lever, "integrity");
    assert_eq!(failures[0].what, "CMAC tables verify");
}

/// `stub_present` is bounds-guarded with `va + 16 <= len`. A stub whose 16-byte
/// window runs off the end of the image is NOT present, and saying so must not
/// panic: the audit runs on whatever the emitter recorded, and a panicking audit
/// is an audit that never renders a verdict at all.
#[test]
fn a_stub_that_runs_off_the_end_of_the_image_is_not_present() {
    let mut img = blank();
    let stub = (IMG_LEN - 8) as u32; // only 8 bytes left: cannot hold a stub
    write_stub(&mut img, IMG_LEN as u32 - 8 - 8); // non-blank bytes just before
    install_bl(&mut img, SPEED_GATE + 4, stub);
    let report = report_of(
        img,
        vec![applied(
            LeverId::Speed,
            vec![("speed_gate", SPEED_GATE), ("speed_stub_va", stub)],
        )],
    );
    let c = find(&audit_image(&blank(), &report), "Speed", "speed detour bl");
    assert!(
        !c.ok,
        "a stub window past the end of the image cannot hold a stub: {}",
        c.detail
    );
}

/// The AKE arm accepts EITHER a wide `B.W` (tail-call install) or a wide `BL`
/// (shared-call install). Both shapes must pass and be named correctly — if the
/// `BL` arm stopped matching, every NB-class build would audit red, and an
/// operator would re-flash chasing a bug that is not there.
#[test]
fn the_ake_detour_check_accepts_a_wide_bl_install_and_names_it() {
    let mut img = blank();
    write_stub(&mut img, AKE_STUB);
    install_bl(&mut img, AKE_SITE, AKE_STUB); // BL, not B.W
    let report = report_of(
        img,
        vec![applied(
            LeverId::RawRead,
            vec![("ake_site", AKE_SITE), ("ake_stub_va", AKE_STUB)],
        )],
    );
    let c = find(
        &audit_image(&blank(), &report),
        "Raw read",
        "AKE detour branch",
    );
    assert!(
        c.ok,
        "a wide BL to the AKE stub is a valid install: {}",
        c.detail
    );
    assert!(
        c.detail.contains("(bl)"),
        "a BL install must be reported as bl, got: {}",
        c.detail
    );
}

/// The AKE branch decoding correctly is NOT enough: the stub it reaches must
/// have been written. A branch into erased flash (`0xFF…`) executes garbage on
/// the drive, so "branch present, stub blank" must be a FAILURE, never a pass.
#[test]
fn an_ake_branch_into_a_blank_stub_fails_the_audit() {
    let mut img = blank();
    install_bw(&mut img, AKE_SITE, AKE_STUB); // stub deliberately left erased
    let report = report_of(
        img,
        vec![applied(
            LeverId::RawRead,
            vec![("ake_site", AKE_SITE), ("ake_stub_va", AKE_STUB)],
        )],
    );
    let c = find(
        &audit_image(&blank(), &report),
        "Raw read",
        "AKE detour branch",
    );
    assert!(!c.ok, "a branch into erased flash must fail: {}", c.detail);
    assert!(
        c.detail.contains("blank"),
        "the detail must name the blank stub, got: {}",
        c.detail
    );
}

/// An AKE hook site whose 4 bytes straddle the end of the image cannot hold a
/// branch: the check must fail cleanly (and must not read past the buffer).
#[test]
fn an_ake_hook_site_straddling_the_image_end_fails_without_reading_past_it() {
    let mut img = blank();
    write_stub(&mut img, AKE_STUB);
    let site = (IMG_LEN - 2) as u32;
    let report = report_of(
        img,
        vec![applied(
            LeverId::RawRead,
            vec![("ake_site", site), ("ake_stub_va", AKE_STUB)],
        )],
    );
    let c = find(
        &audit_image(&blank(), &report),
        "Raw read",
        "AKE detour branch",
    );
    assert!(!c.ok, "a 2-byte tail cannot hold a 4-byte branch");
    assert!(c.detail.contains("past end of image"), "got: {}", c.detail);
}

/// The converse bound: a hook site occupying the LAST four bytes of the image is
/// entirely in range and must pass. Rejecting it (an off-by-one, or a bound
/// computed by scaling the offset instead of adding to it) would fail a
/// perfectly good image and send an operator chasing a phantom.
#[test]
fn an_ake_hook_site_at_the_final_four_bytes_of_the_image_passes() {
    let mut img = blank();
    write_stub(&mut img, AKE_STUB);
    let site = (IMG_LEN - 4) as u32;
    install_bw(&mut img, site, AKE_STUB);
    let report = report_of(
        img,
        vec![applied(
            LeverId::RawRead,
            vec![("ake_site", site), ("ake_stub_va", AKE_STUB)],
        )],
    );
    let c = find(
        &audit_image(&blank(), &report),
        "Raw read",
        "AKE detour branch",
    );
    assert!(
        c.ok,
        "site..site+4 == image end is in bounds and must pass: {}",
        c.detail
    );
}

/// Same two bounds for the plain-`bl` branch checker (`check_branch_impl`),
/// which every non-AKE detour goes through.
#[test]
fn a_bl_hook_site_straddling_the_image_end_fails_without_reading_past_it() {
    let mut img = blank();
    write_stub(&mut img, SPEED_STUB);
    let gate = (IMG_LEN - 6) as u32; // hook site is gate+4 → two bytes short
    let report = report_of(
        img,
        vec![applied(
            LeverId::Speed,
            vec![("speed_gate", gate), ("speed_stub_va", SPEED_STUB)],
        )],
    );
    let c = find(&audit_image(&blank(), &report), "Speed", "speed detour bl");
    assert!(!c.ok, "a 2-byte tail cannot hold a 4-byte bl");
    assert!(c.detail.contains("past end of image"), "got: {}", c.detail);
}

#[test]
fn a_bl_hook_site_at_the_final_four_bytes_of_the_image_passes() {
    let mut img = blank();
    write_stub(&mut img, SPEED_STUB);
    let gate = (IMG_LEN - 8) as u32; // hook site is gate+4 == len-4
    install_bl(&mut img, gate + 4, SPEED_STUB);
    let report = report_of(
        img,
        vec![applied(
            LeverId::Speed,
            vec![("speed_gate", gate), ("speed_stub_va", SPEED_STUB)],
        )],
    );
    let c = find(&audit_image(&blank(), &report), "Speed", "speed detour bl");
    assert!(
        c.ok,
        "site..site+4 == image end is in bounds and must pass: {}",
        c.detail
    );
}

/// The emitter writes the speed `bl` at `speed_gate + 4` and the region `bl` at
/// `region_emitter + 6` — the hook sites, not the anchors. The audit must look
/// at exactly those offsets: checking the anchor instead would pass on an image
/// where the branch never landed, which is the whole failure mode this audit
/// exists to catch.
#[test]
fn the_speed_and_region_detours_are_checked_at_their_real_hook_offsets() {
    for (id, anchor_key, stub_key, anchor, stub, delta, what) in [
        (
            LeverId::Speed,
            "speed_gate",
            "speed_stub_va",
            SPEED_GATE,
            SPEED_STUB,
            4u32,
            "speed detour bl",
        ),
        (
            LeverId::RegionFree,
            "region_emitter",
            "region_stub_va",
            REGION_EMITTER,
            REGION_STUB,
            6u32,
            "region detour bl",
        ),
    ] {
        let lever = id.label();
        // Landed at anchor+delta → passes.
        let mut img = blank();
        write_stub(&mut img, stub);
        install_bl(&mut img, anchor + delta, stub);
        let r = report_of(
            img,
            vec![applied(id, vec![(anchor_key, anchor), (stub_key, stub)])],
        );
        let c = find(&audit_image(&blank(), &r), lever, what);
        assert!(
            c.ok,
            "[{lever}] bl at anchor+{delta} must pass: {}",
            c.detail
        );

        // The SAME bl written at the anchor itself must NOT satisfy the check:
        // the hook site is anchor+{delta} and nowhere else.
        let mut img = blank();
        write_stub(&mut img, stub);
        install_bl(&mut img, anchor, stub);
        let r = report_of(
            img,
            vec![applied(id, vec![(anchor_key, anchor), (stub_key, stub)])],
        );
        let c = find(&audit_image(&blank(), &r), lever, what);
        assert!(
            !c.ok,
            "[{lever}] a bl at the anchor is not a bl at the hook site (anchor+{delta}): {}",
            c.detail
        );
    }
}

/// The handler pointer the audit expects is `handler_va | 1` — the Thumb bit
/// SET, never toggled. The distinction only shows on an already-odd address, so
/// pin it there: a toggle would silently expect `va - 1` for any fact that
/// already carried the Thumb bit, and accept a record pointing one byte low.
/// The same holds for the Reboot literal (`boot_function_entry | 1`).
#[test]
fn thumb_tagging_sets_the_low_bit_rather_than_toggling_it() {
    let handler_va = HANDLER_VA | 1;
    let boot_entry = BOOT_ENTRY | 1;
    let mut img = blank();
    write_stub(&mut img, handler_va);
    let ha = handler_va as usize;
    img[ha..ha + crate::abi::RESP_MAGIC.len()].copy_from_slice(crate::abi::RESP_MAGIC);
    img[ha + 8..ha + 12].copy_from_slice(&(boot_entry | 1).to_le_bytes());
    let ro = RECORD_OFF as usize;
    img[ro + 4..ro + 8].copy_from_slice(&(handler_va | 1).to_le_bytes());
    let r = report_of(
        img,
        vec![applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", RECORD_OFF),
                ("boot_function_entry", boot_entry),
            ],
        )],
    );
    let a = audit_image(&blank(), &r);
    let c = find(&a, "Identity", "record repointed to injected handler");
    assert!(
        c.ok,
        "an already-Thumb-tagged handler_va must still match VA|1: {}",
        c.detail
    );
    let c = find(&a, "Identity", "Reboot boot-function-entry literal baked");
    assert!(
        c.ok,
        "an already-Thumb-tagged boot entry must still match entry|1: {}",
        c.detail
    );
}

/// A record offset whose handler pointer would be read past the end of the
/// image is unreadable, so the repoint is unproven and the check must FAIL —
/// bounds-guarded, without panicking.
#[test]
fn an_identity_record_offset_past_the_image_end_fails_without_panicking() {
    let mut img = blank();
    write_stub(&mut img, HANDLER_VA);
    img[HANDLER_VA as usize..HANDLER_VA as usize + crate::abi::RESP_MAGIC.len()]
        .copy_from_slice(crate::abi::RESP_MAGIC);
    let record_off = (IMG_LEN - 4) as u32;
    let r = report_of(
        img,
        vec![applied(
            LeverId::Identity,
            vec![("handler_va", HANDLER_VA), ("record_off", record_off)],
        )],
    );
    let c = find(
        &audit_image(&blank(), &r),
        "Identity",
        "record repointed to injected handler",
    );
    assert!(
        !c.ok,
        "an unreadable record pointer proves nothing and must fail: {}",
        c.detail
    );
}

/// RESP_MAGIC appearing SOMEWHERE in the image does not prove a handler landed
/// AT `handler_va`: a re-fed image carries the magic already. Both halves are
/// required, so magic-present + blank-handler must fail. This is the clearest
/// "check that stopped checking" shape in the whole audit.
#[test]
fn resp_magic_elsewhere_does_not_excuse_a_blank_handler() {
    let mut img = blank();
    img[0x0002_0000..0x0002_0000 + crate::abi::RESP_MAGIC.len()]
        .copy_from_slice(crate::abi::RESP_MAGIC);
    let ro = RECORD_OFF as usize;
    img[ro + 4..ro + 8].copy_from_slice(&(HANDLER_VA | 1).to_le_bytes());
    assert!(
        is_freemkv_patched(&img),
        "fixture does carry RESP_MAGIC somewhere"
    );
    let r = report_of(
        img,
        vec![applied(
            LeverId::Identity,
            vec![("handler_va", HANDLER_VA), ("record_off", RECORD_OFF)],
        )],
    );
    let a = audit_image(&blank(), &r);
    assert!(
        find(&a, "Identity", "record repointed to injected handler").ok,
        "the repoint itself is fine in this fixture"
    );
    assert!(
        !find(&a, "Identity", "handler injected (RESP_MAGIC present)").ok,
        "RESP_MAGIC elsewhere must not certify a handler_va that is erased flash"
    );
}

/// Classic emits NO deny detour: the 0x40-byte deny block must be byte-identical
/// to OEM, because a wrong reply desyncs the SCSI FIFO. A modified deny block
/// must therefore FAIL — and the length guards around that comparison must hold
/// on both sides, so an image that is genuinely identical still passes.
#[test]
fn a_modified_deny_block_fails_the_byte_identical_check() {
    let build = |mutate: bool| {
        let mut img = blank();
        write_stub(&mut img, GATEA_STUB);
        install_bl(&mut img, GATEA_SITE, GATEA_STUB);
        let original = img.clone();
        if mutate {
            img[DENY_BLOCK as usize + 0x10] ^= 0xFF;
        }
        let r = report_of(
            img,
            vec![applied(
                LeverId::RawRead,
                vec![
                    ("gatea_gate", GATEA_SITE),
                    ("gatea_stub_va", GATEA_STUB),
                    ("deny", DENY_BLOCK),
                ],
            )],
        );
        audit_image(&original, &r)
    };
    assert!(
        find(
            &build(false),
            "Raw read",
            "deny block byte-identical to OEM"
        )
        .ok,
        "an untouched deny block must pass"
    );
    let a = build(true);
    let c = find(&a, "Raw read", "deny block byte-identical to OEM");
    assert!(
        !c.ok,
        "one changed byte in the deny block must fail the audit — a wrong deny \
         reply desyncs the drive's SCSI FIFO"
    );
    assert!(
        find(&a, "Raw read", "Gate-A detour bl").ok,
        "only the deny check may flip; the detour is untouched"
    );
}

/// The deny comparison is bounds-guarded by ADDING 0x40 to the address. A deny
/// address closer to the image start than 0x40 must still be handled — the audit
/// never gets to choose its inputs, and a panic here means no verdict at all.
#[test]
fn a_deny_address_near_the_image_start_is_handled_without_panicking() {
    let deny = 0x20u32; // < 0x40: any subtraction here would underflow
    let img = blank();
    let original = img.clone();
    let r = report_of(
        img,
        vec![applied(
            LeverId::RawRead,
            vec![
                ("gatea_gate", GATEA_SITE),
                ("gatea_stub_va", GATEA_STUB),
                ("deny", deny),
            ],
        )],
    );
    let c = find(
        &audit_image(&original, &r),
        "Raw read",
        "deny block byte-identical to OEM",
    );
    assert!(
        c.ok,
        "deny at 0x20..0x60 is fully in bounds and identical: {}",
        c.detail
    );
}

/// The DE check is `de_off in bounds AND the byte there is 0xDE`. Both halves
/// are load-bearing: a DE byte that was never written must fail, and an offset
/// that is exactly the image length must fail cleanly rather than index past the
/// buffer.
#[test]
fn the_de_check_requires_an_in_bounds_offset_holding_0xde() {
    let de_report = |img: Vec<u8>, de_off: u32| {
        report_of(
            img,
            vec![applied(LeverId::DowngradeEnable, vec![("de_off", de_off)])],
        )
    };
    // Landed.
    let mut img = blank();
    img[DE_OFF as usize] = 0xDE;
    let c = find(
        &audit_image(&blank(), &de_report(img, DE_OFF)),
        "Downgrade (DE)",
        "DE byte set",
    );
    assert!(c.ok, "0xDE at the recorded offset must pass: {}", c.detail);

    // Never written: the byte is still erased flash.
    let c = find(
        &audit_image(&blank(), &de_report(blank(), DE_OFF)),
        "Downgrade (DE)",
        "DE byte set",
    );
    assert!(
        !c.ok,
        "an unwritten DE byte must fail — the lever claimed Applied: {}",
        c.detail
    );

    // Offset exactly at the image length: out of bounds, must not index.
    let c = find(
        &audit_image(&blank(), &de_report(blank(), IMG_LEN as u32)),
        "Downgrade (DE)",
        "DE byte set",
    );
    assert!(
        !c.ok,
        "de_off == image.len() is one past the last byte and must fail: {}",
        c.detail
    );
}

// EQUIVALENT MUTANT (documented, not chased):
//
// `audit_image`'s Reboot-literal window guard `if start < end { … } else { false }`
// admits `<` → `<=`. `end` is `start.saturating_add(0x1000).min(img.len())`, so
// `start == end` is only reachable when `start == img.len()`; the mutant then
// scans the EMPTY slice `img[start..end]`, whose `windows(4)` yields nothing, so
// `found` is `false` — exactly what the `else` arm produces. No input
// distinguishes them.

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
