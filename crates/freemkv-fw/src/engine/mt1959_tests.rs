//! MT1959 build-path tests — the refusals, the graceful-degrade boundary, and
//! the arithmetic that decides *where* a detour lands.
//!
//! Everything here runs against the committed OEM BU40N 1.00 fixture, usually a
//! deliberately *damaged* copy of it: the point of each test is that the build
//! either refuses (fail-closed) or lands a detour at the one address that is
//! correct. An image that flashes with a mis-computed detour target is a bricked
//! drive, so "it still produced an image" is never a pass here.

use super::*;

use crate::engine::lever::{LeverOutcome, LeverReport};
use crate::family::MediaClass;

#[test]
fn uh12_oem_allocation_failure_builds_through_the_normal_modify_api() {
    use sha2::{Digest, Sha256};
    let original = include_bytes!("../../tests/fixtures/UH12NS40_OEM_1.03.bin");
    assert_eq!(
        format!("{:x}", Sha256::digest(original)),
        "eeb1c948f1ed98245b7d21d03fe5e333a3349d28453690e2a60b4a8dc01765ba"
    );
    assert!(
        Mt1959Engine.modify(original).is_err(),
        "original covered holes cannot fit the handler"
    );
    let (report, support) =
        crate::api::modify_with_defaults(original, &crate::boot::BootSettings::standard()).unwrap();
    for id in [
        LeverId::Identity,
        LeverId::Speed,
        LeverId::RegionFree,
        LeverId::RawRead,
        LeverId::BootSettings,
    ] {
        assert!(
            report
                .levers
                .iter()
                .any(|p| p.id == id && p.outcome == LeverOutcome::Applied),
            "{id:?}"
        );
    }
    assert!(crate::boot::BootFeature::ALL
        .iter()
        .all(|f| support.supports(*f)));
    assert!(
        support.supports_value(crate::boot::BootFeature::Unrestricted, 0),
        "the emitted three-way auth hook must expose native refusal"
    );
    assert!(freemkv_flash::cmac::verify(&report.image));
    assert!(crate::engine::code_space::metadata_preserved(
        original,
        &report.image
    ));
    let audit = crate::engine::audit::audit_image(original, &report);
    assert!(audit.ok(), "{audit:#?}");
    let old = freemkv_flash::cmac::parse_table(original).unwrap();
    let new = freemkv_flash::cmac::parse_table(&report.image).unwrap();
    for (before, after) in old.iter().zip(&new) {
        assert_eq!(before.enabled, after.enabled);
        assert_eq!(before.start, after.start);
        assert_eq!(
            after.end,
            if before.index == 2 {
                0x1b801f
            } else {
                before.end
            }
        );
    }
    let mut unplanned = report.image.clone();
    unplanned[freemkv_flash::cmac::TABLE_OFFSET + 4] ^= 0x10;
    let unplanned = freemkv_flash::cmac::resign(&unplanned).unwrap();
    assert!(freemkv_flash::cmac::verify(&unplanned));
    assert!(!crate::engine::code_space::metadata_preserved(
        original, &unplanned
    ));
}

#[test]
fn uh12_coverage_retry_refuses_changed_receiver_contracts_even_when_resigned() {
    let original = include_bytes!("../../tests/fixtures/UH12NS40_OEM_1.03.bin");
    for address in [
        0xa7942, 0x17c576, 0x1746e, 0x17c0f0, 0x17c308, 0x17fa8, 0x18070,
    ] {
        let mut changed = original.to_vec();
        changed[address] ^= 1;
        let changed = freemkv_flash::cmac::resign(&changed).unwrap();
        assert!(freemkv_flash::cmac::verify(&changed));
        assert!(
            crate::engine::code_space::coverage_retry(&changed).is_none(),
            "{address:#x}"
        );
    }
}

#[test]
fn allocation_retry_honors_explicit_settings_after_partial_first_pass() {
    let original = include_bytes!("../../tests/fixtures/WH14NS40_OEM_1.05.bin");
    let defaults = crate::boot::BootSettings::parse(&[
        "region=free".into(),
        "speed=uncapped".into(),
        "hrl=off".into(),
        "encryption=off".into(),
    ])
    .unwrap();
    let (report, _) = crate::api::modify_with_defaults(original, &defaults).unwrap();
    let (saved, _) = crate::boot::inspect(&report.image).unwrap().unwrap();
    for feature in crate::boot::BootFeature::ALL {
        assert_eq!(saved.value(feature), defaults.value(feature));
    }
    assert!(crate::engine::audit::audit_image(original, &report).ok());
    assert!(freemkv_flash::cmac::verify(&report.image));
}

fn fixture() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    );
    std::fs::read(p).expect("committed BU40N OEM fixture")
}

#[test]
fn wh_descriptor_auth_cell_is_selected_from_vid_success_not_the_later_state_check() {
    let image = include_bytes!("../../tests/fixtures/WH16NS58_OEM_1.V9.bin");
    let (site, _) = Mt1959Engine
        .auth_cell_widen_detour(image, FLAG_TABLE_BASE)
        .expect("WH VID preparation has a supported state-band contract");
    assert_eq!(site, 0x13aa96);
    assert_ne!(site, 0x13ac68, "the later check has a different role");
}

/// The fixture's own detected chip identity (so `build_modify` sees the real
/// vendor/model strings and only the capability under test is synthetic).
fn bu40n_chip() -> ChipInfo {
    family::detect_chip(&fixture()).expect("fixture is a detectable MT1959 image")
}

fn cap(media_class: MediaClass, bd_aacs: bool, region_lockable: bool) -> Capability {
    Capability {
        family: crate::family::ChipFamily::Mt1959,
        media_class,
        bd_aacs,
        region_lockable,
    }
}

fn lever(r: &ModifyReport, id: LeverId) -> &LeverReport {
    r.levers
        .iter()
        .find(|l| l.id == id)
        .unwrap_or_else(|| panic!("report is missing the {:?} lever entirely", id))
}

fn fact(l: &LeverReport, key: &str) -> Option<u32> {
    l.facts.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Require a build step to refuse, and hand back the message it refused with.
/// (`unwrap_err` would need `Debug` on the success type; these are emit payloads
/// that deliberately don't carry one.)
#[track_caller]
fn refusal<T>(r: Result<T>, must_refuse: &str) -> String {
    match r {
        Ok(_) => panic!("expected a refusal: {must_refuse}"),
        Err(e) => format!("{e:#}"),
    }
}

// ---------------------------------------------------------------------------
// Capability gate for the Speed lever (`media_class >= Bd || bd_aacs`).
// ---------------------------------------------------------------------------

/// The Speed lever is in scope for anything BD-class *or* AACS-capable. A drive
/// whose capability row says BD media but leaves `bd_aacs` clear (the ordering
/// half of the gate) must still get the read-ramp unlock: turning the `||` into
/// an `&&`, or flipping the `>=`, would silently ship a BD drive with the ramp
/// ceiling still in place and report it as "n/a" rather than skipped.
#[test]
fn speed_lever_is_in_scope_for_bd_media_even_when_the_aacs_bit_is_clear() {
    let img = fixture();
    let rep = Mt1959Engine
        .build_modify(&img, &bu40n_chip(), &cap(MediaClass::Bd, false, true))
        .expect("base is modifiable");
    let sp = lever(&rep, LeverId::Speed);
    assert_eq!(
        sp.outcome,
        LeverOutcome::Applied,
        "BD media alone puts the read-ramp lever in scope; got {:?}",
        sp.outcome
    );
    assert!(
        fact(sp, "speed_stub_va").unwrap_or(0) != 0,
        "an Applied Speed lever must report the trampoline it actually injected"
    );
}

/// The mirror case: AACS capability alone (sub-BD media class) also puts Speed
/// in scope, so neither side of the `||` may be dropped.
#[test]
fn speed_lever_is_in_scope_for_an_aacs_model_below_bd_media_class() {
    let img = fixture();
    let rep = Mt1959Engine
        .build_modify(&img, &bu40n_chip(), &cap(MediaClass::Dvd, true, true))
        .expect("base is modifiable");
    assert_eq!(
        lever(&rep, LeverId::Speed).outcome,
        LeverOutcome::Applied,
        "the AACS half of the Speed scope gate must stand on its own"
    );
}

/// And a CD-class, non-AACS model has no read ramp at all: the lever must report
/// NotApplicable rather than patching a gate that does not belong to this drive.
/// (Inverting the `>=` would patch exactly the models that must not be touched.)
#[test]
fn speed_lever_is_out_of_scope_for_a_cd_only_non_aacs_model() {
    let img = fixture();
    let rep = Mt1959Engine
        .build_modify(&img, &bu40n_chip(), &cap(MediaClass::Cd, false, false))
        .expect("base is still modifiable (Identity always applies)");
    let sp = lever(&rep, LeverId::Speed);
    assert!(
        matches!(sp.outcome, LeverOutcome::NotApplicable { .. }),
        "a CD-only non-AACS model has no BD read ramp to unlock; got {:?}",
        sp.outcome
    );
    assert!(
        sp.facts.is_empty(),
        "an out-of-scope lever must not report grounded facts it never produced"
    );
}

// ---------------------------------------------------------------------------
// Graceful-degrade boundary: a feature detour that DID land must be reported.
// ---------------------------------------------------------------------------

/// UHD / HRL / BD are the graceful members of the Raw-read lever: an image whose
/// gate is not the known shape leaves them unwired (`stub_va == 0`) and the base
/// still ships. The flip side is that when they ARE wired the facts must be
/// reported — the structural audit re-derives each `bl` from these facts, so a
/// wired-but-unreported detour is an installed branch nobody ever re-checks.
#[test]
fn rawread_reports_the_uhd_hrl_bd_and_auth_cell_facts_whenever_those_detours_are_wired() {
    let img = fixture();
    let rep = Mt1959Engine
        .build_modify(&img, &bu40n_chip(), &cap(MediaClass::UhdBd, true, true))
        .expect("base is modifiable");
    let rr = lever(&rep, LeverId::RawRead);
    assert_eq!(rr.outcome, LeverOutcome::Applied, "{:?}", rr.outcome);

    for key in [
        "uhd_site",
        "uhd_stub_va",
        "hrl_stub_va",
        "hrl_site",
        "bd_site",
        "bd_stub_va",
        "auth_cell_site",
        "auth_cell_stub_va",
    ] {
        let v = fact(rr, key).unwrap_or_else(|| {
            panic!(
                "{key} is wired on this base but absent from the Raw-read facts — the audit \
                 would never re-check that installed branch"
            )
        });
        assert_ne!(v, 0, "{key} was reported as wired-at-zero");
    }
    // The desktop lineage detours three cert-path sites through one shared stub;
    // all three are named so the audit re-checks all three `bl`s.
    assert!(
        fact(rr, "hrl_site2").is_some() && fact(rr, "hrl_site3").is_some(),
        "all three HRL cert-path sites must be named as audit facts"
    );
}

// ---------------------------------------------------------------------------
// Finalized byte arrays allocate their exact size within protected geometry.
// ---------------------------------------------------------------------------

/// The erased (`0xFF`) runs `free_space` will consider: 4-aligned, and
/// wholly inside one active CMAC range, including clipped boundary runs.
fn covered_free_runs(buf: &[u8]) -> Vec<(usize, usize)> {
    let ranges: Vec<(u32, u32)> = cmac::parse_table(buf)
        .expect("fixture carries a parseable CMAC table")
        .into_iter()
        .filter(|e| e.is_active() && e.start <= e.end)
        .map(|e| (e.start, e.end))
        .collect();
    let mut runs = Vec::new();
    let mut i = CODE_REGION_START;
    while i < buf.len() {
        if buf[i] != 0xff {
            i += 1;
            continue;
        }
        let start = i;
        while i < buf.len() && buf[i] == 0xff {
            i += 1;
        }
        for &(lo, hi) in &ranges {
            let a = (start.max(lo as usize) + 3) & !3;
            let end = i.min(hi as usize + 1);
            if end > a {
                runs.push((a, end - a));
            }
        }
    }
    runs
}

/// Leave `buf` with exactly ONE piece of injectable free space: a `window`-byte
/// erased run at the address the allocator would have picked anyway. Every other
/// CMAC-covered erased run is filled in, so the allocator has a single candidate
/// of a size this test controls. Returns that window's base.
fn only_free_space(buf: &mut [u8], window: usize) -> u32 {
    let runs = covered_free_runs(buf);
    let base = Mt1959Engine
        .free_space(buf, window)
        .expect("fixture has covered space") as usize;
    let len = runs
        .iter()
        .find(|(start, _)| *start == base)
        .expect("chosen covered run")
        .1;
    assert!(
        window <= len,
        "asked for a {window}-byte window but the base's largest covered run is only {len}"
    );
    for (a, l) in runs {
        buf[a..a + l].fill(0x00);
    }
    buf[base..base + window].fill(0xFF);
    base as u32
}

/// The refusal `free_space` raises when it cannot satisfy a request of `need`.
fn out_of_space(need: usize) -> String {
    format!("free space of {need} bytes")
}

/// Exactly the Speed stub `emit_speed` assembles for the undamaged base,
/// rebuilt here from the same grounded finds so the tests can talk about its
/// size without going through the allocation under test.
fn speed_stub_bytes(image: &[u8]) -> Vec<u8> {
    let e = Mt1959Engine;
    let (gate, idx_reg) = e.find_speed_gate(image).expect("speed gate");
    let bhi_at = gate as usize + 6;
    let bhi = u16::from_le_bytes([image[bhi_at], image[bhi_at + 1]]);
    let mut disp = (bhi & 0xFF) as i32;
    if disp >= 0x80 {
        disp -= 0x100;
    }
    let ramp_exit = (bhi_at as i32 + 4 + disp * 2) as u32;
    e.build_speed_stub(FLAG_TABLE_BASE, gate + 8, ramp_exit, idx_reg)
        .expect("speed stub")
}

/// Exactly the Gate-A stub `emit_rawread` assembles for the undamaged base.
fn gatea_stub_bytes(image: &[u8]) -> Vec<u8> {
    let e = Mt1959Engine;
    let anchor = e.find_vid_gate(image).expect("VID gate");
    let (cmp, bne_at) = (anchor + 18, anchor + 20);
    let bne = u16::from_le_bytes([image[bne_at], image[bne_at + 1]]);
    let mut d = (bne & 0xFF) as i32;
    if d >= 0x80 {
        d -= 0x100;
    }
    let deny = (bne_at as i32 + 4 + d * 2) as u32;
    e.build_gatea_stub(
        FLAG_TABLE_BASE,
        e.find_vid_agid_struct(image).expect("AGID struct"),
        (cmp + 4) as u32,
        deny,
        e.find_aacs_session_reset(image).expect("session_reset"),
    )
    .expect("gate-A stub")
}

/// A finalized stub fits exactly. The next allocation independently checks its
/// own capacity and alignment; no unchecked writes depend on spare tail bytes.
#[test]
fn speed_stub_is_allocated_with_exact_capacity() {
    let e = Mt1959Engine;
    let img = fixture();
    let blob = speed_stub_bytes(&img).len();

    let mut cramped = img.clone();
    only_free_space(&mut cramped, blob - 1);
    let before = cramped.clone();
    let msg = refusal(
        e.emit_speed(&img, &mut cramped, FLAG_TABLE_BASE),
        "a free run one byte short of the finalized blob must not be used",
    );
    assert!(
        msg.contains(&out_of_space(blob)),
        "Speed must ask for its {blob}-byte stub without unneeded extra headroom; got: {msg}"
    );

    assert_eq!(cramped, before, "failed installation changed output");
    let mut exact = img.clone();
    let base = only_free_space(&mut exact, blob);
    let next_byte = exact[base as usize + blob];
    let (_, va) = e
        .emit_speed(&img, &mut exact, FLAG_TABLE_BASE)
        .expect("blob bytes of covered free space is enough to place the Speed stub");
    assert_eq!(
        va, base,
        "the stub must land in the one window we left free"
    );
    assert_eq!(
        exact[base as usize + blob],
        next_byte,
        "stub overran its allocation"
    );
}

/// Same contract for the Region-free stub.
#[test]
fn region_stub_is_allocated_with_exact_capacity() {
    let e = Mt1959Engine;
    let img = fixture();
    let blob = e
        .build_region_stub(FLAG_TABLE_BASE)
        .expect("region stub")
        .len();

    let mut cramped = img.clone();
    only_free_space(&mut cramped, blob - 1);
    let before = cramped.clone();
    let msg = refusal(
        e.emit_region(&img, &mut cramped, FLAG_TABLE_BASE),
        "a free run one byte short of the finalized blob must not be used",
    );
    assert!(
        msg.contains(&out_of_space(blob)),
        "Region must ask for its {blob}-byte stub without unneeded extra headroom; got: {msg}"
    );

    assert_eq!(cramped, before, "failed installation changed output");
    let mut exact = img.clone();
    let base = only_free_space(&mut exact, blob);
    let next_byte = exact[base as usize + blob];
    let (_, va) = e
        .emit_region(&img, &mut exact, FLAG_TABLE_BASE)
        .expect("blob bytes of covered free space is enough to place the Region stub");
    assert_eq!(
        va, base,
        "the stub must land in the one window we left free"
    );
    assert_eq!(
        exact[base as usize + blob],
        next_byte,
        "stub overran its allocation"
    );
}

/// The Raw-read lever injects six blobs back-to-back out of the same run
/// (ake → gate-A → deny → uhd → hrl → bd). Each allocation gets its own
/// capacity check: this walks every one of them, leaves exactly one byte less
/// free space than that blob needs, and requires the refusal to name that
/// blob's size without extra headroom — i.e. the allocation that ran short is
/// the one we aimed at, and it refused instead of squeezing the stub in.
#[test]
fn every_rawread_stub_is_allocated_with_exact_capacity() {
    let e = Mt1959Engine;
    let img = fixture();
    let base = only_free_space(&mut img.clone(), 16); // the allocator's window
    let facts = e
        .emit_rawread(&img, &mut img.clone(), FLAG_TABLE_BASE)
        .expect("raw-read emits on the undamaged base");

    let sites: [(&str, u32, usize); 6] = [
        (
            "AKE",
            facts.ake_stub_va,
            e.ake_detour(&img, FLAG_TABLE_BASE).expect("ake").1.len(),
        ),
        ("Gate-A", facts.gatea_stub_va, gatea_stub_bytes(&img).len()),
        (
            "deny-reset",
            facts.deny_stub_va,
            e.build_deny_reset_stub(e.find_aacs_session_reset(&img).expect("reset"))
                .expect("deny stub")
                .len(),
        ),
        (
            "UHD",
            facts.uhd_stub_va,
            e.uhd_gate_detour(&img, FLAG_TABLE_BASE)
                .expect("uhd")
                .1
                .len(),
        ),
        (
            "HRL-skip",
            facts.hrl_stub_va,
            e.hrl_skip_detour(&img, FLAG_TABLE_BASE)
                .expect("hrl")
                .2
                .len(),
        ),
        (
            "BD-refuse",
            facts.bd_stub_va,
            e.bd_detour(&img, FLAG_TABLE_BASE).expect("bd").1.len(),
        ),
    ];

    for (name, va, blob) in sites {
        assert!(va >= base, "{name} stub is not in the allocator's window");
        // Free space for every preceding blob, and one byte short for this one.
        let window = (va - base) as usize + blob - 1;
        let mut cramped = img.clone();
        assert_eq!(only_free_space(&mut cramped, window), base);
        let msg = refusal(
            e.emit_rawread(&img, &mut cramped, FLAG_TABLE_BASE),
            "a free run one byte short of the finalized blob must not be used",
        );
        assert!(
            msg.contains(&out_of_space(blob)),
            "the {name} stub ({blob} bytes) must request its finalized size; got: {msg}"
        );
    }
}

/// The injected handler is the one allocation the base cannot do without, on
/// both build paths — same exact-capacity contract, and a refusal (never a cramped
/// placement) when the covered free space is one byte short.
#[test]
fn handler_is_allocated_with_exact_capacity_on_both_paths() {
    let e = Mt1959Engine;
    let img = fixture();
    let blob = e
        .build_report(&img)
        .expect("base builds")
        .handler_bytes
        .len();

    let mut cramped = img.clone();
    only_free_space(&mut cramped, blob - 1);
    for msg in [
        refusal(e.build_report(&cramped), "create must refuse"),
        refusal(
            e.build_modify(&cramped, &bu40n_chip(), &cap(MediaClass::UhdBd, true, true)),
            "modify must refuse",
        ),
    ] {
        assert!(
            msg.contains(&out_of_space(blob)),
            "the {blob}-byte handler must request its finalized size; got: {msg}"
        );
    }
}

/// The hijacked dispatch record is repointed at `handler_va | 1` — the Thumb
/// tag. `free_space` only ever returns 4-aligned addresses, so `| 1` and `^ 1`
/// are the same function here: **that mutation is equivalent and cannot be
/// killed**, and contorting a test to chase it would only pin the allocator's
/// alignment twice. This assertion is the real invariant behind it: bit 0 must
/// be free for the Thumb tag, i.e. the allocator must never hand back an odd VA.
#[test]
fn injection_addresses_are_word_aligned_so_the_thumb_tag_is_free() {
    let img = fixture();
    let rep = Mt1959Engine.build_report(&img).expect("base builds");
    for (what, va) in [
        ("handler", rep.handler_va),
        ("boot stub", rep.boot_stub_va),
        ("speed stub", rep.speed_stub_va),
        ("region stub", rep.region_stub_va),
        ("ake stub", rep.ake_stub_va),
        ("gate-A stub", rep.gatea_stub_va),
        ("deny stub", rep.deny_stub_va),
    ] {
        assert_eq!(
            va % 4,
            0,
            "{what} was injected at {va:#x}: an unaligned VA would make the Thumb tag (`| 1`) \
             corrupt the address instead of marking it"
        );
    }
    let at = rep.record.off + 4; // the record's handler pointer
    let repointed = u32::from_le_bytes([
        rep.image[at],
        rep.image[at + 1],
        rep.image[at + 2],
        rep.image[at + 3],
    ]);
    assert_eq!(
        repointed,
        rep.handler_va | 1,
        "the hijacked record must point at the injected handler with the Thumb tag set"
    );
}

// ---------------------------------------------------------------------------
// SRAM flag-table guard width.
// ---------------------------------------------------------------------------

/// Plant a `ldr r0,[pc,#0]` + literal `cell` in erased, CMAC-uncovered flash, so
/// the image statically "references" that SRAM address. Returns the image.
/// (Uncovered erased space so the plant cannot perturb the injection allocator.)
fn image_referencing_sram(cell: u32) -> Vec<u8> {
    let mut img = fixture();
    let at = 0x001c_3810usize; // inside the big erased, CMAC-uncovered run
    assert!(
        img[at..at + 8].iter().all(|&b| b == 0xFF),
        "the plant site must be erased flash"
    );
    img[at..at + 2].copy_from_slice(&0x4800u16.to_le_bytes());
    let pool = (at + 4) & !3; // the `ldr`'s pc-relative literal slot
    img[pool..pool + 4].copy_from_slice(&cell.to_le_bytes());
    assert!(
        referenced_sram(&img).contains(&cell),
        "the planted literal must register as a static SRAM reference"
    );
    img
}

/// The flag table is `NUM_FEATURES + 1` bytes: slot 0 is the NV saved-marker and
/// slots `1..=NUM_FEATURES` are the feature flags. The build-time guard must
/// cover all of them (plus its 4-byte guard band). A guard that stops one or two
/// bytes short would bless an image whose top feature flag overlaps live SRAM —
/// the boot-init hook then writes the flag defaults over whatever the OEM keeps
/// there, on every power-on, on real hardware.
#[test]
fn the_flag_table_guard_covers_every_feature_slot() {
    // The last byte of the guarded span: flag[NUM_FEATURES] + the trailing guard.
    let last = FLAG_TABLE_BASE + NUM_FEATURES as u32 + 4;
    let img = image_referencing_sram(last);
    let e = Mt1959Engine;
    for msg in [
        refusal(e.build_report(&img), "create must refuse"),
        refusal(
            e.build_modify(&img, &bu40n_chip(), &cap(MediaClass::UhdBd, true, true)),
            "modify must refuse",
        ),
    ] {
        assert!(
            msg.contains("flag table") && msg.contains(&format!("{last:#010x}")),
            "a code reference to {last:#010x} sits inside the {} -byte flag table (+guard) and \
             must be caught by the FLAG TABLE check; got: {msg}",
            NUM_FEATURES + 1
        );
    }
}

// ---------------------------------------------------------------------------
// The AACS session-rearm absence guard.
// ---------------------------------------------------------------------------

/// Relocate the OEM AACS session-rearm wrapper to `at` (and blind the original),
/// so `find_aacs_session_rearm` resolves to an address of our choosing.
fn image_with_rearm_wrapper_at(at: usize) -> Vec<u8> {
    let e = Mt1959Engine;
    let mut img = fixture();
    let from = e.find_aacs_session_rearm(&img).expect("rearm wrapper") as usize;
    let reset = e.find_aacs_session_reset(&img).expect("session reset");
    let wrapper = img[from..from + 34].to_vec();
    img[at..at + 34].copy_from_slice(&wrapper);
    // The finder proves the match by decoding the trailing `bl <session_reset>`.
    let bl = thumb::encode_bl(at + 30, reset).expect("rearm tail `bl` in range");
    img[at + 30..at + 34].copy_from_slice(&bl);
    // Blind the original `push {r4,lr}` so the signature stays unique.
    img[from..from + 2].copy_from_slice(&0xB500u16.to_le_bytes());
    img
}

/// Strategy A removed the rearm-on-SET call: the wrapper's VA must never be
/// baked into the handler as a callable literal, or the vendor-CDB path wedges
/// with no medium loaded. The guard exists to catch a refactor that puts it
/// back — so it has to actually scan the handler bytes. Scanning an empty (or
/// reversed) range is a guard that can never fire.
///
/// The image is doctored so the wrapper lives at an address that *is* present
/// as a 4-byte literal inside the handler; the build must then refuse. Several
/// addresses are tried because relocating the wrapper over OEM code can break an
/// unrelated find first — any one of them proving the guard fires is enough.
#[test]
fn the_rearm_absence_guard_scans_the_handler_bytes() {
    let e = Mt1959Engine;
    let img = fixture();
    let handler = e
        .build_report(&img)
        .expect("base builds")
        .handler_bytes
        .clone();
    // Every Thumb-tagged address the handler bytes spell out.
    let targets: Vec<usize> = handler
        .windows(4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .filter(|v| v % 2 == 1 && (*v as usize) + 34 < img.len())
        .map(|v| (v & !1) as usize)
        .collect();
    assert!(
        !targets.is_empty(),
        "the handler always bakes Thumb-tagged OEM addresses; found none"
    );

    let mut tried = Vec::new();
    for at in targets {
        let doctored = image_with_rearm_wrapper_at(at);
        if e.find_aacs_session_rearm(&doctored).ok() != Some(at as u32) {
            continue; // the relocation did not take — not a verdict
        }
        // Both build paths inject the same handler and must both refuse it.
        let create = match e.build_report(&doctored) {
            Ok(_) => panic!(
                "create: the handler bakes {:#x} as a callable literal and the rearm wrapper now \
                 lives there, but the build shipped it anyway — the absence guard scanned nothing",
                at | 1
            ),
            Err(e) => format!("{e:#}"),
        };
        if !create.contains("rearm removal") {
            tried.push(format!("{at:#x}: {create}"));
            continue; // an unrelated find broke first — not a verdict
        }
        let modify = match e.build_modify(
            &doctored,
            &bu40n_chip(),
            &cap(MediaClass::UhdBd, true, true),
        ) {
            Ok(_) => panic!(
                "modify: the rearm wrapper at {:#x} is baked in the handler, but modify shipped \
                 the image anyway — its copy of the absence guard scanned nothing",
                at | 1
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            modify.contains("rearm removal"),
            "create refused this image but modify failed for another reason: {modify}"
        );
        return; // the guard fired on both paths, which is the whole point
    }
    panic!("no relocation reached the rearm guard; the builds failed earlier: {tried:?}");
}

/// ...and it scans ONLY the handler bytes. The same literal sitting elsewhere in
/// the image is not a baked call and must not fail the build: a guard whose
/// upper bound runs past the handler turns unrelated flash contents into a
/// refusal to ship.
#[test]
fn the_rearm_absence_guard_stops_at_the_end_of_the_handler() {
    let e = Mt1959Engine;
    let mut img = fixture();
    let rearm = e.find_aacs_session_rearm(&img).expect("rearm wrapper");
    // Erased, CMAC-uncovered flash well past where the handler is injected.
    let at = 0x001c_3820usize;
    assert!(img[at..at + 4].iter().all(|&b| b == 0xFF));
    img[at..at + 4].copy_from_slice(&(rearm | 1).to_le_bytes());

    let rep = e
        .build_report(&img)
        .expect("a rearm literal OUTSIDE the handler is not a baked call — create must ship");
    assert!(
        (rep.handler_va as usize) + rep.handler_bytes.len() <= at,
        "this test only means something if the planted literal is past the handler"
    );
    e.build_modify(&img, &bu40n_chip(), &cap(MediaClass::UhdBd, true, true))
        .expect("a rearm literal OUTSIDE the handler is not a baked call — modify must ship too");
}

// ---------------------------------------------------------------------------
// Raw-read: the deny sense-setup shape check.
// ---------------------------------------------------------------------------

/// Offsets of the deny-path sense-setup pair (`movs r2,#2; movs r1,#0x6f`) the
/// deny-reset detour overwrites, recomputed exactly the way `emit_rawread` does.
fn deny_site_of(image: &[u8]) -> usize {
    let e = Mt1959Engine;
    let anchor = e.find_vid_gate(image).expect("VID gate");
    let cmp = anchor + 18;
    let bne_at = cmp + 2;
    let bne = u16::from_le_bytes([image[bne_at], image[bne_at + 1]]);
    let mut d = (bne & 0xFF) as i32;
    if d >= 0x80 {
        d -= 0x100;
    }
    let deny = (bne_at as i32 + 4 + d * 2) as usize;
    deny + 0x10
}

/// The deny-reset detour overwrites a 4-byte OEM instruction pair; BOTH halfwords
/// must match or we are writing a `bl` over an instruction we did not identify.
/// Accepting a half-match (`||` weakened to `&&`) would splice a branch into the
/// middle of an unknown OEM sequence.
#[test]
fn deny_sense_setup_refuses_when_either_halfword_is_not_the_known_pair() {
    let img = fixture();
    let site = deny_site_of(&img);
    for (off, wrong) in [(0usize, 0x2203u16), (2, 0x2170)] {
        let mut bad = img.clone();
        bad[site + off..site + off + 2].copy_from_slice(&wrong.to_le_bytes());
        let msg = refusal(
            Mt1959Engine.emit_rawread(&bad, &mut img.clone(), FLAG_TABLE_BASE),
            "a half-matching deny sense-setup must not be detoured",
        );
        assert!(
            msg.contains("deny sense-setup"),
            "expected the deny-shape refusal, got: {msg}"
        );
    }
}

/// The deny site is derived by arithmetic from a branch displacement, so on a
/// short image it can point past the end. The bounds check must refuse *before*
/// the halfword read, and it must bound the real end of that read (`site + 4`):
/// a `site - 4` bound leaves the last 4 bytes of the read unchecked and the
/// build panics on a slice index instead of refusing cleanly.
#[test]
fn deny_site_running_past_the_image_end_is_refused_before_it_is_read() {
    let site = deny_site_of(&fixture()) + 0x20;
    let doctored = rawread_image_with_deny_at_the_tail(site);
    // Two bytes short of the pair: the 4-byte read would run off the end.
    let msg = refusal(
        Mt1959Engine.emit_rawread(&doctored[..site + 2], &mut fixture(), FLAG_TABLE_BASE),
        "a deny site whose 4-byte read runs off the end must be refused",
    );
    assert!(
        msg.contains("past the end of the image"),
        "expected the past-the-end refusal, got: {msg}"
    );
}

/// ...and that bound is inclusive: an image that ends on the *last byte* of the
/// deny pair carries the whole pair, so it must still be patched. A `>=` bound
/// (or an `==` one) turns a complete image into a false refusal and loses the
/// Raw-read lever on it.
#[test]
fn deny_site_ending_exactly_at_the_image_end_is_still_patched() {
    let site = deny_site_of(&fixture()) + 0x20;
    let doctored = rawread_image_with_deny_at_the_tail(site);
    let facts = Mt1959Engine
        .emit_rawread(&doctored[..site + 4], &mut fixture(), FLAG_TABLE_BASE)
        .expect("the deny pair is entirely inside this image — nothing to refuse");
    assert_eq!(
        facts.deny_site as usize, site,
        "the deny-reset detour must land on the pair at the very end of the image"
    );
}

// ---------------------------------------------------------------------------
// Branch-displacement sign extension (the two `-= 0x100` sites).
// ---------------------------------------------------------------------------

/// `bhi` displacements are signed 8-bit. The BU40N ramp exit happens to be a
/// forward branch, so the sign-extension arm only runs on images whose ramp exit
/// sits *behind* the gate. Get it wrong and the Speed stub's "exit the ramp"
/// branch is baked with a target ~512 bytes past the real one — a jump into the
/// middle of an unrelated instruction on a flashed drive.
#[test]
fn speed_ramp_exit_sign_extends_a_backward_bhi() {
    let e = Mt1959Engine;
    let img = fixture();
    let (gate, idx_reg) = e.find_speed_gate(&img).expect("speed gate");
    let bhi_at = gate as usize + 6;

    // Re-point the ramp exit backwards (displacement 0x90 = -112 halfwords).
    let mut back = img.clone();
    back[bhi_at + 1] = 0xD8; // keep it a `bhi`
    back[bhi_at] = 0x90;

    let want_exit = (bhi_at as i32 + 4 - 0x70 * 2) as u32;
    assert!(
        (want_exit as usize) < bhi_at,
        "the doctored ramp exit must be a BACKWARD branch for this test to mean anything"
    );
    let want_bytes = e
        .build_speed_stub(FLAG_TABLE_BASE, gate + 8, want_exit, idx_reg)
        .expect("speed stub");

    let mut out = back.clone();
    let (_, stub_va) = e
        .emit_speed(&back, &mut out, FLAG_TABLE_BASE)
        .expect("speed lever still emits on the doctored image");
    let got = &out[stub_va as usize..stub_va as usize + want_bytes.len()];
    assert_eq!(
        got,
        &want_bytes[..],
        "the Speed stub was assembled for the wrong ramp-exit address: a negative `bhi` \
         displacement must sign-extend to {want_exit:#x}"
    );
}

/// Build a copy of the fixture whose Raw-read prerequisites all resolve *below*
/// the deny site, so the image can be truncated right at the deny pair and the
/// deny bounds check is actually reached.
///
/// Two surgical edits: the VID gate's deny arm is re-pointed forward to
/// `deny_at` (so the deny pair sits at a chosen address) and the producer's
/// AGID session-struct literal is re-planted immediately after its prologue (the
/// OEM one lives in the function's trailing literal pool, ~700 bytes past the
/// deny site, which a truncated image no longer carries). Returns the image and
/// the deny site it now implies.
fn rawread_image_with_deny_at_the_tail(deny_site: usize) -> Vec<u8> {
    let e = Mt1959Engine;
    let mut img = fixture();
    let anchor = e.find_vid_gate(&img).expect("VID gate");
    let (gate, bne_at) = (anchor + 16, anchor + 20);

    // Re-plant the AGID session-struct literal right after the producer prologue.
    let mut producer = gate;
    while u16::from_le_bytes([img[producer], img[producer + 1]]) != 0xB5F0 {
        producer -= 2;
    }
    let agid = e.find_vid_agid_struct(&img).expect("AGID struct");
    let at = producer + 2;
    let pool = (at + 4) & !3;
    img[at..at + 2].copy_from_slice(&0x4F00u16.to_le_bytes()); // ldr r7,[pc,#0]
    img[pool..pool + 4].copy_from_slice(&agid.to_le_bytes());
    // Same for the producer's runtime scratch-buffer literal.
    let (_, out_buf) = e.find_vid_producer(&img).expect("VID producer");
    let at = pool + 4;
    let pool = (at + 4) & !3;
    img[at..at + 2].copy_from_slice(&0x4800u16.to_le_bytes()); // ldr r0,[pc,#0]
    img[pool..pool + 4].copy_from_slice(&out_buf.to_le_bytes());

    // Re-point the deny arm forward so the deny pair lands at `deny_site`.
    let disp = (deny_site - 0x10) as i64 - (bne_at as i64 + 4);
    assert_eq!(disp % 2, 0);
    let disp = disp / 2;
    assert!(
        (0..0x80).contains(&disp),
        "deny arm displacement out of range"
    );
    img[bne_at] = disp as u8;
    img[bne_at + 1] = 0xD1; // bne
    img[deny_site..deny_site + 2].copy_from_slice(&0x2202u16.to_le_bytes());
    img[deny_site + 2..deny_site + 4].copy_from_slice(&0x216fu16.to_le_bytes());
    img
}

/// The same signed-displacement arithmetic decides where the VID gate's deny
/// path is — and the deny path is where the deny-reset detour is written. A
/// mis-signed displacement writes a `bl` at an address that is not the deny
/// block at all.
#[test]
fn gatea_deny_target_sign_extends_a_backward_bne() {
    let e = Mt1959Engine;
    let img = fixture();
    let anchor = e.find_vid_gate(&img).expect("VID gate");
    let bne_at = anchor + 20;

    // Re-point the deny arm backwards (displacement 0xC0 = -64 halfwords) and
    // plant the OEM deny sense-setup pair at the address that implies.
    let mut back = img.clone();
    back[bne_at] = 0xC0;
    back[bne_at + 1] = 0xD1; // keep it a `bne`
    let want_deny = (bne_at as i32 + 4 - 0x40 * 2) as usize;
    let want_site = want_deny + 0x10;
    assert!(
        want_deny < bne_at,
        "the doctored deny arm must branch BACKWARD for this test to mean anything"
    );
    back[want_site..want_site + 2].copy_from_slice(&0x2202u16.to_le_bytes());
    back[want_site + 2..want_site + 4].copy_from_slice(&0x216fu16.to_le_bytes());

    let facts = e
        .emit_rawread(&back, &mut img.clone(), FLAG_TABLE_BASE)
        .expect("raw-read still emits against the backward deny arm");
    assert_eq!(
        facts.deny_site as usize,
        want_site,
        "a negative `bne` displacement must sign-extend: the deny-reset `bl` has to land on \
         the deny block, not {:#x} bytes away",
        (facts.deny_site as i64 - want_site as i64).abs()
    );
}

#[test]
fn allocation_clips_erased_runs_to_one_active_integrity_range() {
    let mut image = vec![0; 0x200000];
    let table = cmac::TABLE_OFFSET;
    image[table..table + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE].fill(0xff);
    let lo = 0x120003u32;
    let hi = 0x12003fu32;
    image[table..table + 4].copy_from_slice(&1u32.to_le_bytes());
    image[table + 4..table + 8].copy_from_slice(&lo.to_le_bytes());
    image[table + 8..table + 12].copy_from_slice(&hi.to_le_bytes());
    image[0x120000..0x121000].fill(0xff);
    assert_eq!(Mt1959Engine.free_space(&image, 60).unwrap(), 0x120004);
    assert!(Mt1959Engine.free_space(&image, 61).is_err());
    // An inactive range cannot extend coverage or bridge an uncovered gap.
    image[table + 28..table + 32].copy_from_slice(&0u32.to_le_bytes());
    image[table + 32..table + 36].copy_from_slice(&0x120040u32.to_le_bytes());
    image[table + 36..table + 40].copy_from_slice(&0x120fffu32.to_le_bytes());
    assert!(Mt1959Engine.free_space(&image, 61).is_err());
    image[table + 28..table + 32].copy_from_slice(&1u32.to_le_bytes());
    image[table + 32..table + 36].copy_from_slice(&0x120080u32.to_le_bytes());
    image[table + 36..table + 40].copy_from_slice(&0x1200bfu32.to_le_bytes());
    assert!(Mt1959Engine.free_space(&image, 100).is_err());
    image[table + 28..table + 32].copy_from_slice(&0u32.to_le_bytes());
    image[table + 4..table + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    image[table + 8..table + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Mt1959Engine.free_space(&image, 1).is_err());
    image[table + 4..table + 8].copy_from_slice(&lo.to_le_bytes());
    let outside_image = image.len() as u32;
    image[table + 8..table + 12].copy_from_slice(&outside_image.to_le_bytes());
    assert!(Mt1959Engine.free_space(&image, 1).is_err());
}

#[test]
fn allocation_rejects_erased_reserved_regions_even_when_authenticated() {
    // Authentication does not imply executable space: these areas can be
    // erased in a perfectly valid OEM image and populated later by the drive.
    for reserved in [
        0x10000..0x10400,   // boot mirror
        0x105c0..0x10610,   // update signatures
        0x1d8000..0x1ec000, // revocation lists and settings
        0x1ec000..0x1ec100, // identity
        0x1f0000..0x200000, // calibration
        0xfff0..0x10000,    // boot integrity digest
    ] {
        let mut image = vec![0; 0x200000];
        let table = cmac::TABLE_OFFSET;
        image[table..table + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE].fill(0xff);
        image[table..table + 4].copy_from_slice(&1u32.to_le_bytes());
        image[table + 4..table + 8].copy_from_slice(&0x9c00u32.to_le_bytes());
        image[table + 8..table + 12].copy_from_slice(&0x1fffffu32.to_le_bytes());
        image[reserved.clone()].fill(0xff);
        assert!(
            Mt1959Engine.free_space(&image, 4).is_err(),
            "allocated reserved {reserved:x?}"
        );
    }
}

#[test]
fn allocation_clips_at_reserved_storage_and_does_not_reuse_written_code() {
    let mut image = vec![0; 0x200000];
    let table = cmac::TABLE_OFFSET;
    image[table..table + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE].fill(0xff);
    image[table..table + 4].copy_from_slice(&1u32.to_le_bytes());
    image[table + 4..table + 8].copy_from_slice(&0x10000u32.to_le_bytes());
    image[table + 8..table + 12].copy_from_slice(&0x1fffffu32.to_le_bytes());
    // One erased run straddles the descriptor; only its safe prefix counts.
    image[0x1ebff0..0x1ec100].fill(0xff);
    // SETTINGS owns that prefix, too: no part of this run is executable.
    assert!(Mt1959Engine.free_space(&image, 4).is_err());
    image[0x1d7ff0..0x1d8100].fill(0xff);
    assert!(Mt1959Engine.free_space(&image, 17).is_err());
    let first = Mt1959Engine.free_space(&image, 8).unwrap() as usize;
    assert_eq!(first, 0x1d7ff0);
    image[first..first + 8].fill(0x55);
    assert_eq!(Mt1959Engine.free_space(&image, 8).unwrap(), 0x1d7ff8);
    image[first + 8..first + 16].fill(0x55);
    assert!(Mt1959Engine.free_space(&image, 1).is_err());
}

#[test]
fn allocation_keeps_existing_whole_run_placements_before_boundary_fallback() {
    let mut image = fixture();
    let original = Mt1959Engine.free_space(&image, 52).unwrap();
    // The final active range is followed by erased bytes outside its coverage.
    let range = cmac::parse_table(&image)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.is_active())
        .max_by_key(|entry| entry.end)
        .unwrap();
    image[range.end as usize - 4095..range.end as usize + 4097].fill(0xff);
    assert_eq!(Mt1959Engine.free_space(&image, 52).unwrap(), original);
}

#[test]
fn reported_wh16ns58_v9_build_installs_raw_read_inside_signed_flash() {
    let original = include_bytes!("../../tests/fixtures/WH16NS58_OEM_1.V9.bin");
    use sha2::Digest;
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(original)),
        "97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061"
    );
    let (report, support) =
        crate::api::modify_with_defaults(original, &BootSettings::standard()).unwrap();
    let raw = lever(&report, LeverId::RawRead);
    assert_eq!(raw.outcome, LeverOutcome::Applied);
    assert!(support.has_boot());
    assert!(
        fact(raw, "bd_stub_va").is_none(),
        "unproven descriptor role must not be installed"
    );
    assert!(raw
        .hooks
        .iter()
        .any(|hook| hook.id == "bd-native" && hook.reason.is_some()));
    let boundary_stub = fact(raw, "auth_cell_stub_va").unwrap();
    let contract = mediatek_optical::image::analysis::AuthCell::detect(original).unwrap();
    let bytes = Mt1959Engine
        .build_authcell_widen_value_stub(FLAG_TABLE_BASE, contract.deny() as u32, 1)
        .unwrap();
    assert_eq!(
        &report.image[boundary_stub as usize..boundary_stub as usize + bytes.len()],
        bytes
    );
    assert_ne!(boundary_stub, 0);
    assert!(boundary_stub as usize >= cmac::TABLE_OFFSET + cmac::ENTRY_COUNT * cmac::ENTRY_SIZE);
    let table = cmac::parse_table(&report.image).unwrap();
    assert!(table.iter().any(|entry| entry.is_active()
        && entry.start <= boundary_stub
        && boundary_stub + bytes.len() as u32 - 1 <= entry.end));
    assert!(cmac::verify_detailed(&report.image)
        .unwrap()
        .iter()
        .all(|entry| entry.matches));
    let audit = crate::engine::audit::audit_image(original, &report);
    assert!(audit.ok(), "{:?}", audit.failures().collect::<Vec<_>>());
    // Modifying settings again uses the signed record without allocating more hooks.
    let (again, _) =
        crate::api::modify_with_defaults(&report.image, &BootSettings::standard()).unwrap();
    assert_eq!(again.image, report.image);
}

#[test]
fn wh16ns58_v9_modification_preserves_every_integrity_table_descriptor() {
    let original = include_bytes!("../../tests/fixtures/WH16NS58_OEM_1.V9.bin");
    let settings = BootSettings::parse(&[
        "hrl=off".into(),
        "encryption=off".into(),
        "speed=uncapped".into(),
        "region=free".into(),
    ])
    .unwrap();
    let (report, _) = crate::api::modify_with_defaults(original, &settings).unwrap();
    for index in 0..cmac::ENTRY_COUNT {
        let at = cmac::TABLE_OFFSET + index * cmac::ENTRY_SIZE;
        assert_eq!(
            &report.image[at..at + 12],
            &original[at..at + 12],
            "table descriptor {index} was overwritten"
        );
        if original[at..at + 4] == [0xff; 4] {
            assert_eq!(
                &report.image[at..at + cmac::ENTRY_SIZE],
                &original[at..at + cmac::ENTRY_SIZE],
                "unused table entry {index} was used as code"
            );
        }
    }
    assert!(cmac::verify(&report.image));
}

#[test]
fn boot_stub_fits_exact_finalized_capacity_and_refuses_short_without_writes() {
    let engine = Mt1959Engine;
    let original = fixture();
    let pair = engine.resolve_boot_init_pair(&original).unwrap();
    let defaults = crate::boot::BootSettings::standard();
    let bytes = engine
        .build_boot_init_with_defaults(FLAG_TABLE_BASE, pair.1, &defaults)
        .unwrap();
    let mut short = original.clone();
    only_free_space(&mut short, bytes.len() - 1);
    let before = short.clone();
    assert!(engine
        .emit_boot_init(&original, &mut short, FLAG_TABLE_BASE, pair, &defaults)
        .is_err());
    assert_eq!(short, before);
    let mut exact = original.clone();
    let base = only_free_space(&mut exact, bytes.len());
    let (_, installed) = engine
        .emit_boot_init(&original, &mut exact, FLAG_TABLE_BASE, pair, &defaults)
        .unwrap();
    assert_eq!(installed, base);
    assert_eq!(&exact[base as usize..base as usize + bytes.len()], bytes);
}

#[test]
fn descriptor_match_does_not_install_a_role_unproven_bd_refusal() {
    let image = include_bytes!("../../tests/fixtures/WH16NS58_OEM_1.V9.bin");
    let engine = Mt1959Engine;
    assert!(
        engine.find_bd_gate(image).is_ok(),
        "the descriptor candidate remains identifiable"
    );
    let result = engine.bd_detour(image, FLAG_TABLE_BASE);
    assert!(
        result.is_err(),
        "a descriptor signature alone must not authorize a native BD hook"
    );
}
