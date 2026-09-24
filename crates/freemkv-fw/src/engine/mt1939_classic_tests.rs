//! MT1939-**classic** builder tests.
//!
//! The classic create/modify path used to be reachable only from a real classic
//! image (`FREEMKV_MT1939_CLASSIC`), so on a bare checkout every classic emit
//! helper ran ZERO times and every mutation of them survived silently. These
//! tests remove that hole: they graft the classic code shapes
//! (`VID_GATE_SIG_CLASSIC`, `AKE_GATE_SIG_CLASSIC`, `HRL_LOOKUP_SIG_CLASSIC`,
//! `REGION_EMIT_SIG`, a classic `~0x1a4000` dispatch table) onto the committed
//! BU40N fixture and drive the classic emitters end to end.
//!
//! **Why the BU40N fixture is the substrate.** The classic emitters all call
//! [`Mt1959Engine::free_space`], which needs a real CMAC table to know which
//! erased runs are integrity-covered, and [`Mt1959Engine::find_cdb_base`], which
//! needs a real scanner. Synthesising both would be re-implementing the format;
//! grafting onto a real image exercises the real ones. Every graft lands in the
//! fixture's large **erased, NON-CMAC-covered** `0x1c3810..0x1d8000` run (or in
//! the un-erased `0x159000` code area for the region anchor), so `free_space`
//! keeps resolving to the covered `0x153968` run that the KAT pins — grafting
//! never moves a stub.
//!
//! Site offsets and gate displacements below are chosen so that an off-by-one in
//! ANY of the emitters' address arithmetic lands somewhere that fails a check,
//! and every emitted fact is asserted exactly rather than "is present".

use super::*;

use crate::engine::lever::{LeverId, LeverOutcome};
use crate::engine::mt1939::{
    masked_matches, AKE_GATE_SIG_CLASSIC, HRL_LOOKUP_SIG_CLASSIC, VID_GATE_SIG_CLASSIC,
};

// --- graft offsets ---------------------------------------------------------

/// Classic VID-producer gate anchor. `cmp r0,#6` lands at `VID+30`, `bne` at `VID+32`.
const VID: usize = 0x001c_4000;
/// Classic AKE accept/reject gate anchor. Reject writer at `AKE+6`, `bl` back at `AKE+0xa`.
const AKE: usize = 0x001c_4100;
/// Classic HRL lookup routine.
const HRL: usize = 0x001c_5000;
/// The shared OEM revoke target carrying the `6F`-deny head.
const REVOKE: usize = 0x001c_5200;
/// An address that is deliberately NOT a revoke head (erased flash). Decoy
/// branches in the grafts aim here so that any mis-anchored site the finder
/// might latch onto fails the `6F`-deny head check instead of passing by luck.
const DECOY_TARGET: usize = 0x001c_5220;
/// Classic RPC-state (Region) emitter anchor — must sit in `0x150000..0x160000`
/// but OUTSIDE the covered erased run (`0x153968..0x158000`) the stubs use.
const REGION: usize = 0x0015_9000;
/// Classic `0x3C` dispatch table, inside the classic `~0x1a4000` window.
const TABLE: usize = 0x001a_6b00;
/// The BU40N OEM `0x3C` handler the grafted classic record points at.
const OEM_3C_HANDLER: u32 = 0x0009_ad5b;
/// The flag-table base the standalone emit tests use (the value does not matter
/// to the emitters — only that it shows up unmodified in the stub literals).
const FLAG_BASE: u32 = 0x0200_120c;

fn fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("BU40N fixture must be present at {path}: {e}"))
}

fn put_hw(img: &mut [u8], off: usize, hws: &[u16]) {
    for (k, &h) in hws.iter().enumerate() {
        img[off + 2 * k..off + 2 * k + 2].copy_from_slice(&h.to_le_bytes());
    }
}

/// True when the 32-bit little-endian word `needle` appears anywhere in `hay`
/// (how a `ldr rX,[pc]` literal is checked inside an emitted stub).
fn has_u32_le(hay: &[u8], needle: u32) -> bool {
    hay.windows(4)
        .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == needle)
}

/// The bytes of the stub that starts at `va` (up to `len`), as the emitters wrote them.
fn stub_at(img: &[u8], va: u32, len: usize) -> &[u8] {
    &img[va as usize..va as usize + len]
}

/// Graft `VID_GATE_SIG_CLASSIC` at `at`, with `bne_lo` as the gate `bne`'s imm8.
/// Every masked halfword is filled with a concrete, non-degenerate value so a
/// mutated index lands on a byte that *differs* (an all-zero filler would let
/// several index mutations read back the value they were looking for).
fn plant_vid_gate(img: &mut [u8], at: usize, bne_lo: u8) {
    put_hw(
        img,
        at,
        &[
            0x7AA8,                     // ldrb r0,[r5,#0xa]
            0x4901,                     // ldr  r1,[pc,#4]
            0x0980,                     // lsrs r0,r0,#6
            0x1840,                     // adds r0,r0,r1
            0x4902,                     // ldr  r1,[pc,#8]
            0x0400,                     // lsls r0,r0,#16
            0x6809,                     // ldr  r1,[r1]
            0x0C00,                     // lsrs r0,r0,#16
            0x1808,                     // adds r0,r1,r0
            0x4903,                     // ldr  r1,[pc,#0xc]
            0x0200,                     // lsls r0,r0,#8
            0x6809,                     // ldr  r1,[r1]
            0x0A00,                     // lsrs r0,r0,#8
            0x1840,                     // adds r0,r0,r1
            0x7800,                     // ldrb r0,[r0]        (+28)
            0x2806,                     // cmp  r0,#6          (+30, the Gate-A detour site)
            0xD100 | u16::from(bne_lo), // bne <deny>          (+32)
        ],
    );
}

/// Graft `AKE_GATE_SIG_CLASSIC` at `at`. The `b` at `+4` deliberately carries a
/// low byte of `0x12` (not `0x01`): with `0x01` the mutation that reads the
/// reject writer's `movs` one halfword EARLY would read back a coincidental
/// `0x2101` and survive.
fn plant_ake_gate(img: &mut [u8], at: usize) {
    put_hw(
        img,
        at,
        &[
            0x0980, // lsrs r0,r0,#6
            0x2106, // movs r1,#6        (accept)
            0xE012, // b    <skip>
            0x0980, // lsrs r0,r0,#6     (+6, the AKE detour site)
            0x2101, // movs r1,#1        (reject)
            0xF000, // bl   set_agid_state  (+0xa, the shared call both arms reach)
        ],
    );
}

/// Graft `HRL_LOOKUP_SIG_CLASSIC` at `at`. The two body `bl`s are real encodings
/// aimed at an unrelated low address so they can never be mistaken for a
/// `bl <hrl>` cert-path call.
fn plant_hrl_routine(img: &mut [u8], at: usize) {
    put_hw(
        img,
        at,
        &[
            0xB5F3, 0xB083, 0x9803, 0x000C, 0x0000, 0x0000, 0x0007, 0x0020, 0x0000, 0x0000, 0x9002,
            0x4901, 0x1D20, 0x680A, 0x0200, 0x0A00, 0x1880, 0x7800, 0x466B, 0x7158,
        ],
    );
    let filler = thumb::encode_bl(at + 8, 0x1000).expect("filler bl in range");
    thumb::write(img, at + 8, &filler);
    let filler = thumb::encode_bl(at + 16, 0x1000).expect("filler bl in range");
    thumb::write(img, at + 16, &filler);
}

/// Graft the version-invariant classic OEM revoke head
/// (`ldrb r0,[r5,#2]; cmp r0,#0; bne …; movs r0,#0x6f`) at `at`.
fn plant_revoke_head(img: &mut [u8], at: usize) {
    put_hw(img, at, &[0x78A8, 0x2800, 0xD1FE, 0x206F]);
}

/// `bne <revoke>` halfword for a `bne` sitting at `bne_off`. Panics when the
/// displacement does not fit the conditional branch's signed imm8 — which would
/// silently make the graft unrepresentable rather than test what it claims to.
fn bne_to(bne_off: usize, revoke: usize) -> u16 {
    let d = (revoke as isize - bne_off as isize - 4) / 2;
    assert!(
        (-128..=127).contains(&d),
        "bne displacement {d} out of imm8 range — move the graft"
    );
    0xD100 | ((d as u16) & 0xFF)
}

/// Graft one classic cert-path check site: `bl <hrl>`, two filler instructions,
/// then `cmp r0,#0; bne <revoke>`. Returns the `cmp` offset — the value
/// `emit_hrl_classic` reports and detours.
///
/// The two fillers are load-bearing. They make the finder actually WALK forward
/// from the `bl` instead of matching on the very first halfword (which exercises
/// the walk's step budget, its `b`-hop test and its cursor advance), and the
/// SECOND filler is a `bne` to an address that is NOT the revoke head: a site
/// must be recognised by `cmp r0,#0` **and** a following `bne` together, so a
/// lone `bne` in the OEM code between the call and the check cannot be mistaken
/// for the cert-path test.
fn plant_hrl_site(img: &mut [u8], bl_at: usize, hrl: usize, revoke: usize) -> usize {
    let bl = thumb::encode_bl(bl_at, hrl as u32).expect("cert-path bl in range");
    thumb::write(img, bl_at, &bl);
    // movs r2,#0 ; bne <not-the-revoke-head>
    put_hw(img, bl_at + 4, &[0x2200, bne_to(bl_at + 6, DECOY_TARGET)]);
    let cmp = bl_at + 8;
    put_hw(img, cmp, &[0x2800, bne_to(cmp + 2, revoke)]);
    cmp
}

/// The standard two-site classic HRL image: unique lookup routine, two cert-path
/// check sites agreeing on one revoke target, and that target carrying the OEM
/// `6F`-deny head. Returns `(image, [cmp_site_0, cmp_site_1])`.
fn classic_hrl_image() -> (Vec<u8>, [usize; 2]) {
    let mut img = fixture();
    plant_hrl_routine(&mut img, HRL);
    plant_revoke_head(&mut img, REVOKE);
    let s0 = plant_hrl_site(&mut img, 0x001c_5280, HRL, REVOKE);
    let s1 = plant_hrl_site(&mut img, 0x001c_52c0, HRL, REVOKE);
    (img, [s0, s1])
}

// ---------------------------------------------------------------------------
// find_vid_agid_struct_classic
// ---------------------------------------------------------------------------

/// The classic AGID struct base IS the CDB base the classic scanner loads into
/// `r5`. Pinning it to the image-derived CDB base (and asserting it is neither
/// `0` nor `1`) is what stops the Gate-A `04 01` rearm from poking a wrong SRAM
/// cell — the whole reason the classic finder exists separately from the modern
/// `ldr r7,[pc]` heuristic.
#[test]
fn classic_agid_struct_is_the_image_derived_cdb_base_never_a_constant() {
    let img = fixture();
    let cdb = Mt1959Engine.find_cdb_base(&img).expect("cdb base");
    let got = Mt1959Engine
        .find_vid_agid_struct_classic(&img)
        .expect("classic agid struct");
    assert_eq!(
        got, cdb,
        "classic AGID struct must be the scanner-derived CDB base, not a constant"
    );
    assert_eq!(
        got, 0x0200_0d38,
        "the CDB base is a live SRAM cell derived from THIS image; a hardcoded 0/1 would \
         make the Gate-A rearm write to address 0"
    );
}

// ---------------------------------------------------------------------------
// build_ake_stub_classic
// ---------------------------------------------------------------------------

/// The classic AKE stub reads `flag[Encryption]`, not some other flag cell, and
/// returns into the shared OEM `bl set_agid_state` with the Thumb bit set. Both
/// are baked as `ldr rX,[pc]` literals, so they are asserted as literals: a
/// wrong flag offset gates on a neighbouring feature's byte, and a wrong return
/// literal lands the `bx` in ARM mode (instant fault on a Thumb-only core).
#[test]
fn classic_ake_stub_bakes_the_encryption_flag_cell_and_a_thumb_tagged_return() {
    let back: u32 = 0x0017_f2de;
    let stub = Mt1959Engine
        .build_ake_stub_classic(FLAG_BASE, back)
        .expect("classic ake stub");
    assert!(
        has_u32_le(&stub, FLAG_BASE + crate::abi::Feature::Encryption as u32),
        "stub must load &flag[Encryption] (flag_base + 0x{:x}); any other arithmetic gates \
         the AKE accept on the wrong feature byte",
        crate::abi::Feature::Encryption as u32
    );
    assert!(
        !has_u32_le(&stub, FLAG_BASE),
        "the bare flag_base is flag[0] — a reserved slot, never the AKE gate"
    );
    assert!(
        has_u32_le(&stub, back | 1),
        "stub must return to the shared `bl set_agid_state` site with the Thumb bit set"
    );
}

/// Thumb-tagging the return address must be idempotent: an already-tagged `back`
/// has to come out unchanged. This pins the `|` in `back | 1` — an `^` there
/// would silently CLEAR the Thumb bit on any odd input and branch into ARM mode.
#[test]
fn classic_ake_stub_thumb_tag_is_idempotent_on_an_already_tagged_return() {
    let back: u32 = 0x0017_f2df; // already Thumb-tagged
    let stub = Mt1959Engine
        .build_ake_stub_classic(FLAG_BASE, back)
        .expect("classic ake stub");
    assert!(
        has_u32_le(&stub, back),
        "an already-tagged return must survive unchanged (OR, never XOR — XOR clears the bit)"
    );
    assert!(
        !has_u32_le(&stub, back & !1),
        "the stub must never bake an ARM-mode (even) return address"
    );
}

// ---------------------------------------------------------------------------
// commit_classic_detour
// ---------------------------------------------------------------------------

/// The best-effort classic detour commit must place the stub in CMAC-covered
/// free space, write a `bl` at the site, and report the REAL stub VA. A constant
/// `Some(0)`/`Some(1)` return would be recorded in the `CreateReport` as the
/// feature's stub address and pass every downstream "is it wired?" check while
/// pointing at nothing.
#[test]
fn commit_classic_detour_reports_the_real_stub_va_and_installs_a_decodable_bl() {
    let mut out = fixture();
    let site = 0x001c_4800usize;
    let bytes: Vec<u8> = (0..24u8).collect();
    let va = Mt1959Engine
        .commit_classic_detour(&mut out, site, &bytes)
        .expect("free space + bl range are both available on the fixture");
    assert_eq!(
        va, 0x0015_3968,
        "the stub must land in the fixture's largest CMAC-covered erased run"
    );
    assert_eq!(
        &out[va as usize..va as usize + bytes.len()],
        &bytes[..],
        "the stub bytes must actually be written at the reported VA"
    );
    assert_eq!(
        thumb::decode_bl(&out, site),
        Some(va),
        "the installed `bl` must decode back to the reported stub VA — the decode-back \
         guard is what stops a silently mis-encoded branch from shipping"
    );
}

/// The decode-back guard must ACCEPT a correct install. Inverting its comparison
/// turns every good commit into a silent miss (feature left unwired with no
/// diagnostic), which is indistinguishable from "this image has no such gate".
#[test]
fn commit_classic_detour_accepts_a_correctly_installed_bl() {
    let mut out = fixture();
    assert!(
        Mt1959Engine
            .commit_classic_detour(&mut out, 0x001c_4800, &[0u8; 32])
            .is_some(),
        "a well-formed install must return Some — a None here silently drops the feature"
    );
}

// ---------------------------------------------------------------------------
// emit_region_classic
// ---------------------------------------------------------------------------

/// Classic Region-free: the anchor is found in the classic `0x15xxxx` window and
/// the detour `bl` replaces the `frame[4]` store at **anchor+6**. The `+6` is the
/// whole contract — at any other offset the `bl` overwrites a different pair of
/// OEM instructions and the RPC frame is emitted from a corrupted register state.
#[test]
fn classic_region_emit_detours_the_frame4_store_at_anchor_plus_six() {
    let mut out = fixture();
    put_hw(
        &mut out,
        REGION,
        &[
            0x466B, 0x789B, 0x18D2, 0x7202, 0x466B, 0x78DA, 0x7202, 0x7204, 0x7201, 0xBD18,
        ],
    );
    let before = out.clone();
    let (emitter, stub_va) = Mt1959Engine
        .emit_region_classic(&mut out, FLAG_BASE)
        .expect("classic region emit");
    assert_eq!(
        emitter, REGION as u32,
        "the reported emitter must be the grafted anchor, not a constant"
    );
    assert_eq!(
        stub_va, 0x0015_3968,
        "the region stub must land in the fixture's covered erased run"
    );
    assert_eq!(
        thumb::decode_bl(&out, REGION + 6),
        Some(stub_va),
        "the detour `bl` must sit at anchor+6 (the `strb r2,[r0,#8]` frame[4] store)"
    );
    assert_eq!(
        before[REGION..REGION + 6],
        out[REGION..REGION + 6],
        "the anchor's first three halfwords are OEM prologue and must be untouched"
    );
}

// ---------------------------------------------------------------------------
// emit_rawread_classic
// ---------------------------------------------------------------------------

/// Build the classic Raw-read image: unique VID gate + unique AKE gate.
fn classic_rawread_image(bne_lo: u8) -> Vec<u8> {
    let mut img = fixture();
    plant_vid_gate(&mut img, VID, bne_lo);
    plant_ake_gate(&mut img, AKE);
    img
}

/// Every address `emit_rawread_classic` derives is asserted EXACTLY, because
/// each is an address a `bl` or a `bx` is aimed at:
///
/// * `gatea_gate = vid+30` — the `cmp r0,#6` the Gate-A `bl` replaces;
/// * `gatea_authed = gatea_gate+4` — where the stub resumes to stage the VID;
/// * `deny` — the OEM deny block the stub falls back to, decoded from the gate
///   `bne`'s signed imm8;
/// * `ake_site = ake+6` — the reject writer the AKE `bl` replaces;
/// * `ake_gate` / `ake_back = ake+0xa` — the shared `bl set_agid_state` both
///   arms converge on.
///
/// An off-by-one in any of them is a `bl` landing mid-instruction on a drive.
#[test]
fn classic_rawread_emit_grounds_every_gate_address_and_installs_both_detours() {
    let img = classic_rawread_image(0x12); // forward `bne`, d = +18
    let mut out = img.clone();
    let facts = Mt1959Engine
        .emit_rawread_classic(&img, &mut out, FLAG_BASE)
        .expect("classic raw-read emit");
    let f = |k: &str| {
        facts
            .iter()
            .find(|(n, _)| *n == k)
            .unwrap_or_else(|| panic!("fact {k} missing"))
            .1
    };

    assert_eq!(facts.len(), 9, "the classic raw-read fact list is fixed");
    assert_eq!(
        f("gatea_gate"),
        (VID + 30) as u32,
        "Gate-A detours the `cmp r0,#6` at VID_GATE_SIG_CLASSIC match+30"
    );
    assert_eq!(
        f("gatea_authed"),
        (VID + 34) as u32,
        "the authed resume point is the halfword AFTER the `cmp`/`bne` pair"
    );
    assert_eq!(
        f("deny"),
        (VID + 36 + 18 * 2) as u32,
        "the deny target is decoded from the gate `bne`'s imm8 (pc = bne+4, imm8 * 2)"
    );
    assert_eq!(
        f("ake_gate"),
        AKE as u32,
        "the AKE anchor is the signature match itself"
    );
    assert_eq!(
        f("ake_site"),
        (AKE + 6) as u32,
        "the AKE detour replaces the reject writer at match+6"
    );
    assert_eq!(
        f("vid_producer"),
        0x0013_675c,
        "the audit-only VID producer anchor still comes from the image"
    );
    assert_eq!(f("scratch"), 0x0021_0c00, "audit-only clear-VID scratch");

    // Both detours installed and decodable.
    let gatea_stub_va = f("gatea_stub_va");
    let ake_stub_va = f("ake_stub_va");
    assert_ne!(gatea_stub_va, 0, "Gate-A stub must be placed");
    assert_ne!(ake_stub_va, 0, "AKE stub must be placed");
    assert_ne!(
        gatea_stub_va, ake_stub_va,
        "the two stubs must not be written on top of each other"
    );
    assert_eq!(
        thumb::decode_bl(&out, VID + 30),
        Some(gatea_stub_va),
        "Gate-A `bl` must decode back to the reported stub"
    );
    assert_eq!(
        thumb::decode_bl(&out, AKE + 6),
        Some(ake_stub_va),
        "AKE `bl` must decode back to the reported stub"
    );

    // The stubs must carry the addresses the facts advertise.
    let gatea = stub_at(&out, gatea_stub_va, 96);
    assert!(
        has_u32_le(gatea, f("gatea_authed") | 1),
        "the Gate-A stub must branch to the Thumb-tagged authed resume point"
    );
    assert!(
        has_u32_le(gatea, f("deny") | 1),
        "the Gate-A stub must keep the OEM deny fallback"
    );
    assert!(
        has_u32_le(gatea, FLAG_BASE + crate::abi::Feature::Encryption as u32),
        "the Gate-A stub gates on flag[Encryption]"
    );
    let ake = stub_at(&out, ake_stub_va, 64);
    assert!(
        has_u32_le(ake, (AKE as u32 + 0xa) | 1),
        "the AKE stub must fall through to the shared `bl set_agid_state` at match+0xa — \
         a wrong return address here skips the OEM state store entirely"
    );

    // Classic ships NO deny detour: the deny block stays byte-identical to OEM.
    let deny = f("deny") as usize;
    assert_eq!(
        img[deny..deny + 0x40],
        out[deny..deny + 0x40],
        "the classic deny path must stay byte-identical to OEM (its clear-output shape \
         is inferred; touching it risks a SCSI-FIFO desync)"
    );
}

/// The gate `bne`'s imm8 is SIGNED. A classic image whose deny block sits
/// *behind* the gate encodes `0x80..=0xFF`, and the decode must sign-extend —
/// otherwise the Gate-A stub's fallback `bx` jumps ~512 bytes past the gate into
/// the middle of an unrelated routine.
#[test]
fn classic_rawread_deny_target_sign_extends_a_backward_gate_branch() {
    let img = classic_rawread_image(0x90); // d = 0x90 - 0x100 = -112
    let mut out = img.clone();
    let facts = Mt1959Engine
        .emit_rawread_classic(&img, &mut out, FLAG_BASE)
        .expect("classic raw-read emit");
    let deny = facts.iter().find(|(n, _)| *n == "deny").unwrap().1;
    assert_eq!(
        deny,
        (VID + 36 - 112 * 2) as u32,
        "a 0x90 imm8 is -112 halfwords, so the deny block is BEHIND the gate"
    );
    let gatea_stub_va = facts.iter().find(|(n, _)| *n == "gatea_stub_va").unwrap().1;
    assert!(
        has_u32_le(stub_at(&out, gatea_stub_va, 96), deny | 1),
        "the sign-extended deny target must be what the stub actually branches to"
    );
}

/// Fail-closed, hit count 0: no classic VID gate at all must refuse, not emit.
#[test]
fn classic_rawread_refuses_when_the_vid_gate_is_absent() {
    let img = fixture();
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_rawread_classic(&img, &mut out, FLAG_BASE)
        .expect_err("no classic VID gate present — must refuse");
    assert!(
        format!("{e:#}").contains("classic VID gate matched 0 time(s)"),
        "got: {e:#}"
    );
    assert_eq!(out, img, "a refused emit must not have touched the image");
}

/// Fail-closed, hit count > 1: an ambiguous VID gate must refuse rather than
/// pick one. Two matches means the anchor is not the producer's gate on this
/// image, and detouring the wrong one corrupts the AACS path.
#[test]
fn classic_rawread_refuses_when_the_vid_gate_is_ambiguous() {
    let mut img = classic_rawread_image(0x12);
    plant_vid_gate(&mut img, VID + 0x200, 0x12);
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_rawread_classic(&img, &mut out, FLAG_BASE)
        .expect_err("two classic VID gates — must refuse");
    assert!(
        format!("{e:#}").contains("classic VID gate matched 2 time(s)"),
        "got: {e:#}"
    );
}

/// Same fail-closed rule for the AKE accept gate.
#[test]
fn classic_rawread_refuses_when_the_ake_gate_is_absent_or_ambiguous() {
    let mut img = fixture();
    plant_vid_gate(&mut img, VID, 0x12);
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_rawread_classic(&img, &mut out, FLAG_BASE)
        .expect_err("no classic AKE gate — must refuse");
    assert!(
        format!("{e:#}").contains("classic AKE gate matched 0 time(s)"),
        "got: {e:#}"
    );

    let mut img = classic_rawread_image(0x12);
    plant_ake_gate(&mut img, AKE + 0x200);
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_rawread_classic(&img, &mut out, FLAG_BASE)
        .expect_err("two classic AKE gates — must refuse");
    assert!(
        format!("{e:#}").contains("classic AKE gate matched 2 time(s)"),
        "got: {e:#}"
    );
}

// ---------------------------------------------------------------------------
// emit_hrl_classic
// ---------------------------------------------------------------------------

/// The classic HRL-skip emit: locate the unique lookup routine, find every
/// cert-path `cmp r0,#0; bne <revoke>` that follows a `bl <hrl>`, prove they all
/// agree on one revoke target, prove that target carries the OEM `6F`-deny head,
/// and only then detour each check site to the shared skip stub.
#[test]
fn classic_hrl_emit_detours_every_agreeing_cert_check_site() {
    let (img, sites) = classic_hrl_image();
    let mut out = img.clone();
    let (got, stub_va) = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect("classic hrl emit");

    assert_eq!(
        got,
        vec![sites[0] as u32, sites[1] as u32],
        "every cert-path check site must be reported, at the `cmp r0,#0` offset the \
         detour `bl` replaces — a wrong offset here patches a live instruction"
    );
    assert_eq!(
        stub_va, 0x0015_3968,
        "the shared skip stub must land in the fixture's covered erased run"
    );
    for &s in &sites {
        assert_eq!(
            thumb::decode_bl(&out, s),
            Some(stub_va),
            "each site's `bl` must decode back to the shared stub"
        );
    }
    let stub = stub_at(&out, stub_va, 64);
    assert!(
        has_u32_le(stub, REVOKE as u32 | 1),
        "the stub must keep the OEM revoke path as a Thumb-tagged branch target — the \
         whole point is that an UNARMED image behaves exactly like OEM"
    );
    assert!(
        has_u32_le(stub, FLAG_BASE + crate::abi::Feature::Hrl as u32),
        "the stub must gate on flag[Hrl]"
    );
}

/// Sites that disagree on the revoke target mean the anchor is not what we think
/// it is. Refusing is mandatory: detouring both would send one cert path to the
/// other's deny block.
#[test]
fn classic_hrl_refuses_when_two_check_sites_disagree_on_the_revoke_target() {
    let mut img = fixture();
    plant_hrl_routine(&mut img, HRL);
    plant_revoke_head(&mut img, REVOKE);
    plant_revoke_head(&mut img, REVOKE + 0x40);
    plant_hrl_site(&mut img, 0x001c_5280, HRL, REVOKE);
    plant_hrl_site(&mut img, 0x001c_52c0, HRL, REVOKE + 0x40);
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect_err("disagreeing revoke targets must refuse");
    assert!(
        format!("{e:#}").contains("disagree on the revoke target"),
        "got: {e:#}"
    );
    assert_eq!(out, img, "a refused emit must not have touched the image");
}

/// Sites that AGREE must be accepted — the agreement guard has to be a real
/// comparison, not an unconditional accept/reject. (The accept direction is
/// covered by the positive test above; this pins the *count*, i.e. that the
/// second agreeing site is kept rather than treated as a conflict.)
#[test]
fn classic_hrl_keeps_every_agreeing_site_rather_than_stopping_at_the_first() {
    let (img, sites) = classic_hrl_image();
    let mut out = img.clone();
    let (got, _) = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect("classic hrl emit");
    assert_eq!(
        got.len(),
        2,
        "both agreeing cert-path sites must be detoured; leaving one OEM means a revoked \
         host cert is still rejected on that path"
    );
    assert_eq!(got[1], sites[1] as u32);
}

/// The classic `bl hrl; b <check>` layout: the check is reached through a single
/// unconditional T2 `b`, and the `b` here is BACKWARD (`imm11 >= 0x400`), so the
/// hop's displacement must be sign-extended. Without the hop — or with the hop
/// mis-decoded — the site is never found and HRL silently ships unwired.
///
/// A decoy `cmp r0,#0; bne <not-the-head>` sits 8 bytes before the hop target,
/// so the hop has to land EXACTLY on its computed address: an off-by-one branch
/// arithmetic error drops the walk onto the decoy and adopts a foreign revoke
/// target instead of quietly resolving the right site anyway.
#[test]
fn classic_hrl_follows_one_backward_unconditional_b_to_reach_the_check() {
    let mut img = fixture();
    plant_hrl_routine(&mut img, HRL);
    plant_revoke_head(&mut img, REVOKE);

    let bl_at = 0x001c_5280usize;
    let check = 0x001c_5240usize;
    let bl = thumb::encode_bl(bl_at, HRL as u32).expect("bl in range");
    thumb::write(&mut img, bl_at, &bl);
    // `b <check>`: pc = (bl_at+4)+4, imm11 is signed and here NEGATIVE.
    let d = (check as isize - (bl_at as isize + 8)) / 2;
    assert!((-1024..0).contains(&d), "the hop must be backward");
    put_hw(&mut img, bl_at + 4, &[0xE000 | ((d as u16) & 0x7FF)]);
    put_hw(
        &mut img,
        check - 8,
        &[0x2800, bne_to(check - 6, DECOY_TARGET)],
    );
    put_hw(&mut img, check, &[0x2800, bne_to(check + 2, REVOKE)]);

    let mut out = img.clone();
    let (sites, stub_va) = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect("the `bl hrl; b <check>` layout must resolve");
    assert_eq!(
        sites,
        vec![check as u32],
        "the site is the `cmp r0,#0` on the far side of the unconditional `b`"
    );
    assert_eq!(
        thumb::decode_bl(&out, check),
        Some(stub_va),
        "the detour must be installed at the hopped-to check, not at the `b`"
    );
}

/// The walk must start AFTER the `bl <hrl>`: the check that matters is the one
/// testing the lookup's result. A `cmp r0,#0; bne` sitting just BEFORE the call
/// tests something else entirely, and anchoring on it sends the HRL stub to a
/// foreign revoke target.
#[test]
fn classic_hrl_ignores_a_cmp_bne_that_precedes_the_lookup_call() {
    let mut img = fixture();
    plant_hrl_routine(&mut img, HRL);
    plant_revoke_head(&mut img, REVOKE);
    let bl_at = 0x001c_5280usize;
    // A decoy `cmp r0,#0; bne <elsewhere>` immediately before the call. Its
    // target is erased flash, so anchoring on it cannot pass the head check.
    put_hw(
        &mut img,
        bl_at - 4,
        &[0x2800, bne_to(bl_at - 2, 0x001c_5300)],
    );
    let site = plant_hrl_site(&mut img, bl_at, HRL, REVOKE);

    let mut out = img.clone();
    let (sites, _) = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect("the real post-call check must still resolve");
    assert_eq!(
        sites,
        vec![site as u32],
        "only the check AFTER the `bl <hrl>` is a cert-path site"
    );
}

/// The forward walk is budgeted. A `bl <hrl>` that is NOT a cert-path call (the
/// routine has other callers) must contribute no site — the budget is what stops
/// the walk running on until it trips over an unrelated `cmp r0,#0; bne` and
/// poisons the agreement check.
#[test]
fn classic_hrl_walk_stops_at_its_step_budget_after_a_non_cert_path_call() {
    let (mut img, sites) = classic_hrl_image();
    let orphan = 0x001c_6000usize;
    let bl = thumb::encode_bl(orphan, HRL as u32).expect("bl in range");
    thumb::write(&mut img, orphan, &bl);
    // The walk checks p = orphan+4 .. orphan+82 (40 steps). Park an unrelated
    // `cmp r0,#0; bne` at the FIRST halfword past the budget.
    let past = orphan + 84;
    put_hw(&mut img, past, &[0x2800, bne_to(past + 2, past + 0x40)]);

    let mut out = img.clone();
    let (got, _) = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect("the two real cert-path sites must still resolve");
    assert_eq!(
        got,
        vec![sites[0] as u32, sites[1] as u32],
        "a `cmp r0,#0; bne` beyond the walk budget must NOT be adopted as a cert-path \
         site — it disagrees with the real revoke target and would fail the whole emit"
    );
}

/// The lookup routine must be unique image-wide. Two matches means the signature
/// is not identifying the routine on this image.
#[test]
fn classic_hrl_refuses_a_non_unique_or_absent_lookup_routine() {
    let img = fixture();
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect_err("no classic HRL routine — must refuse");
    assert!(format!("{e:#}").contains("matched 0 time(s)"), "got: {e:#}");

    let (mut img, _) = classic_hrl_image();
    plant_hrl_routine(&mut img, HRL + 0x80);
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect_err("two classic HRL routines — must refuse");
    assert!(format!("{e:#}").contains("matched 2 time(s)"), "got: {e:#}");
}

/// A `bl <hrl>` with no cert-path check anywhere is not a cert path: the emit
/// must refuse (HRL left unwired) rather than invent a revoke target.
#[test]
fn classic_hrl_refuses_when_no_cert_path_check_site_resolves() {
    let mut img = fixture();
    plant_hrl_routine(&mut img, HRL);
    plant_revoke_head(&mut img, REVOKE);
    let bl = thumb::encode_bl(0x001c_5280, HRL as u32).expect("bl in range");
    thumb::write(&mut img, 0x001c_5280, &bl);
    let mut out = img.clone();
    let e = Mt1959Engine
        .emit_hrl_classic(&img, &mut out, FLAG_BASE)
        .expect_err("no `cmp r0,#0; bne` after the call — must refuse");
    assert!(
        format!("{e:#}").contains("no classic HRL cert-path"),
        "got: {e:#}"
    );
}

/// Every halfword of the version-invariant OEM `6F`-deny head is load-bearing.
/// Corrupting any ONE of them must make the emit refuse: a revoke target that is
/// not the OEM deny head means the `bne` we decoded points somewhere else, and
/// the skip stub would `bx` into the middle of an unrelated routine on every
/// revoked cert.
#[test]
fn classic_hrl_refuses_when_any_single_halfword_of_the_oem_6f_deny_head_is_wrong() {
    // (offset into the head, replacement halfword, what it breaks)
    let cases: [(usize, u16, &str); 4] = [
        (
            0,
            0x78A0,
            "ldrb r0,[r5,#2] (classic r5 — 0x78A0 is the MODERN r4 head)",
        ),
        (2, 0x2801, "cmp r0,#0"),
        (4, 0xD000, "bne <loop>"),
        (6, 0x2000, "movs r0,#0x6f (the 6F copy-protection sense)"),
    ];
    for (off, bad, what) in cases {
        let (mut img, _) = classic_hrl_image();
        put_hw(&mut img, REVOKE + off, &[bad]);
        let mut out = img.clone();
        let e = match Mt1959Engine.emit_hrl_classic(&img, &mut out, FLAG_BASE) {
            Err(e) => e,
            Ok(got) => panic!(
                "a broken `{what}` in the revoke head must REFUSE, but the emit succeeded \
                 with {got:x?} — a mis-anchored revoke target corrupts the cert path"
            ),
        };
        assert!(
            format!("{e:#}").contains("lacks the OEM 6F-deny head"),
            "broken `{what}`: got {e:#}"
        );
        assert_eq!(out, img, "a refused emit must not have touched the image");
    }
}

/// A revoke target that runs off the end of the image must refuse, not index
/// past the tail.
#[test]
fn classic_hrl_refuses_a_revoke_target_without_room_for_the_head() {
    let (mut img, _) = classic_hrl_image();
    put_hw(&mut img, REVOKE, &[0xFFFF]);
    let mut out = img.clone();
    assert!(
        Mt1959Engine
            .emit_hrl_classic(&img, &mut out, FLAG_BASE)
            .is_err(),
        "a revoke target without the OEM head must refuse"
    );
}

// ---------------------------------------------------------------------------
// build_report_classic / build_modify_classic  (whole-path)
// ---------------------------------------------------------------------------

/// A "classic" image: the BU40N fixture with a classic `~0x1a4000` dispatch
/// table, the classic region anchor, the classic VID/AKE gates and the classic
/// HRL cert path all grafted on.
fn classic_full_image() -> Vec<u8> {
    let mut img = fixture();

    // Classic 0x3C dispatch table: 12 coherent records (the finder needs a run
    // of >= 8), one of them the live 0x3C pointing at the OEM handler.
    for i in 0..12usize {
        let p = TABLE + i * 8;
        img[p..p + 8].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    }
    let live = TABLE + 5 * 8;
    img[live] = crate::abi::READ_BUFFER_OPCODE;
    img[live + 1] = LIVE_FLAGS;
    img[live + 4..live + 8].copy_from_slice(&OEM_3C_HANDLER.to_le_bytes());

    put_hw(
        &mut img,
        REGION,
        &[
            0x466B, 0x789B, 0x18D2, 0x7202, 0x466B, 0x78DA, 0x7202, 0x7204, 0x7201, 0xBD18,
        ],
    );
    plant_vid_gate(&mut img, VID, 0x12);
    plant_ake_gate(&mut img, AKE);
    plant_hrl_routine(&mut img, HRL);
    plant_revoke_head(&mut img, REVOKE);
    plant_hrl_site(&mut img, 0x001c_5280, HRL, REVOKE);
    plant_hrl_site(&mut img, 0x001c_52c0, HRL, REVOKE);
    img
}

/// Whole classic CREATE path. The assertions that matter are the ones a wrong
/// value would make invisible: the dispatch record must be repointed at the
/// injected handler **with the Thumb bit set** (an even handler address faults
/// the drive on the first vendor CDB), and every reported feature fact must be
/// the address actually patched — the report is what the audit and the KAT
/// check against.
#[test]
fn classic_create_repoints_the_record_thumb_tagged_and_reports_the_real_facts() {
    let img = classic_full_image();
    let r = Mt1959Engine
        .build_report_classic(&img)
        .expect("classic create on the grafted classic image");

    assert_eq!(
        thumb::read_u32(&r.image, r.record.off + 4),
        r.handler_va | 1,
        "the classic 0x3C record must point at the injected handler with the Thumb bit \
         set; a cleared bit switches the core to ARM mode on the first vendor CDB"
    );
    assert_eq!(
        r.image[r.record.off + 1],
        LIVE_FLAGS,
        "the record's media-gated flags must stay live"
    );
    assert_ne!(r.handler_va, 0, "the handler must be injected somewhere");
    assert_eq!(r.cdb_base, 0x0200_0d38, "classic base: CDB base");
    assert_eq!(r.flag_base, 0x0200_120c, "classic base: derived SRAM cell");

    // Feature facts must be the grafted addresses, not neighbouring fields.
    assert_eq!(
        r.gatea_gate,
        (VID + 30) as u32,
        "the Gate-A fact must be the Gate-A site — reading a neighbouring fact out of \
         the raw-read key/value list silently mislabels the whole report"
    );
    assert_eq!(r.ake_gate, AKE as u32, "the AKE anchor fact");
    assert_eq!(
        r.deny_reset_gate,
        (VID + 36 + 18 * 2) as u32,
        "the deny fact"
    );
    assert_eq!(r.vid_producer, 0x0013_675c, "the VID producer fact");
    assert_eq!(r.region_emitter, REGION as u32, "the region emitter fact");
    assert_eq!(
        r.hrl_sites,
        vec![0x001c_5288, 0x001c_52c8],
        "both classic HRL cert-check sites must be reported"
    );
    assert_ne!(r.boot_stub_va, 0, "the always-on boot hook must be emitted");
    assert_ne!(r.region_stub_va, 0);
    assert_ne!(r.gatea_stub_va, 0);
    assert_ne!(r.ake_stub_va, 0);
    assert_ne!(r.hrl_stub_va, 0);
    assert_eq!(r.de_off, 0x001e_c056, "the DE byte offset");
    assert_eq!(r.image[r.de_off as usize], 0xDE, "DE byte written");
    assert_eq!(r.image.len(), img.len());

    // Classic never wires Speed or the deny detour.
    assert_eq!(
        r.speed_gate, 0,
        "Speed is a documented classic architecture miss"
    );
    assert_eq!(r.deny_stub_va, 0, "classic ships no deny-reset detour");
}

/// **The classic safety coupling.** The boot-init hook is what writes `0xFF`
/// into every flag byte at power-on, and that 0xFF-fill is the only reason the
/// tri-state `0x00 == OFF` convention is safe. If the boot hook cannot be
/// emitted, the build MUST fall back to a bare base and ship NO feature stub —
/// otherwise a freshly powered drive boots every feature into its OFF state
/// (region-locked, BD refused). This is the single most important invariant on
/// the classic path, so it is tested by actually breaking the boot site.
#[test]
fn classic_create_ships_no_feature_stub_when_the_boot_hook_cannot_be_emitted() {
    let mut img = classic_full_image();
    // Blow away the cold/warm-boot convergence `bl <orig_init>` so
    // `resolve_boot_init_pair` cannot resolve a site.
    let conv = Mt1959Engine
        .resolve_boot_init_pair(&img)
        .expect("the fixture normally resolves a boot-init pair")
        .0;
    put_hw(&mut img, conv, &[0x0000, 0x0000]);
    assert!(
        Mt1959Engine.resolve_boot_init_pair(&img).is_err(),
        "precondition: the boot-init pair must now be unresolvable"
    );

    let r = Mt1959Engine
        .build_report_classic(&img)
        .expect("the BARE classic base must still ship");

    assert_eq!(r.boot_init_site, 0, "no boot hook");
    assert_eq!(r.boot_stub_va, 0, "no boot stub");
    // ... and therefore NOTHING flag-gated.
    for (what, va) in [
        ("region", r.region_stub_va),
        ("Gate-A", r.gatea_stub_va),
        ("AKE", r.ake_stub_va),
        ("UHD", r.uhd_stub_va),
        ("BD", r.bd_stub_va),
        ("HRL", r.hrl_stub_va),
    ] {
        assert_eq!(
            va, 0,
            "{what} stub was emitted WITHOUT the boot-init 0xFF fill — a freshly powered \
             drive would boot that feature into its OFF state"
        );
    }
    assert!(
        r.hrl_sites.is_empty(),
        "no HRL sites may be detoured either"
    );
    // The bare base itself still ships (handler + record repoint + DE + re-sign).
    assert_ne!(r.handler_va, 0, "the bare base must still be produced");
    assert_eq!(r.image[r.de_off as usize], 0xDE, "DE is boot-independent");
}

/// Whole classic MODIFY path: the same base, reported as levers. Identity,
/// Region-free and Raw-read must all come back Applied, the HRL facts must be
/// folded into the Raw-read lever (so classic create and modify stay
/// byte-identical), and the record must be repointed Thumb-tagged.
#[test]
fn classic_modify_applies_every_classic_lever_and_folds_in_the_hrl_facts() {
    let img = classic_full_image();
    let chip = crate::family::detect_chip(&img).expect("chip");
    let cap = crate::family::capability_for(&chip.model, chip.family);
    let r = Mt1959Engine
        .build_modify_classic(&img, &chip, &cap)
        .expect("classic modify must produce a report, not refuse");

    let get = |id| {
        r.levers
            .iter()
            .find(|l| l.id == id)
            .unwrap_or_else(|| panic!("{id:?} lever present"))
    };
    assert_eq!(get(LeverId::Identity).outcome, LeverOutcome::Applied);
    assert_eq!(get(LeverId::RegionFree).outcome, LeverOutcome::Applied);
    assert_eq!(get(LeverId::RawRead).outcome, LeverOutcome::Applied);
    assert!(get(LeverId::DowngradeEnable).outcome.is_effective());
    assert!(
        matches!(
            get(LeverId::Speed).outcome,
            LeverOutcome::SignatureNotFound { .. }
        ),
        "Speed has no classic ramp-ceiling gate to detour"
    );

    let rr = get(LeverId::RawRead);
    let fact = |k: &str| rr.facts.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
    assert_eq!(fact("gatea_gate"), Some((VID + 30) as u32));
    assert!(
        fact("hrl_stub_va").is_some_and(|v| v != 0),
        "the HRL stub VA must be folded into the RawRead lever — without it classic \
         create and modify produce different images from the same base"
    );
    assert_eq!(fact("hrl_site"), Some(0x001c_5288));
    assert_eq!(fact("hrl_site2"), Some(0x001c_52c8));

    let rec_off = get(LeverId::Identity)
        .facts
        .iter()
        .find(|(n, _)| *n == "record_off")
        .unwrap()
        .1 as usize;
    let handler_va = get(LeverId::Identity)
        .facts
        .iter()
        .find(|(n, _)| *n == "handler_va")
        .unwrap()
        .1;
    assert_eq!(
        thumb::read_u32(&r.image, rec_off + 4),
        handler_va | 1,
        "the classic record must be repointed at the injected handler, Thumb-tagged"
    );
}

/// An image with nothing to modify must refuse — but an image where levers DID
/// apply must never refuse. Inverting that test turns every successful classic
/// modify into "nothing modifiable on this classic MT1939 image".
#[test]
fn classic_modify_returns_a_report_whenever_any_lever_is_effective() {
    let img = classic_full_image();
    let chip = crate::family::detect_chip(&img).expect("chip");
    let cap = crate::family::capability_for(&chip.model, chip.family);
    let r = Mt1959Engine
        .build_modify_classic(&img, &chip, &cap)
        .expect("levers applied — must not bail with `nothing modifiable`");
    assert!(
        r.levers.iter().any(|l| l.outcome.is_effective()),
        "precondition for the refusal guard: at least one lever is effective"
    );
}

/// Signature sanity: none of the grafted classic shapes exist in the untouched
/// modern fixture, so every classic test above is measuring its own graft and
/// not a coincidental match in OEM code.
#[test]
fn the_modern_fixture_carries_none_of_the_classic_signatures() {
    let img = fixture();
    for (name, sig) in [
        ("VID_GATE_SIG_CLASSIC", VID_GATE_SIG_CLASSIC),
        ("AKE_GATE_SIG_CLASSIC", AKE_GATE_SIG_CLASSIC),
        ("HRL_LOOKUP_SIG_CLASSIC", HRL_LOOKUP_SIG_CLASSIC),
    ] {
        assert!(
            masked_matches(&img, sig, 0, img.len()).is_empty(),
            "{name} must not match the modern BU40N fixture"
        );
    }
}
