//! MT1959 grounded find/build/patch — the *knowledge* the dumb [`crate::thumb`]
//! verbs are pointed at, all **derived from the drive's own code**, never
//! hardcoded.
//!
//! Every fact used to build the freemkv firmware is recovered from a consumer in
//! the image and cross-checked, so a wrong fact fails loudly at the find rather
//! than silently on hardware:
//!
//! * the command-dispatch record format is proven by the **scanner** (the code
//!   that reads the table): it does `ldrb [rec+1]`=flags, `ldrb [rec]`=opcode,
//!   `ldr [rec+4]`=handler — so records are `opcode@0 / flags@1 / handler@4`;
//! * `cdb_base` is the literal the scanner loads to read the incoming CDB;
//! * the sense-setter is the routine the scanner tail-calls to raise a sense;
//! * the `0x3C` handler is the unique live record for that opcode, its handler
//!   pointer cross-checked to land on a real `push {…,lr}` prologue.
//!
//! The freemkv command is a hijack of the standard `READ BUFFER` (`0x3C`)
//! handler, discriminated by an OEM-unused mode: `cdb[1]==0x0E` plus a `C0 DE`
//! knock at `cdb[2..4]`. On a match the handler dispatches on the sub-function
//! (`cdb[4]`) and returns a data payload via the drive's own response path
//! (byte-writer + commit); on a miss it tail-calls the original handler, so OEM
//! behaviour is byte-identical. `flags` stays `0x01` — which on hardware is a
//! drive-*ready* gate, NOT a media gate: the command answers with no disc.

use anyhow::{anyhow, bail, Context, Result};

use freemkv_flash::cmac;

use super::lever::{LeverId, LeverReport, ModifyReport, Validation};
use super::mt1959::Mt1959Engine;
use super::CreateReport;
use crate::abi;
use crate::family::{Capability, ChipInfo, MediaClass};
use crate::thumb::{self, Asm, CommandRecord, CommandTable};

/// Grounded facts produced by the Raw-read lever (VID + AKE + Gate-A + deny).
struct RawReadFacts {
    ake_gate: u32,
    /// The AKE detour `bl` site (where the redirect was written) — needed by the
    /// structural audit to recompute the expected hook via `encode_bl`.
    ake_site: u32,
    ake_stub_va: u32,
    gatea_cmp: u32,
    gatea_stub_va: u32,
    deny_site: u32,
    deny_stub_va: u32,
    /// `04 03` "data clear" bus-off detour site — the OEM `bl <key-prog>` at the start
    /// of the AACS opcode-0x45 arm, replaced by a `bl` to the busenc stub. `0` when not
    /// wired (image whose opcode-0x45 arm is not a known MT1959 shape).
    busenc_site: u32,
    /// Injection address of the `04 03` bus-off (MK-style bit-clear) trampoline.
    /// `0` when not wired.
    busenc_stub_va: u32,
    /// `04 03` UHD mode-gate neutralizer detour site — the classifier prologue's
    /// disc-version reload (`UHD_CLASSIFIER_SIG` match+6), replaced by a `bl` to the
    /// UHD stub. `0` when not wired (image whose classifier prologue is not the known
    /// MT1959 shape).
    uhd_site: u32,
    /// Injection address of the `04 03` UHD mode-gate neutralizer trampoline. `0`
    /// when not wired.
    uhd_stub_va: u32,
    /// The three HRL-skip cert-path detour sites (`flag[Feature::Hrl]==STATE_ON`):
    /// each is a `cmp r0,#0; bne <6F/00>` replaced by a `bl` to the shared HRL-skip
    /// stub. Empty when the HRL cert path is not the known shape (lever MISS).
    hrl_sites: Vec<u32>,
    /// Injection address of the shared HRL-skip trampoline. `0` when not wired.
    hrl_stub_va: u32,
    vid_producer: u32,
}

// The wire frame (opcode / mode / knock / identity sense) is defined once in
// `crate::abi` and imported here — the engine emits exactly what the host ABI
// describes, so the two can never drift.

/// Record flags on the live `0x3C` record. `0x01` is a drive-*ready* gate (NOT a
/// media gate — proven on hardware: the command answers with no disc), which is
/// exactly how OEM ships it. Engine-specific (a property of this firmware's
/// dispatch table), so it lives here rather than in the wire ABI.
pub const LIVE_FLAGS: u8 = 0x01;

/// Chip-family flag value marking a chain record in the dispatch table.
const CHAIN_FLAG: u8 = 0x04;
/// Flag value marking a segment terminator.
const TERM_FLAG: u8 = 0x03;
/// Record stride in bytes.
const STRIDE: usize = 8;
/// Window the dispatch table is searched within.
const TABLE_LO: usize = 0x0014_0000;
const TABLE_HI: usize = 0x0016_0000;
/// Minimum contiguous valid records to treat a byte range as a real table run.
const MIN_RUN: usize = 8;
/// Where injected code may live (past the loader); the scanner region and
/// beyond. Free space is searched from here up.
const CODE_REGION_START: usize = 0x0000_9c00;

/// Bytes cleared in the response buffer before writing a reply (so no stale
/// buffer data leaks into the padding beyond the payload).
const CLEAR_LEN: u8 = 64;
/// Number of feature flags (Feature ids `0x01..=0x07`). Sizes the SRAM flag
/// table, bounds the [`abi::Verb::Reset`] sweep, and sizes the
/// [`abi::Verb::Identity`] feature-state table appended after the magic+version.
const NUM_FEATURES: u8 = 7;

/// The SRAM (on-chip working RAM) window scanned by [`Mt1959Engine::find_free_sram_cell`]
/// and holding every runtime flag/scratch cell.
const SRAM_LO: u32 = 0x0200_0000;
const SRAM_HI: u32 = 0x0200_2000;

/// Mapped-SRAM ceiling for the MT1959 family (a chip constant).
///
/// **Confirmation model — empirical, not documentary.** No MT1959 datasheet,
/// boot-ROM dump, or memory map is public (MediaTek ODD-controller specs are
/// NDA-only and none has leaked; the vendor page lists speeds only). So this
/// bound is proven on the actual silicon, by three converging lines of evidence
/// — which is *ground truth*, arguably stronger than a rev-specific spec sheet:
///   1. runtime full-RAM capture — highest non-zero byte is `0x020019ff`, then a
///      hard all-zero void;
///   2. hardware write-persistence — writes at/above `0x02001a00` are read-as-
///      zero and discarded (exactly why the old `0x02001a00` flag base silently
///      failed), while writes below persist;
///   3. static code refs — the image never touches SRAM at/above this bound.
///
/// Real RAM is `[SRAM_LO, SRAM_END)`; a flag/scratch cell MUST live below
/// `SRAM_END`, and [`Mt1959Engine::assert_sram_cell_free`] re-checks that per
/// image at build time so the derivation can never silently rot.
const SRAM_END: u32 = 0x0200_1a00;

/// Flag-table base in on-chip SRAM (a chip constant, like the other `0x0200_xxxx`
/// cells the OEM code loads — not a flash offset, so it is a literal, not a find).
///
/// The `3C 0E` handler persists each toggle's state to `FLAG_TABLE_BASE + subfn`,
/// and each OEM-code trampoline (Speed 0x02, Region 0x03) reads its own flag byte
/// there. It sits in a **204-byte free hole** at `0x02000e3c..0x02000f07`:
/// flash-unreferenced AND live-zero under the heaviest runtime in the full-RAM
/// capture, bracketed by live cells (`0x02000e38` below, `0x02000f08` above), and
/// byte-identical across all 24 owned MT1959 images (1.00–1.04 + variants, all
/// 1.03 MK models). See `research/libredrive/mtk/SRAM_FLAG_CELL.md`.
///
/// This REPLACES the earlier placeholder `0x02001a00`, which hardware proved is
/// the FIRST UNMAPPED address (reads-zero, writes discarded) — not free RAM. The
/// build-time "largest unreferenced gap" scanner ([`Mt1959Engine::find_free_sram_cell`])
/// is unsound (it picked `0x0200120c`, which is live-in-use via computed base
/// pointers) and is retained only for audit reporting.
const FLAG_TABLE_BASE: u32 = 0x0200_0e40;

/// Signature of the read-ramp CEILING gate inside the per-READ ramp writer
/// (`0x1bb22` on both OEM 1.00 and MK 1.03). The bare `cmp #0x32` is ambiguous
/// (the `0x32` "high-speed band" threshold has many consumers), so the full
/// four-instruction shape is matched and proven unique. The gate `cmp` is at
/// `match+4`, its `bhi <ramp-exit>` at `match+6`, and the ramp continues at
/// `match+8`. The Speed (0x02) detour replaces the `cmp/bhi` (4 bytes at
/// `match+4`) with a `bl` to a flag-gated stub; the ramp itself is UNTOUCHED.
const SPEED_GATE_SIG: &[(u16, u16)] = &[
    (0x4900, 0xFF00), // ldr r1,[pc,#imm]  (speed_index SRAM cell literal)
    (0x780A, 0xFFFF), // ldrb r2,[r1]       r2 = speed_index
    (0x2A32, 0xFFFF), // cmp r2,#0x32       ramp self-ceiling band
    (0xD800, 0xFF00), // bhi <ramp-exit>    stop ramping once past the ceiling
];

/// `r0`-register variant of [`SPEED_GATE_SIG`]. Some builds (LG BU40N 1.04/1.05
/// "Original Flasher"/-INTM, and the whole NB-class BP50NB40/BP55EB40/WP50NB40
/// line) load the ramp `speed_index` into `r0` instead of `r2`; the gate is
/// otherwise byte-identical (same `ldr r1,[pc]` cell, same `#0x32` band, same
/// `bhi`), so the gate `cmp` is still at `match+4` and `bhi` at `match+6`.
///
/// PROVEN (research/hoard-campaign-2026-09-03): unique per image on all 15
/// affected MT1959 images, never ambiguous, never overlapping [`SPEED_GATE_SIG`],
/// and **zero matches** in the BU40N 1.00 KAT base (which matches the original) —
/// original-first keeps the KAT byte-identical. `r0` is redefined immediately
/// after the gate (`ldrb r0,[r5,#5]`), i.e. DEAD at both the fall-through and
/// ramp-exit targets, which is what lets the variant stub use it as scratch.
const SPEED_GATE_SIG_R0: &[(u16, u16)] = &[
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]  (speed_index SRAM cell literal)
    (0x7808, 0xFFFF), // ldrb r0,[r1]       r0 = speed_index (variant register)
    (0x2832, 0xFFFF), // cmp  r0,#0x32      ramp self-ceiling band
    (0xD800, 0xFF00), // bhi  <ramp-exit>
];

/// Signature of the AACS AKE per-AGID state writers at the tail of the
/// key-exchange step handler (`0x136594` on 1.00, `0x13697c` on 1.03 MK —
/// byte-identical). The two writers sit back-to-back: the SUCCESS writer sets the
/// per-AGID state to `6` (AKE authenticated), the RESET writer sets it to `1`
/// (auth failed). Reaching state `6` is the whole VID gate. The RESET writer is the
/// cert accept/reject decision: on a failed host-cert verify the OEM lands here and
/// resets to `1`. Raw Read (0x04) detours the RESET writer's `movs r1,#1; b <back>`
/// (4 bytes at `match+12`) to a flag-gated stub that sets `6` (accept) when
/// `flag[RawRead]` is on, replicating the OEM `1` when off. Proven unique; the two
/// `b <back>` displacements are masked (`0xE000/0xF800`). `movs r1,#6` is unique in
/// the AACS window, which anchors the match.
const AKE_GATE_SIG: &[(u16, u16)] = &[
    (0x7AA8, 0xFFFF), // ldrb r0,[r5,#0xa]   AGID byte
    (0x0980, 0xFFFF), // lsrs r0,r0,#6       r0 = AGID
    (0x2106, 0xFFFF), // movs r1,#6          success: state 6 (authenticated)
    (0xE000, 0xF800), // b <set_agid_state>
    (0x7AA8, 0xFFFF), // ldrb r0,[r5,#0xa]
    (0x0980, 0xFFFF), // lsrs r0,r0,#6       r0 = AGID
    (0x2101, 0xFFFF), // movs r1,#1          reset: state 1  ← detour site (match+12)
    (0xE000, 0xF800), // b <set_agid_state>
];

/// NB-class (LG BP50NB40 / BP55EB40 / WP50NB40 portable) variant of the AKE
/// accept gate. RE'd from `HL-DT-ST_BP50NB40_N1.01` (anchor `0x13405a`),
/// proven-unique across the NB corpus and 0-match on every BU40N image. Two
/// differences from [`AKE_GATE_SIG`] that make the original miss and require a
/// distinct detour: the AGID byte is read via `r4` (not `r5`), and — critically —
/// the accept (`movs r1,#6`) and reject (`movs r1,#1`) arms **converge on a
/// single shared `bl set_agid_state`** at `anchor+12` (the accept arm's `b` lands
/// there) instead of each ending in its own `b`. So the reject writer is a bare
/// 2-byte `movs r1,#1` at `anchor+10` and `anchor+12` is the shared `bl`. Raw
/// Read detours that shared `bl` (see [`Mt1959Engine::build_ake_stub_nb`]) — the
/// stub must PRESERVE `r1` when the flag is off (the accept arm passes through it
/// too), forcing `6` only when `flag[RawRead]==2`.
const AKE_GATE_SIG_NB: &[(u16, u16)] = &[
    (0x7AA0, 0xFFFF), // ldrb r0,[r4,#0xa]   AGID byte (r4, not r5)
    (0x0980, 0xFFFF), // lsrs r0,r0,#6       r0 = AGID   (accept arm)
    (0x2106, 0xFFFF), // movs r1,#6          accept: state 6
    (0xE000, 0xF800), // b <shared bl @ +12>
    (0x0980, 0xFFFF), // lsrs r0,r0,#6       reject arm (no second ldrb)
    (0x2101, 0xFFFF), // movs r1,#1          reject: state 1   (bare, 2 bytes)
                      // anchor+12 = `bl set_agid_state`, the shared join both arms reach ← detour site
];

/// NB-class **`1.V5`** variant of the AKE accept gate. RE'd from the two
/// `WH16NS58 1.V5` images (`unMK_WH16NS58_1.V5_N004900` + its MK sibling,
/// anchor `0x13a254`), where BOTH [`AKE_GATE_SIG`] and [`AKE_GATE_SIG_NB`] match
/// 0×. It is a hybrid of the two shapes:
///
/// * like [`AKE_GATE_SIG_NB`], the AGID byte is read via `r4` (not `r5`) and the
///   accept (`movs r1,#6`) and reject (`movs r1,#1`) arms **converge on one
///   shared `bl set_agid_state`** (the accept arm's `b` lands on it) rather than
///   each ending in its own `b`;
/// * unlike `AKE_GATE_SIG_NB` — and like the desktop [`AKE_GATE_SIG`] — the
///   reject arm **re-reads** the AGID byte (`ldrb r0,[r4,#0xa]; lsrs r0,r0,#6`)
///   instead of falling straight into a bare `lsrs`. That extra `ldrb` (2 bytes)
///   pushes the reject writer to `anchor+12` and the shared `bl` to `anchor+14`.
///
/// PROVEN (fleet scan, `[0x130000,0x140000)`): unique per image (n=1) on exactly
/// the 2 `1.V5` images, **zero matches** on every other hoard image, and neither
/// `AKE_GATE_SIG` nor `AKE_GATE_SIG_NB` matches the `1.V5` images — so the three
/// variants never overlap and existing coverage is untouched. The Raw Read detour
/// replaces the shared `bl` at `anchor+14` and reuses the NB stub verbatim
/// ([`Mt1959Engine::build_ake_stub_nb`]): both arms reach the join with `r1`
/// already set, so the stub must PRESERVE `r1` when the flag is off.
const AKE_GATE_SIG_NB_V5: &[(u16, u16)] = &[
    (0x7AA0, 0xFFFF), // ldrb r0,[r4,#0xa]   AGID byte (r4)   (accept arm)
    (0x0980, 0xFFFF), // lsrs r0,r0,#6       r0 = AGID
    (0x2106, 0xFFFF), // movs r1,#6          accept: state 6
    (0xE000, 0xF800), // b <shared bl @ +14>
    (0x7AA0, 0xFFFF), // ldrb r0,[r4,#0xa]   reject arm RE-READS (unlike NB)
    (0x0980, 0xFFFF), // lsrs r0,r0,#6       r0 = AGID
    (0x2101, 0xFFFF), // movs r1,#1          reject: state 1  ← reject writer @ anchor+12
                      // anchor+14 = `bl set_agid_state`, the shared join both arms reach ← detour site
];

/// Signature of the OEM REPORT KEY key-format-8 (RPC state) emitter tail
/// (`0x119890` on 1.00, `0x119a84` on 1.03) — the byte-for-byte identical run
/// that marshals the 8-byte RPC-state frame into the response FIFO. RPCScheme is
/// hardcoded to `1` (RPC-2) via `r4`; the `frame[4]` store `strb r2,[r0,#8]` is
/// at `match+6`. Region-free (0x03) detours from there (4 bytes at `match+6`,
/// consuming the following `mov r3,sp` too) to a flag-gated stub that re-emits
/// `frame[4..7]` — zeroing TypeCode/RegionMask/RPCScheme for a golden-MK RPC-1
/// frame when set, OEM otherwise. Proven unique per image. (`r1==0`, `r4==1`.)
const REGION_EMIT_SIG: &[(u16, u16)] = &[
    (0x466B, 0xFFFF), // mov  r3,sp
    (0x789B, 0xFFFF), // ldrb r3,[r3,#2]   s2
    (0x18D2, 0xFFFF), // adds r2,r2,r3
    (0x7202, 0xFFFF), // strb r2,[r0,#8]   frame[4] = TypeCode/resets/changes ← detour
    (0x466B, 0xFFFF), // mov  r3,sp        (consumed by the 4-byte bl)
    (0x78DA, 0xFFFF), // ldrb r2,[r3,#3]   s3 (RegionMask source, re-read by the stub)
    (0x7202, 0xFFFF), // strb r2,[r0,#8]   frame[5] = RegionMask
    (0x7204, 0xFFFF), // strb r4,[r0,#8]   frame[6] = RPCScheme (r4==1)
    (0x7201, 0xFFFF), // strb r1,[r0,#8]   frame[7] = 0 (reserved)
    (0xBD18, 0xFFFF), // pop  {r3,r4,pc}   emitter epilogue (replicated by the stub)
];

/// Byte offset of the downgrade-enable (DE) byte within the ASCII drive-descriptor
/// record ([`crate::family::DESCRIPTOR_OFFSET`]). The record's family tag
/// `"MTEKMT19.."` sits at `+0x34`; a within-family variant marker (`0x78/0x58/
/// 0x18/0x38`, NOT an invariant) sits at `+0x50`; the DE slot is at `+0x56`.
/// Verified across the owned MT1959 image set.
const DE_BYTE_OFF: usize = 0x56;

/// Signature of the VID gate's address-compute tail inside the OEM Volume-ID
/// producer, ending in the per-AGID auth-state probe `ldrb r0,[r0]; cmp r0,#6;
/// bne <skip>`. Proven byte-identical in shape across OEM 1.00 and MK 1.03 (only
/// the pc-relative `ldr` imm8s and the `bne` displacement differ, so those are
/// masked). Unique per image — the anchor for the producer and its scratch
/// buffer. The gate `ldrb` is at `match + 16`.
const VID_GATE_SIG: &[(u16, u16)] = &[
    (0x0400, 0xFFFF), // lsls r0,r0,#16
    (0x0C00, 0xFFFF), // lsrs r0,r0,#16
    (0x1808, 0xFFFF), // adds r0,r1,r0
    (0x4900, 0xFF00), // ldr r1,[pc,#imm]  (SRAM base-ptr cell)
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x6809, 0xFFFF), // ldr r1,[r1]
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x7800, 0xFFFF), // ldrb r0,[r0]      (auth-state byte) — the gate
    (0x2806, 0xFFFF), // cmp r0,#6
    (0xD100, 0xFF00), // bne <skip>
];

/// NB-class (LG BP/WP slim/portable: BP50NB40/BP55EB40/BP60NB10/WP50NB40) variant
/// of [`VID_GATE_SIG`]. The producer's address-compute tail differs only in its
/// FIRST TWO halfwords (`adds r0,r0,r1; ldr r1,[r5]` instead of the `lsls #16;
/// lsrs #16` pair) — the gate `ldrb r0,[r0]; cmp r0,#6; bne` and everything from
/// the `adds r0,r1,r0` onward are byte-identical, so the gate is still at
/// `match + 16` and its `cmp` at `match + 18` (no downstream offset change).
///
/// PROVEN (research/hoard-campaign-2026-09-03): RE'd from
/// `LG_BP60NB10_1.00_Official_Flasher.bin` (gate `ldrb` at `0x1369c8`) and
/// cross-checked on BP50NB40 / BP55EB40 / WP50NB40 (gate at `0x1341c8`). The NB
/// line has one address-compute shape with a single build-varying register: the
/// base of the `ldr r1,[rN]` deref is `r5` on BP60NB10 and `r6` on the others, so
/// that one field is masked (`0x6801, 0xFFC7` = `ldr r1,[rN,#0]`), everything
/// else exact. Verified **unique per image on 18 MT1959 images**, never ambiguous,
/// never overlapping [`VID_GATE_SIG`], and **zero matches** in the BU40N 1.00 KAT
/// base (which matches the original) — so trying the original first keeps the KAT
/// byte-identical while this recovers the VID/Raw-Read lever on the whole NB line.
const VID_GATE_SIG_NB: &[(u16, u16)] = &[
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x6801, 0xFFC7), // ldr  r1,[rN]      (SRAM base-ptr deref; rN = r5/r6 per build)
    (0x1808, 0xFFFF), // adds r0,r1,r0
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]  (SRAM base-ptr cell)
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x6809, 0xFFFF), // ldr  r1,[r1]
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x7800, 0xFFFF), // ldrb r0,[r0]      (auth-state byte) — the gate
    (0x2806, 0xFFFF), // cmp  r0,#6
    (0xD100, 0xFF00), // bne  <skip>
];

/// JB8 MT1939-generation VID-producer gate. The JB8 address-compute tail does the
/// SRAM byte-assembly in **two masking rounds** (a `#0x10` round then a `#8` round),
/// unlike the single round of [`VID_GATE_SIG`]/[`VID_GATE_SIG_NB`]. Cut so the gate
/// `ldrb r0,[r0]` still sits at `match + 16` (index 8), same as the other variants.
/// Reversed from `DE_LG_BH14NS50_1.01 @ 0x139774` (gate at `0x139784`). Proven
/// UNIQUE on every JB8-generation image and **zero matches** on BU40N + classic.
const VID_GATE_SIG_JB8: &[(u16, u16)] = &[
    (0x6809, 0xFFFF), // ldr  r1,[r1]      (round-1 SRAM base-ptr deref)
    (0x0C00, 0xFFFF), // lsrs r0,r0,#0x10
    (0x1808, 0xFFFF), // adds r0,r1,r0
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]  (round-2 SRAM base-ptr cell)
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x6809, 0xFFFF), // ldr  r1,[r1]
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x7800, 0xFFFF), // ldrb r0,[r0]      (auth-state byte) — the gate (match+16)
    (0x2806, 0xFFFF), // cmp  r0,#6
    (0xD100, 0xFF00), // bne  <skip>
];

/// Signature of `SetDiscMode`'s prologue — the read-datapath disc-mode dispatcher
/// (`0x43cb0` on 1.00). Its `subs r3,r4,#3` feeds a jump-table dispatch that
/// programs the scramble/sector MMIO. Unique per image. (`bl` displacement masked.)
const SETDISCMODE_SIG: &[(u16, u16)] = &[
    (0xB510, 0xFFFF), // push {r4,lr}
    (0x0004, 0xFFFF), // movs r4,r0        (r4 = mode)
    (0x2000, 0xFFFF), // movs r0,#0
    (0xF000, 0xF800), // bl <early-init>   hw1
    (0xD000, 0xD000), // bl                hw2
    (0x1EE3, 0xFFFF), // subs r3,r4,#3     (mode-3 jump-table index)
];

/// Signature of the OEM AACS command dispatcher's opcode-`0x45` (**Read Data Key**)
/// arm — the point MK's LibreDrive-family firmware detours to turn OFF the drive-side
/// bus-encryption stage (see [`Mt1959Engine::busenc_detour`]). The arm is the entry
/// the command dispatcher branches to for opcode `0x45` (`0x95eec` on BU40N 1.00),
/// and its first instruction is a `bl` into the OEM key-derivation primitive whose
/// target the injected stub REPLAYS so the OEM key programming still runs.
///
/// The dispatcher's *ladder* structure varies across the MT1959 fleet (a `cmp r3,#op`
/// chain on BU40N/BU50N + notebook, a `cmp r1,#op` binary search on the
/// BH/WH16NS60 / BE16NU50 / ASUS desktop sub-family), so the ladder is NOT a stable
/// anchor. The arm BODY, however, is byte-shape-invariant across the whole lineage:
/// `bl <key-prog>; movs r0,#6; muls r0,r4,r0; ldr r1,[pc,#imm]; ldrh r0,[r1,r0];
/// str r0,[sp,#0x24]`, with only the `bl`/`ldr` immediates and a one-op reordering
/// (`ldr r1,[pc]` before vs after `muls`) distinguishing two variants. Both variants
/// are matched (`_A` = BU40N/notebook order, `_B` = BH/WH desktop order); each is
/// proven UNIQUE per image and each image matches exactly ONE (A xor B) across the
/// owned desktop + notebook MT1959 fleet (JB8/MT1939-classic images also match `_B`
/// but never reach this finder — their AKE gate is absent, so `ake_detour` bails
/// first, leaving `04 03` unwired, which is the intended MT1939 = unsupported result).
///
/// The match offset IS the arm's leading `bl` (the detour site); the `bl`'s target
/// (the OEM key-prog primitive) is decoded and replayed by the stub. Register/bit for
/// the bus-off write are recovered at build time from the stub's own emitted constants
/// ([`BUSENC_REG`] = `1<<26`, [`BUSENC_ENABLE_BIT`]).
const AACS45_ARM_SIG_A: &[(u16, u16)] = &[
    (0xF000, 0xF800), // bl <key-prog>   hi   ← match = arm entry / detour site
    (0xF800, 0xF800), //                 lo
    (0x2006, 0xFFFF), // movs r0,#6
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]
    (0x4360, 0xFFFF), // muls r0,r4,r0
    (0x310C, 0xFFFF), // adds r1,#0xc
    (0x5A08, 0xFFFF), // ldrh r0,[r1,r0]
    (0x9009, 0xFFFF), // str  r0,[sp,#0x24]
];

/// BH/WH16NS60 / BE16NU50 / ASUS desktop variant of [`AACS45_ARM_SIG_A`] — same arm,
/// `ldr r1,[pc]` and `muls` reordered and no `adds r1,#0xc`. Tried after `_A` so the
/// BU40N KAT base stays byte-identical (its arm matches `_A`).
const AACS45_ARM_SIG_B: &[(u16, u16)] = &[
    (0xF000, 0xF800), // bl <key-prog>   hi   ← match = arm entry / detour site
    (0xF800, 0xF800), //                 lo
    (0x2006, 0xFFFF), // movs r0,#6
    (0x4360, 0xFFFF), // muls r0,r4,r0
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]
    (0x5A08, 0xFFFF), // ldrh r0,[r1,r0]
    (0x9009, 0xFFFF), // str  r0,[sp,#0x24]
];

/// MMIO control register for the drive-side AACS **bus-encryption** stage on the
/// read datapath (a chip constant, same address on every MT1959 image). Bit
/// [`BUSENC_ENABLE_BIT`] enables the in-transit bus wrap the host must otherwise
/// undo. OEM 1.00 materializes this address inline as `movs rN,#1; lsls rN,rN,#26`
/// (`1<<26`); the injected bus-off stub rebuilds it the same way.
const BUSENC_REG: u32 = 0x0400_0000;
/// The bus-off stub materializes [`BUSENC_REG`] as `movs r1,#1; lsls r1,r1,#26`
/// (`1<<26`) — the exact idiom OEM 1.00 uses inline. Keep the constant and the
/// emitted shift in lockstep.
const _: () = assert!(BUSENC_REG == 1u32 << 26);
/// Bit of [`BUSENC_REG`] that ENABLES the bus-encryption/scramble stage. Clearing
/// it makes the drive emit at-rest-only ciphertext (host decrypts with the real
/// title key). MK's LibreDrive-family firmware clears exactly this bit on the AACS
/// data-key (opcode `0x45`) path. **HARDWARE-KAT-GATED:** that bit `0x10` (and not
/// another bit of this register) is specifically the bus enable is proven only by
/// the MK-vs-OEM diff, not yet re-confirmed on this silicon by us.
const BUSENC_ENABLE_BIT: u8 = 0x10;

/// Signature of the OEM disc-version classifier prologue (`0xcb3c0` on BU40N 1.00,
/// `0xcb3a4` on the owned 1.03 images — **byte-identical**, only relocated). This is
/// the exact function MK's LibreDrive-family firmware hooks on the UHD (AACS 2.0)
/// path: MK replaces this 10-byte prologue with a call into its injected stub, and
/// the stub (with no runtime callback registered) returns the processed disc-version
/// as `0` — i.e. it **forces the disc-version the classifier sees to 0**, so a UHD
/// disc is never categorized into the "mode 1" bucket the downstream REPORT KEY gate
/// refuses with sense `6F/01`.
///
/// The prologue saves the incoming args, reserves a `0x24`-byte frame, reloads the
/// disc-version dword (the first stack arg, saved by the `push {r0-r3}`) into `r0`,
/// and seeds `r5=6` for the per-byte category loop:
///   `push {r0,r1,r2,r3}; push {r4,r5,r6,r7,lr}; sub sp,#0x24;
///    ldr r0,[sp,#0x38]; movs r5,#6`
///
/// Proven UNIQUE on BU40N 1.00 (single match in `[0xc0000,0xd0000)`) and matched
/// byte-identically on the owned 1.03 images. freemkv detours the version reload
/// `ldr r0,[sp,#0x38]` (+`movs r5,#6`, the 4 bytes at `match+6`) to a flag-gated
/// stub ([`Mt1959Engine::build_uhd_stub`]) that replays both and — only when
/// `flag[RawRead]==3` — zeros the disc-version (MK-parity). `lr` is already saved on
/// the stack by the preceding `push {r4-r7,lr}`, so the detour `bl` may clobber it
/// freely and the stub returns with `bx lr` to `match+10` (the classifier body).
const UHD_CLASSIFIER_SIG: &[(u16, u16)] = &[
    (0xB40F, 0xFFFF), // push {r0,r1,r2,r3}
    (0xB5F0, 0xFFFF), // push {r4,r5,r6,r7,lr}
    (0xB089, 0xFFFF), // sub  sp,#0x24
    (0x980E, 0xFFFF), // ldr  r0,[sp,#0x38]   disc-version reload ← detour site (match+6)
    (0x2506, 0xFFFF), // movs r5,#6           (match+8; consumed by the 4-byte detour bl)
];

/// Signature of the flash-resident **Host Revocation List (HRL) lookup** routine
/// (`0x13550e` on BU40N 1.00; relocated per version — `0x13569a` on N1.02,
/// `0x136302` on 1.04, all byte-identical in shape). Returns `1`=host revoked,
/// `2`=blank/`0xFFFF` sentinel, `0`=clean. The cert-send path calls it and then
/// tests `cmp r0,#0; bne <6F/00 emitter>` at three sites; the HRL-skip detour
/// (`flag[Feature::Hrl]==STATE_ON`) forces the clean (fall-through) path at those
/// three sites. Prologue: `push {r0,r1,r4-r7,lr}; sub sp,#0xc; ldr r0,[sp,#0xc];
/// movs r4,r1; bl <…>` — proven UNIQUE in `[0x134000,0x137000)` across the fleet
/// (the trailing `bl` displacement is masked). Verified in
/// `research/libredrive/mtk` against the capstone trace of `BU40N_OEM_1.00.bin`.
const HRL_LOOKUP_SIG: &[(u16, u16)] = &[
    (0xB5F3, 0xFFFF), // push {r0,r1,r4,r5,r6,r7,lr}
    (0xB083, 0xFFFF), // sub  sp,#0xc
    (0x9803, 0xFFFF), // ldr  r0,[sp,#0xc]
    (0x000C, 0xFFFF), // movs r4,r1
    (0xF000, 0xF800), // bl   <…>  hi
    (0xF800, 0xF800), //           lo
];

/// EXTRA CONFIRMATION GATE for the destructive one-time HRL flash wipe
/// ([`Feature::Hrl`] `HRL_WIPE_ONCE`). The wipe permanently rewrites the flash HRL
/// regions and is NOT undone by [`abi::Verb::Reset`], so it is wired into a build
/// ONLY when this is `true`. Default `false`: the record codegen
/// ([`Mt1959Engine::hrl_valid_empty_record`]) exists and is unit-tested, but no
/// image ships the wipe detour (the feature is inert / a lever MISS) until a
/// hardware-validated confirmation flips this.
///
/// [`Feature::Hrl`]: crate::abi::Feature::Hrl
const HRL_WIPE_ARMED: bool = false;

/// The [`abi::Verb::Identity`] reply lead-in: `"freemkv <version>"` (magic +
/// crate version). The live feature-state table (7 bytes, `flag[0x01..=0x07]`)
/// is appended after this by the handler at runtime.
fn identity_blob() -> Vec<u8> {
    format!(
        "{} {}",
        std::str::from_utf8(abi::RESP_MAGIC).unwrap_or("freemkv"),
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
}

/// Resolve the pc-relative literal an `ldr rX, [pc, #imm]` at file offset `at`
/// loads (`None` if the halfword there is not such a load).
fn pc_literal(image: &[u8], at: usize) -> Option<u32> {
    let hw = u16::from_le_bytes([*image.get(at)?, *image.get(at + 1)?]);
    if (hw & 0xF800) != 0x4800 {
        return None;
    }
    let pool = ((at + 4) & !3) + (hw & 0xFF) as usize * 4;
    if pool + 4 > image.len() {
        return None; // literal pool past the image tail — not decodable
    }
    Some(thumb::read_u32(image, pool))
}

/// The set of SRAM addresses (in `SRAM_LO..SRAM_HI`) that code references, used
/// by [`Mt1959Engine::find_free_sram_cell`]. Over-approximate on purpose: a
/// pc-relative literal in the SRAM window marks its 4-byte cell, and if the loaded
/// register is then used as a base (`[rX,#off]`) the `base..base+off` span is
/// marked too. See the finder's docs for why derefs of out-of-window pointer cells
/// don't over-count.
fn referenced_sram(image: &[u8]) -> std::collections::BTreeSet<u32> {
    fn mark(used: &mut std::collections::BTreeSet<u32>, base: u32, span: u32) {
        for k in 0..span {
            let x = base.wrapping_add(k);
            if (SRAM_LO..SRAM_HI).contains(&x) {
                used.insert(x);
            }
        }
    }
    let mut used = std::collections::BTreeSet::new();
    let mut o = 0usize;
    while o + 2 <= image.len() {
        let hw = u16::from_le_bytes([image[o], image[o + 1]]);
        // `ldr rX,[pc,#imm]` with a literal in the SRAM window.
        if (hw & 0xF800) == 0x4800 {
            if let Some(lit) = pc_literal(image, o) {
                if (SRAM_LO..SRAM_HI).contains(&lit) {
                    let rx = (hw >> 8) & 7;
                    mark(&mut used, lit, 4);
                    // Base-register reach: scan the next few instructions for
                    // `[rX,#off]` accesses; mark the whole base..base+off span.
                    let mut max_off = 0u32;
                    let mut p = o + 2;
                    let mut steps = 0;
                    while p + 2 <= image.len() && steps < 16 {
                        let h = u16::from_le_bytes([image[p], image[p + 1]]);
                        // rX redefined by another pc-relative load → stop.
                        if (h & 0xF800) == 0x4800 && ((h >> 8) & 7) == rx {
                            break;
                        }
                        if ((h >> 3) & 7) == rx {
                            let imm5 = ((h >> 6) & 0x1F) as u32;
                            let reach = match h & 0xF800 {
                                0x6800 | 0x6000 => imm5 * 4 + 4, // ldr/str word
                                0x7800 | 0x7000 => imm5 + 1,     // ldrb/strb
                                0x8800 | 0x8000 => imm5 * 2 + 2, // ldrh/strh
                                _ => 0,
                            };
                            max_off = max_off.max(reach);
                        }
                        p += 2;
                        steps += 1;
                    }
                    if max_off > 4 {
                        mark(&mut used, lit, max_off);
                    }
                }
            }
        }
        o += 2;
    }
    used
}

/// Whether the halfwords at `off` match `sig` (each entry `(value, mask)`,
/// matched as `(hw & mask) == value`).
fn matches_sig(image: &[u8], sig: &[(u16, u16)], off: usize) -> bool {
    sig.iter().enumerate().all(|(k, &(v, m))| {
        let hw = u16::from_le_bytes([image[off + 2 * k], image[off + 2 * k + 1]]);
        (hw & m) == v
    })
}

/// Find the first offset in `[lo, hi)` whose halfwords match `sig` (each entry a
/// `(value, mask)` pair, matched as `(hw & mask) == value`).
fn find_masked(image: &[u8], sig: &[(u16, u16)], lo: usize, hi: usize) -> Option<usize> {
    let hi = hi.min(image.len().saturating_sub(sig.len() * 2));
    (lo..hi)
        .step_by(2)
        .find(|&off| matches_sig(image, sig, off))
}

/// Every offset in `[lo, hi)` matching `sig` — used where a finder must prove a
/// signature is *unique* (refuse rather than guess if it is not).
fn find_masked_all(image: &[u8], sig: &[(u16, u16)], lo: usize, hi: usize) -> Vec<usize> {
    let hi = hi.min(image.len().saturating_sub(sig.len() * 2));
    (lo..hi)
        .step_by(2)
        .filter(|&off| matches_sig(image, sig, off))
        .collect()
}

/// Locate `sig`'s single occurrence in `[lo, hi)`, failing loudly if it is absent
/// or ambiguous (more than one hit) — the "prove it or refuse" contract every
/// grounded finder uses.
fn find_unique(
    image: &[u8],
    sig: &[(u16, u16)],
    lo: usize,
    hi: usize,
    what: &str,
) -> Result<usize> {
    match find_masked_all(image, sig, lo, hi).as_slice() {
        [one] => Ok(*one),
        hits => bail!(
            "{what} signature matched {} time(s) in [0x{lo:x},0x{hi:x}) (want exactly 1) — \
             refusing to patch",
            hits.len()
        ),
    }
}

/// Decode a Thumb-2 `BL` at `at` and return its absolute target (thumb bit
/// cleared), or `None` if the two halfwords there are not a `BL`. Used to verify
/// a wildcard-matched call actually targets a known routine.
fn decode_bl_target(image: &[u8], at: usize) -> Option<u32> {
    if at + 4 > image.len() {
        return None;
    }
    let h1 = u16::from_le_bytes([image[at], image[at + 1]]);
    let h2 = u16::from_le_bytes([image[at + 2], image[at + 3]]);
    // BL: h1 = 1111 0S imm10 ; h2 = 11 J1 1 J2 imm11
    if (h1 & 0xF800) != 0xF000 || (h2 & 0xD000) != 0xD000 {
        return None;
    }
    let s = ((h1 >> 10) & 1) as u32;
    let imm10 = (h1 & 0x03FF) as u32;
    let j1 = ((h2 >> 13) & 1) as u32;
    let j2 = ((h2 >> 11) & 1) as u32;
    let imm11 = (h2 & 0x07FF) as u32;
    let i1 = 1 - (j1 ^ s);
    let i2 = 1 - (j2 ^ s);
    let mut off = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
    if off & (1 << 24) != 0 {
        off |= !0u32 << 25; // sign-extend from bit 24
    }
    Some((at as u32 + 4).wrapping_add(off) & !1)
}

impl Mt1959Engine {
    /// Locate the scanner's entry (`push {…,lr}`) by its unique `0x3C` mode-gate
    /// `cmp r2,#{6,7,A,B,C}` chain, then the nearest preceding push. Fails loud
    /// if the signature is absent — without the scanner we cannot prove the
    /// record format, so we refuse rather than guess.
    pub fn find_scanner_entry(&self, image: &[u8]) -> Result<u32> {
        // cmp r2,#imm8  ==  0x2A00 | imm8  ->  little-endian [imm8, 0x2A]
        let pats: [[u8; 2]; 5] = [
            [0x06, 0x2A],
            [0x07, 0x2A],
            [0x0A, 0x2A],
            [0x0B, 0x2A],
            [0x0C, 0x2A],
        ];
        let lo = 0x0001_8000usize.min(image.len());
        let hi = 0x0002_0000usize.min(image.len());
        for base in lo..hi {
            let end = (base + 0x40).min(image.len());
            let w = &image[base..end];
            if pats.iter().all(|p| w.windows(2).any(|c| c == p)) {
                // walk back to the function's push {..,lr} (0xB5xx)
                let mut p = base & !1;
                for _ in 0..0x80 {
                    if p < 2 {
                        break;
                    }
                    let hw = u16::from_le_bytes([image[p], image[p + 1]]);
                    if (hw & 0xFF00) == 0xB500 {
                        return Ok(p as u32);
                    }
                    p -= 2;
                }
                bail!("scanner mode-gate found near 0x{base:x} but no push-lr prologue before it");
            }
        }
        bail!(
            "MT1959 scanner signature (READ BUFFER mode-gate cmp chain) not found — cannot prove \
             the dispatch record format; refusing to patch"
        )
    }

    /// The CDB base the scanner loads to read the incoming command: the literal
    /// of the first `ldr r3, [pc, #imm]` at the scanner entry.
    pub fn find_cdb_base(&self, image: &[u8]) -> Result<u32> {
        let entry = self.find_scanner_entry(image)? as usize;
        // entry+2 is the scanner's CDB-base load: `ldr r3,[pc,#imm]` (0x4Bxx) on
        // MT1959 / JB8, or `ldr r5,[pc,#imm]` (0x4Dxx) on the MT1939 classic
        // scanner (proven, engine-scope §1). Accept either destination register;
        // the pool literal + SRAM-window check below is what actually validates it.
        let ins_off = entry + 2;
        if ins_off + 2 > image.len() {
            bail!("scanner entry+2 (0x{ins_off:x}) runs past the image tail");
        }
        let hw = u16::from_le_bytes([image[ins_off], image[ins_off + 1]]);
        let rt = (hw >> 8) & 0x7;
        if (hw & 0xF800) != 0x4800 || !(rt == 3 || rt == 5) {
            bail!("scanner entry+2 is not `ldr r3/r5,[pc,#imm]` (got 0x{hw:04x})");
        }
        let imm8 = (hw & 0xFF) as usize;
        let pool = ((ins_off + 4) & !3) + imm8 * 4;
        if pool + 4 > image.len() {
            bail!("scanner cdb-base literal pool (0x{pool:x}) runs past the image tail");
        }
        let val = thumb::read_u32(image, pool);
        if !(0x0200_0000..0x0200_2000).contains(&val) {
            bail!("scanner cdb-base literal 0x{val:08x} is not in the expected SRAM window");
        }
        Ok(val)
    }

    /// The sense-setter routine `set_sense(key, asc, ascq)` the scanner
    /// tail-calls: the `bl` target immediately after a `movs r2 ; movs r1 ;
    /// movs r0` immediate triple inside the scanner body.
    pub fn sense_setter(&self, image: &[u8]) -> Result<u32> {
        let entry = self.find_scanner_entry(image)? as usize;
        let end = (entry + 0x120).min(image.len().saturating_sub(4));
        let is_movs = |off: usize, rt: u16| {
            let hw = u16::from_le_bytes([image[off], image[off + 1]]);
            (hw & 0xF800) == 0x2000 && ((hw >> 8) & 0x7) == rt
        };
        let mut off = entry;
        while off + 8 <= end {
            if is_movs(off, 2) && is_movs(off + 2, 1) && is_movs(off + 4, 0) {
                if let Some(t) = thumb::decode_bl(image, off + 6) {
                    return Ok(t);
                }
            }
            off += 2;
        }
        bail!("could not locate the sense-setter (movs r2/r1/r0 + bl) inside the scanner")
    }

    /// The unique live dispatch record for `opcode`: found by scanning coherent
    /// `opcode@0/flags@1/handler@4` runs across the table window, keeping records
    /// with the live media-gated flag and an in-image handler, and requiring
    /// exactly one whose handler lands on a real `push {…,lr}` prologue.
    pub fn find_live_record(&self, image: &[u8], opcode: u8) -> Result<CommandRecord> {
        self.find_live_record_in(image, opcode, TABLE_LO, TABLE_HI)
    }

    /// [`Self::find_live_record`] over an explicit table window. The MT1959/JB8
    /// dispatch table lives at [`TABLE_LO`]..[`TABLE_HI`]; the MT1939 **classic**
    /// generation keeps the same `opcode@0/flags@1/handler@4` record format but in
    /// a different window (`~0x1a4000`, engine-scope §1), so the classic engine
    /// calls this with that window.
    pub fn find_live_record_in(
        &self,
        image: &[u8],
        opcode: u8,
        table_lo: usize,
        table_hi: usize,
    ) -> Result<CommandRecord> {
        let end = table_hi.min(image.len());
        let valid = |p: usize| -> bool {
            if p + STRIDE > image.len() {
                return false;
            }
            let fl = image[p + 1];
            let resv = u16::from_le_bytes([image[p + 2], image[p + 3]]);
            let h = thumb::read_u32(image, p + 4);
            resv == 0 && matches!(fl, 0..=9 | 0x80 | 0x87) && (h == 0 || h < 0x0200_0000)
        };
        let mut hits: Vec<CommandRecord> = Vec::new();
        let mut off = table_lo;
        while off + STRIDE <= end {
            if !valid(off) {
                off += 4;
                continue;
            }
            let mut p = off;
            let mut run = 0usize;
            while p + STRIDE <= image.len() && valid(p) {
                run += 1;
                p += STRIDE;
            }
            if run >= MIN_RUN {
                let mut q = off;
                for _ in 0..run {
                    let op = image[q];
                    let fl = image[q + 1];
                    let h = thumb::read_u32(image, q + 4);
                    if op == opcode && fl == LIVE_FLAGS && (0x1000..0x0020_0000).contains(&(h & !1))
                    {
                        hits.push(CommandRecord {
                            off: q,
                            opcode: op,
                            flags: fl,
                            handler: h,
                        });
                    }
                    q += STRIDE;
                }
                off = p;
            } else {
                off += 4;
            }
        }
        if hits.len() != 1 {
            bail!(
                "expected exactly one live 0x{opcode:02X} record in a coherent table, found {} — \
                 ambiguous, refusing to patch",
                hits.len()
            );
        }
        let rec = hits[0];
        if !thumb::prologue_is_push_lr(image, (rec.handler & !1) as usize, 6) {
            bail!(
                "0x{opcode:02X} handler 0x{:08x} has no push-lr prologue — not a real handler",
                rec.handler
            );
        }
        Ok(rec)
    }

    /// Largest run of erased flash (`0xFF`) of at least `need` bytes, 4-aligned,
    /// lying inside an active CMAC range (so it's integrity-covered like a real
    /// handler), searched from the code region up. Deterministic (largest wins,
    /// lowest offset breaks ties) so `create` is reproducible.
    pub fn free_space(&self, image: &[u8], need: usize) -> Result<u32> {
        let ranges: Vec<(u32, u32)> = cmac::parse_table(image)
            .map_err(|e| anyhow!("{e}"))?
            .into_iter()
            .filter(|e| e.is_active() && e.start <= e.end)
            .map(|e| (e.start, e.end))
            .collect();
        let covered = |p: u32| ranges.iter().any(|&(s, e)| s <= p && p <= e);
        let mut best: Option<(u32, usize)> = None;
        let mut i = CODE_REGION_START;
        while i < image.len() {
            if image[i] == 0xFF {
                let s = i;
                while i < image.len() && image[i] == 0xFF {
                    i += 1;
                }
                let a = (s + 3) & !3;
                if i > a && i - a >= need && covered(a as u32) && covered((i - 1) as u32) {
                    let len = i - a;
                    if best.map(|(_, bl)| len > bl).unwrap_or(true) {
                        best = Some((a as u32, len));
                    }
                }
            } else {
                i += 1;
            }
        }
        best.map(|(a, _)| a)
            .ok_or_else(|| anyhow!("no CMAC-covered free space of {need} bytes in the code region"))
    }

    /// The response byte-writer `response_write_byte(r0=offset, r1=byte)` and the
    /// buffer-base commit offset it uses — both derived by a masked instruction
    /// signature over its (fixed) body, which loads `0xaf90`, `[0x02000c7c]`,
    /// `[0x02000c78]`, then `strb r1,[r0]; bx lr`. Returns `(writer, commit_off)`.
    pub fn find_response_writer(&self, image: &[u8]) -> Result<(u32, u32)> {
        // ldr r2,[pc] | adds r0,r0,r2 | ldr r2,[pc] | ldr r2,[r2] | adds r0,r2,r0 |
        // ldr r2,[pc] | lsls r0,r0,#8 | ldr r2,[r2] | lsrs r0,r0,#8 | adds r0,r0,r2 |
        // strb r1,[r0] | bx lr
        const SIG: &[(u16, u16)] = &[
            (0x4A00, 0xFF00),
            (0x1880, 0xFFFF),
            (0x4A00, 0xFF00),
            (0x6812, 0xFFFF),
            (0x1810, 0xFFFF),
            (0x4A00, 0xFF00),
            (0x0200, 0xFFFF),
            (0x6812, 0xFFFF),
            (0x0A00, 0xFFFF),
            (0x1880, 0xFFFF),
            (0x7001, 0xFFFF),
            (0x4770, 0xFFFF),
        ];
        let at = find_masked(image, SIG, 0x0009_0000, 0x000b_0000)
            .ok_or_else(|| anyhow!("response byte-writer signature not found"))?;
        // the buffer-base offset is the first literal the writer loads (0xaf90).
        let commit_off = pc_literal(image, at)
            .ok_or_else(|| anyhow!("writer's first ldr is not pc-relative"))?;
        Ok((at as u32, commit_off))
    }

    /// The response-commit routine `commit(r0=buffer_offset)` and the transfer
    /// length field it reads. Returns `(commit_entry, length_field)`.
    ///
    /// Matched by the **version-invariant anchors** rather than an exact byte
    /// run, so one engine handles every MT1959 image regardless of who built it:
    /// the commit routine always (a) stores the DMA source with `str r0,[rN,#0x28]`
    /// then (b) loads the 16-bit transfer-length cell with the immediately
    /// following `ldr r0,[pc,#imm]` (an SRAM literal), and (c) begins with a
    /// `ldr r1,[pc,#imm]` that loads an SRAM base-pointer cell. OEM 1.00 puts
    /// these back-to-back (`commit @ 0x98180`); MK 1.03 inserts extra bounds-clamp
    /// instructions mid-body (`commit @ 0x98434`) which broke the old contiguous
    /// 7-instruction signature — but these three anchors hold in both. The MMIO
    /// control-block base loaded for the `[rN,#0x28]` store is a `0x04..` literal,
    /// so the entry scan keeps only the `ldr r1,[pc]` that targets SRAM.
    pub fn find_response_commit(&self, image: &[u8]) -> Result<(u32, u32)> {
        const SRAM: std::ops::Range<u32> = 0x0200_0000..0x0200_2000;
        let lo = 0x0009_0000usize;
        let hi = 0x000a_0000usize.min(image.len().saturating_sub(4));
        // `str r0,[rN,#0x28]`: opcode/imm/rt fixed, rn (bits 5:3) free.
        let is_str_28 = |hw: u16| (hw & 0xFFC7) == 0x6280;
        // `ldr rT,[pc,#imm]` for a specific rT.
        let is_ldr_pc = |hw: u16, rt: u16| (hw & 0xF800) == 0x4800 && ((hw >> 8) & 7) == rt;

        let mut off = lo;
        while off + 4 <= hi {
            let hw0 = u16::from_le_bytes([image[off], image[off + 1]]);
            let hw1 = u16::from_le_bytes([image[off + 2], image[off + 3]]);
            // (a)+(b): DMA-source store immediately followed by the length load.
            if is_str_28(hw0) && is_ldr_pc(hw1, 0) {
                if let Some(len) = pc_literal(image, off + 2).filter(|v| SRAM.contains(v)) {
                    // (c): walk back to the routine's opening `ldr r1,[pc]`→SRAM
                    // (the base-pointer cell), skipping the MMIO base load.
                    let mut p = off;
                    let mut entry = None;
                    for _ in 0..0x20 {
                        if p < lo + 2 {
                            break;
                        }
                        p -= 2;
                        let hw = u16::from_le_bytes([image[p], image[p + 1]]);
                        if is_ldr_pc(hw, 1) {
                            if let Some(v) = pc_literal(image, p) {
                                if SRAM.contains(&v) {
                                    entry = Some(p as u32);
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(entry) = entry {
                        return Ok((entry, len));
                    }
                }
            }
            off += 2;
        }
        bail!("response-commit anchors (str [rN,#0x28] + length load) not found")
    }

    /// The OEM READ DISC STRUCTURE **format dispatcher** and the AACS
    /// auth-granted flag — the two facts needed to read any AACS structure
    /// (Volume ID `0x80`, PMSN `0x81`, Media ID `0x82`, MKB `0x83`, …) by handing
    /// the drive a format byte. Returns `(dispatcher, auth_flag)`.
    ///
    /// * The dispatcher is fingerprinted by its prologue: `push {r4,lr}; ldrb
    ///   r1,[r0,#7]; cmp r1,#0x7f` — it reads the format from `CDB[7]` and splits
    ///   AACS (`≥0x80`) from physical formats. It routes to the plaintext
    ///   `0x136xxx` producers and their emit path commits via the same `0x98180`
    ///   DMA the data-return uses.
    /// * The auth flag is the cell the VID producer gates on, located via the
    ///   unique AACS deny sense `05/6F/02` (`movs r2,#2; movs r1,#0x6f; movs
    ///   r0,#5`) — that base (`0x02000c80`) verified present, flag = base+2.
    ///
    /// Setting `auth_flag` bypasses the sealed host-cert AKE; the structure
    /// values themselves are plaintext identifiers, not sealed secrets.
    ///
    /// Retained as grounded knowledge (the READ DISC STRUCTURE dispatcher + auth
    /// flag). The self-contained VID read (subfn 0x03) no longer routes through
    /// the dispatcher, so this is currently unreferenced by the build.
    #[allow(dead_code)]
    pub fn find_aacs(&self, image: &[u8]) -> Result<(u32, u32)> {
        // dispatcher: push {r4,lr} | ldrb r1,[r0,#7] | cmp r1,#0x7f | bhi
        const DISP: &[(u16, u16)] = &[
            (0xB510, 0xFFFF),
            (0x79C1, 0xFFFF),
            (0x297F, 0xFFFF),
            (0xD800, 0xFF00),
        ];
        let dispatcher = find_masked(image, DISP, 0x000a_0000, 0x000c_0000)
            .ok_or_else(|| anyhow!("READ DISC STRUCTURE format-dispatcher signature not found"))?
            as u32;
        // auth flag via the AACS deny-sense fingerprint.
        const DENY: &[(u16, u16)] = &[(0x2202, 0xFFFF), (0x216F, 0xFFFF), (0x2005, 0xFFFF)];
        let deny = find_masked(image, DENY, 0x0013_0000, 0x0014_0000)
            .ok_or_else(|| anyhow!("AACS deny sense (5/6F/02) signature not found"))?;
        const AUTH_BASE: u32 = 0x0200_0c80;
        thumb::find(
            image,
            thumb::Needle::Word(AUTH_BASE),
            deny.saturating_sub(0x300),
        )
        .filter(|&o| o < deny + 0x40)
        .ok_or_else(|| anyhow!("AACS auth-flag base literal not found near the gate"))?;
        Ok((dispatcher, AUTH_BASE + 2))
    }

    /// The unique offset of the VID gate's address-compute tail. The gate
    /// `ldrb r0,[r0]` is at `result + 16` for BOTH variants.
    ///
    /// Tries the original [`VID_GATE_SIG`] first (so the BU40N KAT base always
    /// matches the same signature → byte-identical output), then the NB-class
    /// [`VID_GATE_SIG_NB`] variant. Each is required unique in its own right; an
    /// ambiguous original still refuses rather than silently trying the variant.
    fn find_vid_gate(&self, image: &[u8]) -> Result<usize> {
        let lo = 0x0012_0000usize.min(image.len());
        let hi = 0x0018_0000usize.min(image.len());
        match find_masked_all(image, VID_GATE_SIG, lo, hi).as_slice() {
            [one] => Ok(*one),
            // No BU40N-shape match → try the NB-class variant, then the JB8 variant.
            // Each is original-first and required unique in its own right.
            [] => match find_masked_all(image, VID_GATE_SIG_NB, lo, hi).as_slice() {
                [one] => Ok(*one),
                [] => find_unique(image, VID_GATE_SIG_JB8, lo, hi, "VID gate (JB8)"),
                hits => bail!(
                    "VID gate (NB-class) signature matched {} time(s) in [0x{lo:x},0x{hi:x}) \
                     (want exactly 1) — refusing to patch",
                    hits.len()
                ),
            },
            hits => bail!(
                "VID gate signature matched {} time(s) in [0x{lo:x},0x{hi:x}) (want exactly 1) — \
                 refusing to patch",
                hits.len()
            ),
        }
    }

    /// The OEM Volume-ID producer and its clear-VID scratch buffer. Returns
    /// `(producer_entry, out_buf)`.
    ///
    /// The producer is the function containing the VID gate: its entry is the
    /// nearest preceding `push {r4,r5,r6,r7,lr}` (`0xB5F0`). Its output buffer is
    /// the scratch literal it loads (~`0x00210c00`, identical across every image
    /// checked) — a *runtime* address above the 2 MiB flash image, read at
    /// runtime, derived here from the producer's own literal pool (never
    /// hardcoded). Calling the producer stages the CLEAR VID into that buffer
    /// before any transit encryption.
    pub fn find_vid_producer(&self, image: &[u8]) -> Result<(u32, u32)> {
        let gate = self.find_vid_gate(image)? + 16; // the `ldrb r0,[r0]` gate
        let mut p = gate;
        let producer = loop {
            if p < 2 || gate - p > 0x200 {
                bail!("VID producer prologue (push {{r4-r7,lr}}) not found before the gate");
            }
            if u16::from_le_bytes([image[p], image[p + 1]]) == 0xB5F0 {
                break p;
            }
            p -= 2;
        };
        // The scratch-buffer literal: a runtime address in [0x00201000,0x00300000)
        // above the flash image. Require exactly one distinct value in the body.
        let mut out: Option<u32> = None;
        let mut o = producer;
        while o + 2 <= (gate + 0x80).min(image.len()) {
            if let Some(v) = pc_literal(image, o) {
                if (0x0020_1000..0x0030_0000).contains(&v) {
                    match out {
                        None => out = Some(v),
                        Some(prev) if prev == v => {}
                        Some(_) => bail!(
                            "VID producer loads more than one runtime scratch literal — ambiguous"
                        ),
                    }
                }
            }
            o += 2;
        }
        let out = out
            .ok_or_else(|| anyhow!("VID producer scratch-buffer literal (~0x210c00) not found"))?;
        Ok((producer as u32, out))
    }

    /// The OEM per-AGID AKE gate-setter primitive `set_agid_state(r0=agid,
    /// r1=value)` (`0xcadf8` on 1.00). Derived from the image, not by a fragile
    /// standalone signature: the producer opens the gate with `movs r1,#1; bl
    /// <set_agid_state>` on both its proceed and skip paths, so the `bl` target is
    /// the routine. Every such site must agree.
    pub fn find_vid_gate_setter(&self, image: &[u8]) -> Result<u32> {
        let gate = self.find_vid_gate(image)? + 16;
        let end = (gate + 0x60).min(image.len().saturating_sub(4));
        let mut target: Option<u32> = None;
        let mut o = gate;
        while o + 4 <= end {
            if u16::from_le_bytes([image[o], image[o + 1]]) == 0x2101 {
                // movs r1,#1
                if let Some(t) = thumb::decode_bl(image, o + 2) {
                    let t = t & !1;
                    match target {
                        None => target = Some(t),
                        Some(prev) if prev == t => {}
                        Some(_) => bail!("VID gate-setter call sites disagree — ambiguous"),
                    }
                }
            }
            o += 2;
        }
        target.ok_or_else(|| anyhow!("VID gate-setter (movs r1,#1; bl) not found in the producer"))
    }

    /// The OEM VID producer's per-AGID **session struct** base (`0x02000d38` on
    /// 1.00). The producer reads the active AGID from `byte[base+0xa] >> 6`
    /// (top two bits) and bails if it is ≥ 2, so a standalone producer call
    /// depends on that field. Derived from the image: it is the first SRAM-window
    /// literal (`0x0200_0000..0x0200_2000`) the producer loads via `ldr r7,[pc]`
    /// near its prologue — never hardcoded. The Gate-A `04 01` bare-read stub uses
    /// this to reset the AGID selector (`byte[0xa] &= 0x3F`, AGID → 0) before the
    /// producer runs, so a prior read or `04 00` deny can't leave the selector
    /// `>= 2` (which makes the producer bail with ABORTED COMMAND until power-cycle).
    pub fn find_vid_agid_struct(&self, image: &[u8]) -> Result<u32> {
        let gate = self.find_vid_gate(image)? + 16;
        // producer entry: nearest preceding `push {r4,r5,r6,r7,lr}` (0xB5F0).
        let mut producer = gate;
        loop {
            if producer < 2 || gate - producer > 0x200 {
                bail!("VID producer prologue not found before the gate (AGID struct)");
            }
            if u16::from_le_bytes([image[producer], image[producer + 1]]) == 0xB5F0 {
                break;
            }
            producer -= 2;
        }
        // The first `ldr r7,[pc,#imm]` (0x4F00) whose literal is an SRAM cell.
        let mut o = producer;
        while o + 2 <= gate {
            if (u16::from_le_bytes([image[o], image[o + 1]]) & 0xFF00) == 0x4F00 {
                if let Some(v) = pc_literal(image, o) {
                    if (0x0200_0000..0x0200_2000).contains(&v) {
                        return Ok(v);
                    }
                }
            }
            o += 2;
        }
        bail!("VID AGID session-struct literal (ldr r7,[pc] → SRAM) not found in the producer")
    }

    /// The **classic**-generation per-AGID session-struct base. The classic VID
    /// producer reads the AGID selector from the CDB base the scanner loads into
    /// `r5` (`ldrb r0,[r5,#0xa]`), so the struct base IS the CDB base — NOT the
    /// `ldr r7,[pc]` literal [`Self::find_vid_agid_struct`] recovers, which on a
    /// classic image resolves to a *different* SRAM cell and would make the
    /// Gate-A `04 01` rearm poke the wrong bytes. Derived per image via
    /// [`Self::find_cdb_base`]; never hardcoded.
    pub fn find_vid_agid_struct_classic(&self, image: &[u8]) -> Result<u32> {
        self.find_cdb_base(image)
    }

    /// `SetDiscMode`, the read-datapath disc-mode dispatcher (`0x43cb0` on 1.00),
    /// located by [`SETDISCMODE_SIG`] and proven unique. This is the Bus
    /// Encryption (subfn 0x04) hook point; see the build report for why it is not
    /// yet wired.
    pub fn find_setdiscmode(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x0004_0000usize.min(image.len());
        let hi = 0x0005_0000usize.min(image.len());
        Ok(find_unique(image, SETDISCMODE_SIG, lo, hi, "SetDiscMode")? as u32)
    }

    /// The Speed (0x02) ramp-ceiling gate anchor. Returns `(anchor, idx_reg)`
    /// where `idx_reg` is the register the ramp holds `speed_index` in (`2` for the
    /// original [`SPEED_GATE_SIG`], `0` for the [`SPEED_GATE_SIG_R0`] variant); the
    /// gate `cmp/bhi` the detour replaces begins at `anchor+4` for both. Original
    /// first so the BU40N KAT base always resolves to the `r2` shape.
    pub fn find_speed_gate(&self, image: &[u8]) -> Result<(u32, u8)> {
        let lo = 0x0001_0000usize.min(image.len());
        let hi = 0x0002_0000usize.min(image.len());
        match find_masked_all(image, SPEED_GATE_SIG, lo, hi).as_slice() {
            [one] => Ok((*one as u32, 2)),
            [] => Ok((
                find_unique(
                    image,
                    SPEED_GATE_SIG_R0,
                    lo,
                    hi,
                    "Speed ramp-ceiling gate (r0)",
                )? as u32,
                0,
            )),
            hits => bail!(
                "Speed ramp-ceiling gate signature matched {} time(s) in [0x{lo:x},0x{hi:x}) \
                 (want exactly 1) — refusing to patch",
                hits.len()
            ),
        }
    }

    /// The Region-free (0x03) RPC-state emitter anchor — the unique
    /// [`REGION_EMIT_SIG`] match (`0x119890` on 1.00, `0x119a84` on 1.03).
    /// Returns the anchor offset; the frame[4] store the detour replaces is at
    /// `anchor+6`.
    pub fn find_region_emitter(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x0011_0000usize.min(image.len());
        let hi = 0x0012_0000usize.min(image.len());
        Ok(find_unique(image, REGION_EMIT_SIG, lo, hi, "RPC-state emitter")? as u32)
    }

    /// [`Self::find_region_emitter`] over an explicit window. `REGION_EMIT_SIG` is
    /// unique on all 42 MT1939 images too, but the MT1939 **classic** RPC emitter
    /// sits at `~0x154000..0x157000` (engine-scope §2), outside the MT1959 window,
    /// so the classic engine searches there.
    pub fn find_region_emitter_in(&self, image: &[u8], lo: usize, hi: usize) -> Result<u32> {
        let lo = lo.min(image.len());
        let hi = hi.min(image.len());
        Ok(find_unique(image, REGION_EMIT_SIG, lo, hi, "RPC-state emitter")? as u32)
    }

    /// The AACS AKE accept-gate anchor — the unique [`AKE_GATE_SIG`] match
    /// (`0x136594` on 1.00). Returns the anchor; the RESET writer the Raw Read
    /// detour replaces (`movs r1,#1; b <back>`, 4 bytes) is at `anchor+12`.
    pub fn find_ake_gate(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x0013_0000usize.min(image.len());
        let hi = 0x0014_0000usize.min(image.len());
        Ok(find_unique(image, AKE_GATE_SIG, lo, hi, "AACS AKE accept gate")? as u32)
    }

    /// The NB-class AKE accept-gate anchor — the unique [`AKE_GATE_SIG_NB`] match.
    /// Returns the anchor; the shared `bl set_agid_state` the Raw Read NB detour
    /// replaces is at `anchor+12` (see [`AKE_GATE_SIG_NB`]).
    pub fn find_ake_gate_nb(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x0013_0000usize.min(image.len());
        let hi = 0x0014_0000usize.min(image.len());
        Ok(find_unique(image, AKE_GATE_SIG_NB, lo, hi, "AACS AKE accept gate (NB)")? as u32)
    }

    /// The NB-class `1.V5` AKE accept-gate anchor — the unique
    /// [`AKE_GATE_SIG_NB_V5`] match. Returns the anchor; the reject writer
    /// (`movs r1,#1`) is at `anchor+12` and the shared `bl set_agid_state` the
    /// Raw Read detour replaces is at `anchor+14` (see [`AKE_GATE_SIG_NB_V5`]).
    pub fn find_ake_gate_nb_v5(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x0013_0000usize.min(image.len());
        let hi = 0x0014_0000usize.min(image.len());
        Ok(find_unique(
            image,
            AKE_GATE_SIG_NB_V5,
            lo,
            hi,
            "AACS AKE accept gate (NB 1.V5)",
        )? as u32)
    }

    /// The OEM AACS engine session-reset routine (`aacs_session_reset`) — the
    /// primitive that idles the AACS hardware engine (a direct engine gate-bit
    /// clear followed by a mailbox reset), used by the Raw Read deny-path detour
    /// so a failed-cert deny never leaves the engine non-idle (which would hang
    /// the next bare `0xAD` VID read). Returns the routine entry.
    ///
    /// Located by its unique AGID-reset loop, anchored on the already-resolved
    /// `set_agid_state` (the loop's inner `bl` MUST target it): `movs r1,#0; movs
    /// r0,#0; bl <mailbox>; movs r3,#0; movs r1,#1; mov r0,r3; bl <set_agid_state>;
    /// adds r3,#1; uxtb r3; cmp r3,#2; blo`. The two `bl`s are wildcarded then the
    /// set_agid_state one is verified by decoding its target, making the match
    /// unique; the entry is the nearest preceding `push {r4,r5,r6,lr}` (`0xB570`).
    pub fn find_aacs_session_reset(&self, image: &[u8]) -> Result<u32> {
        let setter = self.find_vid_gate_setter(image)?;
        // AGID-reset loop core (14 halfwords; the two BL word-pairs wildcarded).
        const SIG: &[(u16, u16)] = &[
            (0x2100, 0xFFFF), // movs r1,#0
            (0x2000, 0xFFFF), // movs r0,#0
            (0x0000, 0x0000), // bl <mailbox> (lo)
            (0x0000, 0x0000), // bl <mailbox> (hi)
            (0x2300, 0xFFFF), // movs r3,#0
            (0x2101, 0xFFFF), // movs r1,#1
            (0x0018, 0xFFFF), // mov r0,r3
            (0x0000, 0x0000), // bl <set_agid_state> (lo)
            (0x0000, 0x0000), // bl <set_agid_state> (hi)
            (0x1C5B, 0xFFFF), // adds r3,#1
            (0x061B, 0xFFFF), // lsls r3,#0x18
            (0x0E1B, 0xFFFF), // lsrs r3,#0x18
            (0x2B02, 0xFFFF), // cmp r3,#2
            (0xD300, 0xFF00), // blo <loop top>
        ];
        let lo = 0x0009_0000usize.min(image.len());
        let hi = 0x000e_0000usize.min(image.len());
        // The set_agid_state BL sits 14 bytes into the match (2+2+4+2+2+2).
        let hits: Vec<usize> = find_masked_all(image, SIG, lo, hi)
            .into_iter()
            .filter(|&m| decode_bl_target(image, m + 14) == Some(setter))
            .collect();
        let m = match hits.as_slice() {
            [one] => *one,
            [] => bail!("aacs_session_reset AGID-reset loop signature not found"),
            _ => bail!(
                "aacs_session_reset signature matched {} time(s) (want exactly 1) — refusing",
                hits.len()
            ),
        };
        // Entry: nearest preceding `push {..r4,r5,r6..,lr}`. Desktop/BU40N is
        // `push {r4,r5,r6,lr}` (0xB570); the NB-class portable line uses
        // `push {r3,r4,r5,r6,r7,lr}` (0xB5F8). Accept any push-with-lr whose
        // register mask includes the loop's working regs r4/r5/r6 (mask bit
        // 0x70) — proven to select the routine prologue on both, and BU40N still
        // resolves to the identical 0xB570 entry (KAT unaffected).
        let mut p = m;
        let entry = loop {
            if p < 2 || m - p > 0x40 {
                bail!(
                    "aacs_session_reset prologue (push {{..r4-r6..,lr}}) not found before the loop"
                );
            }
            let hw = u16::from_le_bytes([image[p], image[p + 1]]);
            if (hw & 0xFF00) == 0xB500 && (hw & 0x0070) == 0x0070 {
                break p;
            }
            p -= 2;
        };
        Ok(entry as u32)
    }

    /// The downgrade-enable (DE) byte offset. Anchored on the ASCII identity page
    /// (the same drive-descriptor record [`crate::family::detect_chip`] parses):
    /// the `"MTEKMT19"` family tag at `descriptor+0x34` must be present, then the
    /// DE slot is `descriptor+0x56`. Refuses rather than guessing a byte to poke
    /// if the page isn't the descriptor.
    ///
    /// The tag is the *only* anchor: the byte at `descriptor+0x50` is a
    /// within-family variant/region marker (`0x78/0x58/0x18/0x38` all occur on
    /// genuine MT1959 parts — proven by the 149-image scan in
    /// `research/hoard-campaign-2026-09-03`), NOT an invariant. It was previously
    /// (wrongly) required to equal `0x78`, which refused 8 otherwise-patchable
    /// images whose DE slot is already correct; that guard is removed. The DE slot
    /// at `+0x56` is stable fleet-wide.
    pub fn find_de_byte(&self, image: &[u8]) -> Result<u32> {
        use crate::family::DESCRIPTOR_OFFSET;
        let de = DESCRIPTOR_OFFSET + DE_BYTE_OFF;
        if de >= image.len() {
            bail!("image too small to contain the drive-descriptor DE byte at 0x{de:x}");
        }
        let tag = &image[DESCRIPTOR_OFFSET + 0x34..DESCRIPTOR_OFFSET + 0x3C];
        if !tag.starts_with(b"MTEKMT19") {
            bail!(
                "drive-descriptor family tag not at 0x{:x} — refusing to place the DE byte",
                DESCRIPTOR_OFFSET + 0x34
            );
        }
        Ok(de as u32)
    }

    /// Build-time SRAM-reference scanner: derive a provably-unused SRAM flag cell
    /// **per-image**, never hardcoded. Returns the base (4-aligned) of the largest
    /// contiguous run of SRAM addresses that no code references.
    ///
    /// The referenced set is built conservatively (over-approximate, so we never
    /// pick a live cell): every `ldr rX,[pc,#imm]` whose pooled literal is in the
    /// SRAM window is marked used, and if that register is then used as a base
    /// (`[rX,#off]`) the whole `base..base+off` span is marked too (base-register
    /// reach). Pointer cells such as `[0x02000c78]`/`[0x02000c7c]` resolve at
    /// runtime to addresses *outside* the SRAM window (the data bank/overlay), so
    /// their dereference targets are correctly NOT counted — only the 4-byte cell
    /// itself is (a `[rX,#0]` deref). Because some SRAM is reached via computed
    /// base pointers that leave no literal, the LARGEST unreferenced gap is chosen
    /// (the region most likely genuinely reserved).
    ///
    /// Cross-check: on OEM 1.00 the live DumpAll sweep found a 1536-byte zero gap
    /// at `0x02001a00`; this scanner independently reports the largest free gap as
    /// `0x0200120c..0x02002000` (3572 bytes) on both 1.00 and 1.03 — which
    /// *contains* `0x02001a00` — so the flag-table base sits inside it.
    /// Hybrid safety belt for a chip-constant SRAM cell (flag table / V5 scratch):
    /// the VALUE is a family constant (SRAM layout is per-chip, validated free +
    /// live-zero across all owned MT1959 images via the full-RAM capture), but at
    /// build time we still ASSERT, against THIS image, that `[base-4, base+len+4)`
    /// (cell + a 4-byte guard each side) is (a) entirely inside mapped RAM
    /// `[SRAM_LO, SRAM_END)` and (b) not touched by any static SRAM reference. Static
    /// reference-analysis is sound in the safety direction — a reference means
    /// corruption risk — so a clean pass means we won't clobber live state; the
    /// "not written at runtime" guarantee comes from the one-time runtime capture.
    /// Refuses to build (rather than emit a dangerous cell) if either check fails.
    fn assert_sram_cell_free(&self, image: &[u8], base: u32, len: u32, what: &str) -> Result<()> {
        let lo = base.saturating_sub(4);
        let hi = base + len + 4;
        if base < SRAM_LO || hi > SRAM_END {
            bail!(
                "{what} cell {base:#010x}..{:#010x} is outside mapped SRAM \
                 [{SRAM_LO:#010x}, {SRAM_END:#010x}) — would be discarded/unmapped",
                base + len
            );
        }
        let used = referenced_sram(image);
        for a in lo..hi {
            if used.contains(&a) {
                bail!(
                    "{what} cell {base:#010x}..{:#010x} overlaps a code-referenced SRAM \
                     address {a:#010x} (+guard) — refusing to clobber live state",
                    base + len
                );
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn find_free_sram_cell(&self, image: &[u8]) -> Result<u32> {
        let used = referenced_sram(image);
        let (mut best_base, mut best_len) = (0u32, 0usize);
        let (mut cur_base, mut cur_len) = (SRAM_LO, 0usize);
        let mut a = SRAM_LO;
        while a < SRAM_HI {
            if used.contains(&a) {
                if cur_len > best_len {
                    best_len = cur_len;
                    best_base = cur_base;
                }
                cur_len = 0;
                cur_base = a + 1;
            } else {
                cur_len += 1;
            }
            a += 1;
        }
        if cur_len > best_len {
            best_len = cur_len;
            best_base = cur_base;
        }
        if best_len < NUM_FEATURES as usize + 2 {
            bail!(
                "largest unreferenced SRAM gap is only {best_len} bytes — too small for a flag \
                 table; refusing to guess a cell"
            );
        }
        Ok((best_base + 3) & !3)
    }

    /// Assemble the freemkv `0x3C 0E` handler for the `verb [feature] [state]`
    /// grammar: knock-check, then dispatch on the **verb** (`cdb[4]`) and act on
    /// the flat feature-flag table in SRAM. Miss on the knock → tail-call the
    /// original handler (OEM `READ BUFFER` byte-identical). Every address (cdb
    /// base, byte-writer, commit, length field, OEM handler) is derived from the
    /// image.
    ///
    /// Verbs (`cdb[4]`):
    ///   * [`abi::Verb::Set`] — `flag[cdb[5]=feature] = cdb[6]=state`; returns a
    ///     zeroed buffer.
    ///   * [`abi::Verb::Reset`] — write [`abi::STATE_PASSTHROUGH`] to every feature
    ///     flag (`0x01..=0x07`); returns a zeroed buffer.
    ///   * [`abi::Verb::Get`] — returns `flag[cdb[5]=feature]` in response byte 0.
    ///   * [`abi::Verb::Identity`] — returns [`abi::RESP_MAGIC`] + version + the
    ///     live feature-state table (`flag[0x01..=0x07]`).
    ///   * [`abi::Verb::DumpAll`] — peek `CLEAR_LEN` bytes at the 32-bit address
    ///     packed big-endian in `cdb[5..9]`.
    ///   * any other verb — zeroed buffer.
    ///
    /// Each OEM-code trampoline reads its own `flag[feature]` byte (Speed
    /// `flag[0x01]`, Region `flag[0x02]`, UHD `flag[0x03]`, BD `flag[0x04]`, HRL
    /// `flag[0x05]`, AKE `flag[0x06]`, Bus `flag[0x07]`) and defaults to OEM
    /// behaviour on the passthrough sentinel (`0xFF`) **and** the SRAM boot value
    /// (`0x00`), so an unarmed or RESET image is byte-behaviour-identical to OEM.
    ///
    /// The host ALWAYS reads `CLEAR_LEN` bytes — a `0x3C` READ BUFFER is a data-in
    /// opcode, so a command with no/short data phase desyncs the transfer (ABORTED
    /// COMMAND + wedged FIFO). Every verb therefore commits the same `CLEAR_LEN`
    /// window (payload leading, zero-padded).
    pub fn build_handler(&self, image: &[u8], oem_handler: u32, flag_base: u32) -> Result<Vec<u8>> {
        let cdb = self.find_cdb_base(image)?;
        let (writer, commit_off) = self.find_response_writer(image)?;
        let (commit, length_field) = self.find_response_commit(image)?;
        let identity = identity_blob();
        let id_len = identity.len() as u8;

        let mut a = Asm::new();
        let tail = a.label();
        let knock_ok = a.label();
        let not_set = a.label();
        let clr = a.label();
        let clr_loop = a.label();
        let clrd = a.label();
        let not_get = a.label();
        let not_dump = a.label();
        let dump_loop = a.label();
        let id_loop = a.label();
        let id_done = a.label();
        let tbl_loop = a.label();
        let docommit = a.label();

        // knock: cdb[1]==KNOCK_MODE && cdb[2..4]==KNOCK, else tail-call OEM.
        a.ldr_lit(3, cdb);
        a.ldrb_imm(0, 3, 1);
        a.cmp_imm(0, abi::KNOCK_MODE);
        a.bne(tail);
        a.ldrb_imm(0, 3, 2);
        a.cmp_imm(0, abi::KNOCK[0]);
        a.bne(tail);
        a.ldrb_imm(0, 3, 3);
        a.cmp_imm(0, abi::KNOCK[1]);
        a.bne(tail);
        // matched -> jump over the OEM tail block (kept next to the knock `bne`s
        // so those conditional branches stay in range as the handler grows).
        a.b(knock_ok);

        // knock miss: tail-call the original handler, registers/lr as entered.
        a.bind(tail);
        a.ldr_lit(3, oem_handler | 1);
        a.bx(3);

        // matched: r7 = byte-writer, r4 = verb.
        a.bind(knock_ok);
        a.push(0x01F0); // push {r4,r5,r6,r7,lr}
        a.ldr_lit(7, writer | 1);
        a.ldrb_imm(4, 3, abi::CDB_VERB as u16); // r4 = verb = cdb[4]

        // SET: flag[cdb[5]=feature] = cdb[6]=state. r3=CDB base, r4=verb preserved.
        a.cmp_imm(4, abi::Verb::Set as u8);
        a.bne(not_set);
        a.ldr_lit(0, flag_base); // r0 = flag-table base (SRAM)
        a.ldrb_imm(1, 3, abi::CDB_FEATURE as u16); // r1 = feature id (cdb[5])
        a.adds_reg(0, 0, 1); // r0 = &flag[feature]
        a.ldrb_imm(1, 3, abi::CDB_STATE as u16); // r1 = state (cdb[6])
        a.strb_imm(1, 0, 0); // flag[feature] = state
        a.b(clr); // return a zeroed buffer
        a.bind(not_set);

        // RESET: write STATE_PASSTHROUGH (0xFF) to every feature flag (0x01..=0x07).
        a.cmp_imm(4, abi::Verb::Reset as u8);
        a.bne(clr); // not Reset → straight to clear (Get/DumpAll/Identity handled after)
        a.ldr_lit(0, flag_base);
        a.movs_imm(1, abi::STATE_PASSTHROUGH);
        for feat in 1..=NUM_FEATURES {
            a.strb_imm(1, 0, feat as u16); // flag[feat] = 0xFF
        }
        // fall through to clear → zeroed buffer.

        // Clear CLEAR_LEN bytes so no stale buffer data leaks (all data verbs
        // lead with their payload; the remainder stays zero).
        a.bind(clr);
        a.movs_imm(5, 0);
        a.bind(clr_loop);
        a.cmp_imm(5, CLEAR_LEN);
        a.bhs(clrd);
        a.mov_reg(0, 5);
        a.movs_imm(1, 0);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(clr_loop);
        a.bind(clrd);

        // GET: response byte 0 = flag[cdb[5]=feature].
        a.cmp_imm(4, abi::Verb::Get as u8);
        a.bne(not_get);
        a.ldr_lit(0, flag_base);
        a.ldrb_imm(1, 3, abi::CDB_FEATURE as u16); // r1 = feature id
        a.adds_reg(0, 0, 1); // r0 = &flag[feature]
        a.ldrb_imm(1, 0, 0); // r1 = flag byte
        a.movs_imm(0, 0); // response offset 0
        a.blx(7);
        a.b(docommit);
        a.bind(not_get);

        // DUMPALL: peek CLEAR_LEN bytes at the 32-bit addr big-endian in cdb[5..9].
        a.cmp_imm(4, abi::Verb::DumpAll as u8);
        a.bne(not_dump);
        a.ldrb_imm(6, 3, 5); // addr[31:24]
        a.lsls_imm(6, 6, 8);
        a.ldrb_imm(0, 3, 6);
        a.adds_reg(6, 6, 0); // |= addr[23:16]
        a.lsls_imm(6, 6, 8);
        a.ldrb_imm(0, 3, 7);
        a.adds_reg(6, 6, 0); // |= addr[15:8]
        a.lsls_imm(6, 6, 8);
        a.ldrb_imm(0, 3, 8);
        a.adds_reg(6, 6, 0); // |= addr[7:0]  → r6 = full 32-bit address
        a.movs_imm(5, 0);
        a.bind(dump_loop);
        a.cmp_imm(5, CLEAR_LEN);
        a.bhs(docommit);
        a.mov_reg(0, 5);
        a.ldrb_reg(1, 6, 5);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(dump_loop);
        a.bind(not_dump);

        // IDENTITY: RESP_MAGIC + version, then the live feature-state table.
        // Any other (unknown) verb falls through to docommit → zeroed buffer.
        a.cmp_imm(4, abi::Verb::Identity as u8);
        a.bne(docommit);
        let blob = a.data_blob(identity);
        a.adr(6, blob);
        a.movs_imm(5, 0);
        a.bind(id_loop);
        a.cmp_imm(5, id_len);
        a.bhs(id_done);
        a.mov_reg(0, 5);
        a.ldrb_reg(1, 6, 5);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(id_loop);
        a.bind(id_done);
        // append flag[0x01..=0x07] at offsets id_len.. (r5 = dest offset, r2 = feature).
        a.ldr_lit(6, flag_base);
        a.movs_imm(5, id_len);
        a.movs_imm(2, 1);
        a.bind(tbl_loop);
        a.cmp_imm(2, NUM_FEATURES + 1); // stop after feature 0x07
        a.bhs(docommit);
        a.ldrb_reg(1, 6, 2); // r1 = flag[feature]
        a.mov_reg(0, 5); // dest offset
        a.blx(7);
        a.adds_imm(5, 1);
        a.adds_imm(2, 1);
        a.b(tbl_loop);

        // length + commit + return good.
        a.bind(docommit);
        a.movs_imm(0, CLEAR_LEN);
        a.ldr_lit(1, length_field);
        a.strh_imm(0, 1, 0);
        a.ldr_lit(0, commit_off);
        a.ldr_lit(2, commit | 1);
        a.blx(2);
        a.pop(0x01F0); // pop {r4,r5,r6,r7,pc}
        a.finish()
    }

    /// The Speed (0x02) flag-gated ceiling trampoline. Entered by a `bl` that
    /// replaces the OEM ramp gate's own `cmp r2,#0x32; bhi <exit>` (the ramp is
    /// otherwise UNTOUCHED). On entry `r2 = speed_index`; `r1`/`r4` are live and
    /// preserved; `r0` is live at the fall-through so it is saved/restored; `lr`
    /// is dead (the ramp saved it on its own stack). The stub reads the Speed
    /// flag byte and compares `speed_index` against `0xFF` (the drive's own
    /// unlimited sentinel) when set or `0x32` (OEM band) when clear, then
    /// replicates the OEM `bhi` and returns to the exact ramp instruction the OEM
    /// gate would have. `fallthrough`/`exit` are the two OEM continuation VAs.
    fn build_speed_stub(
        &self,
        flag_base: u32,
        fallthrough: u32,
        exit: u32,
        idx_reg: u8,
    ) -> Result<Vec<u8>> {
        // flag[Feature::Speed] semantics (`0x00` boot / `0xFF` passthrough BOTH mean
        // OEM, preserving the stealth invariant): `STATE_ON` (0x01) = unlimited
        // (compare against the drive's own `0xFF` sentinel); any other value is an
        // explicit speed-cap byte (compare `speed_index` against it directly).
        let mut a = Asm::new();
        let patched = a.label();
        let oem = a.label();
        let decide = a.label();
        let go_exit = a.label();
        let flag_cell = flag_base + abi::Feature::Speed as u32;
        if idx_reg == 2 {
            // Original shape: speed_index in r2; r0 is live at the ramp fall-through
            // so it is saved/restored and doubles as the flag scratch.
            a.push(0x0001); // push {r0}          save r0 (live at ramp fall-through)
            a.ldr_lit(0, flag_cell); // r0 = &flag[Speed]
            a.ldrb_imm(0, 0, 0); // r0 = Speed flag byte
            a.cmp_imm(0, abi::STATE_ON); // 0x01 -> unlimited
            a.beq(patched);
            a.cmp_imm(0, abi::STATE_OFF); // 0x00 (boot) -> OEM
            a.beq(oem);
            a.cmp_imm(0, abi::STATE_PASSTHROUGH); // 0xFF -> OEM
            a.beq(oem);
            a.cmp_reg(2, 0); // explicit cap: speed_index vs cap byte
            a.b(decide);
            a.bind(patched);
            a.cmp_imm(2, 0xFF); // unlimited: the drive's own 0xFF sentinel
            a.b(decide);
            a.bind(oem);
            a.cmp_imm(2, 0x32); // OEM ramp self-ceiling band
            a.bind(decide);
            a.pop(0x0001); // pop {r0}           restore r0 (POP preserves flags)
            a.bhi(go_exit); // replicate the OEM `bhi <ramp-exit>`
            a.ldr_lit(2, fallthrough | 1); // fall-through: r2 dead at the OEM target
            a.bx(2); // continue the OEM ramp
            a.bind(go_exit);
            a.ldr_lit(2, exit | 1); // taken: r2 dead at the OEM ramp-exit target
            a.bx(2); // jump to the OEM ramp exit
        } else {
            // r0 variant: speed_index in r0 (DEAD after the gate — the OEM ramp
            // redefines it), so r0 needs no saving; the flag byte lives in r1, which
            // is saved/restored around the compare (r1 = cell ptr, may be live).
            a.push(0x0002); // push {r1}          save r1 (cell ptr; may be live)
            a.ldr_lit(1, flag_cell); // r1 = &flag[Speed]
            a.ldrb_imm(1, 1, 0); // r1 = Speed flag byte
            a.cmp_imm(1, abi::STATE_ON); // 0x01 -> unlimited
            a.beq(patched);
            a.cmp_imm(1, abi::STATE_OFF); // 0x00 (boot) -> OEM
            a.beq(oem);
            a.cmp_imm(1, abi::STATE_PASSTHROUGH); // 0xFF -> OEM
            a.beq(oem);
            a.cmp_reg(0, 1); // explicit cap: speed_index vs cap byte
            a.b(decide);
            a.bind(patched);
            a.cmp_imm(0, 0xFF); // unlimited: the drive's own 0xFF sentinel
            a.b(decide);
            a.bind(oem);
            a.cmp_imm(0, 0x32); // OEM ramp self-ceiling band
            a.bind(decide);
            a.pop(0x0002); // pop {r1}           restore r1 (POP preserves flags)
            a.bhi(go_exit); // replicate the OEM `bhi <ramp-exit>`
            a.ldr_lit(0, fallthrough | 1); // fall-through: r0 dead at the OEM target
            a.bx(0); // continue the OEM ramp
            a.bind(go_exit);
            a.ldr_lit(0, exit | 1); // taken: r0 dead at the OEM ramp-exit target
            a.bx(0); // jump to the OEM ramp exit
        }
        a.finish()
    }

    /// The Region-free (0x03) flag-gated RPC-emitter trampoline. Entered by a `bl`
    /// that replaces the OEM emitter's `frame[4]` store `strb r2,[r0,#8]` and the
    /// following `mov r3,sp` at `region_emitter+6`. On entry `r0 = FIFO data-port
    /// base`, `r1 == 0`, `r2 == frame[4]` (OEM TypeCode/reset/change counters),
    /// `r4 == 1`, and `sp[3]` is the RegionMask source (all per the OEM emitter).
    /// When the flag is set the stub zeroes `frame[4..6]` (TypeCode 0, RegionMask
    /// 0x00, RPCScheme 0 → RPC-1 — golden-MK parity) else it replicates the OEM
    /// `frame[4..6]`; both then emit reserved `frame[7]=0` and `pop {r3,r4,pc}`.
    fn build_region_stub(&self, flag_base: u32) -> Result<Vec<u8>> {
        // flag[Feature::Region] semantics (`0x00` boot / `0xFF` passthrough BOTH =
        // OEM, stealth): `STATE_ON` (0x01) = RPC-1 region-free (zero frame[4..6]);
        // `0x11..=0x18` = force DVD region 1..8; `REGION_BD_A/B/C` (0x2A/2B/2C) =
        // force BD region A/B/C; anything else = OEM.
        //
        // Force-region writes a specific RegionMask into `frame[5]`:
        //   * DVD (RPC-2 state): the standard inverted bitmask `~(1<<(region-1))`
        //     (one region enabled) from a lookup table, RPCScheme (`r4`==1) kept.
        //   * BD: a region index (A=1/B=2/C=4) placeholder in `frame[5]`.
        // HARDWARE-KAT-GATED: the exact force-region mask encoding is a hypothesis;
        // the OEM and RPC-1 paths (the KAT-exercised ones) are structurally proven.
        // DVD region mask table: region N (1..8) enabled → 0xFF & ~(1<<(N-1)).
        const DVD_MASKS: [u8; 8] = [0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F];
        // BD region A/B/C placeholder masks.
        const BD_MASKS: [u8; 3] = [0x01, 0x02, 0x04];

        let mut a = Asm::new();
        let region_free = a.label();
        let dvd_force = a.label();
        let bd_force = a.label();
        let oem = a.label();
        let tail = a.label();
        a.ldr_lit(3, flag_base + abi::Feature::Region as u32); // r3 = &flag[Region] (r3 popped)
        a.ldrb_imm(3, 3, 0); // r3 = Region flag byte
        a.cmp_imm(3, abi::STATE_ON); // 0x01 -> RPC-1 free
        a.beq(region_free);
        a.cmp_imm(3, 0x11);
        a.blo(oem); // < 0x11 (incl 0x00/0xFF handled below) -> OEM
        a.cmp_imm(3, 0x19);
        a.blo(dvd_force); // 0x11..=0x18 -> DVD force
        a.cmp_imm(3, abi::REGION_BD_A);
        a.blo(oem); // 0x19..0x29 -> OEM
        a.cmp_imm(3, abi::REGION_BD_C + 1);
        a.blo(bd_force); // 0x2A..=0x2C -> BD force
                         // fall through: >= 0x2D -> OEM

        a.bind(oem);
        a.strb_imm(2, 0, 8); // frame[4] = r2 (OEM TypeCode/#resets/#changes)
        a.raw16(0x466B); // mov r3,sp — re-read the RegionMask source from sp[3]
        a.ldrb_imm(2, 3, 3); // r2 = s3 (frame[4] already emitted, r2 free)
        a.strb_imm(2, 0, 8); // frame[5] = s3 (OEM RegionMask)
        a.strb_imm(4, 0, 8); // frame[6] = r4 (RPCScheme = 1, RPC-2)
        a.b(tail);

        a.bind(region_free);
        a.strb_imm(1, 0, 8); // frame[4] = 0 (TypeCode/resets/changes cleared)
        a.strb_imm(1, 0, 8); // frame[5] = 0 (RegionMask → all regions playable)
        a.strb_imm(1, 0, 8); // frame[6] = 0 (RPCScheme → RPC-1, region-free)
        a.b(tail);

        a.bind(dvd_force);
        let dvd = a.data_blob(DVD_MASKS.to_vec());
        a.strb_imm(2, 0, 8); // frame[4] = r2 (OEM TypeCode)
        a.subs_imm(3, 0x11); // r3 = region index 0..7
        a.adr(2, dvd);
        a.ldrb_reg(2, 2, 3); // r2 = DVD_MASKS[index]
        a.strb_imm(2, 0, 8); // frame[5] = forced DVD RegionMask
        a.strb_imm(4, 0, 8); // frame[6] = r4 (RPCScheme = 1, RPC-2)
        a.b(tail);

        a.bind(bd_force);
        let bd = a.data_blob(BD_MASKS.to_vec());
        a.strb_imm(2, 0, 8); // frame[4] = r2 (OEM TypeCode)
        a.subs_imm(3, abi::REGION_BD_A); // r3 = 0..2 (A/B/C)
        a.adr(2, bd);
        a.ldrb_reg(2, 2, 3); // r2 = BD_MASKS[index]
        a.strb_imm(2, 0, 8); // frame[5] = forced BD region mask
        a.strb_imm(4, 0, 8); // frame[6] = r4 (RPCScheme = 1)
        a.b(tail);

        a.bind(tail);
        a.strb_imm(1, 0, 8); // frame[7] = 0 (reserved, always)
        a.pop(0x0118); // pop {r3,r4,pc} — replicate the emitter epilogue
        a.finish()
    }

    /// The Raw Read (0x04) flag-gated AKE accept-gate trampoline. Entered by a `bl`
    /// that replaces the OEM RESET writer's `movs r1,#1; b <back>` at
    /// [`AKE_GATE_SIG`]'s `match+12`. On entry `r0 = AGID` (set by the preceding
    /// `ldrb/lsrs`), which is preserved. The stub picks the per-AGID state to write:
    /// `6` (AKE authenticated → VID gate open) when `flag[RawRead]==2`, else the
    /// OEM `1` (auth failed → reset). It then jumps to `back` — the OEM
    /// `set_agid_state(r0, r1)` call the reset writer branched to — so the store
    /// happens through the OEM primitive unchanged. `r2` is scratch (dead at `back`);
    /// `lr` is dead (the `bl` clobbers it, matching the OEM `b` that saved nothing).
    ///
    /// This is the `04 02` mode: "accept ANY host cert, revoked or not." The host
    /// still drives the real AKE (`0xA3`/`0xA4`) and may present a revoked (or any)
    /// cert; when the OEM verify FAILS and would reset to state 1, this stub forces
    /// state 6 instead, so the AKE completes and a bus-key `0xAD` read yields the
    /// VID. `04 01` does NOT act here (that mode is the bare-read Gate-A path).
    fn build_ake_stub(&self, flag_base: u32, back: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let accept = a.label();
        let done = a.label();
        a.ldr_lit(2, flag_base + abi::Feature::Ake as u32); // r2 = &flag[Ake]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_ON); // 0x01 = null AKE (accept any/revoked host cert)
        a.beq(accept);
        a.movs_imm(1, 1); // OEM (00/0xFF): reset to state 1 on a failed cert verify
        a.b(done);
        a.bind(accept);
        a.movs_imm(1, 6); // forced: state 6 (AKE authenticated)
        a.bind(done);
        a.ldr_lit(2, back | 1); // -> OEM set_agid_state(r0=agid, r1=state) call
        a.bx(2);
        a.finish()
    }

    /// NB-class Raw Read (0x04) AKE accept-gate trampoline. Entered by a `bl` that
    /// replaces the **shared** `bl set_agid_state` at [`AKE_GATE_SIG_NB`]'s
    /// `anchor+12` — the join BOTH arms reach (`r0 = AGID`, `r1 = 6` on the accept
    /// arm or `1` on the reject arm). Because the accept arm passes through here
    /// too, the stub must **preserve `r1`** when the flag is off (unlike
    /// [`Self::build_ake_stub`], which sits only on the reject writer): it forces
    /// `r1 = 6` only when `flag[RawRead]==2`, then tail-jumps to the OEM
    /// `set_agid_state` (`back`) so the store happens through the OEM primitive.
    /// `r2` is scratch (dead at `back`); `lr` is preserved by the outer `bl` and
    /// carries the OEM return, matching the `bl set_agid_state` this replaces.
    fn build_ake_stub_nb(&self, flag_base: u32, back: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let force = a.label();
        let keep = a.label();
        a.ldr_lit(2, flag_base + abi::Feature::Ake as u32); // r2 = &flag[Ake]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_ON); // 0x01 = null AKE (accept any/revoked host cert)
        a.beq(force);
        a.b(keep); // flag off: preserve r1 (accept arm = 6, reject arm = 1)
        a.bind(force);
        a.movs_imm(1, 6); // forced: state 6 (AKE authenticated)
        a.bind(keep);
        a.ldr_lit(2, back | 1); // -> OEM set_agid_state(r0=agid, r1=state) call
        a.bx(2);
        a.finish()
    }

    /// The Raw Read `04 03` "data clear" trampoline — removes the drive-side AACS
    /// **bus-encryption** stage the MK (LibreDrive-family) way. Entered by a `bl`
    /// that replaces the OEM `bl <key-prog>` at the start of the AACS **opcode-`0x45`
    /// (Read Data Key)** arm (`0x95eec` on BU40N 1.00), located via
    /// [`Mt1959Engine::busenc_detour`] / [`AACS45_DISPATCH_SIG`]. `keyprog` is the
    /// absolute target of that replaced `bl` (decoded from the image), which the stub
    /// REPLAYS so the OEM key programming still runs exactly as shipped.
    ///
    /// On entry `r0..r3` still hold the OEM `bl <key-prog>` arguments (a `bl` does not
    /// disturb them) and `lr = arm+4` (the OEM continuation, where the arm ignores the
    /// call's return value — it does `movs r0,#6` immediately). The stub saves `lr`,
    /// replays the call, and — only when `flag[RawRead]==3` — clears
    /// [`BUSENC_ENABLE_BIT`] of [`BUSENC_REG`] before returning to `arm+4` via the
    /// saved `lr`. `r1..r3` are dead across the OEM continuation (it re-establishes
    /// them), so the stub uses them as scratch; `r4` is pushed only to keep the stack
    /// 8-byte aligned and is restored unchanged.
    ///
    /// # Mechanism
    /// AACS bus encryption is a drive-side hardware stage on the read datapath, gated
    /// by [`BUSENC_ENABLE_BIT`] of the MMIO control register [`BUSENC_REG`]. OEM
    /// leaves it set, so content `READ(10)` is double-wrapped (AACS-at-rest **plus**
    /// the in-transit bus wrap) and even a correct title key yields garbage. Clearing
    /// the bit on the opcode-`0x45` path — the point the firmware programs the read
    /// data key for the session, immediately before the host issues `READ(10)` —
    /// disables the added bus wrap, so the drive emits at-rest-only ciphertext the
    /// host decrypts with the real title key. This is the mechanism the MK firmware
    /// uses; the bit-clear is the load-bearing action (MK additionally installs a
    /// matching bus-less key, which is unnecessary here because we let the OEM key
    /// programming run unchanged and only drop the transport wrap).
    ///
    /// `flag[RawRead]` (`flag[0x04]`) semantics at this site:
    ///   * `!= 3` (OEM / `01` / `02`): replay the OEM key-prog `bl` and return —
    ///     the register is untouched, **bus encryption ON**. Byte-behaviour-identical
    ///     to OEM, so this mode is inert (stealth) until `03` is set.
    ///   * `== 3` (data clear): replay the OEM key-prog `bl`, then
    ///     `*BUSENC_REG &= ~BUSENC_ENABLE_BIT` → the transport wrap is off for the
    ///     following `READ(10)`, content comes back AACS-at-rest only.
    ///
    /// **HARDWARE-KAT-GATED HYPOTHESIS.** That bit `0x10` of `0x0400_0000` is
    /// specifically the bus-encryption enable (and that clearing it here suppresses
    /// the wrap without disturbing the at-rest read path) comes from the MK-vs-OEM
    /// 1.03 diff and is NOT yet re-proven on this silicon; the golden-UK hardware KAT
    /// is the final arbiter. The `!= 3` (bus-ON) path IS structurally proven — it
    /// replays the exact OEM key-prog call and touches nothing else.
    fn build_busenc_stub(&self, flag_base: u32, keyprog: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let skip = a.label();
        a.push(0x0110); // push {r4, lr}   (r4 only to keep SP 8-byte aligned)
        a.ldr_lit(2, keyprog | 1); // r2 = &oem_key_prog (thumb)
        a.blx(2); // replay OEM key programming (its return value is dead at arm+4)
        a.ldr_lit(3, flag_base + abi::Feature::Bus as u32); // r3 = &flag[Bus]
        a.ldrb_imm(3, 3, 0); // r3 = Bus flag byte
        a.cmp_imm(3, abi::STATE_ON); // 0x01 = bus off (remove the bus-encryption stage)
        a.bne(skip); // OEM (00/0xFF): leave BUSENC_REG untouched (bus ON, stealth)
        a.movs_imm(1, 1);
        a.lsls_imm(1, 1, 26); // r1 = 1<<26 = BUSENC_REG (0x0400_0000)
        a.ldr_imm(2, 1, 0); // r2 = *BUSENC_REG
        a.movs_imm(3, BUSENC_ENABLE_BIT); // r3 = bus-enc enable bit (0x10)
        a.bics(2, 3); // r2 &= ~0x10   (turn the bus-encryption stage OFF)
        a.str_imm(2, 1, 0); // *BUSENC_REG = r2
        a.bind(skip);
        a.pop(0x0110); // pop {r4, pc} -> arm+4 (OEM continuation) via the saved lr
        a.finish()
    }

    /// The Raw Read `04 03` **UHD mode-gate neutralizer** trampoline (MK-style
    /// classifier hook). Entered by a `bl` that replaces the disc-version classifier
    /// prologue's reload `ldr r0,[sp,#0x38]; movs r5,#6` (4 bytes at
    /// [`UHD_CLASSIFIER_SIG`]'s `match+6`). It replays both overwritten instructions
    /// and, only when `flag[RawRead]==3`, zeros the disc-version so a UHD (AACS 2.0)
    /// disc is never categorized into the "mode 1" bucket the downstream REPORT KEY
    /// gate refuses with sense `6F/01`.
    ///
    /// # Register / frame contract
    /// The detour is a bare `bl` (it does **not** push), so `sp` is unchanged from the
    /// classifier's frame — the stub's replayed `ldr r0,[sp,#0x38]` therefore resolves
    /// to the exact same slot (the saved first arg = the disc-version dword) the OEM
    /// instruction would have. `lr` is already saved on the stack by the classifier's
    /// own preceding `push {r4,r5,r6,r7,lr}`, so the `bl`'s clobber of `lr` is harmless
    /// and the stub returns to `match+10` (the classifier body) with `bx lr`. `r0`
    /// (disc-version) and `r5` (=6, the per-byte category-loop shift seed) are the two
    /// live outputs the continuation consumes; `r3` is scratch, dead at `match+10`
    /// (the continuation recomputes `r2`/`r3` before use).
    ///
    /// `flag[RawRead]` (`flag[0x04]`) semantics at this site:
    ///   * `!= 3` (OEM / `01` / `02`): replay `ldr r0,[sp,#0x38]; movs r5,#6` verbatim
    ///     and return — the disc-version is untouched, so classification is
    ///     byte-behaviour-identical to OEM. Inert (stealth) until `03` is set.
    ///   * `== 3` (full UHD bypass): after the replay, `r0 = 0` → the classifier sees
    ///     disc-version `0`, dodging the UHD mode-1 categorization (MK-parity: MK's
    ///     injected stub returns the same forced-`0`).
    ///
    /// **HARDWARE-KAT-GATED HYPOTHESIS.** That neutralizing this categorization (the
    /// exact site MK hooks) is what lifts the UHD mode-1 refusal — and that it, together
    /// with the already-shipped bus-encryption bit-clear, yields readable at-rest UHD
    /// content on the vendor path — comes from the MK-vs-OEM diff and is NOT re-proven on
    /// this silicon; a hardware UHD rip is the final arbiter. The `!= 3` (stealth) path
    /// IS structurally proven — it replays the two OEM instructions and touches nothing
    /// else.
    fn build_uhd_stub(&self, flag_base: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let skip = a.label();
        a.raw16(0x980E); // replay: ldr r0,[sp,#0x38]  (r0 = disc-version; sp unchanged by the bl)
        a.movs_imm(5, 6); // replay: movs r5,#6         (per-byte category-loop shift seed)
        a.ldr_lit(3, flag_base + abi::Feature::Uhd as u32); // r3 = &flag[Uhd]
        a.ldrb_imm(3, 3, 0); // r3 = UHD flag byte
        a.cmp_imm(3, abi::STATE_ON); // 0x01 = force UHD (neutralize the mode gate)
        a.bne(skip); // OEM (00/0xFF): leave the disc-version untouched (stealth)
        a.movs_imm(0, 0); // armed: disc-version -> 0 (MK-parity; dodges the UHD mode-1 bucket)
        a.bind(skip);
        a.bx(14); // bx lr -> classifier continuation (match+10)
        a.finish()
    }

    /// Resolve the `04 03` UHD mode-gate neutralizer detour: the classifier prologue's
    /// disc-version reload (located by [`Self::find_uhd_classifier`]). Returns
    /// `(detour_site, stub_bytes)` where a `bl` to the stub is written at
    /// `detour_site` (= classifier `anchor+6`, replacing `ldr r0,[sp,#0x38]; movs
    /// r5,#6`). Verifies the two replaced halfwords are exactly the OEM prologue
    /// reload before returning, so a mis-anchored match refuses rather than patches.
    fn uhd_detour(&self, image: &[u8], flag_base: u32) -> Result<(usize, Vec<u8>)> {
        let anchor = self.find_uhd_classifier(image)? as usize;
        let site = anchor + 6;
        let ldr = u16::from_le_bytes([image[site], image[site + 1]]);
        let movs = u16::from_le_bytes([image[site + 2], image[site + 3]]);
        if ldr != 0x980E || movs != 0x2506 {
            bail!(
                "UHD classifier reload (ldr r0,[sp,#0x38]; movs r5,#6) not at 0x{site:x} \
                 (got 0x{ldr:04x} 0x{movs:04x})"
            );
        }
        let bytes = self.build_uhd_stub(flag_base)?;
        Ok((site, bytes))
    }

    /// **Classic**-generation Raw Read (0x04) AKE accept-gate trampoline (`04 02`).
    /// Entered by a `bl` that replaces the classic reject writer `lsrs r0,r0,#6;
    /// movs r1,#1` (4 bytes at `AKE_GATE_SIG_CLASSIC`'s `match+6`) — unlike the
    /// MT1959 reject writer, the classic one folds the `lsrs` (AGID compute) into
    /// the replaced bytes, so the stub REPLAYS it. It then forces `r1 = 6` when
    /// `flag[RawRead]==2` (accept any host cert) else the OEM `1` (reject), and
    /// falls through to the shared OEM `bl set_agid_state` call at `back`
    /// (`match+0xa`) that BOTH arms converge on — a single clean call, so the
    /// store happens through the OEM primitive unchanged. `r2` scratch; `r0`=AGID
    /// preserved. `04 01` does NOT act here (that is the Gate-A bare-read path).
    fn build_ake_stub_classic(&self, flag_base: u32, back: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let accept = a.label();
        let done = a.label();
        a.lsrs_imm(0, 0, 6); // replay the overwritten `lsrs r0,r0,#6` (r0 = AGID)
        a.ldr_lit(2, flag_base + abi::Feature::Ake as u32); // r2 = &flag[Ake]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_ON); // 0x01 = null AKE (accept any/revoked host cert)
        a.beq(accept);
        a.movs_imm(1, 1); // 00/01: OEM reset to state 1 on a failed cert verify
        a.b(done);
        a.bind(accept);
        a.movs_imm(1, 6); // forced: state 6 (AKE authenticated)
        a.bind(done);
        a.ldr_lit(2, back | 1); // -> shared OEM `bl set_agid_state` call site
        a.bx(2);
        a.finish()
    }

    /// Locate the OEM AACS opcode-`0x45` (Read Data Key) arm and the target of its
    /// leading `bl` (the OEM key-prog primitive). Tries [`AACS45_ARM_SIG_A`] first
    /// (BU40N/notebook order — keeps the KAT base byte-identical), then
    /// [`AACS45_ARM_SIG_B`] (BH/WH desktop order). Returns `(detour_site, keyprog)`
    /// where `detour_site` is the arm's leading `bl` (proven unique) and `keyprog`
    /// is that `bl`'s absolute target. Errors (→ `04 03` left unwired) if neither
    /// variant resolves uniquely.
    fn find_aacs45_arm(&self, image: &[u8]) -> Result<(usize, u32)> {
        let (lo, hi) = (CODE_REGION_START, TABLE_LO);
        let arm = match find_masked_all(image, AACS45_ARM_SIG_A, lo, hi).as_slice() {
            [one] => *one,
            [] => find_unique(image, AACS45_ARM_SIG_B, lo, hi, "AACS opcode-0x45 arm")?,
            hits => bail!(
                "AACS opcode-0x45 arm (A) matched {} time(s) (want exactly 1) — refusing to patch",
                hits.len()
            ),
        };
        let keyprog = thumb::decode_bl(image, arm).ok_or_else(|| {
            anyhow!("AACS opcode-0x45 arm at 0x{arm:x} does not start with a `bl <key-prog>`")
        })?;
        Ok((arm, keyprog))
    }

    /// The OEM disc-version classifier prologue anchor — the unique
    /// [`UHD_CLASSIFIER_SIG`] match (`0xcb3c0` on BU40N 1.00). Returns the anchor;
    /// the disc-version reload `ldr r0,[sp,#0x38]` the `04 03` UHD-bypass detour
    /// replaces (4 bytes, together with the following `movs r5,#6`) is at
    /// `anchor+6`, and the classifier continuation the stub returns to is at
    /// `anchor+10`.
    pub fn find_uhd_classifier(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x000c_0000usize.min(image.len());
        let hi = 0x000d_0000usize.min(image.len());
        Ok(find_unique(
            image,
            UHD_CLASSIFIER_SIG,
            lo,
            hi,
            "UHD disc-version classifier",
        )? as u32)
    }

    /// The flash-resident HRL lookup routine, located by [`HRL_LOOKUP_SIG`] and
    /// proven unique in the cert window. Returns its entry VA.
    pub fn find_hrl_lookup(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x0013_4000usize.min(image.len());
        let hi = 0x0013_7000usize.min(image.len());
        Ok(find_unique(image, HRL_LOOKUP_SIG, lo, hi, "HRL lookup routine")? as u32)
    }

    /// The three cert-path HRL check sites and their shared 6F/00 revoke target.
    ///
    /// Grounded, not hardcoded: find the HRL lookup ([`Self::find_hrl_lookup`]),
    /// then every `bl <hrl_lookup>` in the cert window; each is followed within a
    /// few instructions by `cmp r0,#0; bne <T>`. All three must share the SAME
    /// revoke target `T`, and `T` must carry the OEM revoke shape (`ldrb r0,[r4,#2];
    /// cmp r0,#0; bne …` then the `movs r2,#0; movs r1,#0x6f` 6F/00 sense-setup) —
    /// so a mis-anchored match refuses rather than patches. Returns
    /// `(cmp_offsets, revoke_target)`; `cmp_offsets[k]` is where the 4-byte
    /// `cmp r0,#0; bne T` the detour replaces begins.
    pub fn find_hrl_skip_sites(&self, image: &[u8]) -> Result<(Vec<usize>, u32)> {
        let hrl = self.find_hrl_lookup(image)?;
        let lo = 0x0013_5000usize.min(image.len());
        let hi = 0x0013_8000usize.min(image.len());
        let hw = |o: usize| u16::from_le_bytes([image[o], image[o + 1]]);
        let bne_target = |o: usize| -> u32 {
            let b = hw(o) & 0xFF;
            let disp = if b >= 0x80 {
                b as i32 - 0x100
            } else {
                b as i32
            };
            (o as i32 + 4 + disp * 2) as u32
        };
        let mut sites = Vec::new();
        let mut target: Option<u32> = None;
        let mut o = lo;
        while o + 4 <= hi {
            if decode_bl_target(image, o) == Some(hrl) {
                // nearest following `cmp r0,#0; bne T` within 12 halfwords.
                let mut p = o + 4;
                let end = (o + 4 + 24).min(hi.saturating_sub(4));
                while p + 4 <= end {
                    if hw(p) == 0x2800 && (hw(p + 2) & 0xFF00) == 0xD100 {
                        let t = bne_target(p + 2);
                        match target {
                            None => target = Some(t),
                            Some(prev) if prev == t => {}
                            Some(_) => bail!("HRL check sites disagree on the 6F/00 revoke target"),
                        }
                        sites.push(p);
                        break;
                    }
                    p += 2;
                }
            }
            o += 2;
        }
        let target =
            target.ok_or_else(|| anyhow!("no HRL cert-path `cmp r0,#0; bne` sites found"))?;
        if sites.len() != 3 {
            bail!(
                "expected exactly 3 HRL cert-path check sites, found {} — refusing to patch",
                sites.len()
            );
        }
        // Verify the revoke target's OEM shape: `ldrb r0,[r4,#2]; cmp r0,#0; bne`
        // then the 6F/00 sense-setup `movs r2,#0; movs r1,#0x6f` within 0x14 bytes.
        let t = target as usize;
        let revoke_shape = t + 6 <= image.len()
            && hw(t) == 0x78A0
            && hw(t + 2) == 0x2800
            && (hw(t + 4) & 0xFF00) == 0xD100;
        let emit_near = (0..0x14)
            .step_by(2)
            .any(|k| t + k + 4 <= image.len() && hw(t + k) == 0x2200 && hw(t + k + 2) == 0x216F);
        if !revoke_shape || !emit_near {
            bail!("HRL revoke target 0x{target:x} lacks the OEM 6F/00 revoke shape — refusing");
        }
        Ok((sites, target))
    }

    /// The HRL-skip trampoline (`flag[Feature::Hrl]==STATE_ON`). Shared by the three
    /// cert-path sites: each `bl` replaces `cmp r0,#0; bne <revoke>` (4 bytes) at a
    /// site, so on entry `lr` = that site's CLEAN fall-through and `r0` = the HRL
    /// lookup result (`1`=revoked, `2`=blank, `0`=clean). When `flag[Feature::Hrl]`
    /// is `STATE_ON` the stub takes the clean path regardless of the result (revoked
    /// certs accepted, non-destructive); otherwise it replicates OEM exactly (clean
    /// iff `r0==0`, else jump to the `revoke` 6F/00 path). `r3` is saved/restored;
    /// `r0`/`lr` untouched on the clean path, so behaviour is OEM-identical when the
    /// flag is off (`0x00` boot / `0xFF` passthrough) — the stealth invariant. The
    /// crypto verify (`bl <ca7e4>`) and the success writer are on other paths and
    /// are left intact.
    fn build_hrl_skip_stub(&self, flag_base: u32, revoke: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let clean = a.label();
        a.push(0x0008); // push {r3}   (r3 scratch; no inner call → SP alignment moot)
        a.ldr_lit(3, flag_base + abi::Feature::Hrl as u32); // r3 = &flag[Hrl]
        a.ldrb_imm(3, 3, 0); // r3 = HRL flag byte
        a.cmp_imm(3, abi::STATE_ON); // 0x01 = skip HRL -> force clean
        a.beq(clean);
        a.cmp_imm(0, 0); // OEM: clean iff HRL result == 0
        a.beq(clean);
        // revoked / blank: replicate the OEM `bne <revoke>` (jump to the 6F/00 path).
        a.pop(0x0008); // restore r3, balance the stack
        a.ldr_lit(3, revoke | 1);
        a.bx(3);
        a.bind(clean);
        a.pop(0x0008); // restore r3
        a.bx(14); // bx lr -> the site's clean fall-through
        a.finish()
    }

    /// Resolve the HRL-skip detour: returns `(cmp_offsets, revoke, stub_bytes)`. A
    /// `bl` to the stub is written at each of the three `cmp_offsets`. Errors (→ HRL
    /// skip left unwired) on an image whose HRL cert path is not the known shape.
    fn hrl_skip_detour(&self, image: &[u8], flag_base: u32) -> Result<(Vec<usize>, u32, Vec<u8>)> {
        let (sites, revoke) = self.find_hrl_skip_sites(image)?;
        let bytes = self.build_hrl_skip_stub(flag_base, revoke)?;
        Ok((sites, revoke, bytes))
    }

    /// **HRL wipe-once codegen (destructive; gated).** The valid-empty AACS Host
    /// Revocation List record this would program into both flash HRL regions
    /// (`0x1e0000` BD/mode0 and `0x1d8000` UHD/mode1, `0x8000` bytes each) for
    /// `flag[Feature::Hrl]==HRL_WIPE_ONCE`. Writing a *valid-empty* record — NOT
    /// erasing to `0xFF` — is load-bearing: a blank region reads as the `0xFFFF`
    /// count sentinel, so [`Self::find_hrl_lookup`]'s routine returns `2` (blank) and
    /// the cert path still emits `6F/00`. Layout (multi-byte big-endian):
    /// ```text
    ///   [0]     record type   = 0x21   (Host Revocation List record)
    ///   [1..4]  record length = 0x00000C (12-byte header, zero entries)
    ///   [4..6]  total entries = 0x0000  ← the load-bearing field: NOT 0xFFFF,
    ///                                     so the OEM lookup reads the list as CLEAN
    ///   [6..8]  reserved      = 0x0000
    /// ```
    /// The actual on-drive flash program (routine `0x1354a0`, controller regs
    /// `0x04002240`, mailbox `0x02001200` magic `5A A5 46 4C`, commit `0x13d9b2`
    /// toggling `0x04020000` bit0) is **NOT** synthesized into a shipping image: the
    /// wipe is permanent, not undone by RESET, and the exact record/signature the
    /// lookup accepts is not re-proven on-silicon. It is therefore gated behind
    /// [`HRL_WIPE_ARMED`] (default `false`) — the feature is inert / a lever MISS
    /// until a hardware-validated confirmation flips that constant. The record
    /// bytes here are the documented codegen the eventual programmer emits.
    #[allow(dead_code)]
    fn hrl_valid_empty_record(&self) -> [u8; 8] {
        [0x21, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00]
    }

    /// Resolve the `04 03` bus-off detour the MK way: the OEM `bl <key-prog>` at the
    /// start of the AACS opcode-`0x45` arm (located by [`Self::find_aacs45_arm`]).
    /// Returns `(detour_site, stub_bytes)` where a `bl` to the stub is written at
    /// `detour_site` (replacing the OEM `bl`); the stub replays the OEM key-prog call
    /// and, when `flag[RawRead]==3`, clears [`BUSENC_ENABLE_BIT`] of [`BUSENC_REG`].
    /// Errors (→ `04 03` unwired) on images whose opcode-`0x45` arm is not one of the
    /// two known MT1959 shapes.
    fn busenc_detour(&self, image: &[u8], flag_base: u32) -> Result<(usize, Vec<u8>)> {
        let (detour_site, keyprog) = self.find_aacs45_arm(image)?;
        let bytes = self.build_busenc_stub(flag_base, keyprog)?;
        Ok((detour_site, bytes))
    }

    /// Resolve the AKE detour site + stub for whichever gate variant this image
    /// carries. Tries the BU40N/desktop [`AKE_GATE_SIG`] first (so BU40N stays
    /// byte-identical), then the NB-class [`AKE_GATE_SIG_NB`]. Returns
    /// `(detour_site, stub_bytes, anchor)` where a `bl` to the stub is written at
    /// `detour_site`. Errors (→ RawRead `SignatureNotFound`) only if neither
    /// variant matches.
    fn ake_detour(&self, image: &[u8], flag_base: u32) -> Result<(usize, Vec<u8>, u32)> {
        // Original (BU40N / BP60NB10 / desktop): detour the reject writer
        // `movs r1,#1; b <back>` (4 bytes at anchor+12).
        if let Ok(ake_gate) = self.find_ake_gate(image) {
            let reset_site = ake_gate as usize + 12;
            let movs_hw = u16::from_le_bytes([image[reset_site], image[reset_site + 1]]);
            if movs_hw != 0x2101 {
                bail!(
                    "AKE reset writer `movs r1,#1` not at 0x{reset_site:x} (got 0x{movs_hw:04x})"
                );
            }
            let b_at = reset_site + 2;
            let b_hw = u16::from_le_bytes([image[b_at], image[b_at + 1]]);
            if (b_hw & 0xF800) != 0xE000 {
                bail!("AKE reset writer `b` not at 0x{b_at:x} (got 0x{b_hw:04x})");
            }
            let mut disp = (b_hw & 0x7FF) as i32;
            if disp >= 0x400 {
                disp -= 0x800;
            }
            let ake_back = (b_at as i32 + 4 + disp * 2) as u32;
            let bytes = self.build_ake_stub(flag_base, ake_back)?;
            return Ok((reset_site, bytes, ake_gate));
        }
        // NB-class: detour the shared `bl set_agid_state` at anchor+12.
        if let Ok(nb_gate) = self.find_ake_gate_nb(image) {
            let reject = nb_gate as usize + 10;
            let movs_hw = u16::from_le_bytes([image[reject], image[reject + 1]]);
            if movs_hw != 0x2101 {
                bail!(
                    "NB AKE reject writer `movs r1,#1` not at 0x{reject:x} (got 0x{movs_hw:04x})"
                );
            }
            let bl_site = nb_gate as usize + 12;
            let back = thumb::decode_bl(image, bl_site)
                .ok_or_else(|| anyhow!("NB AKE: no `bl set_agid_state` at 0x{bl_site:x}"))?;
            let bytes = self.build_ake_stub_nb(flag_base, back)?;
            return Ok((bl_site, bytes, nb_gate));
        }
        // NB-class `1.V5`: reject arm re-reads the AGID byte, so the reject writer
        // is at anchor+12 and the shared `bl set_agid_state` at anchor+14. Both
        // arms converge on that shared `bl`, so the NB stub (which PRESERVES r1
        // when the flag is off) applies verbatim.
        let v5_gate = self.find_ake_gate_nb_v5(image)?;
        let reject = v5_gate as usize + 12;
        let movs_hw = u16::from_le_bytes([image[reject], image[reject + 1]]);
        if movs_hw != 0x2101 {
            bail!(
                "NB 1.V5 AKE reject writer `movs r1,#1` not at 0x{reject:x} (got 0x{movs_hw:04x})"
            );
        }
        let bl_site = v5_gate as usize + 14;
        let back = thumb::decode_bl(image, bl_site)
            .ok_or_else(|| anyhow!("NB 1.V5 AKE: no `bl set_agid_state` at 0x{bl_site:x}"))?;
        let bytes = self.build_ake_stub_nb(flag_base, back)?;
        Ok((bl_site, bytes, v5_gate))
    }

    /// The Raw Read (0x04) flag-gated producer Gate-A trampoline. Entered by a `bl`
    /// that replaces the VID producer's OWN gate `cmp r0,#6; bne <deny>` (4 bytes at
    /// [`VID_GATE_SIG`]'s `match+18`). On entry `r0 = the per-AGID auth byte` (from the
    /// preceding `ldrb r0,[r0]`), preserved. This gate is reached by a bare
    /// `READ DISC STRUCTURE` (`0xAD` fmt `0x80`) — NO AKE.
    ///
    /// This is the `04 01` mode: "the cert is valid" — the drive is told the host
    /// auth already succeeded, so an unlocker can just issue a bare `0xAD` fmt `0x80`
    /// and get the VID with NO cert and NO AKE. When `flag[RawRead]==1` the stub
    /// jumps to `authed` (the fall-through that stages+emits VID) regardless of the
    /// auth byte; otherwise (00/02) it replicates the OEM `cmp #6` (authed on `==6`,
    /// which is what the `04 02` AKE path leaves in place). `r2` scratch; `lr` dead
    /// (producer saved it). The drive runs its own producer in its own `0xAD`
    /// context — no inline call, so a missing-buffer failure is a recoverable CHECK
    /// CONDITION, never a wedge.
    fn build_gatea_stub(
        &self,
        flag_base: u32,
        agid_struct: u32,
        authed: u32,
        deny: u32,
    ) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let rearm = a.label(); // 04 01 bare-read: reset AGID selector, then emit
        let authed_direct = a.label(); // 04 02 real-AKE authed: emit WITHOUT touching AGID
        a.ldr_lit(2, flag_base + abi::Feature::Ake as u32); // r2 = &flag[Ake]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_ON); // 0x01 (null AKE): force authed so a bare 0xAD returns the VID
        a.beq(rearm);
        a.cmp_imm(0, 6); // OEM (00/0xFF): authed iff auth byte == 6 (real AKE ran)
        a.beq(authed_direct);
        a.ldr_lit(2, deny | 1); // else OEM deny/fallback
        a.bx(2);
        // 04 01 bare read: the producer bails (ABORTED) if the active AGID selector
        // byte[agid_struct+0xa]>>6 is >= 2; a prior read or 04 00 deny advances it.
        // Reset it to AGID 0 (byte &= 0x3F) so each read runs fresh. 04 02 untouched.
        a.bind(rearm);
        a.ldr_lit(2, agid_struct); // r2 = &per-AGID session struct
        a.ldrb_imm(3, 2, 0xa); // r3 = byte[base+0xa] (AGID selector in top 2 bits)
        a.movs_imm(1, 0xC0); // r1 = 0xC0 (top-two-bits mask)
        a.bics(3, 1); // r3 &= ~0xC0  -> AGID selector = 0
        a.strb_imm(3, 2, 0xa); // write it back
        a.bind(authed_direct);
        a.ldr_lit(2, authed | 1); // proceed to stage + emit VID
        a.bx(2);
        a.finish()
    }

    /// The Raw Read (0x04) deny-path AACS-reset trampoline (Option C). Entered by a
    /// `bl` that replaces the VID producer deny block's sense-setup `movs r2,#2;
    /// movs r1,#0x6f` (the first 4 bytes at the deny target + 0x10). It calls the
    /// OEM `aacs_session_reset` to idle the AACS engine — so a failed-cert deny
    /// never leaves the engine non-idle (which would hang the next bare `0xAD` VID
    /// read) — then REPLAYS the two overwritten sense halfwords and returns to the
    /// OEM continuation (`movs r0,#5; b set_sense`). `aacs_session_reset` clobbers
    /// r0-r3 and preserves r4-r7; the deny continuation re-establishes r0 (=5)
    /// itself, and r2/r1 are replayed here, so nothing needs saving except lr.
    fn build_deny_reset_stub(&self, reset: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        a.push(0x0110); // push {r4, lr}  (r4 only to keep SP 8-byte aligned)
        a.ldr_lit(2, reset | 1); // r2 = &aacs_session_reset (thumb)
        a.blx(2); // aacs_session_reset()  (idle the engine)
        a.movs_imm(2, 2); // replay: movs r2,#2   (sense ASCQ)
        a.movs_imm(1, 0x6f); // replay: movs r1,#0x6f (sense ASC)
        a.pop(0x0110); // pop {r4, pc} -> OEM continuation (movs r0,#5; b set_sense)
        a.finish()
    }

    /// Full freemkv build: prove the find, inject the handler into covered free
    /// space, repoint only the `0x3C` handler pointer (flags untouched), and
    /// re-sign. Returns the new image and the grounded facts used. The [`Engine`]
    /// trait's `create` delegates here.
    ///
    /// [`Engine`]: super::Engine
    pub fn build_report(&self, image: &[u8]) -> Result<CreateReport> {
        let scanner_entry = self.find_scanner_entry(image)?;
        let cdb_base = self.find_cdb_base(image)?;
        let sense_setter = self.sense_setter(image)?;
        let record = self.find_live_record(image, abi::READ_BUFFER_OPCODE)?;
        // Grounded VID (0x03) facts, also proven here so a build fails loudly if
        // any is missing/ambiguous rather than shipping a broken handler.
        let (vid_producer, vid_out_buf) = self.find_vid_producer(image)?;
        let vid_gate_setter = self.find_vid_gate_setter(image)?;
        // Bus Encryption (0x04) hook point — proven locatable and unique (see report).
        let setdiscmode = self.find_setdiscmode(image)?;
        // Toggle hook anchors, all signature-found and proven unique on 1.00 + 1.03.
        let (speed_gate, speed_idx_reg) = self.find_speed_gate(image)?;
        let region_emitter = self.find_region_emitter(image)?;
        // Raw Read (0x04): the AACS AKE accept gate (signature-found, unique).
        let ake_gate = self.find_ake_gate(image)?;
        let de_off = self.find_de_byte(image)?;
        // The build-time SRAM scanner independently derives a candidate free cell;
        // retained for AUDIT only — it is unsound (picks a live-in-use cell), so it
        // is NOT used as the flag base. See FLAG_TABLE_BASE.
        let free_sram_cell = self.find_free_sram_cell(image)?;
        // Flag-table base actually used by the emitted code: the validated 204-byte
        // free hole (chip constant, hardware-proven writable+free across 24 images).
        let flag_base = FLAG_TABLE_BASE;
        // Hybrid safety belt: cells are chip constants, but assert per-image they
        // sit in mapped RAM and are unreferenced before we commit. Handler writes
        // flag[subfn] for 0..=DumpAll(0x09), so the table spans 0x0a bytes.
        let flag_table_len = NUM_FEATURES as u32 + 1;
        self.assert_sram_cell_free(image, flag_base, flag_table_len, "flag table")?;

        let handler_bytes = self
            .build_handler(image, record.handler, flag_base)
            .context("assembling the 3C-0E handler")?;

        let mut out = image.to_vec();

        // Place the injected code blobs into CMAC-covered free space, in order.
        // Each `free_space` call runs on the progressively-written image, so the
        // large erased run shrinks past each blob and the next lands after it.
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

        // Speed (0x02): flag-gated ramp-ceiling trampoline. The gate `cmp/bhi`
        // (4 bytes at speed_gate+4) is detoured to the stub; the ramp is untouched.
        let cmp_at = speed_gate as usize + 4;
        let bhi_at = speed_gate as usize + 6;
        let bhi_hw = u16::from_le_bytes([image[bhi_at], image[bhi_at + 1]]);
        if (bhi_hw & 0xFF00) != 0xD800 {
            bail!("speed gate `bhi` not at 0x{bhi_at:x} (got 0x{bhi_hw:04x})");
        }
        let mut disp = (bhi_hw & 0xFF) as i32;
        if disp >= 0x80 {
            disp -= 0x100; // sign-extend the imm8 branch displacement
        }
        let ramp_exit = (bhi_at as i32 + 4 + disp * 2) as u32; // OEM `bhi` target
        let fallthrough = speed_gate + 8; // OEM ramp continuation
        let speed_bytes =
            self.build_speed_stub(flag_base, fallthrough, ramp_exit, speed_idx_reg)?;
        let speed_stub_va = self.free_space(&out, speed_bytes.len() + 16)?;
        thumb::write(&mut out, speed_stub_va as usize, &speed_bytes);
        let bl = thumb::encode_bl(cmp_at, speed_stub_va)
            .ok_or_else(|| anyhow!("Speed detour `bl` out of range"))?;
        thumb::write(&mut out, cmp_at, &bl);

        // Region-free (0x03): flag-gated RPC-emitter trampoline. The frame[4]
        // store + the following `mov r3,sp` (4 bytes at region_emitter+6) are
        // detoured to the stub, which re-emits frame[4..7] + the epilogue.
        let region_site = region_emitter as usize + 6;
        let region_bytes = self.build_region_stub(flag_base)?;
        let region_stub_va = self.free_space(&out, region_bytes.len() + 16)?;
        thumb::write(&mut out, region_stub_va as usize, &region_bytes);
        let bl = thumb::encode_bl(region_site, region_stub_va)
            .ok_or_else(|| anyhow!("Region detour `bl` out of range"))?;
        thumb::write(&mut out, region_site, &bl);

        // Raw Read (0x04): flag-gated AKE accept-gate trampoline. The RESET writer's
        // `movs r1,#1; b <back>` (4 bytes at ake_gate+12) is detoured to a stub forcing
        // state 6 (accept) when flag[RawRead] is on, else the OEM 1, then jumps to back.
        let reset_site = ake_gate as usize + 12;
        let movs_hw = u16::from_le_bytes([image[reset_site], image[reset_site + 1]]);
        if movs_hw != 0x2101 {
            bail!("AKE reset writer `movs r1,#1` not at 0x{reset_site:x} (got 0x{movs_hw:04x})");
        }
        let b_at = reset_site + 2;
        let b_hw = u16::from_le_bytes([image[b_at], image[b_at + 1]]);
        if (b_hw & 0xF800) != 0xE000 {
            bail!("AKE reset writer `b` not at 0x{b_at:x} (got 0x{b_hw:04x})");
        }
        let mut disp = (b_hw & 0x7FF) as i32;
        if disp >= 0x400 {
            disp -= 0x800; // sign-extend the imm11 branch displacement
        }
        let ake_back = (b_at as i32 + 4 + disp * 2) as u32; // OEM set_agid_state call
        let ake_bytes = self.build_ake_stub(flag_base, ake_back)?;
        let ake_stub_va = self.free_space(&out, ake_bytes.len() + 16)?;
        thumb::write(&mut out, ake_stub_va as usize, &ake_bytes);
        let bl = thumb::encode_bl(reset_site, ake_stub_va)
            .ok_or_else(|| anyhow!("AKE detour `bl` out of range"))?;
        thumb::write(&mut out, reset_site, &bl);

        // Raw Read (0x04): flag-gated producer Gate-A trampoline. The producer's own
        // gate `cmp r0,#6; bne <deny>` (4 bytes at VID_GATE_SIG match+18) is detoured
        // to a stub forcing the authed path when flag[RawRead]==1 (bare 0xAD, no AKE).
        let gatea_anchor = self.find_vid_gate(image)?;
        let gatea_cmp = gatea_anchor + 18;
        let cmp_hw = u16::from_le_bytes([image[gatea_cmp], image[gatea_cmp + 1]]);
        if cmp_hw != 0x2806 {
            bail!("VID gate `cmp r0,#6` not at 0x{gatea_cmp:x} (got 0x{cmp_hw:04x})");
        }
        let gatea_bne = gatea_cmp + 2;
        let bne_hw = u16::from_le_bytes([image[gatea_bne], image[gatea_bne + 1]]);
        if (bne_hw & 0xFF00) != 0xD100 {
            bail!("VID gate `bne` not at 0x{gatea_bne:x} (got 0x{bne_hw:04x})");
        }
        let mut d = (bne_hw & 0xFF) as i32;
        if d >= 0x80 {
            d -= 0x100;
        }
        let gatea_deny = (gatea_bne as i32 + 4 + d * 2) as u32; // OEM deny target
        let gatea_authed = (gatea_cmp + 4) as u32; // fall-through: stage + emit VID
                                                   // The per-AGID session struct the producer gates on: the 04 01 bare-read
                                                   // path resets its AGID selector so a prior read/deny can't leave it >= 2
                                                   // (which makes the producer bail with ABORTED COMMAND until power-cycle).
        let vid_agid_struct = self.find_vid_agid_struct(image)?;
        let gatea_bytes =
            self.build_gatea_stub(flag_base, vid_agid_struct, gatea_authed, gatea_deny)?;
        let gatea_stub_va = self.free_space(&out, gatea_bytes.len() + 16)?;
        thumb::write(&mut out, gatea_stub_va as usize, &gatea_bytes);
        let bl = thumb::encode_bl(gatea_cmp, gatea_stub_va)
            .ok_or_else(|| anyhow!("Gate-A detour `bl` out of range"))?;
        thumb::write(&mut out, gatea_cmp, &bl);

        // Raw Read (0x04) deny-path AACS reset. The deny block's sense-setup
        // `movs r2,#2; movs r1,#0x6f` at the OEM deny target + 0x10 is detoured to a
        // stub that idles the engine via aacs_session_reset, replays sense, returns.
        let aacs_reset = self.find_aacs_session_reset(image)?;
        let deny_site = gatea_deny as usize + 0x10;
        if deny_site + 4 > image.len() {
            bail!("deny sense-setup site 0x{deny_site:x} is past the end of the image");
        }
        let d0 = u16::from_le_bytes([image[deny_site], image[deny_site + 1]]);
        let d1 = u16::from_le_bytes([image[deny_site + 2], image[deny_site + 3]]);
        if d0 != 0x2202 || d1 != 0x216f {
            bail!(
                "deny sense-setup (movs r2,#2; movs r1,#0x6f) not at 0x{deny_site:x} \
                 (got 0x{d0:04x} 0x{d1:04x})"
            );
        }
        let deny_bytes = self.build_deny_reset_stub(aacs_reset)?;
        let deny_stub_va = self.free_space(&out, deny_bytes.len() + 16)?;
        thumb::write(&mut out, deny_stub_va as usize, &deny_bytes);
        let bl = thumb::encode_bl(deny_site, deny_stub_va)
            .ok_or_else(|| anyhow!("deny-reset detour `bl` out of range"))?;
        thumb::write(&mut out, deny_site, &bl);

        // Raw Read `04 03` "data clear" (remove the drive-side bus-encryption stage,
        // MK-style). The OEM `bl <key-prog>` at the start of the AACS opcode-0x45 arm
        // is detoured to a stub that replays the OEM key programming and, only when
        // flag[RawRead]==3, clears BUSENC_ENABLE_BIT of BUSENC_REG so the following
        // content READ(10) comes back AACS-at-rest only. Wired AFTER the deny block so
        // the free_space allocation order matches build_modify (…→ deny → busenc). See
        // `build_busenc_stub` for the mechanism + the hardware-KAT hypothesis.
        let (busenc_site, busenc_bytes) = self.busenc_detour(image, flag_base)?;
        let busenc_stub_va = self.free_space(&out, busenc_bytes.len() + 16)?;
        thumb::write(&mut out, busenc_stub_va as usize, &busenc_bytes);
        let bl = thumb::encode_bl(busenc_site, busenc_stub_va)
            .ok_or_else(|| anyhow!("bus-enc detour `bl` out of range"))?;
        thumb::write(&mut out, busenc_site, &bl);

        // Raw Read `04 03` UHD mode-gate neutralizer (MK-style classifier hook). The
        // classifier prologue's disc-version reload `ldr r0,[sp,#0x38]; movs r5,#6` is
        // detoured to a stub that replays both and, only when flag[RawRead]==3, zeros
        // the disc-version so a UHD disc dodges the mode-1 refusal. Wired AFTER busenc
        // so the free_space allocation order matches build_modify (…→ busenc → uhd).
        // Optional (graceful): images whose classifier prologue is not the known shape
        // leave the mode unwired (0), exactly like the busenc arm on unknown 0x45 shapes.
        let (uhd_site, uhd_stub_va) = match self.uhd_detour(image, flag_base) {
            Ok((site, bytes)) => {
                let stub_va = self.free_space(&out, bytes.len() + 16)?;
                let bl = thumb::encode_bl(site, stub_va)
                    .ok_or_else(|| anyhow!("UHD mode-gate detour `bl` out of range"))?;
                thumb::write(&mut out, stub_va as usize, &bytes);
                thumb::write(&mut out, site, &bl);
                (site as u32, stub_va)
            }
            Err(_) => (0, 0),
        };

        // HRL skip (`flag[Feature::Hrl]==STATE_ON`): one shared stub, a `bl` at each
        // of the three cert-path check sites. Wired AFTER uhd so the free_space
        // allocation order matches build_modify (…→ uhd → hrl). Graceful: an image
        // whose HRL cert path is not the known shape leaves it unwired.
        let (hrl_sites, hrl_stub_va) = match self.hrl_skip_detour(image, flag_base) {
            Ok((sites, _revoke, bytes)) => {
                let stub_va = self.free_space(&out, bytes.len() + 16)?;
                thumb::write(&mut out, stub_va as usize, &bytes);
                for &site in &sites {
                    let bl = thumb::encode_bl(site, stub_va)
                        .ok_or_else(|| anyhow!("HRL-skip detour `bl` out of range"))?;
                    thumb::write(&mut out, site, &bl);
                }
                (
                    sites.iter().map(|&s| s as u32).collect::<Vec<u32>>(),
                    stub_va,
                )
            }
            Err(_) => (Vec::new(), 0),
        };

        // HRL wipe-once is destructive and gated behind HRL_WIPE_ARMED (default
        // off) — its record codegen is `hrl_valid_empty_record`; no image ships the
        // wipe detour until a hardware-validated confirmation flips the constant.
        let _hrl_wipe_armed = HRL_WIPE_ARMED;

        // Downgrade-enable (DE) byte: a build step (not a toggle) — write 0xDE
        // unconditionally at the identity-page slot. Idempotent on already-DE images.
        out[de_off as usize] = 0xDE;

        // repoint handler pointer only; flags stay exactly as OEM shipped.
        let table = CommandTable {
            base: 0,
            stride: STRIDE,
            opcode_off: 0,
            flags_off: 1,
            handler_off: 4,
            term_flag: TERM_FLAG,
            max_records: 1,
        };
        table.replace(&mut out, &record, handler_va | 1, None);
        debug_assert_eq!(out[record.off + 1], LIVE_FLAGS, "flags must remain live");
        let _ = CHAIN_FLAG; // (documented; walk uses it — kept for the record format)

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(CreateReport {
            image: signed,
            scanner_entry,
            cdb_base,
            sense_setter,
            record,
            handler_va,
            handler_bytes,
            vid_producer,
            vid_out_buf,
            vid_gate_setter,
            setdiscmode,
            speed_gate,
            speed_stub_va,
            region_emitter,
            region_stub_va,
            ake_gate,
            ake_stub_va,
            gatea_gate: gatea_cmp as u32,
            gatea_stub_va,
            deny_reset_gate: deny_site as u32,
            deny_stub_va,
            busenc_detour_site: busenc_site as u32,
            busenc_stub_va,
            uhd_classifier_site: uhd_site,
            uhd_stub_va,
            hrl_sites,
            hrl_stub_va,
            de_off,
            flag_base,
            free_sram_cell,
        })
    }

    /// Never-abort MODIFY: run every applicable lever, collect per-lever
    /// outcomes, re-sign once. Aborts the whole run **only** when the base
    /// vendor-command prerequisites cannot be built (nothing modifiable) — a
    /// single lever missing its signature does not stop the others.
    ///
    /// On an image where every lever applies (e.g. the BU40N 1.00 base) this
    /// emits byte-for-byte the same image as [`Self::build_report`]: the same
    /// finds, the same `free_space` allocation order (handler → speed → region →
    /// ake → gate-a → deny), the same detours, one `cmac::resign`. That equality
    /// is asserted by `create_and_modify_agree_on_base` in the KAT tests.
    pub fn build_modify(
        &self,
        image: &[u8],
        chip: &ChipInfo,
        cap: &Capability,
    ) -> Result<ModifyReport> {
        // Idempotency: re-feeding a freemkv-modified image must not re-patch or
        // error out (the repointed 0x3C record now targets our injected handler,
        // which has no stock push-lr prologue). Instead, report every lever
        // AlreadyPresent and return the image byte-identical. Detected by the
        // RESP_MAGIC the Identity handler always injects (absent from stock OEM).
        if is_freemkv_patched(image) {
            return Ok(self.already_present_report(image, chip, cap, "MT1959"));
        }

        // ---- Base prerequisites: if these fail the vendor command cannot exist
        //      at all → whole-run abort ("nothing modifiable"). ----
        self.find_scanner_entry(image)
            .context("nothing modifiable: dispatch scanner signature not found")?;
        self.find_cdb_base(image)?;
        self.sense_setter(image)?;
        let record = self.find_live_record(image, abi::READ_BUFFER_OPCODE)?;
        let flag_base = FLAG_TABLE_BASE;
        let flag_table_len = NUM_FEATURES as u32 + 1;
        self.assert_sram_cell_free(image, flag_base, flag_table_len, "flag table")?;
        let handler_bytes = self
            .build_handler(image, record.handler, flag_base)
            .context("assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

        let mut levers: Vec<LeverReport> = Vec::new();

        // Identity / base (the vendor handler + DumpAll). Always applicable — its
        // success is what makes every toggle addressable.
        levers.push(LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record.off as u32),
            ],
        ));

        // Speed (read-ramp ceiling) — BD capability.
        levers.push(if cap.media_class >= MediaClass::Bd || cap.bd_aacs {
            match self.emit_speed(image, &mut out, flag_base) {
                Ok((gate, va)) => LeverReport::applied(
                    LeverId::Speed,
                    vec![("speed_gate", gate), ("speed_stub_va", va)],
                ),
                Err(e) => LeverReport::missed(LeverId::Speed, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::Speed, "no BD read-ramp on this model")
        });

        // Region-free (RPC-1) — DVD or BD.
        levers.push(if cap.region_lockable {
            match self.emit_region(image, &mut out, flag_base) {
                Ok((emitter, va)) => LeverReport::applied(
                    LeverId::RegionFree,
                    vec![("region_emitter", emitter), ("region_stub_va", va)],
                ),
                Err(e) => LeverReport::missed(LeverId::RegionFree, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RegionFree, "no region lever on this model")
        });

        // Raw read / clear VID (VID gate + AKE accept + deny reset) — AACS/BD.
        levers.push(if cap.bd_aacs {
            match self.emit_rawread(image, &mut out, flag_base) {
                Ok(f) => {
                    let mut facts = vec![
                        ("ake_gate", f.ake_gate),
                        ("ake_site", f.ake_site),
                        ("ake_stub_va", f.ake_stub_va),
                        ("gatea_gate", f.gatea_cmp),
                        ("gatea_stub_va", f.gatea_stub_va),
                        ("deny_site", f.deny_site),
                        ("deny_stub_va", f.deny_stub_va),
                        ("vid_producer", f.vid_producer),
                    ];
                    // `04 03` "data clear" bus-off detour, when wired (opcode-0x45 arm
                    // is a known MT1959 shape). Recorded so the audit re-checks its `bl`.
                    if f.busenc_stub_va != 0 {
                        facts.push(("busenc_site", f.busenc_site));
                        facts.push(("busenc_stub_va", f.busenc_stub_va));
                    }
                    // `04 03` UHD mode-gate neutralizer, when wired (classifier prologue
                    // is a known MT1959 shape). Recorded so the audit re-checks its `bl`.
                    if f.uhd_stub_va != 0 {
                        facts.push(("uhd_site", f.uhd_site));
                        facts.push(("uhd_stub_va", f.uhd_stub_va));
                    }
                    // HRL skip (`flag[Feature::Hrl]==STATE_ON`), when wired. Three
                    // cert-path detour sites share one stub; each `bl` is re-checked.
                    if f.hrl_stub_va != 0 {
                        facts.push(("hrl_stub_va", f.hrl_stub_va));
                        for (k, &site) in f.hrl_sites.iter().enumerate() {
                            facts.push((["hrl_site", "hrl_site2", "hrl_site3"][k], site));
                        }
                    }
                    LeverReport::applied(LeverId::RawRead, facts)
                }
                Err(e) => LeverReport::missed(LeverId::RawRead, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RawRead, "no AACS/BD on this model")
        });

        // Downgrade-enable (DE) — family-agnostic: any image with a well-formed
        // MTEK identity page. Idempotent (already-0xDE → AlreadyPresent).
        levers.push(self.lever_de(image, &mut out, chip));

        // Repoint the hijacked record's handler pointer; flags stay OEM.
        let table = CommandTable {
            base: 0,
            stride: STRIDE,
            opcode_off: 0,
            flags_off: 1,
            handler_off: 4,
            term_flag: TERM_FLAG,
            max_records: 1,
        };
        table.replace(&mut out, &record, handler_va | 1, None);
        debug_assert_eq!(out[record.off + 1], LIVE_FLAGS, "flags must remain live");

        // If literally nothing took effect, this image is not modifiable.
        if !levers.iter().any(|l| l.outcome.is_effective()) {
            bail!("nothing modifiable on this image (no lever applied)");
        }

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(ModifyReport {
            engine: "MT1959",
            family: chip.family.label().to_string(),
            vendor: chip.vendor.clone(),
            model: chip.model.clone(),
            rev: chip.rev.clone(),
            vendor_specific: chip.vendor_specific.clone(),
            media: cap.media_class.label().to_string(),
            levers,
            image: signed,
            validation: Validation::StaticOnly,
        })
    }

    /// MT1939 classic-generation MODIFY (Identity + Region-free + DE).
    ///
    /// The classic generation keeps MT1959's `opcode@0/flags@1/handler@4` dispatch
    /// record format and the same chip-agnostic response writer/commit routines
    /// (all resolve on classic images), but in a different SRAM map + table window.
    /// This wires the two levers whose emit is **structurally provable + self-
    /// verifying** on classic — the Identity vendor handler (which also enables
    /// DumpAll) and Region-free — plus the always-safe DE byte. RawRead and Speed
    /// stay reported-only: the classic clear-VID scratch/deny path is INFERRED and
    /// the classic ramp ceiling is unreversed, so they are NOT emitted.
    ///
    /// Every byte written is well-formed, lands in a provably-free SRAM cell /
    /// CMAC-covered free space, the image re-signs + self-verifies, and it passes
    /// the structural detour audit — so, being structurally valid, Identity +
    /// Region-free + DE are produced unconditionally (no flag). What is not yet
    /// proven is runtime behavior on a real classic drive; the whole report carries
    /// the uniform `static-only` validation label for that. Classic Raw-read is the
    /// one thing withheld here — not as "beta" but because it is structurally unsafe
    /// (its clear-output/deny path is INFERRED; a wrong reply desyncs the SCSI FIFO).
    pub fn build_modify_classic(
        &self,
        image: &[u8],
        chip: &ChipInfo,
        cap: &Capability,
    ) -> Result<ModifyReport> {
        // Idempotency: a re-fed freemkv-modified classic image reports every lever
        // AlreadyPresent and returns byte-identical (see `build_modify`).
        if is_freemkv_patched(image) {
            return Ok(self.already_present_report(image, chip, cap, "MT1959"));
        }

        // Base prerequisites (classic): scanner + CDB base (r5) + the chip-agnostic
        // response writer/commit that build_handler needs. If any is missing the
        // vendor handler can't be built → this classic build can't run (the caller
        // degrades to the DE-only path).
        self.find_scanner_entry(image)
            .context("classic base: dispatch scanner not found")?;
        self.find_cdb_base(image)
            .context("classic base: CDB base")?;
        self.find_response_writer(image)
            .context("classic base: response writer")?;
        self.find_response_commit(image)
            .context("classic base: response commit")?;

        // Classic dispatch table window (~0x1a4000, engine-scope §1).
        const CLASSIC_TABLE_LO: usize = 0x001a_0000;
        const CLASSIC_TABLE_HI: usize = 0x001a_8000;
        let record = self
            .find_live_record_in(
                image,
                abi::READ_BUFFER_OPCODE,
                CLASSIC_TABLE_LO,
                CLASSIC_TABLE_HI,
            )
            .context("classic base: live 0x3C dispatch record")?;

        // Provably-free SRAM cell for the freemkv flag table (classic SRAM map
        // differs from MT1959, so we do not reuse the MT1959 FLAG_TABLE_BASE
        // placeholder — we derive an unreferenced cell from THIS image).
        let flag_base = self
            .find_free_sram_cell(image)
            .context("classic base: free SRAM cell for the flag table")?;

        let handler_bytes = self
            .build_handler(image, record.handler, flag_base)
            .context("classic base: assembling the 3C-0E handler")?;

        let mut out = image.to_vec();
        let handler_va = self.free_space(&out, handler_bytes.len() + 16)?;
        thumb::write(&mut out, handler_va as usize, &handler_bytes);

        let mut levers: Vec<LeverReport> = Vec::new();

        // Identity / vendor handler + DumpAll — structurally valid, self-verifies,
        // passes the structural audit → produced unconditionally (static-only label).
        levers.push(LeverReport::applied(
            LeverId::Identity,
            vec![
                ("handler_va", handler_va),
                ("record_off", record.off as u32),
                ("flag_base", flag_base),
            ],
        ));

        // Speed — the MT1959 ramp-ceiling gate (a byte `speed_index` in an SRAM
        // cell, `cmp #0x32; bhi <ramp-exit>`, incremented by a rate-limit counter)
        // does NOT exist on classic MT1939: RE of all 11 classic speed-miss images
        // finds no incrementing byte-index ramp and no `#0x32` ceiling anywhere in
        // the image. Classic read speed is a disc-type halfword clamp routed through
        // a shared limiter primitive (`~0x1b854` on BH16NS40 1.00, disc-type gated
        // max values 0x64/0xc8/0x190/0x1f4), with no single detourable ramp gate
        // matching the MT1959 stub contract. A residual miss by real architecture
        // difference, not a missing signature — see the fleet survey notes.
        levers.push(LeverReport::missed(
            LeverId::Speed,
            "MT1939 classic uses a disc-type halfword read-speed clamp (shared limiter \
             primitive, no byte speed_index ramp / no 0x32 ceiling) — no MT1959-style \
             ramp-ceiling gate exists to detour (residual RE miss)",
        ));

        // Region-free — REGION_EMIT_SIG transfers to classic in a higher window.
        // Structurally valid + self-verifies → produced unconditionally.
        levers.push(if cap.region_lockable {
            match self.emit_region_classic(&mut out, flag_base) {
                Ok((emitter, va)) => LeverReport::applied(
                    LeverId::RegionFree,
                    vec![("region_emitter", emitter), ("region_stub_va", va)],
                ),
                Err(e) => LeverReport::missed(LeverId::RegionFree, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RegionFree, "no region lever on this model")
        });

        // Raw read — classic MT1939 `04 01` (Gate-A bare-read) + `04 02` (AKE
        // accept). Both detours reuse the shared flag-gated stubs (the classic
        // Gate-A stub is byte-for-byte the MT1959 one); the deny path is left
        // byte-identical to OEM (no deny-reset detour). Structurally audited; the
        // static-only label already carries the pending-hardware-KAT caveat.
        levers.push(if cap.bd_aacs {
            match self.emit_rawread_classic(image, &mut out, flag_base) {
                Ok(facts) => LeverReport::applied(LeverId::RawRead, facts),
                Err(e) => LeverReport::missed(LeverId::RawRead, format!("{e:#}")),
            }
        } else {
            LeverReport::not_applicable(LeverId::RawRead, "no AACS/BD on this model")
        });

        // Downgrade-enable — proven/stable, any identity page.
        levers.push(self.lever_de(image, &mut out, chip));

        // Repoint the classic 0x3C record's handler; flags stay live.
        let table = CommandTable {
            base: 0,
            stride: STRIDE,
            opcode_off: 0,
            flags_off: 1,
            handler_off: 4,
            term_flag: TERM_FLAG,
            max_records: 1,
        };
        table.replace(&mut out, &record, handler_va | 1, None);
        debug_assert_eq!(out[record.off + 1], LIVE_FLAGS, "flags must remain live");

        if !levers.iter().any(|l| l.outcome.is_effective()) {
            bail!("nothing modifiable on this classic MT1939 image");
        }

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(ModifyReport {
            engine: "MT1939",
            family: chip.family.label().to_string(),
            vendor: chip.vendor.clone(),
            model: chip.model.clone(),
            rev: chip.rev.clone(),
            vendor_specific: chip.vendor_specific.clone(),
            media: cap.media_class.label().to_string(),
            levers,
            image: signed,
            validation: Validation::StaticOnly,
        })
    }

    /// Region-free emission for the MT1939 classic window (mirrors [`Self::emit_region`]
    /// with the classic `REGION_EMIT_SIG` window, `~0x154000..0x157000`).
    fn emit_region_classic(&self, out: &mut [u8], flag_base: u32) -> Result<(u32, u32)> {
        let region_emitter = self.find_region_emitter_in(out, 0x0015_0000, 0x0016_0000)?;
        let region_site = region_emitter as usize + 6;
        let region_bytes = self.build_region_stub(flag_base)?;
        let region_stub_va = self.free_space(out, region_bytes.len() + 16)?;
        let bl = thumb::encode_bl(region_site, region_stub_va)
            .ok_or_else(|| anyhow!("classic Region detour `bl` out of range"))?;
        thumb::write(out, region_stub_va as usize, &region_bytes);
        thumb::write(out, region_site, &bl);
        Ok((region_emitter, region_stub_va))
    }

    /// Raw-read emission for the MT1939 **classic** window (mirrors
    /// [`Self::emit_rawread`]: validate read-only, then commit on a working copy).
    /// Emits the Gate-A `04 01` bare-read detour (always) and the AKE `04 02`
    /// accept detour, but NO deny-reset detour — the classic deny path is left
    /// **byte-identical to OEM** (its clear-output shape is inferred, so touching
    /// it risks a SCSI-FIFO desync). Returns the grounded facts.
    ///
    /// * Gate-A: the classic VID producer gate `cmp r0,#6; bne <deny>` sits at
    ///   `VID_GATE_SIG_CLASSIC`'s `match+30`/`+32`; the detour reuses the shared
    ///   [`Self::build_gatea_stub`] verbatim, with `agid_struct` from the CDB base
    ///   ([`Self::find_vid_agid_struct_classic`] — the classic finder fix).
    /// * AKE: the reject writer `lsrs; movs r1,#1` at `AKE_GATE_SIG_CLASSIC`'s
    ///   `match+6`, returning into the shared `bl set_agid_state` at `match+0xa`.
    fn emit_rawread_classic(
        &self,
        image: &[u8],
        out: &mut Vec<u8>,
        flag_base: u32,
    ) -> Result<Vec<(&'static str, u32)>> {
        use super::mt1939::{masked_matches, AKE_GATE_SIG_CLASSIC, VID_GATE_SIG_CLASSIC};
        const LO: usize = 0x0017_0000;
        const HI: usize = 0x0018_0000;

        // ---- validate (read-only) ----
        // Classic VID producer Gate-A, required unique.
        let vid_gate = match masked_matches(image, VID_GATE_SIG_CLASSIC, LO, HI).as_slice() {
            [one] => *one,
            hits => bail!(
                "classic VID gate matched {} time(s) in [0x{LO:x},0x{HI:x}) (want 1)",
                hits.len()
            ),
        };
        let gatea_cmp = vid_gate + 30;
        let cmp_hw = u16::from_le_bytes([image[gatea_cmp], image[gatea_cmp + 1]]);
        if cmp_hw != 0x2806 {
            bail!("classic VID gate `cmp r0,#6` not at 0x{gatea_cmp:x} (got 0x{cmp_hw:04x})");
        }
        let gatea_bne = gatea_cmp + 2;
        let bne_hw = u16::from_le_bytes([image[gatea_bne], image[gatea_bne + 1]]);
        if (bne_hw & 0xFF00) != 0xD100 {
            bail!("classic VID gate `bne` not at 0x{gatea_bne:x} (got 0x{bne_hw:04x})");
        }
        let mut d = (bne_hw & 0xFF) as i32;
        if d >= 0x80 {
            d -= 0x100;
        }
        let gatea_deny = (gatea_bne as i32 + 4 + d * 2) as u32;
        let gatea_authed = (gatea_cmp + 4) as u32;
        // Classic AGID struct = CDB base (the finder fix), NOT the r7 heuristic.
        let agid_struct = self.find_vid_agid_struct_classic(image)?;
        let gatea_bytes =
            self.build_gatea_stub(flag_base, agid_struct, gatea_authed, gatea_deny)?;

        // Scratch clear-VID buffer (audit-only: no stub consumes it — the producer
        // stages the clear VID there itself; pinned unique for the audit).
        let (vid_producer, scratch) = self.find_vid_producer(image)?;

        // Classic AKE accept gate (04 02), required unique. The reject writer folds
        // the `lsrs` (AGID compute) into the 4 replaced bytes.
        let ake = match masked_matches(image, AKE_GATE_SIG_CLASSIC, LO, HI).as_slice() {
            [one] => *one,
            hits => bail!(
                "classic AKE gate matched {} time(s) in [0x{LO:x},0x{HI:x}) (want 1)",
                hits.len()
            ),
        };
        let ake_site = ake + 6;
        let lsrs_hw = u16::from_le_bytes([image[ake_site], image[ake_site + 1]]);
        let movs_hw = u16::from_le_bytes([image[ake_site + 2], image[ake_site + 3]]);
        if lsrs_hw != 0x0980 || movs_hw != 0x2101 {
            bail!(
                "classic AKE reject writer (lsrs r0,#6; movs r1,#1) not at 0x{ake_site:x} \
                 (got 0x{lsrs_hw:04x} 0x{movs_hw:04x})"
            );
        }
        let ake_back = (ake + 0xa) as u32; // shared `bl set_agid_state` call site
        let ake_bytes = self.build_ake_stub_classic(flag_base, ake_back)?;

        // ---- commit on a working copy (atomic) ----
        let mut w = out.clone();
        let gatea_stub_va = self.free_space(&w, gatea_bytes.len() + 16)?;
        let gatea_bl = thumb::encode_bl(gatea_cmp, gatea_stub_va)
            .ok_or_else(|| anyhow!("classic Gate-A detour `bl` out of range"))?;
        thumb::write(&mut w, gatea_stub_va as usize, &gatea_bytes);
        thumb::write(&mut w, gatea_cmp, &gatea_bl);

        let ake_stub_va = self.free_space(&w, ake_bytes.len() + 16)?;
        let ake_bl = thumb::encode_bl(ake_site, ake_stub_va)
            .ok_or_else(|| anyhow!("classic AKE detour `bl` out of range"))?;
        thumb::write(&mut w, ake_stub_va as usize, &ake_bytes);
        thumb::write(&mut w, ake_site, &ake_bl);

        *out = w;
        Ok(vec![
            ("gatea_gate", gatea_cmp as u32),
            ("gatea_stub_va", gatea_stub_va),
            ("gatea_authed", gatea_authed),
            ("ake_site", ake_site as u32),
            ("ake_stub_va", ake_stub_va),
            ("ake_gate", ake as u32),
            ("deny", gatea_deny),
            ("scratch", scratch),
            ("vid_producer", vid_producer),
        ])
    }

    /// Speed lever emission (atomic: writes only on full success). Mirrors the
    /// Speed block of [`Self::build_report`]; the `bl` range is checked before any
    /// write so a miss leaves `out` untouched.
    fn emit_speed(&self, image: &[u8], out: &mut [u8], flag_base: u32) -> Result<(u32, u32)> {
        let (speed_gate, speed_idx_reg) = self.find_speed_gate(image)?;
        let cmp_at = speed_gate as usize + 4;
        let bhi_at = speed_gate as usize + 6;
        let bhi_hw = u16::from_le_bytes([image[bhi_at], image[bhi_at + 1]]);
        if (bhi_hw & 0xFF00) != 0xD800 {
            bail!("speed gate `bhi` not at 0x{bhi_at:x} (got 0x{bhi_hw:04x})");
        }
        let mut disp = (bhi_hw & 0xFF) as i32;
        if disp >= 0x80 {
            disp -= 0x100;
        }
        let ramp_exit = (bhi_at as i32 + 4 + disp * 2) as u32;
        let fallthrough = speed_gate + 8;
        let speed_bytes =
            self.build_speed_stub(flag_base, fallthrough, ramp_exit, speed_idx_reg)?;
        let speed_stub_va = self.free_space(out, speed_bytes.len() + 16)?;
        let bl = thumb::encode_bl(cmp_at, speed_stub_va)
            .ok_or_else(|| anyhow!("Speed detour `bl` out of range"))?;
        thumb::write(out, speed_stub_va as usize, &speed_bytes);
        thumb::write(out, cmp_at, &bl);
        Ok((speed_gate, speed_stub_va))
    }

    /// Region-free lever emission (atomic). Mirrors the Region block of
    /// [`Self::build_report`].
    fn emit_region(&self, image: &[u8], out: &mut [u8], flag_base: u32) -> Result<(u32, u32)> {
        let region_emitter = self.find_region_emitter(image)?;
        let region_site = region_emitter as usize + 6;
        let region_bytes = self.build_region_stub(flag_base)?;
        let region_stub_va = self.free_space(out, region_bytes.len() + 16)?;
        let bl = thumb::encode_bl(region_site, region_stub_va)
            .ok_or_else(|| anyhow!("Region detour `bl` out of range"))?;
        thumb::write(out, region_stub_va as usize, &region_bytes);
        thumb::write(out, region_site, &bl);
        Ok((region_emitter, region_stub_va))
    }

    /// Raw-read lever emission (VID gate + AKE accept + deny reset). Validates all
    /// three sub-finds read-only first, then commits the three detours on a
    /// working copy so a mid-commit invariant break leaves `out` clean. Mirrors
    /// the AKE/Gate-A/deny blocks of [`Self::build_report`], same allocation
    /// order (ake → gate-a → deny).
    fn emit_rawread(
        &self,
        image: &[u8],
        out: &mut Vec<u8>,
        flag_base: u32,
    ) -> Result<RawReadFacts> {
        // ---- validate (read-only) ----
        // AKE accept gate — BU40N/desktop (reject-writer detour) or NB-class
        // (shared-`bl` detour). Resolved by `ake_detour`; BU40N matches the
        // original signature first, so its `reset_site`/`ake_bytes` are unchanged.
        let (reset_site, ake_bytes, ake_gate) = self.ake_detour(image, flag_base)?;

        // Producer Gate-A.
        let gatea_anchor = self.find_vid_gate(image)?;
        let gatea_cmp = gatea_anchor + 18;
        let cmp_hw = u16::from_le_bytes([image[gatea_cmp], image[gatea_cmp + 1]]);
        if cmp_hw != 0x2806 {
            bail!("VID gate `cmp r0,#6` not at 0x{gatea_cmp:x} (got 0x{cmp_hw:04x})");
        }
        let gatea_bne = gatea_cmp + 2;
        let bne_hw = u16::from_le_bytes([image[gatea_bne], image[gatea_bne + 1]]);
        if (bne_hw & 0xFF00) != 0xD100 {
            bail!("VID gate `bne` not at 0x{gatea_bne:x} (got 0x{bne_hw:04x})");
        }
        let mut d = (bne_hw & 0xFF) as i32;
        if d >= 0x80 {
            d -= 0x100;
        }
        let gatea_deny = (gatea_bne as i32 + 4 + d * 2) as u32;
        let gatea_authed = (gatea_cmp + 4) as u32;
        let vid_agid_struct = self.find_vid_agid_struct(image)?;
        let gatea_bytes =
            self.build_gatea_stub(flag_base, vid_agid_struct, gatea_authed, gatea_deny)?;

        // Deny-path AACS reset.
        let aacs_reset = self.find_aacs_session_reset(image)?;
        let deny_site = gatea_deny as usize + 0x10;
        if deny_site + 4 > image.len() {
            bail!("deny sense-setup site 0x{deny_site:x} is past the end of the image");
        }
        let d0 = u16::from_le_bytes([image[deny_site], image[deny_site + 1]]);
        let d1 = u16::from_le_bytes([image[deny_site + 2], image[deny_site + 3]]);
        if d0 != 0x2202 || d1 != 0x216f {
            bail!(
                "deny sense-setup (movs r2,#2; movs r1,#0x6f) not at 0x{deny_site:x} \
                 (got 0x{d0:04x} 0x{d1:04x})"
            );
        }
        let deny_bytes = self.build_deny_reset_stub(aacs_reset)?;

        // VID producer facts (required for the feature; reported).
        let (vid_producer, _vid_out_buf) = self.find_vid_producer(image)?;
        self.find_vid_gate_setter(image)?;

        // ---- commit on a working copy (atomic) ----
        let mut w = out.clone();
        let ake_stub_va = self.free_space(&w, ake_bytes.len() + 16)?;
        let ake_bl = thumb::encode_bl(reset_site, ake_stub_va)
            .ok_or_else(|| anyhow!("AKE detour `bl` out of range"))?;
        thumb::write(&mut w, ake_stub_va as usize, &ake_bytes);
        thumb::write(&mut w, reset_site, &ake_bl);

        let gatea_stub_va = self.free_space(&w, gatea_bytes.len() + 16)?;
        let gatea_bl = thumb::encode_bl(gatea_cmp, gatea_stub_va)
            .ok_or_else(|| anyhow!("Gate-A detour `bl` out of range"))?;
        thumb::write(&mut w, gatea_stub_va as usize, &gatea_bytes);
        thumb::write(&mut w, gatea_cmp, &gatea_bl);

        let deny_stub_va = self.free_space(&w, deny_bytes.len() + 16)?;
        let deny_bl = thumb::encode_bl(deny_site, deny_stub_va)
            .ok_or_else(|| anyhow!("deny-reset detour `bl` out of range"))?;
        thumb::write(&mut w, deny_stub_va as usize, &deny_bytes);
        thumb::write(&mut w, deny_site, &deny_bl);

        // `04 03` "data clear" (remove the drive-side bus-encryption stage, MK-style):
        // detour the OEM `bl <key-prog>` at the start of the AACS opcode-0x45 arm (via
        // busenc_detour → find_aacs45_arm). Images whose 0x45 arm is not a known
        // MT1959 shape leave the mode unwired (0). Committed last so the free_space
        // order matches build_report (…→ deny → busenc).
        let (busenc_site, busenc_stub_va) = match self.busenc_detour(image, flag_base) {
            Ok((site, bytes)) => {
                let stub_va = self.free_space(&w, bytes.len() + 16)?;
                let bl = thumb::encode_bl(site, stub_va)
                    .ok_or_else(|| anyhow!("bus-enc detour `bl` out of range"))?;
                thumb::write(&mut w, stub_va as usize, &bytes);
                thumb::write(&mut w, site, &bl);
                (site as u32, stub_va)
            }
            Err(_) => (0, 0),
        };

        // `04 03` UHD mode-gate neutralizer (MK-style classifier hook): detour the
        // classifier prologue's disc-version reload (via uhd_detour → find_uhd_classifier).
        // Images whose classifier prologue is not the known MT1959 shape leave it unwired
        // (0). Committed last so the free_space order matches build_report (…→ busenc → uhd).
        let (uhd_site, uhd_stub_va) = match self.uhd_detour(image, flag_base) {
            Ok((site, bytes)) => {
                let stub_va = self.free_space(&w, bytes.len() + 16)?;
                let bl = thumb::encode_bl(site, stub_va)
                    .ok_or_else(|| anyhow!("UHD mode-gate detour `bl` out of range"))?;
                thumb::write(&mut w, stub_va as usize, &bytes);
                thumb::write(&mut w, site, &bl);
                (site as u32, stub_va)
            }
            Err(_) => (0, 0),
        };

        // HRL skip (`flag[Feature::Hrl]==STATE_ON`): one shared stub, a `bl` to it at
        // each of the three cert-path `cmp r0,#0; bne <6F/00>` sites. Graceful:
        // images whose HRL cert path is not the known shape leave it unwired.
        // Committed last so the free_space order matches build_report (…→ uhd → hrl).
        let (hrl_sites, hrl_stub_va) = match self.hrl_skip_detour(image, flag_base) {
            Ok((sites, _revoke, bytes)) => {
                let stub_va = self.free_space(&w, bytes.len() + 16)?;
                thumb::write(&mut w, stub_va as usize, &bytes);
                for &site in &sites {
                    let bl = thumb::encode_bl(site, stub_va)
                        .ok_or_else(|| anyhow!("HRL-skip detour `bl` out of range"))?;
                    thumb::write(&mut w, site, &bl);
                }
                (sites.iter().map(|&s| s as u32).collect(), stub_va)
            }
            Err(_) => (Vec::new(), 0),
        };

        *out = w;
        Ok(RawReadFacts {
            ake_gate,
            ake_site: reset_site as u32,
            ake_stub_va,
            gatea_cmp: gatea_cmp as u32,
            gatea_stub_va,
            deny_site: deny_site as u32,
            deny_stub_va,
            busenc_site,
            busenc_stub_va,
            uhd_site,
            uhd_stub_va,
            hrl_sites,
            hrl_stub_va,
            vid_producer,
        })
    }

    /// Downgrade-enable lever. Family-agnostic: writes `0xDE` at the identity-page
    /// slot when a well-formed MTEK descriptor is present; idempotent.
    fn lever_de(&self, image: &[u8], out: &mut [u8], chip: &ChipInfo) -> LeverReport {
        if !chip.descriptor_present {
            return LeverReport::not_applicable(
                LeverId::DowngradeEnable,
                "no MTEK identity page in this image",
            );
        }
        match self.find_de_byte(image) {
            Ok(de_off) => {
                let off = de_off as usize;
                if out[off] == 0xDE {
                    LeverReport::already(LeverId::DowngradeEnable, vec![("de_off", de_off)])
                } else {
                    out[off] = 0xDE;
                    LeverReport::applied(LeverId::DowngradeEnable, vec![("de_off", de_off)])
                }
            }
            Err(e) => LeverReport::missed(LeverId::DowngradeEnable, format!("{e:#}")),
        }
    }

    /// Build an all-`AlreadyPresent` report for an image that is already
    /// freemkv-modified (idempotent re-entry). The image is returned
    /// **byte-identical** (it is already a valid, signed freemkv image), so
    /// `modify(modify(x)) == modify(x)`. Levers are marked `AlreadyPresent`
    /// (capability-gated ones `NotApplicable`) to mirror what a fresh modify
    /// produced.
    fn already_present_report(
        &self,
        image: &[u8],
        chip: &ChipInfo,
        cap: &Capability,
        engine: &'static str,
    ) -> ModifyReport {
        let mut levers = Vec::new();
        levers.push(LeverReport::already(LeverId::Identity, vec![]));
        levers.push(if cap.media_class >= MediaClass::Bd || cap.bd_aacs {
            LeverReport::already(LeverId::Speed, vec![])
        } else {
            LeverReport::not_applicable(LeverId::Speed, "no BD read-ramp on this model")
        });
        levers.push(if cap.region_lockable {
            LeverReport::already(LeverId::RegionFree, vec![])
        } else {
            LeverReport::not_applicable(LeverId::RegionFree, "no region lever on this model")
        });
        levers.push(if cap.bd_aacs {
            LeverReport::already(LeverId::RawRead, vec![])
        } else {
            LeverReport::not_applicable(LeverId::RawRead, "no AACS/BD on this model")
        });
        levers.push(if !chip.descriptor_present {
            LeverReport::not_applicable(
                LeverId::DowngradeEnable,
                "no MTEK identity page in this image",
            )
        } else {
            match self.find_de_byte(image) {
                Ok(de_off) => {
                    LeverReport::already(LeverId::DowngradeEnable, vec![("de_off", de_off)])
                }
                Err(e) => LeverReport::missed(LeverId::DowngradeEnable, format!("{e:#}")),
            }
        });
        ModifyReport {
            engine,
            family: chip.family.label().to_string(),
            vendor: chip.vendor.clone(),
            model: chip.model.clone(),
            rev: chip.rev.clone(),
            vendor_specific: chip.vendor_specific.clone(),
            media: cap.media_class.label().to_string(),
            levers,
            image: image.to_vec(),
            validation: Validation::StaticOnly,
        }
    }
}

/// True if `image` is already freemkv-modified. The Identity handler that every
/// successful modify injects carries the [`abi::RESP_MAGIC`] (`b"freemkv"`)
/// identity string, which never appears in a stock OEM image — so its presence
/// is a reliable, byte-stable "already patched by us" marker (used for
/// idempotent re-entry; see [`Mt1959Engine::build_modify`]).
pub fn is_freemkv_patched(image: &[u8]) -> bool {
    image
        .windows(abi::RESP_MAGIC.len())
        .any(|w| w == abi::RESP_MAGIC)
}

#[cfg(test)]
#[path = "mt1959_kat_tests.rs"]
mod kat_tests;
