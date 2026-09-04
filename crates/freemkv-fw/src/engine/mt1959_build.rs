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
/// Bytes per sub-function payload slot in the response table.
const SLOT_LEN: u8 = 16;
/// `log2(SLOT_LEN)` — used to index the table by `subfn * SLOT_LEN`.
const SLOT_SHIFT: u16 = 4;
/// Payload-table slot count (indices for subfns 0x01..0x06).
const NUM_SUBFNS: u8 = 6;

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

/// Signature of the OEM REPORT KEY key-format-8 (RPC state) emitter tail
/// (`0x119890` on 1.00, `0x119a84` on 1.03) — the byte-for-byte identical run
/// that marshals the 8-byte RPC-state frame into the response FIFO. RPCScheme is
/// hardcoded to `1` (RPC-2) via `r4`; the store `strb r4,[r0,#8]` is at
/// `match+14`. Region-free (0x05) detours that store (4 bytes at `match+14`,
/// consuming the following `strb r1` too) to a flag-gated stub that emits RPC-1
/// (scheme 0) when set. Proven unique per image. (`r1` is provably `0`, `r4==1`.)
const REGION_EMIT_SIG: &[(u16, u16)] = &[
    (0x466B, 0xFFFF), // mov  r3,sp
    (0x789B, 0xFFFF), // ldrb r3,[r3,#2]   s2
    (0x18D2, 0xFFFF), // adds r2,r2,r3
    (0x7202, 0xFFFF), // strb r2,[r0,#8]   frame[4]
    (0x466B, 0xFFFF), // mov  r3,sp
    (0x78DA, 0xFFFF), // ldrb r2,[r3,#3]   s3
    (0x7202, 0xFFFF), // strb r2,[r0,#8]   frame[5] = RegionMask
    (0x7204, 0xFFFF), // strb r4,[r0,#8]   frame[6] = RPCScheme (r4==1) ← detour
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

/// Build the fixed sub-function response table: `NUM_SUBFNS` slots of `SLOT_LEN`
/// bytes, indexed by `subfn-1`. Slot 0 (Identity) is the real reply
/// (`"freemkv <version>"`); the rest are `"Command 0N WIP"` placeholders so the
/// dispatch branching is provable on hardware before each command's real code
/// lands. Editing a reply is a one-line string change here — never machine code.
fn payload_table() -> Vec<u8> {
    let mut table = vec![0u8; NUM_SUBFNS as usize * SLOT_LEN as usize];
    let mut set = |idx: usize, s: &[u8]| {
        let slot = &mut table[idx * SLOT_LEN as usize..(idx + 1) * SLOT_LEN as usize];
        let n = s.len().min(SLOT_LEN as usize);
        slot[..n].copy_from_slice(&s[..n]); // remainder stays 0 (padding)
    };
    // Identity (subfn 1): the "freemkv <version>" magic + version string.
    let identity = format!(
        "{} {}",
        std::str::from_utf8(abi::RESP_MAGIC).unwrap_or("freemkv"),
        env!("CARGO_PKG_VERSION")
    );
    set(0, identity.as_bytes());
    // Slots 1..=5 (subfns 0x02..=0x06) stay zero: the control toggles return a
    // zero-length GOOD (see `build_handler`) and never read the table, and DumpAll
    // (0x09) peeks memory rather than a slot. Only Identity uses a payload slot.
    table
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
        let hw = u16::from_le_bytes([image[ins_off], image[ins_off + 1]]);
        let rt = (hw >> 8) & 0x7;
        if (hw & 0xF800) != 0x4800 || !(rt == 3 || rt == 5) {
            bail!("scanner entry+2 is not `ldr r3/r5,[pc,#imm]` (got 0x{hw:04x})");
        }
        let imm8 = (hw & 0xFF) as usize;
        let pool = ((ins_off + 4) & !3) + imm8 * 4;
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

    /// The Region-free (0x05) RPC-state emitter anchor — the unique
    /// [`REGION_EMIT_SIG`] match (`0x119890` on 1.00, `0x119a84` on 1.03).
    /// Returns the anchor offset; the RPCScheme store the detour replaces is at
    /// `anchor+14`.
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
        if best_len < NUM_SUBFNS as usize + 2 {
            bail!(
                "largest unreferenced SRAM gap is only {best_len} bytes — too small for a flag \
                 table; refusing to guess a cell"
            );
        }
        Ok((best_base + 3) & !3)
    }

    /// Assemble the freemkv `0x3C 0E` handler: knock-check, then dispatch on the
    /// sub-function (`cdb[4]`) to a fixed 16-byte payload slot, clear the response
    /// buffer, write the slot's bytes via the drive's own byte-writer, and commit
    /// the DMA. Miss on the knock → tail-call the original handler. Every address
    /// (cdb base, byte-writer, commit, length field, OEM handler) is derived from
    /// the image; only the payload strings are ours.
    ///
    /// Each sub-function persists `flag[subfn] = cdb[5]` so the OEM-code
    /// trampolines can read it: Speed (0x02), Region (0x03), and Raw Read (0x04 —
    /// the AKE accept-gate stub, see `build_ake_stub`) all act via those trampolines,
    /// not this handler. Every knock command returns the SAME fixed CLEAR_LEN
    /// response: Identity (0x01) and DumpAll (0x09) fill it with a payload; the
    /// control toggles just persist their flag and return a zeroed CLEAR_LEN buffer.
    /// The host ALWAYS reads CLEAR_LEN bytes — a `0x3C` READ BUFFER is a data-in
    /// opcode, so issuing a command with no/short data phase desyncs the transfer
    /// (ABORTED COMMAND + a wedged response FIFO). See `FreemkvUnlocker::send_state`.
    pub fn build_handler(&self, image: &[u8], oem_handler: u32, flag_base: u32) -> Result<Vec<u8>> {
        let cdb = self.find_cdb_base(image)?;
        let (writer, commit_off) = self.find_response_writer(image)?;
        let (commit, length_field) = self.find_response_commit(image)?;
        let table = payload_table();

        let mut a = Asm::new();
        let tail = a.label();
        let knock_ok = a.label();
        let generic = a.label();
        let clr = a.label();
        let clrd = a.label();
        let wr = a.label();
        let docommit = a.label();
        let nogeneric = a.label();
        let p7loop = a.label();

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
        // matched -> jump over the OEM tail block (kept here, next to the knock
        // `bne`s, so those conditional branches stay in range as the handler grows).
        a.b(knock_ok);

        // knock miss: tail-call the original handler, registers/lr as entered.
        a.bind(tail);
        a.ldr_lit(3, oem_handler | 1);
        a.bx(3);

        // matched: r7 = byte-writer, r4 = subfn.
        a.bind(knock_ok);
        a.push(0x01F0); // push {r4,r5,r6,r7,lr}
        a.ldr_lit(7, writer | 1);
        a.ldrb_imm(4, 3, 4); // subfn = cdb[4]

        // Persist flag[subfn] = cdb[5] into the SRAM flag table (see the fn doc).
        // r3 = CDB base, r4 = subfn preserved; r0/r1 are scratch here.
        a.ldr_lit(0, flag_base); // r0 = flag-table base (SRAM)
        a.adds_reg(0, 0, 4); // r0 = &flag[subfn]
        a.ldrb_imm(1, 3, abi::CDB_STATE as u16); // r1 = cdb[5] state (00 OEM / 01 patched)
        a.strb_imm(1, 0, 0); // flag[subfn] = state

        // Every knock returns the SAME fixed CLEAR_LEN buffer and the host ALWAYS
        // reads CLEAR_LEN bytes: 0x3C is a data-in opcode, so committing data but
        // issuing no (or a short) data phase desyncs the FIFO → ABORTED then hang.
        a.bind(generic);

        // clear CLEAR_LEN bytes so no stale buffer data leaks.
        a.movs_imm(5, 0);
        a.bind(clr);
        a.cmp_imm(5, CLEAR_LEN);
        a.bhs(clrd);
        a.mov_reg(0, 5);
        a.movs_imm(1, 0);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(clr);
        a.bind(clrd);

        // Speed (0x02) and Region (0x03) act via the flag persisted above + a clean
        // generic ack; 0x04/0x06 are unassigned. DumpAll (0x09): peek CLEAR_LEN bytes
        // at the 32-bit addr packed big-endian in cdb[5..9] (r3 = CDB base).
        a.cmp_imm(4, abi::SubFn::DumpAll as u8);
        a.bne(nogeneric);
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
        a.bind(p7loop);
        a.cmp_imm(5, CLEAR_LEN);
        a.bhs(docommit);
        a.mov_reg(0, 5);
        a.ldrb_reg(1, 6, 5);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(p7loop);
        a.bind(nogeneric);

        // index = subfn-1; out-of-range → commit the cleared (zero) buffer.
        a.subs_imm(4, 1);
        a.cmp_imm(4, NUM_SUBFNS);
        a.bhs(docommit);
        let tbl = a.data_blob(table);
        a.adr(6, tbl);
        a.lsls_imm(0, 4, SLOT_SHIFT); // index * SLOT_LEN
        a.adds_reg(6, 6, 0); // r6 = &slot

        // write SLOT_LEN bytes from the slot.
        a.movs_imm(5, 0);
        a.bind(wr);
        a.cmp_imm(5, SLOT_LEN);
        a.bhs(docommit);
        a.mov_reg(0, 5);
        a.ldrb_reg(1, 6, 5);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(wr);

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
        let mut a = Asm::new();
        let patched = a.label();
        let decide = a.label();
        let go_exit = a.label();
        if idx_reg == 2 {
            // Original shape: speed_index in r2; r0 is live at the ramp
            // fall-through so it is saved/restored and doubles as the flag scratch.
            // (Byte-identical to the shipped emit — the KAT pins these bytes.)
            a.push(0x0001); // push {r0}          save r0 (live at ramp fall-through)
            a.ldr_lit(0, flag_base + abi::SubFn::Speed as u32); // r0 = &flag[0x02]
            a.ldrb_imm(0, 0, 0); // r0 = Speed flag byte
            a.cmp_imm(0, abi::STATE_ON); // patched (0x01)?
            a.beq(patched); // yes -> unlimited ceiling
            a.cmp_imm(2, 0x32); // OEM: compare speed_index against the 0x32 band
            a.b(decide);
            a.bind(patched);
            a.cmp_imm(2, 0xFF); // patched: compare against the drive's own 0xFF sentinel
            a.bind(decide);
            a.pop(0x0001); // pop {r0}           restore r0 (POP preserves flags)
            a.bhi(go_exit); // replicate the OEM `bhi <ramp-exit>`
            a.ldr_lit(2, fallthrough | 1); // fall-through: r2 dead at the OEM target
            a.bx(2); // continue the OEM ramp
            a.bind(go_exit);
            a.ldr_lit(2, exit | 1); // taken: r2 dead at the OEM ramp-exit target
            a.bx(2); // jump to the OEM ramp exit
        } else {
            // r0 variant: speed_index in r0, which is DEAD after the gate (the OEM
            // ramp redefines it via `ldrb r0,[r5,#5]`), so r0 needs no saving and
            // doubles as the jump scratch. The flag byte is read into r1, saved/
            // restored around that use (r1 = the cell pointer, may be live), so the
            // only registers this stub disturbs are r0 (dead) and r1 (restored).
            a.push(0x0002); // push {r1}          save r1 (cell ptr; may be live)
            a.ldr_lit(1, flag_base + abi::SubFn::Speed as u32); // r1 = &flag[0x02]
            a.ldrb_imm(1, 1, 0); // r1 = Speed flag byte
            a.cmp_imm(1, abi::STATE_ON); // patched (0x01)?
            a.pop(0x0002); // pop {r1}           restore r1 (POP preserves flags)
            a.beq(patched); // yes -> unlimited ceiling
            a.cmp_imm(0, 0x32); // OEM: compare speed_index (r0) against the 0x32 band
            a.b(decide);
            a.bind(patched);
            a.cmp_imm(0, 0xFF); // patched: compare against the drive's own 0xFF sentinel
            a.bind(decide);
            a.bhi(go_exit); // replicate the OEM `bhi <ramp-exit>`
            a.ldr_lit(0, fallthrough | 1); // fall-through: r0 dead at the OEM target
            a.bx(0); // continue the OEM ramp
            a.bind(go_exit);
            a.ldr_lit(0, exit | 1); // taken: r0 dead at the OEM ramp-exit target
            a.bx(0); // jump to the OEM ramp exit
        }
        a.finish()
    }

    /// The Region-free (0x05) flag-gated RPC-emitter trampoline. Entered by a `bl`
    /// that replaces the OEM emitter's `strb r4,[r0,#8]` (RPCScheme=1) and the
    /// following `strb r1,[r0,#8]` (`frame[7]`=0). On entry `r0 = FIFO data-port
    /// base`, `r1 == 0`, `r4 == 1` (all per the OEM emitter); `r2` is dead. The
    /// stub reads the Region flag byte and emits RPCScheme `0` (RPC-1 → all
    /// regions) when set or `r4` (OEM RPC-2) when clear, always writes the
    /// reserved `frame[7]`=0, then replicates the emitter epilogue `pop {r3,r4,pc}`
    /// (the OEM epilogue at the detour tail becomes dead code).
    fn build_region_stub(&self, flag_base: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let patched = a.label();
        let tail = a.label();
        a.ldr_lit(2, flag_base + abi::SubFn::Region as u32); // r2 = &flag[0x05] (r2 dead)
        a.ldrb_imm(2, 2, 0); // r2 = Region flag byte
        a.cmp_imm(2, abi::STATE_ON); // patched (0x01)?
        a.beq(patched); // yes -> force RPC-1
        a.strb_imm(4, 0, 8); // OEM: frame[6] = r4 (RPCScheme = 1, RPC-2)
        a.b(tail);
        a.bind(patched);
        a.strb_imm(1, 0, 8); // patched: frame[6] = 0 (RPC-1 → region-free)
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
        a.ldr_lit(2, flag_base + abi::SubFn::RawRead as u32); // r2 = &flag[0x04]
        a.ldrb_imm(2, 2, 0); // r2 = RawRead flag byte
        a.cmp_imm(2, 2); // 02 = accept ANY host cert (revoked ok); host runs the real AKE
        a.beq(accept);
        a.movs_imm(1, 1); // 00/01: OEM reset to state 1 on a failed cert verify
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
        a.ldr_lit(2, flag_base + abi::SubFn::RawRead as u32); // r2 = &flag[0x04]
        a.ldrb_imm(2, 2, 0); // r2 = RawRead flag byte
        a.cmp_imm(2, 2); // 02 = accept ANY host cert (revoked ok)
        a.beq(force);
        a.b(keep); // flag off: preserve r1 (accept arm = 6, reject arm = 1)
        a.bind(force);
        a.movs_imm(1, 6); // forced: state 6 (AKE authenticated)
        a.bind(keep);
        a.ldr_lit(2, back | 1); // -> OEM set_agid_state(r0=agid, r1=state) call
        a.bx(2);
        a.finish()
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
        let nb_gate = self.find_ake_gate_nb(image)?;
        let reject = nb_gate as usize + 10;
        let movs_hw = u16::from_le_bytes([image[reject], image[reject + 1]]);
        if movs_hw != 0x2101 {
            bail!("NB AKE reject writer `movs r1,#1` not at 0x{reject:x} (got 0x{movs_hw:04x})");
        }
        let bl_site = nb_gate as usize + 12;
        let back = thumb::decode_bl(image, bl_site)
            .ok_or_else(|| anyhow!("NB AKE: no `bl set_agid_state` at 0x{bl_site:x}"))?;
        let bytes = self.build_ake_stub_nb(flag_base, back)?;
        Ok((bl_site, bytes, nb_gate))
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
        a.ldr_lit(2, flag_base + abi::SubFn::RawRead as u32); // r2 = &flag[0x04]
        a.ldrb_imm(2, 2, 0); // r2 = RawRead flag byte
        a.cmp_imm(2, 1); // 01 = "cert valid": force authed so a bare 0xAD returns the VID
        a.beq(rearm);
        a.cmp_imm(0, 6); // OEM / 04 02: authed iff auth byte == 6 (real AKE ran)
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
        let flag_table_len = abi::SubFn::DumpAll as u32 + 1;
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

        // Region-free (0x05): flag-gated RPC-emitter trampoline. The RPCScheme
        // store + the following reserved store (4 bytes at region_emitter+14) are
        // detoured to the stub, which replicates the emitter epilogue.
        let region_site = region_emitter as usize + 14;
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
        let flag_table_len = abi::SubFn::DumpAll as u32 + 1;
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
                Ok(f) => LeverReport::applied(
                    LeverId::RawRead,
                    vec![
                        ("ake_gate", f.ake_gate),
                        ("ake_site", f.ake_site),
                        ("ake_stub_va", f.ake_stub_va),
                        ("gatea_gate", f.gatea_cmp),
                        ("gatea_stub_va", f.gatea_stub_va),
                        ("deny_site", f.deny_site),
                        ("deny_stub_va", f.deny_stub_va),
                        ("vid_producer", f.vid_producer),
                    ],
                ),
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

        // Speed — the classic ramp ceiling is not reversed (engine-scope §4).
        levers.push(LeverReport::missed(
            LeverId::Speed,
            "MT1939 classic read-ramp ceiling not yet reversed (NEEDS-RE)",
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

        // Raw read — the classic VID/AKE gates are located + proven-unique, but the
        // clear-output scratch buffer + deny path are INFERRED (engine-scope §3), so
        // the detour is NOT emitted: a wrong reply-path desyncs the SCSI FIFO —
        // structurally unsafe, withheld. Report the located gates for audit; the emit
        // is left for hardware validation.
        levers.push(LeverReport::missed(
            LeverId::RawRead,
            "classic Raw-read withheld: clear-output/deny path unverified (SCSI-FIFO desync \
             risk) — VID/AKE gates located + proven-unique, emit pending hardware validation",
        ));

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
        let region_site = region_emitter as usize + 14;
        let region_bytes = self.build_region_stub(flag_base)?;
        let region_stub_va = self.free_space(out, region_bytes.len() + 16)?;
        let bl = thumb::encode_bl(region_site, region_stub_va)
            .ok_or_else(|| anyhow!("classic Region detour `bl` out of range"))?;
        thumb::write(out, region_stub_va as usize, &region_bytes);
        thumb::write(out, region_site, &bl);
        Ok((region_emitter, region_stub_va))
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
        let region_site = region_emitter as usize + 14;
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

        *out = w;
        Ok(RawReadFacts {
            ake_gate,
            ake_site: reset_site as u32,
            ake_stub_va,
            gatea_cmp: gatea_cmp as u32,
            gatea_stub_va,
            deny_site: deny_site as u32,
            deny_stub_va,
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
