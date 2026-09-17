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

use anyhow::{anyhow, bail, ensure, Result};

use freemkv_flash::cmac;

use super::lever::{LeverId, LeverReport, ModifyReport, Validation};
use super::mt1959::Mt1959Engine;
use crate::abi;
use crate::family::{Capability, ChipInfo, MediaClass};
use crate::thumb::{self, Asm, CommandRecord};

// The wire frame (opcode / mode / knock / identity sense) is defined once in
// `crate::abi` and imported here — the engine emits exactly what the host ABI
// describes, so the two can never drift.

/// Record flags on the live `0x3C` record. `0x01` is a drive-*ready* gate (NOT a
/// media gate — proven on hardware: the command answers with no disc), which is
/// exactly how OEM ships it. Engine-specific (a property of this firmware's
/// dispatch table), so it lives here rather than in the wire ABI.
pub const LIVE_FLAGS: u8 = 0x01;

/// Chip-family flag value marking a chain record in the dispatch table.
pub(crate) const CHAIN_FLAG: u8 = 0x04;
/// Flag value marking a segment terminator.
pub(crate) const TERM_FLAG: u8 = 0x03;
/// Record stride in bytes.
pub(crate) const STRIDE: usize = 8;
/// Minimum contiguous valid records to treat a byte range as a real table run.
pub(crate) const MIN_RUN: usize = 8;
/// Where injected code may live (past the loader); the scanner region and
/// beyond. Free space is searched from here up.
pub(crate) const CODE_REGION_START: usize = 0x0000_9c00;

/// Bytes cleared in the response buffer before writing a reply (so no stale
/// buffer data leaks into the padding beyond the payload).
pub(crate) const CLEAR_LEN: u8 = 64;
/// Number of feature flags (Feature ids `0x01..=0x07`). Sizes the SRAM flag
/// table, bounds the [`abi::Verb::Reset`] sweep, and sizes the
/// [`abi::Verb::Identity`] feature-state table appended after the magic+version.
pub(crate) const NUM_FEATURES: u8 = 7;

/// The SRAM (on-chip working RAM) window scanned by [`Mt1959Engine::find_free_sram_cell`]
/// and holding every runtime flag/scratch cell.
pub(crate) const SRAM_LO: u32 = 0x0200_0000;
pub(crate) const SRAM_HI: u32 = 0x0200_2000;

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
pub(crate) const SRAM_END: u32 = 0x0200_1a00;

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
pub(crate) const FLAG_TABLE_BASE: u32 = 0x0200_0e40;

/// TEMPORARY flash-write probe ([`abi::Verb::FlashWrite`]) constants.
///
/// The OEM flash PROGRAM routine (thumb): `program(r0=src, r1=dest, r2=len,
/// r3=op)`. `op=1` = erase-aligned read-modify-write. `dest` (r1) is a DIRECT
/// flash byte offset; `src` (r0) is a DIRECT memory pointer (`ldrb [r0+i]`). The
/// OEM HRL wrapper (0x1354a0) calls it `r0=0x30000`, `r1=0x1e0000/0x1d8000`,
/// `r2=0x8000`, `r3=1` — proven. Its address is NOT hardcoded: it is recovered
/// per image by [`Mt1959Engine::find_flash_program`] (`0x13da2a` on BU40N 1.00),
/// so the probe generalizes across the MediaTek corpus instead of pinning one VA.
///
/// Two family-invariant constants disambiguate the PROGRAM routine from a decoy
/// erase routine that shares its prologue: the mailbox doorbell cell and the
/// controller register base, both materialized in the PROGRAM routine's literal
/// pool on every owned MT19xx image. Only the true PROGRAM routine's pool ALSO
/// carries a `0x01ff_xxxx` descriptor pointer (the decoy lacks it), which is the
/// third leg of the match — see [`Mt1959Engine::find_flash_program`].
pub(crate) const FLASH_MAILBOX: u32 = 0x0200_1200;
pub(crate) const FLASH_CONTROLLER: u32 = 0x0400_2240;

/// Prologue signature of the OEM flash PROGRAM routine: `push {r0-r7,lr}; movs
/// r6,r1; movs r5,r2; movs r4,r3; cmp r3,#4; sub sp,#4; bcc <…>`. Matches TWICE
/// on a BU40N image (the true PROGRAM routine at `0x13da2a` plus a decoy erase
/// routine at `0x8faa` that shares the prologue); [`Mt1959Engine::find_flash_program`]
/// disambiguates by the literal-pool contents (mailbox + controller + descriptor).
pub(crate) const FLASH_PROGRAM_SIG: &[(u16, u16)] = &[
    (0xB5FF, 0xFFFF), // push {r0,r1,r2,r3,r4,r5,r6,r7,lr}
    (0x000E, 0xFFFF), // movs r6,r1        (dest)
    (0x0015, 0xFFFF), // movs r5,r2        (len)
    (0x001C, 0xFFFF), // movs r4,r3        (op)
    (0x2B04, 0xFFFF), // cmp  r3,#4
    (0xB081, 0xFFFF), // sub  sp,#4
    (0xD302, 0xFFFF), // bcc  <…>
];

/// Number of pool bytes past the PROGRAM routine's entry scanned for the mailbox /
/// controller / descriptor literals that identify it. The constant table of a
/// routine this size sits within its first ~1 KiB; 0x400 covers it on every owned
/// image.
pub(crate) const FLASH_POOL_SPAN: usize = 0x400;

/// Signature of the MT1959 boot-init hook site — the main-task prologue that reads
/// the boot-mode word and branches on it: `ldr r0,[pc,#imm]; push {r4,r5,r6,lr};
/// ldr r0,[r0,#0x18]; lsls r0,r0,#0x18; bmi <…>; movs r1,#0; movs r0,#0`. The
/// leading `ldr r0,[pc,#imm]` immediate varies per build, so its low byte is masked
/// (`?? 48`). This signature ANCHORS the boot-init hook, but the detour is NOT
/// written here: the `bmi` at `anchor+8` is the cold/warm-boot split, and the cold
/// arm (`movs r1,#0; movs r0,#0; bl <bss/SRAM clear>`) ZEROES the flag table before
/// the two paths rejoin. [`Mt1959Engine::emit_boot_init`] therefore follows the
/// `bmi` to its convergence target — the `bl <orig_init>` both paths reach AFTER the
/// clear — and detours THAT, so the boot stub's `0xFF` flag write is never wiped.
/// [`Mt1959Engine::find_boot_init`] still resolves this anchor's `anchor+4`
/// (the boot-status reload, left untouched). Unique (n==1) on all 68 owned MT1959 images;
/// present on the 17 MT1939-classic images only via [`BOOT_INIT_SIG_CLASSIC`]
/// (an older prologue whose second halfword differs), so the modern shape returns
/// zero there and [`Mt1959Engine::find_boot_init`] falls back.
pub(crate) const BOOT_INIT_SIG: &[(u16, u16)] = &[
    (0x4800, 0xFF00), // ldr  r0,[pc,#imm]   (boot-status base; imm varies → masked)
    (0xB570, 0xFFFF), // push {r4,r5,r6,lr}
    (0x6980, 0xFFFF), // ldr  r0,[r0,#0x18]  ← hook site (anchor+4)
    (0x0600, 0xFFFF), // lsls r0,r0,#0x18
    (0xD403, 0xFFFF), // bmi  <…>
    (0x2100, 0xFFFF), // movs r1,#0
    (0x2000, 0xFFFF), // movs r0,#0
];

/// MT1939-classic variant of the boot-init hook site. RE-derived from the classic
/// lineage (research/hoard-campaign), where the main-task prologue reads the
/// boot-mode word through the SAME `ldr r0,[r0,#0x18]; lsls r0,r0,#0x18` reload as
/// modern, but the surrounding shape differs: the `push {r4,r5,r6,lr}` of
/// [`BOOT_INIT_SIG`] is replaced by a `subs r0,#0xc0` discriminator, and the
/// trailing `movs r1,#0; movs r0,#0` pair is absent, so the modern signature
/// misses entirely on classic images. The four replayed/replaced bytes at the
/// hook site are `80 69 00 06` (`ldr r0,[r0,#0x18]; lsls r0,r0,#0x18`), byte-for-
/// byte identical to modern — so the boot-init stub itself is unchanged; only the
/// finder needs a second shape to resolve the site.
///
/// The hook site is `anchor+4` (index 2, the `ldr r0,[r0,#0x18]`), exactly as for
/// [`BOOT_INIT_SIG`]. Capability base `0x0400_2040`, boot-mode word `@0x0400_2058`.
///
/// SAFETY: this classic site is a CALLED LEAF helper, not `main()`'s prologue, so
/// its runtime power-on call-order is HARDWARE-UNCONFIRMED. The finder therefore
/// tags a classic resolution [`BootInitSite::ClassicUnconfirmed`] and
/// [`Mt1959Engine::emit_boot_init`] FAILS CLOSED on it (see the gate there): the
/// signature resolves and is unit-tested, but production emit for classic images
/// stays a deliberate one-line flip pending on-silicon verification. This helper
/// ALSO matches inside 157 modern images, so [`Mt1959Engine::find_boot_init`] must
/// try [`BOOT_INIT_SIG`] FIRST and only consult this when the modern shape returns
/// zero — a merged scan would make modern images ambiguous.
pub(crate) const BOOT_INIT_SIG_CLASSIC: &[(u16, u16)] = &[
    (0x4800, 0xFF00), // ldr  r0,[pc,#imm]   (boot-status base; imm varies → masked)
    (0x38C0, 0xFFFF), // subs r0,#0xc0       (classic discriminator)
    (0x6980, 0xFFFF), // ldr  r0,[r0,#0x18]  ← hook site (anchor+4)
    (0x0600, 0xFFFF), // lsls r0,r0,#0x18
    (0xD400, 0xFF00), // bmi  <…>            (displacement varies → masked)
];

/// SAFETY BOUND for the flash-write probe: the destination offset MUST satisfy
/// `FLASHWRITE_ALLOW_LO <= off < FLASHWRITE_ALLOW_HI`, else the handler refuses
/// (error status word, PROGRAM routine NOT called).
///
/// The window is the NV block `0x1EA000..0x1EB000` — the SAVE home. Corpus-proven
/// (all 118 OEM images) as the one always-writable free zone:
///   * OEM-WRITTEN in every one of the 118 images (the block holds the OEM region /
///     RPC-2 record at `0x1EA4B0`), so the flash controller UNLOCKS this block on
///     every drive — a write here actually PERSISTS on hardware;
///   * its head `0x1EA000..0x1EA4B0` (1200 bytes) is blank (`0xFF`) in every image —
///     free scratch that clobbers no OEM data;
///   * OUTSIDE CMAC coverage in every image — the highest CMAC-covered byte across
///     the corpus is `0x1CFFFF`, so this block clears it by a wide margin.
///
/// This REPLACES the earlier `0x1ED000..0x1EF000` (and before it `0x1D0000`) windows,
/// which the full-corpus block-writability scan proved are ALWAYS-BLANK / never
/// OEM-written — i.e. controller-LOCKED: writes there do NOT persist (the earlier
/// on-hardware 1-byte probe that read back `0xFF` failed for exactly this reason).
/// The OEM PROGRAM routine reached here is the drive's GENERAL flash programmer (28
/// callers; the HRL wrapper is only one), and `op=1` is a neighbour-preserving
/// erase-block read-modify-write, so a program in the blank head cannot disturb the
/// OEM region record lower in the same block.
pub(crate) const FLASHWRITE_ALLOW_LO: u32 = 0x001E_A000;
pub(crate) const FLASHWRITE_ALLOW_HI: u32 = 0x001E_B000;
const _: () = assert!(FLASHWRITE_ALLOW_LO < FLASHWRITE_ALLOW_HI);
// Stay inside the corpus-proven-unlocked NV block, 4-KiB erase-sector aligned —
// compile-time proven here.
const _: () = assert!(FLASHWRITE_ALLOW_LO >= 0x001E_A000);
const _: () = assert!(FLASHWRITE_ALLOW_HI <= 0x001E_B000);
const _: () = assert!(FLASHWRITE_ALLOW_LO.is_multiple_of(0x1000));
const _: () = assert!(FLASHWRITE_ALLOW_HI.is_multiple_of(0x1000));

/// SAVE home: base of the corpus-universal NV block. [`abi::Verb::Save`] programs the
/// live flag table verbatim to this flash offset; boot and [`abi::RESET_TO_FLASH`]
/// load it back. The engine resolves this per image by SIGNATURE via
/// [`Mt1959Engine::find_nv_block`] (the region record `00 04 05` at block+0x4B0 with a
/// blank head) — it is NOT a hardcoded build input. This constant is the corpus-
/// expected value (`0x1EA000` on all 118), used by the compile-time FlashWrite bound
/// and unit tests; `build_handler` asserts the signature-resolved block agrees with
/// this window on every build. The head is blank in every image and the block is
/// controller-unlocked (OEM writes the region record at `+0x4B0`), so `op=1` RMW here
/// persists our bytes while preserving that OEM record.
pub(crate) const SAVE_HOME: u32 = 0x001E_A000;
const _: () = assert!(SAVE_HOME >= FLASHWRITE_ALLOW_LO && SAVE_HOME < FLASHWRITE_ALLOW_HI);

/// SAVE payload length: the full flag table (slot 0 pad + features `0x01..=0x07`),
/// mirrored byte-for-byte. Blank flash (`0xFF`) == never-saved == all-OEM, so no
/// magic/version/CRC is needed — absence IS the OEM default.
pub(crate) const SAVE_LEN: u8 = NUM_FEATURES + 1;

/// Byte offset from [`FLAG_TABLE_BASE`] of the 1-byte SRAM scratch cell the
/// flash-write probe stages its source byte in before calling the PROGRAM
/// routine (`r0 = &scratch`). Sits in the same validated 204-byte free hole as
/// the flag table, past the 8-byte flag table (slots `0x00..=0x07`), guard-
/// checked per image by [`Mt1959Engine::assert_sram_cell_free`].
pub(crate) const FLASHWRITE_SCRATCH_OFF: u32 = 0x10;

/// Distinct status word the flash-write probe writes to the reply when it
/// REFUSES an out-of-allowlist offset (PROGRAM routine not called). ASCII
/// `"REFU"` — clearly not a PROGRAM return code, so the host can tell a refusal
/// from a real program status.
pub(crate) const FLASHWRITE_REFUSE_STATUS: u32 = 0x5245_4655;

/// Signature of the read-ramp CEILING gate inside the per-READ ramp writer
/// (`0x1bb22` on both OEM 1.00 and MK 1.03). The bare `cmp #0x32` is ambiguous
/// (the `0x32` "high-speed band" threshold has many consumers), so the full
/// four-instruction shape is matched and proven unique. The gate `cmp` is at
/// `match+4`, its `bhi <ramp-exit>` at `match+6`, and the ramp continues at
/// `match+8`. The Speed (0x02) detour replaces the `cmp/bhi` (4 bytes at
/// `match+4`) with a `bl` to a flag-gated stub; the ramp itself is UNTOUCHED.
pub(crate) const SPEED_GATE_SIG: &[(u16, u16)] = &[
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
pub(crate) const SPEED_GATE_SIG_R0: &[(u16, u16)] = &[
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
/// `flag[Ake]==STATE_OFF` (null AKE), replicating the OEM `1` when off. Proven unique; the two
/// `b <back>` displacements are masked (`0xE000/0xF800`). `movs r1,#6` is unique in
/// the AACS window, which anchors the match.
pub(crate) const AKE_GATE_SIG: &[(u16, u16)] = &[
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
/// too), forcing `6` only when `flag[Ake]==STATE_OFF`.
pub(crate) const AKE_GATE_SIG_NB: &[(u16, u16)] = &[
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
pub(crate) const AKE_GATE_SIG_NB_V5: &[(u16, u16)] = &[
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
pub(crate) const REGION_EMIT_SIG: &[(u16, u16)] = &[
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
pub(crate) const DE_BYTE_OFF: usize = 0x56;

/// Signature of the VID gate's address-compute tail inside the OEM Volume-ID
/// producer, ending in the per-AGID auth-state probe `ldrb r0,[r0]; cmp r0,#6;
/// bne <skip>`. Proven byte-identical in shape across OEM 1.00 and MK 1.03 (only
/// the pc-relative `ldr` imm8s and the `bne` displacement differ, so those are
/// masked). Unique per image — the anchor for the producer and its scratch
/// buffer. The gate `ldrb` is at `match + 16`.
pub(crate) const VID_GATE_SIG: &[(u16, u16)] = &[
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
pub(crate) const VID_GATE_SIG_NB: &[(u16, u16)] = &[
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
pub(crate) const VID_GATE_SIG_JB8: &[(u16, u16)] = &[
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
pub(crate) const SETDISCMODE_SIG: &[(u16, u16)] = &[
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
pub(crate) const AACS45_ARM_SIG_A: &[(u16, u16)] = &[
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
pub(crate) const AACS45_ARM_SIG_B: &[(u16, u16)] = &[
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
pub(crate) const BUSENC_REG: u32 = 0x0400_0000;
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
pub(crate) const BUSENC_ENABLE_BIT: u8 = 0x10;

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
/// `flag[Uhd]==STATE_ON` — zeros the disc-version (MK-parity). `lr` is already saved on
/// the stack by the preceding `push {r4-r7,lr}`, so the detour `bl` may clobber it
/// freely and the stub returns with `bx lr` to `match+10` (the classifier body).
pub(crate) const UHD_CLASSIFIER_SIG: &[(u16, u16)] = &[
    (0xB40F, 0xFFFF), // push {r0,r1,r2,r3}
    (0xB5F0, 0xFFFF), // push {r4,r5,r6,r7,lr}
    (0xB089, 0xFFFF), // sub  sp,#0x24
    (0x980E, 0xFFFF), // ldr  r0,[sp,#0x38]   disc-version reload ← detour site (match+6)
    (0x2506, 0xFFFF), // movs r5,#6           (match+8; consumed by the 4-byte detour bl)
];

/// Signature of the **version-compare** disc-version classifier — the NB/NS/newer-MK
/// codegen that classifies by disc-version *thresholds* instead of the byte-extraction
/// prologue [`UHD_CLASSIFIER_SIG`] matches. This is the SAME UHD mode-gate, only a
/// different compiler shape, and covers the MT1959 images the primary signature misses
/// (~1/3 of the fleet: BU40N `1.01`/`1.04`, BP50NB40, WH14NS40 `1.05`, BE16NU50, …).
///
/// The classifier loads the disc-version halfword (`ldrh r0,[r1]`) and buckets it by
/// two band edges, writing the class code into `r2`:
///   ```text
///   ldrh r0,[r1]              (match-2)   ← detour site (with the following `cmp`)
///   cmp  r0,#0x63             (match+0)   ← ANCHOR (the unique head)
///   bls  <lo-band>            (match+2)   return target of the stub's stealth path
///   movs r2,#2               (match+4)   class = UHD/BD (mode-1 — the refused bucket)
///   b    <join1>
///   ldrh r0,[r1]                          reload for the second compare
///   cmp  r0,#0x5e
///   bls  <arm-C>
///   movs r2,#1                            mid band
///   movs r1,#0x73; movs r0,#1; b <join2>
///   movs r2,#3               (match+0x16) ← arm C (lowest band == what version-0 hits)
///   ...join1: movs r1,#0x73; movs r0,#3
///   join2: bl <compose_disc_mode>        packs (r0<<16)|(r1<<8)|r2 into the mode word
///   ```
/// `movs r2,#2` (`r2==2`) is the UHD "mode 1" the downstream REPORT KEY gate refuses
/// with `6F/01`; arm C (`r2==3`, `r0==3`) is exactly the class a disc-version of `0`
/// falls into. So "force the seen disc-version to 0" here = **route to arm C**: the
/// stub (only when `flag[Feature::Uhd]==STATE_ON`) branches straight to `match+0x16`,
/// which is byte-for-byte the version-0 outcome (MK-parity), and otherwise replays
/// `ldrh r0,[r1]; cmp r0,#0x63` verbatim (stealth). The two `bls` displacements are
/// masked. Consulted **only when [`UHD_CLASSIFIER_SIG`] matches zero** (original-first),
/// so the BU40N KAT base and every image the byte-extraction shape covers are untouched.
pub(crate) const UHD_CLASSIFIER_SIG_VER: &[(u16, u16)] = &[
    (0x2863, 0xFFFF), // cmp  r0,#0x63     ← anchor (the `ldrh r0,[r1]` is at match-2)
    (0xD900, 0xFF00), // bls  <lo-band>
    (0x2202, 0xFFFF), // movs r2,#2        class = UHD/BD (mode-1, the refused bucket)
    (0xE000, 0xF800), // b    <join1>
    (0x8808, 0xFFFF), // ldrh r0,[r1]      reload for the second compare
    (0x285E, 0xFFFF), // cmp  r0,#0x5e
    (0xD900, 0xFF00), // bls  <arm-C>
    (0x2201, 0xFFFF), // movs r2,#1
    (0x2173, 0xFFFF), // movs r1,#0x73
    (0x2001, 0xFFFF), // movs r0,#1
];

/// Signature of the AACS **REPORT KEY disc-mode/class accept gate** — the code
/// that decides whether the drive engages a disc for AACS key exchange, keyed on
/// the disc *mode* (`0`=BD/AACS-1.0, `1`=UHD/AACS-2.0 mode-1) and the classifier's
/// *class* byte (`class_struct[7]`). Anchor is the `cmp r0,#1` (mode==1 test); the
/// `Feature::Bd` detour replaces the **mode-0 class check** `ldrb r0,[r2,#7]; cmp
/// r0,#2` at `anchor+16` (`0x1365ce` on BU40N 1.00):
///   ```text
///   cmp  r0,#1              (anchor)     mode == 1 (UHD)?
///   bne  <mode-not-1>       (anchor+2)
///   ldrb r0,[r2,#7]                      class
///   cmp  r0,#3                           UHD accepts iff class==3
///   bne  <deny>
///   ldrb r0,[r1,#0]                      reload mode
///   cmp  r0,#0                           mode == 0 (BD)?
///   bne  <accept>
///   ldrb r0,[r2,#7]        (anchor+16)   ← DETOUR SITE: BD class
///   cmp  r0,#2             (anchor+18)   BD accepts iff class==2
///   beq  <accept>          (anchor+20)   ← stub returns here (uses its Z flag)
///   ...deny: movs r2,#1; movs r1,#0x6f; movs r0,#5; bl <set_sense>  (OEM 6F refusal)
///   ```
/// The `Feature::Bd` stub replays `ldrb r0,[r2,#7]` and then, only when
/// `flag[Bd]==STATE_OFF` (`0x00`), forces a non-equal compare so the caller's `beq`
/// falls through to the OEM deny block (which raises the drive's own `6F` refusal
/// sense) — i.e. the drive REFUSES a BD disc it would otherwise engage. At any
/// non-`STATE_OFF` value (`0xFF` passthrough / `0x01` on) it replays the OEM
/// `cmp r0,#2` verbatim. The boot hook writes `0xFF` into every flag at power-on, so
/// an unarmed/boot image never sees `0x00` here and is byte-behaviour-identical to
/// OEM (stealth) — which is what lets BD use the uniform `0x00` OFF instead of the
/// old distinct `0x02` sentinel. This is the real enforcement point
/// (not the classifier, which only *sets* the class), it reuses OEM's own deny
/// path (no fabricated sense), and it is **unique** in the REPORT KEY window on
/// every MT1959 image that carries this shape; images with a different REPORT KEY
/// codegen leave `Feature::Bd` gracefully unwired (like busenc/uhd/hrl).
///
/// # Corpus measurement
/// Measured over the 118-image OEM corpus (`/tmp/corpus_dw.tsv`): this **explicit
/// mode/class** codegen resolves UNIQUELY on 36 images (n==1), 0 on the rest,
/// never n>1 — so the sig is not over-matching. The remaining AACS images carry
/// the SAME media accept gate in a newer codegen ([`BD_GATE_SIG_VER`]) where the
/// mode==0/BD arm and the class check are folded into a single descriptor
/// classifier; [`Mt1959Engine::find_bd_gate`] consults this exact sig first
/// (original-first — so the BU40N KAT base and the 36 stay byte-identical) and
/// falls back to `BD_GATE_SIG_VER` only when this matches zero.
pub(crate) const BD_GATE_SIG: &[(u16, u16)] = &[
    (0x2801, 0xFFFF), // cmp  r0,#1          ← anchor (mode==1 test)
    (0xD100, 0xFF00), // bne  <mode-not-1>
    (0x79D0, 0xFFFF), // ldrb r0,[r2,#7]
    (0x2803, 0xFFFF), // cmp  r0,#3
    (0xD100, 0xFF00), // bne  <deny>
    (0x7808, 0xFFFF), // ldrb r0,[r1,#0]
    (0x2800, 0xFFFF), // cmp  r0,#0          mode==0 (BD)?
    (0xD100, 0xFF00), // bne  <accept>
    (0x79D0, 0xFFFF), // ldrb r0,[r2,#7]     ← detour site (anchor+16)
    (0x2802, 0xFFFF), // cmp  r0,#2          BD accepts iff class==2
    (0xD000, 0xFF00), // beq  <accept>       ← stub returns here (anchor+20)
];

/// Signature of the **newer-codegen** AACS media accept gate — the same disc
/// mode/class accept/refuse decision as [`BD_GATE_SIG`], but emitted as one
/// descriptor-classifier function instead of the explicit REPORT KEY mode/class
/// ladder. On the ~62 AACS images that carry it (and it is present, byte-identical
/// in its core, on the 36 explicit-shape images too — those keep the original
/// detour via original-first ordering), this is the ONLY `6F/05` media deny in the
/// image, so BD (mode-0) acceptance necessarily flows through it.
///
/// The anchor is the disc-**mode** read + BD arm; the gate body is fixed-shape
/// across every image (only pc-relative literals and branch displacements vary):
///   ```text
///   ldrb r2,[r1]           (anchor)      disc mode byte  (r1 = computed descriptor ptr)
///   movs r5,#1
///   ldr  r1,[pc,#imm]                    r1 = &session struct
///   cmp  r2,#0             (anchor+6)    mode == 0 (BD/AACS-1.0)?   ← DETOUR SITE
///   sub  sp,#imm                         (frame reserve, no flags)
///   bne  <mode-not-0>      (anchor+10)   mode != 0 → other-mode path ← stub returns here
///   ldrb r2,[r1,#6]                      BD path: descriptor gate byte
///   cmp  r2,#0
///   beq  <class-check>                   → shared `ldrb; lsrs #5; cmp #3` accept/deny
///   ...
///   <deny>: movs r2,#1; movs r1,#0x6f; movs r0,#5; bl <set_sense>  (OEM 6F refusal)
///           add sp,#imm; pop {r4,r5,pc}          ← at `anchor+0x40`
///   ```
/// The final `ldrb; lsrs #5; cmp #3` class check is SHARED by every disc mode, so
/// it is NOT a mode-specific detour target; the mode discriminator is the
/// `cmp r2,#0` at `anchor+6` (mode==0 == BD, exactly as the old gate's
/// `ldrb r0,[r1,#0]; cmp r0,#0` BD arm). The `Feature::Bd` detour replaces
/// `cmp r2,#0; sub sp,#imm` (4 bytes at `anchor+6`) with a `bl` to
/// [`Mt1959Engine::build_bd_stub_ver`]; when `flag[Bd]==STATE_OFF` **and** the disc
/// is mode-0 (BD) the stub jumps to the OEM deny at `anchor+0x40` (drive refuses
/// BD); otherwise it replays `sub sp` + `cmp r2,#0` verbatim so the caller's `bne`
/// sees the exact OEM `Z` flag — byte-behaviour-identical to OEM (stealth), and the
/// mode!=0 (UHD/other) arm is never touched. Proven UNIQUE (n==1) full-image on all
/// 98 carriers, absent on the 20 non-AACS/classic parts, `deny == anchor+0x40` and
/// the detour geometry verified on every carrier.
pub(crate) const BD_GATE_SIG_VER: &[(u16, u16)] = &[
    (0x780A, 0xFFFF), // ldrb r2,[r1]        ← anchor (disc mode read)
    (0x2501, 0xFFFF), // movs r5,#1
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]
    (0x2A00, 0xFFFF), // cmp  r2,#0          mode==0 (BD)?  ← detour site (anchor+6)
    (0xB080, 0xFF80), // sub  sp,#imm        (frame reserve; imm masked)
    (0xD102, 0xFFFF), // bne  <mode-not-0>   ← stub returns here (anchor+10)
    (0x798A, 0xFFFF), // ldrb r2,[r1,#6]     BD-path descriptor gate byte
    (0x2A00, 0xFFFF), // cmp  r2,#0
    (0xD000, 0xFF00), // beq  <class-check>
];

/// Byte offset from the [`BD_GATE_SIG_VER`] anchor to the OEM `6F/05` media deny
/// block (`movs r2,#1; movs r1,#0x6f; movs r0,#5; …`). Fixed across every carrier
/// (the intervening instruction count is invariant); verified `== 0x40` on all 98.
pub(crate) const BD_GATE_VER_DENY_OFF: u32 = 0x40;

/// Signature of the flash-resident **Host Revocation List (HRL) lookup** routine
/// (`0x13550e` on BU40N 1.00; relocated per version — e.g. `0x13569a` on BU40N
/// 1.02 / BU50N, `0x134cca` on WH16NS60, `0x138e9a` on BE16NU50 — all
/// byte-identical in shape across the MT1959 **and** MT1939 lineages). Returns
/// `1`=host revoked, `2`=blank/`0xFFFF` sentinel, `0`=clean. The cert-send path
/// calls it and then tests `cmp r0,#0; bne <revoke>` at one or more sites; the
/// HRL-skip detour (`flag[Feature::Hrl]==STATE_OFF`) forces the clean (fall-through)
/// path at those sites.
///
/// The fingerprint is **version-invariant by FUNCTION BODY**, not by the BU40N
/// prologue alone: `push {r0,r1,r4-r7,lr}; sub sp,#0xc; ldr r0,[sp,#0xc]; movs
/// r4,r1; bl <count-reader>; movs r7,r0; movs r0,r4; bl <…>; str r0,[sp,#8]; adds
/// r0,r4,#4`. The three `bl` displacements are masked; the surrounding body ops
/// are exact. Extending past the prologue is load-bearing: the bare 6-halfword
/// prologue also occurs (once) on non-AACS DVD-only drives and would false-match,
/// whereas the 12-halfword body is UNIQUE per image and matches on exactly the 91
/// AACS-capable images (parity with the peer AKE/Bus/UHD/Region cert-path gates),
/// 0 on the DVD/CD-only parts. Proven UNIQUE across the 118-image OEM corpus in
/// `[0x130000,0x140000)`; the sibling AACS helper called alongside it at the same
/// cert sites (`push {r4,r5,r6,lr}` prologue) does NOT match. Verified against the
/// capstone traces of BU40N 1.00, BU50N, WH16NS60, and BE16NU50.
pub(crate) const HRL_LOOKUP_SIG: &[(u16, u16)] = &[
    (0xB5F3, 0xFFFF), // push {r0,r1,r4,r5,r6,r7,lr}
    (0xB083, 0xFFFF), // sub  sp,#0xc
    (0x9803, 0xFFFF), // ldr  r0,[sp,#0xc]
    (0x000C, 0xFFFF), // movs r4,r1
    (0xF000, 0xF800), // bl   <count-reader>  hi
    (0xF800, 0xF800), //                      lo
    (0x0007, 0xFFFF), // movs r7,r0
    (0x0020, 0xFFFF), // movs r0,r4
    (0xF000, 0xF800), // bl   <…>             hi
    (0xF800, 0xF800), //                      lo
    (0x9002, 0xFFFF), // str  r0,[sp,#8]
    (0x1D20, 0xFFFF), // adds r0,r4,#4
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
pub(crate) const HRL_WIPE_ARMED: bool = false;

/// Bless-gate for the MT1939-**classic** boot-init hook. The classic reload site is
/// a called leaf helper whose power-on call-order is hardware-unconfirmed: installing
/// a power-on `0xFF`-fill stub there could brick a classic drive if on-chip SRAM
/// isn't up yet when the leaf runs. The detour rule resolves statically and uniquely
/// 17/17 ([`classic_boot_init_caller`]), but [`Mt1959Engine::emit_boot_init`] only
/// ships it when this is `true`. Default `false` = fail-closed (classic base ships
/// handler-only, no boot hook — safe, see [`Mt1959Engine::build_report_classic`]).
///
/// **Now `true` — blessed on emulation evidence** (`private-repo/tools/boot-emulator`,
/// Unicorn ARM boot): on all 17 classic images the OEM C-runtime scatterload writes the
/// flag-cell SRAM span at icount ~1285, while the detoured leaf caller is not reached
/// until ~128k — SRAM is provably initialised ~127k instructions before our detour. Since
/// the OEM's own write to that cell succeeds on every real-silicon boot, the SRAM
/// controller is provably enabled long before the leaf, so the boot stub's fill cannot
/// fault (a fault there would require the OEM's earlier write to the same cell to fault
/// first — the drive would not boot). This is stronger than the modern hook's ordering
/// bless. Tier: **emulation-verified** (a single reversible on-silicon read-back, doc §5,
/// remains the final belt-and-braces check if a classic drive becomes available).
pub(crate) const CLASSIC_BOOT_BLESSED: bool = true;

/// The [`abi::Verb::Identity`] reply lead-in: `"freemkv <version>"` (magic +
/// crate version). The live feature-state table (7 bytes, `flag[0x01..=0x07]`)
/// is appended after this by the handler at runtime.
pub(crate) fn identity_blob() -> Vec<u8> {
    format!(
        "{} {}",
        std::str::from_utf8(abi::RESP_MAGIC).unwrap_or("freemkv"),
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
}

/// Resolve the pc-relative literal an `ldr rX, [pc, #imm]` at file offset `at`
/// loads (`None` if the halfword there is not such a load).
pub(crate) fn pc_literal(image: &[u8], at: usize) -> Option<u32> {
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
pub(crate) fn referenced_sram(image: &[u8]) -> std::collections::BTreeSet<u32> {
    pub(crate) fn mark(used: &mut std::collections::BTreeSet<u32>, base: u32, span: u32) {
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
pub(crate) fn matches_sig(image: &[u8], sig: &[(u16, u16)], off: usize) -> bool {
    sig.iter().enumerate().all(|(k, &(v, m))| {
        let hw = u16::from_le_bytes([image[off + 2 * k], image[off + 2 * k + 1]]);
        (hw & m) == v
    })
}

/// Find the first offset in `[lo, hi)` whose halfwords match `sig` (each entry a
/// `(value, mask)` pair, matched as `(hw & mask) == value`).
pub(crate) fn find_masked(image: &[u8], sig: &[(u16, u16)], lo: usize, hi: usize) -> Option<usize> {
    let hi = hi.min(image.len().saturating_sub(sig.len() * 2));
    (lo..hi)
        .step_by(2)
        .find(|&off| matches_sig(image, sig, off))
}

/// Every offset in `[lo, hi)` matching `sig` — used where a finder must prove a
/// signature is *unique* (refuse rather than guess if it is not).
pub(crate) fn find_masked_all(
    image: &[u8],
    sig: &[(u16, u16)],
    lo: usize,
    hi: usize,
) -> Vec<usize> {
    let hi = hi.min(image.len().saturating_sub(sig.len() * 2));
    (lo..hi)
        .step_by(2)
        .filter(|&off| matches_sig(image, sig, off))
        .collect()
}

/// Locate `sig`'s single occurrence in `[lo, hi)`, failing loudly if it is absent
/// or ambiguous (more than one hit) — the "prove it or refuse" contract every
/// grounded finder uses.
pub(crate) fn find_unique(
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
pub(crate) fn decode_bl_target(image: &[u8], at: usize) -> Option<u32> {
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

/// From a resolved [`BOOT_INIT_SIG`] hook `site` (`anchor+4`, the boot-status
/// reload), follow the cold/warm-boot `bmi` at `anchor+8` to the convergence point
/// and decode the 32-bit `bl <orig_init>` that sits there.
///
/// The `bmi` is a Thumb T1 conditional branch (`0xD4xx`) whose signed 8-bit
/// immediate is a halfword count relative to `(anchor+8)+4`, so the convergence
/// address is `conv = (anchor+8) + 4 + (simm8 << 1)`. On BU40N this resolves to
/// `0x13d428`, the first instruction after the cold-boot bss/SRAM clear rejoins the
/// warm path. Returns `(conv, orig_init)` — the detour site and the original init
/// routine the boot stub tail-calls — or `None` when the instruction at `conv` is
/// not a 32-bit Thumb `bl` (first halfword `0xF000..=0xF7FF`, second
/// `0xF800..=0xFFFF`), so a build fails closed rather than mis-patching.
pub(crate) fn boot_init_convergence(image: &[u8], site: usize) -> Option<(usize, u32)> {
    let anchor = site.checked_sub(4)?;
    let bmi_at = anchor + 8;
    let bmi = u16::from_le_bytes([*image.get(bmi_at)?, *image.get(bmi_at + 1)?]);
    if (bmi & 0xFF00) != 0xD400 {
        return None; // not the expected cold/warm-boot `bmi`
    }
    let simm8 = (bmi & 0x00FF) as u8 as i8 as i32;
    let conv = ((bmi_at as i32 + 4) + (simm8 << 1)) as usize;
    // The convergence point MUST be a 32-bit Thumb `bl` (the original init call).
    let h1 = u16::from_le_bytes([*image.get(conv)?, *image.get(conv + 1)?]);
    let h2 = u16::from_le_bytes([*image.get(conv + 2)?, *image.get(conv + 3)?]);
    if !(0xF000..=0xF7FF).contains(&h1) || !(0xF800..=0xFFFF).contains(&h2) {
        return None;
    }
    let orig_init = thumb::decode_bl(image, conv)?;
    Some((conv, orig_init))
}

/// Emit code writing the 32-bit register `src` big-endian into the reply buffer
/// at byte offsets `base_off..base_off+4`, through the drive byte-writer held in
/// **r7** (`writer(r0=offset, r1=byte)`). Uses r5 as scratch and preserves
/// `src`. Used by the [`abi::Verb::FlashWrite`] probe to marshal the echoed
/// offset and the PROGRAM status word into the data-in reply. The byte-writer
/// preserves r4-r7 (proven by the handler's clear/dump loops using r5/r6 across
/// it), so `src` (r4/r6) survives the four calls.
pub(crate) fn emit_be_word_to_response(a: &mut Asm, src: u16, base_off: u8) {
    for idx in 0u16..4 {
        // r5 = (src >> (8*(3-idx))) & 0xFF — isolate one byte via left-then-right.
        if idx == 0 {
            a.lsrs_imm(5, src, 24);
        } else {
            a.lsls_imm(5, src, 8 * idx);
            a.lsrs_imm(5, 5, 24);
        }
        a.movs_imm(0, base_off + idx as u8);
        a.mov_reg(1, 5);
        a.blx(7);
    }
}

/// Emit a **flash write** through the OEM PROGRAM engine — the reusable freemkv flash
/// primitive (SAVE uses it; so can any future freemkv-owned write). The engine can only
/// source program data from the firmware's reserved NV DRAM window (it applies
/// `phys = (src & 0x00FFFFFF) + dram_base`), so an SRAM src is unreachable. This:
///   1. reads the boot-set window globals `dram_base = [dram_base_ptr]` and
///      `buf_off = [dram_base_ptr + 4]` (the reserved NV scratch offset);
///   2. CPU-stages `len` bytes from SRAM `src` into `dram_base + buf_off`;
///   3. calls `PROGRAM(src = buf_off, dest, len, op = 1)` — a 4 KiB-sector RMW that
///      erases + reprograms while preserving every neighbouring byte in the sector.
///
/// Leaves the PROGRAM status word in **r0**. Clobbers r0,r1,r2,r3,r5,r6. `dest`/`src`
/// are fixed flash/SRAM addresses (compile-time). NOTE: PROGRAM reports "sequence
/// issued", never "committed" — callers that must confirm should read `dest` back.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_flash_write(
    a: &mut Asm,
    dram_base_ptr: u32,
    dest: u32,
    src: u32,
    len: u8,
    flash_program: u32,
) {
    a.ldr_lit(0, dram_base_ptr);
    a.ldr_imm(6, 0, 0); // r6 = dram_base = [dram_base_ptr]
    a.ldr_lit(0, dram_base_ptr + 4);
    a.ldr_imm(5, 0, 0); // r5 = buf_off = [dram_base_ptr+4] (reserved NV window offset)
    a.adds_reg(6, 6, 5); // r6 = dram_base + buf_off (DRAM staging target)
    a.ldr_lit(0, src); // r0 = &src (SRAM)
    for i in 0..len as u16 {
        a.ldrb_imm(1, 0, i);
        a.strb_imm(1, 6, i); // stage src[i] -> DRAM window
    }
    a.mov_reg(0, 5); // r0 = src arg = buf_off (window offset; PROGRAM re-adds dram_base)
    a.ldr_lit(1, dest); // r1 = flash dest offset
    a.movs_imm(2, len); // r2 = len
    a.movs_imm(3, 1); // r3 = op=1 (RMW erase, neighbour-preserving)
    a.ldr_lit(5, flash_program | 1);
    a.blx(5); // r0 = PROGRAM status word (r4-r11 preserved)
}

/// The resolved boot-init hook site, tagged by which prologue shape matched.
///
/// The distinction is load-bearing for safety: a [`Self::Modern`] site is the
/// MT1959 main-task prologue whose power-on boot hook is HARDWARE-CONFIRMED, so
/// [`Mt1959Engine::emit_boot_init`] ships it. A [`Self::ClassicUnconfirmed`] site
/// is the MT1939-classic leaf helper (matched by [`BOOT_INIT_SIG_CLASSIC`]) whose
/// runtime power-on call-order has NOT been verified on silicon, so `emit_boot_init`
/// FAILS CLOSED on it — the classic images degrade to DE-only exactly as before,
/// while the site now resolves and is unit-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootInitSite {
    /// MT1959 modern prologue site (blessed; shipped by `emit_boot_init`).
    Modern(u32),
    /// MT1939-classic leaf-helper site (hardware-unconfirmed; `emit_boot_init`
    /// fails closed pending on-silicon call-order verification).
    ClassicUnconfirmed(u32),
}

impl BootInitSite {
    /// The hook-site file offset, regardless of which prologue shape matched.
    pub fn site(self) -> u32 {
        match self {
            BootInitSite::Modern(s) | BootInitSite::ClassicUnconfirmed(s) => s,
        }
    }
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
        // Dispatch-table windows come from the image's LINEAGE PROFILE (data, not a
        // `_classic` fork), tried ORIGINAL-FIRST: MT1959 images resolve in the first
        // (MT1959) window and never consult the relocated JBC6 window, so their emit
        // stays byte-identical. JBC6/older-MT1939 keep the same record format but a
        // window above 0x180000; classic lists its own ~0x1a4000 window.
        let windows = super::profile::for_image(image).live_record_windows;
        let mut last = None;
        for &(lo, hi) in windows {
            match self.find_live_record_in(image, opcode, lo, hi) {
                Ok(r) => return Ok(r),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            anyhow!("no dispatch-table window configured for this lineage (opcode 0x{opcode:02x})")
        }))
    }

    /// [`Self::find_live_record`] over an explicit table window. dispatch table lives in the lineage-profile window (MT1959 at 0x140000..0x160000); the MT1939 **classic**
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
        // Commit windows come from the image's LINEAGE PROFILE, tried ORIGINAL-FIRST:
        // MT1959 resolves in the first window (byte-identical); JBC6/older-MT1939 places
        // the same commit routine (same three anchors) above 0xA0000, listed second.
        let windows = super::profile::for_image(image).commit_windows;
        let mut last = None;
        for &(lo, hi) in windows {
            match self.find_response_commit_in(image, lo, hi) {
                Ok(r) => return Ok(r),
                Err(e) => last = Some(e),
            }
        }
        Err(last
            .unwrap_or_else(|| anyhow!("no response-commit window configured for this lineage")))
    }

    /// [`Self::find_response_commit`] over an explicit `[lo,hi)` code window.
    pub fn find_response_commit_in(
        &self,
        image: &[u8],
        lo: usize,
        hi: usize,
    ) -> Result<(u32, u32)> {
        const SRAM: std::ops::Range<u32> = 0x0200_0000..0x0200_2000;
        let hi = hi.min(image.len().saturating_sub(4));
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

    /// Locate the OEM flash **PROGRAM** routine (`program(r0=src, r1=dest, r2=len,
    /// r3=op)`) — the entry a [`abi::Verb::FlashWrite`] `bl`s. Returns the routine's
    /// address (`0x13da2a` on BU40N 1.00; VA == file offset in this flat image).
    ///
    /// The raw prologue [`FLASH_PROGRAM_SIG`] is NOT unique: it also matches a decoy
    /// erase routine that shares the prologue (`0x8faa` on BU40N). Disambiguate by the
    /// candidate's constant table (`+0..+FLASH_POOL_SPAN`), requiring ALL THREE of the
    /// mailbox constant [`FLASH_MAILBOX`], the controller constant [`FLASH_CONTROLLER`],
    /// and a descriptor pointer word in `[0x01ff_0000, 0x0200_0000)`. Only the true
    /// PROGRAM routine carries all three (the decoy lacks the descriptor), which yields
    /// exactly one qualifying candidate across the owned MT19xx corpus. Refuses (rather
    /// than guessing) if zero or more than one candidate qualifies.
    pub fn find_flash_program(&self, image: &[u8]) -> Result<u32> {
        // A descriptor pointer lives in the trailing pool of the true PROGRAM routine.
        let pool_has_word_in = |from: usize, range: std::ops::Range<u32>| -> bool {
            let end = (from + FLASH_POOL_SPAN).min(image.len().saturating_sub(4));
            (from..end)
                .step_by(2)
                .any(|p| range.contains(&thumb::read_u32(image, p)))
        };
        let qualifies = |cand: usize| -> bool {
            pool_has_word_in(cand, FLASH_MAILBOX..FLASH_MAILBOX + 1)
                && pool_has_word_in(cand, FLASH_CONTROLLER..FLASH_CONTROLLER + 1)
                && pool_has_word_in(cand, 0x01ff_0000..0x0200_0000)
        };
        let hits: Vec<usize> = find_masked_all(image, FLASH_PROGRAM_SIG, 0, image.len())
            .into_iter()
            .filter(|&c| qualifies(c))
            .collect();
        match hits.as_slice() {
            [one] => Ok(*one as u32),
            other => bail!(
                "flash PROGRAM routine (prologue + mailbox 0x{FLASH_MAILBOX:08x} + \
                 controller 0x{FLASH_CONTROLLER:08x} + 0x01ff descriptor) matched {} \
                 candidate(s) (want exactly 1) — refusing to patch",
                other.len()
            ),
        }
    }

    /// Locate the **NV DRAM-window base pointer** — the SRAM address of the global that
    /// holds the flash controller's program-source translation base (the engine reads a
    /// program source as `phys = (src & 0x00FFFFFF) + [ptr]`). freemkv's flash-write
    /// primitive ([`emit_flash_write`]) stages data into that window and passes a window
    /// offset, because the OEM program engine cannot source SRAM directly. `[ptr+4]` is
    /// the reserved NV scratch window offset.
    ///
    /// MUST be signature-derived: it is `0x02000C78` on MT1959 but takes SEVEN distinct
    /// values across the 85 MT1939 images (even within one model line across versions), so
    /// a hardcoded constant would corrupt every MT1939 flash write. Validated 118/118.
    ///
    /// Method: the PROGRAM routine's op=1 RMW path calls two copy helpers (stage +
    /// overlay) that each load this pointer as their first pc-relative SRAM literal. Scan
    /// PROGRAM's body for `bl` targets, read each target's first `ldr rX,[pc,#imm]` SRAM
    /// literal (`0x02000000..0x02002000`, 4-aligned), and return the value loaded by
    /// **≥2 distinct helpers** — unique corpus-wide. Refuses otherwise.
    pub fn find_nv_dram_base(&self, image: &[u8]) -> Result<u32> {
        const SRAM: std::ops::Range<u32> = 0x0200_0000..0x0200_2000;
        let program = self.find_flash_program(image)? as usize;
        // Distinct `bl` targets within the PROGRAM body (op=1 RMW calls its copy helpers).
        let mut targets: Vec<usize> = Vec::new();
        let end = (program + 0x260).min(image.len().saturating_sub(4));
        let mut off = program;
        while off + 4 <= end {
            if let Some(t) = thumb::decode_bl(image, off) {
                let t = t as usize;
                if t < image.len() && !targets.contains(&t) {
                    targets.push(t);
                }
            }
            off += 2;
        }
        // literal -> number of distinct helper routines that load it as their first ldr[pc].
        let mut hits: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
        for &t in &targets {
            let tend = (t + 0x40).min(image.len().saturating_sub(2));
            let mut p = t & !1;
            while p + 2 <= tend {
                let hw = u16::from_le_bytes([image[p], image[p + 1]]);
                if (hw & 0xF800) == 0x4800 {
                    if let Some(v) = pc_literal(image, p) {
                        if SRAM.contains(&v) && v & 3 == 0 {
                            *hits.entry(v).or_default() += 1;
                        }
                    }
                    break; // first ldr[pc] of the routine only
                }
                p += 2;
            }
        }
        let winners: Vec<u32> = hits
            .iter()
            .filter(|(_, &c)| c >= 2)
            .map(|(&v, _)| v)
            .collect();
        match winners.as_slice() {
            [one] => Ok(*one),
            other => bail!(
                "NV DRAM-window base pointer: {} SRAM literal(s) loaded by >=2 PROGRAM copy \
                 helpers (want exactly 1) — refusing to resolve the flash-write staging base",
                other.len()
            ),
        }
    }

    /// Locate the **NV block base** (the SAVE home) by the OEM region/RPC-2 record
    /// SIGNATURE — no hardcoded flash offset. The record `00 04 05` sits at a fixed
    /// sub-block offset `+0x4B0`, 16-byte aligned, followed by `0xFF` fill, with the
    /// block head below it (`base..base+0x4B0`) blank — that head is freemkv's write
    /// scratch. Returns the 4 KiB block base (`0x1EA000` on every corpus image, both
    /// chips — proven 118/118 by the corpus NV scan). Because SAVE/RESET/boot all read
    /// and write here, resolving it per-image (rather than trusting a constant) keeps
    /// the foundation correct even on a re-laid-out or wrapped-then-dewrapped payload.
    ///
    /// Refuses (rather than guessing) unless EXACTLY ONE qualifying record exists in the
    /// top 192 KiB of flash — the structural constraints (record bytes + `+0x4B0`
    /// sub-offset + `0xFF` fill + a blank ≥0x4B0-byte head) yield a unique hit corpus-
    /// wide.
    pub fn find_nv_block(&self, image: &[u8]) -> Result<u32> {
        const REC: [u8; 3] = [0x00, 0x04, 0x05]; // OEM region/RPC-2 record tag
        const SUB: usize = 0x4B0; // record offset within its 4 KiB block
        let lo = image.len().saturating_sub(0x3_0000); // NV lives in the top of flash
        let hits: Vec<usize> = (lo..image.len().saturating_sub(16))
            .filter(|&p| {
                (p & 0xFFF) == SUB
                    && p >= SUB
                    && image[p..p + 3] == REC
                    && image[p + 3..p + 16].iter().all(|&b| b == 0xFF)
                    && image[p - SUB..p].iter().all(|&b| b == 0xFF)
            })
            .collect();
        match hits.as_slice() {
            [rec] => Ok((*rec as u32) & !0xFFF),
            other => bail!(
                "NV region record (00 04 05 at block+0x4b0 with a blank head) matched {} \
                 candidate(s) in the top 192 KiB (want exactly 1) — refusing to resolve \
                 SAVE home",
                other.len()
            ),
        }
    }

    /// Locate the MT1959 **boot-init** hook site — the point a future boot-init
    /// detour is written (`anchor+4`, over `ldr r0,[r0,#0x18]; lsls r0,r0,#0x18`).
    /// Returns `0x13d41a` on BU40N 1.00.
    ///
    /// [`BOOT_INIT_SIG`] is unique (n==1) on every owned MT1959 image. On the
    /// MT1939-classic lineage the modern shape returns zero and an ORDERED FALLBACK
    /// to [`BOOT_INIT_SIG_CLASSIC`] recovers the same reload site (tagged
    /// [`BootInitSite::ClassicUnconfirmed`]). Ordering is MANDATORY and the reason
    /// this is not a merged scan: the classic helper ALSO matches inside 157 modern
    /// images, so a simultaneous scan would make modern images ambiguous. The modern
    /// shape is therefore tried FIRST and resolves modern images without ever
    /// consulting the classic signature.
    ///
    /// Each signature is required unique in its own right (`n==1`); `>1` on either
    /// refuses. Zero matches on BOTH returns `Ok(None)` (unknown prologue shape).
    pub fn find_boot_init(&self, image: &[u8]) -> Result<Option<BootInitSite>> {
        match find_masked_all(image, BOOT_INIT_SIG, 0, image.len()).as_slice() {
            [one] => Ok(Some(BootInitSite::Modern(*one as u32 + 4))),
            // No modern-shape match → try the MT1939-classic variant. Original-first
            // keeps modern images resolving via BOOT_INIT_SIG (byte-identical output).
            [] => match find_masked_all(image, BOOT_INIT_SIG_CLASSIC, 0, image.len()).as_slice() {
                [] => Ok(None),
                [one] => Ok(Some(BootInitSite::ClassicUnconfirmed(*one as u32 + 4))),
                many => bail!(
                    "classic boot-init signature matched {} time(s) (want exactly 1) — \
                     refusing to patch",
                    many.len()
                ),
            },
            many => bail!(
                "boot-init signature matched {} time(s) (want 0 on MT1939-classic or \
                 exactly 1 on MT1959) — refusing to patch",
                many.len()
            ),
        }
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
    pub(crate) fn find_vid_gate(&self, image: &[u8]) -> Result<usize> {
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

    /// The Region-free (0x03) RPC-state emitter anchor — the unique
    /// [`REGION_EMIT_SIG`] match (`0x119890` on 1.00, `0x119a84` on 1.03).
    /// Returns the anchor offset; the frame[4] store the detour replaces is at
    /// `anchor+6`.
    pub fn find_region_emitter(&self, image: &[u8]) -> Result<u32> {
        // Full-image scan: `REGION_EMIT_SIG` is a single exact 20-byte hit image-wide
        // on every OEM image (measured maxn==1 across the 118-image corpus), so a
        // bounded window only served to exclude the ~+0x2b000-relocated MT1939-modern
        // block (region emitter at 0x144a66/0x146094/0x145ea4, above the old 0x120000
        // ceiling). `find_unique` still refuses on any n>1.
        Ok(find_unique(image, REGION_EMIT_SIG, 0, image.len(), "RPC-state emitter")? as u32)
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
        // Full-image scan (all three AKE signatures are unique image-wide, maxn==1
        // measured): the old 0x130000..0x140000 window excluded the ~+0x2b000
        // relocated MT1939-modern AACS block (AKE gate lifted above 0x140000).
        Ok(find_unique(image, AKE_GATE_SIG, 0, image.len(), "AACS AKE accept gate")? as u32)
    }

    /// The NB-class AKE accept-gate anchor — the unique [`AKE_GATE_SIG_NB`] match.
    /// Returns the anchor; the shared `bl set_agid_state` the Raw Read NB detour
    /// replaces is at `anchor+12` (see [`AKE_GATE_SIG_NB`]).
    pub fn find_ake_gate_nb(&self, image: &[u8]) -> Result<u32> {
        Ok(find_unique(
            image,
            AKE_GATE_SIG_NB,
            0,
            image.len(),
            "AACS AKE accept gate (NB)",
        )? as u32)
    }

    /// The NB-class `1.V5` AKE accept-gate anchor — the unique
    /// [`AKE_GATE_SIG_NB_V5`] match. Returns the anchor; the reject writer
    /// (`movs r1,#1`) is at `anchor+12` and the shared `bl set_agid_state` the
    /// Raw Read detour replaces is at `anchor+14` (see [`AKE_GATE_SIG_NB_V5`]).
    pub fn find_ake_gate_nb_v5(&self, image: &[u8]) -> Result<u32> {
        Ok(find_unique(
            image,
            AKE_GATE_SIG_NB_V5,
            0,
            image.len(),
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
        // Full-image scan: the 14-halfword AGID-reset loop is already disambiguated
        // by requiring its inner `bl` to target the resolved `set_agid_state`, so it
        // is unique image-wide. The old 0x90000..0xe0000 window excluded the
        // ~+0x2b000-relocated MT1939-modern block (reset routine lifted above 0xe0000).
        let (lo, hi) = (0, image.len());
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
    pub(crate) fn assert_sram_cell_free(
        &self,
        image: &[u8],
        base: u32,
        len: u32,
        what: &str,
    ) -> Result<()> {
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
    /// `flag[0x05]`, AKE `flag[0x06]`, Bus `flag[0x07]`) as a uniform tri-state:
    /// `0xFF` = OEM passthrough, `0x01` = on/armed, `0x00` = off (actively disabled).
    /// The always-on boot-init hook writes `0xFF` into every flag at power-on, so an
    /// unarmed or RESET image is byte-behaviour-identical to OEM and a gate only ever
    /// sees `0x00` (off) when the host has explicitly set it — never at boot.
    ///
    /// The host ALWAYS reads `CLEAR_LEN` bytes — a `0x3C` READ BUFFER is a data-in
    /// opcode, so a command with no/short data phase desyncs the transfer (ABORTED
    /// COMMAND + wedged FIFO). Every verb therefore commits the same `CLEAR_LEN`
    /// window (payload leading, zero-padded).
    pub fn build_handler(&self, image: &[u8], oem_handler: u32, flag_base: u32) -> Result<Vec<u8>> {
        let cdb = self.find_cdb_base(image)?;
        let (writer, commit_off) = self.find_response_writer(image)?;
        let (commit, length_field) = self.find_response_commit(image)?;
        // OEM flash PROGRAM routine, recovered per image (no hardcoded VA) — the
        // [`abi::Verb::FlashWrite`] probe `bl`s this.
        let flash_program = self.find_flash_program(image)?;
        // SAVE home, signature-derived per image (no hardcoded offset). The diagnostic
        // FlashWrite window is a compile-time bound; assert the resolved NV block agrees
        // so SAVE's destination and that window can never drift apart.
        let save_home = self.find_nv_block(image)?;
        // Flash-write staging base pointer, signature-derived per image (MT1959 0x02000C78,
        // but 7 distinct values across MT1939 — a constant would corrupt every MT1939 SAVE).
        let nv_dram_base_ptr = self.find_nv_dram_base(image)?;
        ensure!(
            (FLASHWRITE_ALLOW_LO..FLASHWRITE_ALLOW_HI).contains(&save_home),
            "resolved NV/SAVE block 0x{save_home:x} is outside the flash-write window \
             0x{FLASHWRITE_ALLOW_LO:x}..0x{FLASHWRITE_ALLOW_HI:x}"
        );
        let identity = identity_blob();
        let id_len = identity.len() as u8;

        let mut a = Asm::new();
        let tail = a.label();
        let knock_ok = a.label();
        let not_set = a.label();
        let not_reset = a.label();
        let reset_flash = a.label();
        let not_save = a.label();
        let clr = a.label();
        let clr_loop = a.label();
        let clrd = a.label();
        let not_get = a.label();
        let not_flash = a.label();
        let flash_refuse = a.label();
        let flash_reply = a.label();
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
                                                   // Bounds-clamp the feature id: valid ids are 1..=NUM_FEATURES, so anything
                                                   // >= NUM_FEATURES+1 is rejected (return a zeroed buffer, no write). Without
                                                   // this an id such as 0xC8 would `strb` into live SRAM past the flag hole.
        a.cmp_imm(1, NUM_FEATURES + 1);
        a.bhs(clr);
        a.adds_reg(0, 0, 1); // r0 = &flag[feature]
        a.ldrb_imm(1, 3, abi::CDB_STATE as u16); // r1 = state (cdb[6])
        a.strb_imm(1, 0, 0); // flag[feature] = state
        a.b(clr); // return a zeroed buffer
        a.bind(not_set);

        // RESET: mode rides in the state slot cdb[6].
        //   RESET_TO_OEM   (0xFF) → 0xFF-fill the flag table (slots 0..=NUM_FEATURES).
        //   RESET_TO_FLASH (0x00) → reload the saved table from flash SAVE_HOME
        //                           (blank flash = 0xFF = all-OEM, so this is the same
        //                           result on a never-saved drive).
        // Both fall through to clear → zeroed buffer.
        a.cmp_imm(4, abi::Verb::Reset as u8);
        a.bne(not_reset);
        a.ldrb_imm(0, 3, abi::CDB_STATE as u16); // r0 = mode (cdb[6])
        a.cmp_imm(0, abi::RESET_TO_OEM);
        a.bne(reset_flash);
        // RESET_TO_OEM: 0xFF to slots 0..=NUM_FEATURES (matches the boot default).
        a.ldr_lit(0, flag_base);
        a.movs_imm(1, abi::STATE_PASSTHROUGH);
        for off in 0..=NUM_FEATURES {
            a.strb_imm(1, 0, off as u16);
        }
        a.b(clr);
        // RESET_TO_FLASH: copy SAVE_LEN bytes from flash SAVE_HOME → flag table.
        // Flash is XIP-mapped, so this is a plain memory read (no PROGRAM call).
        a.bind(reset_flash);
        a.ldr_lit(6, flag_base); // r6 = flag-table base (SRAM), callee-saved
        a.ldr_lit(2, save_home); // r2 = flash source base (address to read from)
        for off in 0..SAVE_LEN {
            a.ldrb_imm(1, 2, off as u16); // r1 = flash[off]
            a.strb_imm(1, 6, off as u16); // flag[off] = r1
        }
        a.b(clr);
        a.bind(not_reset);
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

        // FLASHWRITE (TEMPORARY diagnostic): program the byte cdb[9] to the 32-bit
        // flash offset packed big-endian in cdb[5..9], via the OEM PROGRAM routine
        // — but only after a HARD range-check against the compile-time safe-cell
        // allowlist. An out-of-allowlist offset refuses (PROGRAM NOT called) with a
        // distinct status word, so this verb can physically only write the erased
        // non-CMAC gap. Reply = offset echo (BE, [0..4]) + status word (BE, [4..8]).
        let scratch_cell = flag_base + FLASHWRITE_SCRATCH_OFF;
        a.cmp_imm(4, abi::Verb::FlashWrite as u8);
        a.bne(not_flash);
        // r6 = flash offset from cdb[5..9] (big-endian). r6 is callee-saved, so it
        // survives the OEM PROGRAM call and the byte-writer reply loop.
        a.ldrb_imm(6, 3, 5); // off[31:24]
        a.lsls_imm(6, 6, 8);
        a.ldrb_imm(0, 3, 6);
        a.adds_reg(6, 6, 0); // |= off[23:16]
        a.lsls_imm(6, 6, 8);
        a.ldrb_imm(0, 3, 7);
        a.adds_reg(6, 6, 0); // |= off[15:8]
        a.lsls_imm(6, 6, 8);
        a.ldrb_imm(0, 3, 8);
        a.adds_reg(6, 6, 0); // |= off[7:0]  → r6 = full 32-bit offset
                             // stage the source byte cdb[9] into the SRAM scratch cell (harmless if
                             // the range check then refuses — the PROGRAM routine is never reached).
        a.ldrb_imm(0, 3, 9); // r0 = value byte (cdb[9])
        a.ldr_lit(1, scratch_cell);
        a.strb_imm(0, 1, 0); // *scratch = value
                             // SAFETY range check: refuse unless LO <= off < HI. On refuse the OEM
                             // PROGRAM routine is NOT called — the probe can only ever touch the gap.
        a.ldr_lit(0, FLASHWRITE_ALLOW_LO);
        a.cmp_reg(6, 0);
        a.blo(flash_refuse); // off < LO → refuse
        a.ldr_lit(0, FLASHWRITE_ALLOW_HI);
        a.cmp_reg(6, 0);
        a.bhs(flash_refuse); // off >= HI → refuse
                             // armed: program(r0=&scratch, r1=off, r2=1, r3=1) — op=1 is the OEM
                             // erase-aligned read-modify-write. r3 (cdb base) is dead here (all cdb
                             // fields already read), so reusing it as the op arg is safe.
        a.ldr_lit(0, scratch_cell);
        a.mov_reg(1, 6);
        a.movs_imm(2, 1);
        a.movs_imm(3, 1);
        a.ldr_lit(5, flash_program | 1);
        a.blx(5); // r0 = PROGRAM status word (r4-r11 preserved → r6 offset survives)
        a.mov_reg(4, 0); // r4 = status word (callee-saved; survives the reply writes)
        a.b(flash_reply);
        a.bind(flash_refuse);
        a.ldr_lit(4, FLASHWRITE_REFUSE_STATUS); // r4 = "REFU" sentinel (PROGRAM not called)
        a.bind(flash_reply);
        // reply: offset echo at [0..4], status word at [4..8], both big-endian.
        emit_be_word_to_response(&mut a, 6, 0);
        emit_be_word_to_response(&mut a, 4, 4);
        a.b(docommit);
        a.bind(not_flash);

        // SAVE (0x0B): persist the live flag table to flash SAVE_HOME. The OEM PROGRAM
        // engine reads its program-source through the DRAM-window translation, so we
        // FIRST stage the 8 flag bytes SRAM->DRAM (dram_base + buf_off, both boot-set
        // globals read at runtime), then call PROGRAM with the WINDOW OFFSET as src.
        // op=1 RMW preserves the OEM region record at +0x4B0. Reply = status (BE) [0..4].
        a.cmp_imm(4, abi::Verb::Save as u8);
        a.bne(not_save);
        // Persist the live flag table to flash SAVE_HOME via the reusable flash-write
        // primitive (stage SRAM->DRAM window, then OEM PROGRAM op=1 RMW).
        emit_flash_write(
            &mut a,
            nv_dram_base_ptr,
            save_home,
            flag_base,
            SAVE_LEN,
            flash_program,
        );
        a.mov_reg(4, 0); // r4 = status (callee-saved; survives the reply writes)
        emit_be_word_to_response(&mut a, 4, 0);
        a.b(docommit);
        a.bind(not_save);

        // GET: response byte 0 = flag[cdb[5]=feature].
        a.cmp_imm(4, abi::Verb::Get as u8);
        a.bne(not_get);
        a.ldr_lit(0, flag_base);
        a.ldrb_imm(1, 3, abi::CDB_FEATURE as u16); // r1 = feature id
                                                   // Bounds-clamp the feature id (same window as SET): an id >= NUM_FEATURES+1
                                                   // would `ldrb` from live SRAM past the flag hole. Out of range → fall through
                                                   // to `not_get` (verb isn't DumpAll/Identity either, so it reaches `docommit`
                                                   // and returns the already-zeroed buffer).
        a.cmp_imm(1, NUM_FEATURES + 1);
        a.bhs(not_get);
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
    pub(crate) fn build_speed_stub(
        &self,
        flag_base: u32,
        fallthrough: u32,
        exit: u32,
        idx_reg: u8,
    ) -> Result<Vec<u8>> {
        // flag[Feature::Speed] tri-state: `STATE_PASSTHROUGH` (0xFF) = OEM (compare
        // against the OEM 0x32 band); `STATE_ON` (0x01) = unlimited (compare against
        // the drive's own `0xFF` sentinel); any OTHER value is an explicit speed-cap
        // byte (compare `speed_index` against it directly), so `STATE_OFF` (0x00) =
        // cap 0 = the floor (slowest / riplock fully engaged) — the genuine OFF,
        // reached through the same cap path. The boot hook guarantees `0xFF` at
        // power-on, so a gate never sees the `0x00` cap unless the host set it.
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
            a.cmp_imm(0, abi::STATE_PASSTHROUGH); // 0xFF -> OEM
            a.beq(oem);
            a.cmp_reg(2, 0); // explicit cap (incl 0x00 OFF = floor): speed_index vs cap byte
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
            a.cmp_imm(1, abi::STATE_PASSTHROUGH); // 0xFF -> OEM
            a.beq(oem);
            a.cmp_reg(0, 1); // explicit cap (incl 0x00 OFF = floor): speed_index vs cap byte
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
    pub(crate) fn build_region_stub(&self, flag_base: u32) -> Result<Vec<u8>> {
        // flag[Feature::Region] tri-state: `STATE_PASSTHROUGH` (0xFF) = OEM (stealth;
        // the boot hook guarantees this at power-on); `STATE_ON` (0x01) = RPC-1
        // region-free (zero frame[4..6]); `STATE_OFF` (0x00) = region-LOCKED (RPC-2,
        // RegionMask 0xFF → no region playable — the genuine OFF); `0x11..=0x18` =
        // force DVD region 1..8; `REGION_BD_A/B/C` (0x2A/2B/2C) = force BD region
        // A/B/C; anything else = OEM.
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
        let region_lock = a.label();
        let dvd_force = a.label();
        let bd_force = a.label();
        let oem = a.label();
        let tail = a.label();
        a.ldr_lit(3, flag_base + abi::Feature::Region as u32); // r3 = &flag[Region] (r3 popped)
        a.ldrb_imm(3, 3, 0); // r3 = Region flag byte
        a.cmp_imm(3, abi::STATE_ON); // 0x01 -> RPC-1 free
        a.beq(region_free);
        a.cmp_imm(3, abi::STATE_OFF); // 0x00 -> region-locked (genuine OFF)
        a.beq(region_lock);
        a.cmp_imm(3, 0x11);
        a.blo(oem); // 0x02..0x10 -> OEM (0x00/0x01/0xFF already handled)
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

        a.bind(region_lock);
        // Genuine OFF: force RPC-2 with RegionMask 0xFF (every region prohibited →
        // the disc plays in no region). HARDWARE-KAT-GATED: the all-set mask == fully
        // locked is the standard RPC-2 encoding but is not re-proven on this silicon.
        a.strb_imm(2, 0, 8); // frame[4] = r2 (OEM TypeCode/#resets/#changes)
        a.movs_imm(2, 0xFF); // r2 = 0xFF (all 8 regions prohibited)
        a.strb_imm(2, 0, 8); // frame[5] = 0xFF (no region playable)
        a.strb_imm(4, 0, 8); // frame[6] = r4 (RPCScheme = 1, RPC-2)
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
    /// `6` (AKE authenticated → VID gate open) when `flag[Ake]==STATE_OFF`, else the
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
    pub(crate) fn build_ake_stub(&self, flag_base: u32, back: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let accept = a.label();
        let done = a.label();
        a.ldr_lit(2, flag_base + abi::Feature::Ake as u32); // r2 = &flag[Ake]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_OFF); // 0x00 = null AKE / bypass (accept any/revoked host cert); ON/OEM = real handshake
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
    /// `r1 = 6` only when `flag[Ake]==STATE_OFF`, then tail-jumps to the OEM
    /// `set_agid_state` (`back`) so the store happens through the OEM primitive.
    /// `r2` is scratch (dead at `back`); `lr` is preserved by the outer `bl` and
    /// carries the OEM return, matching the `bl set_agid_state` this replaces.
    pub(crate) fn build_ake_stub_nb(&self, flag_base: u32, back: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let force = a.label();
        let keep = a.label();
        a.ldr_lit(2, flag_base + abi::Feature::Ake as u32); // r2 = &flag[Ake]
        a.ldrb_imm(2, 2, 0); // r2 = AKE flag byte
        a.cmp_imm(2, abi::STATE_OFF); // 0x00 = null AKE / bypass (accept any/revoked host cert); ON/OEM = real handshake
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
    /// replays the call **through `r4`** (NOT a low arg register: loading the call
    /// target into `r0..r3` would clobber a key-prog argument, and a >=3-arg AAPCS
    /// key-prog would then program a corrupt read-data-key — the `Bus=off` path would
    /// return wrong content), and — only when `flag[Bus]==STATE_OFF` — clears
    /// [`BUSENC_ENABLE_BIT`] of [`BUSENC_REG`] before returning to `arm+4` via the
    /// saved `lr`. `r1..r3` are dead across the OEM continuation (it re-establishes
    /// them), so the stub uses them as scratch; `r4` is pushed and reused as the
    /// call-target scratch — the key-prog callee preserves it (AAPCS callee-saved), and
    /// the `pop` restores it to its entry value, so the OEM continuation sees it
    /// unchanged.
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
    /// `flag[Bus]` (`flag[Feature::Bus]`) semantics at this site:
    ///   * `!= STATE_OFF` (`passthrough` / `on`): replay the OEM key-prog `bl`
    ///     and return — the register is untouched, **bus encryption ON**.
    ///     Byte-behaviour-identical to OEM, so this mode is inert (stealth) until
    ///     `Bus=on`.
    ///   * `== STATE_OFF` (bus off / data clear): replay the OEM key-prog `bl`, then
    ///     `*BUSENC_REG &= ~BUSENC_ENABLE_BIT` → the transport wrap is off for the
    ///     following `READ(10)`, content comes back AACS-at-rest only.
    ///
    /// **HARDWARE-KAT-GATED HYPOTHESIS.** That bit `0x10` of `0x0400_0000` is
    /// specifically the bus-encryption enable (and that clearing it here suppresses
    /// the wrap without disturbing the at-rest read path) comes from the MK-vs-OEM
    /// 1.03 diff and is NOT yet re-proven on this silicon; the golden-UK hardware KAT
    /// is the final arbiter. The `!= STATE_OFF` (bus-ON) path IS structurally proven —
    /// it replays the exact OEM key-prog call and touches nothing else.
    pub(crate) fn build_busenc_stub(&self, flag_base: u32, keyprog: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let skip = a.label();
        a.push(0x0110); // push {r4, lr}   (r4 saved, then reused as the call-target scratch)
        a.ldr_lit(4, keyprog | 1); // r4 = &oem_key_prog (thumb); r0-r3 (key-prog args) untouched
        a.blx(4); // replay OEM key programming with r0-r3 = original args (return value dead at arm+4)
        a.ldr_lit(3, flag_base + abi::Feature::Bus as u32); // r3 = &flag[Bus]
        a.ldrb_imm(3, 3, 0); // r3 = Bus flag byte
        a.cmp_imm(3, abi::STATE_OFF); // 0x00 = bus off / de-bussed (remove the bus-encryption stage); ON/OEM = bus on
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
    /// and, only when `flag[Uhd]==STATE_ON`, zeros the disc-version so a UHD (AACS 2.0)
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
    /// `flag[Uhd]` (`flag[Feature::Uhd]`) semantics at this site:
    ///   * `!= STATE_ON` (`passthrough` / `off`): replay `ldr r0,[sp,#0x38]; movs r5,#6`
    ///     verbatim and return — the disc-version is untouched, so classification is
    ///     byte-behaviour-identical to OEM. Inert (stealth) until `Uhd=on`.
    ///   * `== STATE_ON` (full UHD bypass): after the replay, `r0 = 0` → the classifier
    ///     sees disc-version `0`, dodging the UHD mode-1 categorization (MK-parity: MK's
    ///     injected stub returns the same forced-`0`).
    ///
    /// **`STATE_OFF` (`0x00`) is RESERVED (== OEM) on this byte-extraction classifier
    /// shape.** The class this classifier assigns is derived from *several* disc-version
    /// bytes through a per-byte category loop (not a single hookable value the reload
    /// controls), so a genuine force-refuse cannot be grounded here from the single
    /// `r0` reload without deeper RE. OFF therefore falls through the `!= STATE_ON`
    /// (verbatim replay) path — safe (boot-behaviour-identical) but a no-op. The
    /// genuine UHD OFF IS emitted on the version-compare classifier shape (see
    /// [`Self::build_uhd_stub_ver`]), which exposes a distinct `movs r2,#2` mode-1 arm.
    ///
    /// **HARDWARE-KAT-GATED HYPOTHESIS.** That neutralizing this categorization (the
    /// exact site MK hooks) is what lifts the UHD mode-1 refusal — and that it, together
    /// with the already-shipped bus-encryption bit-clear, yields readable at-rest UHD
    /// content on the vendor path — comes from the MK-vs-OEM diff and is NOT re-proven on
    /// this silicon; a hardware UHD rip is the final arbiter. The `!= 3` (stealth) path
    /// IS structurally proven — it replays the two OEM instructions and touches nothing
    /// else.
    pub(crate) fn build_uhd_stub(&self, flag_base: u32) -> Result<Vec<u8>> {
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
    pub(crate) fn uhd_detour(&self, image: &[u8], flag_base: u32) -> Result<(usize, Vec<u8>)> {
        let anchor = self.find_uhd_classifier(image)? as usize;
        let head = u16::from_le_bytes([image[anchor], image[anchor + 1]]);
        // The finder returns the head of whichever variant resolved. `push {r0-r3}`
        // (0xB40F) => the byte-extraction prologue (primary); `cmp r0,#0x63` (0x2863)
        // => the version-compare variant. Each has its own detour site + stub, verified
        // against the OEM bytes before patching so a mis-anchored match refuses.
        if head == 0xB40F {
            // Primary: replace the disc-version reload `ldr r0,[sp,#0x38]; movs r5,#6`
            // (4 bytes at anchor+6); the stub returns to the classifier body at anchor+10.
            let site = anchor + 6;
            let ldr = u16::from_le_bytes([image[site], image[site + 1]]);
            let movs = u16::from_le_bytes([image[site + 2], image[site + 3]]);
            if ldr != 0x980E || movs != 0x2506 {
                bail!(
                    "UHD classifier reload (ldr r0,[sp,#0x38]; movs r5,#6) not at 0x{site:x} \
                     (got 0x{ldr:04x} 0x{movs:04x})"
                );
            }
            Ok((site, self.build_uhd_stub(flag_base)?))
        } else {
            // Version-compare variant: the anchor is `cmp r0,#0x63`, preceded by the
            // disc-version load `ldrh r0,[r1]` at anchor-2. Replace those 4 bytes
            // (ldrh + cmp) with the `bl`; the stub replays both (stealth) or, when armed,
            // branches straight to arm C at anchor+0x16 (`movs r2,#3` == the class a
            // disc-version of 0 hits). Verify all three OEM landmarks before patching.
            let site = anchor - 2;
            let ldrh = u16::from_le_bytes([image[site], image[site + 1]]);
            let cmp = u16::from_le_bytes([image[anchor], image[anchor + 1]]);
            let arm_c_va = (anchor + 0x16) as u32;
            let arm_c = u16::from_le_bytes([image[anchor + 0x16], image[anchor + 0x17]]);
            // The mode-1 (UHD-refused) class arm `movs r2,#2` is at anchor+4 (index 2
            // of UHD_CLASSIFIER_SIG_VER); the OFF path routes here to force-refuse UHD.
            let mode1_va = (anchor + 4) as u32;
            let mode1 = u16::from_le_bytes([image[anchor + 4], image[anchor + 5]]);
            if ldrh != 0x8808 || cmp != 0x2863 || arm_c != 0x2203 || mode1 != 0x2202 {
                bail!(
                    "UHD version-compare classifier landmarks off at anchor 0x{anchor:x} \
                     (ldrh@-2=0x{ldrh:04x} cmp=0x{cmp:04x} mode1@+4=0x{mode1:04x} \
                     armC@+0x16=0x{arm_c:04x})"
                );
            }
            Ok((
                site,
                self.build_uhd_stub_ver(flag_base, arm_c_va, mode1_va)?,
            ))
        }
    }

    /// Version-compare sibling of [`Self::build_uhd_stub`] — the `04 03` UHD mode-gate
    /// neutralizer for images whose classifier buckets by disc-version *thresholds*
    /// ([`UHD_CLASSIFIER_SIG_VER`]). Entered by a `bl` that replaces `ldrh r0,[r1];
    /// cmp r0,#0x63` (the 4 bytes at the anchor's `match-2`).
    ///
    /// # Register / frame contract
    /// A bare `bl` (no push), so `sp`/`r1` are unchanged — the replayed `ldrh r0,[r1]`
    /// resolves to the same disc-version halfword the OEM load would. `r3` is scratch:
    /// the classifier never feeds `r3` to the class-compose call (`compose_disc_mode`
    /// sets `r3=0` on entry), and no arm reads it, so clobbering it is invisible on both
    /// paths. `lr` is caller-saved (the function returns via its own `pop {…,pc}`, and
    /// re-arms `lr` at the class-compose `bl`), so the `bl`'s `lr` clobber is harmless.
    ///
    /// `flag[Feature::Uhd]` tri-state at this site:
    ///   * `STATE_PASSTHROUGH` (0xFF) / anything else: replay `ldrh r0,[r1]; cmp
    ///     r0,#0x63` verbatim and `bx lr` to the caller's `bls` (anchor+2) —
    ///     classification is byte-behaviour-identical to OEM. Inert (stealth); the
    ///     boot hook guarantees `0xFF` at power-on.
    ///   * `STATE_ON` (0x01): branch straight to arm C (`arm_c_va` = anchor+0x16,
    ///     `movs r2,#3`), the exact class a disc-version of `0` produces — so a UHD
    ///     disc dodges the `r2==2` mode-1 bucket the REPORT KEY gate refuses
    ///     (MK-parity, force-ENABLE UHD).
    ///   * `STATE_OFF` (0x00): branch straight to the `movs r2,#2` mode-1 arm
    ///     (`mode1_va` = anchor+4) — the UHD/AACS-2.0 bucket the REPORT KEY gate
    ///     refuses with `6F/01`, so the drive genuinely reports/behaves as no-UHD
    ///     (force-DISABLE UHD). The genuine OFF this classifier shape can express.
    ///
    /// **HARDWARE-KAT-GATED HYPOTHESIS** — same status as [`Self::build_uhd_stub`]: the
    /// stealth path is structurally proven (a verbatim replay); the armed ON/OFF
    /// branch targets are the OEM classifier's own class arms, but their end effect on
    /// the UHD refusal is the MK-vs-OEM hypothesis, not re-proven on this silicon.
    pub(crate) fn build_uhd_stub_ver(
        &self,
        flag_base: u32,
        arm_c_va: u32,
        mode1_va: u32,
    ) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let force_on = a.label();
        let force_off = a.label();
        a.raw16(0x8808); // replay: ldrh r0,[r1]   (r0 = disc-version; r1 unchanged by the bl)
        a.ldr_lit(3, flag_base + abi::Feature::Uhd as u32); // r3 = &flag[Uhd]
        a.ldrb_imm(3, 3, 0); // r3 = UHD flag byte
        a.cmp_imm(3, abi::STATE_ON); // 0x01 = force UHD ON (neutralize the mode gate)
        a.beq(force_on);
        a.cmp_imm(3, abi::STATE_OFF); // 0x00 = force UHD OFF (route to the refused mode-1 bucket)
        a.beq(force_off);
        a.cmp_imm(0, 0x63); // stealth: replay `cmp r0,#0x63` LAST so the caller's `bls` sees OEM flags
        a.bx(14); // bx lr -> caller's `bls` at anchor+2 (OEM classification)
        a.bind(force_on);
        a.ldr_lit(3, arm_c_va | 1); // ON: arm C (movs r2,#3) == disc-version-0 class (engage UHD)
        a.bx(3);
        a.bind(force_off);
        a.ldr_lit(3, mode1_va | 1); // OFF: mode-1 arm (movs r2,#2) == UHD bucket REPORT KEY refuses
        a.bx(3);
        a.finish()
    }

    /// The `Feature::Bd` **BD (AACS 1.0) capability-refuse** trampoline. Entered by a
    /// `bl` that replaces the REPORT KEY gate's mode-0 class check `ldrb r0,[r2,#7];
    /// cmp r0,#2` (4 bytes at [`BD_GATE_SIG`]'s `anchor+16`). On entry `r2 = the
    /// per-disc class struct` (loaded by the gate's own `ldr r2,[pc]`, undisturbed by
    /// a `bl`) and `lr = anchor+20` (the OEM `beq <accept>`, which the gate reaches
    /// only for a mode-0 = BD disc). The stub replays the class load and returns to
    /// that `beq` with the compare flags it needs.
    ///
    /// # Register / frame contract
    /// A bare `bl` (no push), so `sp`/`r2` are unchanged — the replayed `ldrb
    /// r0,[r2,#7]` reads the same class byte the OEM load would. `r0` and `r3` are
    /// scratch: both continuation targets (`<accept>` at `anchor+20`'s branch and the
    /// `<deny>` block) recompute `r0` before use and never read `r3`, so clobbering
    /// them is invisible. `lr` is caller-saved (the enclosing function returns via its
    /// own `pop {…,pc}`), so the `bl`'s `lr` clobber is harmless.
    ///
    /// `flag[Bd]` tri-state at this site (uniform `0xFF`/`0x01`/`0x00`; the old
    /// distinct `0x02` sentinel is retired — the always-on boot hook writes `0xFF`
    /// into every flag at power-on, so `0x00` OFF is never seen at boot and BD can
    /// use the uniform value like every other feature):
    ///   * `!= STATE_OFF` (`0xFF` passthrough / `0x01` on): replay `ldrb r0,[r2,#7];
    ///     cmp r0,#2` verbatim, so the caller's `beq` sees the exact OEM flags — BD
    ///     acceptance is byte-behaviour-identical to OEM. Inert (stealth) until armed.
    ///   * `== STATE_OFF` (`0x00`): after the class replay, force a non-equal compare
    ///     (`cmp r0,#0xff`; class is never `0xff`) so the caller's `beq <accept>` is
    ///     NOT taken and control falls into the OEM deny block, which raises the
    ///     drive's own `6F` refusal sense — the drive REFUSES the BD disc.
    pub(crate) fn build_bd_stub(&self, flag_base: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let refuse = a.label();
        a.raw16(0x79D0); // replay: ldrb r0,[r2,#7]  (r0 = disc class; r2 unchanged by the bl)
        a.ldr_lit(3, flag_base + abi::Feature::Bd as u32); // r3 = &flag[Bd]
        a.ldrb_imm(3, 3, 0); // r3 = Bd flag byte
        a.cmp_imm(3, abi::STATE_OFF); // 0x00 = force BD refuse (0xFF passthrough / 0x01 on stay OEM; boot hook makes 0x00 unreachable at power-on)
        a.beq(refuse);
        a.cmp_imm(0, 2); // stealth: replay `cmp r0,#2` LAST so the caller's `beq` sees OEM flags
        a.bx(14); // bx lr -> caller's `beq <accept>` at anchor+20 (OEM acceptance)
        a.bind(refuse);
        a.cmp_imm(0, 0xff); // armed: class never 0xff -> Z=0 -> caller's `beq` falls through to OEM deny (6F)
        a.bx(14);
        a.finish()
    }

    /// Newer-codegen sibling of [`Self::build_bd_stub`] — the `Feature::Bd` BD-refuse
    /// trampoline for the descriptor-classifier media gate ([`BD_GATE_SIG_VER`]).
    /// Entered by a `bl` that replaces `cmp r2,#0; sub sp,#imm` (the 4 bytes at the
    /// gate's `anchor+6`). On entry `r2 = disc mode` (from the gate's own `ldrb
    /// r2,[r1]`, undisturbed by a `bl`), `sp` is the caller's frame *before* its own
    /// `sub` (which we replay), and `lr = anchor+10` (the OEM `bne <mode-not-0>`,
    /// which the gate reaches for every disc mode). `subsp_hw` is the exact OEM
    /// `sub sp,#imm` halfword (frame size varies per image); `deny_va` is the OEM
    /// `6F/05` media deny at `anchor+0x40`.
    ///
    /// # Register / frame contract
    /// The stub uses `r3` as scratch (loaded flag pointer, then the deny target) and
    /// preserves the OEM `r3` across a `push {r3}`/`pop {r3}` pair — `r3` is live on
    /// the `mode != 0` continuation (`adds r2,r2,r3`), so it must survive the stealth
    /// return; it is dead on the deny path. `r0`/`r1`/`r2`/`r5` are untouched, so both
    /// OEM continuations see their exact inputs. The replayed `sub sp,#imm` leaves
    /// `sp` in the same state the OEM instruction would, so the stealth return to
    /// `anchor+10` and the deny block's own `add sp,#imm` both balance. `lr` is
    /// caller-saved (the function returns via its own `pop {…,pc}`).
    ///
    /// `flag[Bd]` tri-state at this site:
    ///   * `!= STATE_OFF` (`0xFF` passthrough / `0x01` on): pop `r3`, replay
    ///     `cmp r2,#0` and `bx lr` — the caller's `bne` sees the exact OEM `Z` flag,
    ///     so disc acceptance is byte-behaviour-identical to OEM. Inert (stealth).
    ///   * `== STATE_OFF` (`0x00`) **and** `r2 == 0` (disc mode-0 = BD): jump to the
    ///     OEM `6F/05` deny at `deny_va` — the drive REFUSES the BD disc using its own
    ///     refusal sense. Any other mode (`r2 != 0`, e.g. UHD/AACS-2.0 mode-1) takes
    ///     the stealth path, so the UHD arm is never affected.
    pub(crate) fn build_bd_stub_ver(
        &self,
        flag_base: u32,
        subsp_hw: u16,
        deny_va: u32,
    ) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let stealth = a.label();
        a.raw16(subsp_hw); // replay: sub sp,#imm  (sp now matches OEM state at return)
        a.push(0x0008); // push {r3}   (preserve OEM r3 — live on the mode!=0 continuation)
        a.ldr_lit(3, flag_base + abi::Feature::Bd as u32); // r3 = &flag[Bd]
        a.ldrb_imm(3, 3, 0); // r3 = Bd flag byte
        a.cmp_imm(3, abi::STATE_OFF); // 0x00 = force BD refuse
        a.bne(stealth); // 0xFF/0x01 -> stealth (byte-identical to OEM)
        a.cmp_imm(2, 0); // mode == 0 (BD)?
        a.bne(stealth); // mode != 0 (UHD/other) -> stealth (never touch the non-BD arm)
        a.pop(0x0008); // BD & OFF: restore r3, sp back to sub-imm
        a.ldr_lit(3, deny_va | 1); // r3 = &OEM 6F/05 deny (thumb)
        a.bx(3); // -> deny (drive refuses the BD disc)
        a.bind(stealth);
        a.pop(0x0008); // restore r3, sp = sub-imm
        a.cmp_imm(2, 0); // re-establish Z=(mode==0) for the OEM `bne` at anchor+10
        a.bx(14); // bx lr -> anchor+10 (OEM continuation)
        a.finish()
    }

    /// Resolve the `Feature::Bd` media-gate refuse detour, dispatching on the shape
    /// [`Self::find_bd_gate`] resolved (original-first). Returns `(detour_site,
    /// stub_bytes)` where a `bl` to the stub is written at `detour_site`. Both shapes
    /// verify their exact OEM bytes before returning, so a mis-anchored match refuses
    /// rather than patches.
    ///
    /// * explicit REPORT KEY gate ([`BD_GATE_SIG`], anchor head `cmp r0,#1`): the
    ///   mode-0 class check `ldrb r0,[r2,#7]; cmp r0,#2` at `anchor+16` ->
    ///   [`Self::build_bd_stub`].
    /// * descriptor-classifier gate ([`BD_GATE_SIG_VER`], anchor head `ldrb r2,[r1]`):
    ///   the mode==0 test `cmp r2,#0; sub sp,#imm` at `anchor+6` ->
    ///   [`Self::build_bd_stub_ver`], jumping to the deny at `anchor+0x40` on refuse.
    pub(crate) fn bd_detour(&self, image: &[u8], flag_base: u32) -> Result<(usize, Vec<u8>)> {
        let anchor = self.find_bd_gate(image)? as usize;
        let head = u16::from_le_bytes([image[anchor], image[anchor + 1]]);
        if head == 0x2801 {
            // Explicit REPORT KEY gate: mode-0 class check at anchor+16.
            let site = anchor + 16;
            let ldrb = u16::from_le_bytes([image[site], image[site + 1]]);
            let cmp = u16::from_le_bytes([image[site + 2], image[site + 3]]);
            if ldrb != 0x79D0 || cmp != 0x2802 {
                bail!(
                    "BD gate mode-0 class check (ldrb r0,[r2,#7]; cmp r0,#2) not at 0x{site:x} \
                     (got 0x{ldrb:04x} 0x{cmp:04x})"
                );
            }
            Ok((site, self.build_bd_stub(flag_base)?))
        } else {
            // Descriptor-classifier gate: mode==0 test `cmp r2,#0; sub sp,#imm` at
            // anchor+6; the OEM 6F/05 deny is at anchor+0x40. Verify all three
            // landmarks (mode test, frame reserve, deny head) before patching.
            let site = anchor + 6;
            let cmp = u16::from_le_bytes([image[site], image[site + 1]]);
            let subsp = u16::from_le_bytes([image[site + 2], image[site + 3]]);
            let deny_off = anchor + BD_GATE_VER_DENY_OFF as usize;
            let deny_head = u16::from_le_bytes([image[deny_off], image[deny_off + 1]]);
            if cmp != 0x2A00 || (subsp & 0xFF80) != 0xB080 || deny_head != 0x2201 {
                bail!(
                    "BD (ver) gate landmarks off at anchor 0x{anchor:x} \
                     (cmp@+6=0x{cmp:04x} sub@+8=0x{subsp:04x} deny@+0x40=0x{deny_head:04x})"
                );
            }
            Ok((
                site,
                self.build_bd_stub_ver(flag_base, subsp, deny_off as u32)?,
            ))
        }
    }

    /// Locate the OEM AACS opcode-`0x45` (Read Data Key) arm and the target of its
    /// leading `bl` (the OEM key-prog primitive). Tries [`AACS45_ARM_SIG_A`] first
    /// (BU40N/notebook order — keeps the KAT base byte-identical), then
    /// [`AACS45_ARM_SIG_B`] (BH/WH desktop order). Returns `(detour_site, keyprog)`
    /// where `detour_site` is the arm's leading `bl` (proven unique) and `keyprog`
    /// is that `bl`'s absolute target. Errors (→ `04 03` left unwired) if neither
    /// variant resolves uniquely.
    pub(crate) fn find_aacs45_arm(&self, image: &[u8]) -> Result<(usize, u32)> {
        // Full-image scan: both 0x45-arm signatures are unique image-wide (maxn==1
        // measured across the corpus). The old CODE_REGION_START..TABLE_LO window
        // capped at 0x140000 and excluded the ~+0x2b000-relocated MT1939-modern block.
        let (lo, hi) = (0, image.len());
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

    /// The OEM disc-version classifier anchor. Two codegen shapes carry the same UHD
    /// mode gate, tried original-first:
    ///
    /// * primary — the byte-extraction prologue ([`UHD_CLASSIFIER_SIG`], `0xcb3c0` on
    ///   BU40N 1.00). The reload `ldr r0,[sp,#0x38]` the `04 03` detour replaces (4
    ///   bytes, with the following `movs r5,#6`) is at `anchor+6`; the stub returns to
    ///   the classifier body at `anchor+10`.
    /// * variant — the version-compare shape ([`UHD_CLASSIFIER_SIG_VER`], consulted
    ///   only when the prologue matches zero). The anchor is `cmp r0,#0x63`; the detour
    ///   replaces `ldrh r0,[r1]; cmp r0,#0x63` (4 bytes at `anchor-2`) and, when armed,
    ///   routes to arm C (`movs r2,#3`) at `anchor+0x16`.
    ///
    /// [`Self::uhd_detour`] disambiguates by the anchor's head halfword and applies the
    /// matching site + stub. Either shape must resolve UNIQUELY.
    pub fn find_uhd_classifier(&self, image: &[u8]) -> Result<u32> {
        // Full-image scan: both classifier signatures are unique image-wide (measured
        // maxn==1 across the corpus). The old 0xc0000..0xd0000 window excluded the
        // ~+0x2b000-relocated MT1939-modern block (classifier lifted above 0xd0000).
        let (lo, hi) = (0, image.len());
        // Original-first (same pattern as `find_aacs45_arm`): the byte-extraction
        // prologue shape wins wherever it resolves, so the BU40N KAT base and every
        // image that shape covers stay on the primary detour byte-for-byte. Only when
        // the prologue matches ZERO do we fall back to the version-compare variant.
        match find_masked_all(image, UHD_CLASSIFIER_SIG, lo, hi).as_slice() {
            [one] => Ok(*one as u32),
            [] => Ok(find_unique(
                image,
                UHD_CLASSIFIER_SIG_VER,
                lo,
                hi,
                "UHD disc-version classifier (version-compare)",
            )? as u32),
            hits => bail!(
                "UHD disc-version classifier signature matched {} time(s) in \
                 [0x{lo:x},0x{hi:x}) (want exactly 1) — refusing to patch",
                hits.len()
            ),
        }
    }

    /// The AACS media accept-gate anchor. Two codegen shapes carry the same disc
    /// mode/class accept/refuse decision, tried **original-first** (full-image; both
    /// signatures are unique image-wide, maxn==1 measured):
    ///
    /// * explicit REPORT KEY gate ([`BD_GATE_SIG`], `0x1365be` on BU40N 1.00, anchor
    ///   head `cmp r0,#1`) — resolves on 36 images. The mode-0 class check the
    ///   `Feature::Bd` detour replaces is at `anchor+16`.
    /// * descriptor-classifier gate ([`BD_GATE_SIG_VER`], anchor head `ldrb r2,[r1]`)
    ///   — the newer codegen the other AACS carriers use; consulted only when the
    ///   explicit sig matches ZERO, so the BU40N KAT base and the 36 stay
    ///   byte-identical. The mode==0 test the detour replaces is at `anchor+6`.
    ///
    /// [`Self::bd_detour`] disambiguates on the anchor head and applies the matching
    /// site + stub. Either shape must resolve UNIQUELY.
    pub fn find_bd_gate(&self, image: &[u8]) -> Result<u32> {
        // Original-first (same pattern as `find_uhd_classifier`): the explicit
        // REPORT KEY shape wins wherever it resolves, so the BU40N KAT base and the
        // 36 explicit-shape images keep the original detour byte-for-byte. Only when
        // it matches ZERO do we fall back to the descriptor-classifier variant.
        match find_masked_all(image, BD_GATE_SIG, 0, image.len()).as_slice() {
            [one] => Ok(*one as u32),
            [] => Ok(find_unique(
                image,
                BD_GATE_SIG_VER,
                0,
                image.len(),
                "AACS media accept gate (descriptor-classifier)",
            )? as u32),
            hits => bail!(
                "AACS REPORT KEY BD accept gate matched {} time(s) full-image \
                 (want exactly 1) — refusing to patch",
                hits.len()
            ),
        }
    }

    /// The flash-resident HRL lookup routine, located by [`HRL_LOOKUP_SIG`] and
    /// proven unique image-wide. Returns its entry VA. The routine relocates
    /// between versions (`0x133666` … `0x139796` on the mainline, ~`0x146xxx` on the
    /// ~+0x2b000-shifted MT1939-modern block, ~`0x16axxx` on the far-shifted
    /// BC-12/CH12/UH12 DVD-combo drives), and the 12-halfword body signature is
    /// unique full-image (maxn==1 measured) on every AACS image and absent on the
    /// DVD/CD-only parts — so a bounded window only served to exclude the shifts.
    pub fn find_hrl_lookup(&self, image: &[u8]) -> Result<u32> {
        // Full-image scan: the 12-halfword body signature is unique image-wide
        // (maxn==1 measured). The old 0x130000..0x140000 window excluded the
        // ~+0x2b000-relocated MT1939-modern block (HRL routine lifted to ~0x146xxx).
        Ok(find_unique(image, HRL_LOOKUP_SIG, 0, image.len(), "HRL lookup routine")? as u32)
    }

    /// The cert-path HRL check sites and their shared revoke target.
    ///
    /// Grounded, not hardcoded: find the HRL lookup ([`Self::find_hrl_lookup`]),
    /// then every `bl <hrl_lookup>` in the cert region; each is followed within a
    /// few instructions by `cmp r0,#0; bne <T>`. ALL such sites must share the SAME
    /// revoke target `T` (any disagreement → refuse), and `T` must carry the OEM
    /// revoke HEAD `ldrb r0,[r4,#2]; cmp r0,#0; bne …` — so a mis-anchored match
    /// refuses rather than patches. Returns `(cmp_offsets, revoke_target)`;
    /// `cmp_offsets[k]` is where the 4-byte `cmp r0,#0; bne T` the detour replaces
    /// begins.
    ///
    /// The site COUNT is version-dependent, not fixed: newer desktop/UHD firmware
    /// (BU40N/BU50N/WH16NS60/BP60NB10 …) checks the HRL at 3 cert sub-paths, while
    /// the NS40/NS50/NU50 notebook lineage checks it at 1 consolidated site. Both
    /// are legitimate — the count is not asserted; ≥1 shared-target site is
    /// required. The 6F/00 sense-setup is NOT keyed on: its `movs r2,#0`/`movs
    /// r1,#0x6f` pair is inline on the older layout but split across basic blocks
    /// (reached via `b`) on the branch-away layout, so requiring it inline was the
    /// original BU40N over-fit that pinned availability to 1/118. Anchoring on the
    /// unique HRL-lookup BODY plus the invariant revoke HEAD lifts availability to
    /// parity with the peer AACS gates (91/118) with no wrong matches.
    pub fn find_hrl_skip_sites(&self, image: &[u8]) -> Result<(Vec<usize>, u32)> {
        let hrl = self.find_hrl_lookup(image)?;
        // Full-image scan: each candidate site is filtered by `decode_bl_target ==
        // hrl` (the already-resolved lookup) plus the trailing `cmp r0,#0; bne`, and
        // every site must agree on one revoke target carrying the OEM revoke HEAD —
        // so the match is strict regardless of window. The old 0x130000..0x13c000
        // window excluded the far-relocated MT1939-modern block (HRL cert path at
        // ~0x16axxx on the BC-12/CH12/UH12 DVD-combo drives).
        let (lo, hi) = (0usize, image.len());
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
                            Some(_) => bail!("HRL check sites disagree on the revoke target"),
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
        // Verify the shared revoke target's version-invariant OEM HEAD:
        // `ldrb r0,[r4,#2]; cmp r0,#0; bne`.
        let t = target as usize;
        let revoke_head = t + 6 <= image.len()
            && hw(t) == 0x78A0
            && hw(t + 2) == 0x2800
            && (hw(t + 4) & 0xFF00) == 0xD100;
        if !revoke_head {
            bail!("HRL revoke target 0x{target:x} lacks the OEM revoke HEAD shape — refusing");
        }
        Ok((sites, target))
    }

    /// The HRL-skip trampoline (`flag[Feature::Hrl]==STATE_OFF`). Shared by the three
    /// cert-path sites: each `bl` replaces `cmp r0,#0; bne <revoke>` (4 bytes) at a
    /// site, so on entry `lr` = that site's CLEAN fall-through and `r0` = the HRL
    /// lookup result (`1`=revoked, `2`=blank, `0`=clean). When `flag[Feature::Hrl]`
    /// is `STATE_OFF` the stub takes the clean path regardless of the result (revoked
    /// certs accepted, non-destructive); otherwise it replicates OEM exactly (clean
    /// iff `r0==0`, else jump to the `revoke` 6F/00 path). `r3` is saved/restored;
    /// `r0`/`lr` untouched on the clean path, so behaviour is OEM-identical when the
    /// flag is off (`0x00` boot / `0xFF` passthrough) — the stealth invariant. The
    /// crypto verify (`bl <ca7e4>`) and the success writer are on other paths and
    /// are left intact.
    pub(crate) fn build_hrl_skip_stub(&self, flag_base: u32, revoke: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let clean = a.label();
        a.push(0x0008); // push {r3}   (r3 scratch; no inner call → SP alignment moot)
        a.ldr_lit(3, flag_base + abi::Feature::Hrl as u32); // r3 = &flag[Hrl]
        a.ldrb_imm(3, 3, 0); // r3 = HRL flag byte
        a.cmp_imm(3, abi::STATE_OFF); // 0x00 = skip HRL -> force clean; ON/OEM = enforce (OEM)
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
    pub(crate) fn hrl_skip_detour(
        &self,
        image: &[u8],
        flag_base: u32,
    ) -> Result<(Vec<usize>, u32, Vec<u8>)> {
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
    pub(crate) fn hrl_valid_empty_record(&self) -> [u8; 8] {
        [0x21, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00]
    }

    /// Resolve the `04 03` bus-off detour the MK way: the OEM `bl <key-prog>` at the
    /// start of the AACS opcode-`0x45` arm (located by [`Self::find_aacs45_arm`]).
    /// Returns `(detour_site, stub_bytes)` where a `bl` to the stub is written at
    /// `detour_site` (replacing the OEM `bl`); the stub replays the OEM key-prog call
    /// and, when `flag[Bus]==STATE_OFF`, clears [`BUSENC_ENABLE_BIT`] of [`BUSENC_REG`].
    /// Errors (→ Bus feature unwired) on images whose opcode-`0x45` arm is not one of the
    /// two known MT1959 shapes.
    pub(crate) fn busenc_detour(&self, image: &[u8], flag_base: u32) -> Result<(usize, Vec<u8>)> {
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
    pub(crate) fn ake_detour(&self, image: &[u8], flag_base: u32) -> Result<(usize, Vec<u8>, u32)> {
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
    /// This is the null-AKE bare-read mode (`flag[Ake]==STATE_OFF`): "the cert is
    /// valid" — the drive is told the host auth already succeeded, so an unlocker can
    /// just issue a bare `0xAD` fmt `0x80` and get the VID with NO cert and NO AKE.
    /// When `flag[Ake]==STATE_OFF` the stub jumps to `authed` (the fall-through that
    /// stages+emits VID) regardless of the auth byte; otherwise (`passthrough`/`off`)
    /// it replicates the OEM `cmp #6` (authed on `==6`, which is what the real-AKE
    /// accept path leaves in place). `r2` scratch; `lr` dead
    /// (producer saved it). The drive runs its own producer in its own `0xAD`
    /// context — no inline call, so a missing-buffer failure is a recoverable CHECK
    /// CONDITION, never a wedge.
    pub(crate) fn build_gatea_stub(
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
        a.cmp_imm(2, abi::STATE_OFF); // 0x00 (null AKE / bypass): force authed so a bare 0xAD returns the VID; ON/OEM = real AKE
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
    pub(crate) fn build_deny_reset_stub(&self, reset: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        a.push(0x0110); // push {r4, lr}  (r4 only to keep SP 8-byte aligned)
        a.ldr_lit(2, reset | 1); // r2 = &aacs_session_reset (thumb)
        a.blx(2); // aacs_session_reset()  (idle the engine)
        a.movs_imm(2, 2); // replay: movs r2,#2   (sense ASCQ)
        a.movs_imm(1, 0x6f); // replay: movs r1,#0x6f (sense ASC)
        a.pop(0x0110); // pop {r4, pc} -> OEM continuation (movs r0,#5; b set_sense)
        a.finish()
    }

    /// The **always-on boot-init** trampoline — the mechanism that makes the
    /// tri-state safe. Entered by a `bl` that replaces the cold/warm-boot
    /// convergence `bl <orig_init>` (the 4 bytes at
    /// [`boot_init_convergence`]'s `conv`, `0x13d428` on BU40N), i.e. the first
    /// instruction both boot paths reach AFTER the cold-boot bss/SRAM clear. Patching
    /// here (not the pre-clear reload at `anchor+4`) is what stops the clear from
    /// wiping the `0xFF` flag table this stub writes.
    ///
    /// Under the tri-state, a flag value of `0x00` means **OFF** (actively disabled),
    /// but the drive's SRAM flag table reads all-`0x00` at power-on — which would
    /// wrongly disable every feature at boot. This stub therefore writes
    /// [`abi::STATE_PASSTHROUGH`] (`0xFF`) into the whole flag table (`flag_base+0 ..=
    /// flag_base+NUM_FEATURES`, i.e. the unused slot 0 plus every feature flag
    /// `1..=7`) at boot, so a freshly powered drive is byte-behaviour-identical to
    /// OEM and no gate ever sees `0x00` unless the host set it. It is NOT
    /// feature-gated — it runs unconditionally on every boot.
    ///
    /// # Register / frame contract
    /// The detour replaces the original `bl <orig_init>`, so the stub must run
    /// `orig_init` itself. It `push {r0,r1,r2,r3,lr}` to preserve everything
    /// `orig_init` might read (it is an arg-less init in the boot sequence, but the
    /// args are preserved to be safe) plus the return address, writes the flag table
    /// (clobbering `r0`/`r1`), then `pop {r0,r1,r2,r3}` to restore the args and
    /// tail-calls the original via `ldr r3,=orig_init|1; blx r3` (`r3` — the last,
    /// least-likely arg — is the sole sacrificed scratch, which is harmless for an
    /// arg-less callee, and `r0..r2` still carry their originals). `blx` reloads `lr`
    /// with the address of the final `pop {pc}`, which returns to `conv+4` (the
    /// instruction after the detoured call). The stub does NOT replay the boot-status
    /// reload `ldr r0,[r0,#0x18]; lsls r0,r0,#0x18` — that stays in place at the old
    /// `anchor+4` site, which is no longer touched.
    pub(crate) fn build_boot_init(
        &self,
        flag_base: u32,
        orig_init: u32,
        save_home: u32,
    ) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        a.push(0x010F); // push {r0,r1,r2,r3,lr}  preserve orig_init's args + return addr
        a.ldr_lit(0, flag_base); // r0 = &flag table (SRAM)
        a.movs_imm(1, abi::STATE_PASSTHROUGH); // r1 = 0xFF (OEM passthrough)
        for off in 0..=NUM_FEATURES {
            a.strb_imm(1, 0, off as u16); // flag[off] = 0xFF (slot 0 pad + features 1..=7)
        }
        // Load the persisted flag table over the 0xFF defaults so saved settings apply
        // across a power cycle. Flash is XIP-mapped → a plain memory read. Blank flash
        // (0xFF) == never-saved == all-OEM, so this is safe on a fresh drive: the copy
        // just re-writes the same 0xFF. r0 (flag base) is still live from the fill.
        a.ldr_lit(2, save_home); // r2 = flash source base
        for off in 0..SAVE_LEN {
            a.ldrb_imm(1, 2, off as u16); // r1 = flash[off]
            a.strb_imm(1, 0, off as u16); // flag[off] = r1
        }
        a.pop(0x000F); // pop {r0,r1,r2,r3}   restore the args orig_init may read
        a.ldr_lit(3, orig_init | 1); // r3 = orig_init (Thumb bit set for blx)
        a.blx(3); // tail-call orig_init; lr := &(pop {pc})
        a.pop(0x0100); // pop {pc}   return to conv+4 (after the detoured bl)
        a.finish()
    }

    /// Install the always-on boot-init hook: find the anchor, follow its `bmi` to the
    /// cold/warm-boot convergence `bl <orig_init>`, inject [`Self::build_boot_init`]
    /// into covered free space, and repoint that `bl` at the stub. Returns
    /// `(conv, stub_va)` — the convergence detour site (the reported `boot_init_site`)
    /// and the stub address.
    ///
    /// **Fail-closed** on both no-site and unconfirmed-site:
    /// * `None` from [`Self::find_boot_init`] (prologue is neither known shape) BAILS
    ///   rather than shipping an image that would boot every feature to OFF (`0x00`).
    /// * a [`BootInitSite::ClassicUnconfirmed`] site (MT1939-classic, matched via
    ///   [`BOOT_INIT_SIG_CLASSIC`]) ALSO bails: the classic reload site resolves and
    ///   is unit-tested, but it is a called leaf helper whose power-on call-order is
    ///   HARDWARE-UNCONFIRMED, so auto-shipping a boot hook there could brick a
    ///   classic drive. Classic images therefore degrade to DE-only exactly as
    ///   before — unchanged production behaviour — until the site is blessed.
    ///
    /// Only a [`BootInitSite::Modern`] site is shipped. Tri-state OFF is safe once a
    /// boot-init site writes `0xFF` at power-on; blessing classic production emit is
    /// a deliberate one-line flip after on-silicon verification, not a code change to
    /// the finder (which is already complete).
    pub(crate) fn emit_boot_init(
        &self,
        image: &[u8],
        out: &mut [u8],
        flag_base: u32,
    ) -> Result<(u32, u32)> {
        // Resolve the detour `(conv, orig_init)` per lineage:
        // * Modern — follow the anchor's cold/warm-boot `bmi` to the convergence
        //   `bl <orig_init>` (the first instruction after the cold path rejoins, which
        //   runs AFTER the SRAM clear and on warm boot). Detouring here, not the
        //   pre-clear reload at `anchor+4`, is what keeps the stub's 0xFF fill alive.
        //   `boot_init_convergence` also verifies the 4 bytes at `conv` decode as that
        //   `bl` (fail-closed otherwise, rather than guessing).
        // * Classic — no such convergence exists (the reload site is a leaf whose `bmi`
        //   targets `bx lr`); detour the helper's unique caller `bl` instead
        //   (`classic_boot_init_caller`), tail-calling the helper. Only when blessed.
        let (conv, orig_init) = match self.find_boot_init(image)? {
            Some(BootInitSite::Modern(s)) => {
                boot_init_convergence(image, s as usize).ok_or_else(|| {
                    anyhow!(
                        "boot-init convergence `bl <orig_init>` not resolvable from anchor at \
                         0x{s:x} (the bmi target is not a 32-bit Thumb bl) — refusing to ship an \
                         unverified boot hook rather than mis-patch"
                    )
                })?
            }
            Some(BootInitSite::ClassicUnconfirmed(s)) => {
                if !CLASSIC_BOOT_BLESSED {
                    bail!(
                        "boot-init site 0x{s:x} resolved via the MT1939-classic signature is a \
                         called leaf helper whose power-on call-order is hardware-unconfirmed. \
                         Refusing to ship an unblessed classic boot hook (could brick the drive) \
                         — CLASSIC_BOOT_BLESSED is false until the site is verified on silicon."
                    );
                }
                classic_boot_init_caller(image, s as usize).ok_or_else(|| {
                    anyhow!(
                        "classic boot-init: the helper at anchor 0x{:x} does not have exactly one \
                         `bl` caller image-wide (want 1) — refusing to ship an ambiguous detour",
                        s.saturating_sub(4)
                    )
                })?
            }
            None => bail!(
                "tri-state OFF is unsafe without a boot-init site: no known boot-init prologue \
                 found on this image (unknown shape). Refusing to ship — a flag table that boots \
                 all-0x00 would disable every feature at power-on."
            ),
        };
        let save_home = self.find_nv_block(image)?;
        let bytes = self.build_boot_init(flag_base, orig_init, save_home)?;
        let stub_va = self.free_space(out, bytes.len() + 16)?;
        let bl = thumb::encode_bl(conv, stub_va)
            .ok_or_else(|| anyhow!("boot-init detour `bl` out of range"))?;
        thumb::write(out, stub_va as usize, &bytes);
        thumb::write(out, conv, &bl);
        Ok((conv as u32, stub_va))
    }

    /// Downgrade-enable lever. Family-agnostic: writes `0xDE` at the identity-page
    /// slot when a well-formed MTEK descriptor is present; idempotent.
    pub(crate) fn lever_de(&self, image: &[u8], out: &mut [u8], chip: &ChipInfo) -> LeverReport {
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
    pub(crate) fn already_present_report(
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

/// MT1939-classic analogue of [`boot_init_convergence`]. The classic reload site is a
/// called **leaf helper**: its internal `bmi` targets a `bx lr` (function return), so —
/// unlike modern — there is NO convergence `bl <orig_init>` inside it to detour. Rule
/// (RE-proven unique on all 17 classic images): the helper's function entry is
/// `anchor = site - 4`; detour the helper's **unique caller `bl`** instead. The stub
/// (`build_boot_init`) does its `0xFF`-fill + flash-load, then tail-calls the helper —
/// structurally identical to the modern detour, just anchored one call-frame up.
///
/// Returns `(caller_bl_site, helper_entry)`. Requires **exactly one** 32-bit Thumb `bl`
/// image-wide whose target is the helper (fail-closed / `None` on 0 or >1). Validated:
/// exactly one caller on every classic image, always inside a `push {…,lr}` function.
pub(crate) fn classic_boot_init_caller(image: &[u8], site: usize) -> Option<(usize, u32)> {
    let helper = site.checked_sub(4)? as u32; // helper leaf entry (anchor, `ldr r0,[pc]`)
    let end = image.len().saturating_sub(4);
    let mut caller: Option<usize> = None;
    let mut off = 0usize;
    while off + 4 <= end {
        if let Some(t) = thumb::decode_bl(image, off) {
            if t & !1 == helper & !1 {
                if caller.is_some() {
                    return None; // >1 caller — ambiguous, fail closed
                }
                caller = Some(off);
            }
        }
        off += 2;
    }
    caller.map(|c| (c, helper))
}

#[cfg(test)]
#[path = "mt1959_kat_tests.rs"]
mod kat_tests;
