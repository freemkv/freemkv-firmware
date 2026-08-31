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

use super::mt1959::Mt1959Engine;
use super::CreateReport;
use crate::abi;
use crate::thumb::{self, Asm, CommandRecord, CommandTable};

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
/// Number of sub-functions (`SubFn::Identity` … `SubFn::Reserved`).
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
/// and each OEM-code trampoline (Speed 0x02, Region 0x05) reads its own flag byte
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

/// VID variant-5 scratch: where the `03` handler synthesizes the READ DISC
/// STRUCTURE (format-0x80) CDB before entering the OEM dispatcher. In the same
/// 204-byte free hole as [`FLAG_TABLE_BASE`], past the 10-byte flag table
/// (`0x02000e40..0x02000e49`), non-overlapping. Chip constant, not a flash find.
const VID_CDB_SCRATCH: u32 = 0x0200_0e50;

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
/// `"MTEKMT19.."` sits at `+0x34`; a `0x78 00 00 00 <crc16>` marker at `+0x50`
/// precedes the DE slot at `+0x56`. Verified on 1.00 and 1.03.
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
    // subfns 2..=6: not-yet-implemented placeholders that prove the branching.
    for i in 2..=NUM_SUBFNS as usize {
        set(i - 1, format!("Command {i:02} WIP").as_bytes());
    }
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
        // entry+2 is `ldr r3, [pc, #imm]` (0x4Bxx).
        let ins_off = entry + 2;
        let hw = u16::from_le_bytes([image[ins_off], image[ins_off + 1]]);
        if (hw & 0xF800) != 0x4800 || ((hw >> 8) & 0x7) != 3 {
            bail!("scanner entry+2 is not `ldr r3,[pc,#imm]` (got 0x{hw:04x})");
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
        let end = TABLE_HI.min(image.len());
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
        let mut off = TABLE_LO;
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

    /// The unique offset of the [`VID_GATE_SIG`] match (the VID gate's
    /// address-compute tail). The gate `ldrb r0,[r0]` is at `result + 16`.
    fn find_vid_gate(&self, image: &[u8]) -> Result<usize> {
        let lo = 0x0012_0000usize.min(image.len());
        let hi = 0x0018_0000usize.min(image.len());
        find_unique(image, VID_GATE_SIG, lo, hi, "VID gate")
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
    /// near its prologue — never hardcoded. VID debug variants that reset the AGID
    /// selector use this to write `byte[0xa] &= 0x3F` (AGID → 0).
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

    /// The Speed (0x02) ramp-ceiling gate anchor — the unique [`SPEED_GATE_SIG`]
    /// match (`0x1bb22` on 1.00 and 1.03). Returns the anchor offset; the gate
    /// `cmp/bhi` the detour replaces begins at `anchor+4`.
    pub fn find_speed_gate(&self, image: &[u8]) -> Result<u32> {
        let lo = 0x0001_0000usize.min(image.len());
        let hi = 0x0002_0000usize.min(image.len());
        Ok(find_unique(image, SPEED_GATE_SIG, lo, hi, "Speed ramp-ceiling gate")? as u32)
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

    /// The downgrade-enable (DE) byte offset. Anchored on the ASCII identity page
    /// (the same drive-descriptor record [`crate::family::detect_chip`] parses):
    /// the `"MTEKMT19"` family tag at `descriptor+0x34` and the `0x78` marker at
    /// `descriptor+0x50` must both be present, then the DE slot is `descriptor+0x56`.
    /// Refuses rather than guessing a byte to poke if the page isn't the descriptor.
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
        if image[DESCRIPTOR_OFFSET + 0x50] != 0x78 {
            bail!(
                "DE marker (0x78 @ 0x{:x}) absent — refusing to guess the DE offset",
                DESCRIPTOR_OFFSET + 0x50
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
    /// Every handled sub-function first persists its toggle into the SRAM flag
    /// table (`flag[subfn] = cdb[5]`) so the OEM-code trampolines (Speed 0x02,
    /// Region 0x05, …) can read it; this is harmless for read-only sub-functions.
    ///
    /// **VID (0x03) is a DEBUG build**: `cdb[5]` selects a retrieval VARIANT so all
    /// strategies ship in ONE image and can be tested on hardware without
    /// reflashing. The OEM producer (0x13675c on 1.00) only releases the clear VID
    /// when (a) its session struct's AGID selector (`byte[0xa]>>6`) is 0/1 AND
    /// (b) the per-AGID auth byte == 6. "request-6" = forcing that auth byte to 6
    /// via the OEM gate-setter = the host-cert bypass (no real AKE). Variants:
    ///   - `0`  OEM no-op.
    ///   - `1`  gate AGID0+AGID1=6, call producer (selector left as-is).
    ///   - `2`  gate AGID0=6, call producer (only AGID0).
    ///   - `3`  reset selector→AGID0, gate AGID0=6, call producer.
    ///   - `4`  reset selector→AGID0, gate AGID0+AGID1, call producer.
    ///   - `5`  FULL OEM PATH (most likely correct): synthesize a READ DISC
    ///     STRUCTURE CDB (format 0x80 = Volume ID) in free SRAM, gate both AGIDs,
    ///     and enter the OEM format dispatcher (0xb07ca) — its own setup + producer
    ///     run with correct session state and pop balanced. Pure Thumb.
    ///
    /// All variants converge on the shared validate/emit tail. Variants >5 fall
    /// through the 1..4 selector (best-effort ≈ V3 without AGID1); only 1..5 are
    /// defined.
    pub fn build_handler(&self, image: &[u8], oem_handler: u32, flag_base: u32) -> Result<Vec<u8>> {
        let cdb = self.find_cdb_base(image)?;
        let (writer, commit_off) = self.find_response_writer(image)?;
        let (commit, length_field) = self.find_response_commit(image)?;
        let sense = self.sense_setter(image)?;
        // VID (subfn 0x03) facts — all derived from the image: the OEM AKE
        // gate-setter primitive, the OEM Volume-ID producer, and the producer's
        // own clear-VID scratch buffer (a literal it loads, ~0x00210c00).
        let gate_setter = self.find_vid_gate_setter(image)?;
        let (vid_producer, vid_out_buf) = self.find_vid_producer(image)?;
        // Per-AGID session struct the producer reads its active AGID from — used
        // by VID debug variants 3/4 to reset the AGID selector to 0.
        let agid_struct = self.find_vid_agid_struct(image)?;
        // VID variant 5 (dispatcher path): a provably-free SRAM cell for the
        // synthesized READ DISC STRUCTURE CDB, plus the OEM format dispatcher entry
        // (0xb07ca on 1.00). The 10-byte CDB sits far below flag_base — no overlap.
        let free_sram = VID_CDB_SCRATCH;
        let dispatcher = self.find_aacs(image)?.0;
        let table = payload_table();

        let mut a = Asm::new();
        let tail = a.label();
        let knock_ok = a.label();
        let generic = a.label();
        // VID (subfn 0x03) labels.
        let vid_begin = a.label();
        let vid_proceed = a.label();
        let vid_not_v5 = a.label();
        let vid_validate = a.label();
        let vid_skip_sel = a.label();
        let vid_do_agid1 = a.label();
        let vid_skip_agid1 = a.label();
        let vid_oem = a.label();
        let vfail = a.label();
        let vchk = a.label();
        let vchkd = a.label();
        let vclr = a.label();
        let vclrd = a.label();
        let vwr = a.label();
        let voem = a.label();
        let voemd = a.label();
        let vcommit = a.label();
        let clr = a.label();
        let clrd = a.label();
        let wr = a.label();
        let docommit = a.label();
        // RAM-probe sub-functions (diagnostic): each peeks one runtime cell and
        // returns its bytes, so we can read the drive's live AACS state on
        // hardware without reflashing per question.
        let np5 = a.label();
        let np6 = a.label();
        let np7 = a.label();
        let nogeneric = a.label();
        let p4loop = a.label();
        let p6loop = a.label();
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

        // subfn Vid (0x03): self-contained clear Volume-ID read (see the fn doc for
        // the variant table). Conditional branches reach only ±127 halfwords, so
        // gate with a near `beq` + an unconditional `b` (±1023) to the far paths.
        a.cmp_imm(4, abi::SubFn::Vid as u8);
        a.beq(vid_begin); // subfn 03 -> VID path
        a.b(generic); // else fall through to the generic dispatch
        a.bind(vid_begin);
        // Variant dispatch on cdb[5]; see the fn doc for the V0..V5 table. 0 = OEM
        // no-op; >5 falls through the 1..4 selector. V5 is handled first (it is
        // self-contained), then 1..4 — all converge on the shared validate tail.
        a.ldrb_imm(4, 3, abi::CDB_STATE as u16); // r4 = variant (cdb[5])
        a.cmp_imm(4, abi::STATE_OFF); // 0 = OEM no-op
        a.bne(vid_proceed);
        a.b(vid_oem); // far branch to the OEM no-op tail
        a.bind(vid_proceed);
        // V5 (variant == 5): the full dispatcher path. Handled first because it is
        // self-contained (builds its own CDB, enters the dispatcher) and then jumps
        // to the shared validate tail; `bne` skips it for variants 1..4.
        a.cmp_imm(4, 5);
        a.bne(vid_not_v5);
        // Build a minimal READ DISC STRUCTURE CDB in free SRAM: only cdb[7]=0x80
        // (format = Volume ID) and cdb[8]=cdb[9]=0 matter to the dispatcher.
        a.ldr_lit(1, free_sram); // r1 = &cdb scratch
        a.movs_imm(0, 0);
        a.strb_imm(0, 1, 8); // cdb[8] = 0
        a.strb_imm(0, 1, 9); // cdb[9] = 0
        a.movs_imm(0, 0x80);
        a.strb_imm(0, 1, 7); // cdb[7] = 0x80 (Volume ID)
                             // gate both AGIDs = 6 (host-cert bypass) via set_agid_state.
        a.ldr_lit(2, gate_setter | 1);
        a.movs_imm(0, 0);
        a.movs_imm(1, 6);
        a.blx(2);
        a.movs_imm(0, 1);
        a.movs_imm(1, 6);
        a.blx(2); // r2 still holds gate_setter|1
                  // enter the OEM READ DISC STRUCTURE dispatcher with r0 = &cdb.
        a.ldr_lit(0, free_sram);
        a.ldr_lit(2, dispatcher | 1);
        a.blx(2); // stages the clear VID into vid_out_buf, pops balanced
        a.b(vid_validate); // -> shared validate/emit tail
        a.bind(vid_not_v5);
        // V3/V4 (variant >= 3): reset the AGID selector to 0 so the producer reads
        // a defined AGID instead of stale session state: struct byte[0xa] &= ~0xC0.
        a.cmp_imm(4, 3);
        a.blo(vid_skip_sel); // variant 1/2 → leave selector as-is
        a.ldr_lit(0, agid_struct); // r0 = &session struct
        a.ldrb_imm(1, 0, 0x0a); // r1 = byte[0xa]
        a.movs_imm(6, 0xC0); // r6 = AGID mask (bits 6-7)
        a.bics(1, 6); // r1 &= ~0xC0 → AGID = 0
        a.strb_imm(1, 0, 0x0a); // store back
        a.bind(vid_skip_sel);
        // gate AGID 0 = 6 (all variants): set_agid_state(0, 6).
        a.ldr_lit(2, gate_setter | 1);
        a.movs_imm(0, 0);
        a.movs_imm(1, 6);
        a.blx(2);
        // gate AGID 1 = 6 for V1 and V4 only.
        a.cmp_imm(4, 1);
        a.beq(vid_do_agid1);
        a.cmp_imm(4, 4);
        a.bne(vid_skip_agid1);
        a.bind(vid_do_agid1);
        a.movs_imm(0, 1);
        a.movs_imm(1, 6);
        a.blx(2); // r2 still holds gate_setter|1
        a.bind(vid_skip_agid1);
        // call the OEM VID producer; it stages the CLEAR VID at vid_out_buf.
        a.ldr_lit(0, vid_producer | 1);
        a.blx(0); // preserves r7 (byte-writer)
                  // validate: OR the 16 staged bytes; all-zero => no VID staged.
                  // V5 rejoins here after the dispatcher call.
        a.bind(vid_validate);
        a.ldr_lit(6, vid_out_buf); // r6 = &clear VID
        a.movs_imm(1, 0); // r1 = OR accumulator
        a.movs_imm(5, 0); // r5 = i
        a.bind(vchk);
        a.cmp_imm(5, abi::VID_LEN as u8);
        a.bhs(vchkd);
        a.ldrb_reg(0, 6, 5); // r0 = VID[i]
        a.orrs(1, 0); // acc |= VID[i]
        a.adds_imm(5, 1);
        a.b(vchk);
        a.bind(vchkd);
        a.cmp_imm(1, 0); // any non-zero byte?
        a.beq(vfail); // all-zero -> treat as no VID
                      // clear the response buffer so no stale bytes leak past the payload.
        a.movs_imm(5, 0);
        a.bind(vclr);
        a.cmp_imm(5, CLEAR_LEN);
        a.bhs(vclrd);
        a.mov_reg(0, 5);
        a.movs_imm(1, 0);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(vclr);
        a.bind(vclrd);
        // Write the 16-byte VID RAW at response offset 0 — no "freemkv" magic:
        // only the host can issue the 3C 0E C0 DE knock, so any GOOD reply is ours
        // by construction (magic stays only on Identity, the detection probe).
        a.ldr_lit(6, vid_out_buf); // r6 = &clear VID
        a.movs_imm(5, 0);
        a.bind(vwr);
        a.cmp_imm(5, abi::VID_LEN as u8);
        a.bhs(vcommit);
        a.mov_reg(0, 5); // response offset = i (raw, from offset 0)
        a.ldrb_reg(1, 6, 5); // byte = VID[i]
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(vwr);
        // no VID available (no disc / producer staged nothing): CHECK CONDITION.
        a.bind(vfail);
        a.movs_imm(0, abi::SENSE_NO_MEDIUM[0]); // key = NOT READY
        a.movs_imm(1, abi::SENSE_NO_MEDIUM[1]); // asc = MEDIUM NOT PRESENT
        a.movs_imm(2, abi::SENSE_NO_MEDIUM[2]); // ascq = 0
        a.ldr_lit(3, sense | 1);
        a.blx(3); // set_sense -> CHECK CONDITION status
        a.pop(0x01F0); // pop {r4,r5,r6,r7,pc}
                       // state==0: OEM no-op — commit a cleared (magic-less) buffer -> host Ok(None).
        a.bind(vid_oem);
        a.movs_imm(5, 0);
        a.bind(voem);
        a.cmp_imm(5, CLEAR_LEN);
        a.bhs(voemd);
        a.mov_reg(0, 5);
        a.movs_imm(1, 0);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(voem);
        a.bind(voemd);
        // local commit tail for subfn 03 (kept near its callers so every branch
        // to it stays in conditional-branch range regardless of the generic path).
        a.bind(vcommit);
        a.movs_imm(0, CLEAR_LEN); // transfer length
        a.ldr_lit(1, length_field);
        a.strh_imm(0, 1, 0); // set the 16-bit transfer-length cell
        a.ldr_lit(0, commit_off); // buffer-base commit offset
        a.ldr_lit(2, commit | 1);
        a.blx(2); // commit the DMA
        a.pop(0x01F0); // pop {r4,r5,r6,r7,pc}
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

        // RAM probes (diagnostic sub-functions). subfn BusEncryption (0x04):
        // diagnostic peek of the word at 0x020004fc — no bus-toggle actuator is
        // emitted here (bus-off is a proven no-op). r3 holds the CDB base.
        a.cmp_imm(4, abi::SubFn::BusEncryption as u8);
        a.bne(np5);
        a.ldr_lit(6, 0x0200_04fc);
        a.movs_imm(5, 0);
        a.bind(p4loop);
        a.cmp_imm(5, 4);
        a.bhs(docommit);
        a.mov_reg(0, 5);
        a.ldrb_reg(1, 6, 5);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(p4loop);
        a.bind(np5);

        // subfn 05: peek the per-AGID auth-state byte at
        // [0x02000c78]+[0x02000c7c]+0xc5a0+AGID(0) — tests whether the drive
        // auto-authenticates on disc load (state byte == 6 means auth done).
        a.cmp_imm(4, abi::SubFn::Region as u8);
        a.bne(np6);
        a.ldr_lit(0, 0x0200_0c78);
        a.ldr_imm(0, 0, 0);
        a.ldr_lit(1, 0x0200_0c7c);
        a.ldr_imm(1, 1, 0);
        a.adds_reg(0, 0, 1);
        a.ldr_lit(2, 0xc5a0);
        a.adds_reg(0, 0, 2);
        a.ldrb_imm(1, 0, 0);
        a.movs_imm(0, 0);
        a.blx(7);
        a.b(docommit);
        a.bind(np6);

        // subfn 06: peek the VID response buffer at [0x02000c7c]+0xaf94 (36
        // bytes) — tests whether a real VID is already resident after disc load.
        a.cmp_imm(4, abi::SubFn::Reserved as u8);
        a.bne(np7);
        a.ldr_lit(6, 0x0200_0c7c);
        a.ldr_imm(6, 6, 0);
        a.ldr_lit(2, 0xaf94);
        a.adds_reg(6, 6, 2);
        a.movs_imm(5, 0);
        a.bind(p6loop);
        a.cmp_imm(5, 36);
        a.bhs(docommit);
        a.mov_reg(0, 5);
        a.ldrb_reg(1, 6, 5);
        a.blx(7);
        a.adds_imm(5, 1);
        a.b(p6loop);
        a.bind(np7);

        // subfn DumpAll (0x09): peek CLEAR_LEN bytes at the absolute 32-bit addr
        // packed big-endian in cdb[5..9] — a general RAM-dump primitive (the host
        // steps the address to read any region). r3 still holds the CDB base.
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
    fn build_speed_stub(&self, flag_base: u32, fallthrough: u32, exit: u32) -> Result<Vec<u8>> {
        let mut a = Asm::new();
        let patched = a.label();
        let decide = a.label();
        let go_exit = a.label();
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
        let speed_gate = self.find_speed_gate(image)?;
        let region_emitter = self.find_region_emitter(image)?;
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
        self.assert_sram_cell_free(image, VID_CDB_SCRATCH, 16, "VID V5 CDB scratch")?;

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
        let speed_bytes = self.build_speed_stub(flag_base, fallthrough, ramp_exit)?;
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
            de_off,
            flag_base,
            free_sram_cell,
        })
    }
}

#[cfg(test)]
#[path = "mt1959_kat_tests.rs"]
mod kat_tests;
