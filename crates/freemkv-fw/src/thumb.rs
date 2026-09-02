//! Generic, platform-neutral toolkit for patching Thumb/ARM firmware images.
//!
//! Everything a platform engine does reduces to three verbs over a flat image:
//!
//! * **find**  — locate something (a byte pattern, a word, a run of free space,
//!   a pc-relative literal load). ONE primitive, [`find`], expressed over a
//!   [`Needle`]; every named finder ([`find_free_space`], …) is a thin overload
//!   of it. Because [`find`] takes a `start` and returns the match offset, finds
//!   compose by nesting: `find(y, find(x, find(a, 0)))`.
//! * **read**  — read a value at a found location ([`read_u32`], [`read_u8`]).
//! * **modify / insert** — [`write()`] bytes at an offset (repoint a record, patch
//!   a field) or [`insert`] a code blob into free space, returning its address.
//!
//! This module knows nothing about any specific firmware. A platform engine
//! (`engine::mt1959`, future `mt1939` / `pioneer`) supplies the *knowledge* —
//! which needle to look for and where — and composes these verbs. Adding a
//! platform is a new engine, never new toolkit logic.

/// A thing [`find`] can search for. Add a variant here to teach every engine a
/// new kind of search without touching engine code.
#[derive(Debug, Clone, Copy)]
pub enum Needle<'a> {
    /// An exact byte pattern.
    Bytes(&'a [u8]),
    /// A little-endian 32-bit word (e.g. an absolute address embedded as a
    /// Thumb literal, or a handler pointer).
    Word(u32),
    /// A run of at least `n` erased-flash bytes (`0xFF`) — i.e. free space.
    FreeRun(usize),
}

/// The one search primitive. Find `needle` at or after byte offset `start`;
/// return the offset of the match, or `None`. Every named finder below is a
/// thin overload of this call.
pub fn find(image: &[u8], needle: Needle, start: usize) -> Option<usize> {
    match needle {
        Needle::Bytes(pat) => find_bytes(image, pat, start),
        Needle::Word(w) => find_bytes(image, &w.to_le_bytes(), start),
        Needle::FreeRun(n) => find_free_run(image, n, start),
    }
}

/// Overload: the first run of `>= n` free (`0xFF`) bytes at or after `start`.
/// `find_free_space(image, 0) == find(image, Needle::FreeRun(n), 0)`.
pub fn find_free_space(image: &[u8], min: usize, start: usize) -> Option<usize> {
    find(image, Needle::FreeRun(min), start)
}

/// Read the little-endian u32 at `at` (e.g. a record's handler pointer).
pub fn read_u32(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]])
}

/// Read the byte at `at`.
pub fn read_u8(image: &[u8], at: usize) -> u8 {
    image[at]
}

/// Modify: overwrite `image[at..at+bytes.len()]` with `bytes`.
pub fn write(image: &mut [u8], at: usize, bytes: &[u8]) {
    image[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Insert: copy `code` into free space at `free_off`, returning the image
/// address it now lives at (offset == load address on this flat mapping).
pub fn insert(image: &mut [u8], free_off: usize, code: &[u8]) -> u32 {
    write(image, free_off, code);
    free_off as u32
}

/// A SCSI-command dispatch table: an array of fixed-size records the drive scans
/// by opcode to find a handler. The record shape is platform-specific, so an
/// [`crate::engine::Engine`] supplies the geometry; the find/replace operations
/// here are generic over it.
///
/// MT1959 record (verified against the scanner at `0x1b690`, which does
/// `ldrb [rec+opcode_off]` then `ldr [rec+handler_off]; blx`):
/// `[opcode(1) | flags(1) | resv(2) | handler(4 LE)]`, stride 8, base 0x14fc9c,
/// terminated by a record whose flags == `term_flag` (0x03).
#[derive(Debug, Clone, Copy)]
pub struct CommandTable {
    /// File offset of the first record.
    pub base: usize,
    /// Bytes per record.
    pub stride: usize,
    /// Byte offset of the opcode within a record.
    pub opcode_off: usize,
    /// Byte offset of the flags byte within a record.
    pub flags_off: usize,
    /// Byte offset of the 4-byte LE handler pointer within a record.
    pub handler_off: usize,
    /// Flags value that marks the terminator record (scan stops here).
    pub term_flag: u8,
    /// Max records to scan before giving up (guards a corrupt/missing terminator).
    pub max_records: usize,
}

/// One resolved dispatch record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandRecord {
    /// File offset of the record.
    pub off: usize,
    /// The opcode it dispatches.
    pub opcode: u8,
    /// The record's flags byte.
    pub flags: u8,
    /// The handler pointer (Thumb bit as-stored; 0 = null / no handler).
    pub handler: u32,
}

impl CommandTable {
    /// `find(opcode)` — the record dispatching `opcode`, or `None` if absent
    /// (scan stops at the terminator, exactly like the drive's scanner).
    pub fn find(&self, image: &[u8], opcode: u8) -> Option<CommandRecord> {
        let mut off = self.base;
        for _ in 0..self.max_records {
            if off + self.stride > image.len() {
                return None;
            }
            let flags = image[off + self.flags_off];
            if flags == self.term_flag {
                return None; // reached terminator without a match
            }
            if image[off + self.opcode_off] == opcode {
                return Some(CommandRecord {
                    off,
                    opcode,
                    flags,
                    handler: read_u32(image, off + self.handler_off),
                });
            }
            off += self.stride;
        }
        None
    }

    /// `replace(record, newHandler)` — overwrite a record's handler pointer (and,
    /// if `flags` is `Some`, its flags byte). This is the hijack: point an
    /// existing opcode's dispatch at our injected code. Prefer a record whose
    /// current handler is null (nothing runs today); hijacking a live handler is
    /// allowed but the caller should warn.
    pub fn replace(&self, image: &mut [u8], rec: &CommandRecord, handler: u32, flags: Option<u8>) {
        if let Some(f) = flags {
            image[rec.off + self.flags_off] = f;
        }
        write(image, rec.off + self.handler_off, &handler.to_le_bytes());
    }
}

impl CommandTable {
    /// Walk the table exactly as the drive's scanner does — following chain
    /// records (`flags == chain_flag`) to successor segments and stopping at the
    /// first terminator (`flags == term_flag`) — collecting every dispatch
    /// record. `chain_flag`/`chain_handler_is_next_base` model the MT1959 scanner
    /// (`flags==4` → `handler` field is the file offset of the next segment).
    ///
    /// Returns the records in scan order. This is the grounded basis for
    /// [`CommandTable::find`]-style lookups when a table spans chained segments.
    pub fn walk(&self, image: &[u8], chain_flag: u8) -> Vec<CommandRecord> {
        let mut out = Vec::new();
        let mut base = self.base;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..self.max_records {
            if !seen.insert(base) {
                break; // chain loop guard
            }
            let mut off = base;
            let mut advanced = false;
            for _ in 0..self.max_records {
                if off + self.stride > image.len() {
                    return out;
                }
                let flags = image[off + self.flags_off];
                if flags == self.term_flag {
                    return out;
                }
                let handler = read_u32(image, off + self.handler_off);
                if flags == chain_flag {
                    base = handler as usize; // next segment base
                    advanced = true;
                    break;
                }
                out.push(CommandRecord {
                    off,
                    opcode: image[off + self.opcode_off],
                    flags,
                    handler,
                });
                off += self.stride;
            }
            if !advanced {
                break;
            }
        }
        out
    }
}

/// Whether the Thumb code at file offset `off` begins with a `push {..., lr}`
/// (`0xB5xx`) within the first `window` halfwords — a cheap "this is a real
/// function entry" cross-check. Used to reject a coincidental byte match when
/// resolving a handler pointer.
pub fn prologue_is_push_lr(image: &[u8], off: usize, window: usize) -> bool {
    (0..window).any(|k| {
        let p = off + k * 2;
        p + 2 <= image.len() && (u16::from_le_bytes([image[p], image[p + 1]]) & 0xFF00) == 0xB500
    })
}

/// A tiny position-independent Thumb assembler with a trailing 4-byte-aligned
/// literal pool — the "create" verb. It is *dumb*: it emits exactly the
/// instructions asked for and lays out `ldr rt, [pc, #imm]` literals in
/// first-reference order. An engine composes it; the toolkit never decides what
/// to assemble.
///
/// Placement invariant: the returned bytes assume a 4-byte-aligned load address
/// (so `Align(PC, 4)` for the pool matches the buffer-relative layout). Callers
/// must place the code at a 4-aligned offset.
#[derive(Default)]
pub struct Asm {
    code: Vec<u8>,
    ldrs: Vec<(usize, u32, u16)>,    // (insn byte pos, value, rt)
    fixups: Vec<(usize, u16, bool)>, // (insn pos, label, is_unconditional) branch
    adrs: Vec<(usize, u16)>,         // (insn pos, blob label) for `adr rd, blob`
    blobs: Vec<(u16, Vec<u8>)>,      // (label, data) appended after the pool
    labels: Vec<Option<usize>>,      // label id -> byte pos
}

impl Asm {
    /// A fresh, empty assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current byte position (also a branch target).
    pub fn pos(&self) -> usize {
        self.code.len()
    }

    /// Reserve a label id; bind it later with [`Asm::bind`].
    pub fn label(&mut self) -> u16 {
        self.labels.push(None);
        (self.labels.len() - 1) as u16
    }

    /// Bind `label` to the current position.
    pub fn bind(&mut self, label: u16) {
        self.labels[label as usize] = Some(self.code.len());
    }

    /// Emit a raw 16-bit Thumb instruction (little-endian).
    pub fn raw16(&mut self, insn: u16) {
        self.code.extend_from_slice(&insn.to_le_bytes());
    }

    /// `ldr rt, [pc, #imm]` loading `value` from the pool (dedup, first-ref order).
    pub fn ldr_lit(&mut self, rt: u16, value: u32) {
        let pos = self.code.len();
        self.raw16(0x4800 | (rt << 8)); // patched in finish()
        self.ldrs.push((pos, value, rt));
    }

    /// `ldrb rt, [rn, #imm5]` (byte load, offset 0..31).
    pub fn ldrb_imm(&mut self, rt: u16, rn: u16, imm5: u16) {
        self.raw16(0x7800 | (imm5 << 6) | (rn << 3) | rt);
    }

    /// `ldr rt, [rn, #imm]` (word load; `imm` must be a multiple of 4, 0..124).
    pub fn ldr_imm(&mut self, rt: u16, rn: u16, imm: u16) {
        self.raw16(0x6800 | ((imm >> 2) << 6) | (rn << 3) | rt);
    }

    /// `strh rt, [rn, #imm]` (halfword store; `imm` must be even, 0..62).
    pub fn strh_imm(&mut self, rt: u16, rn: u16, imm: u16) {
        self.raw16(0x8000 | ((imm >> 1) << 6) | (rn << 3) | rt);
    }

    /// `str rt, [rn, #imm]` (word store; `imm` must be a multiple of 4, 0..124).
    pub fn str_imm(&mut self, rt: u16, rn: u16, imm: u16) {
        self.raw16(0x6000 | ((imm >> 2) << 6) | (rn << 3) | rt);
    }

    /// `bics rd, rm` (bit-clear: `rd &= ~rm`).
    pub fn bics(&mut self, rd: u16, rm: u16) {
        self.raw16(0x4380 | (rm << 3) | rd);
    }

    /// `orrs rd, rm` (`rd |= rm`).
    pub fn orrs(&mut self, rd: u16, rm: u16) {
        self.raw16(0x4300 | (rm << 3) | rd);
    }

    /// `strb rt, [rn, #imm5]` (byte store, offset 0..31).
    pub fn strb_imm(&mut self, rt: u16, rn: u16, imm5: u16) {
        self.raw16(0x7000 | (imm5 << 6) | (rn << 3) | rt);
    }

    /// `cmp rn, #imm8`.
    pub fn cmp_imm(&mut self, rn: u16, imm8: u8) {
        self.raw16(0x2800 | (rn << 8) | imm8 as u16);
    }

    /// `movs rt, #imm8`.
    pub fn movs_imm(&mut self, rt: u16, imm8: u8) {
        self.raw16(0x2000 | (rt << 8) | imm8 as u16);
    }

    /// `push {reglist}` (bit 8 = lr). e.g. `push {lr}` = `0x4000`.
    pub fn push(&mut self, reglist: u16) {
        self.raw16(0xB400 | reglist);
    }

    /// `pop {reglist}` (bit 8 = pc). e.g. `pop {pc}` = `0x0100`.
    pub fn pop(&mut self, reglist: u16) {
        self.raw16(0xBC00 | reglist);
    }

    /// `blx rm`.
    pub fn blx(&mut self, rm: u16) {
        self.raw16(0x4780 | (rm << 3));
    }

    /// `bx rm`.
    pub fn bx(&mut self, rm: u16) {
        self.raw16(0x4700 | (rm << 3));
    }

    /// `bne label` (conditional, patched at [`Asm::finish`]).
    pub fn bne(&mut self, label: u16) {
        let pos = self.code.len();
        self.raw16(0xD100);
        self.fixups.push((pos, label, false));
    }

    /// `beq label` (conditional, patched at [`Asm::finish`]).
    pub fn beq(&mut self, label: u16) {
        let pos = self.code.len();
        self.raw16(0xD000);
        self.fixups.push((pos, label, false));
    }

    /// `bhs label` / `bcs` (unsigned ≥, conditional).
    pub fn bhs(&mut self, label: u16) {
        let pos = self.code.len();
        self.raw16(0xD200);
        self.fixups.push((pos, label, false));
    }

    /// `bhi label` (unsigned >, conditional) — used by the Speed trampoline to
    /// replicate the OEM ramp-gate's own `bhi <ramp-exit>` after choosing the
    /// ceiling.
    pub fn bhi(&mut self, label: u16) {
        let pos = self.code.len();
        self.raw16(0xD800);
        self.fixups.push((pos, label, false));
    }

    /// `blo label` / `bcc` (unsigned <, conditional).
    pub fn blo(&mut self, label: u16) {
        let pos = self.code.len();
        self.raw16(0xD300);
        self.fixups.push((pos, label, false));
    }

    /// `b label` (unconditional, 11-bit offset).
    pub fn b(&mut self, label: u16) {
        let pos = self.code.len();
        self.raw16(0xE000);
        self.fixups.push((pos, label, true));
    }

    /// `ldrb rt, [rn, rm]` (register-offset byte load).
    pub fn ldrb_reg(&mut self, rt: u16, rn: u16, rm: u16) {
        self.raw16(0x5C00 | (rm << 6) | (rn << 3) | rt);
    }

    /// `adds rt, #imm8`.
    pub fn adds_imm(&mut self, rt: u16, imm8: u8) {
        self.raw16(0x3000 | (rt << 8) | imm8 as u16);
    }

    /// `subs rt, #imm8`.
    pub fn subs_imm(&mut self, rt: u16, imm8: u8) {
        self.raw16(0x3800 | (rt << 8) | imm8 as u16);
    }

    /// `lsls rd, rm, #imm5`.
    pub fn lsls_imm(&mut self, rd: u16, rm: u16, imm5: u16) {
        self.raw16((imm5 << 6) | (rm << 3) | rd);
    }

    /// `adds rd, rn, rm` (register).
    pub fn adds_reg(&mut self, rd: u16, rn: u16, rm: u16) {
        self.raw16(0x1800 | (rm << 6) | (rn << 3) | rd);
    }

    /// `mov rd, rm` (low registers) via `adds rd, rm, #0`.
    pub fn mov_reg(&mut self, rd: u16, rm: u16) {
        self.raw16(0x1C00 | (rm << 3) | rd);
    }

    /// `adr rd, blob` — position-independent load of a data blob's address
    /// (`add rd, pc, #imm`). The blob is declared with [`Asm::data_blob`].
    pub fn adr(&mut self, rd: u16, blob_label: u16) {
        let pos = self.code.len();
        self.raw16(0xA000 | (rd << 8));
        self.adrs.push((pos, blob_label));
    }

    /// Declare a read-only data blob appended after the code+pool; returns a
    /// label usable with [`Asm::adr`]. Blobs are laid out 4-byte aligned.
    pub fn data_blob(&mut self, bytes: Vec<u8>) -> u16 {
        let label = self.label();
        self.blobs.push((label, bytes));
        label
    }

    /// Lay out the pool (4-aligned) then data blobs, and back-patch every branch,
    /// `ldr` literal, and `adr`.
    pub fn finish(mut self) -> anyhow::Result<Vec<u8>> {
        use anyhow::bail;
        // 1. code-position branches (targets already bound during emit).
        for (pos, label, uncond) in std::mem::take(&mut self.fixups) {
            let target = self.labels[label as usize]
                .ok_or_else(|| anyhow::anyhow!("unbound label {label}"))?;
            let off = (target as i32 - (pos as i32 + 4)) / 2;
            let enc = if uncond {
                if !(-1024..=1023).contains(&off) {
                    bail!("branch out of range ({off} halfwords)");
                }
                0xE000u16 | (off as u16 & 0x07FF)
            } else {
                if !(-128..=127).contains(&off) {
                    bail!("conditional branch out of range ({off} halfwords)");
                }
                let base = u16::from_le_bytes([self.code[pos], self.code[pos + 1]]) & 0xFF00;
                base | (off as i8 as u8 as u16)
            };
            self.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        // 2. literal pool (4-aligned), patch ldr.
        while !self.code.len().is_multiple_of(4) {
            self.code.push(0x00);
        }
        let mut placed: Vec<(u32, u32)> = Vec::new();
        for (pos, value, rt) in std::mem::take(&mut self.ldrs) {
            let off = match placed.iter().find(|(v, _)| *v == value) {
                Some(&(_, o)) => o,
                None => {
                    let o = self.code.len() as u32;
                    self.code.extend_from_slice(&value.to_le_bytes());
                    placed.push((value, o));
                    o
                }
            };
            let pc = (pos as u32 + 4) & !3;
            let imm8 = (off - pc) / 4;
            if imm8 > 0xFF {
                bail!("ldr literal out of range (imm8 = {imm8})");
            }
            let enc = 0x4800u16 | (rt << 8) | imm8 as u16;
            self.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        // 3. data blobs (each 4-aligned); bind their labels.
        for (label, bytes) in std::mem::take(&mut self.blobs) {
            while !self.code.len().is_multiple_of(4) {
                self.code.push(0x00);
            }
            self.labels[label as usize] = Some(self.code.len());
            self.code.extend_from_slice(&bytes);
        }
        // 4. adr fixups (blob labels now bound).
        for (pos, label) in std::mem::take(&mut self.adrs) {
            let target = self.labels[label as usize]
                .ok_or_else(|| anyhow::anyhow!("unbound blob label {label}"))?;
            let base = (pos as u32 + 4) & !3;
            let imm = target as u32;
            if imm < base || !(imm - base).is_multiple_of(4) || (imm - base) / 4 > 0xFF {
                bail!("adr target out of range (pos=0x{pos:x} target=0x{target:x})");
            }
            let enc = 0xA000u16
                | ((u16::from_le_bytes([self.code[pos], self.code[pos + 1]]) >> 8 & 7) << 8)
                | ((imm - base) / 4) as u16;
            self.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        Ok(self.code)
    }
}

/// Decode a Thumb `BL` at file offset `off` → its absolute target VA (Thumb bit
/// cleared). `None` if the 4 bytes at `off` are not a `BL`.
pub fn decode_bl(image: &[u8], off: usize) -> Option<u32> {
    let b = image.get(off..off + 4)?;
    let hw1 = u16::from_le_bytes([b[0], b[1]]);
    let hw2 = u16::from_le_bytes([b[2], b[3]]);
    if (hw1 & 0xF800) != 0xF000 || (hw2 & 0xD000) != 0xD000 {
        return None;
    }
    let s = ((hw1 >> 10) & 1) as u32;
    let imm10 = (hw1 & 0x3FF) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let imm11 = (hw2 & 0x7FF) as u32;
    let i1 = (!(j1 ^ s)) & 1;
    let i2 = (!(j2 ^ s)) & 1;
    let mut imm = (imm11 | (imm10 << 11) | (i2 << 21) | (i1 << 22) | (s << 23)) << 1;
    if imm & (1 << 24) != 0 {
        imm |= !0u32 << 25;
    }
    Some((off as u32).wrapping_add(4).wrapping_add(imm))
}

/// Encode a Thumb `BL` at file offset `site` that calls absolute target `target`
/// (Thumb bit is implicit; pass the even entry address). Returns the 4 bytes, or
/// `None` if `target` is out of `BL` range (±16 MiB).
pub fn encode_bl(site: usize, target: u32) -> Option<[u8; 4]> {
    let pc = (site as u32).wrapping_add(4);
    let off = (target.wrapping_sub(pc)) as i32;
    if !(-(1 << 24)..(1 << 24)).contains(&off) || off & 1 != 0 {
        return None;
    }
    let imm = (off >> 1) as u32 & 0x00ff_ffff;
    let s = (imm >> 23) & 1;
    let i1 = (imm >> 22) & 1;
    let i2 = (imm >> 21) & 1;
    let imm10 = (imm >> 11) & 0x3ff;
    let imm11 = imm & 0x7ff;
    let j1 = (!(i1 ^ s)) & 1;
    let j2 = (!(i2 ^ s)) & 1;
    let hw1 = 0xF000 | (s << 10) as u16 | imm10 as u16;
    let hw2 = 0xD000 | (j1 << 13) as u16 | (j2 << 11) as u16 | imm11 as u16;
    let mut out = [0u8; 4];
    out[0..2].copy_from_slice(&hw1.to_le_bytes());
    out[2..4].copy_from_slice(&hw2.to_le_bytes());
    Some(out)
}

/// Every file offset holding a Thumb `BL` whose target is `target` (Thumb bit
/// ignored). These are the direct call sites that reach a handler — the thing to
/// redirect when a firmware dispatches by hardcoded call rather than a table.
pub fn find_bl_sites(image: &[u8], target: u32) -> Vec<usize> {
    let want = target & !1;
    (0..image.len().saturating_sub(4))
        .step_by(2)
        .filter(|&off| decode_bl(image, off).map(|t| t & !1) == Some(want))
        .collect()
}

// --- internal matchers (the actual scans behind `find`) ---

fn find_bytes(image: &[u8], pat: &[u8], start: usize) -> Option<usize> {
    if pat.is_empty() || start >= image.len() {
        return None;
    }
    image[start..]
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| p + start)
}

fn find_free_run(image: &[u8], n: usize, start: usize) -> Option<usize> {
    if n == 0 {
        return Some(start.min(image.len()));
    }
    let mut run = 0usize;
    for (i, &b) in image.iter().enumerate().skip(start) {
        if b == 0xFF {
            run += 1;
            if run >= n {
                return Some(i + 1 - n);
            }
        } else {
            run = 0;
        }
    }
    None
}

#[cfg(test)]
#[path = "thumb_tests.rs"]
mod tests;
