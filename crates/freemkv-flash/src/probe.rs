//! READ-ONLY flash-read probe (experimental, MediaTek only).
//!
//! Answers one empirical question on a live drive: **which `READ BUFFER`
//! (`0x3C`) channel — `(mode, buffer-id)` — reads the SPI flash, can it read
//! offset `0x0` (the encrypted boot block), what is the largest chunk it
//! accepts, and can it dump the whole `0x0..0x200000` range?**
//!
//! Two channels are known to matter:
//! * `mode 0x06` / buffer `0x00` — our channel; proven to return real flash
//!   content (`"MT1959 Boot"` at `0x3000`, the descriptor at `0x1EC000`).
//! * `mode 0x01` / buffer `0x44` — the vendor tool's channel; observed reading
//!   only drive RAM/registers in tiny (<=64 B) peeks, offset `0x0` returning a
//!   status header, not flash. Included so we can confirm/deny on hardware.
//!
//! This module issues **only** `READ BUFFER` (`0x3C`) — never a write. Worst
//! case is a rejected read. The flash channel is identified by the boot banner
//! signature `MT19` at `0x3000`, then chunk-size-probed and swept.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::drive::mtk::{cdb_read_buffer, CHUNK, IMAGE_SIZE};
use crate::drive::FullImage;
use crate::platform::ScsiDevice;

/// A `(mode, buffer-id)` READ BUFFER channel to try.
struct Channel {
    mode: u8,
    buffer_id: u8,
    label: &'static str,
}

const CHANNELS: &[Channel] = &[
    Channel {
        mode: 0x06,
        buffer_id: 0x00,
        label: "mode6/buf00 (flash, current tool)",
    },
    Channel {
        mode: 0x01,
        buffer_id: 0x44,
        label: "mode1/buf44 (vendor RAM/reg channel)",
    },
    Channel {
        mode: 0x02,
        buffer_id: 0x00,
        label: "mode2/buf00",
    },
];

/// The flash boot banner at `0x3000` starts with these bytes ("MT19"). A channel
/// whose `0x3000` read starts with this is reading the real SPI flash.
const FLASH_SIG: &[u8] = b"MT19";
/// Offset of the boot banner (known-good flash read; shared with `freemkv_chipset`).
const BANNER_OFF: u32 = freemkv_chipset::BANNER_OFFSET as u32;
/// Offset of the ASCII descriptor (known-good flash read; shared with `freemkv_chipset`).
const DESCR_OFF: u32 = freemkv_chipset::DESCRIPTOR_OFFSET as u32;
/// Candidate chunk sizes to probe, largest-first (bytes).
const CHUNK_LADDER: &[usize] = &[0x10000, 0x8000, 0x4000, 0x1000, 0x400, 0x40];

fn read_at(dev: &mut dyn ScsiDevice, ch: &Channel, off: u32, len: u32) -> Result<Vec<u8>> {
    let cdb = cdb_read_buffer(ch.mode, ch.buffer_id, off, len);
    dev.command_in(&cdb, len as usize)
}

fn rd(dev: &mut dyn ScsiDevice, mode: u8, buf: u8, off: u32, len: u32) -> Result<Vec<u8>> {
    dev.command_in(&cdb_read_buffer(mode, buf, off, len), len as usize)
}

/// Classify a read result for the map.
enum Cls {
    Err,
    Zero,
    Data,
}

fn classify(r: &Result<Vec<u8>>) -> Cls {
    match r {
        Err(_) => Cls::Err,
        Ok(v) if v.is_empty() || v.iter().all(|&b| b == 0) => Cls::Zero,
        Ok(_) => Cls::Data,
    }
}

/// Drive identity passed into `map_fw` for the map header.
pub struct MapIdent<'a> {
    /// INQUIRY vendor id (e.g. `HL-DT-ST`).
    pub vendor: &'a str,
    /// INQUIRY product id (e.g. `BD-RE BU40N`).
    pub product: &'a str,
    /// INQUIRY revision (e.g. `1.03`).
    pub revision: &'a str,
    /// Boot banner read from flash, if available.
    pub banner: Option<&'a str>,
}

/// One standard channel probe: `(mode, buffer-id, offset, len, label)`.
const STANDARD_PROBES: &[(u8, u8, u32, u32, &str)] = &[
    (6, 0x00, 0x003000, 0x20, "flash: boot banner / vectors"),
    (6, 0x00, 0x1EC000, 0x40, "flash: ASCII descriptor"),
    (
        6,
        0x00,
        0x1F0000,
        0x40,
        "flash: per-unit calibration (head)",
    ),
    (1, 0x44, 0x003000, 0x40, "RAM: unlock/LibreDrive marker"),
    (2, 0x80, 0x100000, 0x40, "table: command descriptors"),
    (5, 0x20, 0x100000, 0x40, "mfg: calibration/serial string"),
    (7, 0x00, 0x100000, 0x20, "firmware version/date block"),
];

fn ascii_of(v: &[u8]) -> String {
    v.iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// JSON-escape a string.
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

// SCSI command-descriptor (opcode) table: on-flash chained 8-byte records {u32
// handler (LE, low bit=Thumb), u8 opcode, u8 flags, u16 rsv}; flags 0x03 ends a
// segment, 0x04 chains. Head DETECTED not hardcoded; parsed from image bytes.

/// File-offset window the table is searched within.
const CMD_SCAN_START: usize = 0x140000;
/// End of the search window (exclusive).
const CMD_SCAN_END: usize = 0x160000;
/// Minimum contiguous plausible-record run to accept as a table segment.
const CMD_MIN_RUN: usize = 6;
/// Loop guard: max records walked across all segments.
const CMD_MAX_ITERS: usize = 200_000;

/// A plausible `flags` byte for an 8-byte command record.
fn plausible_flags(flags: u8) -> bool {
    matches!(
        flags,
        0x00 | 0x01 | 0x02 | 0x07 | 0x08 | 0x80 | 0x87 | 0x03 | 0x04
    )
}

/// A plausible handler pointer (handlers are memory-mapped, up to ~0x01FE_xxxx).
fn plausible_handler(ptr: u32) -> bool {
    ptr == 0 || ptr < 0x0200_0000
}

/// Decode the 8-byte record at file offset `off`: `(handler_ptr, opcode, flags,
/// reserved)`. `None` if the record would run past the image.
fn parse_record(image: &[u8], off: usize) -> Option<(u32, u8, u8, u16)> {
    let r = image.get(off..off + 8)?;
    let handler = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
    let reserved = u16::from_le_bytes([r[6], r[7]]);
    Some((handler, r[4], r[5], reserved))
}

/// A record is a valid table entry if flags and handler are plausible and the
/// reserved field is zero.
fn record_valid(handler: u32, flags: u8, reserved: u16) -> bool {
    reserved == 0 && plausible_flags(flags) && plausible_handler(handler)
}

/// True if a valid 8-byte record starts at file offset `off`.
fn record_valid_at(image: &[u8], off: usize) -> bool {
    match parse_record(image, off) {
        Some((h, _op, fl, res)) => record_valid(h, fl, res),
        None => false,
    }
}

/// One collected (non-marker) command record.
#[derive(Debug, Clone, Copy)]
struct CmdRecord {
    handler_ptr: u32,
    opcode: u8,
}

/// Walk the search window collecting every command record from all table
/// segments. A "segment" is a maximal contiguous run of >= [`CMD_MIN_RUN`] valid
/// 8-byte records; per-disc-profile segments are laid out as separate runs, and
/// within a run the `0x03` (terminator) and `0x04` (chain-to-next) records are
/// markers that delimit sub-segments — both are skipped, never collected. The
/// table head drifts per build, so nothing is hardcoded: the whole window is
/// swept. Guarded against runaways by [`CMD_MAX_ITERS`]. Returns
/// `(records, head_offset, segment_count)` where `head_offset` is the lowest
/// segment start.
fn walk_segments(image: &[u8]) -> (Vec<CmdRecord>, Option<usize>, usize) {
    let end = CMD_SCAN_END.min(image.len());
    let mut records: Vec<CmdRecord> = Vec::new();
    let mut head: Option<usize> = None;
    let mut segment_count = 0usize;
    let mut iters = 0usize;
    let mut off = CMD_SCAN_START;
    while off + 8 <= end {
        if !record_valid_at(image, off) {
            off += 4;
            continue;
        }
        // Extend a maximal contiguous run of valid records.
        let start = off;
        let mut run = 0usize;
        let mut p = off;
        while p + 8 <= image.len() && record_valid_at(image, p) {
            iters += 1;
            if iters > CMD_MAX_ITERS {
                break;
            }
            run += 1;
            p += 8;
        }
        if run >= CMD_MIN_RUN {
            segment_count += 1;
            head.get_or_insert(start);
            let mut q = start;
            for _ in 0..run {
                if let Some((h, op, fl, _res)) = parse_record(image, q) {
                    // Skip segment markers (terminator / chain); collect commands.
                    if fl != 0x03 && fl != 0x04 {
                        records.push(CmdRecord {
                            handler_ptr: h,
                            opcode: op,
                        });
                    }
                }
                q += 8;
            }
        }
        if iters > CMD_MAX_ITERS {
            break;
        }
        off = p.max(start + 8); // jump past the run (or advance if run < min)
    }
    (records, head, segment_count)
}

/// SCSI mnemonic for a known opcode, else `""` (vendor / unknown).
fn scsi_opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "TEST UNIT READY",
        0x12 => "INQUIRY",
        0x1B => "START/STOP",
        0x25 => "READ CAPACITY",
        0x28 => "READ10",
        0xA8 => "READ12",
        0xAD => "READ DISC STRUCTURE",
        0x3B => "WRITE BUFFER",
        0x3C => "READ BUFFER",
        0x55 => "MODE SELECT",
        0x5A => "MODE SENSE",
        0xA3 => "SEND KEY",
        0xA4 => "REPORT KEY",
        0xBE => "READ CD",
        _ => "",
    }
}

/// `"vendor"` for the 0xC0-0xFF vendor range (unless a known standard code),
/// else `"standard"`.
fn opcode_range(op: u8) -> &'static str {
    if op < 0xC0 || !scsi_opcode_name(op).is_empty() {
        "standard"
    } else {
        "vendor"
    }
}

/// Aggregated info for one distinct opcode.
struct OpcodeEntry {
    opcode: u8,
    record_count: usize,
    handlers: Vec<u32>,
}

/// Result of analyzing the on-flash command table.
struct CommandTable {
    found: bool,
    head_offset: usize,
    segment_count: usize,
    record_count: usize,
    /// Distinct opcodes, sorted ascending.
    opcodes: Vec<OpcodeEntry>,
}

impl CommandTable {
    fn not_found() -> Self {
        Self {
            found: false,
            head_offset: 0,
            segment_count: 0,
            record_count: 0,
            opcodes: Vec::new(),
        }
    }

    /// Which 0xC0-0xFF vendor opcodes are USED in this image.
    fn vendor_used(&self) -> Vec<u8> {
        self.opcodes
            .iter()
            .map(|e| e.opcode)
            .filter(|&op| op >= 0xC0)
            .collect()
    }

    /// Which 0xC0-0xFF vendor opcodes are FREE (not present) in this image.
    fn vendor_free(&self) -> Vec<u8> {
        let used: BTreeSet<u8> = self.vendor_used().into_iter().collect();
        (0xC0u8..=0xFF).filter(|op| !used.contains(op)).collect()
    }

    fn standard_count(&self) -> usize {
        self.opcodes
            .iter()
            .filter(|e| opcode_range(e.opcode) == "standard")
            .count()
    }

    fn vendor_count(&self) -> usize {
        self.opcodes.len() - self.standard_count()
    }
}

/// Detect and parse the drive's SCSI command table from the image bytes.
/// GRACEFUL: returns `CommandTable::not_found()` on an opaque / non-MTK image.
fn analyze_command_table(image: &[u8]) -> CommandTable {
    let (records, head, segment_count) = walk_segments(image);
    let (Some(head), false) = (head, records.is_empty()) else {
        return CommandTable::not_found();
    };
    // Aggregate by opcode: record count + distinct handler set.
    let mut by_op: BTreeMap<u8, (usize, BTreeSet<u32>)> = BTreeMap::new();
    for r in &records {
        let e = by_op
            .entry(r.opcode)
            .or_insert_with(|| (0, BTreeSet::new()));
        e.0 += 1;
        e.1.insert(r.handler_ptr);
    }
    let opcodes = by_op
        .into_iter()
        .map(|(opcode, (record_count, handlers))| OpcodeEntry {
            opcode,
            record_count,
            handlers: handlers.into_iter().collect(),
        })
        .collect();
    CommandTable {
        found: true,
        head_offset: head,
        segment_count,
        record_count: records.len(),
        opcodes,
    }
}

/// Emit the `command_table` object (and self-describing `drive`) into the map
/// JSON. Rendered as a trailing top-level member (caller closes the object).
fn command_table_json(ct: &CommandTable, product: &str, revision: &str) -> String {
    let mut j = String::new();
    j.push_str(&format!(
        "  \"drive\": {{ \"product\": {}, \"revision\": {} }},\n",
        jstr(product),
        jstr(revision)
    ));
    if !ct.found {
        j.push_str("  \"command_table\": { \"found\": false, \"note\": \"command table not found (opaque or non-MTK image)\" }\n");
        return j;
    }
    j.push_str("  \"command_table\": {\n");
    j.push_str("    \"found\": true,\n");
    j.push_str(&format!(
        "    \"head_offset\": \"0x{:06X}\",\n",
        ct.head_offset
    ));
    j.push_str(&format!("    \"segment_count\": {},\n", ct.segment_count));
    j.push_str(&format!("    \"record_count\": {},\n", ct.record_count));
    j.push_str(&format!(
        "    \"distinct_opcodes\": {},\n",
        ct.opcodes.len()
    ));
    j.push_str("    \"opcodes\": [\n");
    for (i, e) in ct.opcodes.iter().enumerate() {
        let handlers: String = e
            .handlers
            .iter()
            .map(|h| format!("\"0x{h:06X}\""))
            .collect::<Vec<_>>()
            .join(", ");
        j.push_str(&format!(
            "      {{ \"opcode\": \"0x{:02X}\", \"name\": {}, \"range\": {}, \"record_count\": {}, \"handlers\": [{}] }}{}\n",
            e.opcode,
            jstr(scsi_opcode_name(e.opcode)),
            jstr(opcode_range(e.opcode)),
            e.record_count,
            handlers,
            if i + 1 < ct.opcodes.len() { "," } else { "" }
        ));
    }
    j.push_str("    ],\n");
    let used: String = ct
        .vendor_used()
        .iter()
        .map(|op| format!("\"0x{op:02X}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let free: String = ct
        .vendor_free()
        .iter()
        .map(|op| format!("\"0x{op:02X}\""))
        .collect::<Vec<_>>()
        .join(", ");
    j.push_str(&format!(
        "    \"vendor_opcodes\": {{ \"used\": [{used}], \"free\": [{free}] }}\n"
    ));
    j.push_str("  }\n");
    j
}

/// Emit the human-readable command-table section into the map Markdown, framed
/// as a capability statement tied to the drive identity.
fn command_table_md(ct: &CommandTable, product: &str, revision: &str) -> String {
    let mut m = String::new();
    m.push_str("\n## SCSI command table\n\n");
    if !ct.found {
        m.push_str("_command table not found (opaque or non-MTK image)_\n");
        return m;
    }
    m.push_str(&format!(
        "Firmware {product} {revision} supports {} SCSI commands ({} standard, {} vendor).\n\n",
        ct.opcodes.len(),
        ct.standard_count(),
        ct.vendor_count()
    ));
    m.push_str(&format!(
        "Table head `0x{:06X}`, {} segment(s), {} records.\n\n",
        ct.head_offset, ct.segment_count, ct.record_count
    ));

    let render_rows = |m: &mut String, entries: &[&OpcodeEntry]| {
        m.push_str("| opcode | name | range | #records | handlers |\n|---|---|---|---|---|\n");
        for e in entries {
            let handlers: String = e
                .handlers
                .iter()
                .map(|h| format!("`0x{h:06X}`"))
                .collect::<Vec<_>>()
                .join(", ");
            m.push_str(&format!(
                "| `0x{:02X}` | {} | {} | {} | {} |\n",
                e.opcode,
                scsi_opcode_name(e.opcode),
                opcode_range(e.opcode),
                e.record_count,
                handlers
            ));
        }
    };

    let standard: Vec<&OpcodeEntry> = ct
        .opcodes
        .iter()
        .filter(|e| opcode_range(e.opcode) == "standard")
        .collect();
    let vendor: Vec<&OpcodeEntry> = ct
        .opcodes
        .iter()
        .filter(|e| opcode_range(e.opcode) == "vendor")
        .collect();

    m.push_str("### Standard commands\n\n");
    render_rows(&mut m, &standard);
    m.push_str("\n### Vendor commands (0xC0-0xFF)\n\n");
    if vendor.is_empty() {
        m.push_str("_none present_\n");
    } else {
        render_rows(&mut m, &vendor);
    }
    let free: String = ct
        .vendor_free()
        .iter()
        .map(|op| format!("0x{op:02X}"))
        .collect::<Vec<_>>()
        .join(", ");
    m.push_str(&format!("\nFree vendor opcodes (available): {free}\n"));
    m
}

/// Build the firmware read-surface map from an ALREADY-READ full image: the
/// flash-window classification (derived from `image` + `err_gaps` — no re-read)
/// plus the decoded metadata channel probes. Returns `(json, md)` strings for
/// embedding in the `dump` tar. Read-only (only the metadata probes touch the
/// drive; `0x3C` only).
pub(crate) fn build_map(
    dev: &mut dyn ScsiDevice,
    ident: &MapIdent,
    image: &[u8],
    err_gaps: &[(usize, usize)],
) -> Result<(String, String)> {
    // ---- flash-window classification (from the single full-image read) --------
    let step = 0x1000usize;
    let in_gap = |off: usize| err_gaps.iter().any(|(s, e)| off >= *s && off < *e);
    let classify_block = |off: usize| -> &'static str {
        if in_gap(off) {
            "error"
        } else if image[off..(off + step).min(image.len())]
            .iter()
            .all(|&b| b == 0)
        {
            "zero"
        } else {
            "data"
        }
    };
    let mut windows: Vec<(u32, u32, &'static str)> = Vec::new();
    let mut run_start = 0u32;
    let mut run_name = classify_block(0);
    let mut off = step;
    while off < image.len() {
        let n = classify_block(off);
        if n != run_name {
            windows.push((run_start, off as u32, run_name));
            run_start = off as u32;
            run_name = n;
        }
        off += step;
    }
    windows.push((run_start, image.len() as u32, run_name));

    // ---- standard channel probes ---------------------------------------------
    struct Row {
        mode: u8,
        buf: u8,
        offset: u32,
        len: u32,
        label: &'static str,
        status: String,
        hex: String,
        ascii: String,
    }
    let mut rows = Vec::new();
    for &(mode, buf, offset, len, label) in STANDARD_PROBES {
        let (status, hex, ascii) = match rd(dev, mode, buf, offset, len) {
            Ok(v) if v.is_empty() || v.iter().all(|&b| b == 0) => {
                ("zero".to_string(), String::new(), String::new())
            }
            Ok(v) => ("ok".to_string(), hex_all(&v), ascii_of(&v)),
            Err(e) => (format!("error: {e}"), String::new(), String::new()),
        };
        rows.push(Row {
            mode,
            buf,
            offset,
            len,
            label,
            status,
            hex,
            ascii,
        });
    }

    // ---- emit JSON ------------------------------------------------------------
    let mut j = String::new();
    j.push_str("{\n");
    j.push_str(&format!("  \"device\": {},\n", jstr(&dev.describe())));
    j.push_str(&format!(
        "  \"inquiry\": {{ \"vendor\": {}, \"product\": {}, \"revision\": {}, \"banner\": {} }},\n",
        jstr(ident.vendor),
        jstr(ident.product),
        jstr(ident.revision),
        jstr(ident.banner.unwrap_or("")),
    ));
    j.push_str("  \"flash_windows\": [\n");
    for (i, (from, to, n)) in windows.iter().enumerate() {
        j.push_str(&format!(
            "    {{ \"from\": \"0x{from:06X}\", \"to\": \"0x{to:06X}\", \"state\": {} }}{}\n",
            jstr(n),
            if i + 1 < windows.len() { "," } else { "" }
        ));
    }
    j.push_str("  ],\n  \"channels\": [\n");
    for (i, r) in rows.iter().enumerate() {
        j.push_str(&format!(
            "    {{ \"mode\": {}, \"buf\": {}, \"offset\": \"0x{:06X}\", \"len\": {}, \"label\": {}, \"status\": {}, \"hex\": {}, \"ascii\": {} }}{}\n",
            r.mode, r.buf, r.offset, r.len, jstr(r.label), jstr(&r.status), jstr(&r.hex), jstr(&r.ascii),
            if i + 1 < rows.len() { "," } else { "" }
        ));
    }
    j.push_str("  ],\n");
    // ---- command-descriptor (opcode) table ------------------------------------
    let ct = analyze_command_table(image);
    j.push_str(&command_table_json(&ct, ident.product, ident.revision));
    j.push_str("}\n");

    // ---- emit Markdown --------------------------------------------------------
    let mut m = String::new();
    m.push_str(&format!(
        "# {} {} rev {} — READ BUFFER map\n\n",
        ident.vendor, ident.product, ident.revision
    ));
    if let Some(b) = ident.banner {
        m.push_str(&format!("Banner: `{b}`\n\n"));
    }
    m.push_str("Read-only (`READ BUFFER 0x3C`), sense-clean transport. Generated by `freemkv-flash dump`.\n\n");
    m.push_str("## Flash offset windows (`mode6/buf0`)\n\n| From | To | State |\n|---|---|---|\n");
    for (from, to, n) in &windows {
        m.push_str(&format!("| `0x{from:06X}` | `0x{to:06X}` | {n} |\n"));
    }
    m.push_str("\n## Channels\n\n| mode | buf | offset | status | ascii | hex |\n|---|---|---|---|---|---|\n");
    for r in &rows {
        m.push_str(&format!(
            "| {:02x} | {:02x} | `0x{:06X}` | {} | `{}` | `{}` |\n",
            r.mode,
            r.buf,
            r.offset,
            if r.status.starts_with("error") {
                "error"
            } else {
                &r.status
            },
            r.ascii,
            r.hex
        ));
    }
    m.push_str("\n_Labels_: ");
    for (i, (mode, buf, _, _, label)) in STANDARD_PROBES.iter().enumerate() {
        m.push_str(&format!(
            "{}`{mode:02x}/{buf:02x}` = {label}",
            if i > 0 { "; " } else { "" }
        ));
    }
    m.push('\n');
    m.push_str(&command_table_md(&ct, ident.product, ident.revision));

    Ok((j, m))
}

fn hex_all(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the full 2 MiB firmware image via the flash channel (`mode6/buf0`),
/// GRACEFUL: any region the drive doesn't map to READ BUFFER is filled with
/// `0xFF`. Returns `(image, readable_bytes, gaps)`. Read-only (`0x3C` only).
/// 4 KiB reads (~2.5 s for a fully-exposed image). Shared by `dump`.
pub(crate) fn read_full_image(dev: &mut dyn ScsiDevice) -> Result<FullImage> {
    let chunk = 0x1000usize;
    let mut image = Vec::with_capacity(IMAGE_SIZE);
    let mut readable = 0usize;
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut off = 0usize;
    while off < IMAGE_SIZE {
        let l = chunk.min(IMAGE_SIZE - off);
        match rd(dev, 6, 0, off as u32, l as u32) {
            Ok(v) if v.len() == l => {
                image.extend_from_slice(&v);
                readable += l;
            }
            _ => {
                image.extend(std::iter::repeat_n(0xFFu8, l));
                match gaps.last_mut() {
                    Some((_, end)) if *end == off => *end = off + l,
                    _ => gaps.push((off, off + l)),
                }
            }
        }
        off += l;
    }
    Ok((image, readable, gaps))
}

/// Single raw `READ BUFFER` via an explicit `(mode, buffer-id, offset, len)`, or
/// — with `dump` — sweep the whole 2 MiB via that channel and save it. Uses the
/// sense-clean transport (unlike `sg_raw`, which mishandles the `mode2` DMA
/// residual and returns 0 bytes). Read-only.
pub fn read_raw(
    dev: &mut dyn ScsiDevice,
    mode: u8,
    buf: u8,
    offset: u32,
    len: u32,
    dump: Option<&Path>,
) -> Result<()> {
    match dump {
        None => {
            let v = rd(dev, mode, buf, offset, len).with_context(|| {
                format!("read mode={mode:02x} buf={buf:02x} off=0x{offset:06X}")
            })?;
            println!(
                "mode={mode:02x} buf={buf:02x} off=0x{offset:06X} len=0x{len:X} -> {} bytes",
                v.len()
            );
            for (i, ch) in v.chunks(16).enumerate() {
                let hex: String = ch.iter().map(|b| format!("{b:02x} ")).collect();
                let asc: String = ch
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                println!("  {:06x}: {:<48} {asc}", offset as usize + i * 16, hex);
            }
        }
        Some(p) => {
            // GRACEFUL full dump: regions this channel can't expose are 0xFF-filled
            // and reported, never a hard failure. A partial dump is useful; the
            // summary states exactly what came back and what did not.
            let chunk = if len == 0 { 0x40usize } else { len as usize };
            let mut image = Vec::with_capacity(IMAGE_SIZE);
            let mut readable = 0usize;
            let mut gaps: Vec<(usize, usize)> = Vec::new();
            let mut off = 0usize;
            while off < IMAGE_SIZE {
                let l = chunk.min(IMAGE_SIZE - off);
                match rd(dev, mode, buf, off as u32, l as u32) {
                    Ok(v) if v.len() == l => {
                        image.extend_from_slice(&v);
                        readable += l;
                    }
                    // Not exposed / short read — fill and record a contiguous gap.
                    _ => {
                        image.extend(std::iter::repeat_n(0xFFu8, l));
                        match gaps.last_mut() {
                            Some((_, end)) if *end == off => *end = off + l,
                            _ => gaps.push((off, off + l)),
                        }
                    }
                }
                off += l;
            }
            std::fs::write(p, &image).with_context(|| format!("writing {}", p.display()))?;
            println!(
                "dumped {} bytes via mode={mode:02x}/buf={buf:02x} -> {}",
                image.len(),
                p.display()
            );
            println!(
                "  readable: {}   not-exposed (filled 0xFF): {}",
                crate::engine::human_size(readable),
                crate::engine::human_size(IMAGE_SIZE - readable)
            );
            for (s, e) in &gaps {
                println!(
                    "    gap 0x{s:06X}..0x{e:06X} ({} not readable on this channel)",
                    crate::engine::human_size(e - s)
                );
            }
            if gaps.is_empty() {
                println!("  (full coverage — every offset returned data)");
            }
            println!("sha256 {:x}", Sha256::digest(&image));
        }
    }
    Ok(())
}

/// Build a full `(mode × buffer-id × offset)` map of the READ BUFFER surface,
/// using the sense-clean transport (auto-drains sense, so one failed read does
/// not cascade). Issues only `READ BUFFER` (`0x3C`). Two parts:
///  1. channel scan — `mode 0..15 × buf 0..255` at a main-body offset (which we
///     cannot yet read) and a flash-window offset (control), reporting every
///     channel that returns real data;
///  2. flash-channel offset map — `mode6/buf0` across `0..0x200000`, compressed
///     into readable / zero / error runs.
pub fn read_map(dev: &mut dyn ScsiDevice, out: Option<&Path>) -> Result<()> {
    use std::fmt::Write as _;
    let mut log = String::new();
    macro_rules! line { ($($a:tt)*) => {{ let s = format!($($a)*); println!("{s}"); let _ = writeln!(log, "{s}"); }} }

    line!("device: {}", dev.describe());
    line!("READ-BUFFER MAP — issues only 0x3C; sense-clean transport.\n");

    // ---- Part 1: channel scan (mode x buf) at target + control offsets --------
    const MAIN: u32 = 0x100000; // main body — currently unreadable
    const FLASHWIN: u32 = 0x003000; // known flash window (banner)
    line!("== channel scan: mode 0..15 x buf 0..255 (len 0x40) ==");
    line!("   target 0x{MAIN:06X} (main body) + control 0x{FLASHWIN:06X} (flash window)");
    let mut hits = 0usize;
    for mode in 0u8..16 {
        for buf in 0u8..=255 {
            let at_main = rd(dev, mode, buf, MAIN, 0x40);
            if let Cls::Data = classify(&at_main) {
                let m = at_main.unwrap();
                // Is it offset-responsive (flash/RAM) or a fixed value?
                let at2 = rd(dev, mode, buf, MAIN + 0x1000, 0x40).ok();
                let responsive = at2.as_deref().map(|v| v != m.as_slice()).unwrap_or(false);
                // Does the same channel return the flash banner at 0x3000?
                let flashy = rd(dev, mode, buf, FLASHWIN, 0x20)
                    .map(|v| v.starts_with(FLASH_SIG))
                    .unwrap_or(false);
                let kind = if flashy {
                    "FLASH"
                } else if responsive {
                    "offset-responsive (flash/RAM)"
                } else {
                    "fixed value (register?)"
                };
                line!(
                    "  mode={mode:02x} buf={buf:02x} @MAIN DATA [{}]  {kind}",
                    head_hex(&m)
                );
                hits += 1;
            }
        }
    }
    if hits == 0 {
        line!("  no (mode,buf) returned real data at the main-body offset 0x{MAIN:06X}");
        line!("  => the main FW body is NOT exposed to any READ BUFFER channel on this firmware.");
    }

    // ---- Part 2: flash-channel offset map (mode6/buf0) ------------------------
    line!("\n== flash channel mode6/buf0 offset map (step 0x1000, len 0x10) ==");
    let step = 0x1000u32;
    let mut run_start = 0u32;
    let mut run_cls = classify(&rd(dev, 6, 0, 0, 0x10));
    let flush = |from: u32, to: u32, cls: &Cls, log: &mut String| {
        let tag = match cls {
            Cls::Err => "ERR ",
            Cls::Zero => "ZERO",
            Cls::Data => "DATA",
        };
        let s = format!("  0x{from:06X}..0x{to:06X}  {tag}");
        println!("{s}");
        let _ = writeln!(log, "{s}");
    };
    let mut off = step;
    while off < IMAGE_SIZE as u32 {
        let cls = classify(&rd(dev, 6, 0, off, 0x10));
        let same = matches!(
            (&cls, &run_cls),
            (Cls::Err, Cls::Err) | (Cls::Zero, Cls::Zero) | (Cls::Data, Cls::Data)
        );
        if !same {
            flush(run_start, off, &run_cls, &mut log);
            run_start = off;
            run_cls = cls;
        }
        off += step;
    }
    flush(run_start, IMAGE_SIZE as u32, &run_cls, &mut log);

    if let Some(p) = out {
        std::fs::write(p, log.as_bytes()).with_context(|| format!("writing {}", p.display()))?;
        println!("\nwrote map to {}", p.display());
    }
    Ok(())
}

fn head_hex(v: &[u8]) -> String {
    v.iter()
        .take(12)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Run the read probe. Issues only `READ BUFFER` (`0x3C`).
pub fn read_probe(dev: &mut dyn ScsiDevice, out: Option<&Path>) -> Result<()> {
    println!("device: {}", dev.describe());
    println!("READ-ONLY probe — issues only READ BUFFER (0x3C); no writes.\n");

    // Phase 1: which channel returns the flash signature at 0x3000?
    let mut flash_channel: Option<&Channel> = None;
    for ch in CHANNELS {
        print!(
            "channel {:<38} [3C {:02X} {:02X}] ",
            ch.label, ch.mode, ch.buffer_id
        );
        match read_at(dev, ch, BANNER_OFF, 0x20) {
            Ok(v) if v.starts_with(FLASH_SIG) => {
                println!("FLASH  0x3000=[{}]", head_hex(&v));
                if flash_channel.is_none() {
                    flash_channel = Some(ch);
                }
            }
            Ok(v) => println!("read OK but not flash  0x3000=[{}]", head_hex(&v)),
            Err(e) => println!("FAIL  {e}"),
        }
    }
    println!();

    let Some(ch) = flash_channel else {
        println!("RESULT: no channel returned the flash signature at 0x3000 — cannot dump.");
        return Ok(());
    };
    println!("flash channel: {}\n", ch.label);

    // Phase 2: sanity — second known-good flash offset.
    match read_at(dev, ch, DESCR_OFF, 0x40) {
        Ok(v) => println!("  0x1EC000 descriptor: [{}]", head_hex(&v)),
        Err(e) => println!("  0x1EC000 descriptor: FAIL {e}"),
    }

    // Phase 3: can it read the boot block at 0x0? (the real unknown)
    let zero_ok = match read_at(dev, ch, 0x000000, 0x40) {
        Ok(v) => {
            println!("  0x000000 boot block: OK   [{}]", head_hex(&v));
            true
        }
        Err(e) => {
            println!("  0x000000 boot block: FAIL {e}");
            false
        }
    };

    // Phase 4: largest accepted chunk (probe at a mid offset, largest-first).
    let mut chunk = 0usize;
    for &c in CHUNK_LADDER {
        if 0x100000 + c > IMAGE_SIZE {
            continue;
        }
        if read_at(dev, ch, 0x100000, c as u32).is_ok() {
            chunk = c;
            break;
        }
    }
    if chunk == 0 {
        chunk = 0x40;
    }
    println!("  max chunk accepted: {chunk} B (0x{chunk:X})\n");

    if !zero_ok {
        println!("RESULT: flash readable BUT offset 0x0 rejects — a full verbatim dump is");
        println!("        blocked at the boot block. (Region reads still work.) Pivot needed");
        println!("        for the encrypted boot block; see READ_BUFFER_HANDLER research.");
        return Ok(());
    }

    // Phase 5: full sweep 0x0..0x200000.
    println!(
        "==> sweeping 0x0..0x200000 on {} (chunk {chunk} B)...",
        ch.label
    );
    let sweep = chunk.min(CHUNK.max(chunk));
    let mut image = Vec::with_capacity(IMAGE_SIZE);
    let mut offset = 0usize;
    while offset < IMAGE_SIZE {
        let len = sweep.min(IMAGE_SIZE - offset);
        match read_at(dev, ch, offset as u32, len as u32) {
            Ok(v) if v.len() == len => image.extend_from_slice(&v),
            Ok(v) => bail!(
                "sweep stopped at 0x{offset:06X}: short read ({} of {len} B); \
                 0x{offset:X} of 0x200000 read before the cap",
                v.len()
            ),
            Err(e) => bail!(
                "sweep stopped at 0x{offset:06X} (0x{offset:X} of 0x200000 read OK first): {e}"
            ),
        }
        offset += len;
    }

    let digest = Sha256::digest(&image);
    println!("\nRESULT: FULL 2 MiB READ OK — {} bytes", image.len());
    println!("        sha256 {digest:x}");
    if let Some(p) = out {
        std::fs::write(p, &image).with_context(|| format!("writing {}", p.display()))?;
        println!("        wrote {}", p.display());
    } else {
        println!("        (re-run with -o <file> to save the image)");
    }
    Ok(())
}

#[cfg(test)]
mod cmd_table_tests {
    use super::*;

    /// Encode one 8-byte command record.
    fn rec(handler: u32, opcode: u8, flags: u8) -> [u8; 8] {
        let mut r = [0u8; 8];
        r[0..4].copy_from_slice(&handler.to_le_bytes());
        r[4] = opcode;
        r[5] = flags;
        // reserved (r[6..8]) stays zero
        r
    }

    /// Build a synthetic image with a single command segment at `head`, isolated
    /// by 0xFF fill so detection cannot latch onto surrounding bytes.
    fn synthetic(head: usize, recs: &[[u8; 8]]) -> Vec<u8> {
        let mut img = vec![0xFFu8; head + recs.len() * 8 + 0x100];
        let mut p = head;
        for r in recs {
            img[p..p + 8].copy_from_slice(r);
            p += 8;
        }
        img
    }

    #[test]
    fn parses_opcodes_head_and_counts() {
        let head = 0x150000;
        // Six real records incl. INQUIRY (0x12) and a vendor opcode (0xC0),
        // then a segment terminator.
        let recs = [
            rec(0x0001_AB10 | 1, 0x00, 0x01), // TEST UNIT READY (thumb bit set)
            rec(0x0001_AB20 | 1, 0x12, 0x01), // INQUIRY
            rec(0x0001_AB30 | 1, 0x28, 0x01), // READ10
            rec(0x0001_AB40 | 1, 0xA8, 0x01), // READ12
            rec(0x0001_AB50 | 1, 0x3C, 0x01), // READ BUFFER
            rec(0x0001_AB60 | 1, 0xC0, 0x01), // vendor
            rec(0x0000_0000, 0x00, 0x03),     // terminator
        ];
        let img = synthetic(head, &recs);

        let ct = analyze_command_table(&img);
        assert!(ct.found);
        assert_eq!(ct.head_offset, head);
        assert_eq!(ct.segment_count, 1);
        assert_eq!(ct.record_count, 6);
        assert_eq!(ct.opcodes.len(), 6);

        // 0x12 maps to INQUIRY, standard range.
        let inq = ct.opcodes.iter().find(|e| e.opcode == 0x12).unwrap();
        assert_eq!(scsi_opcode_name(inq.opcode), "INQUIRY");
        assert_eq!(opcode_range(inq.opcode), "standard");

        // 0xC0 is a vendor opcode with a blank name.
        let v = ct.opcodes.iter().find(|e| e.opcode == 0xC0).unwrap();
        assert_eq!(scsi_opcode_name(v.opcode), "");
        assert_eq!(opcode_range(v.opcode), "vendor");

        // Vendor 0xC0 used; 0xDE free.
        assert!(ct.vendor_used().contains(&0xC0));
        assert!(ct.vendor_free().contains(&0xDE));
        assert!(!ct.vendor_free().contains(&0xC0));
    }

    #[test]
    fn recurring_opcode_across_segments() {
        // Two separate segments (per-disc-profile), each isolated by a 0xFF gap,
        // each carrying INQUIRY (0x12) with a DIFFERENT handler. The parser must
        // sweep both and merge them into one opcode entry with two handlers.
        let head = 0x148000;
        let seg2 = 0x149000;
        let mut img = vec![0xFFu8; 0x14A000];
        let seg1 = [
            rec(0x0001_0000 | 1, 0x12, 0x02), // INQUIRY, handler A
            rec(0x0001_0008 | 1, 0x28, 0x02),
            rec(0x0001_0010 | 1, 0xA8, 0x02),
            rec(0x0001_0018 | 1, 0x3C, 0x02),
            rec(0x0001_0020 | 1, 0xC0, 0x02),
            rec(0x0000_0000, 0x00, 0x03), // terminator
        ];
        let seg2_recs = [
            rec(0x0002_0000 | 1, 0x12, 0x02), // INQUIRY, handler B (recurrence)
            rec(0x0002_0008 | 1, 0x5A, 0x02),
            rec(0x0002_0010 | 1, 0xAD, 0x02),
            rec(0x0002_0018 | 1, 0xBE, 0x02),
            rec(0x0002_0020 | 1, 0xA3, 0x02),
            rec(0x0000_0000, 0x00, 0x03), // terminator
        ];
        for (base, recs) in [(head, &seg1), (seg2, &seg2_recs)] {
            let mut p = base;
            for r in recs {
                img[p..p + 8].copy_from_slice(r);
                p += 8;
            }
        }

        let ct = analyze_command_table(&img);
        assert!(ct.found);
        assert_eq!(ct.segment_count, 2);
        assert_eq!(ct.head_offset, head);
        // 0x12 seen once per segment, with two distinct handlers.
        let inq = ct.opcodes.iter().find(|e| e.opcode == 0x12).unwrap();
        assert_eq!(inq.record_count, 2);
        assert_eq!(inq.handlers.len(), 2);
        assert!(ct.vendor_used().contains(&0xC0));
    }

    #[test]
    fn opaque_image_is_graceful() {
        // Random-ish bytes with no plausible run: found=false, no panic.
        let img: Vec<u8> = (0..0x160000u32)
            .map(|i| (i.wrapping_mul(0x9E37)) as u8)
            .collect();
        let ct = analyze_command_table(&img);
        // Either not found, or if a short accidental run appears it must not panic;
        // the JSON/MD emitters must handle both.
        let _ = command_table_json(&ct, "P", "R");
        let _ = command_table_md(&ct, "P", "R");
        if !ct.found {
            let j = command_table_json(&ct, "P", "R");
            assert!(j.contains("\"found\": false"));
        }
    }

    #[test]
    fn real_image_opcode_table() {
        // Fixture path from the environment only (no owned path baked into this
        // public repo): `FREEMKV_KAT_BASE` = an OEM BU40N 1.00 image; unset skips.
        let Ok(path) = std::env::var("FREEMKV_KAT_BASE") else {
            eprintln!("skipping: FREEMKV_KAT_BASE unset (real firmware image)");
            return;
        };
        let Ok(img) = std::fs::read(&path) else {
            eprintln!("skipping: real firmware image not present at {path}");
            return;
        };
        let ct = analyze_command_table(&img);
        assert!(
            ct.found,
            "expected to find the command table in the real image"
        );
        assert!(
            (50..=100).contains(&ct.opcodes.len()),
            "expected ~74 distinct opcodes, got {}",
            ct.opcodes.len()
        );
        assert!(
            ct.vendor_free().contains(&0xDE),
            "expected vendor opcode 0xDE to be FREE in this image"
        );
    }
}
