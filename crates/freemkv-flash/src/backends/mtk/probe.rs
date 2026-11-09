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

use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::platform::ScsiDevice;
use mediatek_optical::cdb::{self, CHUNK};
use mediatek_optical::layout::IMAGE_SIZE;

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
    let cdb = cdb::read_buffer(ch.mode, ch.buffer_id, off, len);
    dev.command_in(&cdb, len as usize)
}

fn rd(dev: &mut dyn ScsiDevice, mode: u8, buf: u8, off: u32, len: u32) -> Result<Vec<u8>> {
    dev.command_in(&cdb::read_buffer(mode, buf, off, len), len as usize)
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

/// A full firmware read: `(image, readable byte count, unreadable (start, end)
/// gaps)`. Every offset the drive does not expose is filled and recorded.
pub type FullImage = (Vec<u8>, usize, Vec<(usize, usize)>);

/// Read the full 2 MiB firmware image via the flash channel (`mode6/buf0`),
/// GRACEFUL: any region the drive doesn't map to READ BUFFER is filled with
/// `0xFF`. Returns `(image, readable_bytes, gaps)`. Read-only (`0x3C` only).
/// 4 KiB reads (~2.5 s for a fully-exposed image). Shared by `dump`.
/// Retain evidence that every failed firmware read was an explicit unsupported
/// or invalid-field command response, rather than a connection/short-read error.
pub(crate) fn read_full_image_with_restriction(
    dev: &mut dyn ScsiDevice,
) -> Result<(FullImage, bool)> {
    const CHUNK: usize = 0x1000;
    const PIECE: usize = 0x200;
    // Stop splitting after this many consecutive dead chunks; resume at the next
    // readable chunk. Keeps a fully unreadable range to one command per chunk.
    const SPLIT_BUDGET: usize = 8;
    let mut image = Vec::with_capacity(IMAGE_SIZE);
    let mut readable = 0usize;
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut dead_chunks = 0usize;
    let mut off = 0usize;
    let mut progress = crate::style::Progress::new("reading drive memory", IMAGE_SIZE);
    let mut take = |off: usize, len: usize, data: Option<Vec<u8>>, image: &mut Vec<u8>| match data {
        Some(v) => {
            image.extend_from_slice(&v);
            readable += len;
        }
        None => {
            image.extend(std::iter::repeat_n(0xFFu8, len));
            match gaps.last_mut() {
                Some((_, end)) if *end == off => *end = off + len,
                _ => gaps.push((off, off + len)),
            }
        }
    };
    let mut rejected = false;
    let mut other_failure = false;
    let mut read_exact = |dev: &mut dyn ScsiDevice, off: usize, len: usize| match rd(
        dev, 6, 0, off as u32, len as u32,
    ) {
        Ok(bytes) if bytes.len() == len => Some(bytes),
        Err(error)
            if matches!(
                crate::platform::sense_triplet(&error),
                Some((5, 0x20 | 0x24, 0))
            ) =>
        {
            rejected = true;
            None
        }
        _ => {
            other_failure = true;
            None
        }
    };
    while off < IMAGE_SIZE {
        let l = CHUNK.min(IMAGE_SIZE - off);
        if let Some(v) = read_exact(dev, off, l) {
            dead_chunks = 0;
            take(off, l, Some(v), &mut image);
        } else if dead_chunks >= SPLIT_BUDGET {
            take(off, l, None, &mut image);
        } else {
            let mut any = false;
            for piece in (off..off + l).step_by(PIECE) {
                let data = read_exact(dev, piece, PIECE);
                any |= data.is_some();
                take(piece, PIECE, data, &mut image);
            }
            dead_chunks = if any { 0 } else { dead_chunks + 1 };
        }
        off += l;
        progress.set(off);
        crate::output::publish(crate::output::Event::Phase {
            phase: "reading",
            component: "filter.firmware",
            done: Some(off),
            total: Some(IMAGE_SIZE),
        });
    }
    Ok(((image, readable, gaps), rejected && !other_failure))
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
                crate::style::human_size(readable),
                crate::style::human_size(IMAGE_SIZE - readable)
            );
            for (s, e) in &gaps {
                println!(
                    "    gap 0x{s:06X}..0x{e:06X} ({} not readable on this channel)",
                    crate::style::human_size(e - s)
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
