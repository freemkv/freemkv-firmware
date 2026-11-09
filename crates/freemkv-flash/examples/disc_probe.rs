//! Read-only disc probe through our own SCSI transport (not the OS).
//!
//! This is the ground-truth media test for the firmware loop: it proves the
//! drive — on whatever firmware is loaded — actually sees and reads the disc.
//! macOS cannot read UHD at all, so a UHD before/after can only be measured
//! here, at the drive command level. Issues only reads; writes nothing.
//!
//! Usage: `disc_probe <selector>` (selector from `freemkv-flash list`).
use anyhow::Result;
use freemkv_flash::platform::open;

fn profile_name(code: u16) -> &'static str {
    match code {
        0x0008 => "CD-ROM",
        0x0010 => "DVD-ROM",
        0x0040 => "BD-ROM",
        0x0041 => "BD-R SRM",
        0x0043 => "BD-RE",
        _ => "other/unknown",
    }
}

fn hexdump(label: &str, d: &[u8], max: usize) {
    println!("{label} ({} bytes):", d.len());
    for (i, chunk) in d
        .iter()
        .take(max)
        .collect::<Vec<_>>()
        .chunks(16)
        .enumerate()
    {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let asc: String = chunk
            .iter()
            .map(|&&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("  {:04x}  {hex:<48} {asc}", i * 16);
    }
}

/// One probe step's result, kept for the end-of-run verdict so a stock-vs-
/// flashed before/after diffs at a glance.
enum Step {
    Ok(String),
    Zeros,
    Fail(String),
}

fn main() -> Result<()> {
    let sel = std::env::args()
        .nth(1)
        .expect("usage: disc_probe <selector>");
    let mut dev = open(&sel, false)?;
    println!("device: {}", dev.describe());
    let mut verdict: Vec<(&str, Step)> = Vec::new();

    // GET CONFIGURATION (0x46), RT=current: the drive's current media profile.
    let step = match dev.command_in(&[0x46, 0x01, 0, 0, 0, 0, 0, 0x00, 0x20, 0], 0x20) {
        Ok(d) if d.len() >= 8 => {
            let current = u16::from_be_bytes([d[6], d[7]]);
            let name = format!("0x{current:04x} ({})", profile_name(current));
            println!("current profile: {name}");
            Step::Ok(name)
        }
        Ok(d) => Step::Fail(format!("short: {} bytes", d.len())),
        Err(e) => Step::Fail(format!("{e:#}")),
    };
    if let Step::Fail(ref e) = step {
        println!("GET CONFIGURATION failed: {e}");
    }
    verdict.push(("media profile", step));

    // READ CAPACITY (0x25): last readable LBA and block size.
    let mut last_lba = 0u32;
    let step = match dev.command_in(&[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8) {
        Ok(d) if d.len() >= 8 => {
            last_lba = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
            let block = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
            let gib = (u64::from(last_lba) + 1) * u64::from(block) / (1 << 30);
            println!(
                "capacity: last LBA {last_lba} ({} blocks), block {block} bytes, ~{gib} GiB",
                last_lba + 1
            );
            Step::Ok(format!("~{gib} GiB"))
        }
        Ok(_) => Step::Fail("short".into()),
        Err(e) => Step::Fail(format!("{e:#}")),
    };
    verdict.push(("capacity", step));

    // READ(12) (0xA8) one 2048-byte sector. The real proof: can the drive hand
    // us data off this disc on its current firmware? Zeros on a commercial disc
    // are AACS-protected content; the UDF anchor (LBA 256) is unencrypted.
    let read12 = |lba: u32| {
        let b = lba.to_be_bytes();
        [0xA8, 0, b[0], b[1], b[2], b[3], 0, 0, 0, 1, 0, 0]
    };
    for (label, lba) in [
        ("sector 0 (start)", 0),
        ("UDF anchor", 256),
        ("high sector", last_lba.saturating_sub(16)),
    ] {
        let step = match dev.command_in(&read12(lba), 2048) {
            Ok(d) => {
                hexdump(&format!("READ(12) {label} @ LBA {lba}"), &d, 64);
                if d.iter().all(|&b| b == 0) {
                    Step::Zeros
                } else {
                    Step::Ok("data".into())
                }
            }
            Err(e) => {
                println!("READ(12) {label} @ LBA {lba} FAILED: {e:#}");
                Step::Fail(format!("{e:#}"))
            }
        };
        verdict.push((label, step));
    }

    // READ DISC STRUCTURE (0xAD) BD format 0x00 (Disc Information / DI). UHD
    // media carry distinct DI contents; a stock drive may refuse this on UHD.
    let step = match dev.command_in(&[0xAD, 0x01, 0, 0, 0, 0, 0, 0x00, 0x00, 0x20, 0, 0], 0x20) {
        Ok(d) => {
            hexdump("READ DISC STRUCTURE (BD DI)", &d, 32);
            // The DI unit identifier is three ASCII chars (e.g. "BDO" = BD-ROM).
            let id: String = d
                .get(12..15)
                .map_or(String::new(), |s| s.iter().map(|&b| b as char).collect());
            Step::Ok(format!("DI id {id:?}"))
        }
        Err(e) => {
            println!("READ DISC STRUCTURE (BD DI) failed: {e:#}");
            Step::Fail(format!("{e:#}"))
        }
    };
    verdict.push(("disc structure (DI)", step));

    // One-line-per-step verdict: a stock vs flashed run diffs here directly.
    // On a UHD disc a stock drive FAILs these; a working UHD conversion makes
    // them read, matching the BD control.
    println!("\n==== VERDICT ({}) ====", dev.describe());
    for (name, step) in &verdict {
        let (mark, detail) = match step {
            Step::Ok(d) => ("OK  ", d.as_str()),
            Step::Zeros => ("ZERO", "all zero (AACS-protected content, expected)"),
            Step::Fail(e) => ("FAIL", e.as_str()),
        };
        println!("  [{mark}] {name}: {detail}");
    }
    Ok(())
}
