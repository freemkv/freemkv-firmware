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

fn main() -> Result<()> {
    let sel = std::env::args()
        .nth(1)
        .expect("usage: disc_probe <selector>");
    let mut dev = open(&sel, false)?;
    println!("device: {}", dev.describe());

    // GET CONFIGURATION (0x46), RT=current: the drive's current media profile.
    match dev.command_in(&[0x46, 0x01, 0, 0, 0, 0, 0, 0x00, 0x20, 0], 0x20) {
        Ok(d) if d.len() >= 8 => {
            let current = u16::from_be_bytes([d[6], d[7]]);
            println!(
                "current profile: 0x{current:04x} ({})",
                profile_name(current)
            );
        }
        Ok(d) => println!("GET CONFIGURATION short: {} bytes", d.len()),
        Err(e) => println!("GET CONFIGURATION failed: {e:#}"),
    }

    // READ CAPACITY (0x25): last readable LBA and block size.
    let mut last_lba = 0u32;
    match dev.command_in(&[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8) {
        Ok(d) if d.len() >= 8 => {
            last_lba = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
            let block = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
            println!(
                "capacity: last LBA {last_lba} ({} blocks), block {block} bytes, ~{:.2} GiB",
                last_lba + 1,
                (u64::from(last_lba) + 1) * u64::from(block) / (1 << 30)
            );
        }
        Ok(_) => println!("READ CAPACITY short"),
        Err(e) => println!("READ CAPACITY failed: {e:#}"),
    }

    // READ(12) (0xA8) one 2048-byte sector at the given LBA. The real proof: can
    // the drive hand us user data off this disc on its current firmware?
    let read12 = |lba: u32| {
        let b = lba.to_be_bytes();
        [0xA8, 0, b[0], b[1], b[2], b[3], 0, 0, 0, 1, 0, 0]
    };
    // LBA 256 holds the UDF Anchor Volume Descriptor Pointer — filesystem
    // metadata, unencrypted, so a real read returns a non-zero `AVDP`/tag here.
    for (label, lba) in [
        ("sector 0 (start)", 0),
        ("UDF anchor", 256),
        ("high sector", last_lba.saturating_sub(16)),
    ] {
        match dev.command_in(&read12(lba), 2048) {
            Ok(d) => hexdump(&format!("READ(12) {label} @ LBA {lba}"), &d, 64),
            Err(e) => println!("READ(12) {label} @ LBA {lba} FAILED: {e:#}"),
        }
    }

    // READ DISC STRUCTURE (0xAD) BD format 0x00 (Disc Information / DI). UHD
    // media carry distinct DI contents; a stock drive may refuse this on UHD.
    match dev.command_in(&[0xAD, 0x01, 0, 0, 0, 0, 0, 0x00, 0x00, 0x20, 0, 0], 0x20) {
        Ok(d) => hexdump("READ DISC STRUCTURE (BD DI)", &d, 32),
        Err(e) => println!("READ DISC STRUCTURE (BD DI) failed: {e:#}"),
    }
    Ok(())
}
