//! Read-only live probe: map which drive offsets are readable BEFORE vs AFTER
//! the `unlock_all_reads` command (`3C 02 F1`), to prove the broad-read unlock.
//! Usage: cargo run --example read_map_probe -- <selector>
//! Issues ONLY reads (READ BUFFER 0x3C). No writes, no kernel mode.

use anyhow::Result;
use freemkv_flash::platform::{open, ScsiDevice};

/// Vendor firmware read: READ BUFFER mode 2, buffer-id 0xB0, 24-bit offset, len.
fn read_region(dev: &mut dyn ScsiDevice, off: u32, n: usize) -> Result<Vec<u8>> {
    let cdb = [
        0x3c,
        0x02,
        0xb0,
        (off >> 16) as u8,
        (off >> 8) as u8,
        off as u8,
        0,
        0,
        n as u8,
        0,
    ];
    dev.command_in(&cdb, n)
}

/// The real `unlock_all_reads` from the 0.9.2/backup code: WRITE BUFFER mode 2,
/// buffer-id 0x41, magic `A5 AA AA` ("enter Pioneer firmware read service").
fn unlock_all_reads(dev: &mut dyn ScsiDevice) -> Result<()> {
    let cdb = [0x3b, 0x02, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0];
    dev.command_out(&cdb, &[])
}

fn classify(r: &Result<Vec<u8>>, n: usize) -> String {
    match r {
        Ok(d) if d.len() != n => format!("SHORT({}/{n})", d.len()),
        Ok(d) if d.iter().all(|&b| b == 0x00) => "ok:zeros".into(),
        Ok(d) if d.iter().all(|&b| b == 0xff) => "ok:0xFF".into(),
        Ok(d) => format!("ok:data {:02x}{:02x}{:02x}{:02x}..", d[0], d[1], d[2], d[3]),
        Err(e) => {
            let m = format!("{e:#}");
            format!("BLOCKED({})", m.chars().take(40).collect::<String>())
        }
    }
}

fn main() -> Result<()> {
    let selector = std::env::args()
        .nth(1)
        .expect("usage: read_map_probe <selector>");
    let n = 0x40usize;
    // Probe grid across the runtime address space (coarse).
    let offsets: Vec<u32> = (0..=0x60).map(|i| i * 0x10000).collect(); // 0..0x600000 step 64K

    // Open FRESH (locked state) and probe WITHOUT unlock first.
    let mut dev = open(&selector, false)?;
    println!("== LOCKED (no unlock_all_reads issued) ==");
    let mut before = Vec::new();
    for &off in &offsets {
        let r = read_region(dev.as_mut(), off, n);
        before.push((off, classify(&r, n)));
    }

    // Issue unlock_all_reads, then re-probe the same offsets.
    unlock_all_reads(dev.as_mut())
        .map_err(|e| eprintln!("unlock_all_reads err: {e:#}"))
        .ok();
    println!("unlock_all_reads (3B 02 41 A5 AA AA) issued");
    println!("== AFTER unlock_all_reads ==");
    let mut after = Vec::new();
    for &off in &offsets {
        let r = read_region(dev.as_mut(), off, n);
        after.push((off, classify(&r, n)));
    }

    println!(
        "\n{:<10}  {:<32}  {:<32}  changed?",
        "offset", "BEFORE", "AFTER"
    );
    let mut changed = 0;
    for ((off, b), (_, a)) in before.iter().zip(after.iter()) {
        let diff = if b != a {
            changed += 1;
            "<-- CHANGED"
        } else {
            ""
        };
        println!("{off:#08x}  {b:<32}  {a:<32}  {diff}");
    }
    println!(
        "\n{changed} of {} offsets changed after unlock_all_reads.",
        offsets.len()
    );
    Ok(())
}
