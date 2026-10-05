//! SAFE live probe of vendor "kernel mode" (write unlock): runs ONLY the F3/F2
//! challenge-response handshake — NO 04/FF entry, NO 07 chunk, NO 05 finish — so
//! it performs NO firmware write. Proves on silicon that (a) the handshake
//! completes, and (b) kernel mode does NOT open protected reads (independence
//! from the read-unlock knock). Usage: cargo run --example kernel_mode_probe -- <selector>

use anyhow::Result;
use freemkv_flash::platform::{open, ScsiDevice};
use pioneer_optical as po;

fn lcg_step(state: &mut u32) -> u8 {
    *state = state.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
    (*state >> 16) as u8
}

/// Brute-force the 16-bit seed whose first 4 LCG bytes match the challenge.
fn recover_seed(sig: &[u8]) -> Option<u16> {
    (0u32..=0xFFFF).find_map(|v| {
        let mut s = v;
        if (0..4).all(|i| lcg_step(&mut s) == sig[i]) {
            Some(v as u16)
        } else {
            None
        }
    })
}

fn response_byte(seed: u16) -> u8 {
    let mut s = seed as u32;
    for _ in 0..po::KERNEL_CHALLENGE_LEN {
        lcg_step(&mut s);
    }
    !lcg_step(&mut s)
}

fn protected_read_ok(dev: &mut dyn ScsiDevice) -> bool {
    matches!(dev.command_in(&po::read_memory(0x010000, 0x40), 0x40), Ok(d) if d.len() == 0x40)
}

fn main() -> Result<()> {
    let sel = std::env::args()
        .nth(1)
        .expect("usage: kernel_mode_probe <selector>");
    let mut dev = open(&sel, true)?; // writable session (kernel mode arms writes)

    println!(
        "locked protected read (0x10000): {}",
        protected_read_ok(dev.as_mut())
    );

    // Does the read-knock first enable F3/F2? (rule out kernel-mode-behind-read-unlock)
    let knock_first = std::env::args().any(|a| a == "--knock-first");
    if knock_first {
        let k = dev.command_out(&po::knock(), &[]);
        println!("knock first: {}", if k.is_ok() { "ok" } else { "err" });
    }

    // F3 arm (zero-length), F2 challenge (0x400), recover seed, F2 response (0x100).
    dev.command_out(&po::kernel_mode_arm(), &[])
        .map_err(|e| eprintln!("arm err: {e:#}"))
        .ok();
    let challenge = dev.command_in(
        &po::kernel_mode_challenge(),
        po::KERNEL_CHALLENGE_LEN as usize,
    );
    match &challenge {
        Ok(c) if c.len() >= 4 => {
            println!("F2 challenge first 4: {:02x?}", &c[..4]);
            match recover_seed(&c[..4]) {
                Some(seed) => {
                    println!("recovered seed: {seed:#06x}");
                    let resp = vec![response_byte(seed); po::KERNEL_RESPONSE_LEN as usize];
                    match dev.command_out(&po::kernel_mode_response(), &resp) {
                        Ok(()) => println!("kernel-mode handshake COMPLETED (response accepted)"),
                        Err(e) => println!("response rejected: {e:#}"),
                    }
                }
                None => println!("no 16-bit seed reproduces the challenge (unexpected)"),
            }
        }
        Ok(c) => println!("short challenge: {} bytes", c.len()),
        Err(e) => println!("F2 challenge failed: {e:#}"),
    }

    // Independence: after kernel mode (no knock), are protected reads open?
    println!(
        "protected read AFTER kernel mode (no knock): {}  => kernel mode {} a read unlock",
        protected_read_ok(dev.as_mut()),
        if protected_read_ok(dev.as_mut()) {
            "IS ALSO"
        } else {
            "is NOT"
        }
    );
    Ok(())
}
