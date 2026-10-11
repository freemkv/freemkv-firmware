//! Send one explicitly supplied SCSI data-out command through the repository
//! transport. This is a transport probe; it does not construct or infer a CDB.
//!
//! Usage:
//!   cargo run -p freemkv-fw --example scsi_out_probe -- /dev/sg0 <cdb-hex> <data-file>

use anyhow::{bail, Context, Result};
use freemkv_flash::platform;
use std::{env, fs, process::ExitCode};

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("hex input must contain only ASCII hexadecimal digits");
    }
    if !compact.len().is_multiple_of(2) {
        bail!("hex input must contain an even number of digits");
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).map_err(Into::into))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_hex;

    #[test]
    fn accepts_ascii_hex_and_spacing() {
        assert_eq!(parse_hex(" c0\tDE\n01 ").unwrap(), vec![0xc0, 0xde, 1]);
    }

    #[test]
    fn invalid_hex_returns_error_without_panicking() {
        for input in ["0", "gg", "€0", "\u{2003}0", "éé"] {
            assert!(parse_hex(input).is_err(), "accepted {input:?}");
        }
    }
}

fn main() -> Result<ExitCode> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        bail!("usage: scsi_out_probe <device> <cdb-hex> <data-file>");
    }
    let cdb = parse_hex(&args[2]).context("invalid CDB hex")?;
    if cdb.is_empty() || cdb.len() > 16 {
        bail!("CDB length must be 1..16 bytes");
    }
    let data = fs::read(&args[3]).with_context(|| format!("reading {}", args[3]))?;
    let mut dev =
        platform::open(&args[1], false).with_context(|| format!("opening {}", args[1]))?;
    dev.command_out(&cdb, &data)
        .context("SCSI data-out failed")?;
    let cdb_text = cdb
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "SCSI data-out succeeded: cdb={cdb_text} data_len={}",
        data.len()
    );
    Ok(ExitCode::SUCCESS)
}
