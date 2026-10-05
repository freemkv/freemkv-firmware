//! Read-only probe: dump the 48-byte vendor identity block (`3C 02 F1`) and the
//! standard INQUIRY, to ground the identity/response parser and the drive-class
//! ("type") detection. Issues only reads. Usage: identity_probe <selector>
use anyhow::Result;
use freemkv_flash::platform::open;
use pioneer_optical as po;

fn hexdump(label: &str, d: &[u8]) {
    println!("{label} ({} bytes):", d.len());
    for (i, chunk) in d.chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let asc: String = chunk
            .iter()
            .map(|&b| {
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
        .expect("usage: identity_probe <selector>");
    let mut dev = open(&sel, false)?;
    let inq = dev.command_in(&po::inquiry(0x60), 0x60)?;
    hexdump("INQUIRY", &inq);
    let id = dev.command_in(&po::vendor_identity(), po::IDENTITY_LEN as usize)?;
    hexdump("VENDOR IDENTITY (3C 02 F1)", &id);
    Ok(())
}
