//! Interoperability proof for the `dump` subcommand's tar format.
//!
//! When a real `makemkvcon dump_user` capture is available, parse it and assert
//! the six members, their sizes, and the decoded identity fields. The staged
//! BH-A10AME capture lives outside this repo (in firmware-hoard), so the test is
//! gated on the file existing; set `FREEMKV_DUMP_TAR` to point at another
//! capture.

use std::path::PathBuf;

use freemkv_flash::drive::mtk::{self as dump, UserDump, FEATURE_FWDATE, FEATURE_SERIAL};

fn staged_tar() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FREEMKV_DUMP_TAR") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let default = PathBuf::from(
        "/Users/matthew/Developer/freemkv/freemkv-private/firmware-hoard/incoming/\
         harvest-2026-08-28/bh-a10ame/\
         dump_user_HL-DT-ST_BD-RE__BH-A10AME_1.03_212009021730_009HANK118975.tar",
    );
    default.exists().then_some(default)
}

#[test]
fn round_trip_synthetic_dump() {
    let dump = UserDump {
        rom_003000: vec![1u8; 0x20],
        rom_1ec000: vec![2u8; 0x100],
        rom_1f0000: vec![3u8; 0x10000],
        inq: vec![4u8; 96],
        fd_fwdate: vec![5u8; 28],
        fd_sn: vec![6u8; 28],
    };
    let bytes = dump.to_tar_bytes().unwrap();
    let back = UserDump::from_tar_bytes(&bytes).unwrap();
    assert_eq!(dump, back);
}

#[test]
fn parse_real_bh_a10ame_capture() {
    let Some(path) = staged_tar() else {
        eprintln!("skipping: no staged dump_user tar present");
        return;
    };
    let bytes = std::fs::read(&path).expect("read staged tar");
    let dump = UserDump::from_tar_bytes(&bytes).expect("parse staged tar");

    // Six members at their proven sizes.
    assert_eq!(dump.rom_003000.len(), 0x20);
    assert_eq!(dump.rom_1ec000.len(), 0x100);
    assert_eq!(dump.rom_1f0000.len(), 0x10000);
    assert_eq!(dump.inq.len(), 96);
    assert_eq!(dump.fd_fwdate.len(), 28);
    assert_eq!(dump.fd_sn.len(), 28);

    // Boot banner region begins with the MT1959 boot magic.
    assert!(dump.rom_003000.starts_with(b"MT1959 Boot"));

    // INQUIRY product string is BH-A10AME.
    let product = String::from_utf8_lossy(&dump.inq[16..32]);
    assert!(product.contains("BH-A10AME"), "product was {product:?}");

    // Field descriptors decode as GET CONFIG features carrying serial / date.
    let sn = dump::parse_field_descriptor(&dump.fd_sn).expect("decode fd_sn");
    assert_eq!(sn.feature, FEATURE_SERIAL);
    assert_eq!(sn.ascii, "009HANK118975");

    let fw = dump::parse_field_descriptor(&dump.fd_fwdate).expect("decode fd_fwdate");
    assert_eq!(fw.feature, FEATURE_FWDATE);
    assert_eq!(fw.ascii, "212009021730");
}
