//! Interoperability proof for the `dump` subcommand's tar format: a full
//! encode → decode round-trip over every member, asserting the bytes survive.

use freemkv_flash::drive::mtk::UserDump;

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
