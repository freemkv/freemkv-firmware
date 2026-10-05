//! Interoperability proof for the `backup` subcommand's tar format: a full
//! encode → decode round-trip over every member, asserting the bytes survive.

use freemkv_flash::drive::mtk::UserDump;

#[test]
fn round_trip_synthetic_dump() {
    let dump = UserDump {
        rom_003000: vec![1u8; 0x20],
        rom_1ec000: vec![2u8; 0x100],
        rom_1f0000: vec![3u8; 0x10000],
        inq: {
            let mut data = vec![4u8; 96];
            data[4] = 91;
            data
        },
        fd_fwdate: descriptor(0x010C, 16),
        fd_sn: descriptor(0x0108, 16),
    };
    let bytes = dump.to_tar_bytes().unwrap();
    let back = UserDump::from_tar_bytes(&bytes).unwrap();
    assert_eq!(dump, back);
}

fn descriptor(feature: u16, payload_len: u8) -> Vec<u8> {
    let mut data = vec![0u8; 12 + usize::from(payload_len)];
    let length = (data.len() - 4) as u32;
    data[..4].copy_from_slice(&length.to_be_bytes());
    data[8..10].copy_from_slice(&feature.to_be_bytes());
    data[11] = payload_len;
    data[12..].fill(b'S');
    data
}
