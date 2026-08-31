//! Tests for the freemkv vendor-command ABI wire frame.

use super::*;

#[test]
fn subfn_values_are_pinned_to_the_wire_protocol() {
    // These numeric values ARE the wire protocol; a drift breaks every host.
    assert_eq!(SubFn::Identity as u8, 0x01);
    assert_eq!(SubFn::Speed as u8, 0x02);
    assert_eq!(SubFn::Vid as u8, 0x03);
    assert_eq!(SubFn::BusEncryption as u8, 0x04);
    assert_eq!(SubFn::Region as u8, 0x05);
    assert_eq!(SubFn::Reserved as u8, 0x06);
    // DumpAll parked at 0x09 after the 0x06–0x08 reserved gap.
    assert_eq!(SubFn::DumpAll as u8, 0x09);
}

#[test]
fn build_cdb_lays_out_the_knock_frame() {
    // Identity with a 0x0107-byte allocation length.
    let cdb = build_cdb(SubFn::Identity, None, 0x0107);
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &KNOCK);
    assert_eq!(cdb[CDB_SUBFN], SubFn::Identity as u8);
    assert_eq!(cdb[CDB_STATE], STATE_OFF); // None → OFF
                                           // 24-bit big-endian allocation length at cdb[6..9].
    assert_eq!(&cdb[CDB_ALLOC_LEN..CDB_ALLOC_LEN + 3], &[0x00, 0x01, 0x07]);
}

#[test]
fn build_cdb_carries_the_state_byte() {
    // Speed's state byte IS the cap value (here 0x80).
    let cdb = build_cdb(SubFn::Speed, Some(0x80), 0);
    assert_eq!(cdb[CDB_SUBFN], 0x02);
    assert_eq!(cdb[CDB_STATE], 0x80);

    // A plain on toggle.
    let cdb = build_cdb(SubFn::Region, Some(STATE_ON), 0);
    assert_eq!(cdb[CDB_STATE], STATE_ON);
}

#[test]
fn dumpall_memread_packs_address_big_endian_at_5_to_9() {
    let cdb = build_memread_cdb(0x01F8_1234);
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &KNOCK);
    assert_eq!(cdb[CDB_SUBFN], SubFn::DumpAll as u8);
    assert_eq!(cdb[CDB_SUBFN], 0x09);
    assert_eq!(&cdb[5..9], &[0x01, 0xF8, 0x12, 0x34]);
}

#[test]
fn verify_response_matches_only_the_magic_lead() {
    assert!(verify_response(b"freemkv\x01\x00"));
    assert!(verify_response(RESP_MAGIC));
    assert!(!verify_response(b"nope"));
    assert!(!verify_response(b""));
}
