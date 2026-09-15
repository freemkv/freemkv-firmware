//! Tests for the freemkv vendor-command ABI wire frame.

use super::*;

#[test]
fn verb_values_are_pinned_to_the_wire_protocol() {
    // These numeric values ARE the wire protocol; a drift breaks every host.
    assert_eq!(Verb::Identity as u8, 0x01);
    assert_eq!(Verb::Set as u8, 0x02);
    assert_eq!(Verb::Get as u8, 0x03);
    assert_eq!(Verb::Reset as u8, 0x04);
    assert_eq!(Verb::DumpAll as u8, 0x09);
}

#[test]
fn feature_values_are_pinned_to_the_wire_protocol() {
    assert_eq!(Feature::Speed as u8, 0x01);
    assert_eq!(Feature::Region as u8, 0x02);
    assert_eq!(Feature::Uhd as u8, 0x03);
    assert_eq!(Feature::Bd as u8, 0x04);
    assert_eq!(Feature::Hrl as u8, 0x05);
    assert_eq!(Feature::Ake as u8, 0x06);
    assert_eq!(Feature::Bus as u8, 0x07);
}

#[test]
fn state_sentinels_are_pinned() {
    assert_eq!(STATE_PASSTHROUGH, 0xFF);
    assert_eq!(STATE_OFF, 0x00);
    assert_eq!(STATE_ON, 0x01);
    assert_eq!(HRL_WIPE_ONCE, 0x02);
    assert_eq!(REGION_BD_A, 0x2A);
    assert_eq!(REGION_BD_B, 0x2B);
    assert_eq!(REGION_BD_C, 0x2C);
}

#[test]
fn build_cdb_lays_out_the_knock_frame() {
    // Identity with a 0x0107-byte allocation length.
    let cdb = build_identity_cdb(0x0107);
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &KNOCK);
    assert_eq!(cdb[CDB_VERB], Verb::Identity as u8);
    // 16-bit big-endian allocation length at cdb[7..9].
    assert_eq!(&cdb[CDB_ALLOC_LEN..CDB_ALLOC_LEN + 2], &[0x01, 0x07]);
}

#[test]
fn build_set_cdb_carries_feature_and_state() {
    let cdb = build_set_cdb(Feature::Uhd, STATE_ON);
    assert_eq!(cdb[CDB_VERB], Verb::Set as u8);
    assert_eq!(cdb[CDB_FEATURE], Feature::Uhd as u8);
    assert_eq!(cdb[CDB_STATE], STATE_ON);

    // Speed's state byte IS the cap value.
    let cdb = build_set_cdb(Feature::Speed, 0x80);
    assert_eq!(cdb[CDB_FEATURE], 0x01);
    assert_eq!(cdb[CDB_STATE], 0x80);

    // Region force-BD-A.
    let cdb = build_set_cdb(Feature::Region, REGION_BD_A);
    assert_eq!(cdb[CDB_FEATURE], 0x02);
    assert_eq!(cdb[CDB_STATE], 0x2A);
}

#[test]
fn build_get_and_reset_cdbs() {
    let cdb = build_get_cdb(Feature::Hrl);
    assert_eq!(cdb[CDB_VERB], Verb::Get as u8);
    assert_eq!(cdb[CDB_FEATURE], Feature::Hrl as u8);
    // GET requests a 1-byte data-in for the state.
    assert_eq!(&cdb[CDB_ALLOC_LEN..CDB_ALLOC_LEN + 2], &[0x00, 0x01]);

    let cdb = build_reset_cdb();
    assert_eq!(cdb[CDB_VERB], Verb::Reset as u8);
    assert_eq!(cdb[CDB_FEATURE], 0);
    assert_eq!(cdb[CDB_STATE], 0);
}

#[test]
fn dumpall_memread_packs_address_big_endian_at_5_to_9() {
    let cdb = build_memread_cdb(0x01F8_1234);
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &KNOCK);
    assert_eq!(cdb[CDB_VERB], Verb::DumpAll as u8);
    assert_eq!(&cdb[5..9], &[0x01, 0xF8, 0x12, 0x34]);
}

#[test]
fn verify_response_matches_only_the_magic_lead() {
    assert!(verify_response(b"freemkv\x01\x00"));
    assert!(verify_response(RESP_MAGIC));
    assert!(!verify_response(b"nope"));
    assert!(!verify_response(b""));
}
