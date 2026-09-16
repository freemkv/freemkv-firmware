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
    // TEMPORARY diagnostic flash-write probe verb.
    assert_eq!(Verb::FlashWrite as u8, 0x0A);
    // Save — the only verb that persists the RAM state table to flash.
    assert_eq!(Verb::Save as u8, 0x0B);
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
    // The uniform tri-state every feature flag speaks: OEM / OFF / ON.
    assert_eq!(STATE_PASSTHROUGH, 0xFF); // OEM passthrough
    assert_eq!(STATE_OFF, 0x00); // actively disabled (safe because the boot hook writes 0xFF)
    assert_eq!(STATE_ON, 0x01); // armed / active
                                // The three canonical states are distinct — no feature-specific sentinel (the
                                // old BD `0x02` STATE_BD_DISABLE is retired; BD OFF is now the uniform 0x00).
    assert_ne!(STATE_PASSTHROUGH, STATE_OFF);
    assert_ne!(STATE_PASSTHROUGH, STATE_ON);
    assert_ne!(STATE_OFF, STATE_ON);

    // Reset carries its mode in the state slot: reload-from-flash vs force-to-OEM.
    assert_eq!(RESET_TO_FLASH, 0x00);
    assert_eq!(RESET_TO_OEM, 0xFF);
    assert_eq!(RESET_TO_OEM, STATE_PASSTHROUGH);
}

#[test]
fn feature_value_consts_are_pinned_to_the_locked_spec() {
    // Speed: OFF (0x00) means the limiter is off, i.e. run uncapped at max.
    assert_eq!(SPEED_MAX, 0x00);
    assert_eq!(SPEED_MAX, STATE_OFF);

    // Region low-nibble scheme: DVD 1..8 = 0x01..=0x08, BD A/B/C = 0x0A..=0x0C,
    // region-free = 0x0F, and 0x00 (locked) is the OFF leg.
    assert_eq!(REGION_DVD_BASE, 0x00);
    assert_eq!(REGION_DVD_BASE + 1, 0x01); // DVD region 1
    assert_eq!(REGION_DVD_BASE + 8, 0x08); // DVD region 8
    assert_eq!(REGION_BD_A, 0x0A);
    assert_eq!(REGION_BD_B, 0x0B);
    assert_eq!(REGION_BD_C, 0x0C);
    assert_eq!(REGION_FREE, 0x0F);
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

    // Region force-BD-A (BD regions now live in the 0x0A..=0x0C low-nibble block).
    let cdb = build_set_cdb(Feature::Region, REGION_BD_A);
    assert_eq!(cdb[CDB_FEATURE], 0x02);
    assert_eq!(cdb[CDB_STATE], 0x0A);
}

#[test]
fn build_get_and_reset_cdbs() {
    let cdb = build_get_cdb(Feature::Hrl);
    assert_eq!(cdb[CDB_VERB], Verb::Get as u8);
    assert_eq!(cdb[CDB_FEATURE], Feature::Hrl as u8);
    // GET requests a MIN_ALLOC_LEN (64-byte) data-in; the drive aborts a 1-byte
    // transfer (HW-confirmed). The state is read from data offset 0.
    assert_eq!(&cdb[CDB_ALLOC_LEN..CDB_ALLOC_LEN + 2], &[0x00, 0x40]);

    // RESET-to-flash: mode 0x00 rides in the state slot; no feature.
    let cdb = build_reset_cdb(RESET_TO_FLASH);
    assert_eq!(cdb[CDB_VERB], Verb::Reset as u8);
    assert_eq!(cdb[CDB_FEATURE], 0);
    assert_eq!(cdb[CDB_STATE], RESET_TO_FLASH);
    // RESET floors its data-in at MIN_ALLOC_LEN for the same HW reason.
    assert_eq!(&cdb[CDB_ALLOC_LEN..CDB_ALLOC_LEN + 2], &[0x00, 0x40]);

    // RESET-to-OEM: mode 0xFF rides in the state slot.
    let cdb = build_reset_cdb(RESET_TO_OEM);
    assert_eq!(cdb[CDB_VERB], Verb::Reset as u8);
    assert_eq!(cdb[CDB_FEATURE], 0);
    assert_eq!(cdb[CDB_STATE], RESET_TO_OEM);

    // SAVE: the flash-persist verb, no feature/state, floored data-in.
    let cdb = build_save_cdb();
    assert_eq!(cdb[CDB_VERB], Verb::Save as u8);
    assert_eq!(cdb[CDB_FEATURE], 0);
    assert_eq!(cdb[CDB_STATE], 0);
    assert_eq!(&cdb[CDB_ALLOC_LEN..CDB_ALLOC_LEN + 2], &[0x00, 0x40]);
}

#[test]
fn vendor_commands_floor_alloc_len_at_min_for_hw() {
    // HW-confirmed (LG BU40N): the READ BUFFER hijack aborts a data-in transfer
    // smaller than ~16 bytes. Every builder that could otherwise ask for 0/1
    // bytes must request at least MIN_ALLOC_LEN so the drive does not abort.
    // MIN_ALLOC_LEN is 64 — comfortably above the ~16-byte hardware floor.
    assert_eq!(MIN_ALLOC_LEN, 64);

    let alloc =
        |cdb: &[u8; CDB_LEN]| u16::from_be_bytes([cdb[CDB_ALLOC_LEN], cdb[CDB_ALLOC_LEN + 1]]);
    assert_eq!(alloc(&build_set_cdb(Feature::Ake, STATE_ON)), MIN_ALLOC_LEN);
    assert_eq!(alloc(&build_get_cdb(Feature::Ake)), MIN_ALLOC_LEN);
    assert_eq!(alloc(&build_reset_cdb(RESET_TO_OEM)), MIN_ALLOC_LEN);
    assert_eq!(alloc(&build_save_cdb()), MIN_ALLOC_LEN);
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
fn flashwrite_packs_offset_big_endian_and_value_at_9() {
    let cdb = build_flashwrite_cdb(0x001C_4000, 0xA5);
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &KNOCK);
    assert_eq!(cdb[CDB_VERB], Verb::FlashWrite as u8);
    // 32-bit big-endian flash offset at cdb[5..9], value byte at cdb[9].
    assert_eq!(&cdb[5..9], &[0x00, 0x1C, 0x40, 0x00]);
    assert_eq!(cdb[9], 0xA5);
    // Exact wire bytes for the report's documented probe (write 0xA5 @ 0x1C4000).
    assert_eq!(
        cdb,
        [0x3C, 0x0E, 0xC0, 0xDE, 0x0A, 0x00, 0x1C, 0x40, 0x00, 0xA5]
    );
}

#[test]
fn verify_response_matches_only_the_magic_lead() {
    assert!(verify_response(b"freemkv\x01\x00"));
    assert!(verify_response(RESP_MAGIC));
    assert!(!verify_response(b"nope"));
    assert!(!verify_response(b""));
}
