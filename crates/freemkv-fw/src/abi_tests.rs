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
    // Call — interactive fw-exploration `blx target(r0)`, debug-knock only.
    assert_eq!(Verb::Call as u8, 0x0C);
    // Poke — arbitrary single-byte store, debug-knock only.
    assert_eq!(Verb::Poke as u8, 0x0D);
    // Reboot — invoke the boot function's cold entry (baked target), debug-knock only.
    assert_eq!(Verb::Reboot as u8, 0x0F);
}

#[test]
fn debug_knock_is_distinct_from_safe_knock() {
    assert_eq!(KNOCK, [0xC0, 0xDE]);
    assert_eq!(DEBUG_KNOCK, [0xDE, 0xB9]);
    assert_ne!(KNOCK, DEBUG_KNOCK);
}

#[test]
fn build_call_and_poke_cdbs_carry_debug_knock_and_target() {
    // Call: target packed BE at cdb[5..9], r0 arg at cdb[9], DEBUG_KNOCK at cdb[2..4].
    let cdb = build_call_cdb(0x000C_AE18, 0x42);
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &DEBUG_KNOCK);
    assert_eq!(cdb[CDB_VERB], Verb::Call as u8);
    assert_eq!(&cdb[5..9], &[0x00, 0x0C, 0xAE, 0x18]);
    assert_eq!(cdb[9], 0x42);

    // Poke: target packed BE at cdb[5..9], value byte at cdb[9], DEBUG_KNOCK.
    // Exercise four target addresses spanning the ranges the verb legitimately
    // reaches — SRAM base, an MMIO cell, the AACS ladder state region, and the
    // 0x00000000 edge — to catch any off-by-one in address serialization.
    for (target, val, want) in [
        (0x0403_204Cu32, 0xA5u8, [0x04, 0x03, 0x20, 0x4C]),
        (0x0200_0000, 0x11, [0x02, 0x00, 0x00, 0x00]), // SRAM base
        (0x0403_2000, 0x22, [0x04, 0x03, 0x20, 0x00]), // MMIO cell
        (0x01FF_9E00, 0x33, [0x01, 0xFF, 0x9E, 0x00]), // AACS ladder state region
        (0x0000_0000, 0x44, [0x00, 0x00, 0x00, 0x00]), // edge / low address
    ] {
        let cdb = build_poke_cdb(target, val);
        assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
        assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
        assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &DEBUG_KNOCK);
        assert_eq!(cdb[CDB_VERB], Verb::Poke as u8);
        assert_eq!(
            &cdb[5..9],
            &want,
            "poke target 0x{target:08x} BE-packing at cdb[5..9]"
        );
        assert_eq!(cdb[9], val, "poke value byte at cdb[9] for 0x{target:08x}");
    }

    // Reboot: no target/arg on the wire — verb byte + DEBUG_KNOCK + floored alloc.
    let cdb = build_reboot_cdb();
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &DEBUG_KNOCK);
    assert_eq!(cdb[CDB_VERB], Verb::Reboot as u8);
    // No target/arg carried on the wire (baked into the fw at build time). Slots
    // 5..7 are zero; cdb[7..9] is the alloc_len (MIN_ALLOC_LEN, floored so the
    // drive does not abort the data-in). cdb[9] (control) is zero.
    assert_eq!(&cdb[5..7], &[0, 0]);
    assert_eq!(cdb[9], 0);
    // Alloc length floors at MIN_ALLOC_LEN (drive aborts sub-16-byte transfers).
    assert_eq!(
        u16::from_be_bytes([cdb[CDB_ALLOC_LEN], cdb[CDB_ALLOC_LEN + 1]]),
        MIN_ALLOC_LEN
    );
    // Exact wire bytes for the reboot CDB.
    assert_eq!(
        cdb,
        [0x3C, 0x0E, 0xDE, 0xB9, 0x0F, 0x00, 0x00, 0x00, 0x40, 0x00]
    );
}

#[test]
fn feature_values_are_pinned_to_the_wire_protocol() {
    assert_eq!(Feature::Speed as u8, 0x01);
    assert_eq!(Feature::Region as u8, 0x02);
    assert_eq!(Feature::Uhd as u8, 0x03);
    assert_eq!(Feature::Bd as u8, 0x04);
    assert_eq!(Feature::Hrl as u8, 0x05);
    assert_eq!(Feature::Encryption as u8, 0x06);
    // Wire id 0x07 (former `Bus`) is retired / unassigned.
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
    assert_eq!(
        alloc(&build_set_cdb(Feature::Encryption, STATE_ON)),
        MIN_ALLOC_LEN
    );
    assert_eq!(alloc(&build_get_cdb(Feature::Encryption)), MIN_ALLOC_LEN);
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
    let cdb = build_flashwrite_cdb(0x001E_D000, 0xA5);
    assert_eq!(cdb[CDB_OPCODE], READ_BUFFER_OPCODE);
    assert_eq!(cdb[CDB_MODE], KNOCK_MODE);
    assert_eq!(&cdb[CDB_KNOCK..CDB_KNOCK + 2], &KNOCK);
    assert_eq!(cdb[CDB_VERB], Verb::FlashWrite as u8);
    // 32-bit big-endian flash offset at cdb[5..9], value byte at cdb[9].
    assert_eq!(&cdb[5..9], &[0x00, 0x1E, 0xD0, 0x00]);
    assert_eq!(cdb[9], 0xA5);
    // Exact wire bytes for the documented probe (write 0xA5 @ the OEM-unlocked 0x1ED000).
    assert_eq!(
        cdb,
        [0x3C, 0x0E, 0xC0, 0xDE, 0x0A, 0x00, 0x1E, 0xD0, 0x00, 0xA5]
    );
}

#[test]
fn verify_response_matches_only_the_magic_lead() {
    assert!(verify_response(b"freemkv\x01\x00"));
    assert!(verify_response(RESP_MAGIC));
    assert!(!verify_response(b"nope"));
    assert!(!verify_response(b""));
}
