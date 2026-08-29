//! Unit tests for [`super`] (the generic engine: flash flow + safety gate).

use super::*;
use crate::drive::mtk::{
    Mtk, CHUNK, IMAGE_SIZE, ROM_003000_LEN, ROM_1EC000_LEN, ROM_1EC000_OFFSET, ROM_1F0000_LEN,
    ROM_1F0000_OFFSET,
};
use crate::drive::InputKind;
use crate::manifest::FlashMode;
use crate::platform::MockScsiDevice;

/// A non-zero, byte-position-dependent pattern (distinguishable from an
/// all-zero or all-constant image, and from its own AES-encrypted form).
fn patterned_image(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Big-endian 24-bit offset bytes, as they appear at `cdb[3..6]`.
fn offset_bytes(offset: u32) -> [u8; 3] {
    [(offset >> 16) as u8, (offset >> 8) as u8, offset as u8]
}

fn is_stream_write(cdb: &[u8]) -> bool {
    cdb.first() == Some(&0x3B) && cdb.get(1).map(|m| m & 0x1f) == Some(0x06)
}

fn is_mode6_read(cdb: &[u8]) -> bool {
    cdb.first() == Some(&0x3C) && cdb.get(1).map(|m| m & 0x1f) == Some(0x06)
}

/// A `UserDump` with distinct, non-zero patterns in the two restorable regions
/// (rom_1EC000 / rom_1F0000), so a restore test can assert on real content.
fn sample_user_dump() -> UserDump {
    UserDump {
        rom_003000: vec![0u8; ROM_003000_LEN as usize],
        rom_1ec000: patterned_image(ROM_1EC000_LEN as usize),
        rom_1f0000: (0..ROM_1F0000_LEN as usize)
            .map(|i| ((i * 7 + 3) % 251) as u8)
            .collect(),
        inq: vec![0u8; 96],
        fd_fwdate: vec![0u8; 28],
        fd_sn: vec![0u8; 28],
    }
}

fn bin_req(image: Vec<u8>, execute: bool) -> FlashRequest {
    FlashRequest {
        input: image,
        input_kind: InputKind::Bin,
        mode: FlashMode::Full,
        execute,
        rescue_no_dump: false,
        acknowledged_risk: execute,
        enc_override: None,
        drive_model: "BU40N".into(),
        predump_out: None,
    }
}

#[test]
fn flash_dry_run_writes_nothing_but_reads_for_backup() {
    let mut dev = MockScsiDevice::new();
    let req = bin_req(vec![0x11u8; IMAGE_SIZE], false);
    flash(&mut dev, &Mtk, &req).unwrap();
    assert!(dev.writes.is_empty(), "dry-run must not write");
    assert!(
        !dev.reads.is_empty(),
        "dry-run still reads for the backup + plan"
    );
}

#[test]
fn flash_rejects_wrong_size_bin() {
    let mut dev = MockScsiDevice::new();
    let req = bin_req(vec![0u8; 1024], false);
    assert!(flash(&mut dev, &Mtk, &req).is_err());
}

#[test]
fn flash_execute_streams_verbatim_and_verifies() {
    // All-zero plaintext image so the mock's zero-fill read-back matches.
    let mut dev = MockScsiDevice::new();
    let req = bin_req(vec![0u8; IMAGE_SIZE], true);
    flash(&mut dev, &Mtk, &req).unwrap();
    // 1 PREPARE + 128 STREAM + 1 COMMIT, all WRITE_BUFFER (0x3B).
    assert_eq!(dev.writes.len(), 1 + IMAGE_SIZE / CHUNK + 1);
    assert!(dev.writes.iter().all(|(cdb, _)| cdb[0] == 0x3B));
    // Bytes streamed are the verbatim (all-zero) image.
    assert!(dev
        .writes
        .iter()
        .all(|(_, data)| data.iter().all(|&b| b == 0)));
}

#[test]
fn flash_execute_requires_ack() {
    let mut dev = MockScsiDevice::new();
    let mut req = bin_req(vec![0u8; IMAGE_SIZE], true);
    req.acknowledged_risk = false;
    assert!(flash(&mut dev, &Mtk, &req).is_err());
}

#[test]
fn safety_requires_ack() {
    // The irreversible write path refuses without --i-understand-risk.
    assert!(check_safety(false).is_err());
    assert!(check_safety(true).is_ok());
}

// ---- non-tautological read-back verify: real content, echoed by the mock --

#[test]
fn flash_execute_streams_patterned_image_verbatim() {
    // A non-zero, position-dependent image against an ECHOING mock: the
    // streamed bytes must equal the original image, not merely "whatever the
    // mock happens to read back."
    let mut dev = MockScsiDevice::echoing();
    let image = patterned_image(IMAGE_SIZE);
    let req = bin_req(image.clone(), true);
    flash(&mut dev, &Mtk, &req).unwrap();

    let streamed: Vec<u8> = dev
        .writes
        .iter()
        .filter(|(cdb, _)| is_stream_write(cdb))
        .flat_map(|(_, data)| data.clone())
        .collect();
    assert_eq!(streamed, image);
}

#[test]
fn flash_execute_detects_readback_mismatch() {
    // Same patterned image, but the mock answers the READ BUFFER for one
    // specific chunk offset with the wrong bytes. If verify were a no-op (or
    // compared against the mock's own zero-fill instead of the real write),
    // this would still return Ok — proving the test actually exercises verify.
    let image = patterned_image(IMAGE_SIZE);
    let bad_offset = (CHUNK * 5) as u32;
    let want = offset_bytes(bad_offset);
    let mut dev = MockScsiDevice::echoing().on(
        move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&want[..]),
        vec![0xFFu8; CHUNK],
    );
    let req = bin_req(image, true);
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(
        err.to_string().contains("read-back verify failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn flash_execute_streams_enc_payload_not_plaintext() {
    // enc_override=Some(true): the FIRST streamed chunk must be the
    // AES-transformed payload, not a slice of the plaintext image (proves the
    // enc transform actually ran end-to-end through the streaming loop).
    let mut dev = MockScsiDevice::echoing();
    let image = patterned_image(IMAGE_SIZE);
    let mut req = bin_req(image.clone(), true);
    req.enc_override = Some(true);
    flash(&mut dev, &Mtk, &req).unwrap();

    let first_chunk = dev
        .writes
        .iter()
        .find(|(cdb, _)| is_stream_write(cdb))
        .map(|(_, data)| data.clone())
        .expect("at least one STREAM write");
    assert_ne!(first_chunk, image[..CHUNK]);
}

#[test]
fn flash_restore_tar_writes_and_verifies_regions() {
    let dump = sample_user_dump();
    let tar = dump.to_tar_bytes().unwrap();
    let mut dev = MockScsiDevice::echoing();
    let mut req = bin_req(vec![], true);
    req.input = tar;
    req.input_kind = InputKind::Tar;
    flash(&mut dev, &Mtk, &req).unwrap();

    let wrote_region = |offset: u32, expected: &[u8]| {
        let want = offset_bytes(offset);
        dev.writes.iter().any(|(cdb, data)| {
            cdb.first() == Some(&0x3B) && cdb.get(3..6) == Some(&want[..]) && data == expected
        })
    };
    assert!(
        wrote_region(ROM_1EC000_OFFSET, &dump.rom_1ec000),
        "rom_1EC000 region not written verbatim"
    );
    assert!(
        wrote_region(ROM_1F0000_OFFSET, &dump.rom_1f0000),
        "rom_1F0000 region not written verbatim"
    );
}

/// A minimal fixed-format REQUEST SENSE payload carrying `key`.
fn fixed_sense(key: u8) -> Vec<u8> {
    let mut s = vec![0u8; 18];
    s[0] = 0x70; // fixed-format response code
    s[2] = key & 0x0F; // sense key
    s[7] = 10; // additional sense length
    s
}

#[test]
fn flash_close_tolerates_benign_unit_attention() {
    // The near-certain state after a microcode program is UNIT ATTENTION (0x6);
    // a successful, already-burned flash must NOT be reported as a failure.
    let mut dev = MockScsiDevice::echoing().on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x06));
    let req = bin_req(patterned_image(IMAGE_SIZE), true);
    flash(&mut dev, &Mtk, &req).expect("benign UNIT ATTENTION must not fail the flash");
}

#[test]
fn flash_close_tolerates_benign_not_ready() {
    // NOT READY (0x2) is a benign mid-transition state after a program; it must
    // not fail the flash either.
    let mut dev = MockScsiDevice::echoing().on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x02));
    let req = bin_req(patterned_image(IMAGE_SIZE), true);
    flash(&mut dev, &Mtk, &req).expect("benign NOT READY must not fail the flash");
}

#[test]
fn flash_close_fails_on_hardware_error_sense() {
    // A genuine HARDWARE ERROR (0x4) after the burn IS a real failure.
    let mut dev = MockScsiDevice::echoing().on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x04));
    let req = bin_req(patterned_image(IMAGE_SIZE), true);
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(
        err.to_string().contains("hardware/medium error"),
        "unexpected error: {err}"
    );
}

#[test]
fn flash_restore_tar_detects_readback_mismatch() {
    let dump = sample_user_dump();
    let tar = dump.to_tar_bytes().unwrap();
    let want = offset_bytes(ROM_1EC000_OFFSET);
    let mut dev = MockScsiDevice::echoing().on(
        move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&want[..]),
        vec![0xFFu8; ROM_1EC000_LEN as usize],
    );
    let mut req = bin_req(vec![], true);
    req.input = tar;
    req.input_kind = InputKind::Tar;
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(
        err.to_string().contains("read-back verify failed"),
        "unexpected error: {err}"
    );
}
