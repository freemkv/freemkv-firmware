//! Unit tests for [`super`] (the generic engine: flash flow + safety gate).

use super::*;
use crate::drive::mtk::{
    Mtk, CHUNK, IMAGE_SIZE, ROM_003000_LEN, ROM_1EC000_LEN, ROM_1EC000_OFFSET, ROM_1F0000_LEN,
    ROM_1F0000_OFFSET,
};
use crate::drive::{for_family, Family, InputKind};
use crate::manifest::FlashMode;
use crate::platform::MockScsiDevice;

/// A non-zero, byte-position-dependent pattern (distinguishable from an
/// all-zero or all-constant image, and from its own AES-encrypted form).
fn patterned_image(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Stamp a valid MT19xx drive descriptor at 0x1EC000: `model` at +0x08 and the
/// `MTEKMT1959` family tag at +0x34, so the write-path model gate recognizes it.
fn stamp_descriptor(img: &mut [u8], model: &str) {
    let d = ROM_1EC000_OFFSET as usize;
    img[d + 0x08..d + 0x08 + model.len()].copy_from_slice(model.as_bytes());
    img[d + 0x34..d + 0x34 + 10].copy_from_slice(b"MTEKMT1959");
}

/// Turn a full-size image into one the write-path gates accept: stamp a matching
/// descriptor + one active CMAC range, then sign it so `cmac::verify` passes.
fn make_flashable(mut img: Vec<u8>, model: &str) -> Vec<u8> {
    assert_eq!(img.len(), IMAGE_SIZE);
    stamp_descriptor(&mut img, model);
    let img = with_active_cmac_range(img, 0x11000, 0x1FFFF);
    crate::cmac::resign(&img).expect("resign a well-formed image")
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
        verbose: false,
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
    // A signed, model-matching image (mostly zero); the mock's zero-fill
    // read-back matches inside the CMAC-protected range (also zero).
    let mut dev = MockScsiDevice::new();
    let image = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    let req = bin_req(image.clone(), true);
    flash(&mut dev, &Mtk, &req).unwrap();
    // 1 PREPARE + 128 STREAM + 1 COMMIT, all WRITE_BUFFER (0x3B).
    assert_eq!(dev.writes.len(), 1 + IMAGE_SIZE / CHUNK + 1);
    assert!(dev.writes.iter().all(|(cdb, _)| cdb[0] == 0x3B));
    // Bytes streamed are the verbatim image.
    let streamed: Vec<u8> = dev
        .writes
        .iter()
        .filter(|(cdb, _)| is_stream_write(cdb))
        .flat_map(|(_, data)| data.clone())
        .collect();
    assert_eq!(streamed, image);
}

#[test]
fn flash_execute_requires_ack() {
    // A valid, model-matching image so the flow reaches the ACK gate (not the
    // CMAC/model gates) — the refusal here must be the missing acknowledgement.
    let mut dev = MockScsiDevice::new();
    let mut req = bin_req(make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N"), true);
    req.acknowledged_risk = false;
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(err.to_string().contains("SAFETY GATE"), "got: {err}");
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
    let image = make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N");
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

/// Stamp one ACTIVE CMAC entry at the integrity table so `[start, end]` is a
/// protected range (enabled=1, start, end). Mirrors the on-file layout the drive
/// authenticates: `[enabled(4) | start(4) | end(4) | tag(16)]` at 0x10400.
fn with_active_cmac_range(mut image: Vec<u8>, start: u32, end: u32) -> Vec<u8> {
    let off = 0x10400usize; // cmac::TABLE_OFFSET
    image[off..off + 4].copy_from_slice(&1u32.to_le_bytes()); // enabled
    image[off + 4..off + 8].copy_from_slice(&start.to_le_bytes());
    image[off + 8..off + 12].copy_from_slice(&end.to_le_bytes());
    image
}

#[test]
fn flash_execute_fails_on_mismatch_inside_a_cmac_protected_range() {
    // A read-back mismatch INSIDE a CMAC-protected range is genuine corruption
    // (those bytes the drive authenticates), so verify must FAIL. The mock answers
    // one chunk's READ BUFFER with wrong bytes inside the active protected range.
    let bad_offset = (CHUNK * 5) as u32; // 0x14000
    let image = make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N");
    assert!((0x11000..=0x1FFFF).contains(&bad_offset));
    let want = offset_bytes(bad_offset);
    let mut dev = MockScsiDevice::echoing().on(
        move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&want[..]),
        vec![0xFFu8; CHUNK],
    );
    let req = bin_req(image, true);
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(
        err.to_string().contains("read-back verify FAILED"),
        "unexpected error: {err}"
    );
}

#[test]
fn flash_execute_tolerates_readback_mismatch_outside_protected_ranges() {
    // A mismatch OUTSIDE every CMAC-protected range — here the per-unit NVRAM/
    // calibration region, owned and rewritten by the drive — legitimately differs
    // on a perfect flash, so verify must PASS. Protected range placed away from it.
    let bad_offset = ROM_1F0000_OFFSET + CHUNK as u32; // inside per-unit NVRAM
    assert!((bad_offset as usize) < ROM_1F0000_OFFSET as usize + ROM_1F0000_LEN as usize);
    let image = make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N");
    assert!(
        bad_offset > 0x1FFFF,
        "mismatch must be outside the protected range"
    );
    let want = offset_bytes(bad_offset);
    let mut dev = MockScsiDevice::echoing().on(
        move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&want[..]),
        vec![0xFFu8; CHUNK],
    );
    let req = bin_req(image, true);
    flash(&mut dev, &Mtk, &req)
        .expect("mismatch outside every CMAC-protected range must pass verify");
}

#[test]
fn flash_execute_streams_enc_payload_not_plaintext() {
    // enc_override=Some(true): the FIRST streamed chunk must be the
    // AES-transformed payload, not a slice of the plaintext image (proves the
    // enc transform actually ran end-to-end through the streaming loop).
    let mut dev = MockScsiDevice::echoing();
    let image = make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N");
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

#[test]
fn non_mtk_family_reports_full_image_unsupported_not_panic() {
    // Full-image path routes through the DriveFamily trait, so a family that
    // doesn't implement it (Unknown) returns "unsupported" rather than panicking —
    // dump degrades gracefully (omits fw.bin). (Pioneer/Renesas do implement it.)
    let drive = for_family(Family::Unknown);
    let mut dev = MockScsiDevice::new();
    let err = drive.read_full_image(&mut dev).unwrap_err();
    assert!(
        err.to_string().contains("not supported"),
        "expected an unsupported-family error, got: {err}"
    );
    // The read-surface map default is simply "no map" (None), also non-panicking.
    let id = drive.identity(&mut dev);
    let map = drive
        .read_surface_map(&mut dev, &id, &[], &[])
        .expect("default surface map must not error");
    assert!(map.is_none(), "a family with no map returns None");
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
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        true,
    );
    flash(&mut dev, &Mtk, &req).expect("benign UNIT ATTENTION must not fail the flash");
}

#[test]
fn flash_close_tolerates_benign_not_ready() {
    // NOT READY (0x2) is a benign mid-transition state after a program; it must
    // not fail the flash either.
    let mut dev = MockScsiDevice::echoing().on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x02));
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        true,
    );
    flash(&mut dev, &Mtk, &req).expect("benign NOT READY must not fail the flash");
}

#[test]
fn flash_close_fails_on_hardware_error_sense() {
    // A genuine HARDWARE ERROR (0x4) after the burn IS a real failure.
    let mut dev = MockScsiDevice::echoing().on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x04));
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        true,
    );
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("HARDWARE ERROR") && msg.contains("flash may have FAILED"),
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

// ---- write-path integrity + model gates (never write a bad image) ----------

#[test]
fn model_gate_accepts_a_matching_image() {
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    assert!(ensure_image_matches_drive(&img, "BU40N").is_ok());
}

#[test]
fn model_gate_refuses_a_wrong_model_image() {
    // A valid MT19xx image built for a DIFFERENT model than the drive reports.
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE WH16NS60");
    let err = ensure_image_matches_drive(&img, "BU40N").unwrap_err();
    assert!(err.to_string().contains("wrong-model"), "got: {err}");
}

#[test]
fn model_gate_refuses_a_non_mt19xx_image() {
    // No MTEKMT19 family tag at the descriptor → not a recognizable image.
    assert!(ensure_image_matches_drive(&vec![0u8; IMAGE_SIZE], "BU40N").is_err());
}

#[test]
fn model_gate_refuses_an_unknown_drive_product() {
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    assert!(ensure_image_matches_drive(&img, "   ").is_err());
}

#[test]
fn model_gate_refuses_a_truncated_image() {
    assert!(ensure_image_matches_drive(&[0u8; 0x1000], "BU40N").is_err());
}

#[test]
fn flash_execute_refuses_an_unsigned_image_with_no_write() {
    // The brick guard: a model-matching image whose CMAC does NOT verify (empty
    // integrity table) must be refused before any firmware byte is streamed.
    let mut dev = MockScsiDevice::new();
    let mut img = vec![0u8; IMAGE_SIZE];
    stamp_descriptor(&mut img, "BD-RE BU40N");
    let err = flash(&mut dev, &Mtk, &bin_req(img, true)).unwrap_err();
    assert!(err.to_string().contains("AES-CMAC"), "got: {err}");
    assert!(
        !dev.writes.iter().any(|(cdb, _)| is_stream_write(cdb)),
        "no firmware bytes may be streamed for an unsigned image"
    );
}

#[test]
fn flash_aborts_on_a_failed_backup_without_rescue_flag() {
    // A failed pre-flash per-unit backup must abort the flash unless the
    // operator opts into --rescue-no-dump — never write firmware over a drive
    // whose recovery image we could not capture.
    let mut dev = MockScsiDevice::new().on_fail(is_mode6_read, "dump read refused");
    let req = bin_req(vec![0u8; IMAGE_SIZE], true); // rescue_no_dump = false
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(
        err.to_string().contains("pre-flash per-unit dump failed"),
        "got: {err}"
    );
    assert!(
        !dev.writes.iter().any(|(cdb, _)| is_stream_write(cdb)),
        "no firmware bytes may be streamed after a failed backup"
    );
}

#[test]
fn flash_execute_refuses_a_wrong_model_image_with_no_write() {
    // A correctly-signed image for a DIFFERENT model must never reach the write.
    let mut dev = MockScsiDevice::new();
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE WH16NS60");
    let err = flash(&mut dev, &Mtk, &bin_req(img, true)).unwrap_err();
    assert!(err.to_string().contains("wrong-model"), "got: {err}");
    assert!(
        !dev.writes.iter().any(|(cdb, _)| is_stream_write(cdb)),
        "no firmware bytes may be streamed for a wrong-model image"
    );
}
