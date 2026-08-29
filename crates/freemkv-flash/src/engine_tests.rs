//! Unit tests for [`super`] (the generic engine: flash flow + safety gate).

use super::*;
use crate::drive::mtk::{Mtk, CHUNK, IMAGE_SIZE};
use crate::drive::InputKind;
use crate::manifest::FlashMode;
use crate::platform::MockScsiDevice;

fn bin_req(image: Vec<u8>, execute: bool) -> FlashRequest {
    FlashRequest {
        input: image,
        input_kind: InputKind::Bin,
        mode: FlashMode::Full,
        execute,
        rescue_no_dump: false,
        allow_cross_flash: false,
        acknowledged_risk: execute,
        enc_override: None,
        drive_model: "BU40N".into(),
        firmware_model: String::new(),
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
fn safety_requires_ack_and_blocks_mismatch() {
    let no_ack = SafetyContext {
        drive_model: "BU40N",
        firmware_model: "BU40N",
        acknowledged_risk: false,
        allow_cross_flash: false,
    };
    assert!(check_safety(&no_ack).is_err());

    let mismatch = SafetyContext {
        drive_model: "BU40N",
        firmware_model: "WH16NS60",
        acknowledged_risk: true,
        allow_cross_flash: false,
    };
    assert!(check_safety(&mismatch).is_err());
    let allowed = SafetyContext {
        allow_cross_flash: true,
        ..mismatch
    };
    assert!(check_safety(&allowed).is_ok());
}
