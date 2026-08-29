//! Unit tests for [`super`] (MTK CDBs, enc, dump/tar, the flash sequence).

use super::*;
use crate::platform::MockScsiDevice;

// ---- CDB layouts ------------------------------------------------------------

#[test]
fn read_buffer_cdb_layout() {
    assert_eq!(
        cdb_read_buffer(MODE_6, ROM_BUFFER_ID, 0x1EC000, 0x100),
        [0x3C, 0x06, 0x00, 0x1E, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00]
    );
}

#[test]
fn get_config_cdb_layout() {
    assert_eq!(
        cdb_get_config(FEATURE_FWDATE, FD_LEN),
        [0x46, 0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00]
    );
}

#[test]
fn targeted_write_buffer_cdb_layout() {
    // A 64 KiB region write (len exceeds u16) uses the 10-byte 0x3B form.
    let cdb = cdb_write_buffer(MODE_6, FLASH_BUFFER_ID, 0x1F0000, 0x10000);
    assert_eq!(
        cdb,
        [0x3B, 0x06, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
    );
}

#[test]
fn flash_sequence_cdbs_are_twelve_bytes() {
    assert_eq!(cdb_read_probe().len(), 12);
    assert_eq!(cdb_test_unit_ready(), [0u8; 12]);
    assert_eq!(cdb_wb_prepare()[9], 0x0B);
    assert_eq!(
        cdb_wb_data(0x004000, 0x4000),
        [0x3B, 0x06, 0, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0, 0, 0]
    );
    assert_eq!(&cdb_wb_commit()[10..], &[0x1B, 0x12]);
    assert_eq!(cdb_request_sense()[0], 0x03);
}

// ---- enc --------------------------------------------------------------------

#[test]
fn enc_transform_needs_block_multiple_and_changes_bytes() {
    let mut short = vec![0u8; 17];
    assert!(enc_transform(&mut short).is_err());
    let mut block = vec![0u8; 16];
    enc_transform(&mut block).unwrap();
    assert_ne!(block, vec![0u8; 16]);
}

#[test]
fn enc_needed_defaults_to_plaintext() {
    let mut dev = MockScsiDevice::new();
    assert!(
        !enc_needed(&mut dev),
        "enc must default off until research lands"
    );
}

// ---- dump / tar -------------------------------------------------------------

fn sample_dump(a: u8, b: u8) -> UserDump {
    UserDump {
        rom_003000: vec![0; ROM_003000_LEN as usize],
        rom_1ec000: vec![a; ROM_1EC000_LEN as usize],
        rom_1f0000: vec![b; ROM_1F0000_LEN as usize],
        inq: vec![0; 96],
        fd_fwdate: vec![0; 28],
        fd_sn: vec![0; 28],
    }
}

#[test]
fn dump_plan_issues_expected_cdbs() {
    let mut dev = MockScsiDevice::new();
    let dump = DumpPlan::new().execute(&mut dev).unwrap();
    assert_eq!(dump.rom_1ec000.len(), 0x100);
    assert_eq!(dump.rom_1f0000.len(), 0x10000);
    assert_eq!(dev.reads.len(), 6);
    assert_eq!(dev.reads[0][0], 0x3C);
    assert_eq!(dev.reads[3][0], 0x12);
    assert_eq!(&dev.reads[4][2..4], &[0x01, 0x0C]);
    assert_eq!(&dev.reads[5][2..4], &[0x01, 0x08]);
}

#[test]
fn tar_round_trip() {
    let dump = sample_dump(0x22, 0x33);
    let bytes = dump.to_tar_bytes().unwrap();
    assert_eq!(UserDump::from_tar_bytes(&bytes).unwrap(), dump);
}

#[test]
fn parse_field_descriptor_serial_and_helpers() {
    let mut data = vec![
        0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x03, 0x10,
    ];
    data.extend_from_slice(b"009HANK118975   ");
    let fd = parse_field_descriptor(&data).unwrap();
    assert_eq!(fd.feature, FEATURE_SERIAL);
    assert_eq!(fd.ascii, "009HANK118975");

    let mut dump = sample_dump(0, 0);
    dump.fd_sn = data;
    assert_eq!(dump.serial().as_deref(), Some("009HANK118975"));
}

// ---- flash sequence plan ----------------------------------------------------

#[test]
fn flash_sequence_has_128_streams_plus_framing() {
    let seq = flash_sequence(IMAGE_SIZE, CHUNK).unwrap();
    assert_eq!(seq.len(), 134);
    let streams = seq.iter().filter(|s| s.label == LABEL_STREAM).count();
    assert_eq!(streams, 128);
    assert_eq!(seq[0].label, LABEL_PROBE);
    assert_eq!(seq[2].label, LABEL_PREPARE);
    assert_eq!(seq[131].label, LABEL_COMMIT);
    assert_eq!(seq[133].label, LABEL_STATUS);
}

#[test]
fn flash_sequence_rejects_wrong_geometry() {
    assert!(flash_sequence(0x100000, CHUNK).is_err());
    assert!(flash_sequence(IMAGE_SIZE, 0).is_err());
    assert!(flash_sequence(IMAGE_SIZE, 0x3000).is_err());
    // A chunk that would overflow the u16 length field is rejected.
    assert!(flash_sequence(IMAGE_SIZE, 0x10000).is_err());
}

#[test]
fn describe_collapses_stream_but_shows_framing_and_point_of_no_return() {
    let seq = flash_sequence(IMAGE_SIZE, CHUNK).unwrap();
    let text = describe_sequence(&seq);
    assert!(text.contains("#01 PROBE"));
    assert!(text.contains("#03 PREPARE"));
    assert!(text.contains("@0x000000"));
    assert!(text.contains("@0x1FC000"));
    assert!(text.contains("128 identical-shape STREAM chunks (collapsed)"));
    assert!(text.contains("#132 COMMIT"));
    assert!(text.contains("POINT OF NO RETURN"));
    assert!(text.lines().count() < 20);
}

// ---- the Mtk trait impl -----------------------------------------------------

#[test]
fn mtk_geometry_and_readback() {
    let m = Mtk;
    assert_eq!(m.image_size(), IMAGE_SIZE);
    assert_eq!(m.chunk_size(), CHUNK);
    let mut dev = MockScsiDevice::new();
    let got = m.readback(&mut dev, 0x1000, 64).unwrap();
    assert_eq!(got.len(), 64);
    assert_eq!(dev.reads[0][0], 0x3C);
}

#[test]
fn mtk_envelope_plaintext_by_default() {
    let m = Mtk;
    let mut dev = MockScsiDevice::new();
    let image = vec![0xABu8; IMAGE_SIZE];
    let (payload, enc) = m.envelope(&mut dev, &image, None).unwrap();
    assert!(!enc);
    assert_eq!(payload, image);
    // Forced enc changes the bytes.
    let (enc_payload, enc_on) = m.envelope(&mut dev, &image, Some(true)).unwrap();
    assert!(enc_on);
    assert_ne!(enc_payload, image);
}
