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
fn plan_clean_is_human_readable_with_no_cdbs() {
    let seq = flash_sequence(IMAGE_SIZE, CHUNK).unwrap();
    let text = describe_sequence(&seq, false);
    assert!(text.contains("POINT OF NO RETURN"), "{text}");
    assert!(text.contains("2 MiB"), "{text}");
    assert!(text.contains("128"), "{text}");
    // No raw CDB hex or step numbers in the clean view.
    assert!(!text.contains("#01"), "{text}");
    assert!(!text.contains("3C 06"), "{text}");
    assert!(text.lines().count() < 12, "{text}");
}

#[test]
fn plan_verbose_shows_framing_and_collapses_streams() {
    let seq = flash_sequence(IMAGE_SIZE, CHUNK).unwrap();
    let text = describe_sequence(&seq, true);
    assert!(text.contains("#01 PROBE"), "{text}");
    assert!(text.contains("#03 PREPARE"), "{text}");
    assert!(text.contains("@0x1FC000"), "{text}");
    assert!(text.contains("identical STREAM chunks collapsed"), "{text}");
    assert!(text.contains("#132 COMMIT"), "{text}");
    assert!(text.contains("POINT OF NO RETURN"), "{text}");
}

// ---- the Mtk trait impl -----------------------------------------------------

#[test]
fn mtk_geometry_and_readback() {
    let m = Mtk;
    assert_eq!(m.image_size(), IMAGE_SIZE);
    assert_eq!(m.chunk_size(), CHUNK);

    // Distinct, non-zero bytes at the queried offset: a mock that just
    // zero-fills would make a bug that swaps FLASH_BUFFER_ID / mode / offset
    // in `readback` invisible. Pin the exact CDB *and* the returned content.
    let want: Vec<u8> = (0..64u32).map(|i| (i * 3 + 1) as u8).collect();
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb == cdb_read_buffer(MODE_6, FLASH_BUFFER_ID, 0x1000, 64).as_slice(),
        want.clone(),
    );
    let got = m.readback(&mut dev, 0x1000, 64).unwrap();
    assert_eq!(got.len(), 64);
    assert_eq!(got, want);
    assert_eq!(dev.reads[0][0], 0x3C);
    assert_eq!(
        dev.reads[0],
        cdb_read_buffer(MODE_6, FLASH_BUFFER_ID, 0x1000, 64)
    );
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

#[test]
fn parse_sense_fixed_descriptor_and_short_buffers() {
    // Fixed format (0x70/0x71): key=byte2&0xF, ASC=byte12, ASCQ=byte13.
    let mut fixed = vec![0u8; 18];
    fixed[0] = 0x70;
    fixed[2] = 0x04;
    fixed[7] = 10;
    fixed[12] = 0x11;
    fixed[13] = 0x22;
    assert_eq!(parse_sense(&fixed), Some((0x04, 0x11, 0x22)));
    // Descriptor format (0x72/0x73): key=byte1&0xF, ASC=byte2, ASCQ=byte3.
    assert_eq!(
        parse_sense(&[0x72, 0x06, 0x33, 0x44]),
        Some((0x06, 0x33, 0x44))
    );
    // Short / empty / unknown response code must return None, never panic.
    assert_eq!(parse_sense(&[0x70, 0x00, 0x04]), None);
    assert_eq!(parse_sense(&[0x72, 0x06]), None);
    assert_eq!(parse_sense(&[]), None);
    assert_eq!(parse_sense(&[0x00; 4]), None);
}

// preflight / flash_open safety (regression: hardware-found). The benign "no
// disc" case is tolerated in the transport, so at THIS layer a TEST UNIT READY
// surfacing as an error is a genuine fault that must never reach a write.

use crate::drive::DriveFamily;

#[test]
fn preflight_is_read_only_on_a_responsive_drive() {
    let mut dev = MockScsiDevice::new();
    Mtk.preflight(&mut dev)
        .expect("a responsive drive passes the read-only handshake");
    assert!(dev.writes.is_empty(), "preflight must issue no writes");
}

#[test]
fn flash_open_aborts_without_writing_when_preflight_fails() {
    // TEST UNIT READY fails at the transport for a non-tolerated reason (a real
    // fault). flash_open must abort BEFORE issuing PREPARE — no writes.
    let mut dev = MockScsiDevice::new().on_fail(|cdb| cdb == [0u8; 12].as_slice(), "TUR faulted");
    assert!(Mtk
        .flash_open(&mut dev, crate::manifest::FlashMode::Full)
        .is_err());
    assert!(
        dev.writes.is_empty(),
        "a not-ready drive must never reach PREPARE"
    );
}
