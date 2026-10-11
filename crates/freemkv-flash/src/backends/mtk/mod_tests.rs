//! Unit tests for [`super`] (MTK CDBs, enc, dump/tar, the flash sequence).

use super::*;
use crate::platform::MockScsiDevice;

// ---- CDB layouts ------------------------------------------------------------

#[test]
fn read_buffer_cdb_layout() {
    assert_eq!(
        cdb::read_memory(0x1EC000, 0x100),
        [0x3C, 0x06, 0x00, 0x1E, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00]
    );
}

#[test]
fn get_config_cdb_layout() {
    assert_eq!(
        cdb::get_configuration(FEATURE_FWDATE, FD_LEN),
        [0x46, 0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00]
    );
}

#[test]
fn targeted_write_buffer_cdb_layout() {
    // A 64 KiB region write (len exceeds u16) uses the 10-byte 0x3B form.
    let cdb = cdb::write_buffer(cdb::MODE_DATA, cdb::BUFFER_ID, 0x1F0000, 0x10000);
    assert_eq!(
        cdb,
        [0x3B, 0x06, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
    );
}

#[test]
fn flash_sequence_cdbs_are_twelve_bytes() {
    assert_eq!(cdb::probe().len(), 12);
    assert_eq!(cdb::test_unit_ready(), [0u8; 12]);
    assert_eq!(cdb::enter_update()[9], 0x0B);
    assert_eq!(
        cdb::transfer(0x004000, 0x4000),
        [0x3B, 0x06, 0, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0, 0, 0]
    );
    assert_eq!(&cdb::finish()[10..], &[0x1B, 0x12]);
    assert_eq!(cdb::request_sense()[0], 0x03);
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
        inq: {
            let mut data = vec![0; 96];
            data[4] = 91;
            data
        },
        fd_fwdate: descriptor(0x010C, 16),
        fd_sn: descriptor(0x0108, 16),
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

/// `UserDump::from_members` MUST refuse a member whose length does not match
/// the on-drive region size exactly. A too-large `rom_1F0000.bin` would
/// overrun the 0x200000 flash target on restore; a >16 MiB member would
/// truncate the 24-bit CDB length field the WRITE BUFFER writes go out
/// with. Confirm every member enforces its expected size independently.
#[test]
fn from_members_rejects_wrong_size_members() {
    fn base_members() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("rom_003000.bin", vec![0; ROM_003000_LEN as usize]),
            ("rom_1EC000.bin", vec![0; ROM_1EC000_LEN as usize]),
            ("rom_1F0000.bin", vec![0; ROM_1F0000_LEN as usize]),
            ("inq.bin", {
                let mut data = vec![0; 96];
                data[4] = 91;
                data
            }),
            ("fd_fwdate.bin", descriptor(0x010C, 16)),
            ("fd_sn.bin", descriptor(0x0108, 16)),
        ]
    }

    // Baseline: correct sizes → accepted.
    assert!(UserDump::from_members(base_members()).is_ok());

    // Each member's size is checked independently — mutating any one of
    // them (too large OR too small) must refuse.
    let mutations: &[(&str, Vec<u8>, &str)] = &[
        ("rom_003000.bin", vec![0; 0], "empty rom_003000.bin"),
        (
            "rom_003000.bin",
            vec![0; ROM_003000_LEN as usize + 1],
            "one-byte oversize rom_003000.bin",
        ),
        (
            "rom_1EC000.bin",
            vec![0; ROM_1EC000_LEN as usize - 1],
            "one-byte undersize rom_1EC000.bin",
        ),
        // The load-bearing one: an oversized rom_1F0000 would restore past
        // the 0x200000 flash-target boundary. Guard MUST refuse.
        (
            "rom_1F0000.bin",
            vec![0; ROM_1F0000_LEN as usize * 2],
            "2x oversize rom_1F0000.bin (would overrun flash on restore)",
        ),
        ("inq.bin", vec![0; 32], "undersize inq.bin"),
        ("fd_fwdate.bin", vec![0; 128], "oversize fd_fwdate.bin"),
    ];

    for (name, data, label) in mutations {
        let mut members = base_members();
        // Replace the named member with the mutated data.
        for m in members.iter_mut() {
            if m.0 == *name {
                m.1 = data.clone();
                break;
            }
        }
        let err = UserDump::from_members(members).expect_err(&format!(
            "from_members MUST refuse a {label} — mismatched per-member length is a \
             restore-time overrun / truncation hazard"
        ));
        let msg = format!("{err:#}");
        assert!(
            msg.contains(name) && msg.contains("expected"),
            "error message must name the offending member and its expected size (got: {msg})"
        );
    }
}

/// The `read_tar` size cap must refuse a tar member whose declared header
/// size exceeds [`READ_TAR_MEMBER_CAP`] BEFORE allocating a full-length
/// buffer for it. Without this guard a hostile 100-GiB header would force
/// a large allocation and only THEN get rejected by `from_members`'s
/// per-member length gate.
#[test]
fn read_tar_refuses_oversized_member_before_allocating() {
    // Build a minimal single-entry tar whose header claims a size just
    // beyond the cap. `tar::Builder` writes the header verbatim, so we
    // can drive `read_tar` into the oversize branch without allocating
    // the full body ourselves.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        let mut header = tar::Header::new_gnu();
        header
            .set_path("rom_1F0000.bin")
            .expect("set_path on header");
        header.set_size(READ_TAR_MEMBER_CAP as u64 + 1);
        header.set_cksum();
        // Body bytes: use a real (much smaller) body — the tar reader
        // truncates to the header's declared size, so read_tar hits our
        // size guard on the declared size, not the body. That's exactly
        // the point: reject before allocation.
        let body = [0u8; 32];
        b.append(&header, &body[..]).expect("append body");
        b.finish().expect("finalize tar");
    }
    let err = UserDump::read_tar(&buf[..]).expect_err(
        "read_tar MUST refuse a member whose declared size exceeds READ_TAR_MEMBER_CAP",
    );
    let msg = format!("{err:#}");
    assert!(
        msg.contains("rom_1F0000.bin") && msg.contains("cap"),
        "error message must name the offending member and the cap (got: {msg})"
    );
}

#[test]
fn parse_field_descriptor_serial_and_helpers() {
    let mut data = vec![
        0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x03, 0x10,
    ];
    data.extend_from_slice(b"009HANK118975    ");
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
        |cdb| cdb == cdb::read_memory(0x1000, 64).as_slice(),
        want.clone(),
    );
    let got = m.readback(&mut dev, 0x1000, 64).unwrap();
    assert_eq!(got.len(), 64);
    assert_eq!(got, want);
    assert_eq!(dev.reads[0][0], 0x3C);
    assert_eq!(dev.reads[0], cdb::read_memory(0x1000, 64));
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
fn flash_stream_aborts_without_writing_when_preflight_fails() {
    // TEST UNIT READY fails at the transport for a non-tolerated reason (a real
    // fault). flash_open must abort BEFORE issuing PREPARE — no writes.
    let mut dev = MockScsiDevice::new().on_fail(|cdb| cdb == [0u8; 12].as_slice(), "TUR faulted");
    assert!(stream(&mut dev, &[0; 32]).is_err());
    assert!(
        dev.writes.is_empty(),
        "a not-ready drive must never reach PREPARE"
    );
}

#[test]
fn firmware_writes_reject_status_that_a_lenient_transport_would_tolerate() {
    struct Rejected;
    impl crate::platform::ScsiDevice for Rejected {
        fn command_in(&mut self, _cdb: &[u8], alloc: usize) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0; alloc])
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> anyhow::Result<()> {
            panic!("firmware write used lenient status handling")
        }
        fn command_out_strict(&mut self, _cdb: &[u8], _data: &[u8]) -> anyhow::Result<()> {
            Err(crate::platform::ScsiSenseError::new(6, 0x29, 0, "UNIT ATTENTION").into())
        }
        fn describe(&self) -> String {
            "rejected write".into()
        }
    }
    // PREPARE is the first data-out; it goes strict and its status aborts.
    assert!(stream(&mut Rejected, &[0; 4]).is_err());
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

#[test]
fn backup_accepts_complete_24_byte_serial_and_preserves_it_in_tar() {
    let serial = descriptor(FEATURE_SERIAL, 12);
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x46) && cdb.get(2..4) == Some(&[1, 8][..]),
        serial.clone(),
    );
    let dump = DumpPlan::new().execute(&mut dev).unwrap();
    assert_eq!(dump.fd_sn, serial);
    let restored = UserDump::from_tar_bytes(&dump.to_tar_bytes().unwrap()).unwrap();
    assert_eq!(restored.fd_sn, serial);
    assert!(dev.writes.is_empty());
}

#[test]
fn descriptor_length_comes_from_header_not_allocation() {
    for payload in [4, 12, 16, 32, 252] {
        let full = descriptor(FEATURE_SERIAL, payload);
        let mut dev = MockScsiDevice::new()
            .on(
                |cdb| cdb.get(7..9) == Some(&[0, 28][..]),
                full[..full.len().min(28)].to_vec(),
            )
            .on(|cdb| cdb.first() == Some(&0x46), full.clone());
        let result = Acquire::GetConfig {
            feature: FEATURE_SERIAL,
            alloc: FD_LEN,
        }
        .run(&mut dev)
        .unwrap();
        assert_eq!(result, full);
        assert_eq!(dev.reads.len(), if payload > 16 { 2 } else { 1 });
        if payload > 16 {
            assert_eq!(&dev.reads[1][7..9], &(full.len() as u16).to_be_bytes());
        }
    }
}

#[test]
fn incomplete_or_inconsistent_descriptors_are_rejected_live_and_in_tar() {
    let full = descriptor(FEATURE_SERIAL, 16);
    let mut wrong_feature = full.clone();
    wrong_feature[9] = 0x0c;
    let mut wrong_total = full.clone();
    wrong_total[3] = 20;
    let mut invalid_ascii = full.clone();
    invalid_ascii[12] = 0xff;
    let mut overflowing_total = full.clone();
    overflowing_total[..4].fill(0xff);
    let mut longer = descriptor(FEATURE_SERIAL, 32);
    longer.truncate(28);
    for data in [
        vec![],
        vec![0; 8],
        full[..11].to_vec(),
        full[..24].to_vec(),
        wrong_feature,
        wrong_total,
        invalid_ascii,
        overflowing_total,
        descriptor(FEATURE_SERIAL, 13),
        longer,
    ] {
        let mut dev = MockScsiDevice::new().on(|cdb| cdb.first() == Some(&0x46), data.clone());
        assert!(Acquire::GetConfig {
            feature: FEATURE_SERIAL,
            alloc: FD_LEN
        }
        .run(&mut dev)
        .is_err());
        assert!(dev.reads.len() <= 2, "descriptor reads must be bounded");
        let mut dump = sample_dump(0, 0);
        dump.fd_sn = data;
        assert!(UserDump::from_tar_bytes(&dump.to_tar_bytes().unwrap()).is_err());
    }
}

#[test]
fn truncated_descriptor_is_not_displayed_as_a_complete_serial() {
    let data = descriptor(FEATURE_SERIAL, 16);
    assert!(parse_field_descriptor(&data[..24]).is_none());
}

#[test]
fn inquiry_backup_accepts_complete_short_reply_and_reads_long_reply() {
    for length in [36usize, 96, 128, 260] {
        let mut reply = vec![0; length];
        reply[4] = (length - 5) as u8;
        let mut dev = MockScsiDevice::new()
            .on(
                |cdb| cdb.get(3..5) == Some(&[0, 96][..]),
                reply[..length.min(96)].to_vec(),
            )
            .on(|cdb| cdb.first() == Some(&0x12), reply.clone());
        let data = Acquire::Inquiry { alloc: INQUIRY_LEN }
            .run(&mut dev)
            .unwrap();
        assert_eq!(data, reply);
        let mut dump = sample_dump(0, 0);
        dump.inq = data;
        assert_eq!(
            UserDump::from_tar_bytes(&dump.to_tar_bytes().unwrap()).unwrap(),
            dump
        );
        assert_eq!(dev.reads.len(), if length > 96 { 2 } else { 1 });
    }
}

#[test]
fn inquiry_backup_rejects_truncated_or_inconsistent_identity() {
    for (returned, declared) in [(0usize, 0usize), (35, 36), (36, 96), (96, 128), (96, 5)] {
        let mut reply = vec![0; returned];
        if returned >= 5 {
            reply[4] = (declared - 5) as u8;
        }
        let mut dev = MockScsiDevice::new().on(|cdb| cdb.first() == Some(&0x12), reply.clone());
        assert!(Acquire::Inquiry { alloc: INQUIRY_LEN }
            .run(&mut dev)
            .is_err());
        assert!(dev.reads.len() <= 2);
        let mut dump = sample_dump(0, 0);
        dump.inq = reply;
        assert!(UserDump::from_tar_bytes(&dump.to_tar_bytes().unwrap()).is_err());
    }
}

#[test]
fn short_preflight_rom_read_prevents_prepare_write() {
    let mut dev = MockScsiDevice::new().on(
        |cdb| cdb.first() == Some(&0x3c),
        vec![0; cdb::PROBE_LEN - 1],
    );
    let error = format!("{:#}", stream(&mut dev, &[0; 32]).unwrap_err());
    assert!(
        error.contains("before any firmware data was sent"),
        "{error}"
    );
    assert!(error.contains("short transfer"), "{error}");
    assert!(dev.writes.is_empty());
}

#[test]
fn short_firmware_report_window_is_not_fingerprinted() {
    let mut dev = MockScsiDevice::new().on(|cdb| cdb.first() == Some(&0x3c), vec![0; 8]);
    assert!(Mtk.firmware_report(&mut dev).is_err());
}

#[test]
fn fixed_sense_with_valid_information_bit_preserves_hardware_fault() {
    let mut sense = vec![0; 18];
    sense[0] = 0xf0;
    sense[2] = 4;
    sense[7] = 10;
    sense[12] = 0x44;
    assert_eq!(parse_sense(&sense), Some((4, 0x44, 0)));
}

/// Run the MTK image-stream flash of `payload`, discarding progress.
fn stream(dev: &mut dyn crate::platform::ScsiDevice, payload: &[u8]) -> anyhow::Result<()> {
    Mtk.flash_stream(dev, payload, crate::manifest::FlashMode::Full, &mut |_| {})
}

#[test]
fn flash_stream_sends_the_oem_sequence_and_reports_progress() {
    let mut dev = MockScsiDevice::new();
    let payload = vec![0xA5u8; 2 * CHUNK];
    let mut seen = Vec::new();
    Mtk.flash_stream(
        &mut dev,
        &payload,
        crate::manifest::FlashMode::Full,
        &mut |n| seen.push(n),
    )
    .unwrap();
    assert_eq!(seen, vec![CHUNK, 2 * CHUNK]);
    let cdbs: Vec<&[u8]> = dev.writes.iter().map(|(c, _)| c.as_slice()).collect();
    assert_eq!(cdbs[0], cdb::enter_update());
    assert_eq!(cdbs[1], cdb::transfer(0, CHUNK as u16));
    assert_eq!(cdbs[2], cdb::transfer(CHUNK as u32, CHUNK as u16));
    assert_eq!(cdbs[3], cdb::finish());
    assert_eq!(dev.reads[0], cdb::probe());
}
