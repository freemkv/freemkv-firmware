use super::*;
use crate::backends::pioneer::{transfer, CONTROL_LEN};
use crate::platform::ScsiDevice;
use pioneer_optical::drive::{execute_update, UpdateTransfer};

#[test]
fn prepared_errors_keep_transport_causes_and_restoration_guidance() {
    let source = || anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
    for error in [
        FlashError::Preflight {
            pass: FlashPass::Restoration,
            source: source(),
        },
        FlashError::DescriptorRead {
            pass: FlashPass::Restoration,
            source: pioneer_optical::drive::Error::Transport(source()),
        },
        FlashError::Update {
            pass: FlashPass::Restoration,
            source: UpdateError::Finish(pioneer_optical::drive::Error::Transport(source())),
        },
        FlashError::Readback {
            pass: FlashPass::Restoration,
            source: pioneer_optical::drive::Error::Transport(source()),
        },
    ] {
        let error = prepared_error(error);
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert!(format!("{error:#}").contains("temporary Kernel may remain installed"));
    }
}

/// Execute one prepared update pass after the final tray guard.
/// The caller owns captured receiver evidence and any required restoration.
fn execute_flash(
    dev: &mut dyn ScsiDevice,
    control: &[u8; CONTROL_LEN],
    kernel: Option<&[u8]>,
    normal: &[u8],
) -> Result<()> {
    let kernel_transfer = kernel.map(transfer::select_kernel).transpose()?;
    let kernel = match kernel_transfer.as_ref() {
        Some(transfer::KernelTransfer::LinearFe(bytes)) => Some(*bytes),
        Some(transfer::KernelTransfer::PreparedFe(bytes)) => Some(bytes.as_slice()),
        None => None,
    };
    crate::engine::guard_no_medium(dev, true)?;
    let shared = SharedDevice::new(dev);
    let class = DriveClass::Bd;
    let mut port = ScsiTransport::flash(&shared);
    let mut runtime = Runtime {
        device: &shared,
        class,
        initial_identity: (String::new(), String::new()),
        target_identity: None,
        start: Instant::now(),
        kernel: style::Progress::new("flashing kernel", kernel.map_or(0, <[u8]>::len)),
        normal: style::Progress::new("flashing normal", normal.len()),
    };
    execute_update(
        &mut port,
        &mut runtime,
        control,
        UpdateTransfer { kernel, normal },
        UpdateOptions {
            class,
            recover: false,
        },
    )
    .map_err(update_error)
}

#[test]
fn pr1ame_1_05_real_kernel_passes_flash_entry_preflight() {
    struct Pr1ame {
        device_type: u8,
        hardware: &'static [u8; 8],
        vendor: &'static [u8; 8],
        product: &'static [u8; 16],
        tag: &'static [u8; 8],
        writes: usize,
    }
    impl ScsiDevice for Pr1ame {
        fn medium_status(&mut self) -> Result<crate::platform::MediumStatus> {
            Ok(crate::platform::MediumStatus::ClosedEmpty)
        }
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            let mut out = vec![0; len];
            if cdb[0] == 0x12 {
                out[0] = self.device_type;
                out[8..16].copy_from_slice(self.vendor);
                out[16..32].copy_from_slice(self.product);
                out[32..36].copy_from_slice(b"1.05");
            } else if cdb == pioneer_optical::cdb::vendor_identity() {
                out[16..24].copy_from_slice(self.hardware);
                out[24..32].copy_from_slice(self.tag);
            } else {
                anyhow::bail!("unexpected read {cdb:02x?}");
            }
            Ok(out)
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
            self.writes += 1;
            anyhow::bail!("preflight must not write")
        }
        fn describe(&self) -> String {
            "PR1AME 1.05".into()
        }
    }
    const KERNEL: &[u8] = include_bytes!("../../../tests/fixtures/pioneer/pr1ame_1_05_kernel.enc");
    let class = super::super::dialect::from_kernel(KERNEL).unwrap();
    let header = pioneer_optical::envelope::header_info(KERNEL).unwrap();
    for (device_type, vendor, product, hardware, tag, should_pass) in [
        (
            5,
            b"PIONEER ",
            b"BDR-PR1AME      ",
            b"SAT 8000",
            b"ID90    ",
            true,
        ),
        (
            5,
            b"PIONEER ",
            b"UNUSUAL PRODUCT ",
            b"SAT 8000",
            b"ID90    ",
            true,
        ),
        (
            5,
            b"PIONEER ",
            b"BDR-PR1AME      ",
            b"SAT 8800",
            b"ID90    ",
            false,
        ),
        (
            5,
            b"PIONEER ",
            b"BDR-PR1AME      ",
            b"SAT 8000",
            b"ID88    ",
            false,
        ),
        (
            5,
            b"NOTOEM  ",
            b"BDR-PR1AME      ",
            b"SAT 8000",
            b"ID90    ",
            false,
        ),
        (
            0,
            b"PIONEER ",
            b"BDR-PR1AME      ",
            b"SAT 8000",
            b"ID90    ",
            false,
        ),
    ] {
        let mut drive = Pr1ame {
            device_type,
            hardware,
            vendor,
            product,
            tag,
            writes: 0,
        };
        let shared = SharedDevice::new(&mut drive);
        let mut runtime = Runtime {
            device: &shared,
            class,
            initial_identity: (
                header.hardware_version.clone(),
                header.kernel_version.clone(),
            ),
            target_identity: None,
            start: Instant::now(),
            kernel: style::Progress::new("kernel", 0),
            normal: style::Progress::new("normal", 0),
        };
        let result = runtime.prepare_pass(FlashPass::Initial);
        assert_eq!(result.is_ok(), should_pass, "{result:?}");
        if let Ok(options) = result {
            assert_eq!(options.class, DriveClass::Bd);
        }
        assert_eq!(drive.writes, 0);
    }
}

/// A BD-generation INQUIRY response (36+ bytes): `PIONEER` / `BD-RW   BDR-UD04`
/// with the given 4-byte revision field. The post-entry gate reads `000` out of
/// bytes `[0x20..0x23]`, which is the start of that revision field.
fn bd_inquiry(alloc: usize, revision: &[u8; 4]) -> Vec<u8> {
    let mut r = vec![0u8; alloc.max(36)];
    r[8..16].copy_from_slice(b"PIONEER ");
    r[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
    r[32..36].copy_from_slice(revision);
    r
}

/// The 0x8A10 (UD04) OEM control buffer, built generically from the embedded
/// key table exactly as the live flasher does for the self/GENERAL path.
fn ud04_control() -> [u8; CONTROL_LEN] {
    let row = crate::backends::pioneer::keys::lookup(0x8A10).expect("0x8A10 in key table");
    let key = row
        .key_for_tag(crate::backends::pioneer::keys::DEFAULT_TAG)
        .expect("GENERAL key");
    row.control_payload(key)
}

/// Minimal UD04 Normal envelope: valid banner + 256-byte aligned size.
fn ud04_normal(len: usize) -> Vec<u8> {
    let mut e = vec![0u8; len];
    let header = b"********  Copyright(c) 2000 Pioneer Corporation\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11.\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
    e[..header.len()].copy_from_slice(header);
    e
}

/// Records every CDB AND the data payload of each write, tracks whether the
/// STRICT data-out entry point was used, and answers the post-entry INQUIRY
/// with "000" / TEST UNIT READY ready so a cooperative drive completes.
/// `fail_strict_at` makes the Nth strict write (0-indexed) return an error.
#[derive(Default)]
struct Recorder {
    writes: Vec<(Vec<u8>, Vec<u8>)>, // (cdb, data)
    ins: Vec<Vec<u8>>,
    strict_writes: usize,
    lenient_writes: usize,
    fail_strict_at: Option<usize>,
}
impl ScsiDevice for Recorder {
    fn command_in(&mut self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
        self.ins.push(cdb.to_vec());
        if cdb.first() == Some(&0x12) {
            return Ok(bd_inquiry(alloc, b"000 "));
        }
        Ok(vec![0u8; alloc])
    }
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.lenient_writes += 1;
        self.writes.push((cdb.to_vec(), data.to_vec()));
        Ok(())
    }
    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        let n = self.strict_writes;
        self.strict_writes += 1;
        if self.fail_strict_at == Some(n) {
            anyhow::bail!("simulated CHECK CONDITION on strict write {n}");
        }
        self.writes.push((cdb.to_vec(), data.to_vec()));
        Ok(())
    }
    fn describe(&self) -> String {
        "recorder".into()
    }
}

#[test]
fn disc_inserted_at_confirmation_is_refused_before_update_entry() {
    let mut dev = crate::platform::MockScsiDevice::pioneer().with_medium_loaded();
    let normal = ud04_normal(0x100000);
    let error = execute_flash(&mut dev, &ud04_control(), None, &normal)
        .expect_err("a disc inserted since the engine guard must abort the write");
    assert!(error.to_string().contains("disc"));
    assert!(
        dev.writes.is_empty(),
        "the entry command is already a write"
    );
}

#[test]
fn executes_entry_normal_chunks_finish_via_strict_writes_with_gate_and_poll() {
    // 1 MiB + 0x100 => 32 full 07/F0 chunks + one 0x100 partial.
    let len = 0x0010_0000usize + 0x100;
    let normal = ud04_normal(len);
    let control = ud04_control();
    let mut dev = Recorder::default();
    execute_flash(&mut dev, &control, None, &normal).unwrap();

    let chunks = len.div_ceil(0x8000);
    // EVERY write went through the strict (abort-on-any-nonzero) path — guards
    // the hardening: a regression to lenient command_out fails this.
    assert_eq!(dev.strict_writes, chunks + 2);
    assert_eq!(dev.lenient_writes, 0);
    let cdbs: Vec<&Vec<u8>> = dev.writes.iter().map(|(c, _)| c).collect();
    assert_eq!(cdbs[0][..3], [0x3b, 0x04, 0xff]); // entry
    assert_eq!(cdbs.last().unwrap()[..3], [0x3b, 0x05, 0xff]); // finish
    assert!(cdbs[1..=chunks]
        .iter()
        .all(|c| c[..3] == [0x3b, 0x07, 0xf0]));
    assert_eq!(cdbs[chunks][3..9], [0x10, 0x00, 0x00, 0x00, 0x01, 0x00]);
    // The concatenated 07/F0 payloads reproduce the Normal byte-for-byte —
    // guards against sending corrupted/truncated data.
    let sent: Vec<u8> = dev.writes[1..=chunks]
        .iter()
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    assert_eq!(sent, normal);
    // Post-entry INQUIRY and post-finish TEST UNIT READY were issued.
    assert!(dev.ins.iter().any(|c| c.first() == Some(&0x12)));
    assert!(dev.ins.iter().any(|c| c == &vec![0u8; 6]));
}

#[test]
fn plain_flash_issues_no_kernel_mode_commands() {
    let normal = ud04_normal(0x0010_0000);
    let mut dev = Recorder::default();
    execute_flash(&mut dev, &ud04_control(), None, &normal).unwrap();
    // No F3/F2 buffer-id traffic at all on the plain path.
    assert!(!dev
        .writes
        .iter()
        .any(|(c, _)| c.get(2) == Some(&0xF3) || c.get(2) == Some(&0xF2)));
    assert!(!dev
        .ins
        .iter()
        .any(|c| c.first() == Some(&0x3C) && c.get(2) == Some(&0xF2)));
}

#[test]
fn aborts_before_any_transfer_when_drive_not_in_update_state() {
    struct BadEntry {
        writes: Vec<Vec<u8>>,
    }
    impl ScsiDevice for BadEntry {
        fn command_in(&mut self, _cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
            Ok(bd_inquiry(alloc, b"1.11")) // INQUIRY reports a revision, not "000"
        }
        fn command_out_strict(&mut self, cdb: &[u8], _data: &[u8]) -> Result<()> {
            self.writes.push(cdb.to_vec());
            Ok(())
        }
        fn command_out(&mut self, cdb: &[u8], _d: &[u8]) -> Result<()> {
            self.writes.push(cdb.to_vec());
            Ok(())
        }
        fn describe(&self) -> String {
            "bad-entry".into()
        }
    }
    let normal = ud04_normal(0x0010_0000 + 0x100);
    let mut dev = BadEntry { writes: Vec::new() };
    let err = execute_flash(&mut dev, &ud04_control(), None, &normal).unwrap_err();
    assert!(format!("{err:#}").contains("post-entry update state"));
    // Only the entry write happened; NO Normal chunk or finish followed.
    assert_eq!(dev.writes.len(), 1);
    assert_eq!(dev.writes[0][..3], [0x3b, 0x04, 0xff]);
    assert!(!dev.writes.iter().any(|c| c[..3] == [0x3b, 0x07, 0xf0]));
}

#[test]
fn a_failed_mid_transfer_write_aborts_with_a_recovery_hint() {
    let normal = ud04_normal(0x0010_0000 + 0x100);
    // Fail the first Normal chunk (strict write index 1: 0=entry, 1=first F0).
    let mut dev = Recorder {
        fail_strict_at: Some(1),
        ..Recorder::default()
    };
    let err = execute_flash(&mut dev, &ud04_control(), None, &normal).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("Normal") && msg.contains("re-flash the captured"));
    // No finish (05/FF) was sent after the failed transfer.
    assert!(!dev.writes.iter().any(|(c, _)| c[..3] == [0x3b, 0x05, 0xff]));
}

/// A structurally valid envelope-wrapped Kernel whose decoded `0xFE` marker is `marker`.
fn marker_kernel(marker: u8) -> Vec<u8> {
    layout_kernel(marker, false)
}

fn layout_kernel(marker: u8, derived: bool) -> Vec<u8> {
    let mut body = vec![0u8; 0x10000];
    body[0xFE] = marker;
    body[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    body[0x1008..0x1010].copy_from_slice(b"ID58    ");
    body[0x1010..0x1014].copy_from_slice(b"ID5 ");
    // FrontKey dispatcher signature: `ae fe .. .. .. .. ae f0`.
    let reg = if derived { 0xad } else { 0xae };
    body[0x2000..0x2008].copy_from_slice(&[reg, 0xfe, 0, 0, 0, 0, reg, 0xf0]);
    let sum = body
        .chunks(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .fold(0u32, |a, w| a.wrapping_add(w));
    let fix = 0u32.wrapping_sub(sum);
    body[0x1020..0x1024].copy_from_slice(&fix.to_be_bytes());
    pioneer_optical::envelope::builder::encode_kernel_envelope(
        &body,
        "PIONEER BD-RW   BDR-UD04",
        &pioneer_optical::envelope::builder::KernelBuild::from_seed(0x123456),
    )
    .expect("test kernel envelope")
}

#[test]
fn executor_preserves_prepared_kernel_bytes() {
    let kernel = marker_kernel(0xFF);
    let normal = ud04_normal(0x8100);
    let mut dev = Recorder::default();
    execute_flash(&mut dev, &ud04_control(), Some(&kernel), &normal).unwrap();
    let sent: Vec<u8> = dev
        .writes
        .iter()
        .filter(|(c, _)| c[..3] == [0x3b, 0x07, 0xfe])
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    assert!(sent == kernel, "Kernel must be written byte-identical");
}

#[test]
fn derived_kernel_sends_real_key_and_decodes_exactly_at_receiver() {
    let kernel = layout_kernel(1, true);
    let expected_body = pioneer_optical::envelope::Envelope::load(&kernel)
        .unwrap()
        .image;
    let normal = ud04_normal(0x8100);
    let mut dev = Recorder::default();
    execute_flash(&mut dev, &[0xa5; 256], Some(&kernel), &normal).unwrap();
    assert_eq!(dev.strict_writes, 7);
    assert_eq!(dev.lenient_writes, 0);
    let mut wire = Vec::new();
    for (cdb, data) in &dev.writes[1..4] {
        assert_eq!(&cdb[..3], &[0x3b, 7, 0xfe]);
        let offset = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
        assert_eq!(offset, wire.len());
        wire.extend_from_slice(data);
    }
    assert_eq!(wire.len(), 0x11200);
    let key = &wire[0x200..0x1200];
    let mut decoded = Vec::new();
    for (i, word) in wire[0x1200..].as_chunks::<4>().0.iter().enumerate() {
        let key_word = u32::from_le_bytes(key[(i * 4) % key.len()..][..4].try_into().unwrap());
        let cipher = u32::from_le_bytes(*word);
        decoded.extend_from_slice(
            &(cipher ^ key_word)
                .rotate_right(key_word & 31)
                .to_le_bytes(),
        );
    }
    assert_eq!(decoded, expected_body);
    assert_eq!(decoded[0xfe], 1);
    assert_eq!(dev.writes[4].1, normal[..0x8000]);
    assert_eq!(dev.writes[5].1, normal[0x8000..]);
    assert_eq!(dev.writes[6].1, dev.writes[0].1);
}

#[test]
fn executes_both_kernel_and_normal_via_strict_writes_in_order() {
    // A front-key Kernel has three FE slices; this Normal has two F0 chunks.
    let kernel = marker_kernel(1);
    let normal: Vec<u8> = (0..0x8100usize).map(|i| (i % 251) as u8).collect();
    let mut dev = Recorder::default();
    execute_flash(&mut dev, &[0xA5; 256], Some(&kernel), &normal).unwrap();

    // entry + 3 kernel FE + 2 normal F0 + finish, all strict, nothing lenient.
    assert_eq!(dev.strict_writes, 7);
    assert_eq!(dev.lenient_writes, 0);
    let cdbs: Vec<&Vec<u8>> = dev.writes.iter().map(|(c, _)| c).collect();
    assert_eq!(cdbs[0][..3], [0x3b, 0x04, 0xff]); // entry
    assert!(cdbs[1..=3].iter().all(|c| c[..3] == [0x3b, 0x07, 0xfe])); // kernel
    assert!(cdbs[4..=5].iter().all(|c| c[..3] == [0x3b, 0x07, 0xf0])); // normal
    assert_eq!(cdbs[6][..3], [0x3b, 0x05, 0xff]); // finish

    // Each chunk's 24-bit BE offset is index*FLASH_CHUNK — pins the offset
    // arithmetic in both loops (kills `*`->`+`/`/` on the offset expression).
    let off = |c: &Vec<u8>| ((c[3] as u32) << 16) | ((c[4] as u32) << 8) | c[5] as u32;
    assert_eq!(
        [off(cdbs[1]), off(cdbs[2]), off(cdbs[3])],
        [0, FLASH_CHUNK as u32, 2 * FLASH_CHUNK as u32]
    ); // kernel FE offsets
    assert_eq!([off(cdbs[4]), off(cdbs[5])], [0, FLASH_CHUNK as u32]); // normal F0 offsets

    // Both payloads were sent byte-exact through the strict path.
    let kernel_sent: Vec<u8> = dev.writes[1..=3]
        .iter()
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    assert_eq!(kernel_sent, kernel);
    let normal_sent: Vec<u8> = dev.writes[4..=5]
        .iter()
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    assert_eq!(normal_sent, normal);
    // Post-entry INQUIRY gate and post-finish TEST UNIT READY poll both ran.
    assert!(dev.ins.iter().any(|c| c.first() == Some(&0x12)));
    assert!(dev.ins.iter().any(|c| c == &vec![0u8; 6]));
}

#[test]
fn post_entry_identity_gate_aborts_a_degraded_receiver() {
    // A degraded drive that never reports the post-entry "000" identity.
    #[derive(Default)]
    struct Degraded {
        writes: usize,
        finished: bool,
    }
    impl ScsiDevice for Degraded {
        fn command_in(&mut self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
            // INQUIRY never reports the "000" update state; TEST UNIT READY ok.
            if cdb.first() == Some(&0x12) {
                return Ok(bd_inquiry(alloc, b"1.11"));
            }
            Ok(vec![0u8; alloc])
        }
        fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
            self.command_out_strict(cdb, data)
        }
        fn command_out_strict(&mut self, cdb: &[u8], _data: &[u8]) -> Result<()> {
            self.writes += 1;
            if cdb.first() == Some(&0x3b) && cdb.get(1) == Some(&0x05) {
                self.finished = true;
            }
            Ok(())
        }
        fn describe(&self) -> String {
            "degraded".into()
        }
    }
    let normal = ud04_normal(0x0010_0000);

    // The post-entry identity gate aborts before any transfer.
    let mut normal_dev = Degraded::default();
    let err = execute_flash(&mut normal_dev, &ud04_control(), None, &normal).unwrap_err();
    assert!(format!("{err:#}").contains("post-entry update state"));
    assert!(!normal_dev.finished, "a gated flash must not reach finish");
}

/// HARD INVARIANT: the generically-built 0x8A10 control buffer is byte-for-
/// byte the old hand-baked UD04 payload ("PIONEER BDR-US04" + 0xFD236642 LE,
/// zero tail), and the UD04 Normal-only self-flash CDB sequence AND every
/// data-out payload on the wire are unchanged. This is the one validated
/// write path; its bytes must never drift.
#[test]
fn ud04_self_flash_control_and_wire_bytes_are_byte_exact() {
    // 1 control oracle: the exact bytes the removed ud04_oem_control_payload()
    // produced.
    let mut oracle = [0u8; CONTROL_LEN];
    oracle[..16].copy_from_slice(b"PIONEER BDR-US04");
    oracle[16..20].copy_from_slice(&0xFD23_6642u32.to_le_bytes());
    let control = ud04_control();
    assert_eq!(
        control, oracle,
        "generic 0x8A10 control must equal old UD04 payload"
    );

    // 0x1D7000 => 59 full 07/F0 chunks; the canonical UD04 Normal size.
    let normal = ud04_normal(0x1D7000);
    let mut dev = Recorder::default();
    execute_flash(&mut dev, &control, None, &normal).unwrap();

    // Exact CDB sequence: 04/FF entry, 59x 07/F0 chunks, 05/FF finish.
    let cdbs: Vec<Vec<u8>> = dev.writes.iter().map(|(c, _)| c.clone()).collect();
    assert_eq!(cdbs.len(), 61);
    assert_eq!(cdbs[0], vec![0x3B, 0x04, 0xFF, 0, 0, 0, 0, 1, 0, 0]);
    assert_eq!(cdbs[1], vec![0x3B, 0x07, 0xF0, 0, 0, 0, 0, 0x80, 0, 0]);
    assert_eq!(cdbs[59], vec![0x3B, 0x07, 0xF0, 0x1D, 0, 0, 0, 0x70, 0, 0]);
    assert_eq!(cdbs[60], vec![0x3B, 0x05, 0xFF, 0, 0, 0, 0, 1, 0, 0]);

    // Exact payloads: entry and finish carry the control; the 59 F0 chunks
    // reproduce the Normal byte-for-byte.
    assert_eq!(dev.writes[0].1.as_slice(), control.as_slice());
    assert_eq!(dev.writes[60].1.as_slice(), control.as_slice());
    let sent: Vec<u8> = dev.writes[1..=59]
        .iter()
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    assert_eq!(sent, normal);
}

#[test]
fn error_guidance_distinguishes_no_transfer_from_unverified_completion() {
    let cause = || pioneer_optical::drive::Error::Transport(anyhow!("device disconnected"));
    for error in [
        UpdateError::Entry(cause()),
        UpdateError::EntryStateRead(cause()),
    ] {
        let message = format!("{:#}", update_error(error));
        assert!(message.contains("no firmware data was transferred"));
        assert!(message.contains("device disconnected"));
        assert!(message.contains("pioneer.transfer."));
        assert!(!message.contains("partial firmware"));
    }
    let message = format!("{:#}", update_error(UpdateError::ReadyTimeout(cause())));
    assert!(message.contains("completion could not be verified"));
    assert!(message.contains("pre-flash backup"));
    assert!(!message.contains("no firmware data was transferred"));
}

#[test]
fn preparation_error_keeps_typed_code_cause_and_prewrite_guidance() {
    let error = preparation_error(pioneer_optical::receiver::Error::UnknownTargetFamily);
    assert!(error
        .downcast_ref::<pioneer_optical::receiver::Error>()
        .is_some());
    let message = format!("{error:#}");
    assert!(message.contains("pioneer.receiver.unknown_target_family"));
    assert!(message.contains("No firmware was written"));
}

#[test]
fn rejected_tray_never_announces_execution() {
    use std::{cell::RefCell, rc::Rc};
    let messages = Rc::new(RefCell::new(Vec::new()));
    let sink = messages.clone();
    let mut dev = crate::platform::MockScsiDevice::pioneer().with_tray_open();
    let result = crate::output::capture(
        move |line| sink.borrow_mut().push(line),
        || execute_flash(&mut dev, &ud04_control(), None, &ud04_normal(0x100000)),
    );
    assert!(result.is_err());
    assert!(dev.writes.is_empty());
    assert!(!messages.borrow().iter().any(|m| m.contains("EXECUTING")));
}
