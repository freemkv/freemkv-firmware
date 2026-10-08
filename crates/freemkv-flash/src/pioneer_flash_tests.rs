use super::*;

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
    let row = crate::pioneer_keys::lookup(0x8A10).expect("0x8A10 in key table");
    let key = row
        .key_for_tag(crate::pioneer_keys::DEFAULT_TAG)
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
    let error = execute_flash(
        &mut dev,
        &ud04_control(),
        None,
        &normal,
        false,
        false,
        false,
    )
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
    execute_flash(&mut dev, &control, None, &normal, false, false, false).unwrap();

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
    execute_flash(
        &mut dev,
        &ud04_control(),
        None,
        &normal,
        false,
        false,
        false,
    )
    .unwrap();
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
    let err = execute_flash(
        &mut dev,
        &ud04_control(),
        None,
        &normal,
        false,
        false,
        false,
    )
    .unwrap_err();
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
    let err = execute_flash(
        &mut dev,
        &ud04_control(),
        None,
        &normal,
        false,
        false,
        false,
    )
    .unwrap_err();
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
fn ff_marker_kernel_is_written_unpatched_when_patch_kernel_is_false() {
    let kernel = marker_kernel(0xFF);
    let normal = ud04_normal(0x8100);
    let mut dev = Recorder::default();
    execute_flash(
        &mut dev,
        &ud04_control(),
        Some(&kernel),
        &normal,
        false,
        false,
        false,
    )
    .unwrap();
    let sent: Vec<u8> = dev
        .writes
        .iter()
        .filter(|(c, _)| c[..3] == [0x3b, 0x07, 0xfe])
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    assert!(sent == kernel, "Kernel must be written byte-identical");

    // With patch_kernel=true the FF marker IS patched (downgrade path).
    let mut dev = Recorder::default();
    execute_flash(
        &mut dev,
        &ud04_control(),
        Some(&kernel),
        &normal,
        false,
        true,
        false,
    )
    .unwrap();
    let sent: Vec<u8> = dev
        .writes
        .iter()
        .filter(|(c, _)| c[..3] == [0x3b, 0x07, 0xfe])
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    assert_ne!(sent, kernel);
}

#[test]
fn will_patch_only_for_ff_or_00_marker_on_known_new_or_unknown_receiver() {
    use crate::drive::pioneer::will_patch_kernel;
    let ff = marker_kernel(0xFF);
    let zero = marker_kernel(0x00);
    let one = marker_kernel(0x01);
    assert!(will_patch_kernel(Some(&ff), Some(true)));
    assert!(will_patch_kernel(Some(&zero), None));
    assert!(!will_patch_kernel(Some(&ff), Some(false)));
    assert!(!will_patch_kernel(Some(&one), Some(true)));
    assert!(!will_patch_kernel(None, Some(true)));
}

#[test]
fn derived_kernel_sends_real_key_and_decodes_exactly_at_receiver() {
    let kernel = layout_kernel(1, true);
    let expected_body = pioneer_optical::envelope::Envelope::load(&kernel)
        .unwrap()
        .image;
    let normal = ud04_normal(0x8100);
    let mut dev = Recorder::default();
    execute_flash(
        &mut dev,
        &[0xa5; 256],
        Some(&kernel),
        &normal,
        false,
        false,
        false,
    )
    .unwrap();
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
    execute_flash(
        &mut dev,
        &[0xA5; 256],
        Some(&kernel),
        &normal,
        false,
        false,
        false,
    )
    .unwrap();

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
fn recover_skips_the_identity_gate_that_aborts_a_normal_flash() {
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

    // Without recover, the post-entry identity gate aborts before any transfer.
    let mut normal_dev = Degraded::default();
    let err = execute_flash(
        &mut normal_dev,
        &ud04_control(),
        None,
        &normal,
        false,
        false,
        false,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("post-entry update state"));
    assert!(!normal_dev.finished, "a gated flash must not reach finish");

    // With recover, the gate is skipped and the forced write runs to finish.
    let mut recover_dev = Degraded::default();
    execute_flash(
        &mut recover_dev,
        &ud04_control(),
        None,
        &normal,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        recover_dev.finished,
        "recover must force the write through finish"
    );
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
    execute_flash(&mut dev, &control, None, &normal, false, false, false).unwrap();

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

/// A mock that answers INQUIRY / the vendor identity with a chosen product.
struct Ident(&'static [u8; 16]);
impl ScsiDevice for Ident {
    fn command_in(&mut self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
        let mut r = vec![0u8; alloc.max(36)];
        if cdb.first() == Some(&0x12) {
            r[8..16].copy_from_slice(b"PIONEER ");
            r[16..32].copy_from_slice(self.0);
        }
        Ok(r)
    }
    fn command_out(&mut self, _cdb: &[u8], _d: &[u8]) -> Result<()> {
        Ok(())
    }
    fn describe(&self) -> String {
        "ident".into()
    }
}

#[test]
fn class_follows_an_unambiguous_identity() {
    let id = transport::identify(&mut Ident(b"BD-RW   BDR-UD04")).unwrap();
    // The target need not profile: the drive's own identity decides.
    assert_eq!(resolve_class(Ok(id), false, false).unwrap(), DriveClass::Bd);
}

#[test]
fn ambiguous_identity_without_a_known_family_is_refused_before_any_write() {
    // Neither BD nor DVD-R/DVR, and a Normal that does not profile.
    let id = transport::identify(&mut Ident(b"CD-RW   UNKNOWN1")).unwrap();
    let err = resolve_class(Ok(id), false, true).unwrap_err();
    assert!(format!("{err:#}").contains("refusing before any write"));
    // An unreadable identity is equally ambiguous.
    let err = resolve_class(Err(anyhow::anyhow!("no identity")), false, true).unwrap_err();
    assert!(format!("{err:#}").contains("refusing before any write"));
}

#[test]
fn bd_class_is_only_assumed_for_a_recover_flash() {
    // Unreadable identity + a target that profiles as a known family.
    let unreadable = || Err(anyhow::anyhow!("no identity"));
    assert_eq!(
        resolve_class(unreadable(), true, true).unwrap(),
        DriveClass::Bd
    );
    let err = resolve_class(unreadable(), true, false).unwrap_err();
    assert!(format!("{err:#}").contains("refusing before any write"));
    // Same for an identity that is neither BD nor DVR.
    let id = transport::identify(&mut Ident(b"CD-RW   UNKNOWN1")).unwrap();
    assert!(resolve_class(Ok(id.clone()), true, false).is_err());
    assert_eq!(resolve_class(Ok(id), true, true).unwrap(), DriveClass::Bd);
}
