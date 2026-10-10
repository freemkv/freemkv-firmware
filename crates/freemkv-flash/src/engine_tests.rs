//! Unit tests for [`super`] (the generic engine: flash flow + safety gate).

use super::*;
use crate::drive::mtk::crossflash::{decide_crossflash, ensure_image_matches_drive};
use crate::drive::mtk::file_info::{classify_file, CmacSummary};
use crate::drive::mtk::{
    Mtk, CHUNK, IMAGE_SIZE, ROM_003000_LEN, ROM_1EC000_LEN, ROM_1EC000_OFFSET, ROM_1F0000_LEN,
    ROM_1F0000_OFFSET,
};
use crate::drive::{for_family, Family, InputKind, UserDump};
use crate::manifest::FlashMode;
use crate::platform::{MockScsiDevice, ScsiDevice};

/// Observe the very first data-out command and prove the rollback file is
/// already present, readable, and accepted by the same backend's flash path.
struct BackupBeforeWriteDevice {
    inner: MockScsiDevice,
    backup_path: std::path::PathBuf,
    checked: bool,
}

impl ScsiDevice for BackupBeforeWriteDevice {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        self.inner.command_in(cdb, len)
    }

    fn command_out(&mut self, cdb: &[u8], bytes: &[u8]) -> Result<()> {
        if !self.checked {
            let archive = std::fs::read(&self.backup_path)
                .context("first write preceded the durable rollback file")?;
            Mtk.validate_backup(&archive, "BD-RE BU40N")?;
            self.checked = true;
        }
        self.inner.command_out(cdb, bytes)
    }

    fn describe(&self) -> String {
        self.inner.describe()
    }

    fn medium_status(&mut self) -> Result<MediumStatus> {
        self.inner.medium_status()
    }
}

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
    img[..0x400].copy_from_slice(stored_boot_page());
    stamp_descriptor(&mut img, model);
    let img = with_active_cmac_range(img, 0x11000, 0x1FFFF);
    crate::cmac::resign(&img).expect("resign a well-formed image")
}

/// The stored boot page every cataloged MT1959 build shares.
pub(crate) fn stored_boot_page() -> &'static [u8] {
    crate::drive::mtk::oem::catalog()
        .default_for(mediatek_optical::Chip::Mt1959)
        .expect("MT1959 default")
        .boot_page()
}

/// Big-endian 24-bit offset bytes, as they appear at `cdb[3..6]`.
fn offset_bytes(offset: u32) -> [u8; 3] {
    [(offset >> 16) as u8, (offset >> 8) as u8, offset as u8]
}

fn is_stream_write(cdb: &[u8]) -> bool {
    cdb.first() == Some(&0x3B) && cdb.get(1).map(|m| m & 0x1f) == Some(0x06)
}

/// A banner or descriptor read: the only reads the chip gate issues.
fn is_identity_read(cdb: &[u8]) -> bool {
    is_mode6_read(cdb)
        && (cdb.get(3..6) == Some(&offset_bytes(ROM_1EC000_OFFSET)[..])
            || cdb.get(3..6) == Some(&offset_bytes(0x3000)[..]))
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
        inq: {
            let mut data = vec![0u8; 96];
            data[4] = 91;
            data
        },
        fd_fwdate: descriptor(0x010C, 16),
        fd_sn: descriptor(0x0108, 16),
    }
}

static BACKUP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn backup_firmware() -> Vec<u8> {
    make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N")
}

fn coherent_backup() -> BackupArtifact {
    let firmware = backup_firmware();
    let mut per_unit = sample_user_dump();
    let d = ROM_1EC000_OFFSET as usize;
    let n = ROM_1F0000_OFFSET as usize;
    per_unit
        .rom_1ec000
        .copy_from_slice(&firmware[d..d + ROM_1EC000_LEN as usize]);
    per_unit
        .rom_1f0000
        .copy_from_slice(&firmware[n..n + ROM_1F0000_LEN as usize]);
    BackupArtifact {
        firmware,
        per_unit,
        drive_product: "BD-RE BU40N".into(),
    }
}

fn fresh_backup_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "freemkv-backup-{}-{}.tar",
        std::process::id(),
        BACKUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ^ std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
    ))
}

fn bin_req(image: Vec<u8>, execute: bool) -> FlashRequest {
    FlashRequest {
        input: image,
        input_kind: InputKind::Bin,
        mode: FlashMode::Full,
        execute,
        acknowledged_risk: execute,
        enc_override: None,
        drive_model: "BU40N".into(),
        verbose: false,
        predump_out: execute.then(fresh_backup_path),
        allow_crossflash: false,
        skip_backup: false,
        recover: false,
        force: false,
    }
}

#[test]
fn pioneer_real_ud04_envelope_is_offline_only() {
    let Ok(path) = std::env::var("PIONEER_UD04_ENC_FIXTURE") else {
        return; // Local OEM fixture is not checked into the source repository.
    };
    let image = std::fs::read(path).unwrap();
    assert_eq!(image.len(), 0x1d7000);
    assert_eq!(
        format!("{:x}", Sha256::digest(&image)),
        "a5aa757081478620637ed2950b540f35f1cbb969598532cfc872daba0a0366e6"
    );
    let mut req = bin_req(image, false);
    req.drive_model = "BDR-UD04".into();
    let mut dev = MockScsiDevice::pioneer();
    flash(&mut dev, &*for_family(Family::Pioneer), &req).unwrap();
    assert!(dev.writes.is_empty());
    assert!(dev.reads.is_empty());
    req.execute = true;
    assert!(flash(&mut dev, &*for_family(Family::Pioneer), &req).is_err());
    assert!(dev.writes.is_empty());
    assert!(dev.reads.is_empty());
}

#[test]
fn pioneer_offline_plan_does_not_gate_on_marketing_model() {
    let Ok(path) = std::env::var("PIONEER_UD04_ENC_FIXTURE") else {
        return;
    };
    let image = std::fs::read(path).unwrap();
    let mut req = bin_req(image, false);
    req.drive_model = "BDR-UD040".into();
    let mut dev = MockScsiDevice::pioneer();
    flash(&mut dev, &*for_family(Family::Pioneer), &req).unwrap();
    assert!(dev.reads.is_empty());
    assert!(dev.writes.is_empty());
}

#[test]
fn pioneer_offline_plan_rejects_malformed_envelope_without_device_io() {
    let mut image = vec![0u8; crate::drive::pioneer::IMAGE_MIN];
    let header = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nThis is microcode file.\r\nID : PIONEER BD-RW   BDR-212.\r\nRevision Level : 1.05 .\r\n";
    image[..header.len()].copy_from_slice(header);
    let mut req = bin_req(image, false);
    req.drive_model = "BDR-212".into();
    let mut dev = MockScsiDevice::pioneer();
    let err = flash(&mut dev, &*for_family(Family::Pioneer), &req).unwrap_err();
    assert!(format!("{err:#}").contains("malformed bundle"));
    assert!(dev.reads.is_empty());
    assert!(dev.writes.is_empty());
}

#[test]
fn pioneer_template_free_backup_rejects_missing_hardware_identity_without_service_io() {
    let mut inquiry = vec![b' '; 36];
    inquiry[0] = 0x05;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
    let mut dev = MockScsiDevice::new()
        .on(|cdb| cdb.first() == Some(&0x12), inquiry)
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            vec![0xA5; 8],
        );
    let out = std::env::temp_dir().join(format!("pioneer-not-backup-{}.tar", std::process::id()));
    let err = backup(&mut dev, &*for_family(Family::Pioneer), &out, false, false).unwrap_err();
    assert!(format!("{err:#}").contains("complete hardware identity"));
    assert!(dev.reads.iter().all(|cdb| {
        cdb.first() == Some(&0x12) || (cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1))
    }));
    assert!(dev.writes.is_empty());
    assert!(!out.exists());
}

#[test]
fn unknown_backend_backup_fails_without_reads_writes_or_file() {
    let mut dev = MockScsiDevice::new();
    let out = fresh_backup_path();
    let err = backup(&mut dev, &*for_family(Family::Unknown), &out, false, false).unwrap_err();
    assert!(format!("{err:#}").contains("no firmware backup capability"));
    assert!(dev.reads.is_empty());
    assert!(dev.writes.is_empty());
    assert!(!out.exists());
}

#[test]
fn pioneer_execute_without_risk_ack_is_safety_gated_and_issues_no_writes() {
    let mut image = vec![0u8; 0x1d7000];
    let header = b"********  Copyright(c) 2000 Pioneer Corporation\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11.\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
    image[..header.len()].copy_from_slice(header);
    let mut req = bin_req(image, true);
    req.acknowledged_risk = false;
    req.drive_model = "BD-RW   BDR-UD04".into();
    let mut dev = MockScsiDevice::pioneer();
    let err = flash(&mut dev, &*for_family(Family::Pioneer), &req).unwrap_err();
    // The shared safety gate fires before any backup or write.
    assert!(format!("{err:#}").contains("SAFETY GATE"));
    assert!(dev.writes.is_empty());
    assert!(dev.reads.is_empty());
}

#[test]
fn flash_dry_run_writes_nothing_but_reads_for_backup() {
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let req = bin_req(
        make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N"),
        false,
    );
    flash(&mut dev, &Mtk, &req).unwrap();
    assert!(dev.writes.is_empty(), "dry-run must not write");
    assert!(
        !dev.reads.is_empty(),
        "dry-run still reads for the backup + plan"
    );
}

#[test]
fn flash_dry_run_rejects_bad_cmac_without_writes() {
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let mut image = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    image[0x11000] ^= 1; // inside the active authenticated range
    let err = flash(&mut dev, &Mtk, &bin_req(image, false)).unwrap_err();
    assert!(err.to_string().contains("AES-CMAC"), "got: {err}");
    assert!(dev.writes.is_empty());
}

#[test]
fn flash_dry_run_rejects_wrong_model_without_writes() {
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let image = make_flashable(vec![0u8; IMAGE_SIZE], "WH16NS60");
    let err = flash(&mut dev, &Mtk, &bin_req(image, false)).unwrap_err();
    assert!(err.to_string().contains("wrong-model"), "got: {err}");
    assert!(dev.writes.is_empty());
}

#[test]
fn flash_rejects_wrong_size_bin() {
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let req = bin_req(vec![0u8; 1024], false);
    assert!(flash(&mut dev, &Mtk, &req).is_err());
}

#[test]
fn flash_execute_streams_verbatim_and_verifies() {
    // A signed, model-matching image (mostly zero); the mock's zero-fill
    // read-back matches inside the CMAC-protected range (also zero).
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
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
fn validated_rollback_file_exists_before_first_device_write() {
    let mut req = bin_req(backup_firmware(), true);
    let backup_path = fresh_backup_path();
    req.predump_out = Some(backup_path.clone());
    let mut dev = BackupBeforeWriteDevice {
        inner: MockScsiDevice::echoing().with_firmware_image(backup_firmware()),
        backup_path: backup_path.clone(),
        checked: false,
    };
    flash(&mut dev, &Mtk, &req).unwrap();
    assert!(dev.checked);
    assert!(!dev.inner.writes.is_empty());
    std::fs::remove_file(backup_path).unwrap();
}

#[test]
fn failed_middle_stream_chunk_never_sends_commit_or_reports_success() {
    let failing_offset = offset_bytes((2 * CHUNK) as u32);
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on_fail(
            move |cdb| is_stream_write(cdb) && cdb.get(3..6) == Some(&failing_offset[..]),
            "injected stream failure",
        );
    let req = bin_req(backup_firmware(), true);
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(format!("{err:#}").contains("injected stream failure"));
    let stream_count = dev
        .writes
        .iter()
        .filter(|(cdb, _)| is_stream_write(cdb))
        .count();
    assert_eq!(stream_count, 2);
    assert_eq!(
        dev.writes.len(),
        3,
        "prepare and two chunks only; no commit"
    );
}

#[test]
fn failed_backup_persistence_prevents_first_device_write() {
    let mut req = bin_req(backup_firmware(), true);
    let nonexistent_parent = fresh_backup_path();
    req.predump_out = Some(nonexistent_parent.join("rollback.tar"));
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(format!("{err:#}").contains("creating temporary backup"));
    assert!(dev.writes.is_empty());
    assert!(!nonexistent_parent.exists());
}

#[test]
fn flash_execute_requires_ack() {
    // A valid, model-matching image so the flow reaches the ACK gate (not the
    // CMAC/model gates) — the refusal here must be the missing acknowledgement.
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
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
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
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
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on_after_stream(
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

/// Codeaudit HIGH-4 (`tests` lens): the post-flash "unverified > 0" bail —
/// added when `.warn+exit-0` was upgraded to `.bail!` — had no test path
/// that would trigger it. This test forces a read-back to ERROR (not
/// mismatch) on a protected chunk, so the engine's `differing`+`first_bad`
/// path is not taken and `unverified` increments; the flash must then
/// bail with the "read-back INCOMPLETE" message and NOT exit 0.
#[test]
fn flash_execute_bails_on_unverified_read_back_of_protected_chunk() {
    let bad_offset = (CHUNK * 5) as u32; // 0x14000, inside a CMAC-active range
    let image = make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N");
    assert!((0x11000..=0x1FFFF).contains(&bad_offset));
    let want = offset_bytes(bad_offset);
    // `on_fail` refuses the read entirely — `readback` returns Err, the
    // engine's match falls through to the `has_protected` arm, and
    // `unverified` increments. With protected ranges non-empty AND no
    // differing bytes AND unverified > 0, the new bail! must fire.
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on_fail_after_stream(
            move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&want[..]),
            "simulated read-back transport error",
        );
    let req = bin_req(image, true);
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("read-back INCOMPLETE") || msg.contains("unverified"),
        "expected the codeaudit-driven 'unverified > 0' bail, got: {msg}"
    );
    assert!(
        !msg.contains("read-back verify FAILED"),
        "must NOT be the 'differing bytes' bail — the mock errored, it didn't mismatch"
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
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on_after_stream(
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
    let image = make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N");
    // The device exposes decoded firmware, not the encrypted wire envelope.
    let mut dev = MockScsiDevice::new().with_firmware_image(image.clone());
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
fn flash_restore_tar_reflashes_complete_firmware_only() {
    let tar = coherent_backup().to_tar_bytes().unwrap();
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    let mut req = bin_req(vec![], true);
    req.input = tar;
    req.input_kind = InputKind::Tar;
    req.drive_model = "BD-RE BU40N".into();
    flash(&mut dev, &Mtk, &req).unwrap();

    let streamed: Vec<u8> = dev
        .writes
        .iter()
        .filter(|(cdb, _)| is_stream_write(cdb))
        .flat_map(|(_, bytes)| bytes.clone())
        .collect();
    // A 0.10.x archive restores as its OEM-format rebuild, never the raw capture.
    let expected =
        mediatek_optical::oem::rebuild(&backup_firmware(), crate::drive::mtk::oem::catalog())
            .unwrap()
            .image;
    assert_eq!(streamed, expected);
    assert!(!dev.writes.iter().any(|(cdb, data)| cdb.get(3..6)
        == Some(&offset_bytes(ROM_1EC000_OFFSET)[..])
        && data.len() == ROM_1EC000_LEN as usize));
}

#[test]
fn non_mtk_family_reports_full_image_unsupported_not_panic() {
    // Full-image path routes through the DriveFamily trait, so a family that
    // doesn't implement it (Unknown) returns "unsupported" rather than panicking —
    // dump degrades gracefully (omits fw.bin). (Pioneer/Renesas do implement it.)
    let drive = for_family(Family::Unknown);
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
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
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x06));
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
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x02));
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        true,
    );
    flash(&mut dev, &Mtk, &req).expect("benign NOT READY must not fail the flash");
}

#[test]
fn flash_execute_refuses_when_disc_loaded() {
    // A disc in the tray must hard-abort a --execute flash BEFORE any write —
    // reprogramming while the drive services a medium can wedge the controller.
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .with_medium_loaded();
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        true,
    );
    let err = flash(&mut dev, &Mtk, &req).expect_err("disc-loaded flash must be refused");
    assert!(
        err.to_string().contains("refusing to flash"),
        "unexpected error: {err}"
    );
    assert!(
        dev.writes.is_empty(),
        "no WRITE BUFFER may be issued when a disc is loaded"
    );
}

#[test]
fn flash_dryrun_warns_but_proceeds_when_disc_loaded() {
    // A dry run only WARNS on a loaded disc (no writes happen anyway), so the
    // operator still sees the full plan before committing.
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .with_medium_loaded();
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        false,
    );
    flash(&mut dev, &Mtk, &req).expect("dry run must not fail on a loaded disc");
    assert!(dev.writes.is_empty(), "dry run issues no writes");
}

#[test]
fn flash_execute_refuses_when_tray_open() {
    // An OPEN tray is not a settled flash state — refuse a --execute flash with a
    // distinct "close the tray" message, before any write.
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .with_tray_open();
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        true,
    );
    let err = flash(&mut dev, &Mtk, &req).expect_err("tray-open flash must be refused");
    assert!(
        err.to_string().contains("tray is OPEN"),
        "unexpected error: {err}"
    );
    assert!(
        dev.writes.is_empty(),
        "no WRITE BUFFER may be issued with the tray open"
    );
}

#[test]
fn flash_execute_proceeds_when_closed_empty() {
    // The default mock is a closed, empty tray (the only flash-safe state): the
    // medium guard must NOT block it, and the flash streams to completion.
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    let req = bin_req(
        make_flashable(patterned_image(IMAGE_SIZE), "BD-RE BU40N"),
        true,
    );
    flash(&mut dev, &Mtk, &req).expect("closed-empty tray must flash");
    assert!(
        !dev.writes.is_empty(),
        "a closed-empty flash must issue WRITE BUFFERs"
    );
}

#[test]
fn flash_close_fails_on_hardware_error_sense() {
    // A genuine HARDWARE ERROR (0x4) after the burn IS a real failure.
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on(|cdb| cdb.first() == Some(&0x03), fixed_sense(0x04));
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
    let tar = coherent_backup().to_tar_bytes().unwrap();
    let want = offset_bytes((CHUNK * 5) as u32);
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on_after_stream(
            move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&want[..]),
            vec![0xFFu8; CHUNK],
        );
    let mut req = bin_req(vec![], true);
    req.input = tar;
    req.input_kind = InputKind::Tar;
    req.drive_model = "BD-RE BU40N".into();
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(
        err.to_string().contains("read-back verify FAILED"),
        "unexpected error: {err}"
    );
}

// ---- write-path integrity + model gates (never write a bad image) ----------

#[test]
fn model_gate_accepts_a_matching_image() {
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    assert!(ensure_image_matches_drive(&img, "BU40N", Family::Mtk, false, None).is_ok());
}

#[test]
fn model_gate_refuses_a_wrong_model_image() {
    // A valid MT19xx image built for a DIFFERENT model than the drive reports.
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE WH16NS60");
    let err = ensure_image_matches_drive(&img, "BU40N", Family::Mtk, false, None).unwrap_err();
    assert!(err.to_string().contains("wrong-model"), "got: {err}");
}

#[test]
fn model_gate_refuses_a_non_mt19xx_image() {
    // No MTEKMT19 family tag at the descriptor → not a recognizable image.
    assert!(
        ensure_image_matches_drive(&vec![0u8; IMAGE_SIZE], "BU40N", Family::Mtk, false, None)
            .is_err()
    );
}

#[test]
fn model_gate_refuses_an_unknown_drive_product() {
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    assert!(ensure_image_matches_drive(&img, "   ", Family::Mtk, false, None).is_err());
}

#[test]
fn model_gate_refuses_a_truncated_image() {
    assert!(ensure_image_matches_drive(&[0u8; 0x1000], "BU40N", Family::Mtk, false, None).is_err());
}

#[test]
fn family_cross_gate_refuses_an_mt19xx_image_on_a_non_mtk_drive() {
    // A perfectly valid MT1959 image, but the connected drive classified as a
    // different silicon family — refuse across families, before any write.
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    let err = ensure_image_matches_drive(&img, "BU40N", Family::Pioneer, false, None).unwrap_err();
    assert!(
        err.to_string().contains("across silicon families"),
        "got: {err}"
    );
    assert!(ensure_image_matches_drive(&img, "BU40N", Family::Unknown, false, None).is_err());
}

// ---- crossflash gate (--allow-crossflash): waive model, never the family ------

use freemkv_chipset::ChipFamily;

#[test]
fn crossflash_refuses_cross_chip_family_even_with_the_flag() {
    // MT1959 image, but the drive's CURRENT firmware reads as MT1939 silicon:
    // an instant brick. --allow-crossflash must NOT override this.
    let err = decide_crossflash(
        ChipFamily::Mt1959,
        "BD-RE BU40N",
        "WH16NS60",
        Some(ChipFamily::Mt1939),
        true,
        true, // allow_crossflash
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("across chip families"),
        "got: {err}"
    );
}

#[test]
fn crossflash_waives_the_model_match_with_the_flag_same_family() {
    // Different model, same chipset (or unknown drive silicon) + the flag → allowed.
    let info = decide_crossflash(
        ChipFamily::Mt1959,
        "BD-RE BU40N",
        "WH16NS60",
        Some(ChipFamily::Mt1959),
        true, // de enabled
        true, // allow_crossflash
    )
    .unwrap()
    .expect("authorized crossflash");
    assert_eq!(info.image_family, ChipFamily::Mt1959);
    assert!(!info.warnings.iter().any(|w| w.contains("downgrade")));
}

#[test]
fn model_mismatch_is_refused_without_the_flag() {
    let err = decide_crossflash(
        ChipFamily::Mt1959,
        "BD-RE BU40N",
        "WH16NS60",
        None,
        true,
        false, // no crossflash
    )
    .unwrap_err();
    assert!(err.to_string().contains("wrong-model"), "got: {err}");
    assert!(err.to_string().contains("compatible image"), "got: {err}");
}

#[test]
fn crossflash_warns_when_image_is_not_downgrade_enabled() {
    let info = decide_crossflash(
        ChipFamily::Mt1959,
        "BD-RE BU40N",
        "WH16NS60",
        Some(ChipFamily::Mt1959),
        false, // DE NOT set → the drive will likely reject it
        true,
    )
    .unwrap()
    .expect("authorized crossflash");
    assert!(
        info.warnings
            .iter()
            .any(|w| w.contains("downgrade-enabled")),
        "warnings: {:?}",
        info.warnings
    );
}

#[test]
fn crossflash_warns_when_the_drive_silicon_is_unconfirmed() {
    // drive_fine_family = None → the sub-family gate could not be checked here.
    let info = decide_crossflash(
        ChipFamily::Mt1959,
        "BD-RE BU40N",
        "WH16NS60",
        None,
        true,
        true,
    )
    .unwrap()
    .expect("authorized crossflash");
    assert!(
        info.warnings.iter().any(|w| w.contains("MT1959 vs MT1939")),
        "warnings: {:?}",
        info.warnings
    );
}

#[test]
fn crossflash_requires_model_override_and_complete_backup() {
    // Two behaviours in one test:
    //
    // 1. Without `--allow-crossflash`, a wrong-model image is refused at the
    //    model-name gate regardless of drive firmware — the existing "model
    //    gate is authoritative" contract.
    //
    // 2. With `--allow-crossflash`, the sub-family gate (`MT1959` vs
    //    `MT1939`) becomes load-bearing and MUST be verified by reading the
    //    drive's current firmware. If that read succeeds but the bytes
    //    aren't identifiable as an MT19xx image (as here — the mock's
    //    default zero-fill response), the flash MUST refuse. Previously the
    //    engine used `.ok()` on `detect_chip` and silently treated an
    //    unidentifiable firmware as "family unknown, warn and proceed",
    //    which let a cross-family flash slip through on any drive whose
    //    firmware couldn't be identified — the exact class of brick this
    //    gate exists to prevent. See the codeaudit HIGH-1 fix in
    //    `engine.rs::flash` where `drive_fine_family` is now `?`-propagated.
    let image = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE WH16NS60");

    let refused = bin_req(image.clone(), true);
    assert!(
        flash(
            &mut MockScsiDevice::new().with_firmware_image(backup_firmware()),
            &Mtk,
            &refused
        )
        .is_err(),
        "wrong-model flash must refuse without --allow-crossflash"
    );

    let mut allowed = bin_req(image, true);
    allowed.allow_crossflash = true;
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    flash(&mut dev, &Mtk, &allowed).expect("same-silicon crossflash with full saved backup");
    assert!(dev.writes.iter().any(|(cdb, _)| is_stream_write(cdb)));
}

#[test]
fn flash_execute_refuses_an_unsigned_image_with_no_write() {
    // The brick guard: a model-matching image whose CMAC does NOT verify (empty
    // integrity table) must be refused before any firmware byte is streamed.
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
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
    // A failed pre-flash per-unit backup must abort the flash. A signed,
    // model-matching input ensures this test reaches the backup gate.
    let mut dev = MockScsiDevice::new()
        .with_firmware_image(backup_firmware())
        .on_fail(
            |cdb: &[u8]| is_mode6_read(cdb) && !is_identity_read(cdb),
            "dump read refused",
        );
    let req = bin_req(make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N"), true);
    let err = flash(&mut dev, &Mtk, &req).unwrap_err();
    assert!(
        format!("{err:#}").contains("backup needs every firmware byte"),
        "got: {err}"
    );
    assert!(
        !dev.writes.iter().any(|(cdb, _)| is_stream_write(cdb)),
        "no firmware bytes may be streamed after a failed backup"
    );
}

#[test]
fn dump_refuses_unreadable_firmware_without_creating_archive() {
    let gap = offset_bytes(0x100000);
    let mut dev = MockScsiDevice::new()
        .with_firmware_image(backup_firmware())
        .on_fail(
            move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&gap[..]),
            "unreadable main",
        );
    let out = fresh_backup_path();
    let err = backup(&mut dev, &Mtk, &out, false, false).unwrap_err();
    assert!(err.to_string().contains("backup needs every firmware byte"));
    assert!(!out.exists());
    assert!(dev.writes.is_empty());
}

#[test]
fn execute_refuses_unsaved_or_existing_backup_before_write() {
    let mut req = bin_req(backup_firmware(), true);
    req.predump_out = None;
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    assert!(flash(&mut dev, &Mtk, &req)
        .unwrap_err()
        .to_string()
        .contains("no preflash backup path"));
    assert!(dev.writes.is_empty());

    let out = fresh_backup_path();
    std::fs::write(&out, b"existing backup").unwrap();
    req.predump_out = Some(out.clone());
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    assert!(format!("{:#}", flash(&mut dev, &Mtk, &req).unwrap_err())
        .contains("existing backups are never overwritten"));
    assert!(dev.writes.is_empty());
    assert_eq!(std::fs::read(&out).unwrap(), b"existing backup");
    std::fs::remove_file(out).unwrap();
}

#[test]
fn restore_refuses_partial_or_corrupt_archive_without_write() {
    let complete = coherent_backup();
    let mut tar = complete.to_tar_bytes().unwrap();
    let needle = b"rom_1F0000.bin";
    let pos = tar.windows(needle.len()).position(|w| w == needle).unwrap();
    let body = pos + 512;
    tar[body] ^= 0x01;
    let mut req = bin_req(tar, true);
    req.input_kind = InputKind::Tar;
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    assert!(format!("{:#}", flash(&mut dev, &Mtk, &req).unwrap_err())
        .contains("per-unit regions do not match"));
    assert!(dev.writes.is_empty());

    req.input = sample_user_dump().to_tar_bytes().unwrap();
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    assert!(
        format!("{:#}", flash(&mut dev, &Mtk, &req).unwrap_err()).contains("missing backup.toml")
    );
    assert!(dev.writes.is_empty());
}

#[test]
fn restore_refuses_other_drive_backup_without_write() {
    let tar = coherent_backup().to_tar_bytes().unwrap();
    let mut req = bin_req(tar, true);
    req.input_kind = InputKind::Tar;
    req.drive_model = "WH16NS60".into();
    req.allow_crossflash = true;
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    assert!(flash(&mut dev, &Mtk, &req)
        .unwrap_err()
        .to_string()
        .contains("does not match the target drive"));
    assert!(dev.writes.is_empty());
}

#[test]
fn backup_refuses_image_per_unit_disagreement_without_write() {
    let mut artifact = coherent_backup();
    artifact.per_unit.rom_1f0000[0] ^= 1;
    let tar = artifact.to_tar_bytes().unwrap();
    let mut req = bin_req(tar, true);
    req.input_kind = InputKind::Tar;
    req.drive_model = "BD-RE BU40N".into();
    let mut dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    assert!(format!("{:#}", flash(&mut dev, &Mtk, &req).unwrap_err())
        .contains("disagree with firmware image"));
    assert!(dev.writes.is_empty());
}

#[test]
fn flash_execute_refuses_a_wrong_model_image_with_no_write() {
    // A correctly-signed image for a DIFFERENT model must never reach the write.
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE WH16NS60");
    let err = flash(&mut dev, &Mtk, &bin_req(img, true)).unwrap_err();
    assert!(err.to_string().contains("wrong-model"), "got: {err}");
    assert!(
        !dev.writes.iter().any(|(cdb, _)| is_stream_write(cdb)),
        "no firmware bytes may be streamed for a wrong-model image"
    );
}

// ---- info on a FILE (classify_file) ----

#[test]
fn classify_file_reports_a_valid_mt1959_image() {
    // A correctly-signed BU40N image classifies as MT1959 / BD-UHD / executable
    // / CMAC-valid — the `info <file>` happy path, no drive involved.
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    let fc = classify_file(&img);
    let chip = fc.chip.expect("recognized MT1959");
    assert_eq!(chip.family, freemkv_chipset::ChipFamily::Mt1959);
    assert!(chip.model.to_ascii_uppercase().contains("BU40N"));
    let cap = fc.capability.expect("capability");
    assert!(cap.bd_aacs);
    assert!(cap.media_class >= freemkv_chipset::MediaClass::Bd);
    let (_, status) = fc.flash.expect("MediaTek flash recipe");
    assert!(status.is_executable());
    assert!(
        matches!(fc.cmac, CmacSummary::Valid { .. }),
        "a signed image must report valid integrity"
    );
}

#[test]
fn classify_file_flags_a_corrupt_signed_image() {
    // Flip a byte inside a signed range → integrity must report Invalid.
    let mut img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    img[0x12000] ^= 0xFF;
    assert!(matches!(
        classify_file(&img).cmac,
        CmacSummary::Invalid { .. }
    ));
}

#[test]
fn classify_file_rejects_unrecognizable_bytes() {
    // Too small / no MTEKMT19xx tag → not a recognizable image (never panics),
    // and no capability/flash is inferred for an unrecognized image.
    assert!(classify_file(&[0u8; 100]).chip.is_none());
    assert!(classify_file(&vec![0xAAu8; IMAGE_SIZE]).chip.is_none());
    let fc = classify_file(&[0u8; 100]);
    assert!(fc.capability.is_none() && fc.flash.is_none());
    assert!(matches!(fc.cmac, CmacSummary::Unsigned));
}

#[test]
fn existing_preflash_destination_fails_before_capturing_the_drive() {
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let req = bin_req(backup_firmware(), true);
    let path = req.predump_out.as_ref().unwrap();
    std::fs::write(path, b"keep this rollback").unwrap();
    let result = flash(&mut dev, &Mtk, &req);
    std::fs::remove_file(path).unwrap();
    assert!(result.is_err());
    // Only the chip-gate identity reads (banner + descriptor) precede the
    // collision check; never the multi-minute firmware read.
    assert!(
        dev.reads.iter().all(|c| is_identity_read(c)),
        "do not spend minutes reading before finding a path collision"
    );
    assert!(dev.writes.is_empty());
}

#[test]
fn encrypted_upload_still_detects_corrupt_plaintext_readback() {
    let want = offset_bytes(0x10000);
    let mut dev = MockScsiDevice::new()
        .with_firmware_image(backup_firmware())
        .on_after_stream(
            move |cdb| is_mode6_read(cdb) && cdb.get(3..6) == Some(&want[..]),
            vec![0xff; CHUNK],
        );
    let mut req = bin_req(backup_firmware(), true);
    req.enc_override = Some(true);
    req.skip_backup = true;
    let error = flash(&mut dev, &Mtk, &req)
        .expect_err("encrypted transport must not disable integrity verification");
    assert!(error.to_string().contains("read-back verify FAILED"));
}

#[test]
fn forced_flash_skips_backup_without_device_io_or_file_creation() {
    let mut req = bin_req(backup_firmware(), true);
    req.force = true;
    let path = req.predump_out.clone().unwrap();
    for mut dev in [
        MockScsiDevice::new().with_firmware_image(backup_firmware()),
        MockScsiDevice::new(),
        MockScsiDevice::pioneer(),
    ] {
        let (summary, bytes) = capture_preflash_backup(&mut dev, &Mtk, &req).unwrap();
        assert!(bytes.is_none());
        assert!(summary.contains("SKIPPED (--force)"));
        assert!(dev.reads.is_empty());
        assert!(dev.writes.is_empty());
        assert!(!path.exists());
    }
    // Force does not require a destination or touch an existing backup.
    std::fs::write(&path, b"keep this rollback").unwrap();
    let mut dev = MockScsiDevice::new();
    capture_preflash_backup(&mut dev, &Mtk, &req).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"keep this rollback");
    std::fs::remove_file(&path).unwrap();
    req.predump_out = None;
    capture_preflash_backup(&mut dev, &Mtk, &req).unwrap();
    assert!(dev.reads.is_empty());
    assert!(dev.writes.is_empty());
}

#[test]
fn unforced_flash_still_requires_successful_backup() {
    let req = bin_req(backup_firmware(), true);
    let mut dev = MockScsiDevice::new();
    assert!(capture_preflash_backup(&mut dev, &Mtk, &req).is_err());
    assert!(!dev.reads.is_empty());
    assert!(dev.writes.is_empty());
}

#[test]
fn mediatek_dump_preserves_raw_unsigned_memory_without_requiring_backup_integrity() {
    let raw = vec![0x5a; IMAGE_SIZE];
    let mut dev = MockScsiDevice::new().with_firmware_image(raw.clone());
    assert_eq!(Mtk.capture_dump(&mut dev, true).unwrap(), raw);
    assert!(dev.writes.is_empty());
    assert!(Mtk.capture_backup(&mut dev).is_err());
}

#[test]
fn force_waives_model_identity_but_keeps_input_structure_checks() {
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    assert!(Mtk
        .validate_forced_image(&mut dev, &backup_firmware())
        .is_ok());
    // --force reads only the drive's identity, for the chip gate.
    assert!(dev.reads.iter().all(|c| is_identity_read(c)));
    assert!(Mtk
        .validate_forced_image(&mut dev, b"not a firmware image")
        .is_err());
    assert!(dev.writes.is_empty());
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
fn guard_no_medium_force_overrides_disc_and_open_tray() {
    // Non-force execute refuses a loaded disc or open tray (the safe default).
    let mut loaded = MockScsiDevice::new().with_medium_loaded();
    assert!(guard_no_medium(&mut loaded, true, false).is_err());
    let mut open = MockScsiDevice::new().with_tray_open();
    assert!(guard_no_medium(&mut open, true, false).is_err());

    // --force means force: the same states warn but proceed, because a
    // partially bricked drive routinely misreports its tray/medium.
    let mut loaded = MockScsiDevice::new().with_medium_loaded();
    assert!(guard_no_medium(&mut loaded, true, true).is_ok());
    let mut open = MockScsiDevice::new().with_tray_open();
    assert!(guard_no_medium(&mut open, true, true).is_ok());
}

#[test]
fn guard_no_medium_allows_closed_empty_regardless_of_force() {
    let mut dev = MockScsiDevice::new();
    assert!(guard_no_medium(&mut dev, true, false).is_ok());
    let mut dev = MockScsiDevice::new();
    assert!(guard_no_medium(&mut dev, true, true).is_ok());
}

#[test]
fn forced_tray_warning_does_not_claim_refusal() {
    use std::{cell::RefCell, rc::Rc};
    let messages = Rc::new(RefCell::new(Vec::new()));
    let sink = messages.clone();
    let mut dev = MockScsiDevice::pioneer().with_tray_open();
    crate::output::capture(
        move |line| sink.borrow_mut().push(line),
        || guard_no_medium(&mut dev, true, true),
    )
    .unwrap();
    let text = messages.borrow().join("\n");
    assert!(text.contains("tray is OPEN"));
    assert!(text.contains("Proceeding because --force"));
    assert!(!text.contains("refusing"));
}

#[test]
fn capture_is_saved_before_target_dependent_rollback_check() {
    use crate::drive::{Capabilities, Identity, ProbeEvidence};
    struct RejectUpdate {
        path: std::path::PathBuf,
    }
    impl DriveFamily for RejectUpdate {
        fn family(&self) -> Family {
            Family::Mtk
        }
        fn capabilities(&self) -> Capabilities {
            Mtk.capabilities()
        }
        fn backend_name(&self) -> &'static str {
            "rollback ordering test"
        }
        fn probe(&self, _: &mut dyn ScsiDevice, _: &Identity) -> Result<Option<ProbeEvidence>> {
            unreachable!()
        }
        fn capture_backup(&self, _: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
            Ok(backup_firmware())
        }
        fn validate_backup(&self, bytes: &[u8], model: &str) -> Result<Vec<u8>> {
            Mtk.validate_backup(bytes, model)
        }
        fn verify_preflash_backup(&self, bytes: &[u8], _: &[u8]) -> Result<()> {
            assert_eq!(
                std::fs::read(&self.path).expect("capture must already be saved"),
                bytes
            );
            bail!("target requires an uncaptured region")
        }
        fn image_size(&self) -> usize {
            Mtk.image_size()
        }
        fn chunk_size(&self) -> usize {
            Mtk.chunk_size()
        }
        fn envelope(
            &self,
            _: &mut dyn ScsiDevice,
            _: &[u8],
            _: Option<bool>,
        ) -> Result<(Vec<u8>, bool)> {
            unreachable!()
        }
        fn flash_plan(&self, _: usize, _: bool) -> Result<String> {
            unreachable!()
        }
        fn flash_stream(
            &self,
            _: &mut dyn ScsiDevice,
            _: &[u8],
            _: FlashMode,
            _: &mut dyn FnMut(usize),
        ) -> Result<()> {
            panic!("update prohibited")
        }
    }
    let req = bin_req(vec![], true);
    let path = req.predump_out.clone().unwrap();
    let backend = RejectUpdate { path: path.clone() };
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let error = capture_required_backup(&mut dev, &backend, &req).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("backup saved to"), "{message}");
    assert!(
        message.contains("target requires an uncaptured region"),
        "{message}"
    );
    assert!(path.exists());
    assert!(dev.writes.is_empty());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn chip_gate_refuses_cross_generation_images_even_forced() {
    // Drive: MT1959 (BU40N). Image: an MT1939 build with a matching model.
    let mut img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    let d = ROM_1EC000_OFFSET as usize;
    img[d + 0x34..d + 0x3E].copy_from_slice(b"MTEKMT1939");
    let img = crate::cmac::resign(&img).unwrap();
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let forced = Mtk.validate_forced_image(&mut dev, &img).unwrap_err();
    assert!(
        forced.to_string().contains("cannot be overridden"),
        "{forced}"
    );
    let normal = Mtk
        .validate_image(&mut dev, &img, "BD-RE BU40N", false)
        .unwrap_err();
    assert!(format!("{normal:#}").contains("MT1939"), "{normal:#}");
    assert!(dev.writes.is_empty());
}

#[test]
fn raw_drive_reads_are_never_flashable() {
    // A drive read's boot page is the read-back mirror of 0x10000; writing it
    // would store the wrong boot page. Refused with and without --force.
    let mut read = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    let mirror = read[0x1_0000..0x1_0400].to_vec();
    read[..0x400].copy_from_slice(&mirror);
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let forced = Mtk.validate_forced_image(&mut dev, &read).unwrap_err();
    assert!(forced.to_string().contains("raw drive read"), "{forced}");
    let normal = Mtk
        .validate_image(&mut dev, &read, "BD-RE BU40N", false)
        .unwrap_err();
    assert!(normal.to_string().contains("raw drive read"), "{normal}");
}

#[test]
fn unknown_boot_pages_need_force() {
    let mut img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    img[..0x400].fill(0x42);
    let mut dev = MockScsiDevice::new().with_firmware_image(backup_firmware());
    let err = Mtk
        .validate_image(&mut dev, &img, "BD-RE BU40N", false)
        .unwrap_err();
    assert!(err.to_string().contains("boot page"), "{err}");
    Mtk.validate_forced_image(&mut dev, &img).unwrap();
}

#[test]
fn chip_gate_refuses_when_the_descriptor_is_unreadable() {
    // A banner can name the wrong generation, so a tagged image needs the
    // drive's descriptor; an unreadable one refuses rather than failing open.
    let img = make_flashable(vec![0u8; IMAGE_SIZE], "BD-RE BU40N");
    let mut dev = MockScsiDevice::new()
        .with_firmware_image(backup_firmware())
        .on_fail(
            |cdb: &[u8]| cdb.get(3..6) == Some(&offset_bytes(ROM_1EC000_OFFSET)[..]),
            "descriptor read refused",
        );
    let err = Mtk.validate_forced_image(&mut dev, &img).unwrap_err();
    assert!(err.to_string().contains("identity descriptor"), "{err}");
}
