use super::*;
use freemkv_flash::cmac;

fn synthetic_image() -> Vec<u8> {
    let mut img = vec![0u8; 0x20000];
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        for b in &mut img[off..off + cmac::ENTRY_SIZE] {
            *b = 0xFF;
        }
    }
    let (start, end): (u32, u32) = (0x1000, 0x1FFF);
    let off = cmac::TABLE_OFFSET;
    img[off..off + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[off + 4..off + 8].copy_from_slice(&start.to_le_bytes());
    img[off + 8..off + 12].copy_from_slice(&end.to_le_bytes());
    let digest = cmac::compute_stored_digest(&img, start, end).unwrap();
    img[off + 12..off + 28].copy_from_slice(&digest);
    img
}

#[test]
fn verify_image_ok() {
    let img = synthetic_image();
    let (_, verdicts) = verify_image(&img, None).unwrap();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts.iter().all(|v| v.ok));
}

#[test]
fn sign_image_repairs_and_self_verifies() {
    let mut img = synthetic_image();
    img[0x1234] ^= 0xFF;
    let (_, signed, changes) = sign_image(&img, None).unwrap();
    assert_eq!(changes.len(), 1);
    let (_, verdicts) = verify_image(&signed, None).unwrap();
    assert!(verdicts.iter().all(|v| v.ok));
}

#[test]
fn unrecognized_image_is_clean_error() {
    let zeros = vec![0u8; 0x20000];
    assert!(verify_image(&zeros, None).is_err());
}

#[test]
fn default_signed_path_uses_stem() {
    let p = default_signed_path(Path::new("/tmp/fw.bin"));
    assert_eq!(p, PathBuf::from("/tmp/fw.signed.bin"));
}

#[test]
fn default_created_path_uses_stem() {
    let p = default_created_path(Path::new("/tmp/fw.bin"));
    assert_eq!(p, PathBuf::from("/tmp/fw.freemkv.bin"));
}

// -- verify's file-vs-device dispatch ------------------------------------

#[test]
fn classify_plain_path_is_file() {
    // Doesn't exist, doesn't look like a device path: treated as a file so
    // the ordinary "no such file" error still fires.
    assert_eq!(
        classify_verify_target(Path::new("/tmp/does-not-exist-freemkv-fw.bin")),
        VerifyTarget::File
    );
    assert_eq!(
        classify_verify_target(Path::new("firmware.bin")),
        VerifyTarget::File
    );
}

#[test]
fn classify_dev_prefixed_path_is_device() {
    // Purely path-based: doesn't need the node to actually exist, so this
    // runs the same on every host including CI.
    assert_eq!(
        classify_verify_target(Path::new("/dev/sg1")),
        VerifyTarget::Device
    );
    assert_eq!(
        classify_verify_target(Path::new("/dev/rdisk4")),
        VerifyTarget::Device
    );
}

#[test]
fn classify_existing_regular_file_is_file() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("freemkv-fw-classify-test-{}", std::process::id()));
    std::fs::write(&path, b"not a device").unwrap();
    assert_eq!(classify_verify_target(&path), VerifyTarget::File);
    let _ = std::fs::remove_file(&path);
}

/// Requires a real character/block special file (e.g. a real drive node)
/// to exercise the metadata branch on an actual device; not runnable in
/// CI. Gated out by default.
#[test]
#[ignore = "requires real hardware: a live device node to probe"]
fn classify_real_device_node_is_device() {
    // Point this at a real device (e.g. `/dev/rdisk4` or `/dev/sg1`) when
    // running manually against attached hardware.
    let path = std::env::var("FREEMKV_FW_TEST_DEVICE").expect("set FREEMKV_FW_TEST_DEVICE");
    assert_eq!(
        classify_verify_target(Path::new(&path)),
        VerifyTarget::Device
    );
}
