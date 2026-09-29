//! Unit tests for the Pioneer OEM protocol (offline OEM protocol plan,
//! backup and live flash gated off).

use super::*;
use crate::drive::{for_family, Family};
use crate::manifest::FlashMode;
use crate::platform::MockScsiDevice;

fn pioneer_corpus_root() -> std::path::PathBuf {
    std::env::var_os("FWEXT_HOARD")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(4)
                .expect("freemkv-flash crate must be inside the freemkv checkout")
                .join("firmware-extractor/hoard")
        })
}

// ---- Proven CDB layouts (byte-for-byte) -------------------------------------

// ---- classify → no restorable dump ------------------------------------------

#[test]
fn pioneer_classifies_but_cannot_dump_without_restorable_format() {
    let mut dev = MockScsiDevice::pioneer();
    assert_eq!(crate::drive::classify(&mut dev), Family::Pioneer);
    dev.reads.clear(); // classification probes are separate from the blocked dump API

    let drive = for_family(Family::Pioneer);
    assert!(!drive.dump_supported());
    assert!(drive.read_full_image(&mut dev).is_err());
    assert!(drive.read_dump(&mut dev).is_err());
    assert!(drive.readback(&mut dev, 0, 0xA4).is_err());
    assert!(dev.writes.is_empty());
    assert!(dev.reads.is_empty());
}

// ---- Pioneer flash primitives (unit-level, no live drive) -------------------

#[test]
fn ud04_kernel_key_lookup_returns_oem_memory_order() {
    let k = key_for("PIONEER BD-RW   BDR-UD04").expect("UD04 key present");
    assert_eq!(k.key, 0xFD23_6642);
    assert_eq!(k.layout, KeyLayout::Array);
    // Case + whitespace insensitivity.
    assert!(key_for("pioneer   bdr-ud04  ").is_some());
    // Unknown model → no key.
    assert!(key_for("PIONEER BD-RW BDR-FAKE99").is_none());
}

#[test]
fn banner_parses_ud04_1_11eu_header() {
    // Reconstruct the plaintext banner shape (matches the on-disk BDR-UD04
    // 1.11EU header). All fields must round-trip through `parse_banner`.
    let mut hdr = Vec::new();
    hdr.extend_from_slice(PIONEER_MAGIC);
    hdr.extend_from_slice(
        b"    \r\nThis is microcode file.  \r\nID : PIONEER BD-RW   BDR-UD04.\
          \r\nRevision Level : 1.11 .\r\nHardware Version : SAT 8A10.\r\n\
          Destination : GENERAL.\r\nFile Type : Normal.\r\n",
    );
    let b = parse_banner(&hdr).expect("banner parses");
    assert_eq!(b.model, "BDR-UD04");
    assert_eq!(b.revision, "1.11");
    assert_eq!(b.hardware, "SAT 8A10");
    assert_eq!(b.destination, "GENERAL");
    assert_eq!(b.file_type, "Normal");
}

#[test]
fn flash_cdbs_match_the_proven_bytes() {
    assert_eq!(
        cdb_wb_flash_entry(),
        [0x3B, 0x04, 0xFF, 0, 0, 0, 0, 1, 0, 0],
    );
    assert_eq!(
        cdb_wb_flash_chunk(0x8000, 0x8000),
        [0x3B, 0x07, 0xF0, 0x00, 0x80, 0x00, 0x00, 0x80, 0x00, 0]
    );
    assert_eq!(
        cdb_wb_flash_chunk(0x1D0000, 0x7000),
        [0x3B, 0x07, 0xF0, 0x1D, 0, 0, 0, 0x70, 0, 0]
    );
    assert_eq!(
        cdb_wb_flash_finish(),
        [0x3B, 0x05, 0xFF, 0, 0, 0, 0, 1, 0, 0]
    );
}

#[test]
fn ud04_oem_control_payload_matches_full_static_construction() {
    use sha2::{Digest, Sha256};

    let payload = ud04_oem_control_payload();
    assert_eq!(payload.len(), 256);
    assert_eq!(&payload[..16], b"PIONEER BDR-US04");
    assert_eq!(&payload[16..20], &[0x42, 0x66, 0x23, 0xFD]);
    assert!(payload[20..].iter().all(|&b| b == 0));
    assert_eq!(
        format!("{:x}", Sha256::digest(payload)),
        "b2d58e59403a858c7be55b6726ee816741f4783f40fabd0cc64b120ebf525020"
    );
}

#[test]
fn s09_v130_control_payload_has_updater_descriptor_not_envelope_model() {
    use sha2::{Digest, Sha256};
    let payload = s09_v130_oem_control_payload();
    assert_eq!(&payload[..16], b"PIONEER  BDR-209");
    assert_eq!(&payload[16..20], &[0x98, 0x2B, 0x1F, 0xCE]);
    assert!(payload[20..].iter().all(|&b| b == 0));
    assert_eq!(payload.len(), 0x100);
    assert_eq!(
        format!("{:x}", Sha256::digest(payload)),
        "6588a8422698617330e1845086d1f9008167c3cd7e0d131458830ed18d61b621"
    );
}

#[test]
fn s09_v130_real_oem_envelope_transcript() {
    use sha2::{Digest, Sha256};
    let path = pioneer_corpus_root().join("models/BDR-S09/firmware/1.30EU/BDR-S09_FW130EU.enc");
    if !path.exists() {
        return;
    }
    let image = std::fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&image)),
        OemUpdateProfile::S09V130Normal
            .evidence()
            .reference_envelope_sha256
    );
    assert_eq!(
        select_oem_profile("PIONEER BD-RW   BDR-S09", &image).unwrap(),
        OemUpdateProfile::S09V130Normal
    );
    assert!(select_oem_profile("BDR-209", &image).is_err());
    let mut wrong_hardware = image.clone();
    let hardware = b"SAT 8600";
    let offset = wrong_hardware
        .windows(hardware.len())
        .position(|w| w == hardware)
        .unwrap();
    wrong_hardware[offset + 7] = b'1';
    assert!(select_oem_profile("BDR-S09", &wrong_hardware).is_err());
    let mut wrong_revision = image.clone();
    let revision = b"1.30";
    let offset = wrong_revision
        .windows(revision.len())
        .position(|w| w == revision)
        .unwrap();
    wrong_revision[offset + 3] = b'1';
    assert!(select_oem_profile("BDR-S09", &wrong_revision).is_err());
    assert_eq!(
        OemUpdateProfile::S09V130Normal.envelope_evidence(&image),
        EnvelopeEvidence::ExactOemReference
    );
    let transfers = offline_oem_transcript(OemUpdateProfile::S09V130Normal, &image).unwrap();
    assert_eq!(transfers.len(), 61);
    assert_eq!(transfers[0].data.as_ref(), s09_v130_oem_control_payload());
    assert_eq!(transfers[59].cdb, cdb_wb_flash_chunk(0x1D0000, 0x900));
    assert_eq!(transfers[59].data.as_ref(), &image[0x1D0000..]);
    let mut digest = Sha256::new();
    for transfer in &transfers[1..60] {
        digest.update(&transfer.data);
    }
    assert_eq!(
        format!("{:x}", digest.finalize()),
        format!("{:x}", Sha256::digest(image))
    );
}

#[test]
fn s09_aeu_updater_shares_the_audited_normal_transfer_profile() {
    let evidence = OemUpdateProfile::S09V130Normal.evidence();
    assert_eq!(
        evidence.alternate_updater_sha256,
        Some("2869613b666f20c6c404e2fbabc98a525888c3676da106154e20476d934bdea6")
    );
    assert_eq!(
        evidence.reference_envelope_sha256,
        "7f391cf35bc727bbefc97b3b27786283a6e8e5ca1d82f71dc57c78633843c59f"
    );
}

#[test]
fn bdr212_dynamic_stage_is_explicit_and_seeded_generator_matches_crt() {
    use sha2::{Digest, Sha256};
    assert_eq!(BDR212_V105_STAGES[0], Bdr212Stage::EntryControl);
    assert_eq!(
        BDR212_V105_STAGES[1],
        Bdr212Stage::KernelPrefix {
            source_offset: 0,
            length: 0x1200
        }
    );
    assert_eq!(
        BDR212_V105_STAGES[2],
        Bdr212Stage::GeneratedKernelBlock { length: 0x200 }
    );
    assert_eq!(
        BDR212_V105_STAGES[6],
        Bdr212Stage::KernelFe {
            cdb_offset: 0x11200,
            source_offset: 0x10200,
            length: 0x1000
        }
    );
    assert_eq!(
        BDR212_V105_STAGES[7],
        Bdr212Stage::NormalEnvelope { length: 0x1d7600 }
    );
    assert_eq!(BDR212_V105_STAGES[8], Bdr212Stage::FinishControl);
    let block = bdr212_generated_kernel_block(0);
    assert_eq!(
        &block[..16],
        &[
            0x26, 0x27, 0xf6, 0x85, 0x97, 0x15, 0xad, 0x1d, 0xd2, 0x94, 0xdd, 0xc4, 0x76, 0x19,
            0x39, 0x31
        ]
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(block)),
        "e9687a87ce390b005b343fd185e357587948c16b15aa4ed55fb467ce733866da"
    );
}

#[test]
fn bdr212_v105_exact_resources_materialize_seeded_data_out_only() {
    use sha2::{Digest, Sha256};
    let corpus_root = pioneer_corpus_root();
    let base = corpus_root.join("models/BDR-212/firmware/1.05EU");
    let kernel_path = base.join("BDR-212_ULBK_EBK_FW105EU_kernel.enc");
    let normal_path = base.join("BDR-212_ULBK_EBK_FW105EU_main.enc");
    if !kernel_path.exists() || !normal_path.exists() {
        return;
    }
    let kernel = std::fs::read(kernel_path).unwrap();
    let normal = std::fs::read(normal_path).unwrap();
    let transfers = offline_bdr212_v105_data_out(&kernel, &normal, 0).unwrap();
    assert_eq!(transfers.len(), 66); // entry + prefix + 4 FE + 59 Normal + finish
    assert_eq!(transfers[0].cdb, cdb_wb_flash_entry());
    assert_eq!(
        format!("{:x}", Sha256::digest(&transfers[0].data)),
        "506030191e30ed5c6a6af3483ceb216b76e5d0d2c25018bfcadb6fbe61c72dbe"
    );
    assert_eq!(transfers[1].stage, TransferStage::KernelPrefix);
    assert_eq!(transfers[1].data.as_ref(), &kernel[..0x1200]);
    assert_eq!(transfers[2].cdb, cdb_write_buffer(0x07, 0xFE, 0, 0x200));
    assert_eq!(transfers[2].data.as_ref(), bdr212_generated_kernel_block(0));
    assert_eq!(
        transfers[5].cdb,
        cdb_write_buffer(0x07, 0xFE, 0x11200, 0x1000)
    );
    assert_eq!(transfers[5].data.as_ref(), &kernel[0x10200..0x11200]);
    assert_eq!(transfers.last().unwrap().cdb, cdb_wb_flash_finish());
    assert_eq!(transfers.last().unwrap().data, transfers[0].data);
    let mut digest = Sha256::new();
    for transfer in &transfers[6..65] {
        digest.update(&transfer.data);
    }
    assert_eq!(
        format!("{:x}", digest.finalize()),
        format!("{:x}", Sha256::digest(&normal))
    );
    let mut bad = kernel.clone();
    bad[0x300] ^= 1;
    assert!(offline_bdr212_v105_data_out(&bad, &normal, 0).is_err());
    let mut bad = normal.clone();
    bad[0x300] ^= 1;
    assert!(offline_bdr212_v105_data_out(&kernel, &bad, 0).is_err());
}

#[test]
fn bounded_profile_table_has_verified_shape_and_no_duplicate_resource_pairs() {
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    assert_eq!(BOUNDED_PROFILES.len(), 46);
    assert_eq!(
        BOUNDED_PROFILES
            .iter()
            .filter(|p| p.unique_executable)
            .count(),
        38
    );
    let mut pairs = HashSet::new();
    for profile in BOUNDED_PROFILES {
        assert_eq!(profile.kernel_len, 0x11200);
        assert_eq!(profile.control_header.len(), 16);
        assert_eq!(profile.source_sha256.len(), 64);
        assert_eq!(profile.updater_sha256.len(), 64);
        assert!(pairs.insert((profile.kernel_sha256, profile.normal_sha256)));
        let mut control = [0u8; 0x100];
        control[..16].copy_from_slice(&profile.control_header);
        control[16..20].copy_from_slice(&profile.key.to_le_bytes());
        assert_eq!(
            format!("{:x}", Sha256::digest(control)),
            profile.control_sha256
        );
    }
}

#[test]
fn ud04_offline_transcript_matches_oem_cdb_and_payload_shape() {
    let image = synthetic_pioneer_image("BDR-UD04", 0x1D7000);
    assert_eq!(
        OemUpdateProfile::Ud04V111Normal.envelope_evidence(&image),
        EnvelopeEvidence::UncertifiedCandidate
    );
    let transfers = offline_oem_transcript(OemUpdateProfile::Ud04V111Normal, &image).unwrap();
    assert_eq!(transfers.len(), 61); // entry + 59 chunks + finish
    assert_eq!(transfers[0].stage, TransferStage::Entry);
    assert_eq!(transfers[0].cdb, [0x3B, 0x04, 0xFF, 0, 0, 0, 0, 1, 0, 0]);
    assert_eq!(transfers[0].data.as_ref(), ud04_oem_control_payload());
    assert_eq!(transfers[1].stage, TransferStage::Normal);
    assert_eq!(transfers[1].cdb, [0x3B, 0x07, 0xF0, 0, 0, 0, 0, 0x80, 0, 0]);
    assert_eq!(transfers[1].data.as_ref(), &image[..0x8000]);
    assert_eq!(
        transfers[59].cdb,
        [0x3B, 0x07, 0xF0, 0x1D, 0, 0, 0, 0x70, 0, 0]
    );
    assert_eq!(transfers[59].data.as_ref(), &image[0x1D0000..]);
    assert_eq!(transfers[60].stage, TransferStage::Finish);
    assert_eq!(transfers[60].cdb, [0x3B, 0x05, 0xFF, 0, 0, 0, 0, 1, 0, 0]);
    assert_eq!(transfers[60].data.as_ref(), ud04_oem_control_payload());
    let assembled: Vec<u8> = transfers[1..60]
        .iter()
        .flat_map(|transfer| transfer.data.iter().copied())
        .collect();
    assert_eq!(assembled, image);
}

#[test]
fn ud04_offline_transcript_rejects_other_model_and_unaligned_size() {
    let other = synthetic_pioneer_image("BDR-212", 0x1D7000);
    assert!(offline_oem_transcript(OemUpdateProfile::Ud04V111Normal, &other).is_err());
    let unaligned = synthetic_pioneer_image("BDR-UD04", 0x1D7001);
    assert!(offline_oem_transcript(OemUpdateProfile::Ud04V111Normal, &unaligned).is_err());
}

#[test]
fn ud04_profile_selection_requires_drive_and_envelope_structure() {
    let mut image = synthetic_pioneer_image("BDR-UD04", 0x1D7000);
    assert!(select_oem_profile("BDR-212", &image).is_err());
    assert!(select_oem_profile("BDR-UD04", &image).is_err()); // TEST destination
    let old = b"Destination : TEST.";
    let new = b"Destination : GENERAL.\r\nFile Type : Normal.\r\n";
    let i = image.windows(old.len()).position(|w| w == old).unwrap();
    image[i..i + new.len()].copy_from_slice(new);
    assert_eq!(
        select_oem_profile("PIONEER BD-RW   BDR-UD04", &image).unwrap(),
        OemUpdateProfile::Ud04V111Normal
    );
    assert_eq!(
        OemUpdateProfile::Ud04V111Normal.evidence().components,
        UpdateComponents::NormalOnly
    );
}

#[test]
fn ud04_local_oem_envelope_transcript_when_configured() {
    use sha2::{Digest, Sha256};
    let Ok(path) = std::env::var("PIONEER_UD04_ENC_FIXTURE") else {
        return;
    };
    let image = std::fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&image)),
        "a5aa757081478620637ed2950b540f35f1cbb969598532cfc872daba0a0366e6"
    );
    let transfers = offline_oem_transcript(OemUpdateProfile::Ud04V111Normal, &image).unwrap();
    assert_eq!(
        OemUpdateProfile::Ud04V111Normal.envelope_evidence(&image),
        EnvelopeEvidence::ExactOemReference
    );
    assert_eq!(
        select_oem_profile("BDR-UD04", &image).unwrap(),
        OemUpdateProfile::Ud04V111Normal
    );
    assert_eq!(transfers.len(), 61);
    let mut digest = Sha256::new();
    for transfer in &transfers[1..60] {
        digest.update(&transfer.data);
    }
    assert_eq!(
        format!("{:x}", digest.finalize()),
        format!("{:x}", Sha256::digest(image))
    );
}

#[test]
fn flash_plan_states_execution_blockers() {
    let plan = Pioneer::new().flash_plan(0x1D7000, false).unwrap();
    assert!(plan.contains("59 raw-envelope chunks"));
    assert!(plan.contains("Execution is blocked"));
}

#[test]
fn verbose_plan_uses_actual_variable_image_length() {
    let plan = Pioneer::new().flash_plan(0x1D7100, true).unwrap();
    assert!(plan.contains("59 raw-envelope chunks"));
    assert!(plan.contains("chunk  1D0000  07100  [3B, 07, F0, 1D, 00, 00, 00, 71, 00, 00]"));
    assert!(plan.contains("entry  [3B, 04, FF, 00, 00, 00, 00, 01, 00, 00]"));
    assert!(plan.contains("finish [3B, 05, FF, 00, 00, 00, 00, 01, 00, 00]"));
}

#[test]
fn preflight_refuses_arbitrary_bytes() {
    let img = vec![0u8; IMAGE_MIN + 1];
    let id = Identity {
        vendor: "PIONEER".into(),
        product: "BDR-UD04".into(),
        revision: "1.14".into(),
        banner: None,
    };
    let e = preflight(&img, &id, false).unwrap_err().to_string();
    assert!(e.contains("Pioneer magic"), "actual: {e}");
}

#[test]
fn preflight_refuses_when_size_out_of_range() {
    let mut img = Vec::new();
    img.extend_from_slice(PIONEER_MAGIC);
    let id = Identity {
        vendor: "PIONEER".into(),
        product: "BDR-UD04".into(),
        revision: "1.14".into(),
        banner: None,
    };
    let e = preflight(&img, &id, false).unwrap_err().to_string();
    assert!(
        e.contains("outside the plausible Pioneer range"),
        "actual: {e}"
    );
}

#[test]
fn preflight_refuses_mismatched_model_without_crossflash() {
    let img = synthetic_pioneer_image("BDR-212", 0x0011_0000);
    let id = Identity {
        vendor: "PIONEER".into(),
        product: "BDR-UD04".into(),
        revision: "1.14".into(),
        banner: None,
    };
    let e = preflight(&img, &id, false).unwrap_err().to_string();
    assert!(e.contains("does not match"), "actual: {e}");
    // With crossflash allowed, it moves past the model check and now hits the
    // key gate for BDR-UD04 — that succeeds → preflight OK.
    let ok = preflight(&img, &id, true).unwrap();
    assert_eq!(ok.key.key, 0xFD23_6642);
}

#[test]
fn preflight_refuses_when_no_key_on_file() {
    let img = synthetic_pioneer_image("BDR-FAKE99", 0x0011_0000);
    let id = Identity {
        vendor: "PIONEER".into(),
        product: "BDR-FAKE99".into(),
        revision: "9.99".into(),
        banner: None,
    };
    let e = preflight(&img, &id, false).unwrap_err().to_string();
    assert!(e.contains("no kernel key on file"), "actual: {e}");
}

#[test]
fn flash_open_fails_before_any_write() {
    let mut dev = pioneer_with_inquiry("BDR-UD04");
    let drive = super::Pioneer::new();
    assert!(drive.flash_open(&mut dev, FlashMode::Full).is_err());
    assert!(drive.flash_chunk(&mut dev, 0, &[0x5A; 32]).is_err());
    assert!(drive.flash_close(&mut dev, FlashMode::Full).is_err());
    assert!(dev.writes.is_empty());
}

#[test]
fn flash_chunk_and_close_fail_without_open() {
    let mut dev = pioneer_with_inquiry("BDR-UD04");
    let drive = Pioneer::new();
    assert!(drive.flash_chunk(&mut dev, 0, &[0x5A; 32]).is_err());
    assert!(drive.flash_close(&mut dev, FlashMode::Full).is_err());
    assert!(dev.writes.is_empty());
}

/// A Pioneer mock plus a configured INQUIRY response: vendor `PIONEER`,
/// product = `product` padded to 16 chars, revision `1.14`.
fn pioneer_with_inquiry(product: &str) -> MockScsiDevice {
    let mut inq = vec![0u8; 96];
    inq[8..16].copy_from_slice(b"PIONEER ");
    let mut prod16 = [b' '; 16];
    let bytes = product.as_bytes();
    prod16[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
    inq[16..32].copy_from_slice(&prod16);
    inq[32..36].copy_from_slice(b"1.14");
    MockScsiDevice::pioneer().on(|cdb| cdb.first() == Some(&0x12), inq)
}

fn synthetic_pioneer_image(model: &str, len: usize) -> Vec<u8> {
    let mut img = vec![0u8; len];
    let header = format!(
        "********  Copyright(c) 2000 Pioneer Corporation  ********     \r\n\
         This is microcode file.  \r\n\
         ID : PIONEER BD-RW   {model}.\r\n\
         Revision Level : 9.99 .\r\n\
         Hardware Version : SAT 8A10.\r\n\
         Destination : TEST.\r\n\
         File Type : Normal.\r\n"
    );
    let bytes = header.as_bytes();
    img[..bytes.len()].copy_from_slice(bytes);
    img
}
