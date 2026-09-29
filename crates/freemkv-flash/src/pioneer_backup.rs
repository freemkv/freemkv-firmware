//! Offline image-to-envelope reconstruction. This does not establish that a
//! capture came from persistent flash, covers all writable state, or can restore
//! a drive. Live backup/flash capability remains gated separately.

use crate::pioneer_bundle::{Bundle, Role};
use crate::platform::ScsiDevice;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Build an encrypted UD04 package directly from two captured images. The
/// public point in its Normal header belongs to a fresh caller-owned key;
/// drive-side trust and restore are not established by this constructor.
pub fn construct_ud04_signed_candidate(
    kernel: &[u8],
    normal: &[u8],
    envelope_id: &str,
    revision: &str,
) -> Result<Vec<u8>> {
    let date = std::str::from_utf8(
        normal
            .get(0x18bb6b..0x18bb73)
            .context("captured Normal date is missing")?,
    )?;
    let mut seeds = [0u8; 6];
    getrandom::fill(&mut seeds)
        .map_err(|e| anyhow::anyhow!("generating fresh Pioneer encoding tables: {e}"))?;
    let kernel_seed = u32::from_be_bytes([0, seeds[0], seeds[1], seeds[2]]);
    let normal_seed = u32::from_be_bytes([0, seeds[3], seeds[4], seeds[5]]);
    let signer = pioneer_codec::signature::SigningKey::random().map_err(|e| anyhow::anyhow!(e))?;
    let input = pioneer_codec::builder::Ud04BuildInputs {
        kernel_image: kernel,
        normal_image: normal,
        envelope_id,
        normal_revision: revision,
        normal_date: date,
        kernel_key_seed: kernel_seed,
        normal_key_seed: normal_seed,
    };
    let pair = pioneer_codec::builder::encode_ud04_encrypted_pair(&input, &signer)
        .map_err(|e| anyhow::anyhow!(e))?;
    let mut tar = tar::Builder::new(Vec::new());
    for bytes in [&pair.kernel, &pair.normal] {
        let embedded = bytes[0x1f0..0x200]
            .split(|byte| *byte == 0)
            .next()
            .context("generated envelope filename missing")?;
        let embedded = std::str::from_utf8(embedded)?;
        if embedded.is_empty()
            || !embedded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        {
            bail!("generated envelope filename is invalid");
        }
        let path = format!("components/{embedded}.enc");
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, path, bytes.as_slice())?;
    }
    let out = tar.into_inner()?;
    validate_signed_candidate(&out, "BDR-UD04")?;
    Ok(out)
}

/// Structural, codec and signature checks for a generated encrypted pair.
/// This intentionally does not claim that a physical drive trusts its key.
pub fn validate_signed_candidate(bytes: &[u8], product: &str) -> Result<()> {
    let bundle = Bundle::from_tar_bytes(bytes)?;
    if bundle.components.len() != 2 {
        bail!("UD04 signed candidate requires Kernel and Normal");
    }
    let kernel = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .context("signed candidate Kernel is missing")?;
    let normal = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .context("signed candidate Normal is missing")?;
    validate_signed_pair(&kernel.bytes, &normal.bytes, product)
}

/// Validate the two envelope members of a UD04 candidate without a tar wrapper.
pub fn validate_signed_pair(kernel: &[u8], normal: &[u8], product: &str) -> Result<()> {
    if !product.split_whitespace().any(|s| s == "BDR-UD04") {
        bail!("signed candidate is only established for BDR-UD04");
    }
    let kh = pioneer_codec::header_info(kernel).context("invalid Kernel header")?;
    let nh = pioneer_codec::header_info(normal).context("invalid Normal header")?;
    if kh.model != "BDR-UD04"
        || nh.model != kh.model
        || kh.hardware_version != "SAT 8A10"
        || nh.hardware_version != kh.hardware_version
        || kh.revision != "BKP"
        || nh.revision != "1.14"
        || kh.destination != "GENERAL"
        || nh.destination != "GENERAL"
    {
        bail!("signed candidate identity does not match the UD04 capture profile");
    }
    let decoded_kernel = pioneer_codec::decode_envelope(kernel)
        .context("signed candidate Kernel cannot be decoded")?;
    let decoded_normal = pioneer_codec::decode_envelope_with_kernel(normal, &decoded_kernel)
        .context("signed candidate Normal cannot be receiver-decoded")?;
    pioneer_codec::builder::validate_ud04_encrypted_pair(
        &pioneer_codec::builder::Ud04EncryptedPair {
            kernel: kernel.to_vec(),
            normal: normal.to_vec(),
        },
        &decoded_kernel.image,
        &decoded_normal.image,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if !zero_be32_sum(&decoded_kernel.image) || !zero_be32_sum(&decoded_normal.image) {
        bail!("signed candidate decoded checksum is invalid");
    }
    Ok(())
}

/// Read bounded live UD04 regions twice and save a self-signed encrypted
/// package candidate. This issues no flash commands.
pub fn capture_signed_candidate(dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
    let (kernel, normal, revision, envelope_id) = read_ud04_pair(dev)?;
    construct_ud04_signed_candidate(&kernel, &normal, &envelope_id, &revision)
}

fn zero_be32_sum(image: &[u8]) -> bool {
    image.len() % 4 == 0
        && image.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
        }) == 0
}

fn backup_header(
    id: &str,
    revision: &str,
    hardware: &str,
    kernel_tag: &str,
    role: &str,
    kernel_version2: &str,
) -> Result<Vec<u8>> {
    let lines = format!(
        "********  Copyright(c) 2000 Pioneer Corporation  ********\r\n\
         This is microcode file.\r\n\
         ID : {id}\r\n\
         Revision Level : {revision}\r\n\
         Hardware Version : {hardware}\r\n\
         Kernel Version : {kernel_tag}\r\n\
         Destination : BACKUP\r\n\
         File Type : {role}\r\n\
         Generated Date : BACKUP\r\n\
         Kernel Version2 : {kernel_version2}\r\n"
    );
    if lines.len() > 0x160
        || [id, revision, hardware, kernel_tag, role, kernel_version2]
            .iter()
            .any(|s| s.is_empty() || !s.is_ascii() || s.bytes().any(|b| b < 0x20 || b == 0x7f))
    {
        bail!("invalid synthetic Pioneer backup identity");
    }
    let mut header = vec![0; 0x200];
    header[..lines.len()].copy_from_slice(lines.as_bytes());
    Ok(header)
}

/// Construct a UD04 raw-path package from the two captured images alone.
/// This matches the receiver's traced plaintext framing; it is an offline
/// candidate until transfer and persistent restore have been exercised.
pub fn construct_ud04_plain_candidate(
    kernel: &[u8],
    normal: &[u8],
    inquiry_revision: &str,
) -> Result<Vec<u8>> {
    if kernel.len() != 0x10000
        || normal.len() < 0x2000
        || normal.len() % 0x100 != 0
        || !zero_be32_sum(kernel)
        || !zero_be32_sum(normal)
    {
        bail!("UD04 raw image length or checksum is invalid");
    }
    let hardware = std::str::from_utf8(&kernel[0x1000..0x1008])?.trim();
    let kernel_tag = std::str::from_utf8(&kernel[0x1008..0x1010])?.trim();
    let kernel_version2 = std::str::from_utf8(&kernel[0x1010..0x1014])?.trim();
    let id = std::str::from_utf8(&normal[..16])?.trim();
    if hardware != "SAT 8A10"
        || id != "PIONEER BDR-US04"
        || kernel_tag.is_empty()
        || kernel_version2.is_empty()
        || u32::from_be_bytes(normal[20..24].try_into().unwrap()) as usize != normal.len()
    {
        bail!("captured images do not satisfy the traced UD04 raw receiver identity");
    }
    let mut k = backup_header(
        id,
        "BACKUP",
        hardware,
        kernel_tag,
        "Kernel",
        kernel_version2,
    )?;
    k.resize(0x1200, 0);
    k.extend_from_slice(kernel);
    let mut n = backup_header(
        id,
        inquiry_revision,
        hardware,
        kernel_tag,
        "Normal",
        kernel_version2,
    )?;
    n.resize(0x10200, 0);
    n.extend_from_slice(normal);
    let mut tar = tar::Builder::new(Vec::new());
    for (path, bytes) in [
        ("components/backup-kernel.enc", &k),
        ("components/backup-normal.enc", &n),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, path, bytes.as_slice())?;
    }
    let out = tar.into_inner()?;
    Bundle::from_tar_bytes(&out).context("synthetic backup package failed intake")?;
    Ok(out)
}

fn reference_pair(bytes: &[u8]) -> Result<Bundle> {
    let bundle = Bundle::from_tar_bytes(bytes)?;
    if bundle.components.len() != 2 {
        bail!("UD04 backup template requires Kernel and Normal");
    }
    for (role, hash) in [
        (
            Role::Kernel,
            "36996326ae5eaa369ef34a8434514ca137b31a3f144af0955c2d12f4a8b2ea83",
        ),
        (
            Role::Main,
            "8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141",
        ),
    ] {
        let c = bundle
            .components
            .iter()
            .find(|c| c.role == role)
            .context("missing component")?;
        if format!("{:x}", Sha256::digest(&c.bytes)) != hash {
            bail!("backup read profile is established only for the supplied UD04 1.14 pair");
        }
    }
    Ok(bundle)
}

/// Reject an unsupported template without issuing any device commands.
pub fn validate_template(bytes: &[u8]) -> Result<()> {
    reference_pair(bytes).map(|_| ())
}

fn read_region(dev: &mut dyn ScsiDevice, start: usize, len: usize) -> Result<Vec<u8>> {
    let mut image = Vec::with_capacity(len);
    while image.len() < len {
        let off = start + image.len();
        let n = (len - image.len()).min(0xa4);
        let cdb = [
            0x3c,
            2,
            0xb0,
            (off >> 16) as u8,
            (off >> 8) as u8,
            off as u8,
            0,
            0,
            n as u8,
            0,
        ];
        let data = dev
            .command_in(&cdb, n)
            .with_context(|| format!("reading firmware at {off:#x}"))?;
        if data.len() != n {
            bail!("short firmware read at {off:#x}: {}/{n}", data.len());
        }
        image.extend(data);
    }
    Ok(image)
}

/// Capture the established UD04 1.14 firmware regions using the supplied pair
/// as framing templates. Reads only Kernel and Normal, twice for consistency.
/// Issues the documented zero-payload service knock, but no flash writes.
/// Unsupported templates/identity and mismatches fail without returning a backup.
fn read_ud04_pair(dev: &mut dyn ScsiDevice) -> Result<(Vec<u8>, Vec<u8>, String, String)> {
    let inquiry = dev.command_in(&[0x12, 0, 0, 0, 36, 0], 36)?;
    if inquiry.len() != 36
        || &inquiry[8..16] != b"PIONEER "
        || !String::from_utf8_lossy(&inquiry[16..32])
            .split_whitespace()
            .any(|s| s == "BDR-UD04")
        || &inquiry[32..36] != b"1.14"
    {
        bail!("backup profile requires PIONEER BDR-UD04 1.14");
    }
    let f1 = dev.command_in(&[0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0], 48)?;
    if f1.len() != 48 || &f1[16..24] != b"SAT 8A10" {
        bail!("backup profile requires SAT 8A10");
    }
    dev.command_out(&[0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0], &[])?;
    let kernel = read_region(dev, 0x400000, 0x10000)?;
    let normal = read_region(dev, 0x410000, 0x1c7500)?;
    if read_region(dev, 0x400000, kernel.len())? != kernel
        || read_region(dev, 0x410000, normal.len())? != normal
    {
        bail!("firmware reads changed between passes; no backup produced");
    }
    let envelope_id = std::str::from_utf8(&inquiry[8..32])?.trim_end().to_owned();
    let revision = std::str::from_utf8(&inquiry[32..36])?.to_owned();
    Ok((kernel, normal, revision, envelope_id))
}

/// Read the bounded UD04 firmware regions and construct a raw-path backup.
pub fn capture_plain_backup(dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
    let (kernel, normal, revision, _) = read_ud04_pair(dev)?;
    construct_ud04_plain_candidate(&kernel, &normal, &revision)
}

/// Read the same UD04 regions and reproduce a supplied reference envelope pair.
pub fn capture_reference_backup(dev: &mut dyn ScsiDevice, template: &[u8]) -> Result<Vec<u8>> {
    reference_pair(template)?; // Reject unsupported profiles before any command.
    let (kernel, normal, _, _) = read_ud04_pair(dev)?;
    let bytes = reconstruct_candidate(template, &kernel, &normal)?;
    // Current bounded profile promises exact equivalence to the known pair.
    reference_pair(&bytes).context("captured firmware differs from established reference pair")?;
    Ok(bytes)
}

/// Validate the bounded reference backup and return its Normal envelope.
pub fn validate_reference_backup(bytes: &[u8], product: &str) -> Result<Vec<u8>> {
    if !product.split_whitespace().any(|s| s == "BDR-UD04") {
        bail!("UD04 backup target mismatch");
    }
    let reference = reference_pair(bytes)
        .context("Pioneer restore accepts only the exact established OEM reference pair")?;
    Ok(reference
        .components
        .into_iter()
        .find(|c| c.role == Role::Main)
        .unwrap()
        .bytes)
}

/// Reconstruct a manifestless Kernel + Normal tar using original envelopes as
/// templates and explicitly supplied decoded image slices.
///
/// The captured Kernel must equal the template's decoded Kernel: its receiver
/// instructions determine the Normal codec. Unknown layouts, missing components,
/// identity mismatches and size changes are refused. No device I/O is performed.
/// Returned bytes are a reconstruction candidate, not a certified rollback image.
pub fn reconstruct_candidate(
    template: &[u8],
    kernel_image: &[u8],
    normal_image: &[u8],
) -> Result<Vec<u8>> {
    let bundle = Bundle::from_tar_bytes(template).context("invalid Pioneer template package")?;
    if bundle.components.len() != 2 {
        bail!("backup reconstruction requires exactly one Kernel and one Normal template");
    }
    let kernel = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .context("missing Kernel template")?;
    let normal = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .context("missing Normal template")?;
    let kh = pioneer_codec::header_info(&kernel.bytes).context("invalid Kernel header")?;
    let nh = pioneer_codec::header_info(&normal.bytes).context("invalid Normal header")?;
    for (label, a, b) in [
        ("model", &kh.model, &nh.model),
        ("hardware", &kh.hardware_version, &nh.hardware_version),
        ("Kernel Version", &kh.kernel_version, &nh.kernel_version),
        ("Destination", &kh.destination, &nh.destination),
    ] {
        if a.is_empty() || a != b {
            bail!("missing or mismatched template {label}");
        }
    }
    let decoded_kernel = pioneer_codec::decode_envelope(&kernel.bytes)
        .context("unsupported Kernel template codec")?;
    if decoded_kernel.image != kernel_image {
        bail!("captured Kernel differs from template; receiver policy is not established");
    }
    let decoded_normal = pioneer_codec::decode_envelope_with_kernel(&normal.bytes, &decoded_kernel)
        .context("unsupported Normal receiver codec")?;
    // Identity and geometry in the runtime Normal header must remain unchanged.
    // This is deliberately narrower than a firmware modification interface.
    if normal_image.len() != decoded_normal.image.len()
        || normal_image.get(..0x20) != decoded_normal.image.get(..0x20)
    {
        bail!("captured Normal identity/geometry differs from template");
    }
    let kernel_enc = decoded_kernel
        .repack(kernel_image)
        .context("Kernel re-encode failed")?;
    let normal_enc = decoded_normal
        .repack(normal_image)
        .context("Normal re-encode failed")?;
    let check = pioneer_codec::decode_envelope_with_kernel(&normal_enc, &decoded_kernel)
        .context("reconstructed Normal failed decode verification")?;
    if check.image != normal_image {
        bail!("Normal reconstruction verification mismatch");
    }
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in [(&kernel.path, &kernel_enc), (&normal.path, &normal_enc)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes.as_slice())?;
    }
    let bytes = tar.into_inner()?;
    Bundle::from_tar_bytes(&bytes).context("reconstructed package validation failed")?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replay captured address-space bytes without opening a device. Reject
    /// every command outside the bounded reference backup transaction.
    struct CaptureReplay {
        dump: Vec<u8>,
        reads: usize,
        knocks: usize,
        corrupt_second_pass: bool,
    }

    impl ScsiDevice for CaptureReplay {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            if cdb == [0x12, 0, 0, 0, len as u8, 0] && matches!(len, 36 | 96) {
                let mut data = vec![0; len];
                data[8..16].copy_from_slice(b"PIONEER ");
                data[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
                data[32..36].copy_from_slice(b"1.14");
                return Ok(data);
            }
            if cdb == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
                assert_eq!(len, 48);
                let mut data = vec![0; 48];
                data[16..24].copy_from_slice(b"SAT 8A10");
                return Ok(data);
            }
            if cdb == [0x3c, 0x06, 0, 0, 0x30, 0, 0, 0, 0x20, 0] {
                bail!("Pioneer does not implement the MTK identity buffer");
            }
            assert_eq!(
                self.knocks, 1,
                "unexpected pre-knock CDB: {cdb:02x?}, len={len}"
            );
            assert_eq!(cdb.len(), 10);
            assert_eq!(&cdb[..3], &[0x3c, 2, 0xb0]);
            assert_eq!(&cdb[6..], &[0, 0, len as u8, 0]);
            assert!((1..=0xa4).contains(&len));
            let offset = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
            assert!(offset >= 0x400000 && offset + len <= 0x5d7500);
            let mut data = self.dump[offset..offset + len].to_vec();
            if self.corrupt_second_pass && offset == 0x400000 && self.reads > 0 {
                data[0] ^= 1;
            }
            self.reads += 1;
            Ok(data)
        }

        fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
            assert_eq!(cdb, [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]);
            assert!(data.is_empty());
            self.knocks += 1;
            Ok(())
        }

        fn describe(&self) -> String {
            "saved capture replay; no hardware".into()
        }
    }

    #[test]
    fn malformed_template_is_rejected() {
        assert!(reconstruct_candidate(b"not a tar", &[], &[]).is_err());
    }

    #[test]
    fn self_signed_live_capture_is_a_verified_offline_candidate_when_configured() {
        let Ok(path) = std::env::var("PIONEER_LIVE_DUMP_FIXTURE") else {
            return;
        };
        let dump = std::fs::read(path).unwrap();
        assert_eq!(dump.len(), 0x600000);
        let mut replay = CaptureReplay {
            dump: dump.clone(),
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        };
        let candidate = capture_signed_candidate(&mut replay).unwrap();
        if let Ok(path) = std::env::var("PIONEER_SIGNED_BACKUP_KAT_OUTPUT") {
            std::fs::write(path, &candidate).unwrap();
        }
        assert_eq!(replay.knocks, 1);
        validate_signed_candidate(&candidate, "BD-RW BDR-UD04").unwrap();
        assert!(validate_reference_backup(&candidate, "BD-RW BDR-UD04").is_err());
        let bundle = Bundle::from_tar_bytes(&candidate).unwrap();
        let kernel = bundle
            .components
            .iter()
            .find(|c| c.role == Role::Kernel)
            .unwrap();
        let normal = bundle
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap();
        let candidate_steps =
            crate::drive::pioneer::offline_linear_fe_data_out(&kernel.bytes, &normal.bytes)
                .unwrap();
        if let Ok(path) = std::env::var("PIONEER_UD04_AUTOFLASHER_BUNDLE_FIXTURE") {
            let original = Bundle::from_tar_bytes(&std::fs::read(path).unwrap()).unwrap();
            let original_kernel = original
                .components
                .iter()
                .find(|c| c.role == Role::Kernel)
                .unwrap();
            let original_normal = original
                .components
                .iter()
                .find(|c| c.role == Role::Main)
                .unwrap();
            let original_steps = crate::drive::pioneer::offline_linear_fe_data_out(
                &original_kernel.bytes,
                &original_normal.bytes,
            )
            .unwrap();
            assert_eq!(candidate_steps.len(), original_steps.len());
            for (candidate, original) in candidate_steps.iter().zip(&original_steps) {
                assert_eq!(candidate.stage, original.stage);
                assert_eq!(candidate.cdb, original.cdb);
                assert_eq!(candidate.data.len(), original.data.len());
            }
        }
        let decoded_kernel = pioneer_codec::decode_envelope(&kernel.bytes).unwrap();
        let decoded_normal =
            pioneer_codec::decode_envelope_with_kernel(&normal.bytes, &decoded_kernel).unwrap();
        assert_eq!(decoded_kernel.image, dump[0x400000..0x410000]);
        assert_eq!(decoded_normal.image, dump[0x410000..0x5d7500]);
        let output =
            std::env::temp_dir().join(format!("ud04-signed-candidate-{}.tar", std::process::id()));
        let _ = std::fs::remove_file(&output);
        let drive = crate::drive::pioneer::Pioneer::new();
        crate::engine::plan_pioneer_offline(
            &candidate,
            crate::drive::InputKind::PioneerBundle,
            "BD-RW BDR-UD04",
            false,
            false,
            false,
            &drive,
        )
        .unwrap();
        replay.knocks = 0;
        replay.reads = 0;
        crate::engine::pioneer_signed_candidate(&mut replay, &drive, &output).unwrap();
        let saved = std::fs::read(&output).unwrap();
        validate_signed_candidate(&saved, "BD-RW BDR-UD04").unwrap();
        std::fs::remove_file(&output).unwrap();
        replay.knocks = 0;
        replay.reads = 0;
        replay.corrupt_second_pass = true;
        assert!(capture_signed_candidate(&mut replay).is_err());
    }

    /// Optional external KAT; explicitly set both paths when validating delivery.
    #[test]
    fn supplied_ud04_and_live_images_recreate_both_envelopes() {
        let Ok(path) = std::env::var("PIONEER_UD04_AUTOFLASHER_BUNDLE_FIXTURE") else {
            return;
        };
        let live = std::env::var("PIONEER_LIVE_DUMP_FIXTURE")
            .expect("set PIONEER_LIVE_DUMP_FIXTURE with the package KAT");
        let template = std::fs::read(path).unwrap();
        let original = Bundle::from_tar_bytes(&template).unwrap();
        let dump = std::fs::read(live).unwrap();
        assert_eq!(dump.len(), 0x600000);
        // Explicitly documented UD04 capture mapping, not generic read offsets.
        let ki = dump[0x400000..0x410000].to_vec();
        let ni = dump[0x410000..0x5d7500].to_vec();
        let synthetic = construct_ud04_plain_candidate(&ki, &ni, "1.14").unwrap();
        if let Ok(output) = std::env::var("PIONEER_PLAIN_BACKUP_KAT_OUTPUT") {
            std::fs::write(output, &synthetic).unwrap();
        }
        assert!(validate_reference_backup(&synthetic, "BD-RW BDR-UD04").is_err());
        let synthetic_bundle = Bundle::from_tar_bytes(&synthetic).unwrap();
        let raw_kernel = synthetic_bundle
            .components
            .iter()
            .find(|c| c.role == Role::Kernel)
            .unwrap();
        let raw_normal = synthetic_bundle
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap();
        let decoded_kernel = pioneer_codec::decode_envelope(&raw_kernel.bytes).unwrap();
        let decoded_normal =
            pioneer_codec::decode_envelope_with_kernel(&raw_normal.bytes, &decoded_kernel).unwrap();
        assert_eq!(decoded_kernel.image, ki);
        assert_eq!(decoded_normal.image, ni);
        assert_eq!(decoded_kernel.repack(&ki).unwrap(), raw_kernel.bytes);
        assert_eq!(decoded_normal.repack(&ni).unwrap(), raw_normal.bytes);
        assert_eq!(raw_kernel.bytes.len(), 0x11200);
        assert_eq!(&raw_kernel.bytes[0x1200..], ki);
        assert_eq!(&raw_normal.bytes[0x10200..], ni);
        assert!(raw_kernel.bytes[0x200..0x1200].iter().all(|&b| b == 0));
        assert!(raw_normal.bytes[0x200..0x10200].iter().all(|&b| b == 0));
        assert_eq!(
            pioneer_codec::header_info(&raw_kernel.bytes)
                .unwrap()
                .revision,
            "BACKUP"
        );
        assert_eq!(
            pioneer_codec::header_info(&raw_normal.bytes)
                .unwrap()
                .revision,
            "1.14"
        );
        let mut tampered = ni.clone();
        tampered[0x100] ^= 1;
        assert!(construct_ud04_plain_candidate(&ki, &tampered, "1.14").is_err());
        let rebuilt = reconstruct_candidate(&template, &ki, &ni).unwrap();
        let mut replay = CaptureReplay {
            dump: dump.clone(),
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        };
        assert_eq!(
            capture_reference_backup(&mut replay, &template).unwrap(),
            rebuilt
        );
        assert_eq!(replay.knocks, 1);
        replay.reads = 0;
        replay.knocks = 0;
        assert_eq!(capture_plain_backup(&mut replay).unwrap(), synthetic);
        assert_eq!(replay.knocks, 1);
        let mut engine_replay = CaptureReplay {
            dump: dump.clone(),
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        };
        let output =
            std::env::temp_dir().join(format!("ud04-plain-backup-{}.tar", std::process::id()));
        let _ = std::fs::remove_file(&output);
        let error = crate::engine::backup(
            &mut engine_replay,
            &*crate::drive::for_family(crate::drive::Family::Pioneer),
            &output,
        )
        .unwrap_err();
        assert!(error.to_string().contains("matching signed OEM template"));
        assert_eq!(engine_replay.reads, 0);
        assert_eq!(engine_replay.knocks, 0);
        assert!(!output.exists());
        crate::engine::backup_with_template(
            &mut engine_replay,
            &*crate::drive::for_family(crate::drive::Family::Pioneer),
            &output,
            Some(&template),
        )
        .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), template);
        assert_eq!(engine_replay.knocks, 1);
        std::fs::remove_file(&output).unwrap();
        replay.reads = 0;
        replay.knocks = 0;
        replay.corrupt_second_pass = true;
        assert!(capture_reference_backup(&mut replay, &template)
            .unwrap_err()
            .to_string()
            .contains("changed between passes"));
        let mut no_io = CaptureReplay {
            dump: Vec::new(),
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        };
        assert!(capture_reference_backup(&mut no_io, b"invalid").is_err());
        assert_eq!((no_io.reads, no_io.knocks), (0, 0));
        let actual = Bundle::from_tar_bytes(&rebuilt).unwrap();
        assert_eq!(actual.components.len(), 2);
        for expected in &original.components {
            let found = actual
                .components
                .iter()
                .find(|c| c.role == expected.role)
                .unwrap();
            assert_eq!(found.path, expected.path);
            assert_eq!(found.bytes, expected.bytes);
        }
        if let Ok(output) = std::env::var("PIONEER_RECONSTRUCTION_KAT_OUTPUT") {
            std::fs::write(output, &rebuilt).unwrap();
        }
        assert!(reconstruct_candidate(&template, &ki, &ni[..ni.len() - 1]).is_err());
        let mut bad_kernel = ki.clone();
        bad_kernel[0] ^= 1;
        assert!(reconstruct_candidate(&template, &bad_kernel, &ni).is_err());
        let mut bad_normal = ni.clone();
        bad_normal[0] ^= 1;
        assert!(reconstruct_candidate(&template, &ki, &bad_normal).is_err());
    }
}
