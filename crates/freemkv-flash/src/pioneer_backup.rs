//! Offline image-to-envelope reconstruction. This does not establish that a
//! capture came from persistent flash, covers all writable state, or can restore
//! a drive. Live backup/flash capability remains gated separately.

use crate::pioneer_bundle::{Bundle, Role};
use crate::platform::ScsiDevice;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

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
pub fn capture_reference_backup(dev: &mut dyn ScsiDevice, template: &[u8]) -> Result<Vec<u8>> {
    reference_pair(template)?; // Reject unsupported profiles before any command.
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
    Ok(reference_pair(bytes)?
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
            if cdb == [0x12, 0, 0, 0, 36, 0] {
                assert_eq!(len, 36);
                let mut data = vec![0; 36];
                data[8..16].copy_from_slice(b"PIONEER ");
                data[16..32].copy_from_slice(b"BD-RW BDR-UD04  ");
                data[32..36].copy_from_slice(b"1.14");
                return Ok(data);
            }
            if cdb == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
                assert_eq!(len, 48);
                let mut data = vec![0; 48];
                data[16..24].copy_from_slice(b"SAT 8A10");
                return Ok(data);
            }
            assert_eq!(self.knocks, 1);
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
