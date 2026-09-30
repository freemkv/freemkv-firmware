//! Offline image-to-envelope reconstruction. This does not establish that a
//! capture came from persistent flash, covers all writable state, or can restore
//! a drive. Live backup/flash capability remains gated separately.

use crate::pioneer_bundle::{Bundle, Role};
use crate::platform::ScsiDevice;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

// Deliberately custom generator defaults, not recovered OEM seeds or signing keys.
const KERNEL_SEED: u32 = 0x123456;
const NORMAL_SEED: u32 = 0x654321;

/// Build an encrypted package directly from two captured images. The
/// public point in its Normal header belongs to a fresh caller-owned key;
/// drive-side trust and restore are not established by this constructor.
pub fn construct_signed_candidate(
    kernel: &[u8],
    normal: &[u8],
    envelope_id: &str,
    revision: &str,
) -> Result<Vec<u8>> {
    let date = unique_embedded_date(normal).unwrap_or("BACKUP");
    // Encoding tables are generated from our own explicit constants.
    // Neither seed claims to reproduce the original OEM encoding table.
    // Keep signing entropy independent: encoding seeds are not signing keys.
    let signer = pioneer_codec::signature::SigningKey::random().map_err(|e| anyhow::anyhow!(e))?;
    let input = pioneer_codec::builder::BuildInputs {
        kernel_image: kernel,
        normal_image: normal,
        envelope_id,
        normal_revision: revision,
        normal_date: date,
        kernel_key_seed: KERNEL_SEED,
        normal_key_seed: NORMAL_SEED,
    };
    let pair = pioneer_codec::builder::encode_encrypted_pair(&input, &signer)
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
    let parsed = Bundle::from_tar_bytes(&out)?;
    if parsed.components.len() != 2 {
        bail!("generated package did not contain Kernel and Normal");
    }
    Ok(out)
}

/// Firmware build dates, when present as a unique YY/MM/DD or MmmDD,YYYY literal in the
/// captured Normal image, are recoverable without a model or offset table.
fn unique_embedded_date(image: &[u8]) -> Option<&str> {
    let mut found = None;
    for field in image.windows(8) {
        if field[2] == b'/'
            && field[5] == b'/'
            && [0, 1, 3, 4, 6, 7]
                .iter()
                .all(|&i| field[i].is_ascii_digit())
        {
            let month = (field[3] - b'0') * 10 + field[4] - b'0';
            let day = (field[6] - b'0') * 10 + field[7] - b'0';
            if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
                continue;
            }
            let value = std::str::from_utf8(field).ok()?;
            if found.is_some_and(|previous| previous != value) {
                return None;
            }
            found = Some(value);
        }
    }
    for field in image.windows(10) {
        let month = [
            b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
            b"Dec",
        ]
        .iter()
        .position(|m| field[..3] == **m);
        if month.is_some()
            && field[5] == b','
            && [3, 4, 6, 7, 8, 9]
                .iter()
                .all(|&i| field[i].is_ascii_digit())
        {
            let day = (field[3] - b'0') * 10 + field[4] - b'0';
            if !(1..=31).contains(&day) {
                continue;
            }
            let value = std::str::from_utf8(field).ok()?;
            if found.is_some_and(|previous| previous != value) {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

/// Recover the OEM-spaced envelope ID from captured firmware, using INQUIRY
/// only to identify its vendor, media class and model tokens. The fixed-width
/// INQUIRY product may have different spacing from the envelope header.
fn embedded_envelope_id(inquiry: &[u8], kernel: &[u8], normal: &[u8]) -> Result<String> {
    let vendor = std::str::from_utf8(inquiry.get(8..16).context("short INQUIRY vendor")?)?.trim();
    let product = std::str::from_utf8(inquiry.get(16..32).context("short INQUIRY product")?)?;
    let tokens: Vec<_> = product.split_whitespace().collect();
    let (Some(model), media) = (tokens.last(), &tokens[..tokens.len().saturating_sub(1)]) else {
        bail!("INQUIRY product has no model");
    };
    if vendor.is_empty() || media.is_empty() {
        bail!("INQUIRY identity is incomplete");
    }
    let media = media.join(" ");
    for image in [kernel, normal] {
        let mut found = None;
        for spaces in 1..=8 {
            let candidate = format!("{vendor} {media}{}{model}", " ".repeat(spaces));
            if candidate.len() > 24 {
                continue;
            }
            if image
                .windows(candidate.len())
                .enumerate()
                .any(|(offset, window)| {
                    window == candidate.as_bytes()
                        && image.get(offset + candidate.len()).is_none_or(|next| {
                            (!next.is_ascii_alphanumeric() && !matches!(*next, b'-' | b'_'))
                                || image
                                    .get(offset + candidate.len()..offset + candidate.len() + 5)
                                    .is_some_and(|tail| {
                                        tail[0].is_ascii_digit()
                                            && (tail[1].is_ascii_digit() || tail[1] == b'.')
                                            && tail[2..4].iter().all(u8::is_ascii_digit)
                                            && tail[4] == b' '
                                    })
                        })
                })
            {
                if found.is_some() {
                    bail!("multiple firmware envelope identities match INQUIRY");
                }
                found = Some(candidate);
            }
        }
        if let Some(id) = found {
            return Ok(id);
        }
    }
    bail!("captured firmware has no envelope identity matching INQUIRY")
}

/// Structural, codec and signature checks for a Pioneer envelope pair,
/// regardless of whether it came from an updater or a live capture.
pub fn validate_envelope_package(bytes: &[u8], product: &str) -> Result<()> {
    let bundle = Bundle::from_tar_bytes(bytes)?;
    if bundle.components.len() != 2 {
        bail!("Pioneer package requires Kernel and Normal");
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
    validate_envelope_pair(&kernel.bytes, &normal.bytes, product)
}

/// Validate a pair without interpreting its provenance or archival labels.
pub fn validate_envelope_pair(kernel: &[u8], normal: &[u8], product: &str) -> Result<()> {
    let kh = pioneer_codec::header_info(kernel).context("invalid Kernel header")?;
    let nh = pioneer_codec::header_info(normal).context("invalid Normal header")?;
    if !product.split_whitespace().any(|part| part == kh.model)
        || nh.model != kh.model
        || nh.hardware_version != kh.hardware_version
        || kh.file_type != "Kernel"
        || nh.file_type != "Normal"
        || kh.kernel_version != nh.kernel_version
        || kh.kernel_version2 != nh.kernel_version2
        || kh.destination != nh.destination
    {
        bail!("Pioneer envelope identity does not match the drive");
    }
    let decoded_kernel =
        pioneer_codec::decode_envelope(kernel).context("Kernel cannot be decoded")?;
    let decoded_normal = pioneer_codec::decode_envelope_with_kernel(normal, &decoded_kernel)
        .context("Normal cannot be receiver-decoded")?;
    if !pioneer_codec::builder::normal_authentication_valid(normal, &decoded_kernel.image)
        || decoded_normal.info.layout
            != if pioneer_codec::builder::scaled_normal_geometry_from_kernel(&decoded_kernel.image)
                .is_some()
            {
                "normal-scaled-key"
            } else {
                "normal"
            }
        || !zero_be32_sum(&decoded_kernel.image)
        || !zero_be32_sum(&decoded_normal.image)
    {
        bail!("Pioneer signature, image integrity or layout mismatch");
    }
    if decoded_kernel.repack(&decoded_kernel.image).as_deref() != Some(kernel)
        || decoded_normal.repack(&decoded_normal.image).as_deref() != Some(normal)
    {
        bail!("Pioneer envelope does not round-trip exactly");
    }
    Ok(())
}

/// Read the shared H8/SAT image regions twice and save a self-signed encrypted
/// package candidate. This issues no flash commands.
pub fn capture_signed_candidate(dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
    let (kernel, normal, revision, envelope_id) = read_h8_image_pair(dev)?;
    construct_signed_candidate(&kernel, &normal, &envelope_id, &revision)
}

fn zero_be32_sum(image: &[u8]) -> bool {
    let (words, remainder) = image.as_chunks::<4>();
    remainder.is_empty()
        && words.iter().fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(*word))
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
        || !normal.len().is_multiple_of(0x100)
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

/// Shared H8/SAT image map observed in decoded Kernels from 28 hardware
/// groups. This is an address-space rule, not a per-model firmware record.
const KERNEL_IMAGE_BASE: usize = 0x400000;
const NORMAL_IMAGE_BASE: usize = 0x410000;

/// Older receivers already allow B0 reads and need no service command. Only
/// the observed invalid-field denial permits one attempt at the shared knock;
/// transport failures, short data and other sense codes must stop capture.
fn prepare_firmware_read(dev: &mut dyn ScsiDevice) -> Result<()> {
    match read_region(dev, KERNEL_IMAGE_BASE, 1) {
        Ok(_) => Ok(()),
        Err(error) if crate::platform::sense_triplet(&error) == Some((5, 0x24, 0)) => dev
            .command_out(&[0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0], &[])
            .context("entering Pioneer firmware read service"),
        Err(error) => Err(error).context("probing Pioneer firmware read access"),
    }
}

/// Capture each structurally identified image region twice. No OEM envelope,
/// previously saved backup, model, revision or hardware lookup is consulted.
fn read_h8_image_pair(dev: &mut dyn ScsiDevice) -> Result<(Vec<u8>, Vec<u8>, String, String)> {
    let inquiry = dev.command_in(&[0x12, 0, 0, 0, 36, 0], 36)?;
    if inquiry.len() != 36
        || !inquiry[8..32].is_ascii()
        || inquiry[8..32].iter().any(|&b| b < 0x20 || b == 0x7f)
        || inquiry[8..32].iter().all(|&b| b == b' ')
    {
        bail!("drive does not have a usable H8/SAT INQUIRY identity");
    }
    let f1 = dev.command_in(&[0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0], 48)?;
    if f1.len() != 48 {
        bail!("Pioneer backup stopped: incomplete hardware identity response ({} bytes, expected 48); no firmware image read or backup created", f1.len());
    }
    if !f1[16..24].starts_with(b"SAT ") {
        let hardware = String::from_utf8_lossy(&f1[16..24]);
        bail!("Pioneer backup is not implemented for hardware {hardware:?}: H8/SAT hardware identity required; no firmware image read or backup created");
    }
    let kernel_len = NORMAL_IMAGE_BASE
        .checked_sub(KERNEL_IMAGE_BASE)
        .filter(|len| *len > 0 && *len <= 0x100000)
        .context("invalid Kernel/Normal address span")?;
    prepare_firmware_read(dev)?;
    let kernel = read_region(dev, KERNEL_IMAGE_BASE, kernel_len)?;
    if kernel.get(0x1000..0x1008) != Some(&f1[16..24]) {
        bail!("captured Kernel hardware differs from drive identity");
    }
    pioneer_codec::builder::kernel_layout_from_image(&kernel)
        .context("captured Kernel receiver layout is unsupported; Normal capture not attempted")?;
    let normal_head = read_region(dev, NORMAL_IMAGE_BASE, 24)?;
    if !normal_head.starts_with(b"PIONEER ") {
        bail!("Normal image header is missing at the discovered base");
    }
    let normal_len = match pioneer_codec::builder::scaled_normal_geometry_from_kernel(&kernel) {
        Some(geometry) => geometry.image_len,
        None => u32::from_be_bytes(normal_head[20..24].try_into().unwrap()) as usize,
    };
    if !(0x2000..=0x800000).contains(&normal_len)
        || !normal_len.is_multiple_of(0x100)
        || NORMAL_IMAGE_BASE + normal_len > 0x1000000
    {
        bail!("Normal image declares an invalid length");
    }
    let normal = read_region(dev, NORMAL_IMAGE_BASE, normal_len)?;
    if read_region(dev, KERNEL_IMAGE_BASE, kernel_len)? != kernel
        || read_region(dev, NORMAL_IMAGE_BASE, normal_len)? != normal
    {
        bail!("firmware reads changed between passes; no backup produced");
    }
    let envelope_id = embedded_envelope_id(&inquiry, &kernel, &normal)?;
    let revision = std::str::from_utf8(&inquiry[32..36])?.to_owned();
    Ok((kernel, normal, revision, envelope_id))
}

/// Read the bounded UD04 firmware regions and construct a raw-path backup.
pub fn capture_plain_backup(dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
    let (kernel, normal, revision, _) = read_h8_image_pair(dev)?;
    construct_ud04_plain_candidate(&kernel, &normal, &revision)
}

/// Read the same UD04 regions and reproduce a supplied reference envelope pair.
pub fn capture_reference_backup(dev: &mut dyn ScsiDevice, template: &[u8]) -> Result<Vec<u8>> {
    reference_pair(template)?; // Reject unsupported profiles before any command.
    let (kernel, normal, _, _) = read_h8_image_pair(dev)?;
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

    #[test]
    fn read_access_probes_before_knock_and_never_retries_unrelated_failures() {
        struct Access {
            response: Option<Result<Vec<u8>>>,
            knocks: usize,
        }
        impl ScsiDevice for Access {
            fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
                assert_eq!(cdb, [0x3c, 2, 0xb0, 0x40, 0, 0, 0, 0, 1, 0]);
                assert_eq!(len, 1);
                self.response.take().expect("only one access probe")
            }
            fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
                assert_eq!(cdb, [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]);
                assert!(data.is_empty());
                self.knocks += 1;
                Ok(())
            }
            fn describe(&self) -> String {
                "read permission test".into()
            }
        }
        let sense = |key, asc, ascq| {
            Err(crate::platform::ScsiSenseError::new(key, asc, ascq, "test sense").into())
        };
        for (response, ok, knocks) in [
            (Ok(vec![0]), true, 0), // ungated older receiver
            (sense(5, 0x24, 0), true, 1),
            (sense(5, 0x20, 0), false, 0), // unsupported opcode, not the read gate
            (sense(4, 0x44, 0), false, 0),
            (Err(anyhow::anyhow!("transport disconnected")), false, 0),
            (Ok(vec![]), false, 0), // a short response is never access denial
        ] {
            let mut dev = Access {
                response: Some(response),
                knocks: 0,
            };
            assert_eq!(prepare_firmware_read(&mut dev).is_ok(), ok);
            assert_eq!(dev.knocks, knocks);
        }
    }

    #[test]
    fn unsupported_capture_identity_stops_before_service_entry_or_memory_reads() {
        struct IdentityOnly {
            f1: Vec<u8>,
            commands: usize,
        }
        impl ScsiDevice for IdentityOnly {
            fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
                self.commands += 1;
                match self.commands {
                    1 => {
                        assert_eq!(cdb, [0x12, 0, 0, 0, 36, 0]);
                        assert_eq!(len, 36);
                        let mut inquiry = vec![b' '; 36];
                        inquiry[8..16].copy_from_slice(b"PIONEER ");
                        Ok(inquiry)
                    }
                    2 => {
                        assert_eq!(cdb, [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0]);
                        assert_eq!(len, 48);
                        Ok(self.f1.clone())
                    }
                    _ => panic!("unsupported identity must not trigger memory reads"),
                }
            }
            fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
                panic!("unsupported identity must not trigger service entry")
            }
            fn describe(&self) -> String {
                "identity-only test transport".into()
            }
        }
        for hardware in [b"ATA 0009", b"SCSI0001", b"UNKNOWN "] {
            let mut f1 = vec![0; 48];
            f1[16..24].copy_from_slice(hardware);
            let mut dev = IdentityOnly { f1, commands: 0 };
            assert!(read_h8_image_pair(&mut dev)
                .unwrap_err()
                .to_string()
                .contains("H8/SAT hardware identity"));
            assert_eq!(dev.commands, 2);
        }
        for length in [0, 16, 23, 47, 49] {
            let mut dev = IdentityOnly {
                f1: vec![0; length],
                commands: 0,
            };
            assert!(read_h8_image_pair(&mut dev).is_err());
            assert_eq!(dev.commands, 2);
        }
    }

    #[test]
    fn embedded_identity_preserves_spacing_and_rejects_model_prefixes() {
        let mut inquiry = [b' '; 36];
        inquiry[8..15].copy_from_slice(b"PIONEER");
        inquiry[16..30].copy_from_slice(b"BD-RW  BDR-212");
        assert!(embedded_envelope_id(&inquiry, b"PIONEER BD-RW   BDR-212M\0", b"").is_err());
        assert_eq!(
            embedded_envelope_id(&inquiry, b"PIONEER BD-RW   BDR-212\0", b"").unwrap(),
            "PIONEER BD-RW   BDR-212"
        );
    }

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
                if let Ok(path) = std::env::var("PIONEER_INQUIRY_FIXTURE") {
                    let bytes = std::fs::read(path).unwrap();
                    return Ok(bytes[..len].to_vec());
                }
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
            if self.knocks == 0 {
                assert_eq!(cdb, [0x3c, 2, 0xb0, 0x40, 0, 0, 0, 0, 1, 0]);
                assert_eq!(len, 1);
                return Err(
                    crate::platform::ScsiSenseError::new(5, 0x24, 0, "read access locked").into(),
                );
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
    fn unknown_sat_receiver_stops_after_kernel_capture() {
        let mut dump = vec![0; NORMAL_IMAGE_BASE];
        dump[KERNEL_IMAGE_BASE + 0x1000..KERNEL_IMAGE_BASE + 0x1008].copy_from_slice(b"SAT 8A10");
        // The replay has no Normal bytes. Any read beyond the Kernel panics,
        // proving rejection occurs before guessing Normal geometry.
        let mut replay = CaptureReplay {
            dump,
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        };
        let error = read_h8_image_pair(&mut replay).unwrap_err();
        assert!(error.to_string().contains("receiver layout is unsupported"));
        assert_eq!(replay.knocks, 1);
        assert!(replay.reads > 0);
    }

    #[test]
    fn oem_pair_rebuilds_from_decoded_images_when_configured() {
        let Ok(path) = std::env::var("PIONEER_PAIR_KAT") else {
            return;
        };
        let source = Bundle::from_tar_bytes(&std::fs::read(path).unwrap()).unwrap();
        let kernel = source
            .components
            .iter()
            .find(|c| c.role == Role::Kernel)
            .unwrap();
        let normal = source
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap();
        let k = pioneer_codec::decode_envelope(&kernel.bytes).unwrap();
        let detected = pioneer_codec::builder::kernel_layout_from_image(&k.image).unwrap();
        let expected = match k.info.layout.as_str() {
            "kernel-front" => pioneer_codec::builder::KernelLayout::FrontKey,
            "kernel-derived" => pioneer_codec::builder::KernelLayout::DerivedKey,
            other => panic!("unsupported Kernel layout: {other}"),
        };
        assert_eq!(detected, expected);
        let n = pioneer_codec::decode_envelope_with_kernel(&normal.bytes, &k).unwrap();
        let h = pioneer_codec::header_info(&normal.bytes).unwrap();
        let output = construct_signed_candidate(&k.image, &n.image, &h.id, &h.revision).unwrap();
        validate_envelope_package(&output, &h.model).unwrap();
        let rebuilt = Bundle::from_tar_bytes(&output).unwrap();
        let rk = rebuilt
            .components
            .iter()
            .find(|c| c.role == Role::Kernel)
            .unwrap();
        let rn = rebuilt
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap();
        assert_eq!(&rn.bytes[..0x160], &normal.bytes[..0x160]);
        if h.destination == "GENERAL" || h.destination.starts_with("ID") {
            assert_eq!(&rn.bytes[0x1f0..0x200], &normal.bytes[0x1f0..0x200]);
        } else {
            assert!(rn.bytes[0x1f0..]
                .starts_with(format!("NORMAL.{}\0", h.revision.replace('.', "")).as_bytes()));
        }
        if pioneer_codec::builder::normal_authentication_from_kernel(&k.image)
            == Some(pioneer_codec::builder::NormalAuthentication::ScaledChecksumOnly)
        {
            assert!(pioneer_codec::builder::normal_authentication_valid(
                &normal.bytes,
                &k.image
            ));
            assert!(pioneer_codec::builder::normal_authentication_valid(
                &rn.bytes, &k.image
            ));
        } else {
            assert_eq!(
                pioneer_codec::signature::verify_normal_signature(&normal.bytes),
                pioneer_codec::signature::verify_normal_signature(&rn.bytes)
            );
        }
        let dk = pioneer_codec::decode_envelope(&rk.bytes).unwrap();
        let dn = pioneer_codec::decode_envelope_with_kernel(&rn.bytes, &dk).unwrap();
        assert_eq!(dk.image, k.image);
        assert_eq!(dn.image, n.image);
        let mut damaged = rn.bytes.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(validate_envelope_pair(&rk.bytes, &damaged, &h.model).is_err());
        assert_eq!(
            unique_embedded_date(&n.image),
            Some(h.generated_date.as_str())
        );
    }

    #[test]
    fn corpus_encoding_seeds_when_configured() {
        let Ok(root) = std::env::var("PIONEER_INSTALLER_CORPUS_KAT_ROOT") else {
            return;
        };
        let mut dirs = vec![std::path::PathBuf::from(root)];
        let mut seen = std::collections::HashSet::new();
        let mut groups =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<u32>>::new();
        let mut seeds = std::collections::BTreeMap::<u32, usize>::new();
        let mut unknown = std::collections::BTreeMap::<String, usize>::new();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if !path.to_string_lossy().ends_with(".installer.tar") {
                    continue;
                }
                let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(path).unwrap()) else {
                    continue;
                };
                for component in bundle.components {
                    if !seen.insert(Sha256::digest(&component.bytes).to_vec()) {
                        continue;
                    }
                    let Some(decoded) = pioneer_codec::decode_envelope(&component.bytes) else {
                        continue;
                    };
                    let h = pioneer_codec::header_info(&component.bytes).unwrap();
                    let group = format!(
                        "{}/{}/{}/{}/{}",
                        h.model,
                        h.hardware_version,
                        h.destination,
                        h.file_type,
                        decoded.info.layout
                    );
                    if let Some(seed) = decoded.encoding_seed() {
                        *seeds.entry(seed).or_default() += 1;
                        groups.entry(group).or_default().insert(seed);
                    } else {
                        *unknown.entry(group).or_default() += 1;
                    }
                }
            }
        }
        eprintln!("Encoding seeds (hex, distinct envelopes): {seeds:x?}");
        eprintln!("Non-LCG decoded key tables: {unknown:?}");
        eprintln!(
            "Seed groups: {}; varying groups: {}",
            groups.len(),
            groups.values().filter(|s| s.len() > 1).count()
        );
        for (group, values) in groups.iter().filter(|(_, s)| s.len() > 1) {
            eprintln!("varying seeds: {group}: {values:x?}");
        }
        assert!(!groups.is_empty());
    }

    #[test]
    fn embedded_build_date_preserves_formats_and_rejects_ambiguity() {
        assert_eq!(
            unique_embedded_date(b"model 1.10 Sep18,2008   "),
            Some("Sep18,2008")
        );
        assert_eq!(
            unique_embedded_date(b"model 1.14 20/06/15   "),
            Some("20/06/15")
        );
        assert_eq!(unique_embedded_date(b"Sep18,2008 20/06/15"), None);
        assert_eq!(unique_embedded_date(b"20/06/15 20/06/15"), Some("20/06/15"));
        assert_eq!(
            unique_embedded_date(b"Sep18,2008 Sep18,2008"),
            Some("Sep18,2008")
        );
        assert_eq!(unique_embedded_date(b"20/06/15 20/06/16"), None);
        assert_eq!(
            unique_embedded_date(b"20/00/15 20/13/15 20/06/00 20/06/32"),
            None
        );
        assert_eq!(unique_embedded_date(b"99/99/99 20/06/15"), Some("20/06/15"));
        assert_eq!(unique_embedded_date(b"Sep00,2008"), None);
        assert_eq!(unique_embedded_date(b"Bog18,2008"), None);
    }

    #[test]
    fn scaled_image_capture_uses_receiver_length_when_configured() {
        let Ok(path) = std::env::var("PIONEER_SCALED_KERNEL_FIXTURE") else {
            return;
        };
        let kernel = pioneer_codec::decode_envelope(&std::fs::read(path).unwrap()).unwrap();
        let normal_bytes =
            std::fs::read(std::env::var("PIONEER_SCALED_NORMAL_FIXTURE").unwrap()).unwrap();
        let normal = pioneer_codec::decode_envelope_with_kernel(&normal_bytes, &kernel).unwrap();
        let h = pioneer_codec::header_info(&normal_bytes).unwrap();
        let (vendor, product) = h.id.split_once(' ').unwrap();
        let product = product.trim();
        assert!(vendor.len() <= 8 && product.len() <= 16 && h.revision.len() == 4);
        let mut inquiry = vec![b' '; 36];
        inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
        inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
        inquiry[32..36].copy_from_slice(h.revision.as_bytes());
        let mut dump = vec![0; 0x600000];
        dump[KERNEL_IMAGE_BASE..NORMAL_IMAGE_BASE].copy_from_slice(&kernel.image);
        dump[NORMAL_IMAGE_BASE..NORMAL_IMAGE_BASE + normal.image.len()]
            .copy_from_slice(&normal.image);
        struct Replay {
            inner: CaptureReplay,
            inquiry: Vec<u8>,
            hardware: Vec<u8>,
            ungated: bool,
        }
        impl ScsiDevice for Replay {
            fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
                if cdb == [0x12, 0, 0, 0, 36, 0] {
                    return Ok(self.inquiry.clone());
                }
                if cdb == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
                    let mut out = vec![0; 48];
                    out[16..24].copy_from_slice(&self.hardware);
                    return Ok(out);
                }
                if self.ungated && cdb.get(..3) == Some(&[0x3c, 2, 0xb0]) {
                    assert_eq!(self.inner.knocks, 0);
                    assert!((1..=0xa4).contains(&len));
                    assert_eq!(&cdb[6..], &[0, 0, len as u8, 0]);
                    let at = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
                    return Ok(self.inner.dump[at..at + len].to_vec());
                }
                self.inner.command_in(cdb, len)
            }
            fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
                self.inner.command_out(cdb, data)
            }
            fn describe(&self) -> String {
                "saved older image replay; no hardware".into()
            }
        }
        let mut replay = Replay {
            inner: CaptureReplay {
                dump,
                reads: 0,
                knocks: 0,
                corrupt_second_pass: false,
            },
            inquiry,
            hardware: kernel.image[0x1000..0x1008].to_vec(),
            ungated: false,
        };
        // The modern length field is executable code here, not the image size.
        assert_ne!(
            u32::from_be_bytes(normal.image[20..24].try_into().unwrap()) as usize,
            normal.image.len()
        );
        let (captured_kernel, captured_normal, revision, _) =
            read_h8_image_pair(&mut replay).unwrap();
        assert_eq!(captured_kernel, kernel.image);
        assert_eq!(captured_normal, normal.image);
        assert_eq!(revision, h.revision);
        replay.ungated = true;
        replay.inner.knocks = 0;
        let (captured_kernel, captured_normal, _, _) = read_h8_image_pair(&mut replay).unwrap();
        assert_eq!(captured_kernel, kernel.image);
        assert_eq!(captured_normal, normal.image);
        assert_eq!(replay.inner.knocks, 0);
    }

    #[test]
    fn corpus_kernel_sharing_by_catalog_model_when_configured() {
        let Ok(root) = std::env::var("PIONEER_KERNEL_SHARING_ROOT") else {
            return;
        };
        let mut dirs = vec![std::path::PathBuf::from(root)];
        let mut cache = std::collections::HashMap::<Vec<u8>, Option<String>>::new();
        let mut groups =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
        let mut undecodable = std::collections::BTreeSet::new();
        let mut invalid_packages = 0;
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if !path.to_string_lossy().ends_with(".installer.tar") {
                    continue;
                }
                let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(&path).unwrap()) else {
                    invalid_packages += 1;
                    continue;
                };
                let Some(component) = bundle.components.iter().find(|c| c.role == Role::Kernel)
                else {
                    continue;
                };
                let envelope_hash = Sha256::digest(&component.bytes).to_vec();
                let raw_hash = cache.entry(envelope_hash.clone()).or_insert_with(|| {
                    pioneer_codec::decode_envelope(&component.bytes)
                        .map(|d| format!("{:x}", Sha256::digest(&d.image)))
                });
                let Some(raw_hash) = raw_hash else {
                    undecodable.insert(envelope_hash);
                    continue;
                };
                // Keep catalog models even when they use identical envelope bytes.
                let model = path
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                groups.entry(raw_hash.clone()).or_default().insert(model);
            }
        }
        assert!(!groups.is_empty(), "no decoded Kernels in corpus");
        let shared = groups.values().filter(|models| models.len() > 1).count();
        let models: std::collections::BTreeSet<_> = groups.values().flatten().collect();
        eprintln!("Kernel sharing: {} decoded image hashes, {} catalog models, {shared} cross-model groups, {} undecodable envelope hashes, {invalid_packages} invalid packages", groups.len(), models.len(), undecodable.len());
        for (hash, models) in groups.iter().filter(|(_, m)| m.len() > 1) {
            eprintln!("shared Kernel {hash}: {models:?}");
        }
    }

    #[test]
    fn corpus_kernel_dispatcher_selects_recorded_wrapper_when_configured() {
        let Ok(root) = std::env::var("PIONEER_INSTALLER_CORPUS_KAT_ROOT") else {
            return;
        };
        let mut dirs = vec![std::path::PathBuf::from(root)];
        let mut seen = std::collections::HashSet::new();
        let mut front = 0;
        let mut derived = 0;
        let mut literal_id_in_kernel = 0;
        let mut missing_literal_ids = Vec::new();
        let mut unrecognized = Vec::new();
        let mut unsupported_kernels = std::collections::BTreeMap::<String, usize>::new();
        let mut unsupported_normals = std::collections::BTreeMap::<String, usize>::new();
        let mut raw_metadata =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
        let mut kernel_revision_literals = 0;
        let mut kernel_date_literals = 0;
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if !path.to_string_lossy().ends_with(".installer.tar") {
                    continue;
                }
                let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(&path).unwrap()) else {
                    continue;
                };
                let Some(component) = bundle.components.iter().find(|c| c.role == Role::Kernel)
                else {
                    continue;
                };
                let digest = Sha256::digest(&component.bytes);
                if !seen.insert(digest.to_vec()) {
                    continue;
                }
                let Some(decoded) = pioneer_codec::decode_envelope(&component.bytes) else {
                    let hardware = pioneer_codec::header_info(&component.bytes)
                        .map(|h| h.hardware_version)
                        .unwrap_or_else(|| "invalid header".into());
                    *unsupported_kernels.entry(hardware).or_default() += 1;
                    continue;
                };
                if let Some(h) = pioneer_codec::header_info(&component.bytes) {
                    kernel_revision_literals += usize::from(
                        !h.revision.is_empty()
                            && decoded
                                .image
                                .windows(h.revision.len())
                                .any(|w| w == h.revision.as_bytes()),
                    );
                    kernel_date_literals += usize::from(
                        !h.generated_date.is_empty()
                            && decoded
                                .image
                                .windows(h.generated_date.len())
                                .any(|w| w == h.generated_date.as_bytes()),
                    );
                    raw_metadata
                        .entry(format!("{:x}", Sha256::digest(&decoded.image)))
                        .or_default()
                        .insert(format!("{} {} {}", h.model, h.revision, h.generated_date));
                }
                if let Some(normal) = bundle.components.iter().find(|c| c.role == Role::Main) {
                    if pioneer_codec::decode_envelope_with_kernel(&normal.bytes, &decoded).is_none()
                    {
                        let hardware = pioneer_codec::header_info(&normal.bytes)
                            .map(|h| h.hardware_version)
                            .unwrap_or_else(|| "invalid header".into());
                        *unsupported_normals.entry(hardware).or_default() += 1;
                    }
                    if let Some(header) = pioneer_codec::header_info(&normal.bytes) {
                        if decoded
                            .image
                            .windows(header.id.len())
                            .any(|w| w == header.id.as_bytes())
                        {
                            literal_id_in_kernel += 1;
                        } else {
                            missing_literal_ids.push(path.display().to_string());
                        }
                    }
                }
                let expected = match decoded.info.layout.as_str() {
                    "kernel-front" => {
                        front += 1;
                        pioneer_codec::builder::KernelLayout::FrontKey
                    }
                    "kernel-derived" => {
                        derived += 1;
                        pioneer_codec::builder::KernelLayout::DerivedKey
                    }
                    _ => continue,
                };
                let detected = pioneer_codec::builder::kernel_layout_from_image(&decoded.image);
                if detected.is_none() {
                    let signature = bundle
                        .components
                        .iter()
                        .find(|c| c.role == Role::Main)
                        .map(|c| pioneer_codec::signature::verify_normal_signature(&c.bytes));
                    unrecognized.push(format!("{} signature={signature:?}", path.display()));
                } else {
                    assert_eq!(detected, Some(expected), "{}", path.display());
                }
            }
        }
        assert!(front > 0 && derived > 0);
        eprintln!("Undecodable unique Kernels by hardware: {unsupported_kernels:?}");
        eprintln!("Undecodable receiver Normal per unique Kernel: {unsupported_normals:?}");
        eprintln!("Kernel header revision/date literals in decoded image: {kernel_revision_literals}/{kernel_date_literals}");
        for (hash, labels) in raw_metadata.iter().filter(|(_, labels)| labels.len() > 1) {
            eprintln!("identical raw Kernel {hash}, envelope labels: {labels:?}");
        }
        eprintln!("Kernel dispatcher corpus: {front} front, {derived} derived unique envelopes; {} unrecognized", unrecognized.len());
        eprintln!(
            "OEM ID literal in Kernel: {literal_id_in_kernel}; missing in {} cases",
            missing_literal_ids.len()
        );
        for path in missing_literal_ids.iter().take(12) {
            eprintln!("missing ID: {path}");
        }
        for path in &unrecognized {
            eprintln!("unrecognized: {path}");
        }
    }

    #[test]
    fn corpus_builder_reports_hardware_coverage_when_configured() {
        let Ok(root) = std::env::var("PIONEER_INSTALLER_CORPUS_KAT_ROOT") else {
            return;
        };
        let mut dirs = vec![std::path::PathBuf::from(root)];
        let mut seen_hardware = std::collections::HashSet::new();
        let all_pairs = std::env::var_os("PIONEER_ALL_PAIRS_KAT").is_some();
        let mut built = 0;
        let mut exact_text = 0;
        let mut exact_name = 0;
        let mut generated_name = 0;
        let mut signature_range_match = 0;
        let mut failures = Vec::new();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if !path.to_string_lossy().ends_with(".installer.tar") {
                    continue;
                }
                let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(&path).unwrap()) else {
                    continue;
                };
                let (Some(kernel), Some(normal)) = (
                    bundle.components.iter().find(|c| c.role == Role::Kernel),
                    bundle.components.iter().find(|c| c.role == Role::Main),
                ) else {
                    continue;
                };
                let Some(k) = pioneer_codec::decode_envelope(&kernel.bytes) else {
                    continue;
                };
                let Some(n) = pioneer_codec::decode_envelope_with_kernel(&normal.bytes, &k) else {
                    continue;
                };
                let Some(h) = pioneer_codec::header_info(&normal.bytes) else {
                    continue;
                };
                let identity = if all_pairs {
                    format!(
                        "{:x}:{:x}",
                        Sha256::digest(&kernel.bytes),
                        Sha256::digest(&normal.bytes)
                    )
                } else {
                    h.hardware_version.clone()
                };
                if !seen_hardware.insert(identity) {
                    continue;
                }
                let words: Vec<_> = h.id.split_whitespace().collect();
                if words.len() < 3 {
                    failures.push(format!(
                        "{}: OEM ID has no vendor/media/model",
                        h.hardware_version
                    ));
                    continue;
                }
                let vendor = words[0];
                let product = words[1..].join(" ");
                if vendor.len() > 8 || product.len() > 16 {
                    failures.push(format!(
                        "{}: OEM ID cannot form a SCSI INQUIRY",
                        h.hardware_version
                    ));
                    continue;
                }
                let mut inquiry = [b' '; 36];
                inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
                inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
                let id = embedded_envelope_id(&inquiry, &k.image, &n.image)
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                assert_eq!(id, h.id);
                match construct_signed_candidate(&k.image, &n.image, &id, &h.revision) {
                    Ok(output) => {
                        validate_envelope_package(&output, &product).unwrap();
                        let rebuilt = Bundle::from_tar_bytes(&output).unwrap();
                        let rebuilt_normal = rebuilt
                            .components
                            .iter()
                            .find(|c| c.role == Role::Main)
                            .unwrap();
                        built += 1;
                        exact_text +=
                            usize::from(rebuilt_normal.bytes[..0x160] == normal.bytes[..0x160]);
                        exact_name += usize::from(
                            rebuilt_normal.bytes[0x1f0..0x200] == normal.bytes[0x1f0..0x200],
                        );
                        if h.destination != "GENERAL" && !h.destination.starts_with("ID") {
                            assert!(rebuilt_normal.bytes[0x1f0..].starts_with(
                                format!("NORMAL.{}\0", h.revision.replace('.', "")).as_bytes()
                            ));
                            generated_name += 1;
                        }
                        signature_range_match += usize::from(if pioneer_codec::builder::normal_authentication_from_kernel(&k.image) == Some(pioneer_codec::builder::NormalAuthentication::ScaledChecksumOnly) {
                            pioneer_codec::builder::normal_authentication_valid(&normal.bytes, &k.image)
                                && pioneer_codec::builder::normal_authentication_valid(&rebuilt_normal.bytes, &k.image)
                        } else {
                            pioneer_codec::signature::verify_normal_signature(
                                &rebuilt_normal.bytes,
                            ) == pioneer_codec::signature::verify_normal_signature(&normal.bytes)
                        });
                    }
                    Err(error) => failures.push(format!("{}: {error:#}", h.hardware_version)),
                }
            }
        }
        eprintln!("builder corpus: {built} built, {} unsupported; {exact_text} exact textual headers, {exact_name} exact names, {signature_range_match} matching signature ranges", failures.len());
        for failure in &failures {
            eprintln!("unsupported: {failure}");
        }
        assert!(
            failures.is_empty(),
            "decoded OEM pairs failed reconstruction: {failures:?}"
        );
        assert!(built > 0);
        assert_eq!(exact_text, built, "OEM textual header drift");
        eprintln!("explicit generated Normal filenames: {generated_name}");
        assert_eq!(
            exact_name + generated_name,
            built,
            "unexplained embedded filename drift"
        );
        assert_eq!(signature_range_match, built, "OEM signature range drift");
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
        validate_envelope_package(&candidate, "BD-RW BDR-UD04").unwrap();
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
            let original_bytes = std::fs::read(path).unwrap();
            validate_envelope_package(&original_bytes, "BD-RW BDR-UD04").unwrap();
            let original = Bundle::from_tar_bytes(&original_bytes).unwrap();
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
            assert_eq!(&normal.bytes[..0x160], &original_normal.bytes[..0x160]);
            assert_eq!(
                &normal.bytes[0x160..0x170],
                &original_normal.bytes[0x160..0x170]
            );
            assert_eq!(
                &normal.bytes[0x1c0..0x200],
                &original_normal.bytes[0x1c0..0x200]
            );
            assert_ne!(&normal.bytes[0x200..], &original_normal.bytes[0x200..]);
            let generated_kernel = pioneer_codec::decode_envelope(&kernel.bytes).unwrap();
            let supplied_kernel = pioneer_codec::decode_envelope(&original_kernel.bytes).unwrap();
            let generated_normal =
                pioneer_codec::decode_envelope_with_kernel(&normal.bytes, &generated_kernel)
                    .unwrap();
            let supplied_normal = pioneer_codec::decode_envelope_with_kernel(
                &original_normal.bytes,
                &supplied_kernel,
            )
            .unwrap();
            assert_eq!(generated_kernel.encoding_seed(), Some(KERNEL_SEED));
            assert_eq!(generated_normal.encoding_seed(), Some(NORMAL_SEED));
            assert_eq!(generated_kernel.image, supplied_kernel.image);
            assert_eq!(generated_normal.image, supplied_normal.image);
            assert_eq!(
                &normal.bytes[0x1f0..0x200],
                &original_normal.bytes[0x1f0..0x200]
            );
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
        validate_envelope_package(&saved, "BD-RW BDR-UD04").unwrap();
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
