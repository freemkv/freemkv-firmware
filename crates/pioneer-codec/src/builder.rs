//! Template-free Pioneer envelope construction from captured images.
//! The resulting signatures are mathematically valid under a caller-owned key;
//! physical receiver acceptance remains unproved.

use super::signature::{verify_normal_signature, SignatureCheck, SigningKey};
use super::{
    be32_sum_zero, build_header, decode_envelope, decode_envelope_with_kernel, kernel_xor_branches,
    make_key, transform, transform_with_policy, PioneerHeaderInfo, PioneerHeaderOpaque,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelLayout {
    FrontKey,
    DerivedKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalAuthentication {
    Unsigned,
    ScaledChecksumOnly,
    KeyAndCiphertext,
    CiphertextOnly,
}

/// Geometry explicitly supplied to an older receiver's Normal decoder.
/// These are derived from instruction operands, not a hardware/model table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScaledNormalGeometry {
    pub image_len: usize,
    pub key_len: usize,
    pub envelope_len: usize,
}

/// Recognize the bounded legacy sequence: compare total length; reject on
/// mismatch; load payload address, image length and key address; call decoder.
/// Require the same decoder to be called for the Kernel, and require the
/// observed 16:1 image/key relationship. Unknown or ambiguous code returns None.
pub fn scaled_normal_geometry_from_kernel(kernel: &[u8]) -> Option<ScaledNormalGeometry> {
    let decoder = legacy_decoder_target(kernel)?;
    let mut matches = kernel.windows(32).filter_map(|w| {
        if w[..2] != [0x7a, 0x21]
            || w[6..8] != [0x58, 0x60]
            || w[10..12] != [0x7a, 0]
            || w[16..18] != [0x7a, 1]
            || w[22..28] != [0x7a, 2, 0, 1, 4, 0]
            || w[28..32] != decoder
        {
            return None;
        }
        let word = |i| u32::from_be_bytes(w[i..i + 4].try_into().unwrap()) as usize;
        let envelope_len = word(2);
        let image_len = word(18);
        let key_len = word(12).checked_sub(0x10400)?;
        if image_len < 0x2000
            || image_len % 0x100 != 0
            || key_len.checked_mul(16)? != image_len
            || 0x200usize.checked_add(key_len)?.checked_add(image_len)? != envelope_len
        {
            return None;
        }
        Some(ScaledNormalGeometry {
            image_len,
            key_len,
            envelope_len,
        })
    });
    let geometry = matches.next()?;
    matches.next().is_none().then_some(geometry)
}

/// Earlier receivers pass explicit staging addresses to the same decoder:
/// key=0x10400, Kernel=0x11400, length=0x10000. Relative to staging
/// base 0x10200 these are the front-key envelope offsets 0x200/0x1200.
/// Require a unique call site and resolve its target inside the captured Kernel.
fn legacy_decoder_target(kernel: &[u8]) -> Option<[u8; 4]> {
    const ARGS: &[u8] = &[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
    let mut calls = kernel.windows(16).enumerate().filter(|(offset, w)| {
        if w[..12] != *ARGS || w[12] != 0x5e {
            return false;
        }
        let long_length = offset.checked_sub(6).and_then(|i| kernel.get(i..*offset))
            == Some(&[0x7a, 1, 0, 1, 0, 0][..]);
        let high_word_length = offset.checked_sub(4).and_then(|i| kernel.get(i..*offset))
            == Some(&[0x79, 9, 0, 1][..])
            && offset
                .checked_sub(40)
                .and_then(|i| kernel.get(i..*offset))
                .is_some_and(|prefix| prefix.windows(2).any(|w| w == [0x1a, 0x91]));
        // An older receiver loads 0x11200 for its total-length comparison,
        // then clears R1H (the 0x12 byte), leaving ER1=0x10000.
        let cleared_length = offset
            .checked_sub(24)
            .and_then(|i| kernel.get(i..*offset))
            .is_some_and(|p| {
                p[..10] == [0x7a, 1, 0, 1, 0x12, 0, 0x1f, 0x90, 0x58, 0x60]
                    && p[12..16] == [0x1a, 0xc4, 0x01, 0]
                    && p[16..18] == [0x6b, 0xa4]
                    && p[22..24] == [0x18, 0x11]
            });
        long_length || high_word_length || cleared_length
    });
    let call: [u8; 4] = calls.next()?.1[12..16].try_into().ok()?;
    if calls.next().is_some() {
        return None;
    }
    let target = u32::from_be_bytes([0, call[1], call[2], call[3]]);
    let offset = target.checked_sub(0x400000)? as usize;
    kernel.get(offset..offset + 4)?;
    Some(call)
}

/// Recognize the earlier Normal decoder call, with no signature operation
/// between its length calculation and call. The signed successor instead
/// passes staging+0x170 to its validation routine before this decode.
pub fn normal_authentication_from_kernel(kernel: &[u8]) -> Option<NormalAuthentication> {
    if scaled_normal_geometry_from_kernel(kernel).is_some() {
        return Some(NormalAuthentication::ScaledChecksumOnly);
    }
    if let Some(call) = legacy_decoder_target(kernel) {
        const UNSIGNED_ARGS: &[u8] = &[
            0x7a, 0x31, 0, 1, 2, 0, 0x01, 0, 0x69, 0xf4, 0x0f, 0xf0, 0x79, 0x10, 0, 8, 0x01, 0,
            0x6f, 0xf0, 0, 4, 0x7a, 0, 0, 2, 4, 0, 0x7a, 2, 0, 1, 4, 0,
        ];
        let unsigned = kernel
            .windows(38)
            .filter(|w| w[..34] == *UNSIGNED_ARGS && w[34..] == call)
            .count();
        // mov.l #0xA10400,er0; mov.l #0xA10370,er2; jsr validator.
        let signed = kernel
            .windows(16)
            .filter(|w| {
                w[..12] == [0x7a, 0, 0, 0xa1, 4, 0, 0x7a, 2, 0, 0xa1, 3, 0x70]
                    && w[12] == 0x5e
                    && w[13] == 0x40
            })
            .count();
        return match (unsigned, signed) {
            (1, 0) => Some(NormalAuthentication::Unsigned),
            (0, 1) => Some(NormalAuthentication::KeyAndCiphertext),
            _ => None,
        };
    }
    match kernel_layout_from_image(kernel)? {
        KernelLayout::FrontKey => Some(NormalAuthentication::KeyAndCiphertext),
        KernelLayout::DerivedKey => Some(NormalAuthentication::CiphertextOnly),
    }
}

pub fn normal_authentication_valid(normal: &[u8], kernel: &[u8]) -> bool {
    match normal_authentication_from_kernel(kernel) {
        Some(NormalAuthentication::ScaledChecksumOnly) => {
            let Some(geometry) = scaled_normal_geometry_from_kernel(kernel) else {
                return false;
            };
            if normal.len() != geometry.envelope_len {
                return false;
            }
            let branches = kernel_xor_branches(kernel);
            let [(_, exceptions)] = branches.as_slice() else {
                return false;
            };
            let key_end = 0x200 + geometry.key_len;
            transform_with_policy(
                &normal[key_end..],
                &normal[0x200..key_end],
                false,
                false,
                exceptions,
            )
            .is_some_and(|image| image.starts_with(b"PIONEER ") && be32_sum_zero(&image))
        }
        Some(NormalAuthentication::Unsigned) => normal
            .get(0x170..0x1c0)
            .is_some_and(|bytes| bytes.iter().all(|b| *b == 0)),
        Some(NormalAuthentication::KeyAndCiphertext) => {
            verify_normal_signature(normal) == SignatureCheck::ValidKeyAndCiphertext
        }
        Some(NormalAuthentication::CiphertextOnly) => {
            verify_normal_signature(normal) == SignatureCheck::ValidCiphertextOnly
        }
        None => false,
    }
}

/// The two observed receiver dispatcher generations compare FE then F0 on
/// different H8 byte registers. This is a code signature, not a model table.
/// An unrecognized or ambiguous dispatcher must not be assigned a wrapper.
pub fn kernel_layout_from_image(kernel: &[u8]) -> Option<KernelLayout> {
    let paired_cmp = |reg: u8| {
        kernel
            .windows(8)
            .filter(|w| w[0..2] == [reg, 0xfe] && w[6..8] == [reg, 0xf0])
            .count()
    };
    match (
        paired_cmp(0xae),
        paired_cmp(0xad),
        legacy_decoder_target(kernel).is_some(),
    ) {
        (1, 0, false) | (0, 0, true) => Some(KernelLayout::FrontKey),
        (0, 1, false) => Some(KernelLayout::DerivedKey),
        _ => None,
    }
}

pub struct EncryptedPair {
    pub kernel: Vec<u8>,
    pub normal: Vec<u8>,
}

/// Key material for the Kernel key table.
///
/// Most OEM kernels derive the 0x1000-byte table from a 24-bit LCG seed, so
/// `Seed` is the common case (`make_key` expands it). A few kernels use a table
/// that is not LCG-derived; for those, supply the raw 0x1000 bytes verbatim with
/// `RawKey` (FrontKey layout only).
#[derive(Clone, Copy, Debug)]
pub enum KernelKeySource<'a> {
    /// 24-bit LCG seed; the low 24 bits are expanded into the key table.
    Seed(u32),
    /// Exactly 0x1000 raw key bytes used verbatim as the FrontKey table.
    RawKey(&'a [u8]),
}

/// Kernel header identity and key material supplied by the caller.
///
/// `revision`/`date` populate the Kernel header's `Revision Level`/`Generated
/// Date` fields and drive the embedded filename. [`KernelBuild::from_seed`]
/// reproduces the historical defaults (revision `0000`, date `00/00/00`).
#[derive(Clone, Copy, Debug)]
pub struct KernelBuild<'a> {
    pub revision: &'a str,
    pub date: &'a str,
    pub key: KernelKeySource<'a>,
}

impl<'a> KernelBuild<'a> {
    /// Historical defaults: header revision `0000`, date `00/00/00`, key from an
    /// LCG seed. Equivalent to the previous hardcoded Kernel header behavior.
    pub fn from_seed(seed: u32) -> Self {
        Self {
            revision: "0000",
            date: "00/00/00",
            key: KernelKeySource::Seed(seed),
        }
    }
}

/// The Normal ECDSA signature block (r, s, public point X, Y), occupying
/// `0x170..0x1c0` inside the 0x200 header.
pub const NORMAL_SIGNATURE_RANGE: std::ops::Range<usize> = 0x170..0x1c0;

/// How the Normal envelope's signature region is populated for a signed policy.
pub enum NormalSignature<'a> {
    /// Sign the body with a caller-owned key: mathematically valid but NOT the
    /// OEM signature (the public point differs). Used when no OEM signature is
    /// known and a self-consistent candidate is still wanted.
    Sign(&'a SigningKey),
    /// Stamp a verbatim OEM signature block (`NORMAL_SIGNATURE_RANGE`, 0x50
    /// bytes) recovered from the hoard, yielding a byte-exact OEM Normal.
    Oem(&'a [u8]),
    /// Leave the signature region all-zero: the deliberate, obvious "not OEM /
    /// unverified" sentinel. The resulting Normal does not pass ECDSA checks.
    Zeroed,
}

/// All non-image inputs are explicit so an archival label cannot be mistaken
/// for a fact recovered from flash. Seeds select fresh encoding tables.
pub struct BuildInputs<'a> {
    pub kernel_image: &'a [u8],
    pub normal_image: &'a [u8],
    pub envelope_id: &'a str,
    pub normal_revision: &'a str,
    pub normal_date: &'a str,
    /// Kernel header identity and key material. Use [`KernelBuild::from_seed`]
    /// for the historical defaults.
    pub kernel: KernelBuild<'a>,
    pub normal_key_seed: u32,
}

fn text(bytes: &[u8]) -> Result<&str, &'static str> {
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| "firmware identity is not ASCII")
}

fn filename(name: &str) -> Result<[u8; 16], &'static str> {
    if name.len() > 16 || !name.is_ascii() {
        return Err("invalid embedded filename");
    }
    let mut out = [0u8; 16];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Ok(out)
}

fn header(
    id: &str,
    hardware: &str,
    kernel_tag: &str,
    kernel_version2: &str,
    role: &str,
    revision: &str,
    date: &str,
    embedded_name: &str,
) -> Result<[u8; 0x200], &'static str> {
    let info = PioneerHeaderInfo {
        id: id.into(),
        model: id
            .split_whitespace()
            .last()
            .ok_or("envelope ID has no model")?
            .into(),
        revision: revision.into(),
        hardware_version: hardware.into(),
        kernel_version: kernel_tag.into(),
        destination: kernel_tag.into(),
        generated_date: date.into(),
        kernel_version2: kernel_version2.into(),
        file_type: role.into(),
    };
    let opaque = PioneerHeaderOpaque {
        id_left_padding: 0,
        prevalidation: [0; 0x10],
        validation: [0; 0x50],
        extension: [0; 0x30],
        filename: filename(embedded_name)?,
    };
    build_header(&info, &opaque).ok_or("Pioneer header fields do not fit")
}

/// Resolve the OEM destination code from a kernel tag: `GENERAL` maps to `00`,
/// and `ID<xx>` tags expose their two alphanumeric characters. Other tags have
/// no established OEM filename mapping.
fn destination_code(kernel_tag: &str) -> Option<&str> {
    if kernel_tag == "GENERAL" {
        Some("00")
    } else {
        kernel_tag
            .strip_prefix("ID")
            .filter(|code| code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphanumeric()))
    }
}

/// OEM Kernel filename scheme: `S<hw[4..]><dest>0.<revision digits>` (e.g.
/// hardware `SAT 8A10`, GENERAL, revision `1.00` -> `S8A10000.100`). Tags with
/// no destination mapping fall back to a generated archival label.
fn kernel_filename(hardware: &str, kernel_tag: &str, revision: &str) -> String {
    let rev = revision.replace('.', "");
    match destination_code(kernel_tag) {
        Some(code) => format!("S{}{code}0.{rev}", &hardware[4..]),
        None => format!("KERNEL.{rev}"),
    }
}

/// Build a byte-exact Kernel envelope from its decoded image and explicit
/// identity plus key material.
///
/// `envelope_id` is the full OEM `ID` string (recovered from drive identity or
/// an OEM envelope header); the hardware, kernel tag and version2 fields are
/// read from the image itself. The opaque header regions and the kernel
/// signature region are emitted as zeros, matching OEM kernels.
pub fn encode_kernel_envelope(
    kernel_image: &[u8],
    envelope_id: &str,
    build: &KernelBuild<'_>,
) -> Result<Vec<u8>, &'static str> {
    if kernel_image.len() != 0x10000
        || !be32_sum_zero(kernel_image)
        || !kernel_image
            .get(0x1000..0x1008)
            .is_some_and(|v| v.starts_with(b"SAT "))
    {
        return Err("captured Kernel image does not satisfy Pioneer H8/SAT structure");
    }
    let hardware = text(&kernel_image[0x1000..0x1008])?;
    let kernel_tag = text(&kernel_image[0x1008..0x1010])?;
    let kernel_version2 = text(&kernel_image[0x1010..0x1014])?;
    if !hardware.starts_with("SAT ")
        || hardware.len() != 8
        || kernel_tag.is_empty()
        || kernel_version2.is_empty()
        || envelope_id.split_whitespace().count() < 2
        || !envelope_id.is_ascii()
        || envelope_id.bytes().any(|b| b < 0x20 || b == 0x7f)
        || build.revision.is_empty()
        || build.date.is_empty()
        || build.date.len() > 10
        || !build.date.is_ascii()
    {
        return Err("captured Kernel image or drive identity is incomplete");
    }
    let layout = kernel_layout_from_image(kernel_image)
        .ok_or("Kernel receiver dispatcher does not identify a unique envelope layout")?;
    let name = kernel_filename(hardware, kernel_tag, build.revision);
    let mut enc = header(
        envelope_id,
        hardware,
        kernel_tag,
        kernel_version2,
        "Kernel",
        build.revision,
        build.date,
        &name,
    )?
    .to_vec();
    let key: Vec<u8> = match build.key {
        KernelKeySource::Seed(seed) => make_key(seed & 0x00ff_ffff, 0x1000),
        KernelKeySource::RawKey(bytes) => {
            if bytes.len() != 0x1000 {
                return Err("raw Kernel key must be exactly 0x1000 bytes");
            }
            bytes.to_vec()
        }
    };
    let cipher = transform(kernel_image, &key, true).ok_or("Kernel encode failed")?;
    match layout {
        KernelLayout::FrontKey => {
            enc.extend_from_slice(&key);
            enc.extend_from_slice(&cipher);
        }
        KernelLayout::DerivedKey => {
            let KernelKeySource::Seed(seed) = build.key else {
                return Err("derived-key Kernel requires an LCG seed, not raw key bytes");
            };
            enc.extend_from_slice(&cipher);
            // The 0x1000-byte trailer is one continuous LCG stream. The
            // decoder recovers state from its final 16 bytes, then walks
            // backward over the entire post-header stream plus key span.
            let steps = 0x11200 - 0x200 - 16 + 0x1000;
            let final_state = super::jump_seed(seed & 0x00ff_ffff, steps, false);
            let trailer_start = super::jump_seed(final_state, 0xff0, true);
            enc.extend_from_slice(&make_key(trailer_start, 0x1000));
        }
    }
    Ok(enc)
}

/// Build Kernel and Normal envelopes without a source `.enc` file.
/// This is an encrypted package candidate, not a proven rollback artifact.
pub fn encode_encrypted_pair(
    input: &BuildInputs<'_>,
    signature: NormalSignature<'_>,
) -> Result<EncryptedPair, &'static str> {
    let kernel = input.kernel_image;
    let normal = input.normal_image;
    let scaled = scaled_normal_geometry_from_kernel(kernel);
    if kernel.len() != 0x10000
        || normal.len() < 0x2000
        || normal.len() % 0x100 != 0
        || !be32_sum_zero(kernel)
        || !be32_sum_zero(normal)
        || !kernel
            .get(0x1000..0x1008)
            .is_some_and(|v| v.starts_with(b"SAT "))
        || !normal.get(..16).is_some_and(|v| v.starts_with(b"PIONEER "))
        || match scaled {
            Some(geometry) => geometry.image_len != normal.len(),
            None => u32::from_be_bytes(normal[20..24].try_into().unwrap()) as usize != normal.len(),
        }
    {
        return Err("captured images do not satisfy Pioneer H8/SAT image structure");
    }
    let hardware = text(&kernel[0x1000..0x1008])?;
    let kernel_tag = text(&kernel[0x1008..0x1010])?;
    let kernel_version2 = text(&kernel[0x1010..0x1014])?;
    let id = input.envelope_id;
    if !hardware.starts_with("SAT ")
        || hardware.len() != 8
        || kernel_tag.is_empty()
        || kernel_version2.is_empty()
        || id.split_whitespace().count() < 2
        || !id.is_ascii()
        || id.bytes().any(|b| b < 0x20 || b == 0x7f)
        || input.normal_revision.is_empty()
    {
        return Err("captured image or drive identity is incomplete");
    }
    let normal_revision_digits = input.normal_revision.replace('.', "");
    let normal_name = match destination_code(kernel_tag) {
        Some(code) => format!("S{}{code}1.{normal_revision_digits}", &hardware[4..]),
        // Generated archival label; retain the actual destination in the
        // header instead of inventing an OEM destination-to-filename mapping.
        None => format!("NORMAL.{normal_revision_digits}"),
    };
    if input.normal_date.is_empty() || input.normal_date.len() > 10 || !input.normal_date.is_ascii()
    {
        return Err("Normal build date is invalid");
    }
    let branches = kernel_xor_branches(kernel);
    let [(_, exceptions)] = branches.as_slice() else {
        return Err("Kernel XOR exception policy is not unique");
    };
    if exceptions
        .iter()
        .any(|off| *off as usize >= normal.len() || off % 4 != 0)
    {
        return Err("Kernel XOR exception is outside Normal image");
    }
    let kernel_layout = kernel_layout_from_image(kernel)
        .ok_or("Kernel receiver dispatcher does not identify a unique envelope layout")?;
    let kernel_enc = encode_kernel_envelope(kernel, id, &input.kernel)?;

    let mut normal_enc = header(
        id,
        hardware,
        kernel_tag,
        kernel_version2,
        "Normal",
        input.normal_revision,
        input.normal_date,
        &normal_name,
    )?
    .to_vec();
    let normal_key = make_key(
        input.normal_key_seed & 0x00ff_ffff,
        scaled.map_or(0x10000, |g| g.key_len),
    );
    normal_enc.extend_from_slice(&normal_key);
    normal_enc.extend_from_slice(
        &transform_with_policy(normal, &normal_key, true, false, exceptions)
            .ok_or("Normal encode failed")?,
    );
    // Policies that carry no body signature ignore the `signature` argument;
    // the header's signature region stays zero either way.
    let policy = normal_authentication_from_kernel(kernel)
        .ok_or("Kernel authentication policy is unknown")?;
    let mut zeroed_signature = false;
    match policy {
        NormalAuthentication::Unsigned | NormalAuthentication::ScaledChecksumOnly => {}
        NormalAuthentication::KeyAndCiphertext | NormalAuthentication::CiphertextOnly => {
            match signature {
                NormalSignature::Sign(signer) => {
                    if matches!(policy, NormalAuthentication::KeyAndCiphertext) {
                        signer.sign_normal(&mut normal_enc)?
                    } else {
                        signer.sign_normal_ciphertext_only(&mut normal_enc)?
                    }
                }
                NormalSignature::Oem(bytes) => {
                    if bytes.len() != NORMAL_SIGNATURE_RANGE.len() {
                        return Err("OEM Normal signature block must be exactly 0x50 bytes");
                    }
                    normal_enc[NORMAL_SIGNATURE_RANGE].copy_from_slice(bytes);
                }
                // Leave the signature region zero: the explicit non-OEM sentinel.
                NormalSignature::Zeroed => zeroed_signature = true,
            }
        }
    }
    let pair = EncryptedPair {
        kernel: kernel_enc,
        normal: normal_enc,
    };
    // A zeroed sentinel Normal deliberately fails ECDSA, so skip only the
    // signature check; structure, receiver-decode and image round-trip still run.
    validate_pair_inner(&pair, kernel, normal, kernel_layout, !zeroed_signature)?;
    Ok(pair)
}

/// Verify format, receiver-aware decode, exact captured images and ECDSA.
/// This does not certify the drive's public-key trust policy.
pub fn validate_encrypted_pair(
    pair: &EncryptedPair,
    kernel_image: &[u8],
    normal_image: &[u8],
    kernel_layout: KernelLayout,
) -> Result<(), &'static str> {
    validate_pair_inner(pair, kernel_image, normal_image, kernel_layout, true)
}

/// As [`validate_encrypted_pair`], but `check_signature == false` skips only the
/// ECDSA check (for a deliberately zeroed non-OEM sentinel Normal); every other
/// structural, receiver-decode and image-round-trip check still runs.
fn validate_pair_inner(
    pair: &EncryptedPair,
    kernel_image: &[u8],
    normal_image: &[u8],
    kernel_layout: KernelLayout,
    check_signature: bool,
) -> Result<(), &'static str> {
    let scaled = scaled_normal_geometry_from_kernel(kernel_image);
    if pair.kernel.len() != 0x1200 + kernel_image.len()
        || pair.normal.len() != scaled.map_or(0x10200 + normal_image.len(), |g| g.envelope_len)
        || (check_signature && !normal_authentication_valid(&pair.normal, kernel_image))
    {
        return Err("envelope size or Normal signature is invalid");
    }
    let kernel = decode_envelope(&pair.kernel).ok_or("Kernel envelope cannot be decoded")?;
    let normal = decode_envelope_with_kernel(&pair.normal, &kernel)
        .ok_or("Normal envelope cannot be receiver-decoded")?;
    let expected_kernel_layout = match kernel_layout {
        KernelLayout::FrontKey => "kernel-front",
        KernelLayout::DerivedKey => "kernel-derived",
    };
    if kernel.info.layout != expected_kernel_layout
        || normal.info.layout
            != if scaled.is_some() {
                "normal-scaled-key"
            } else {
                "normal"
            }
        || kernel.image != kernel_image
        || normal.image != normal_image
    {
        return Err("envelope round trip differs from captured firmware");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaled_receiver_geometry_matches_oem_when_configured() {
        let Ok(path) = std::env::var("PIONEER_SCALED_KERNEL_FIXTURE") else {
            return;
        };
        let normal_path = std::env::var("PIONEER_SCALED_NORMAL_FIXTURE").unwrap();
        let kernel = decode_envelope(&std::fs::read(path).unwrap()).unwrap();
        let normal_bytes = std::fs::read(normal_path).unwrap();
        let normal = decode_envelope_with_kernel(&normal_bytes, &kernel).unwrap();
        let geometry = scaled_normal_geometry_from_kernel(&kernel.image).unwrap();
        assert_eq!(geometry.image_len, normal.image.len());
        assert_eq!(geometry.envelope_len, normal_bytes.len());
        assert_eq!(geometry.key_len, normal.image.len() / 16);
        assert!(normal_authentication_valid(&normal_bytes, &kernel.image));
        let mut damaged = normal_bytes.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(!normal_authentication_valid(&damaged, &kernel.image));
        let h = super::super::header_info(&normal_bytes).unwrap();
        let mut private = [0; 20];
        private[19] = 5;
        let signer = SigningKey::from_bytes(private).unwrap();
        let rebuilt = encode_encrypted_pair(
            &BuildInputs {
                kernel_image: &kernel.image,
                normal_image: &normal.image,
                envelope_id: &h.id,
                normal_revision: &h.revision,
                normal_date: &h.generated_date,
                kernel: KernelBuild::from_seed(1),
                normal_key_seed: 0x47d001,
            },
            NormalSignature::Sign(&signer),
        );
        let rebuilt = rebuilt.unwrap();
        validate_encrypted_pair(
            &rebuilt,
            &kernel.image,
            &normal.image,
            KernelLayout::FrontKey,
        )
        .unwrap();
        if !h.destination.starts_with("ID") {
            assert!(rebuilt.normal[0x1f0..].starts_with(b"NORMAL."));
            assert_eq!(
                super::super::header_info(&rebuilt.normal)
                    .unwrap()
                    .destination,
                h.destination
            );
        }
        assert_eq!(
            kernel_layout_from_image(&kernel.image),
            Some(KernelLayout::FrontKey)
        );

        // An inconsistent decoder image length cannot become an inferred read
        // size; duplicate valid call sites must also fail as ambiguous.
        let mut changed = kernel.image.clone();
        let decoder = legacy_decoder_target(&changed).unwrap();
        let at = changed
            .windows(32)
            .position(|w| w[..2] == [0x7a, 0x21] && w[28..] == decoder)
            .unwrap();
        changed[at + 21] ^= 1;
        assert_eq!(scaled_normal_geometry_from_kernel(&changed), None);
        let mut ambiguous = kernel.image.clone();
        ambiguous.extend_from_slice(&kernel.image[at..at + 32]);
        assert_eq!(scaled_normal_geometry_from_kernel(&ambiguous), None);
    }

    #[test]
    fn live_ud04_images_make_independent_encrypted_pair_when_configured() {
        let Ok(path) = std::env::var("PIONEER_LIVE_DUMP_FIXTURE") else {
            return;
        };
        let dump = std::fs::read(path).unwrap();
        assert_eq!(dump.len(), 0x600000);
        let kernel = &dump[0x400000..0x410000];
        let normal = &dump[0x410000..0x5d7500];
        let mut private = [0u8; 20];
        private[19] = 5;
        let signer = SigningKey::from_bytes(private).unwrap();
        let input = BuildInputs {
            kernel_image: kernel,
            normal_image: normal,
            envelope_id: "PIONEER BD-RW   BDR-UD04",
            normal_revision: "1.14",
            normal_date: "20/06/15",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        };
        let pair = encode_encrypted_pair(&input, NormalSignature::Sign(&signer)).unwrap();
        assert_eq!(
            decode_envelope(&pair.kernel).unwrap().encoding_seed(),
            Some(0x123456)
        );
        assert_eq!(
            decode_envelope(&pair.normal).unwrap().encoding_seed(),
            Some(input.normal_key_seed)
        );
        validate_encrypted_pair(&pair, kernel, normal, KernelLayout::FrontKey).unwrap();
        assert_eq!(pair.kernel.len(), 0x11200);
        assert_eq!(pair.normal.len(), 0x1d7700);
        let mut tampered = pair;
        tampered.normal[0x1d7600] ^= 1;
        assert!(
            validate_encrypted_pair(&tampered, kernel, normal, KernelLayout::FrontKey).is_err()
        );

        assert_eq!(
            kernel_layout_from_image(kernel),
            Some(KernelLayout::FrontKey)
        );
    }

    // ---- Synthetic-fixture coverage for the recognizers and guards ----

    fn be32_fix(buf: &mut [u8], fix_at: usize) {
        buf[fix_at..fix_at + 4].copy_from_slice(&[0; 4]);
        let mut sum = 0u32;
        let mut i = 0;
        while i + 4 <= buf.len() {
            sum = sum.wrapping_add(u32::from_be_bytes([
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
            ]));
            i += 4;
        }
        buf[fix_at..fix_at + 4].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    }

    fn write_branch(buf: &mut [u8], at: usize, offs: [u32; 2]) {
        buf[at] = 0x7a;
        buf[at + 1] = 0x20;
        buf[at + 2..at + 6].copy_from_slice(&offs[0].to_be_bytes());
        buf[at + 6] = 0x47;
        buf[at + 7] = 12;
        buf[at + 8] = 0x7a;
        buf[at + 9] = 0x20;
        buf[at + 10..at + 14].copy_from_slice(&offs[1].to_be_bytes());
        buf[at + 14] = 0x47;
        buf[at + 15] = 4;
        buf[at + 16..at + 20].copy_from_slice(&[1, 0xf0, 0x65, 5]);
    }

    fn front_kernel_with(branch: [u32; 2]) -> Vec<u8> {
        let mut k = vec![0u8; 0x10000];
        k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
        k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
        k[0x1010..0x1014].copy_from_slice(b"0000");
        k[0x40] = 0xae;
        k[0x41] = 0xfe;
        k[0x46] = 0xae;
        k[0x47] = 0xf0;
        write_branch(&mut k, 0x100, branch);
        be32_fix(&mut k, 0xff00);
        k
    }

    fn front_kernel() -> Vec<u8> {
        front_kernel_with([0x100, 0x200])
    }

    fn normal_image(len: usize) -> Vec<u8> {
        let mut n = vec![0u8; len];
        n[..8].copy_from_slice(b"PIONEER ");
        n[20..24].copy_from_slice(&(len as u32).to_be_bytes());
        be32_fix(&mut n, len - 0x100);
        n
    }

    const DECODER: [u8; 4] = [0x5e, 0x40, 0x01, 0x00];

    fn with_legacy_site(k: &mut [u8], at: usize, decoder: [u8; 4]) {
        const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
        k[at - 6..at].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
        k[at..at + 12].copy_from_slice(&ARGS);
        k[at + 12..at + 16].copy_from_slice(&decoder);
    }

    #[allow(clippy::too_many_arguments)]
    fn scaled_window(k: &mut [u8], at: usize, env: u32, keyword: u32, img: u32, decoder: [u8; 4]) {
        k[at] = 0x7a;
        k[at + 1] = 0x21;
        k[at + 2..at + 6].copy_from_slice(&env.to_be_bytes());
        k[at + 6] = 0x58;
        k[at + 7] = 0x60;
        k[at + 10] = 0x7a;
        k[at + 11] = 0;
        k[at + 12..at + 16].copy_from_slice(&keyword.to_be_bytes());
        k[at + 16] = 0x7a;
        k[at + 17] = 1;
        k[at + 18..at + 22].copy_from_slice(&img.to_be_bytes());
        k[at + 22..at + 28].copy_from_slice(&[0x7a, 2, 0, 1, 4, 0]);
        k[at + 28..at + 32].copy_from_slice(&decoder);
    }

    fn base_inputs<'a>(kernel: &'a [u8], normal: &'a [u8]) -> BuildInputs<'a> {
        BuildInputs {
            kernel_image: kernel,
            normal_image: normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        }
    }

    fn a_signer() -> SigningKey {
        let mut private = [0u8; 20];
        private[19] = 5;
        SigningKey::from_bytes(private).unwrap()
    }

    #[test]
    fn legacy_decoder_target_requires_unique_site_and_in_range_target() {
        let mut k = vec![0u8; 0x2000];
        with_legacy_site(&mut k, 0x300, DECODER);
        assert_eq!(legacy_decoder_target(&k), Some(DECODER));

        // Target resolving outside the image is rejected.
        let mut out = vec![0u8; 0x2000];
        with_legacy_site(&mut out, 0x300, [0x5e, 0x60, 0x00, 0x00]);
        assert!(legacy_decoder_target(&out).is_none());

        // Two valid call sites are ambiguous.
        let mut amb = vec![0u8; 0x2000];
        with_legacy_site(&mut amb, 0x300, DECODER);
        with_legacy_site(&mut amb, 0x800, DECODER);
        assert!(legacy_decoder_target(&amb).is_none());

        // The argument block without any recognized length prelude is not a site.
        let mut nolen = vec![0u8; 0x2000];
        nolen[0x300..0x30c].copy_from_slice(&[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0]);
        nolen[0x30c..0x310].copy_from_slice(&DECODER);
        assert!(legacy_decoder_target(&nolen).is_none());
    }

    #[test]
    fn scaled_geometry_enforces_the_16_to_1_relationship() {
        let mut k = vec![0u8; 0x2000];
        with_legacy_site(&mut k, 0x300, DECODER);
        scaled_window(&mut k, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
        let g = scaled_normal_geometry_from_kernel(&k).unwrap();
        assert_eq!(
            (g.image_len, g.key_len, g.envelope_len),
            (0x2000, 0x200, 0x2400)
        );

        // key_len * 16 must equal image_len.
        let mut bad = vec![0u8; 0x2000];
        with_legacy_site(&mut bad, 0x300, DECODER);
        scaled_window(&mut bad, 0x400, 0x2500, 0x10700, 0x2000, DECODER);
        assert!(scaled_normal_geometry_from_kernel(&bad).is_none());

        // 0x200 + key_len + image_len must equal envelope_len.
        let mut bad_env = vec![0u8; 0x2000];
        with_legacy_site(&mut bad_env, 0x300, DECODER);
        scaled_window(&mut bad_env, 0x400, 0x2401, 0x10600, 0x2000, DECODER);
        assert!(scaled_normal_geometry_from_kernel(&bad_env).is_none());

        // image_len below the 0x2000 minimum is rejected.
        let mut small = vec![0u8; 0x2000];
        with_legacy_site(&mut small, 0x300, DECODER);
        scaled_window(&mut small, 0x400, 0x1300, 0x10500, 0x1000, DECODER);
        assert!(scaled_normal_geometry_from_kernel(&small).is_none());

        // The window's decoder word must match the resolved call target.
        let mut mismatch = vec![0u8; 0x2000];
        with_legacy_site(&mut mismatch, 0x300, DECODER);
        scaled_window(
            &mut mismatch,
            0x400,
            0x2400,
            0x10600,
            0x2000,
            [0x5e, 0x40, 0x02, 0x00],
        );
        assert!(scaled_normal_geometry_from_kernel(&mismatch).is_none());

        // Two identical windows are ambiguous.
        let mut dup = vec![0u8; 0x2000];
        with_legacy_site(&mut dup, 0x300, DECODER);
        scaled_window(&mut dup, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
        scaled_window(&mut dup, 0x800, 0x2400, 0x10600, 0x2000, DECODER);
        assert!(scaled_normal_geometry_from_kernel(&dup).is_none());
    }

    #[test]
    fn legacy_normal_authentication_distinguishes_unsigned_and_signed() {
        const UNSIGNED_ARGS: [u8; 34] = [
            0x7a, 0x31, 0, 1, 2, 0, 0x01, 0, 0x69, 0xf4, 0x0f, 0xf0, 0x79, 0x10, 0, 8, 0x01, 0,
            0x6f, 0xf0, 0, 4, 0x7a, 0, 0, 2, 4, 0, 0x7a, 2, 0, 1, 4, 0,
        ];
        let mut unsigned = vec![0u8; 0x2000];
        with_legacy_site(&mut unsigned, 0x300, DECODER);
        unsigned[0x400..0x422].copy_from_slice(&UNSIGNED_ARGS);
        unsigned[0x422..0x426].copy_from_slice(&DECODER);
        assert_eq!(
            normal_authentication_from_kernel(&unsigned),
            Some(NormalAuthentication::Unsigned)
        );

        let mut signed = vec![0u8; 0x2000];
        with_legacy_site(&mut signed, 0x300, DECODER);
        signed[0x400..0x40e].copy_from_slice(&[
            0x7a, 0, 0, 0xa1, 4, 0, 0x7a, 2, 0, 0xa1, 3, 0x70, 0x5e, 0x40,
        ]);
        assert_eq!(
            normal_authentication_from_kernel(&signed),
            Some(NormalAuthentication::KeyAndCiphertext)
        );

        // Neither marker present -> ambiguous -> None.
        let mut neither = vec![0u8; 0x2000];
        with_legacy_site(&mut neither, 0x300, DECODER);
        assert_eq!(normal_authentication_from_kernel(&neither), None);

        // Unsigned validity is the all-zero header signature region.
        let mut normal = vec![0u8; 0x2000];
        assert!(normal_authentication_valid(&normal, &unsigned));
        normal[0x180] = 1;
        assert!(!normal_authentication_valid(&normal, &unsigned));
    }

    #[test]
    fn destination_code_maps_general_and_id_tags_only() {
        assert_eq!(destination_code("GENERAL"), Some("00"));
        assert_eq!(destination_code("ID72"), Some("72"));
        assert_eq!(destination_code("IDAB"), Some("AB"));
        assert_eq!(destination_code("ID7"), None);
        assert_eq!(destination_code("ID7!"), None);
        assert_eq!(destination_code("OTHER"), None);
    }

    #[test]
    fn filename_rejects_overlong_or_non_ascii() {
        assert_eq!(&filename("S8A10001.114").unwrap()[..12], b"S8A10001.114");
        assert_eq!(filename("0123456789ABCDEF").unwrap().len(), 16);
        assert!(filename("0123456789ABCDEFG").is_err());
        assert!(filename("café.bin").is_err());
    }

    #[test]
    fn kernel_filename_follows_the_oem_scheme() {
        assert_eq!(
            kernel_filename("SAT 8A10", "GENERAL", "1.00"),
            "S8A10000.100"
        );
        assert_eq!(kernel_filename("SAT 8A10", "ID72", "1.14"), "S8A10720.114");
        // Tags with no destination mapping fall back to a generated label.
        assert_eq!(kernel_filename("SAT 8A10", "OTHER", "1.00"), "KERNEL.100");
    }

    // A high-word-length call site; `with_1a91` toggles the required marker.
    fn high_word_site(k: &mut [u8], at: usize, with_1a91: bool, decoder: [u8; 4]) {
        k[at - 4..at].copy_from_slice(&[0x79, 9, 0, 1]);
        if with_1a91 {
            k[at - 40..at - 38].copy_from_slice(&[0x1a, 0x91]);
        }
        const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
        k[at..at + 12].copy_from_slice(&ARGS);
        k[at + 12..at + 16].copy_from_slice(&decoder);
    }

    // A cleared-length call site; the flags select which sub-field is correct.
    fn cleared_site(k: &mut [u8], at: usize, p12: bool, p16: bool, p22: bool, decoder: [u8; 4]) {
        let base = at - 24;
        k[base..base + 10].copy_from_slice(&[0x7a, 1, 0, 1, 0x12, 0, 0x1f, 0x90, 0x58, 0x60]);
        k[base + 12..base + 16].copy_from_slice(if p12 {
            &[0x1a, 0xc4, 0x01, 0]
        } else {
            &[0, 0, 0, 0]
        });
        k[base + 16..base + 18].copy_from_slice(if p16 { &[0x6b, 0xa4] } else { &[0, 0] });
        k[base + 22..base + 24].copy_from_slice(if p22 { &[0x18, 0x11] } else { &[0, 0] });
        const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
        k[at..at + 12].copy_from_slice(&ARGS);
        k[at + 12..at + 16].copy_from_slice(&decoder);
    }

    #[test]
    fn legacy_decoder_target_prelude_variants_and_bounds() {
        // A non-0x5e opcode with a long prelude must be rejected; `|| -> &&`
        // on the opcode check would accept it.
        let mut wrong_op = vec![0u8; 0x1000];
        wrong_op[0x300 - 6..0x300].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
        wrong_op[0x300..0x30c]
            .copy_from_slice(&[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0]);
        wrong_op[0x30c..0x310].copy_from_slice(&[0x5f, 0x40, 0x01, 0x00]);
        assert!(legacy_decoder_target(&wrong_op).is_none());

        // Valid high-word call site is recognized (guards its `==` and the final
        // `high || cleared` combinator).
        let mut hw = vec![0u8; 0x1000];
        high_word_site(&mut hw, 0x300, true, DECODER);
        assert_eq!(legacy_decoder_target(&hw), Some(DECODER));
        // High-word prefix without the 0x1a91 marker is not a site; `&& -> ||`
        // or `== -> !=` in that clause would wrongly accept it.
        let mut hw_no = vec![0u8; 0x1000];
        high_word_site(&mut hw_no, 0x300, false, DECODER);
        assert!(legacy_decoder_target(&hw_no).is_none());

        // Valid cleared-length call site is recognized (guards its `==` chain).
        let mut cl = vec![0u8; 0x1000];
        cleared_site(&mut cl, 0x300, true, true, true, DECODER);
        assert_eq!(legacy_decoder_target(&cl), Some(DECODER));
        // Each cleared sub-field, wrong in isolation, must reject (guards the
        // `&&` chain and its `==` operators).
        for (p12, p16, p22) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let mut c = vec![0u8; 0x1000];
            cleared_site(&mut c, 0x300, p12, p16, p22, DECODER);
            assert!(legacy_decoder_target(&c).is_none());
        }

        // Target valid for `+ 4` but out of range for `* 4`.
        let mut small = vec![0u8; 0x200];
        small[0x180 - 6..0x180].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
        small[0x180..0x18c].copy_from_slice(&[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0]);
        small[0x18c..0x190].copy_from_slice(&DECODER);
        assert_eq!(legacy_decoder_target(&small), Some(DECODER));
    }

    #[test]
    fn scaled_geometry_window_field_isolation() {
        let mut base = vec![0u8; 0x2000];
        with_legacy_site(&mut base, 0x300, DECODER);
        scaled_window(&mut base, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
        assert!(scaled_normal_geometry_from_kernel(&base).is_some());
        // Corrupt each marker field (w[6..8], w[10..12], w[16..18], w[22..28]):
        // the window must stop matching, so a `|| -> &&` on the field chain
        // (which would accept the near-match) is caught.
        for off in [0x406usize, 0x40a, 0x410, 0x416] {
            let mut k = base.clone();
            k[off] ^= 0xff;
            assert!(scaled_normal_geometry_from_kernel(&k).is_none());
        }
    }

    fn front_kernel_field(mut mutate: impl FnMut(&mut Vec<u8>)) -> Vec<u8> {
        let mut k = front_kernel();
        mutate(&mut k);
        be32_fix(&mut k, 0xff00);
        k
    }

    #[test]
    fn encode_kernel_second_guard_isolation() {
        let valid = front_kernel();
        let b = KernelBuild::from_seed(1);
        assert!(encode_kernel_envelope(&valid, "PIONEER BDR-TEST", &b).is_ok());
        // hardware length != 8 (still starts "SAT ") -> rejected.
        let hw7 = front_kernel_field(|k| k[0x1000..0x1008].copy_from_slice(b"SAT 8A1 "));
        assert!(encode_kernel_envelope(&hw7, "PIONEER BDR-TEST", &b).is_err());
        // empty kernel tag -> rejected.
        let tag0 = front_kernel_field(|k| k[0x1008..0x1010].copy_from_slice(b"        "));
        assert!(encode_kernel_envelope(&tag0, "PIONEER BDR-TEST", &b).is_err());
        // empty version2 -> rejected.
        let v20 = front_kernel_field(|k| k[0x1010..0x1014].copy_from_slice(b"    "));
        assert!(encode_kernel_envelope(&v20, "PIONEER BDR-TEST", &b).is_err());
        // A date of exactly 10 chars is valid (isolates `> 10` vs `== 10`/`>= 10`).
        assert!(encode_kernel_envelope(
            &valid,
            "PIONEER BDR-TEST",
            &KernelBuild {
                revision: "1.00",
                date: "0123456789",
                key: KernelKeySource::Seed(1),
            }
        )
        .is_ok());
    }

    #[test]
    fn encode_pair_guard_isolation() {
        let kernel = front_kernel();
        let s = a_signer();
        let n = normal_image(0x2000);
        assert!(
            encode_encrypted_pair(&base_inputs(&kernel, &n), NormalSignature::Sign(&s)).is_ok()
        );
        // A larger valid normal still works (isolates `< 0x2000` vs `> 0x2000`).
        let big = normal_image(0x4000);
        assert!(
            encode_encrypted_pair(&base_inputs(&kernel, &big), NormalSignature::Sign(&s)).is_ok()
        );
        // normal below 0x2000 -> rejected.
        let small = normal_image(0x1000);
        assert!(
            encode_encrypted_pair(&base_inputs(&kernel, &small), NormalSignature::Sign(&s))
                .is_err()
        );
        // normal length not a multiple of 0x100 (be32 still zero) -> rejected.
        let misaligned = normal_image(0x2080);
        assert!(encode_encrypted_pair(
            &base_inputs(&kernel, &misaligned),
            NormalSignature::Sign(&s)
        )
        .is_err());
        // Empty normal_revision -> rejected (not re-checked by encode_kernel).
        let mut empty_rev = base_inputs(&kernel, &n);
        empty_rev.normal_revision = "";
        assert!(encode_encrypted_pair(&empty_rev, NormalSignature::Sign(&s)).is_err());
        // Empty normal_date -> rejected (an empty date is accepted by build_header,
        // so this isolates the `is_empty` branch of the date guard).
        let mut empty_date = base_inputs(&kernel, &n);
        empty_date.normal_date = "";
        assert!(encode_encrypted_pair(&empty_date, NormalSignature::Sign(&s)).is_err());
        // A 10-char date is valid (isolates `> 10` vs `== 10`/`>= 10`).
        let mut date10 = base_inputs(&kernel, &n);
        date10.normal_date = "0123456789";
        assert!(encode_encrypted_pair(&date10, NormalSignature::Sign(&s)).is_ok());
        // An id with more than two tokens is valid (isolates `< 2` vs `> 2`).
        let mut three = base_inputs(&kernel, &n);
        three.envelope_id = "PIONEER BD RW BDR-TEST";
        assert!(encode_encrypted_pair(&three, NormalSignature::Sign(&s)).is_ok());
    }

    #[test]
    fn kernel_layout_requires_full_compare_pair() {
        // [reg,0xfe] without the matching [reg,0xf0] at +6 must not count as a
        // dispatcher compare pair; `&& -> ||` would count it.
        let mut k = vec![0u8; 0x2000];
        k[0x40] = 0xae;
        k[0x41] = 0xfe;
        assert!(kernel_layout_from_image(&k).is_none());
    }

    #[test]
    fn normal_authentication_valid_scaled_requires_zero_checksum() {
        let mut kernel = vec![0u8; 0x2000];
        with_legacy_site(&mut kernel, 0x300, DECODER);
        scaled_window(&mut kernel, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
        write_branch(&mut kernel, 0x600, [0x100, 0x200]);
        assert_eq!(
            normal_authentication_from_kernel(&kernel),
            Some(NormalAuthentication::ScaledChecksumOnly)
        );
        // A scaled normal whose decoded image starts PIONEER but is NOT
        // big-endian-sum-zero must be rejected; `&& -> ||` on the final check
        // would accept it on the PIONEER prefix alone.
        let mut image = vec![0u8; 0x2000];
        image[..8].copy_from_slice(b"PIONEER ");
        image[0x400] = 1; // non-zero checksum
        let key = make_key(0x47d001, 0x200);
        let mut normal = vec![0u8; 0x200]; // header region is irrelevant here
        normal.extend_from_slice(&key);
        normal.extend_from_slice(
            &transform_with_policy(&image, &key, true, false, &[0x100, 0x200]).unwrap(),
        );
        assert_eq!(normal.len(), 0x2400);
        assert!(!normal_authentication_valid(&normal, &kernel));
    }

    #[test]
    fn validate_pair_inner_guard_isolation() {
        let kernel = front_kernel();
        let n = normal_image(0x2000);
        let s = a_signer();
        let pair =
            encode_encrypted_pair(&base_inputs(&kernel, &n), NormalSignature::Sign(&s)).unwrap();
        validate_encrypted_pair(&pair, &kernel, &n, KernelLayout::FrontKey).unwrap();

        // Tamper the signature region only: structure and images stay valid, so
        // only the signature check fails. A `|| -> &&` would skip it and pass.
        let mut tampered = EncryptedPair {
            kernel: pair.kernel.clone(),
            normal: pair.normal.clone(),
        };
        tampered.normal[0x180] ^= 1;
        assert!(validate_encrypted_pair(&tampered, &kernel, &n, KernelLayout::FrontKey).is_err());

        // A different (but same-shape) kernel image: only the kernel-image
        // comparison fails.
        let other_k = front_kernel_field(|k| k[0x6000] ^= 1);
        assert!(validate_encrypted_pair(&pair, &other_k, &n, KernelLayout::FrontKey).is_err());

        // A different (same-length) normal image: only the normal-image
        // comparison fails.
        let mut other_n = n.clone();
        other_n[0x50] ^= 1;
        assert!(validate_encrypted_pair(&pair, &kernel, &other_n, KernelLayout::FrontKey).is_err());
    }

    #[test]
    fn encode_kernel_envelope_rejects_bad_identity_and_image() {
        let k = front_kernel();
        assert!(encode_kernel_envelope(&k, "PIONEER BDR-TEST", &KernelBuild::from_seed(1)).is_ok());
        // Wrong image length.
        assert!(encode_kernel_envelope(
            &k[..0xfffc],
            "PIONEER BDR-TEST",
            &KernelBuild::from_seed(1)
        )
        .is_err());
        // Broken big-endian checksum.
        let mut bad_sum = k.clone();
        bad_sum[0x3000] ^= 1;
        assert!(
            encode_kernel_envelope(&bad_sum, "PIONEER BDR-TEST", &KernelBuild::from_seed(1))
                .is_err()
        );
        // Missing SAT identity (checksum re-fixed so only SAT differs).
        let mut no_sat = k.clone();
        no_sat[0x1000] = b'X';
        be32_fix(&mut no_sat, 0xff00);
        assert!(
            encode_kernel_envelope(&no_sat, "PIONEER BDR-TEST", &KernelBuild::from_seed(1))
                .is_err()
        );
        // Envelope ID without a model token.
        assert!(encode_kernel_envelope(&k, "PIONEER", &KernelBuild::from_seed(1)).is_err());
        // Non-ASCII identity.
        assert!(encode_kernel_envelope(&k, "PIONEER BDR-É", &KernelBuild::from_seed(1)).is_err());
        // Empty revision and too-long date.
        assert!(encode_kernel_envelope(
            &k,
            "PIONEER BDR-TEST",
            &KernelBuild {
                revision: "",
                date: "00/00/00",
                key: KernelKeySource::Seed(1)
            }
        )
        .is_err());
        assert!(encode_kernel_envelope(
            &k,
            "PIONEER BDR-TEST",
            &KernelBuild {
                revision: "1.00",
                date: "0123456789A",
                key: KernelKeySource::Seed(1)
            }
        )
        .is_err());
    }

    #[test]
    fn encode_encrypted_pair_rejects_malformed_normal_and_exceptions() {
        let kernel = front_kernel();
        let normal = normal_image(0x2000);
        let s = a_signer();
        assert!(
            encode_encrypted_pair(&base_inputs(&kernel, &normal), NormalSignature::Sign(&s))
                .is_ok()
        );

        // Normal not a multiple of 0x100.
        let mut odd = normal.clone();
        odd.extend_from_slice(&[0u8; 4]);
        assert!(
            encode_encrypted_pair(&base_inputs(&kernel, &odd), NormalSignature::Sign(&s)).is_err()
        );

        // Normal missing the PIONEER prefix (checksum re-fixed).
        let mut no_pioneer = normal.clone();
        let fix_at = no_pioneer.len() - 0x100;
        no_pioneer[0] = b'X';
        be32_fix(&mut no_pioneer, fix_at);
        assert!(encode_encrypted_pair(
            &base_inputs(&kernel, &no_pioneer),
            NormalSignature::Sign(&s)
        )
        .is_err());

        // Declared size (bytes 20..24) disagreeing with the actual length.
        let mut wrong_declared = normal.clone();
        let fix_at = wrong_declared.len() - 0x100;
        wrong_declared[20..24].copy_from_slice(&0x3000u32.to_be_bytes());
        be32_fix(&mut wrong_declared, fix_at);
        assert!(encode_encrypted_pair(
            &base_inputs(&kernel, &wrong_declared),
            NormalSignature::Sign(&s)
        )
        .is_err());

        // Broken big-endian checksum on an otherwise valid Normal.
        let mut bad_sum = normal.clone();
        bad_sum[0x44] ^= 1;
        assert!(
            encode_encrypted_pair(&base_inputs(&kernel, &bad_sum), NormalSignature::Sign(&s))
                .is_err()
        );

        // A XOR exception offset outside the Normal image is rejected.
        let big_exc_kernel = front_kernel_with([0x100, 0x4000]);
        assert!(encode_encrypted_pair(
            &base_inputs(&big_exc_kernel, &normal),
            NormalSignature::Sign(&s)
        )
        .is_err());

        // A non-unique XOR branch policy is rejected.
        let mut two_branches = front_kernel();
        write_branch(&mut two_branches, 0x600, [0x100, 0x200]);
        be32_fix(&mut two_branches, 0xff00);
        assert!(encode_encrypted_pair(
            &base_inputs(&two_branches, &normal),
            NormalSignature::Sign(&s)
        )
        .is_err());
    }
}
