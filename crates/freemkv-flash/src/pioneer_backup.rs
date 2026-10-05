//! Offline image-to-envelope reconstruction. This does not establish that a
//! capture came from persistent flash, covers all writable state, or can restore
//! a drive. Live backup/flash capability remains gated separately.

use crate::pioneer_bundle::{Bundle, Role};
use crate::platform::ScsiDevice;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Build an encrypted package directly from two captured images.
///
/// The KERNEL is reconstructed byte-for-byte OEM when its decoded image is one
/// of our known OEM kernels (`crate::pioneer_k`): real revision/date and the
/// OEM key table. An unrecognized kernel gets honest zero placeholders —
/// revision `0000`, date `00/00/00`, seed `0` — so the output plainly reads as
/// "not OEM". The NORMAL self-recovers its real revision/date from its own body
/// and is signed with a fresh caller-owned key (seed `0`); it is intentionally
/// not byte-exact and its drive-side acceptance is not established here.
pub fn construct_signed_candidate(
    kernel: &[u8],
    normal: &[u8],
    envelope_id: &str,
    revision: &str,
) -> Result<Vec<u8>> {
    // Recognize the normal by its decoded-image hash. `normal` is already the
    // decoded on-flash image, so hash it directly (do NOT re-decode it as an
    // envelope). A match rebuilds a byte-exact OEM normal (true seed + verbatim
    // OEM signature + OEM revision/date); a miss uses a zero seed and an all-zero
    // signature region — the obvious "not OEM / unverified" sentinel.
    let normal_oem = crate::pioneer_n::lookup(&format!("{:x}", Sha256::digest(normal)));
    let (normal_seed, normal_signature, revision, date): (
        u32,
        pioneer_optical::envelope::builder::NormalSignature,
        &str,
        &str,
    ) = match normal_oem {
        Some(entry) => (
            entry.seed,
            pioneer_optical::envelope::builder::NormalSignature::Oem(&entry.signature),
            &entry.revision,
            &entry.date,
        ),
        None => (
            0,
            pioneer_optical::envelope::builder::NormalSignature::Zeroed,
            revision,
            unique_embedded_date(normal).unwrap_or("00/00/00"),
        ),
    };

    // Recognize the kernel by its decoded-image hash and rebuild it exactly;
    // otherwise stamp the kernel's own zero placeholders (seed 0 is obvious).
    let kernel_build = oem_kernel_build(kernel);

    let input = pioneer_optical::envelope::builder::BuildInputs {
        kernel_image: kernel,
        normal_image: normal,
        envelope_id,
        normal_revision: revision,
        normal_date: date,
        kernel: kernel_build,
        normal_key_seed: normal_seed,
    };
    let pair = pioneer_optical::envelope::builder::encode_encrypted_pair(&input, normal_signature)
        .map_err(|e| anyhow::anyhow!(e))?;
    let out = assemble_tar(&[pair.kernel, pair.normal])?;
    let parsed = Bundle::from_tar_bytes(&out)?;
    if parsed.components.len() != 2 {
        bail!("generated package did not contain Kernel and Normal");
    }
    Ok(out)
}

/// Append one envelope to a tar under `components/<embedded-name>.enc`, deriving
/// the archive name from the envelope's own embedded filename.
fn append_envelope(tar: &mut tar::Builder<Vec<u8>>, bytes: &[u8]) -> Result<()> {
    // The codec is expected to emit a full 0x200-byte header; guard the
    // embedded-filename slice so a short return is an error, not a panic.
    let embedded = bytes
        .get(0x1f0..0x200)
        .context("generated envelope is shorter than its header")?
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
    tar.append_data(&mut header, path, bytes)?;
    Ok(())
}

/// Assemble a backup `.tar` from one or more built component envelopes.
fn assemble_tar(components: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    for bytes in components {
        append_envelope(&mut tar, bytes)?;
    }
    Ok(tar.into_inner()?)
}

/// Build just the Kernel envelope from a captured Kernel image: byte-exact OEM
/// when recognized in `crate::pioneer_k`, otherwise zero placeholders. Used to
/// still produce a Kernel-only archive when the Normal region could not be read.
fn build_kernel_envelope(kernel: &[u8], envelope_id: &str) -> Result<Vec<u8>> {
    pioneer_optical::envelope::builder::encode_kernel_envelope(
        kernel,
        envelope_id,
        &oem_kernel_build(kernel),
    )
    .map_err(|e| anyhow::anyhow!(e))
}

/// Resolve the Kernel build inputs from a captured Kernel image: the byte-exact
/// OEM revision/date/key when its decoded image (including an exact generation
/// patch) is recognized in
/// `crate::pioneer_k`, otherwise the obvious zero placeholders (revision
/// `0000`, date `00/00/00`, seed `0`). Single source of truth for both the
/// full-pair and Kernel-only capture paths, so they cannot drift.
fn oem_kernel_build(kernel: &[u8]) -> pioneer_optical::envelope::builder::KernelBuild<'static> {
    use pioneer_optical::envelope::builder::{KernelBuild, KernelKeySource};
    match crate::pioneer_k::recognize(kernel).map(|m| m.entry) {
        Some(entry) => KernelBuild {
            revision: &entry.revision,
            date: &entry.date,
            key: match &entry.key {
                crate::pioneer_k::KeyMaterial::Seed(seed) => KernelKeySource::Seed(*seed),
                crate::pioneer_k::KeyMaterial::Raw(bytes) => KernelKeySource::RawKey(bytes),
            },
        },
        None => KernelBuild {
            revision: "0000",
            date: "00/00/00",
            key: KernelKeySource::Seed(0),
        },
    }
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
    let bundle = Bundle::from_backup_tar_bytes(bytes)?;
    if bundle.components.is_empty() || bundle.components.len() > 2 {
        bail!("Pioneer package must contain a Kernel and/or a Normal");
    }
    let kernel = bundle.components.iter().find(|c| c.role == Role::Kernel);
    let normal = bundle.components.iter().find(|c| c.role == Role::Main);
    match (kernel, normal) {
        // Healthy capture: validate the full pair together.
        (Some(k), Some(n)) => validate_envelope_pair(&k.bytes, &n.bytes, product),
        // Partial capture: the Kernel is self-contained and validates alone.
        (Some(k), None) => validate_kernel_only(&k.bytes, product),
        // A Normal cannot be receiver-decoded without its Kernel, so a
        // Normal-only archive is not a validatable restore artifact.
        (None, Some(_)) => {
            bail!("Normal-only archive cannot be validated without its Kernel")
        }
        (None, None) => bail!("Pioneer package has neither a Kernel nor a Normal"),
    }
}

/// The role (`"kernel"` / `"main"`) and archive filename of each component in a
/// captured package, for user-facing messaging.
pub fn component_roles(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(bundle) = Bundle::from_backup_tar_bytes(bytes) else {
        return Vec::new();
    };
    bundle
        .components
        .iter()
        .map(|c| {
            let role = match c.role {
                Role::Kernel => "kernel",
                Role::Main => "main",
                _ => "other",
            };
            (role.to_string(), c.path.clone())
        })
        .collect()
}

/// Validate a Kernel envelope on its own: header model match, decode, image
/// integrity and exact round-trip. Used for a partial (Kernel-only) capture.
fn validate_kernel_only(kernel: &[u8], product: &str) -> Result<()> {
    let kh = pioneer_optical::envelope::header_info(kernel).context("invalid Kernel header")?;
    if !product.split_whitespace().any(|part| part == kh.model)
        || kh.kind != Some(pioneer_optical::ComponentKind::Kernel)
    {
        bail!("Pioneer Kernel identity does not match the drive");
    }
    let decoded =
        pioneer_optical::envelope::decode_envelope(kernel).context("Kernel cannot be decoded")?;
    if !zero_be32_sum(&decoded.image) {
        bail!("Pioneer Kernel image integrity mismatch");
    }
    if decoded.repack(&decoded.image).as_deref() != Some(kernel) {
        bail!("Pioneer Kernel envelope does not round-trip exactly");
    }
    Ok(())
}

/// Per-component OEM provenance of a captured package, decided from its bytes.
/// A component is OEM only when it is byte-exact to what the OEM would ship: the
/// kernel is recognized by its decoded-image hash in `crate::pioneer_k`, and
/// the normal by its decoded-image hash in `crate::pioneer_n` (which also
/// supplies the verbatim OEM signature). Generation-patched kernels are tracked
/// separately and retain the captured bytes. An unrecognized component is a
/// reconstruction (zero seed, zero signature) and is not OEM.
pub struct Provenance {
    /// Kernel is byte-exact OEM (recognized and rebuilt from the OEM key table).
    pub kernel_oem: bool,
    /// Exact OEM image with only the supported generation patch applied.
    pub kernel_generation_patched: bool,
    /// Normal is byte-exact OEM (recognized seed + verbatim OEM signature).
    pub normal_oem: bool,
}

/// Decide [`Provenance`] from a captured `.tar`'s bytes. A package that cannot
/// be re-parsed is treated as fully non-OEM.
pub fn package_provenance(bytes: &[u8]) -> Provenance {
    let Ok(bundle) = Bundle::from_backup_tar_bytes(bytes) else {
        return Provenance {
            kernel_oem: false,
            kernel_generation_patched: false,
            normal_oem: false,
        };
    };
    let decoded_kernel = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .and_then(|c| pioneer_optical::envelope::decode_envelope(&c.bytes));
    let kernel_match = decoded_kernel
        .as_ref()
        .and_then(|d| crate::pioneer_k::recognize(&d.image));
    let kernel_oem = kernel_match.as_ref().is_some_and(|m| !m.generation_patched);
    let kernel_generation_patched = kernel_match.as_ref().is_some_and(|m| m.generation_patched);
    // The normal is receiver-decoded with the package's own kernel, then matched
    // by decoded-image hash against the OEM normal table.
    let normal_oem = match (
        &decoded_kernel,
        bundle.components.iter().find(|c| c.role == Role::Main),
    ) {
        (Some(k), Some(n)) => pioneer_optical::envelope::decode_envelope_with_kernel(&n.bytes, k)
            .map(|d| crate::pioneer_n::lookup(&format!("{:x}", Sha256::digest(&d.image))).is_some())
            .unwrap_or(false),
        _ => false,
    };
    Provenance {
        kernel_oem,
        kernel_generation_patched,
        normal_oem,
    }
}

/// Validate a pair without interpreting its provenance or archival labels.
pub fn validate_envelope_pair(kernel: &[u8], normal: &[u8], product: &str) -> Result<()> {
    let kh = pioneer_optical::envelope::header_info(kernel).context("invalid Kernel header")?;
    let nh = pioneer_optical::envelope::header_info(normal).context("invalid Normal header")?;
    if !product.split_whitespace().any(|part| part == kh.model)
        || nh.model != kh.model
        || nh.hardware_version != kh.hardware_version
        || kh.kind != Some(pioneer_optical::ComponentKind::Kernel)
        || nh.kind != Some(pioneer_optical::ComponentKind::Normal)
        || kh.kernel_version != nh.kernel_version
        || kh.kernel_version2 != nh.kernel_version2
        || kh.destination != nh.destination
    {
        bail!("Pioneer envelope identity does not match the drive");
    }
    let decoded_kernel =
        pioneer_optical::envelope::decode_envelope(kernel).context("Kernel cannot be decoded")?;
    let decoded_normal =
        pioneer_optical::envelope::decode_envelope_with_kernel(normal, &decoded_kernel)
            .context("Normal cannot be receiver-decoded")?;
    // A zeroed signature region is the deliberate "not OEM / unverified"
    // sentinel (a table-miss normal): accept it structurally and skip only the
    // ECDSA check. A nonzero signature must verify.
    let sentinel_signature = normal
        .get(pioneer_optical::envelope::builder::NORMAL_SIGNATURE_RANGE)
        .is_some_and(|sig| sig.iter().all(|&b| b == 0));
    if (!sentinel_signature
        && !pioneer_optical::envelope::builder::normal_authentication_valid(
            normal,
            &decoded_kernel.image,
        ))
        || decoded_normal.info().layout
            != if pioneer_optical::envelope::builder::scaled_normal_geometry_from_kernel(
                &decoded_kernel.image,
            )
            .is_some()
            {
                pioneer_optical::envelope::Layout::NormalScaledKey
            } else {
                pioneer_optical::envelope::Layout::Normal
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

/// Normal backup: read each shared H8/SAT image region with a fast, strict read
/// (stable double-read, fail-fast). Issues no flash commands.
pub fn capture_signed_candidate(dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
    capture(dev, false)
}

/// Recover: same capture, but any region that the strict read cannot get is
/// retried with a deeper, instability-tolerant salvage read. Issues no flash
/// commands.
pub fn capture_recover_candidate(dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
    capture(dev, true)
}

/// First address of the `dump` span: the device base.
const DUMP_BASE: usize = 0;
/// Minimum `dump` span length: the whole flash, `0x000000..0x600000` (the range
/// the read-map probe covers; the UD04 Normal ends at `0x5d7500`, inside it).
/// Extended to the Normal's end if a drive's geometry reaches past it, and never
/// past the unlocked read ceiling (`pioneer_optical::cdb::READ_CEILING`).
const DUMP_MIN_LEN: usize = 0x60_0000;

/// `dump`: ONE contiguous raw read of the entire device — `0x000000` up to
/// `0x600000` (or the end of the Normal if the drive's geometry reaches further,
/// capped at the read ceiling) — as a single verbatim byte image. No envelope
/// wrapping, no tar. Uses the deep, instability-tolerant read (unreadable spans
/// are zero-filled and reported; it errors only if nothing at all was readable).
/// Never uses vendor kernel mode and issues no flash commands: every read goes
/// through `pioneer_optical::drive::read_memory`, which handles the read unlock.
///
/// Normally the drive identity and the Kernel receiver layout must validate.
/// `force` trusts nothing the drive reports: identity, read-unlock and layout
/// failures become warnings and the FULL span is still read and written.
pub fn capture_raw_dump(dev: &mut dyn ScsiDevice, force: bool) -> Result<Vec<u8>> {
    let amber = |msg: &str| eprintln!("  {}", crate::style::amber(msg));
    if let Err(error) = read_identity(dev) {
        if !force {
            return Err(error);
        }
        amber(&format!(
            "identity not trusted ({error:#}); reading the full device span anyway (--force)"
        ));
    }
    if let Err(error) = prepare_firmware_read(dev) {
        if !force {
            return Err(error);
        }
        amber(&format!(
            "read unlock not confirmed ({error:#}); attempting the read anyway (--force)"
        ));
    }
    let (mut image, mut gaps) = read_region_deep_gaps(dev, DUMP_BASE, DUMP_MIN_LEN)
        .context("could not read the device firmware span")?;

    // Kernel receiver layout (inside the dump) gives the Normal geometry.
    let kernel = &image[KERNEL_IMAGE_BASE..NORMAL_IMAGE_BASE];
    if let Err(error) = pioneer_optical::envelope::builder::kernel_layout_from_image(kernel)
        .context("captured Kernel receiver layout is unsupported")
    {
        if !force {
            return Err(error);
        }
        amber(&format!("{error:#} (continuing: --force)"));
    }
    // If the Normal extends past the minimum span, read the remainder so the dump
    // still holds the whole image; stay within the read ceiling.
    let normal_end = pioneer_optical::envelope::builder::scaled_normal_geometry_from_kernel(kernel)
        .map(|g| NORMAL_IMAGE_BASE + g.image_len)
        .filter(|end| *end <= pioneer_optical::cdb::READ_CEILING as usize);
    if let Some(end) = normal_end.filter(|end| *end > image.len()) {
        let (extra, extra_gaps) = read_region_deep_gaps(dev, image.len(), end - image.len())
            .context("could not read the Normal past the standard dump span")?;
        image.extend_from_slice(&extra);
        gaps.extend(extra_gaps);
    }
    // The dump still succeeds with gaps (it is a best-effort salvage), but say so
    // loudly in the final summary.
    crate::output::field("Dump size", format!("{} bytes", image.len()));
    if let Some(note) = gap_summary(&gaps) {
        crate::output::field("Dump gaps", &note);
        amber(&note);
    }
    Ok(image)
}

/// Capture the Kernel and Normal as INDEPENDENT components and archive whichever
/// succeeded. The Kernel is read first (it establishes the Normal's geometry);
/// the Normal is then attempted on its own. A region the read cannot get never
/// discards the other: the archive holds 2 components on a healthy drive, or 1
/// when a region failed (the caller points the user at `dump` for a raw salvage read). Fails only
/// if nothing could be read. `deep` selects the salvage read for failed regions.
fn capture(dev: &mut dyn ScsiDevice, deep: bool) -> Result<Vec<u8>> {
    let (inquiry, hardware, kernel_len) = read_identity(dev)?;
    prepare_firmware_read(dev)?;

    // The Kernel is required: it defines the Normal's receiver geometry, so a
    // Kernel we cannot read leaves nothing buildable. Say so and point at dump.
    let kernel = read_region(dev, KERNEL_IMAGE_BASE, kernel_len, deep).with_context(|| {
        if deep {
            "could not read the Kernel firmware region even with a deeper salvage read"
        } else {
            "could not read the Kernel firmware region; run `freemkv-flash dump <device>` for a raw salvage read"
        }
    })?;
    if kernel.get(0x1000..0x1008) != Some(hardware.as_slice()) {
        bail!("captured Kernel hardware differs from drive identity");
    }
    pioneer_optical::envelope::builder::kernel_layout_from_image(&kernel)
        .context("captured Kernel receiver layout is unsupported")?;
    let revision = std::str::from_utf8(&inquiry[32..36])?.trim().to_owned();

    // The Normal is attempted independently; its failure keeps the Kernel.
    match read_normal_region(dev, &kernel, deep) {
        Ok(normal) => {
            let envelope_id = embedded_envelope_id(&inquiry, &kernel, &normal)?;
            construct_signed_candidate(&kernel, &normal, &envelope_id, &revision)
        }
        Err(error) => {
            eprintln!(
                "  {}",
                crate::style::amber(&format!(
                    "Normal region not recovered ({error:#}); saving Kernel only"
                ))
            );
            let envelope_id = embedded_envelope_id(&inquiry, &kernel, &[])?;
            let kernel_env = build_kernel_envelope(&kernel, &envelope_id)?;
            assemble_tar(&[kernel_env])
        }
    }
}

/// Strict capture of both image regions as raw images (test helper mirroring the
/// healthy-drive path of [`capture`]). Production uses [`capture`], which is
/// per-component resilient.
#[cfg(test)]
fn read_h8_image_pair(dev: &mut dyn ScsiDevice) -> Result<(Vec<u8>, Vec<u8>, String, String)> {
    let (inquiry, hardware, kernel_len) = read_identity(dev)?;
    prepare_firmware_read(dev)?;
    let kernel = read_region(dev, KERNEL_IMAGE_BASE, kernel_len, false)?;
    if kernel.get(0x1000..0x1008) != Some(hardware.as_slice()) {
        bail!("captured Kernel hardware differs from drive identity");
    }
    pioneer_optical::envelope::builder::kernel_layout_from_image(&kernel)
        .context("captured Kernel receiver layout is unsupported")?;
    let normal = read_normal_region(dev, &kernel, false)?;
    let envelope_id = embedded_envelope_id(&inquiry, &kernel, &normal)?;
    let revision = std::str::from_utf8(&inquiry[32..36])?.trim().to_owned();
    Ok((kernel, normal, revision, envelope_id))
}

/// Read and validate the drive identity, returning the raw INQUIRY, the 8-byte
/// H8/SAT hardware tag, and the Kernel image length.
fn read_identity(dev: &mut dyn ScsiDevice) -> Result<(Vec<u8>, Vec<u8>, usize)> {
    let identity = crate::drive::pioneer_transport::identify(dev)
        .context("Pioneer backup stopped: could not read a complete hardware identity; no firmware image read or backup created")?;
    let inquiry = identity.inquiry_bytes().to_vec();
    // Vendor+product (8..32) AND the revision (32..36) must be printable ASCII:
    // the revision flows verbatim into the generated envelope header, so a
    // drive returning control bytes there must be rejected, not propagated.
    if !inquiry[8..36].is_ascii()
        || inquiry[8..36].iter().any(|&b| b < 0x20 || b == 0x7f)
        || inquiry[8..32].iter().all(|&b| b == b' ')
    {
        bail!("drive does not have a usable H8/SAT INQUIRY identity");
    }
    let f1 = identity.vendor_bytes();
    if !f1[16..24].starts_with(b"SAT ") {
        let hardware = String::from_utf8_lossy(&f1[16..24]);
        bail!("Pioneer backup is not implemented for hardware {hardware:?}: H8/SAT hardware identity required; no firmware image read or backup created");
    }
    let kernel_len = NORMAL_IMAGE_BASE
        .checked_sub(KERNEL_IMAGE_BASE)
        .filter(|len| *len > 0 && *len <= 0x100000)
        .context("invalid Kernel/Normal address span")?;
    Ok((inquiry, f1[16..24].to_vec(), kernel_len))
}

/// Read the Normal image region: locate its header, derive its length from the
/// Kernel geometry, and capture it (`deep` selects the salvage read).
fn read_normal_region(dev: &mut dyn ScsiDevice, kernel: &[u8], deep: bool) -> Result<Vec<u8>> {
    let normal_head = read_region(dev, NORMAL_IMAGE_BASE, 24, deep)?;
    if !normal_head.starts_with(b"PIONEER ") {
        bail!("Normal image header is missing at the discovered base");
    }
    let normal_len =
        match pioneer_optical::envelope::builder::scaled_normal_geometry_from_kernel(kernel) {
            Some(geometry) => geometry.image_len,
            None => u32::from_be_bytes(normal_head[20..24].try_into().unwrap()) as usize,
        };
    if !(0x2000..=0x800000).contains(&normal_len)
        || !normal_len.is_multiple_of(0x100)
        || NORMAL_IMAGE_BASE + normal_len > 0x1000000
    {
        bail!("Normal image declares an invalid length");
    }
    read_region(dev, NORMAL_IMAGE_BASE, normal_len, deep)
}

fn zero_be32_sum(image: &[u8]) -> bool {
    let (words, remainder) = image.as_chunks::<4>();
    remainder.is_empty()
        && words.iter().fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(*word))
        }) == 0
}

/// Largest single vendor read. The `3C/02/B0` CDB carries a 24-bit length
/// field, so the ceiling is `0xFFFFFF`, but the drive's receive buffer caps
/// transfers in practice. `0x8000` (32 KiB) is well below any observed buffer
/// limit and is ~200x the historical `0xA4` OEM read, which turns a full ~6
/// MiB dump from ~10 min into seconds. If a chunk fails the deep-read salvage
/// path subdivides down to `DEEP_MIN_CHUNK = 4` automatically.
const READ_CHUNK: usize = 0x8000;
/// Deep-read retry budget per failing span before it is subdivided / given up.
const DEEP_RETRIES: usize = 6;
/// Smallest span a deep read drops to while isolating a bad region.
const DEEP_MIN_CHUNK: usize = 4;

/// One vendor firmware read at `off` of exactly `n` bytes, through
/// `pioneer_optical::drive::read_memory` (which issues the read-unlock knock
/// itself, so no caller ever sequences it).
fn read_chunk(dev: &mut dyn ScsiDevice, off: usize, n: usize) -> Result<Vec<u8>> {
    let data = crate::drive::pioneer_transport::read_memory_exact(dev, off as u32, n as u32)
        .with_context(|| format!("reading firmware at {off:#x}"))?;
    if data.len() != n {
        bail!("short firmware read at {off:#x}: {}/{n}", data.len());
    }
    Ok(data)
}

/// Capture a firmware region. `deep == false` is the fast, strict read used by a
/// normal backup (read twice, fail on the first error or any instability);
/// `deep == true` is the recover salvage read (retry, subdivide, tolerate
/// instability, zero-fill and report unreadable gaps). Progress for large
/// regions is printed to stderr.
fn read_region(dev: &mut dyn ScsiDevice, start: usize, len: usize, deep: bool) -> Result<Vec<u8>> {
    if deep {
        read_region_deep(dev, start, len)
    } else {
        // Two labeled passes: read, then verify (the stability re-read must match
        // or the capture is not trustworthy — per component, so one bad region
        // never taints the other).
        let first = read_region_strict(dev, start, len, "reading")?;
        if read_region_strict(dev, start, len, "verifying")? != first {
            bail!("firmware reads changed between passes at {start:#x}; no backup produced");
        }
        Ok(first)
    }
}

/// Human progress label for a region base.
fn region_label(verb: &str, start: usize) -> String {
    let region = if start == KERNEL_IMAGE_BASE {
        "kernel"
    } else if start == NORMAL_IMAGE_BASE {
        "normal"
    } else {
        "firmware"
    };
    format!("{verb} {region}")
}

/// Strict single pass: `READ_CHUNK` reads, fail-fast on any error or short read.
/// `verb` labels the phase (`reading` / `verifying`).
fn read_region_strict(
    dev: &mut dyn ScsiDevice,
    start: usize,
    len: usize,
    verb: &str,
) -> Result<Vec<u8>> {
    let label = region_label(verb, start);
    // Big regions get a live progress bar; a mid-size region (the 64 KiB kernel)
    // is below the bar threshold, so announce it as a one-liner so every phase
    // is visible.
    if (0x8000..crate::style::Progress::MIN_BYTES).contains(&len) {
        eprintln!("  {label}...");
    }
    let mut image = Vec::with_capacity(len);
    let mut progress = crate::style::Progress::new(label, len);
    while image.len() < len {
        let off = start + image.len();
        let n = (len - image.len()).min(READ_CHUNK);
        image.extend(read_chunk(dev, off, n)?);
        progress.set(image.len());
    }
    Ok(image)
}

/// Salvage pass: read `READ_CHUNK` at a time; on a failing chunk, retry, then
/// subdivide down to `DEEP_MIN_CHUNK`, zero-filling spans that never read and
/// recording them. Returns `len` bytes (with zero-filled gaps) as long as
/// anything at all was read; errors only if the whole region is unreadable.
fn read_region_deep(dev: &mut dyn ScsiDevice, start: usize, len: usize) -> Result<Vec<u8>> {
    read_region_deep_gaps(dev, start, len).map(|(image, _)| image)
}

/// Zero-filled unreadable spans, `(offset, len)`.
type Gaps = Vec<(usize, usize)>;

/// Consecutive wholly-unreadable `READ_CHUNK`s (after something had read) that
/// trigger a liveness probe; a failed probe aborts the salvage.
const DEAD_STREAK: usize = 4;

/// [`read_region_deep`], also returning the zero-filled gaps `(offset, len)`.
fn read_region_deep_gaps(
    dev: &mut dyn ScsiDevice,
    start: usize,
    len: usize,
) -> Result<(Vec<u8>, Gaps)> {
    let mut image = vec![0u8; len];
    let mut pos = 0usize;
    let mut dead_streak = 0usize;
    // Offset of the last chunk that read cleanly: the liveness probe re-reads it,
    // so it never depends on any one region (e.g. the Kernel base) being readable.
    let mut last_good: Option<usize> = None;
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut any = false;
    let mut progress = crate::style::Progress::new(region_label("recovering", start), len);
    while pos < len {
        let off = start + pos;
        let n = (len - pos).min(READ_CHUNK);
        match read_chunk(dev, off, n) {
            Ok(data) => {
                image[pos..pos + n].copy_from_slice(&data);
                any = true;
                last_good = Some(off);
                dead_streak = 0;
                pos += n;
            }
            Err(_) => {
                let got = salvage_span(dev, start, &mut image, pos, n, &mut gaps);
                any |= got;
                pos += n;
                dead_streak = if got { 0 } else { dead_streak + 1 };
                // A drive that dropped out would otherwise cost millions of
                // retries: after a run of dead chunks, check the drive still
                // re-reads the last offset that read cleanly and give up if it does not.
                if dead_streak >= DEAD_STREAK
                    && last_good.is_some_and(|good| read_chunk(dev, good, 1).is_err())
                {
                    bail!(
                        "the drive stopped responding at {:#x} after {dead_streak} consecutive \
                         unreadable chunks; aborting the salvage read",
                        start + pos
                    );
                }
            }
        }
        progress.set(pos);
    }
    if !any {
        bail!(
            "region {start:#x}..{:#x} was entirely unreadable",
            start + len
        );
    }
    if !gaps.is_empty() {
        let total: usize = gaps.iter().map(|(_, l)| l).sum();
        eprintln!(
            "  {}",
            crate::style::amber(&format!(
                "recover: {total} byte(s) across {} gap(s) could not be read and were zero-filled",
                gaps.len()
            ))
        );
        for (off, l) in &gaps {
            eprintln!("    gap {off:#x}..{:#x}", off + l);
        }
    }
    Ok((image, gaps))
}

/// Loud end-of-dump note for unreadable spans (`None` when the read was gap-free).
fn gap_summary(gaps: &[(usize, usize)]) -> Option<String> {
    if gaps.is_empty() {
        return None;
    }
    let total: usize = gaps.iter().map(|(_, l)| l).sum();
    Some(format!(
        "DUMP INCOMPLETE: {} gap(s), {total} byte(s) could not be read and are ZERO-FILLED in \
         the saved image; it is NOT a faithful copy of the flash",
        gaps.len()
    ))
}

/// Salvage one `READ_CHUNK` span that failed a bulk read. First retry the whole
/// span (for a transient error); if it is hard-failing, re-read it in
/// `DEEP_MIN_CHUNK` units so only the units that truly never read are
/// zero-filled and recorded as gaps. Returns whether any byte was recovered.
fn salvage_span(
    dev: &mut dyn ScsiDevice,
    start: usize,
    image: &mut [u8],
    pos: usize,
    n: usize,
    gaps: &mut Vec<(usize, usize)>,
) -> bool {
    if let Some(data) = retry_read(dev, start + pos, n) {
        image[pos..pos + n].copy_from_slice(&data);
        return true;
    }
    let mut any = false;
    let mut p = pos;
    while p < pos + n {
        let m = DEEP_MIN_CHUNK.min(pos + n - p);
        match retry_read(dev, start + p, m) {
            Some(data) => {
                image[p..p + m].copy_from_slice(&data);
                any = true;
            }
            None => push_gap(gaps, start + p, m),
        }
        p += m;
    }
    any
}

/// Read `off..off+n` up to `DEEP_RETRIES` times. Every attempt re-knocks (the
/// crate's `read_memory` unlocks before each read), covering a drive that
/// dropped out of read mode. `None` if every attempt failed.
fn retry_read(dev: &mut dyn ScsiDevice, off: usize, n: usize) -> Option<Vec<u8>> {
    for _ in 0..DEEP_RETRIES {
        if let Ok(data) = read_chunk(dev, off, n) {
            return Some(data);
        }
    }
    None
}

/// Append an unreadable `[off, off+len)` gap, merging it with the previous gap
/// when they are contiguous.
fn push_gap(gaps: &mut Vec<(usize, usize)>, off: usize, len: usize) {
    if let Some(last) = gaps.last_mut() {
        if last.0 + last.1 == off {
            last.1 += len;
            return;
        }
    }
    gaps.push((off, len));
}

/// Shared H8/SAT image map observed in decoded Kernels from 28 hardware
/// groups. This is an address-space rule, not a per-model firmware record.
const KERNEL_IMAGE_BASE: usize = 0x400000;
const NORMAL_IMAGE_BASE: usize = 0x410000;

/// Confirm firmware reads work before a capture: one 1-byte read at the Kernel
/// base. The read-unlock knock is issued inside `pioneer_optical::drive::read_memory`,
/// so this is just a fail-fast probe; any failure (transport, short data, sense)
/// stops the capture.
fn prepare_firmware_read(dev: &mut dyn ScsiDevice) -> Result<()> {
    read_chunk(dev, KERNEL_IMAGE_BASE, 1)
        .map(|_| ())
        .context("probing Pioneer firmware read access")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Kernel-only partial capture is validatable and named by the backup notice
    /// (a Kernel-only tar is still not a flashable `Bundle::from_tar_bytes`).
    #[test]
    fn patched_oem_backup_preserves_body_and_original_receiver_when_configured() {
        let Ok(path) = std::env::var("PIONEER_PATCHED_KERNEL_FIXTURE") else {
            return;
        };
        let body = std::fs::read(path).unwrap();
        let env = build_kernel_envelope(&body, "PIONEER BD-RW   BDR-UD04").unwrap();
        let decoded = pioneer_optical::envelope::decode_envelope(&env).unwrap();
        assert_eq!(
            decoded.image, body,
            "backup must retain the actual patched body"
        );
        let header = pioneer_optical::envelope::header_info(&env).unwrap();
        assert_eq!(header.revision, "1.00");
        let tar = assemble_tar(&[env]).unwrap();
        let provenance = package_provenance(&tar);
        assert!(!provenance.kernel_oem);
        assert!(provenance.kernel_generation_patched);
        // The planner must not confuse our patched marker with a newer receiver.
        assert_eq!(
            crate::pioneer_k::receiver_generation(&decoded.image),
            Some(false)
        );
    }

    #[test]
    fn kernel_only_partial_backup_validates_and_is_reported_partial() {
        let mut body = vec![0u8; 0x10000];
        body[0xFE] = 0x01;
        body[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
        body[0x1008..0x1010].copy_from_slice(b"ID58    ");
        body[0x1010..0x1014].copy_from_slice(b"ID5 ");
        body[0x2000..0x2008].copy_from_slice(&[0xae, 0xfe, 0, 0, 0, 0, 0xae, 0xf0]);
        let sum = body
            .chunks(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .fold(0u32, |a, w| a.wrapping_add(w));
        body[0x1020..0x1024].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
        let env = build_kernel_envelope(&body, "PIONEER BD-RW   BDR-UD04").unwrap();
        let tar = assemble_tar(&[env]).unwrap();
        validate_envelope_package(&tar, "BD-RW BDR-UD04")
            .expect("a Kernel-only partial backup must validate");
        assert!(Bundle::from_tar_bytes(&tar).is_err());
        let roles = component_roles(&tar);
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].0, "kernel");
    }

    #[test]
    fn read_access_probe_knocks_then_reads_and_stops_on_any_failure() {
        struct Access {
            response: Option<Result<Vec<u8>>>,
            order: Vec<&'static str>,
        }
        impl ScsiDevice for Access {
            fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
                assert_eq!(cdb, [0x3c, 2, 0xb0, 0x40, 0, 0, 0, 0, 1, 0]);
                assert_eq!(len, 1);
                self.order.push("read");
                self.response.take().expect("only one access probe")
            }
            fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
                assert_eq!(cdb, [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]);
                assert!(data.is_empty());
                self.order.push("knock");
                Ok(())
            }
            fn describe(&self) -> String {
                "read permission test".into()
            }
        }
        let sense = |key, asc, ascq| {
            Err(crate::platform::ScsiSenseError::new(key, asc, ascq, "test sense").into())
        };
        for (response, ok) in [
            (Ok(vec![0]), true),
            (sense(5, 0x24, 0), false), // still locked after the knock
            (sense(5, 0x20, 0), false),
            (sense(4, 0x44, 0), false),
            (Err(anyhow::anyhow!("transport disconnected")), false),
            (Ok(vec![]), false), // a short response is never success
        ] {
            let mut dev = Access {
                response: Some(response),
                order: Vec::new(),
            };
            assert_eq!(prepare_firmware_read(&mut dev).is_ok(), ok);
            // The knock is issued by the crate, exactly once, before the read.
            assert_eq!(dev.order, ["knock", "read"]);
        }
    }

    #[test]
    fn deep_read_salvages_around_an_unreadable_span_and_reports_the_gap() {
        // A device that serves byte `off & 0xff` everywhere except a bad window
        // `[bad, bad+badlen)`, where every read intersecting it errors.
        struct Spotty {
            bad: usize,
            badlen: usize,
        }
        impl ScsiDevice for Spotty {
            fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
                let start = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
                if start < self.bad + self.badlen && start + len > self.bad {
                    bail!("unreadable span");
                }
                Ok((0..len).map(|i| ((start + i) & 0xff) as u8).collect())
            }
            fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
                Ok(())
            }
            fn describe(&self) -> String {
                "spotty".into()
            }
        }
        let len = 0x200usize;
        let bad = 0x100usize;
        let badlen = 0x10usize;
        let mut dev = Spotty { bad, badlen };
        let image = read_region_deep(&mut dev, 0, len).unwrap();
        assert_eq!(image.len(), len);
        // Readable bytes are their offset mod 256; the bad window is zero-filled.
        for (i, b) in image.iter().enumerate() {
            if (bad..bad + badlen).contains(&i) {
                assert_eq!(*b, 0, "byte {i:#x} should be a zero-filled gap");
            } else {
                assert_eq!(*b, (i & 0xff) as u8, "byte {i:#x} should be recovered");
            }
        }
        // A fully readable region salvages byte-for-byte with no gaps.
        let mut clean = Spotty {
            bad: len,
            badlen: 0,
        };
        let whole = read_region_deep(&mut clean, 0, len).unwrap();
        assert!(whole
            .iter()
            .enumerate()
            .all(|(i, b)| *b == (i & 0xff) as u8));
    }

    #[test]
    fn deep_read_aborts_when_the_drive_drops_out_mid_region() {
        // Serves the first read, then every read (including the liveness probe)
        // fails: a dropped drive must not cost millions of retries.
        struct Dying {
            reads: usize,
        }
        impl ScsiDevice for Dying {
            fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
                self.reads += 1;
                let _ = cdb;
                if self.reads > 1 {
                    bail!("drive gone");
                }
                Ok(vec![0u8; len])
            }
            fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
                Ok(())
            }
            fn describe(&self) -> String {
                "dying".into()
            }
        }
        let mut dev = Dying { reads: 0 };
        let err = read_region_deep(&mut dev, 0, READ_CHUNK * 24).unwrap_err();
        assert!(format!("{err:#}").contains("stopped responding"), "{err:#}");
        assert!(dev.reads < 400_000, "too many retries: {}", dev.reads);
    }

    #[test]
    fn force_dump_with_unreadable_kernel_base_still_saves_a_zero_filled_image() {
        // Alive drive; only 0x400000..0x440000 (the Kernel base) is unreadable.
        struct BadKernelBase;
        impl ScsiDevice for BadKernelBase {
            fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
                if cdb[2] != 0xb0 {
                    bail!("no identity");
                }
                let start = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
                if start < 0x44_0000 && start + len > 0x40_0000 {
                    bail!("unreadable kernel base");
                }
                Ok(vec![0xAA; len])
            }
            fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
                Ok(())
            }
            fn describe(&self) -> String {
                "bad kernel base".into()
            }
        }
        let image = capture_raw_dump(&mut BadKernelBase, true).expect("dump must complete");
        assert_eq!(image.len(), DUMP_MIN_LEN);
        assert!(image[0x40_0000..0x44_0000].iter().all(|b| *b == 0));
        assert!(image[..0x40_0000].iter().all(|b| *b == 0xAA));
        assert!(image[0x44_0000..].iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn gap_summary_is_loud_and_counts_bytes() {
        assert_eq!(gap_summary(&[]), None);
        let msg = gap_summary(&[(0x100, 8), (0x200, 0x18)]).unwrap();
        assert!(msg.contains("2 gap(s)"), "{msg}");
        assert!(msg.contains("32 byte(s)"), "{msg}");
        assert!(msg.to_lowercase().contains("zero"), "{msg}");
    }

    #[test]
    fn push_gap_merges_contiguous_runs_and_separates_disjoint_ones() {
        let mut g = Vec::new();
        push_gap(&mut g, 0x100, 4);
        push_gap(&mut g, 0x104, 4); // contiguous with the previous → merged
        push_gap(&mut g, 0x200, 8); // disjoint → new entry
        assert_eq!(g, vec![(0x100, 8), (0x200, 8)]);
    }

    #[test]
    fn deep_read_bails_when_the_whole_region_is_unreadable() {
        struct Dead;
        impl ScsiDevice for Dead {
            fn command_in(&mut self, _c: &[u8], _a: usize) -> Result<Vec<u8>> {
                bail!("dead drive")
            }
            fn command_out(&mut self, _c: &[u8], _d: &[u8]) -> Result<()> {
                bail!("dead drive")
            }
            fn describe(&self) -> String {
                "dead".into()
            }
        }
        let err = read_region_deep(&mut Dead, 0, 0x200).unwrap_err();
        assert!(format!("{err:#}").contains("entirely unreadable"));
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
            // Firmware reads are gated until the read-unlock knock; the crate
            // issues the knock itself before every read.
            if self.knocks == 0 {
                return Err(
                    crate::platform::ScsiSenseError::new(5, 0x24, 0, "read access locked").into(),
                );
            }
            assert_eq!(cdb.len(), 10);
            assert_eq!(&cdb[..3], &[0x3c, 2, 0xb0]);
            // 24-bit length field: top byte is 0 for anything under 16 MiB; low two bytes carry the length.
            let cdb_len = ((cdb[6] as usize) << 16) | ((cdb[7] as usize) << 8) | cdb[8] as usize;
            assert_eq!(cdb_len, len);
            assert_eq!(cdb[9], 0);
            assert!((1..=READ_CHUNK).contains(&len));
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
        assert!(replay.knocks >= 1, "the crate knocks before reading");
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
        let k = pioneer_optical::envelope::decode_envelope(&kernel.bytes).unwrap();
        let detected =
            pioneer_optical::envelope::builder::kernel_layout_from_image(&k.image).unwrap();
        let expected = match k.info().layout.as_str() {
            "kernel-front" => pioneer_optical::envelope::Layout::KernelFront,
            "kernel-derived" => pioneer_optical::envelope::Layout::KernelDerived,
            other => panic!("unsupported Kernel layout: {other}"),
        };
        assert_eq!(detected, expected);
        let n = pioneer_optical::envelope::decode_envelope_with_kernel(&normal.bytes, &k).unwrap();
        let h = pioneer_optical::envelope::header_info(&normal.bytes).unwrap();
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
        if pioneer_optical::envelope::builder::normal_authentication_from_kernel(&k.image)
            == Some(pioneer_optical::envelope::builder::NormalAuthentication::ScaledChecksumOnly)
        {
            assert!(
                pioneer_optical::envelope::builder::normal_authentication_valid(
                    &normal.bytes,
                    &k.image
                )
            );
            assert!(
                pioneer_optical::envelope::builder::normal_authentication_valid(
                    &rn.bytes, &k.image
                )
            );
        } else {
            assert_eq!(
                pioneer_optical::envelope::signature::verify_normal_signature(&normal.bytes),
                pioneer_optical::envelope::signature::verify_normal_signature(&rn.bytes)
            );
        }
        let dk = pioneer_optical::envelope::decode_envelope(&rk.bytes).unwrap();
        let dn = pioneer_optical::envelope::decode_envelope_with_kernel(&rn.bytes, &dk).unwrap();
        assert_eq!(dk.image, k.image);
        assert_eq!(dn.image, n.image);
        // Provenance: an OEM-sourced pair rebuilds a byte-exact OEM kernel and,
        // when its decoded normal is in the OEM normal table, a byte-exact OEM
        // normal too. normal_oem must agree with the pioneer_n lookup.
        let prov = package_provenance(&output);
        assert!(
            prov.kernel_oem,
            "OEM kernel must be recognized as byte-exact"
        );
        let normal_in_table =
            crate::pioneer_n::lookup(&format!("{:x}", Sha256::digest(&n.image))).is_some();
        assert_eq!(
            prov.normal_oem, normal_in_table,
            "normal_oem must reflect the pioneer_n table"
        );
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
    fn unparseable_package_has_no_oem_provenance() {
        let p = package_provenance(b"not a tar at all");
        assert!(!p.kernel_oem && !p.normal_oem);
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
                    let Some(decoded) =
                        pioneer_optical::envelope::decode_envelope(&component.bytes)
                    else {
                        continue;
                    };
                    let h = pioneer_optical::envelope::header_info(&component.bytes).unwrap();
                    let group = format!(
                        "{}/{}/{}/{}/{}",
                        h.model,
                        h.hardware_version,
                        h.destination,
                        h.kind.map_or("unknown", |t| t.as_str()),
                        decoded.info().layout.as_str()
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
        let kernel =
            pioneer_optical::envelope::decode_envelope(&std::fs::read(path).unwrap()).unwrap();
        let normal_bytes =
            std::fs::read(std::env::var("PIONEER_SCALED_NORMAL_FIXTURE").unwrap()).unwrap();
        let normal =
            pioneer_optical::envelope::decode_envelope_with_kernel(&normal_bytes, &kernel).unwrap();
        let h = pioneer_optical::envelope::header_info(&normal_bytes).unwrap();
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
                    pioneer_optical::envelope::decode_envelope(&component.bytes)
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
                let Some(decoded) = pioneer_optical::envelope::decode_envelope(&component.bytes)
                else {
                    let hardware = pioneer_optical::envelope::header_info(&component.bytes)
                        .map(|h| h.hardware_version)
                        .unwrap_or_else(|| "invalid header".into());
                    *unsupported_kernels.entry(hardware).or_default() += 1;
                    continue;
                };
                if let Some(h) = pioneer_optical::envelope::header_info(&component.bytes) {
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
                    if pioneer_optical::envelope::decode_envelope_with_kernel(
                        &normal.bytes,
                        &decoded,
                    )
                    .is_none()
                    {
                        let hardware = pioneer_optical::envelope::header_info(&normal.bytes)
                            .map(|h| h.hardware_version)
                            .unwrap_or_else(|| "invalid header".into());
                        *unsupported_normals.entry(hardware).or_default() += 1;
                    }
                    if let Some(header) = pioneer_optical::envelope::header_info(&normal.bytes) {
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
                let expected = match decoded.info().layout.as_str() {
                    "kernel-front" => {
                        front += 1;
                        pioneer_optical::envelope::Layout::KernelFront
                    }
                    "kernel-derived" => {
                        derived += 1;
                        pioneer_optical::envelope::Layout::KernelDerived
                    }
                    _ => continue,
                };
                let detected =
                    pioneer_optical::envelope::builder::kernel_layout_from_image(&decoded.image);
                if detected.is_none() {
                    let signature =
                        bundle
                            .components
                            .iter()
                            .find(|c| c.role == Role::Main)
                            .map(|c| {
                                pioneer_optical::envelope::signature::verify_normal_signature(
                                    &c.bytes,
                                )
                            });
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
                let Some(k) = pioneer_optical::envelope::decode_envelope(&kernel.bytes) else {
                    continue;
                };
                let Some(n) =
                    pioneer_optical::envelope::decode_envelope_with_kernel(&normal.bytes, &k)
                else {
                    continue;
                };
                let Some(h) = pioneer_optical::envelope::header_info(&normal.bytes) else {
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
                        signature_range_match += usize::from(if pioneer_optical::envelope::builder::normal_authentication_from_kernel(&k.image) == Some(pioneer_optical::envelope::builder::NormalAuthentication::ScaledChecksumOnly) {
                            pioneer_optical::envelope::builder::normal_authentication_valid(&normal.bytes, &k.image)
                                && pioneer_optical::envelope::builder::normal_authentication_valid(&rebuilt_normal.bytes, &k.image)
                        } else {
                            pioneer_optical::envelope::signature::verify_normal_signature(
                                &rebuilt_normal.bytes,
                            ) == pioneer_optical::envelope::signature::verify_normal_signature(&normal.bytes)
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
        assert!(replay.knocks >= 1, "the crate knocks before reading");
        validate_envelope_package(&candidate, "BD-RW BDR-UD04").unwrap();
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
            crate::drive::pioneer::offline_pair_data_out(&kernel.bytes, &normal.bytes).unwrap();
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
            let generated_kernel =
                pioneer_optical::envelope::decode_envelope(&kernel.bytes).unwrap();
            let supplied_kernel =
                pioneer_optical::envelope::decode_envelope(&original_kernel.bytes).unwrap();
            let generated_normal = pioneer_optical::envelope::decode_envelope_with_kernel(
                &normal.bytes,
                &generated_kernel,
            )
            .unwrap();
            let supplied_normal = pioneer_optical::envelope::decode_envelope_with_kernel(
                &original_normal.bytes,
                &supplied_kernel,
            )
            .unwrap();
            // UD04 is a known OEM kernel in pioneer_k.bin, so the whole kernel
            // envelope is reconstructed byte-for-byte (real revision/date + the
            // OEM raw front key).
            assert_eq!(kernel.bytes, original_kernel.bytes);
            // The Normal is still self-made with the obvious placeholder seed 0.
            assert_eq!(generated_normal.encoding_seed(), Some(0));
            assert_eq!(generated_kernel.image, supplied_kernel.image);
            assert_eq!(generated_normal.image, supplied_normal.image);
            assert_eq!(
                &normal.bytes[0x1f0..0x200],
                &original_normal.bytes[0x1f0..0x200]
            );
            let original_steps = crate::drive::pioneer::offline_pair_data_out(
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
        let decoded_kernel = pioneer_optical::envelope::decode_envelope(&kernel.bytes).unwrap();
        let decoded_normal =
            pioneer_optical::envelope::decode_envelope_with_kernel(&normal.bytes, &decoded_kernel)
                .unwrap();
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
        )
        .unwrap();
        replay.knocks = 0;
        replay.reads = 0;
        crate::engine::backup(&mut replay, &drive, &output, false, false).unwrap();
        let saved = std::fs::read(&output).unwrap();
        validate_envelope_package(&saved, "BD-RW BDR-UD04").unwrap();
        std::fs::remove_file(&output).unwrap();
        replay.knocks = 0;
        replay.reads = 0;
        replay.corrupt_second_pass = true;
        assert!(capture_signed_candidate(&mut replay).is_err());
    }
}
