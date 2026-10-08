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
/// First address the 24-bit B0 offset field cannot express.
const ADDRESS_LIMIT: usize = 0x100_0000;

/// Whether the drive serves a one-byte B0 read at `off`. Only a 05/24/00 refusal
/// means "past the end"; any other failure is a real error.
fn serves_address(dev: &mut dyn ScsiDevice, off: usize) -> Result<bool> {
    match crate::drive::pioneer_transport::read_memory_exact(dev, off as u32, 1) {
        Ok(_) => Ok(true),
        Err(error) if crate::platform::sense_triplet(&error) == Some((0x05, 0x24, 0x00)) => {
            Ok(false)
        }
        Err(error) => Err(error.context(format!("probing the read end at {off:#x}"))),
    }
}

/// End of the span the drive's B0 memory read serves: the first address it
/// refuses with 05/24/00. The firmware checks a single upper bound (UD04 1.14:
/// `0x880300`), so a binary search over the 24-bit space finds it in ~24 reads.
fn probe_read_end(dev: &mut dyn ScsiDevice) -> Result<usize> {
    if serves_address(dev, ADDRESS_LIMIT - 1)? {
        return Ok(ADDRESS_LIMIT);
    }
    let (mut served, mut refused) = (DUMP_BASE, ADDRESS_LIMIT - 1);
    if !serves_address(dev, served)? {
        bail!("the drive refuses the device base {served:#x}");
    }
    while refused - served > 1 {
        let mid = served + (refused - served) / 2;
        if serves_address(dev, mid)? {
            served = mid;
        } else {
            refused = mid;
        }
    }
    Ok(refused)
}

/// `dump`: ONE contiguous raw read of the entire device — `0x000000` up to the
/// first address the drive refuses (found by [`probe_read_end`]; UD04 1.14:
/// `0x880300`, which covers the flash, work RAM at `0x800000` and the
/// `0x880000` register window) — as a single verbatim byte image. No envelope
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
    let end = match probe_read_end(dev) {
        Ok(end) => end,
        Err(error) if force => {
            let end = pioneer_optical::cdb::READ_CEILING as usize;
            amber(&format!(
                "{error:#}; reading up to the known ceiling {end:#x} (--force)"
            ));
            end
        }
        Err(error) => return Err(error),
    };
    // Always cover the Kernel so its layout can be checked; reads the drive
    // refuses below that are zero-filled and reported as gaps.
    let (image, gaps) = read_region_deep_gaps(dev, DUMP_BASE, end.max(NORMAL_IMAGE_BASE))
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
    // The dump still succeeds with gaps (it is a best-effort salvage), but say so
    // loudly in the final summary.
    crate::output::field(
        "Dump size",
        format!("{} bytes (0x0..{:#x})", image.len(), image.len()),
    );
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

    // Establish the supported physical map before allowing a partial backup.
    // A read failure may be salvaged; unknown geometry must never be mislabeled.
    validate_backup_map(dev, &kernel)?;

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
    eprintln!(
        "Pioneer backup identity: drive={:?} revision={:?} hardware={:?}",
        String::from_utf8_lossy(&inquiry[8..32]),
        String::from_utf8_lossy(&inquiry[32..36]),
        String::from_utf8_lossy(&f1[16..24])
    );
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

/// Probe the readable ceiling and inspect descriptors throughout that span.
/// The envelope codec currently supports a 64 KiB Kernel at 0x400000 only.
/// Refuse other/ambiguous maps instead of manufacturing a truncated backup.
fn validate_backup_map(dev: &mut dyn ScsiDevice, kernel: &[u8]) -> Result<()> {
    let end = probe_read_end(dev)?;
    let mut image = Vec::with_capacity(end);
    for offset in (0..end).step_by(READ_CHUNK) {
        image.extend_from_slice(&read_chunk(dev, offset, READ_CHUNK.min(end - offset))?);
    }
    validate_backup_image_map(&image, kernel)
}

fn validate_backup_image_map(image: &[u8], kernel: &[u8]) -> Result<()> {
    const DESCRIPTOR_ALIGNMENT: usize = 0x100;
    const DESCRIPTOR_LEN: usize = 24;
    let mut bases = Vec::new();
    for base in (0..image.len().saturating_sub(DESCRIPTOR_LEN - 1)).step_by(DESCRIPTOR_ALIGNMENT) {
        if image[base..].starts_with(b"PIONEER ") {
            bases.push(base);
        }
    }
    if bases != [NORMAL_IMAGE_BASE] {
        bail!("unsupported or ambiguous firmware map: Normal descriptors at {bases:x?}; no backup created; use dump for raw capture");
    }
    if kernel.len() != NORMAL_IMAGE_BASE - KERNEL_IMAGE_BASE || !zero_be32_sum(kernel) {
        bail!("unsupported Kernel extent or invalid checksum; no backup created");
    }
    let normal_len = normal_image_len(kernel, &image[NORMAL_IMAGE_BASE..])?;
    if NORMAL_IMAGE_BASE
        .checked_add(normal_len)
        .is_none_or(|end| end > image.len())
    {
        bail!("Normal firmware extends beyond the probed readable ceiling; no backup created");
    }
    Ok(())
}

fn normal_image_len(kernel: &[u8], normal_head: &[u8]) -> Result<usize> {
    if normal_head.len() < 24 || !normal_head.starts_with(b"PIONEER ") {
        bail!("Normal image header is missing at the supported base");
    }
    let normal_len =
        match pioneer_optical::envelope::builder::scaled_normal_geometry_from_kernel(kernel) {
            Some(geometry) => geometry.image_len,
            None => u32::from_be_bytes(normal_head[20..24].try_into().unwrap()) as usize,
        };
    if !(0x2000..=0x800000).contains(&normal_len)
        || !normal_len.is_multiple_of(0x100)
        || NORMAL_IMAGE_BASE + normal_len > ADDRESS_LIMIT
    {
        bail!("Normal image declares an invalid length");
    }
    Ok(normal_len)
}

/// Read the Normal image region: locate its header, derive its length from the
/// Kernel geometry, and capture it (`deep` selects the salvage read).
fn read_normal_region(dev: &mut dyn ScsiDevice, kernel: &[u8], deep: bool) -> Result<Vec<u8>> {
    let normal_head = read_region(dev, NORMAL_IMAGE_BASE, 24, deep)?;
    let normal_len = normal_image_len(kernel, &normal_head)?;
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

/// [`read_region_deep`], also returning the zero-filled gaps `(offset, len)`.
fn read_region_deep_gaps(
    dev: &mut dyn ScsiDevice,
    start: usize,
    len: usize,
) -> Result<(Vec<u8>, Gaps)> {
    let mut image = vec![0u8; len];
    let mut pos = 0usize;
    // Offset of the last chunk that read cleanly: the liveness probe re-reads it,
    // so it never depends on any one region (e.g. the Kernel base) being readable.
    let mut last_good: Option<(usize, usize)> = None;
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
                last_good = Some((off, n.min(DEEP_MIN_CHUNK)));
                pos += n;
            }
            Err(error) => {
                crate::diagnostics::record(format!(
                    "salvage bulk failure: offset={off:#x} length={n} error={error:#}"
                ));
                let good = salvage_span(dev, start, &mut image, (pos, n), &mut gaps, last_good)?;
                any |= good.is_some();
                last_good = good.or(last_good);
                pos += n;
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
/// zero-filled and recorded as gaps. Check a known-readable location before
/// expensive subdivision, so a disconnect does not trigger thousands of reads.
fn salvage_span(
    dev: &mut dyn ScsiDevice,
    start: usize,
    image: &mut [u8],
    span: (usize, usize),
    gaps: &mut Vec<(usize, usize)>,
    last_good: Option<(usize, usize)>,
) -> Result<Option<(usize, usize)>> {
    let (pos, n) = span;
    if let Some(data) = retry_read(dev, start + pos, n) {
        image[pos..pos + n].copy_from_slice(&data);
        return Ok(Some((start + pos, n.min(DEEP_MIN_CHUNK))));
    }
    if let Some((off, len)) = last_good {
        crate::platform::trace_commands(|| read_chunk(dev, off, len))
            .with_context(|| format!("the drive stopped responding at {:#x}; known-readable location {off:#x} also failed; aborting salvage", start + pos))?;
    }
    let mut good = None;
    let mut p = pos;
    while p < pos + n {
        let m = DEEP_MIN_CHUNK.min(pos + n - p);
        match retry_read(dev, start + p, m) {
            Some(data) => {
                image[p..p + m].copy_from_slice(&data);
                good = Some((start + p, m));
            }
            None => push_gap(gaps, start + p, m),
        }
        p += m;
    }
    Ok(good)
}

/// Read `off..off+n` up to `DEEP_RETRIES` times. Every attempt re-knocks (the
/// crate's `read_memory` unlocks before each read), covering a drive that
/// dropped out of read mode. `None` if every attempt failed.
fn retry_read(dev: &mut dyn ScsiDevice, off: usize, n: usize) -> Option<Vec<u8>> {
    for attempt in 1..=DEEP_RETRIES {
        match read_chunk(dev, off, n) {
            Ok(data) => return Some(data),
            Err(error) => crate::diagnostics::record(format!("salvage read failed: address={off:#x} length={n} attempt={attempt}/{DEEP_RETRIES} error={error:#}")),
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

/// Probe a complete word at the Kernel base, avoiding a sub-word transfer.
/// Retry short responses at most twice, re-unlocking each time. Explicit errors
/// still stop immediately; successful access requires a complete response.
fn prepare_firmware_read(dev: &mut dyn ScsiDevice) -> Result<()> {
    crate::platform::trace_commands(|| {
        eprintln!(
            "Pioneer firmware read probe: freemkv-flash={} os={} arch={} device={}",
            env!("CARGO_PKG_VERSION"), std::env::consts::OS,
            std::env::consts::ARCH, dev.describe()
        );
        for attempt in 1..=3 {
            let data = crate::drive::pioneer_transport::read_memory_exact(
                dev, KERNEL_IMAGE_BASE as u32, 4,
            )?;
            eprintln!(
                "Pioneer firmware read probe: attempt={attempt}/3 address={KERNEL_IMAGE_BASE:#x} requested=4 returned={}",
                data.len()
            );
            if data.len() == 4 {
                return Ok(());
            }
            if attempt == 3 {
                bail!("short firmware read at {KERNEL_IMAGE_BASE:#x}: {}/4 after {attempt} attempts", data.len());
            }
            eprintln!("Pioneer firmware read probe: retrying short response after 100 ms");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        unreachable!()
    })
    .context("probing Pioneer firmware read access")
}

#[cfg(test)]
#[path = "pioneer_backup_tests.rs"]
mod tests;
