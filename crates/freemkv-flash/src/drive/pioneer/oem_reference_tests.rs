//! Historical OEM transcript oracles; never compiled into production.
#![allow(dead_code)]
use super::*;
use sha2::{Digest, Sha256};
// ---- Kernel-key table (intentionally minimal) ------------------------------

/// On-wire layout of the 32-bit kernel key inside `payload[0x10..0x14]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLayout {
    /// Big-endian 4-byte word in legacy catalog metadata; not proven on wire.
    Struct,
    /// Little-endian 4-byte word, as copied by the UD04 OEM updater.
    Array,
}

/// A resolved kernel key for a drive: the 32-bit value and its wire layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelKey {
    /// The 32-bit kernel key value.
    pub key: u32,
    /// How it's laid out in the 4 bytes at `payload[0x10..0x14]`.
    pub layout: KeyLayout,
}

/// One catalog entry. Match `prefix` (case-insensitive, whitespace-collapsed)
/// against the INQUIRY product string; longest match wins.
#[derive(Debug, Clone, Copy)]
pub struct KeyEntry {
    /// INQUIRY-product substring that selects this key (e.g. `"BDR-UD04"`).
    pub prefix: &'static str,
    /// The 32-bit kernel key value.
    pub key: u32,
    /// How to lay it out at `payload[0x10..0x14]`.
    pub layout: KeyLayout,
}

/// The compiled-in LEGACY kernel-key table (unused by the live flash path; see
/// the module docs).
///
/// **Grow this deliberately.** Each new row is added only after a real
/// flash-mode entry has been observed on a physical drive of that family.
/// Do not import the full hoard catalog wholesale.
pub const KEYS: &[KeyEntry] = &[KeyEntry {
    prefix: "BDR-UD04",
    key: 0xFD23_6642,
    layout: KeyLayout::Array,
}];

/// Case-insensitive whitespace-collapsed key lookup by INQUIRY product string.
/// Longest matching prefix wins.
pub fn key_for(inquiry_product: &str) -> Option<KernelKey> {
    let needle = normalize(inquiry_product);
    let mut best: Option<(&KeyEntry, usize)> = None;
    for e in KEYS {
        let p = normalize(e.prefix);
        if needle.contains(&p) {
            let len = p.len();
            if best.map(|(_, bl)| len > bl).unwrap_or(true) {
                best = Some((e, len));
            }
        }
    }
    best.map(|(e, _)| KernelKey {
        key: e.key,
        layout: e.layout,
    })
}

pub(super) fn normalize(s: &str) -> String {
    let upper = s.to_ascii_uppercase();
    let mut out = String::with_capacity(upper.len());
    let mut last_space = false;
    for ch in upper.chars() {
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out.trim().to_string()
}

/// Resolve the controller id and OEM control row for a Pioneer envelope from its
/// banner `Hardware Version : SAT xxxx` tag. The SAT value is the controller id
/// in hex. Resolution is by controller id, never by INQUIRY/banner model string,
/// so the model-string collisions in the key table cannot be silently resolved.
fn control_row_for_envelope(
    envelope: &[u8],
) -> Result<&'static crate::drive::pioneer::keys::KeyEntry> {
    let banner =
        parse_banner(envelope).ok_or_else(|| anyhow!("invalid Pioneer envelope banner"))?;
    let cid =
        crate::drive::pioneer::keys::controller_id_from_sat(&banner.hardware).ok_or_else(|| {
            anyhow!(
                "envelope hardware {:?} is not a SAT controller id",
                banner.hardware
            )
        })?;
    crate::drive::pioneer::keys::lookup(cid).ok_or_else(|| {
        anyhow!("no OEM control key on file for controller id {cid:#06X}; cannot flash this model")
    })
}

/// Build the 256-byte OEM control buffer generically for the self/OEM-update
/// (Normal-only) path: the key is selected by the envelope's `Destination` OEM
/// tag (e.g. `GENERAL` for UD04, `ID43` for S09), looked up in the embedded
/// `pioneer_keys.bin` table. Byte-for-byte equivalent to the former hand-baked
/// per-model payloads for every validated model. No drive-acceptance claim.
fn oem_normal_control(envelope: &[u8]) -> Result<[u8; CONTROL_LEN]> {
    let banner =
        parse_banner(envelope).ok_or_else(|| anyhow!("invalid Pioneer envelope banner"))?;
    let row = control_row_for_envelope(envelope)?;
    let tag = if banner.destination.is_empty() {
        crate::drive::pioneer::keys::DEFAULT_TAG
    } else {
        banner.destination.as_str()
    };
    let key = row
        .key_for_tag(tag)
        .ok_or_else(|| anyhow!("no OEM key for destination tag {tag:?} on this controller id"))?;
    Ok(row.control_payload(key))
}

/// OEM updater path whose command and control-buffer bytes were recovered.
/// Profiles are intentionally explicit: other Pioneer variants can use a
/// separate Kernel transfer or different control buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OemUpdateProfile {
    /// BDR-UD04 1.11EU updater, Normal envelope only.
    Ud04V111Normal,
    /// BDR-S09 1.30EU updater, SAT 8600 Normal envelope only.
    S09V130Normal,
}

/// Audited local sources for one host-side update protocol. Hashes identify
/// the exact files, not a signature or authorization of modified firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileEvidence {
    /// Human-readable source package and transfer variant.
    pub source: &'static str,
    /// SHA-256 of the nested OEM updater executable whose host path was traced.
    pub updater_sha256: &'static str,
    /// Additional updater PE with the same selected host data-out path, if audited.
    pub alternate_updater_sha256: Option<&'static str>,
    /// SHA-256 of the exact OEM Normal envelope extracted from that updater.
    pub reference_envelope_sha256: &'static str,
    /// Required update components established for this host path.
    pub components: UpdateComponents,
}

/// Whether the observed updater transfers a separate Kernel resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateComponents {
    /// The audited host path transfers only the supplied Normal envelope.
    NormalOnly,
    /// A separate exact Kernel resource would be needed; unsupported here.
    KernelAndNormal,
}

/// Relationship of an envelope to the audited host transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeEvidence {
    /// Byte-identical to the audited OEM envelope.
    ExactOemReference,
    /// Same-model, structurally eligible offline candidate; not drive-certified.
    UncertifiedCandidate,
}

impl OemUpdateProfile {
    /// Exact source hashes anchoring this profile's command sequence.
    pub const fn evidence(self) -> ProfileEvidence {
        match self {
            Self::Ud04V111Normal => ProfileEvidence {
                source: "BDR-UD04 1.11EU nested Updater.exe, Normal-only path",
                updater_sha256: "af5a2969686e3295fc540e27939342578d533ace57652cb1ae650b7f0cfde072",
                alternate_updater_sha256: None,
                reference_envelope_sha256:
                    "a5aa757081478620637ed2950b540f35f1cbb969598532cfc872daba0a0366e6",
                components: UpdateComponents::NormalOnly,
            },
            Self::S09V130Normal => ProfileEvidence {
                source: "BDR-S09 1.30EU/1.30AEU updaters, SAT 8600 Normal-only path",
                updater_sha256: "eabd55640323a0f9dfbf80668531d2202d1ad3079045625cf55d62821040836d",
                alternate_updater_sha256: Some(
                    "2869613b666f20c6c404e2fbabc98a525888c3676da106154e20476d934bdea6",
                ),
                reference_envelope_sha256:
                    "7f391cf35bc727bbefc97b3b27786283a6e8e5ca1d82f71dc57c78633843c59f",
                components: UpdateComponents::NormalOnly,
            },
        }
    }

    /// Classify an input only against the exact OEM envelope hash. A matching
    /// model/banner is never promoted to reference evidence by itself.
    pub fn envelope_evidence(self, image: &[u8]) -> EnvelopeEvidence {
        let hash = format!("{:x}", Sha256::digest(image));
        if hash == self.evidence().reference_envelope_sha256 {
            EnvelopeEvidence::ExactOemReference
        } else {
            EnvelopeEvidence::UncertifiedCandidate
        }
    }
}

/// Choose a registered host strategy using only live drive identity and the
/// supplied envelope. No updater package or sidecar is a runtime input.
/// Unknown and ambiguous structures fail closed; exact OEM hashes only
/// upgrade evidence status, not command selection.
pub fn select_oem_profile(drive_product: &str, envelope: &[u8]) -> Result<OemUpdateProfile> {
    let banner =
        parse_banner(envelope).ok_or_else(|| anyhow!("invalid Pioneer envelope banner"))?;
    check_normal_size(envelope)?;
    let drive_model = normalize(drive_product);
    let ud04_model_match = drive_model
        .split_whitespace()
        .any(|part| part == "BDR-UD04");
    let mut matches = Vec::new();
    if ud04_model_match
        && banner.model.eq_ignore_ascii_case("BDR-UD04")
        && banner.hardware.eq_ignore_ascii_case("SAT 8A10")
        && banner.destination.eq_ignore_ascii_case("GENERAL")
        && banner.file_type.eq_ignore_ascii_case("Normal")
    {
        matches.push(OemUpdateProfile::Ud04V111Normal);
    }
    let s09_model_match = drive_model.split_whitespace().any(|part| part == "BDR-S09");
    if s09_model_match
        && banner.model.eq_ignore_ascii_case("BDR-S09")
        && banner.revision == "1.30"
        && banner.hardware.eq_ignore_ascii_case("SAT 8600")
        && banner.destination.eq_ignore_ascii_case("ID43")
        && banner.file_type.eq_ignore_ascii_case("Normal")
    {
        matches.push(OemUpdateProfile::S09V130Normal);
    }
    match matches.as_slice() {
        [profile] => Ok(*profile),
        [] => bail!(
            "no audited Pioneer OEM writer profile matches drive identity and envelope structure"
        ),
        _ => bail!("ambiguous Pioneer OEM writer profiles; refusing offline plan"),
    }
}

/// Build only the observed WRITE BUFFER portion of a Normal-only OEM update.
/// This function performs no SCSI I/O. Polling and drive acceptance are not
/// sufficiently established to make this transcript executable.
pub fn offline_oem_transcript<'a>(
    profile: OemUpdateProfile,
    envelope: &'a [u8],
) -> Result<Vec<OemTransfer<'a>>> {
    let banner =
        parse_banner(envelope).ok_or_else(|| anyhow!("invalid Pioneer envelope banner"))?;
    if !envelope.len().is_multiple_of(0x100) || !(IMAGE_MIN..=IMAGE_MAX).contains(&envelope.len()) {
        bail!("Pioneer envelope size is outside the offline profile range or not 256-byte aligned");
    }
    // Keep the per-profile envelope gating (identity/structure must match an
    // audited Normal-only profile), then build the control buffer generically
    // from the embedded key table rather than a hand-baked per-model constant.
    match profile {
        OemUpdateProfile::Ud04V111Normal
            if banner.model.eq_ignore_ascii_case("BDR-UD04")
                && banner.file_type.eq_ignore_ascii_case("Normal") => {}
        OemUpdateProfile::Ud04V111Normal => {
            bail!("UD04 1.11 OEM transcript requires a BDR-UD04 Normal envelope")
        }
        OemUpdateProfile::S09V130Normal
            if banner.model.eq_ignore_ascii_case("BDR-S09")
                && banner.revision == "1.30"
                && banner.hardware.eq_ignore_ascii_case("SAT 8600")
                && banner.destination.eq_ignore_ascii_case("ID43")
                && banner.file_type.eq_ignore_ascii_case("Normal") => {}
        OemUpdateProfile::S09V130Normal => {
            bail!("S09 1.30 OEM transcript requires a BDR-S09 1.30 SAT 8600 ID43 Normal envelope")
        }
    }
    let control = oem_normal_control(envelope)?;
    transfer::data_out(&control, envelope, None)
}

// ---- Preflight (safety belt) -----------------------------------------------

/// Verified pre-flash state: image + drive both look genuine and compatible.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// Parsed banner from the image (`ID :` / `Hardware Version :` etc).
    pub image_banner: PioneerBanner,
    /// The drive's live INQUIRY product string.
    pub drive_product: String,
    /// The kernel key resolved for the drive's INQUIRY product.
    pub key: KernelKey,
}

/// Legacy hard-refuse checks (NOT called by the live flash path, which is gated
/// by the flash plan and `select_oem_profile`; kept as public API).
///
/// * Image starts with the `********  Copyright(c) 2000 Pioneer` magic
/// * Image size is plausible (`IMAGE_MIN..=IMAGE_MAX`)
/// * Image banner parses and its model equals the drive's INQUIRY product
///   (case-insensitive; `--allow-crossflash` waives this check on identical
///   silicon — the caller performs that override)
/// * A kernel key exists in [`KEYS`] for the drive's INQUIRY product
pub fn preflight(image: &[u8], drive_id: &Identity, allow_crossflash: bool) -> Result<Preflight> {
    if image.len() < IMAGE_MIN || image.len() > IMAGE_MAX {
        bail!(
            "image size {} bytes is outside the plausible Pioneer range ({}..={})",
            image.len(),
            IMAGE_MIN,
            IMAGE_MAX
        );
    }
    let banner = parse_banner(image).ok_or_else(|| {
        anyhow!(
            "image does not begin with the Pioneer magic \"********  Copyright(c) 2000 Pioneer\" \
             — refusing to flash arbitrary bytes"
        )
    })?;
    let drive_product = drive_id.product.trim().to_string();
    if !allow_crossflash {
        let banner_n = normalize(&banner.model);
        let drive_n = normalize(&drive_product);
        if !drive_n.contains(&banner_n) && !banner_n.contains(&drive_n) {
            bail!(
                "image model {:?} does not match drive INQUIRY product {:?}; \
                 pass --allow-crossflash to override (same silicon required)",
                banner.model,
                drive_product
            );
        }
    }
    let key = key_for(&drive_product).ok_or_else(|| {
        anyhow!(
            "no kernel key on file for drive INQUIRY product {:?}; \
             cannot flash this model",
            drive_product
        )
    })?;
    Ok(Preflight {
        image_banner: banner,
        drive_product,
        key,
    })
}
