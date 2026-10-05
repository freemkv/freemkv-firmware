//! Pioneer OEM update protocol — byte-exact OEM backup capture + a live,
//! heavily-gated OEM write (Normal-only profiles).
//!
//! The Pioneer OEM updater supplies the host command sequence. A Renesas
//! controller identity alone does not prove this protocol applies. Backup
//! capture is read-only; the live write (`crate::pioneer_flash`, reached via
//! [`DriveFamily::flash_bundle`]) runs only behind the engine's gates
//! (`--execute` + `--i-understand-risk`, empty-tray guard, and a mandatory,
//! completeness-verified pre-flash backup).
//!
//! ## FLASH
//! The UD04 1.11 OEM updater uses 04/FF with a 256-byte entry buffer,
//! 07/F0 with raw envelope chunks, and 05/FF with a 256-byte final buffer,
//! then an INQUIRY `000` gate and a status poll. UD04 is Normal-only. Drive
//! acceptance beyond a byte-exact OEM replay is still the drive's call, not
//! the host's — hence the gates and the idempotent-self-flash-first rollout.
//!
//! ## Kernel-key table
//! Kept intentionally minimal ([`KEYS`]). Grows deliberately per validated
//! model — new entries land here only after a flash-mode entry has been
//! empirically confirmed on that model.

use anyhow::{anyhow, bail, Context, Result};
use pioneer_optical::Role;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

use super::{Capabilities, DriveFamily, Family, FullImage, Identity, RestoreRegion, UserDump};
use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;

#[path = "pioneer_bounded_profiles.rs"]
mod bounded_profiles;
pub use bounded_profiles::BOUNDED_PROFILES;

#[path = "pioneer/transfer.rs"]
pub mod transfer;

// ---- Protocol constants -----------------------------------------------------

// ============================================================================
// FLASH — UD04 1.11 OEM host-side transcript (offline only)
// ============================================================================

pub(crate) const CONTROL_LEN: usize = 0x100;
/// OEM Normal transfer chunk limit.
pub(crate) const FLASH_CHUNK: usize = 0x8000;
/// Minimum/maximum plausible Pioneer image sizes for the size safety-belt.
pub(crate) const IMAGE_MIN: usize = 0x0010_0000; // 1.0 MiB
pub(crate) const IMAGE_MAX: usize = 0x0048_0000; // 4.5 MiB
/// The ASCII magic every genuine Pioneer image starts with.
pub(crate) const PIONEER_MAGIC: &[u8] = b"********  Copyright(c) 2000 Pioneer";

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

/// The compiled-in kernel-key table.
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

fn normalize(s: &str) -> String {
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

/// Extracted fields from the Pioneer plaintext banner (first ~0x160 bytes of
/// any genuine `.fw.bin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PioneerBanner {
    /// Model tag from the banner's `ID :` line, e.g. `BDR-UD04`.
    pub model: String,
    /// `Revision Level :` value, e.g. `1.11`.
    pub revision: String,
    /// `Hardware Version :` value, e.g. `SAT 8A10`.
    pub hardware: String,
    /// `Destination :` value, e.g. `GENERAL`.
    pub destination: String,
    /// `File Type :` value, e.g. `Normal` or `Kernel`.
    pub file_type: String,
}

/// Parse the plaintext ASCII banner. Returns `None` if the magic is missing.
pub fn parse_banner(bytes: &[u8]) -> Option<PioneerBanner> {
    if !bytes.starts_with(PIONEER_MAGIC) {
        return None;
    }
    let head = &bytes[..bytes.len().min(0x200)];
    let text = String::from_utf8_lossy(head);

    fn take_after<'a>(hay: &'a str, needle: &str) -> Option<&'a str> {
        let i = hay.find(needle)?;
        Some(&hay[i + needle.len()..])
    }
    fn until_terminator(s: &str) -> String {
        // The banner terminates every field with `\r\n`; some also carry an
        // internal trailing `.` after a padded space (e.g. `1.11 .`). Split on
        // the line break, then peel a lone trailing `.` if present.
        let line = s.split(['\r', '\n']).next().unwrap_or("").trim();
        line.trim_matches('\0')
            .trim_end_matches('.')
            .trim()
            .to_string()
    }

    let model = take_after(&text, "ID : ")
        .map(|rest| {
            let raw = until_terminator(rest);
            raw.split_whitespace()
                .last()
                .unwrap_or("")
                .trim_end_matches('\u{0}')
                .to_string()
        })
        .unwrap_or_default();
    let revision = take_after(&text, "Revision Level : ")
        .map(until_terminator)
        .unwrap_or_default();
    let hardware = take_after(&text, "Hardware Version : ")
        .map(until_terminator)
        .unwrap_or_default();
    let destination = take_after(&text, "Destination : ")
        .map(until_terminator)
        .unwrap_or_default();
    let file_type = take_after(&text, "File Type : ")
        .map(until_terminator)
        .unwrap_or_default();

    if model.is_empty() {
        return None;
    }
    Some(PioneerBanner {
        model,
        revision,
        hardware,
        destination,
        file_type,
    })
}

// ---- CDB builders ----------------------------------------------------------

/// OEM entry CDB for the traced UD04 1.11 host path.
pub fn cdb_wb_flash_entry() -> [u8; 10] {
    pioneer_optical::cdb::enter_update()
}

/// OEM raw Normal-envelope transfer CDB. `len` excludes any control prefix.
pub fn cdb_wb_flash_chunk(off: u32, len: u32) -> [u8; 10] {
    pioneer_optical::cdb::transfer(Role::Normal, off, len)
}

/// OEM after-transfer CDB; this is not a zero-length commit.
pub fn cdb_wb_flash_finish() -> [u8; 10] {
    pioneer_optical::cdb::finish()
}

/// Resolve the controller id and OEM control row for a Pioneer envelope from its
/// banner `Hardware Version : SAT xxxx` tag. The SAT value is the controller id
/// in hex. Resolution is by controller id, never by INQUIRY/banner model string,
/// so the model-string collisions in the key table cannot be silently resolved.
fn control_row_for_envelope(envelope: &[u8]) -> Result<&'static crate::pioneer_keys::KeyEntry> {
    let banner =
        parse_banner(envelope).ok_or_else(|| anyhow!("invalid Pioneer envelope banner"))?;
    let cid = crate::pioneer_keys::controller_id_from_sat(&banner.hardware).ok_or_else(|| {
        anyhow!(
            "envelope hardware {:?} is not a SAT controller id",
            banner.hardware
        )
    })?;
    crate::pioneer_keys::lookup(cid).ok_or_else(|| {
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
        crate::pioneer_keys::DEFAULT_TAG
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

/// One exact-resource host profile from the bounded BDR-212-style updater
/// cluster. The source hash is manifest provenance; both resource hashes are
/// checked against bytes in the bundle before any offline stage is described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedOemProfile {
    /// SHA-256 of the original downloaded package.
    pub source_sha256: &'static str,
    /// Basename of the downloaded package.
    pub source_name: &'static str,
    /// SHA-256 of the matching nested updater executable.
    pub updater_sha256: &'static str,
    /// Member name of the matching updater executable.
    pub updater_member: &'static str,
    /// Whether exactly one matching updater executable is in the package.
    pub unique_executable: bool,
    /// Exact 16-byte descriptor copied to the OEM control buffer.
    pub control_header: [u8; 16],
    /// OEM control key copied little-endian after the descriptor.
    pub key: u32,
    /// SHA-256 of the complete 256-byte zero-tailed control buffer.
    pub control_sha256: &'static str,
    /// SHA-256 of PE Binary ID131 Kernel resource.
    pub kernel_sha256: &'static str,
    /// Length of PE Binary ID131 Kernel resource.
    pub kernel_len: usize,
    /// SHA-256 of PE Binary ID132 Normal resource.
    pub normal_sha256: &'static str,
    /// Length of PE Binary ID132 Normal resource.
    pub normal_len: usize,
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

/// Size sanity for a Normal about to be written: within `IMAGE_MIN..=IMAGE_MAX`
/// and 256-byte aligned (offsets are 24-bit; a bad size would fail mid-session).
fn check_normal_size(envelope: &[u8]) -> Result<()> {
    if !(IMAGE_MIN..=IMAGE_MAX).contains(&envelope.len()) || !envelope.len().is_multiple_of(0x100) {
        bail!("Pioneer envelope length is outside the supported profile range or not 256-byte aligned");
    }
    Ok(())
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

/// One data-out command in an offline OEM transfer transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStage {
    /// Enter the OEM update mode with a 256-byte control buffer.
    Entry,
    /// Transfer the initial raw Kernel prefix on buffer F0.
    KernelPrefix,
    /// Transfer one Kernel FE slice, possibly generated at runtime.
    KernelFe,
    /// Transfer one raw Normal envelope chunk.
    Normal,
    /// Finish the OEM transfer with a 256-byte control buffer.
    Finish,
}

/// A data-out SCSI command and its exact payload, held offline.
#[derive(Debug, Clone)]
pub struct OemTransfer<'a> {
    /// Stage of the observed host sequence.
    pub stage: TransferStage,
    /// Ten-byte WRITE BUFFER command descriptor block.
    pub cdb: [u8; 10],
    /// Data-out bytes; Normal chunks borrow the original envelope.
    pub data: Cow<'a, [u8]>,
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

/// A code-backed BDR-212 1.05 stage outline. It intentionally does not
/// implement the full preflight, status polling, bundle selection, or a live
/// executor. `GeneratedKernelBlock` depends on the updater's GetTickCount
/// seed; it cannot be represented by a byte-exact package-only transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bdr212Stage {
    /// 04/FF with the descriptor/key control buffer.
    EntryControl,
    /// 07/F0 sends the unchanged Kernel resource prefix.
    KernelPrefix {
        /// Offset in the Kernel resource.
        source_offset: u32,
        /// Transfer length.
        length: u32,
    },
    /// Runtime GetTickCount/CRT-rand block replaces the working buffer head.
    GeneratedKernelBlock {
        /// Generated byte count.
        length: u32,
    },
    /// 07/FE sends one selected Kernel working-buffer slice.
    KernelFe {
        /// Offset encoded in the WRITE BUFFER CDB.
        cdb_offset: u32,
        /// Offset in the working Kernel buffer after generation.
        source_offset: u32,
        /// Transfer length.
        length: u32,
    },
    /// 07/F0 sends the unchanged Normal resource in bounded chunks.
    NormalEnvelope {
        /// Total transfer length.
        length: u32,
    },
    /// 05/FF with the descriptor/key control buffer.
    FinishControl,
}

/// Selected BDR-212 1.05 updater data-out stages, without the separate
/// read/clear/poll/status operations needed for a complete executable path.
pub const BDR212_V105_STAGES: &[Bdr212Stage] = &[
    Bdr212Stage::EntryControl,
    Bdr212Stage::KernelPrefix {
        source_offset: 0,
        length: 0x1200,
    },
    Bdr212Stage::GeneratedKernelBlock { length: 0x200 },
    Bdr212Stage::KernelFe {
        cdb_offset: 0,
        source_offset: 0,
        length: 0x200,
    },
    Bdr212Stage::KernelFe {
        cdb_offset: 0x1200,
        source_offset: 0x200,
        length: 0x8000,
    },
    Bdr212Stage::KernelFe {
        cdb_offset: 0x9200,
        source_offset: 0x8200,
        length: 0x8000,
    },
    Bdr212Stage::KernelFe {
        cdb_offset: 0x11200,
        source_offset: 0x10200,
        length: 0x1000,
    },
    Bdr212Stage::NormalEnvelope { length: 0x1d7600 },
    Bdr212Stage::FinishControl,
];

/// Reproduce the updater's 512-byte MSVC CRT `rand()` block for an explicit
/// seed. This is an offline algorithm KAT, not evidence that any seed is
/// accepted by the drive or that a firmware bundle selects this path.
pub fn bdr212_generated_kernel_block(seed: u32) -> [u8; 0x200] {
    let mut state = seed;
    let mut out = [0u8; 0x200];
    for byte in &mut out {
        state = state.wrapping_mul(0x343fd).wrapping_add(0x269ec3);
        *byte = ((state >> 16) & 0xff) as u8;
    }
    out
}

/// Materialize only the BDR-212 1.05 data-out sequence for exact audited PE
/// resources and a caller-supplied timestamp seed. The actual updater obtains
/// that seed from GetTickCount; this API neither predicts it nor performs I/O.
/// Read/clear/poll/status operations are excluded, so this is not an
/// executable firmware update plan.
pub fn offline_bdr212_v105_data_out<'a>(
    kernel: &'a [u8],
    normal: &'a [u8],
    seed: u32,
) -> Result<Vec<OemTransfer<'a>>> {
    let profile = BOUNDED_PROFILES
        .iter()
        .find(|p| {
            p.kernel_sha256 == "7c4e8f4a45f2f555d425d7dce3fb6362bdcfc8ff1a78bfa914ca8470c70c97e6"
                && p.normal_sha256
                    == "f570afebf6d00aa494b5d6e4ec3ae8360494536de4c2fc9c7f202fd3414c8403"
        })
        .ok_or_else(|| anyhow!("audited BDR-212 1.05 profile missing from pinned table"))?;
    offline_bounded_oem_data_out(profile, kernel, normal, seed)
}

/// A receiver/transfer profile is selected from envelope facts. Adding a
/// model requires independent updater evidence for its control word and wire
/// framing; no release filename or OEM hash belongs in this registry.
struct LinearFeProfile {
    model: &'static str,
    hardware: &'static str,
    kernel_len: usize,
    normal_len: usize,
}

const LINEAR_FE_PROFILES: &[LinearFeProfile] = &[LinearFeProfile {
    model: "BDR-UD04",
    hardware: "SAT 8A10",
    kernel_len: 0x11200,
    normal_len: 0x1d7700,
}];

/// Validate an established linear-FE Kernel+Normal pair and build its 256-byte
/// OEM control buffer. The validated framing constraints (model, hardware,
/// resource lengths, identity agreement, signature, decoded integrity) are
/// preserved exactly; the control bytes are now sourced generically from the
/// embedded key table — the descriptor plus the model's autoflasher fallback
/// key (the crossflash path bypasses the per-destination dispatcher). Source and
/// advertised revision do not select this path; receiver acceptance is untested.
fn linear_fe_control(kernel: &[u8], normal: &[u8]) -> Result<[u8; CONTROL_LEN]> {
    use pioneer_optical::envelope::signature::{verify_normal_signature, SignatureCheck};
    let kh = pioneer_optical::envelope::header_info(kernel)
        .ok_or_else(|| anyhow!("Kernel header missing"))?;
    let nh = pioneer_optical::envelope::header_info(normal)
        .ok_or_else(|| anyhow!("Normal header missing"))?;
    let profile = LINEAR_FE_PROFILES
        .iter()
        .find(|profile| {
            kh.model == profile.model
                && kh.hardware_version == profile.hardware
                && kernel.len() == profile.kernel_len
                && normal.len() == profile.normal_len
        })
        .ok_or_else(|| anyhow!("no established linear-FE profile matches the envelopes"))?;
    if nh.model != kh.model
        || nh.hardware_version != kh.hardware_version
        || kh.destination != "GENERAL"
        || nh.destination != kh.destination
        || kh.file_type != Some(pioneer_optical::ComponentKind::Kernel)
        || nh.file_type != Some(pioneer_optical::ComponentKind::Normal)
        || kh.kernel_version != nh.kernel_version
        || kh.kernel_version2 != nh.kernel_version2
    {
        bail!("linear-FE envelope identities disagree");
    }
    if verify_normal_signature(normal) != SignatureCheck::ValidKeyAndCiphertext {
        bail!("Normal signature is invalid or unsupported for this profile");
    }
    let decoded_kernel = pioneer_optical::envelope::decode_envelope(kernel)
        .ok_or_else(|| anyhow!("Kernel decode failed"))?;
    let decoded_normal =
        pioneer_optical::envelope::decode_envelope_with_kernel(normal, &decoded_kernel)
            .ok_or_else(|| anyhow!("Normal receiver decode failed"))?;
    if decoded_kernel.info.layout != pioneer_optical::envelope::Layout::KernelFront
        || decoded_normal.info.layout != pioneer_optical::envelope::Layout::Normal
        || !zero_word_sum(&decoded_kernel.image)
        || !zero_word_sum(&decoded_normal.image)
    {
        bail!("decoded image integrity or layout mismatch");
    }
    let _ = profile;
    let row = control_row_for_envelope(normal)?;
    Ok(row.control_payload(row.fallback))
}

/// Validate and plan an established linear-FE envelope pair from its contents.
/// Offline-only transcript for dry-run/verification; the live write goes through
/// the imperative executor. Receiver acceptance is a separate, untested question.
pub fn offline_linear_fe_data_out<'a>(
    kernel: &'a [u8],
    normal: &'a [u8],
) -> Result<Vec<OemTransfer<'a>>> {
    let control = linear_fe_control(kernel, normal)?;
    transfer::data_out(
        &control,
        normal,
        Some(transfer::KernelTransfer::LinearFe(kernel)),
    )
}

fn zero_word_sum(bytes: &[u8]) -> bool {
    bytes.len().is_multiple_of(4)
        && bytes.as_chunks::<4>().0.iter().fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(*word))
        }) == 0
}

/// Materialize the shared bounded-flow data-out path for an exact, pinned
/// Kernel/Normal resource pair and an explicit GetTickCount seed. This omits
/// preflight, read/clear, polling, status, and reset; it never opens a drive.
pub fn offline_bounded_oem_data_out<'a>(
    profile: &BoundedOemProfile,
    kernel: &'a [u8],
    normal: &'a [u8],
    seed: u32,
) -> Result<Vec<OemTransfer<'a>>> {
    if profile.kernel_len != 0x11200
        || kernel.len() != profile.kernel_len
        || format!("{:x}", Sha256::digest(kernel)) != profile.kernel_sha256
    {
        bail!("Kernel resource differs from pinned PE Binary ID131");
    }
    if normal.len() != profile.normal_len
        || format!("{:x}", Sha256::digest(normal)) != profile.normal_sha256
    {
        bail!("Normal resource differs from pinned PE Binary ID132");
    }
    let mut control = [0u8; CONTROL_LEN];
    control[..16].copy_from_slice(&profile.control_header);
    control[16..20].copy_from_slice(&profile.key.to_le_bytes());
    if format!("{:x}", Sha256::digest(control)) != profile.control_sha256 {
        bail!("control buffer differs from pinned updater construction");
    }
    transfer::data_out(
        &control,
        normal,
        Some(transfer::KernelTransfer::PrefixF0GeneratedFe {
            bytes: kernel,
            seed,
        }),
    )
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

/// Run every hard-refuse check before any OEM update-entry write hits the wire.
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

// ---- Flash input classification + confirm prompt ---------------------------

/// Writable components resolved from a flash input: `(kernel, normal)`, each
/// present only when the input carries that envelope.
pub(crate) type FlashComponents = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Resolve the flash input into its writable components: `(kernel, normal)`.
/// A bare Normal `.enc` (recognizable Pioneer banner) is a Normal-only input;
/// anything else MUST parse as a strict bundle — a malformed/hostile tar is
/// refused, never silently reinterpreted as a raw envelope.
pub(crate) fn classify_flash_input(input: &[u8]) -> Result<FlashComponents> {
    if parse_banner(input).is_some() {
        return Ok((None, Some(input.to_vec())));
    }
    let bundle = crate::pioneer_bundle::Bundle::from_tar_bytes(input)
        .context("flash input is neither a valid Pioneer bundle nor a Normal .enc")?;
    let find = |role| {
        bundle
            .components
            .iter()
            .find(|c| c.role == role)
            .map(|c| c.bytes.clone())
    };
    Ok((
        find(crate::pioneer_bundle::Role::Kernel),
        find(crate::pioneer_bundle::Role::Main),
    ))
}

/// Which components a flash will write, decided from the classified input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlashSelection {
    /// Write the Normal envelope only (bare `.enc` or a Normal-only bundle).
    NormalOnly,
    /// Write both the Kernel and the Normal (crossflash/downgrade package).
    KernelAndNormal,
}

/// Decide the flash path from the presence of each component. Kernel-only has
/// no validated transcript; neither present is a malformed selection.
pub(crate) fn decide_flash(has_kernel: bool, has_normal: bool) -> Result<FlashSelection> {
    match (has_kernel, has_normal) {
        (true, true) => Ok(FlashSelection::KernelAndNormal),
        (false, true) => Ok(FlashSelection::NormalOnly),
        (true, false) => {
            bail!("kernel-only flash is not yet supported (no validated kernel-only transcript)")
        }
        (false, false) => bail!("flash input has neither a Kernel nor a Normal component to write"),
    }
}

/// One-line human summary of what the flash WILL write and what is MISSING.
/// Revisions come from each envelope header; a missing/unreadable header shows
/// `unknown` rather than failing.
pub(crate) fn flash_summary(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> String {
    fn rev(bytes: &[u8]) -> String {
        pioneer_optical::envelope::header_info(bytes)
            .map(|h| h.revision)
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }
    match (kernel, normal) {
        (Some(k), Some(n)) => format!(
            "This will flash: KERNEL (rev {}) + NORMAL (rev {})",
            rev(k),
            rev(n)
        ),
        (None, Some(_)) => "This will flash: NORMAL only — no Kernel in the package".to_string(),
        (Some(_), None) => "This will flash: KERNEL only — no Normal in the package".to_string(),
        (None, None) => "This will flash: (nothing selected)".to_string(),
    }
}

/// Derive installed-firmware routing facts from the pre-flash backup — the OEM
/// package captured off this very drive moments earlier. Returns `None` when the
/// backup is absent or its identity cannot be resolved (callers then treat the
/// flash as plain; the backup + gates still protect the drive).
pub(crate) fn installed_facts(
    backup: Option<&[u8]>,
) -> Option<crate::pioneer_flash_plan::Installed> {
    use crate::pioneer_flash_plan::{FwDate, Generation, Installed};
    let (installed_kernel, installed_normal) = classify_flash_input(backup?).ok()?;
    let header = |b: &Option<Vec<u8>>| {
        b.as_deref()
            .and_then(pioneer_optical::envelope::header_info)
    };
    let kinfo = header(&installed_kernel);
    let ninfo = header(&installed_normal);
    // Controller id from the Normal (preferred) or Kernel header.
    let controller_id = ninfo
        .as_ref()
        .or(kinfo.as_ref())
        .and_then(|h| crate::pioneer_keys::controller_id_from_sat(&h.hardware_version))?;
    let normal_date = ninfo
        .as_ref()
        .and_then(|h| FwDate::parse(&h.generated_date));
    // Receiver-generation proxy: the new-gen Site-1 signatures co-occur with the
    // installed Kernel's `0x01` marker (whitepaper §15.2), so marker `01` on the
    // installed Kernel implies a new-generation (Site-1-bearing) receiver.
    let receiver_new_gen = installed_kernel
        .as_deref()
        .and_then(pioneer_optical::envelope::decode_envelope)
        .and_then(|d| d.image.get(0xFE).copied())
        .map(|m| Generation::from_marker(m) == Generation::Newer);
    // Installed family: profile the decoded installed Normal body (the same
    // decode used for the target, so the two keys are directly comparable).
    let family = installed_normal
        .as_deref()
        .and_then(crate::pioneer_flash_plan::normal_family);
    // Installed Kernel ID tag: use the installed Normal envelope header's
    // declared required-Kernel tag. On a drive that was shipped as a paired
    // Kernel+Normal release this is exactly the drive's live `3C/02/F1`
    // kernel-tag byte-for-byte (OEM Pioneer updaters compare the two). If a
    // live Identity is also available we would prefer it (handles the
    // paired-mismatch edge case), but the backup header is a reliable source.
    let kernel_tag = ninfo
        .as_ref()
        .map(|h| h.kernel_version.trim().to_string())
        .filter(|s| !s.is_empty());
    Some(Installed {
        controller_id,
        receiver_new_gen,
        normal_date,
        family,
        kernel_tag,
    })
}

/// Route the installed firmware against the target ([`crate::pioneer_flash_plan`])
/// and return the plan. The installed facts come from the just-captured pre-flash
/// backup (the planner stays pure; the family keys are computed here, where the
/// backup bytes are in hand). `recover` uses the recover plan (family gate only);
/// `force` ignores the family match. Without installed facts (no backup) the
/// family cannot be proven, so the flash is refused unless `force`.
pub(crate) fn resolve_flash_plan(
    installed_backup: Option<&[u8]>,
    kernel: Option<&[u8]>,
    normal: Option<&[u8]>,
    recover: bool,
    force: bool,
) -> Result<crate::pioneer_flash_plan::FlashPlan> {
    use crate::pioneer_flash_plan::{decide_recover_plan, normal_family, target_from_components};

    let installed = installed_facts(installed_backup);
    if recover {
        let target_family = normal.and_then(normal_family);
        let plan = decide_recover_plan(
            installed.as_ref().and_then(|i| i.family.as_ref()),
            target_family.as_ref(),
            force,
        );
        crate::style::trace(&format!("recover plan = {plan:?}"));
        return Ok(plan);
    }
    let target = target_from_components(kernel, normal)
        .context("could not read target bundle identity for flash routing")?;
    crate::style::trace(&format!(
        "flash routing: installed={installed:?}, target={target:?}"
    ));
    let plan = plan_for(installed.as_ref(), &target, force);
    crate::style::trace(&format!("flash plan = {plan:?}"));
    Ok(plan)
}

/// Pure routing core of [`resolve_flash_plan`]: no installed facts means the
/// installed family is unknown, so the family gate refuses (or `force` overrides).
fn plan_for(
    installed: Option<&crate::pioneer_flash_plan::Installed>,
    target: &crate::pioneer_flash_plan::Target,
    force: bool,
) -> crate::pioneer_flash_plan::FlashPlan {
    use crate::pioneer_flash_plan::{decide_flash_plan, Installed};
    match installed {
        Some(inst) => decide_flash_plan(inst, target, force),
        None => {
            // Nothing known about the installed firmware: only the family gate's
            // "unknown installed" refusal applies, which `force` waives.
            let unknown = Installed {
                controller_id: target.controller_id,
                receiver_new_gen: None,
                normal_date: None,
                family: None,
                kernel_tag: None,
            };
            decide_flash_plan(&unknown, target, force)
        }
    }
}

/// Loud notice that the family gate (and every safety classification) was waived.
const FORCED_WARNING: &str = "WARNING: the firmware-family match was bypassed (--force). \
    Flashing firmware from a different or unprofiled family can permanently brick this drive.";

/// Loud notice shown for a cross-generation downgrade — the §15.3 Site-1
/// marker patch WILL be applied to the incoming Kernel so it crosses the gate.
/// The write succeeds, but the drive ends up advertising a disguised marker.
const DOWNGRADE_WARNING: &str = "WARNING: this flash crosses the firmware generation barrier. \
    The incoming Kernel's generation marker will be patched (§15.3: body[0xFE] FF/00→01, \
    checksum word @0x1020 compensated) so the receiver's Site-1 gate accepts it. The drive \
    will run the older firmware with a disguised newer-era marker. Pre-flash backup+dump \
    are mandatory; keep them.";

/// Whether the §15.3 Site-1 marker patch will be applied to the Kernel written:
/// a Kernel is written, its decoded `0xFE` marker is `FF`/`00`, and the receiver
/// is not KNOWN to be old-generation (`None` = unknown, patched as before).
pub(crate) fn will_patch_kernel(kernel: Option<&[u8]>, receiver_new_gen: Option<bool>) -> bool {
    let Some(kernel) = kernel else { return false };
    let marker =
        pioneer_optical::envelope::decode_envelope(kernel).and_then(|d| d.image.get(0xFE).copied());
    matches!(marker, Some(0xFF | 0x00)) && receiver_new_gen != Some(false)
}

/// Whether the plan (or a `Forced` plan's inner plan) is `KernelDowngrade`.
fn plan_is_downgrade(plan: &crate::pioneer_flash_plan::FlashPlan) -> bool {
    use crate::pioneer_flash_plan::FlashPlan;
    match plan {
        FlashPlan::KernelDowngrade => true,
        FlashPlan::Forced(inner) => plan_is_downgrade(inner),
        _ => false,
    }
}

/// Decide whether the executor may act on a plan. `Refused` aborts before any
/// write. Same-generation and same/newer flashes execute via the ordinary OEM
/// route. A cross-generation downgrade is now executable — the §15.3 patch is
/// applied to the Kernel bytes inside [`crate::pioneer_flash::execute_flash`]
/// just before the Kernel write, so the receiver's Site-1 gate accepts the
/// disguised marker. No plan requires kernel mode
/// ([`crate::pioneer_flash_plan::kernel_mode_required`]).
pub(crate) fn check_plan_executable(plan: &crate::pioneer_flash_plan::FlashPlan) -> Result<()> {
    use crate::pioneer_flash_plan::FlashPlan;
    match plan {
        FlashPlan::Plain | FlashPlan::KernelCrossflash => Ok(()),
        FlashPlan::Forced(inner) => {
            eprintln!("{}", crate::style::amber(FORCED_WARNING));
            check_plan_executable(inner)
        }
        FlashPlan::KernelDowngrade => {
            eprintln!("{}", crate::style::amber(DOWNGRADE_WARNING));
            Ok(())
        }
        FlashPlan::Refused(reason) => bail!("refusing to flash: {reason}"),
    }
}

/// Print the summary and get explicit consent. On a TTY, require `y`/`yes`;
/// when stdin is not a TTY the `--execute`/`--i-understand-risk` flags already
/// are the consent, so proceed automatically (and say so).
pub(crate) fn confirm_proceed(summary: &str) -> Result<()> {
    use std::io::IsTerminal;
    let is_tty = std::io::stdin().is_terminal();
    confirm_with(summary, is_tty, &mut std::io::stdin().lock())
}

/// Testable core of [`confirm_proceed`]: decoupled from the real stdin so the
/// non-TTY auto-proceed and the explicit-yes TTY paths can be exercised offline.
fn confirm_with(summary: &str, is_tty: bool, reader: &mut impl std::io::BufRead) -> Result<()> {
    use std::io::Write;
    println!("{}", crate::style::bold(summary));
    if !is_tty {
        println!(
            "{}",
            crate::style::dim(
                "stdin is not a TTY; proceeding on the --execute / --i-understand-risk consent."
            )
        );
        return Ok(());
    }
    print!("Proceed? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    reader.read_line(&mut line)?;
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => bail!("flash aborted at confirmation prompt"),
    }
}

// ---- The Pioneer DriveFamily impl ------------------------------------------

/// Pioneer OEM protocol backend: identity, byte-exact OEM backup capture, and a
/// gated live OEM write (Normal-only) via [`DriveFamily::flash_bundle`]. The
/// image-chunk `flash_open/chunk/close` methods stay fail-closed and unused —
/// Pioneer's live write goes through `flash_bundle`, not that path.
#[derive(Default)]
pub struct Pioneer;

impl Pioneer {
    /// Create a fresh Pioneer family handle with no cached session state.
    pub const fn new() -> Self {
        Self
    }
}

impl DriveFamily for Pioneer {
    fn backend_name(&self) -> &'static str {
        "pioneer-oem"
    }

    fn probe(
        &self,
        dev: &mut dyn ScsiDevice,
        identity: &super::Identity,
    ) -> Result<Option<super::ProbeEvidence>> {
        let pioneer_model = identity
            .product
            .split_whitespace()
            .last()
            .is_some_and(|model| {
                ["BDR-", "BDC-", "DVR-"]
                    .iter()
                    .any(|prefix| model.starts_with(prefix))
            });
        Ok((identity.vendor.eq_ignore_ascii_case("PIONEER")
            && pioneer_model
            && super::read_buffer_f1_ok(dev))
        .then_some(super::ProbeEvidence {
            family: Family::Pioneer,
            backend_name: self.backend_name(),
            discriminator: "PIONEER BDR/BDC/DVR INQUIRY + READ BUFFER 02/F1 hardware",
        }))
    }
    fn offline_plan(&self, req: &super::FlashRequest) -> Option<Result<()>> {
        // On --execute the live bundle executor owns the flow (engine gates it);
        // offline_plan only serves the dry run.
        if req.execute {
            return None;
        }
        Some(crate::engine::plan_pioneer_offline(
            &req.input,
            req.input_kind,
            &req.drive_model,
            req.allow_crossflash,
            req.verbose,
        ))
    }
    fn flash_is_bundle(&self) -> bool {
        true
    }
    fn verify_preflash_backup(&self, backup: &[u8], input: &[u8]) -> Result<()> {
        // The backup must hold a rollback for EVERY region this flash overwrites.
        // Decide what will be written from the input; if it cannot be classified
        // yet, fall back to the historical rule (a Normal is always written).
        let (writes_kernel, writes_normal) = match classify_flash_input(input) {
            Ok((kernel, normal)) => (kernel.is_some(), normal.is_some()),
            Err(_) => (false, true),
        };
        let roles = crate::pioneer_backup::component_roles(backup);
        let has = |role: &str| roles.iter().any(|(r, _)| r == role);
        for (writes, role, label) in [
            (writes_normal, "main", "Normal"),
            (writes_kernel, "kernel", "Kernel"),
        ] {
            if writes && !has(role) {
                bail!(
                    "pre-flash backup is incomplete: the {label} region (which the flash \
                     overwrites) could not be captured, so it has no rollback. Refusing to flash. \
                     Run `recover` or resolve the read error first, or pass --skip-backup to \
                     proceed with NO rollback."
                );
            }
        }
        Ok(())
    }
    fn flash_bundle(
        &self,
        dev: &mut dyn ScsiDevice,
        req: &super::FlashRequest,
        installed_backup: Option<&[u8]>,
    ) -> Option<Result<()>> {
        if !req.execute {
            return None;
        }
        Some((|| {
            // Flash whatever components the input carries: a Kernel+Normal
            // package crossflashes via the linear-FE path, a Normal-only input
            // (bundle or bare `.enc`) via the OEM Normal path. A Kernel-only
            // input has no validated path and is refused. The 256-byte control
            // buffer is built here from the embedded key table (keyed by the
            // envelope's controller id), then the executor issues the WRITE
            // BUFFER CDBs imperatively — there is no pre-built replayed list.
            let (kernel, normal) = classify_flash_input(&req.input)?;
            let selection = decide_flash(kernel.is_some(), normal.is_some())?;
            let normal = normal
                .as_deref()
                .expect("normal present for both selections");

            // An image with an unrecoverable envelope tail is never flashed — not
            // even with --force or --recover.
            crate::pioneer_flash_plan::ensure_no_unrecovered_tail(kernel.as_deref(), Some(normal))?;

            // Routing: the family-match gate (installed vs target Normal family,
            // computed from the just-captured pre-flash backup and the target).
            // `--recover` skips the downgrade/pair refusals but keeps the family
            // gate; `--force` ignores the family match. No path uses kernel mode.
            // Bundle self-consistency gate: refuse malformed bundles (bad
            // headers, SAT mismatch between Kernel/Normal, Kernel ID tag ≠
            // Normal's required-Kernel tag, unrecovered envelope tail) BEFORE
            // any planning or writes. Even `--force` would still be flashing
            // garbage; a broken bundle never has a legitimate path.
            crate::pioneer_flash_plan::validate_bundle(kernel.as_deref(), Some(normal))
                .map_err(|e| anyhow!("{e}"))?;
            let plan = resolve_flash_plan(
                installed_backup,
                kernel.as_deref(),
                Some(normal),
                req.recover,
                req.force,
            )?;
            check_plan_executable(&plan)?;
            debug_assert!(!crate::pioneer_flash_plan::kernel_mode_required(&plan));

            // `--recover` waives the profile gate but not the size sanity check.
            if req.recover {
                check_normal_size(normal)?;
            }
            let (control, kernel_to_write) = match selection {
                FlashSelection::KernelAndNormal => {
                    let kernel = kernel
                        .as_deref()
                        .expect("kernel present for KernelAndNormal");
                    (linear_fe_control(kernel, normal)?, Some(kernel))
                }
                FlashSelection::NormalOnly => {
                    // Normally keep the audited profile gate (identity/structure/
                    // ambiguity refusal); `--recover` waives it (a degraded drive
                    // may not report a trustworthy identity). Then build the
                    // control generically from the key table.
                    if !req.recover {
                        let _profile = select_oem_profile(&req.drive_model, normal)?;
                    }
                    (oem_normal_control(normal)?, None)
                }
            };
            // The §15.3 marker patch is applied only when it will really happen:
            // known new-gen (or unknown, e.g. --recover/--skip-backup) receiver and
            // an FF/00-marker Kernel. Warn once; KernelDowngrade already warned in
            // check_plan_executable.
            let will_patch = will_patch_kernel(
                kernel_to_write,
                installed_facts(installed_backup).and_then(|i| i.receiver_new_gen),
            );
            if will_patch && !plan_is_downgrade(&plan) {
                eprintln!("{}", crate::style::amber(DOWNGRADE_WARNING));
            }
            // Summarize what will be written and what is missing, then confirm.
            confirm_proceed(&flash_summary(kernel.as_deref(), Some(normal)))?;
            crate::pioneer_flash::execute_flash(
                dev,
                &control,
                kernel_to_write,
                normal,
                req.recover,
                will_patch,
            )?;
            println!(
                "{}",
                crate::style::green("flash complete; drive returned ready.")
            );
            // Auto post-flash identity readback: the drive just rebooted into
            // whatever it now reports as its live identity. Print it so the user
            // sees exactly what landed without a separate `info` invocation.
            // Non-fatal: a transient post-boot read error is a warning, not a
            // flash failure (the write already committed).
            match crate::drive::pioneer_transport::identify(dev) {
                Ok(ident) => {
                    println!(
                        "post-flash: vendor='{}' product='{}' rev='{}' platform='{}' kernel-tag='{}'",
                        ident.vendor(),
                        ident.product(),
                        ident.revision(),
                        ident.platform(),
                        ident.kernel_tag(),
                    );
                }
                Err(e) => eprintln!(
                    "{}",
                    crate::style::amber(&format!(
                        "post-flash identify failed ({e:#}); the flash itself committed OK"
                    ))
                ),
            }
            Ok(())
        })())
    }
    fn family(&self) -> Family {
        Family::Pioneer
    }
    fn backup_extension(&self) -> Option<&'static str> {
        Some("tar")
    }
    fn backup_kind(&self) -> super::BackupKind {
        // The advisory is decided per-capture in `backup_notice`, not statically:
        // a byte-exact OEM capture gets no warning.
        super::BackupKind {
            infix: "candidate",
            notice: None,
        }
    }
    fn backup_notice(&self, bytes: &[u8]) -> super::BackupNotice {
        use super::BackupNotice;
        let components = crate::pioneer_backup::component_roles(bytes);
        let kernel = components.iter().find(|(role, _)| *role == "kernel");
        let normal = components.iter().find(|(role, _)| *role == "main");
        // Partial capture: one region could not be read. Name what was saved and
        // point the user at `recover` for a deeper read of the missing region.
        match (kernel, normal) {
            (Some((_, kname)), None) => {
                return BackupNotice::Unverified(format!(
                    "PARTIAL BACKUP: saved the Kernel only (as {kname}). The Normal region could \
                     not be read — run `freemkv-flash recover <device>` to attempt a deeper read."
                ))
            }
            (None, Some((_, nname))) => {
                return BackupNotice::Unverified(format!(
                    "PARTIAL BACKUP: saved the Normal only (as {nname}). The Kernel region could \
                     not be read — run `freemkv-flash recover <device>` to attempt a deeper read."
                ))
            }
            _ => {}
        }
        let p = crate::pioneer_backup::package_provenance(bytes);
        match (p.kernel_oem, p.normal_oem) {
            (true, true) => BackupNotice::VerifiedOem(
                "OEM-VERIFIED: kernel and normal are byte-exact OEM originals."
                    .to_string(),
            ),
            (true, false) => BackupNotice::Unverified(
                "PARTIAL OEM: kernel is a byte-exact OEM original; the normal is NOT recognized OEM \
                 (zero seed + zeroed signature sentinel). Physical restore and drive acceptance are untested."
                    .to_string(),
            ),
            (false, true) => BackupNotice::Unverified(
                "PARTIAL OEM: normal is a byte-exact OEM original; the kernel is NOT recognized OEM \
                 (zero placeholders). Physical restore and drive acceptance are untested."
                    .to_string(),
            ),
            (false, false) => BackupNotice::Unverified(
                "UNVERIFIED: neither kernel nor normal is recognized OEM (zero placeholders + zeroed \
                 signature sentinel). Physical restore and drive acceptance are untested."
                    .to_string(),
            ),
        }
    }
    fn capture_backup(&self, dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
        // Dump the live H8/SAT image regions and re-wrap them as byte-exact OEM
        // envelopes where recognized, else zero-sentinel. Read-only: no write.
        crate::pioneer_backup::capture_signed_candidate(dev)
    }
    fn dump_is_raw(&self) -> bool {
        true
    }
    fn capture_dump(&self, dev: &mut dyn ScsiDevice, force: bool) -> Result<Vec<u8>> {
        // One contiguous raw read of the whole firmware window. Never uses vendor
        // kernel mode (not cold-reachable on BD firmware; see
        // `pioneer_flash_plan::kernel_mode_required`). `force` tolerates a
        // degraded drive: unreadable spans are zero-filled and reported instead
        // of aborting. Read-only.
        crate::pioneer_backup::capture_raw_dump(dev, force)
    }
    fn validate_backup(&self, bytes: &[u8], target_model: &str) -> Result<Vec<u8>> {
        // Per-component structural/codec/signature checks; accepts 1 or 2
        // components (a partial capture still yields a valid single-component
        // archive).
        crate::pioneer_backup::validate_envelope_package(bytes, target_model)?;
        Ok(bytes.to_vec())
    }
    fn capabilities(&self) -> Capabilities {
        // Identity, OEM backup, and a gated live OEM write (via flash_bundle)
        // are implemented; the image-chunk flash_open/chunk/close stay off.
        Capabilities {
            info: true,
            backup: true,
            // Live write is the Normal-only OEM update session executed by
            // `flash_bundle`; still gated by --execute/--i-understand-risk and a
            // mandatory pre-flash backup in the engine.
            flash: true,
            // A per-component capture: if a region read fails, `recover` retries
            // it with a deeper, instability-tolerant read.
            recover: true,
        }
    }
    fn dump_supported(&self) -> bool {
        false
    }
    fn read_dump(&self, _dev: &mut dyn ScsiDevice) -> Result<UserDump> {
        bail!(
            "per-unit region dump is not defined for the {} family; \
             the full-image dump is used instead",
            Family::Pioneer
        )
    }
    fn read_full_image(&self, _dev: &mut dyn ScsiDevice) -> Result<FullImage> {
        bail!("Pioneer has no proven restorable firmware read path")
    }
    fn image_size(&self) -> usize {
        // OEM envelope sizes vary; no restorable image size is established.
        0
    }
    fn chunk_size(&self) -> usize {
        FLASH_CHUNK
    }
    fn envelope(
        &self,
        _dev: &mut dyn ScsiDevice,
        image: &[u8],
        _enc_override: Option<bool>,
    ) -> Result<(Vec<u8>, bool)> {
        // Pioneer .fw.bin is already the on-wire image (the drive decrypts /
        // decompresses the body itself). Pass through.
        Ok((image.to_vec(), false))
    }
    fn flash_plan(&self, image_len: usize, verbose: bool) -> Result<String> {
        use std::fmt::Write;
        let mut plan = format!(
            "UD04 OEM offline transcript: OEM update entry (256 B control), \
             then {} raw-envelope chunks of at most {} B via the OEM Normal transfer, \
             then OEM finish (256 B control) and status polling. \
             Execution is blocked: restorable backup, drive acceptance, and status handling are unverified.\n",
            image_len.div_ceil(FLASH_CHUNK),
            FLASH_CHUNK,
        );
        if verbose {
            writeln!(
                &mut plan,
                "Observed CDB shape (UD04 control payload construction known):"
            )?;
            writeln!(&mut plan, "  entry  {:02X?}", cdb_wb_flash_entry())?;
            for offset in (0..image_len).step_by(FLASH_CHUNK) {
                let len = (image_len - offset).min(FLASH_CHUNK);
                writeln!(
                    &mut plan,
                    "  chunk  {:06X}  {:05X}  {:02X?}",
                    offset,
                    len,
                    cdb_wb_flash_chunk(offset as u32, len as u32)
                )?;
            }
            writeln!(&mut plan, "  finish {:02X?}", cdb_wb_flash_finish())?;
        }
        Ok(plan)
    }
    fn flash_open(&self, _dev: &mut dyn ScsiDevice, _mode: FlashMode) -> Result<()> {
        bail!(
            "Pioneer OEM flash execution is blocked: restorable backup and drive acceptance are unverified"
        )
    }
    fn flash_chunk(&self, _dev: &mut dyn ScsiDevice, _offset: usize, _bytes: &[u8]) -> Result<()> {
        bail!("Pioneer OEM flash execution is blocked: flash_open cannot safely complete")
    }
    fn flash_close(&self, _dev: &mut dyn ScsiDevice, _mode: FlashMode) -> Result<()> {
        bail!(
            "Pioneer OEM flash execution is blocked: restorable backup and status rules are unverified"
        )
    }
    fn readback(&self, _dev: &mut dyn ScsiDevice, _offset: usize, _len: usize) -> Result<Vec<u8>> {
        bail!("Pioneer has no proven persistent firmware readback path")
    }
    fn restore_regions<'a>(&self, _dump: &'a UserDump) -> Vec<RestoreRegion<'a>> {
        Vec::new()
    }
    fn write_region(&self, _dev: &mut dyn ScsiDevice, _offset: u32, _bytes: &[u8]) -> Result<()> {
        bail!(
            "Pioneer flash goes through flash_open + flash_chunk + flash_close; \
             write_region (per-unit MTK layout) is not defined here"
        )
    }
}

#[cfg(test)]
#[path = "pioneer_tests.rs"]
mod tests;
