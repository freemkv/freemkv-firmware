//! Pioneer OEM update protocol — offline flash planning, live writes gated.
//!
//! The Pioneer OEM updater supplies the host command sequence. A Renesas
//! controller identity alone does not prove this protocol applies. Live flash
//! execution is currently blocked.
//!
//! ## FLASH
//! The UD04 1.11 OEM updater uses 04/FF with a 256-byte entry buffer,
//! 07/F0 with raw envelope chunks, and 05/FF with a 256-byte final buffer.
//! The UD04 host control buffers are reconstructed, but drive acceptance,
//! a restorable backup, and completion status remain unproven, so
//! live flashing fails closed before issuing any write.
//!
//! ## Kernel-key table
//! Kept intentionally minimal ([`KEYS`]). Grows deliberately per validated
//! model — new entries land here only after a flash-mode entry has been
//! empirically confirmed on that model.

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use std::borrow::Cow;

use super::mtk::cdb_write_buffer;
use super::{DriveFamily, Family, FullImage, Identity, RestoreRegion, UserDump};
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

pub(crate) const ENTRY_MODE: u8 = 0x04;
pub(crate) const FINISH_MODE: u8 = 0x05;
pub(crate) const CONTROL_BUFFER_ID: u8 = 0xFF;
pub(crate) const TRANSFER_MODE: u8 = 0x07;
pub(crate) const NORMAL_BUFFER_ID: u8 = 0xF0;
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
    cdb_write_buffer(ENTRY_MODE, CONTROL_BUFFER_ID, 0, CONTROL_LEN as u32)
}

/// OEM raw Normal-envelope transfer CDB. `len` excludes any control prefix.
pub fn cdb_wb_flash_chunk(off: u32, len: u32) -> [u8; 10] {
    cdb_write_buffer(TRANSFER_MODE, NORMAL_BUFFER_ID, off, len)
}

/// OEM after-transfer CDB; this is not a zero-length commit.
pub fn cdb_wb_flash_finish() -> [u8; 10] {
    cdb_write_buffer(FINISH_MODE, CONTROL_BUFFER_ID, 0, CONTROL_LEN as u32)
}

/// Construct the 256-byte entry/finish data-out used by the UD04 1.11 OEM
/// updater. The shared buffer is zero-initialized; each command copies the
/// 16-byte descriptor and four little-endian key bytes over that zero tail.
/// This is an offline reference, not a drive-acceptance claim.
pub fn ud04_oem_control_payload() -> [u8; CONTROL_LEN] {
    let mut payload = [0u8; CONTROL_LEN];
    payload[..16].copy_from_slice(b"PIONEER BDR-US04");
    payload[16..20].copy_from_slice(&0xFD23_6642u32.to_le_bytes());
    payload
}

/// BDR-S09 1.30EU control payload. The updater's control descriptor is
/// `PIONEER  BDR-209`; the resource banner and target product are BDR-S09.
/// Those strings serve different fields and are not interchangeable aliases.
pub fn s09_v130_oem_control_payload() -> [u8; CONTROL_LEN] {
    let mut payload = [0u8; CONTROL_LEN];
    payload[..16].copy_from_slice(b"PIONEER  BDR-209");
    payload[16..20].copy_from_slice(&0xCE1F_2B98u32.to_le_bytes());
    payload
}

/// Supplied third-party Autoflasher GUI's selected UD04 control payload.
/// The GUI passes arg5=1 at 0x401F52 into 0x41425C. Entry/finish helpers
/// bypass the model-key dispatcher for that flag and serialize 0x6123789A
/// little-endian. This is not the OEM UD04 model-specific control word,
/// nor evidence of a downgrade-enable effect in the receiver.
pub fn ud04_autoflasher_control_payload() -> [u8; CONTROL_LEN] {
    let mut payload = [0u8; CONTROL_LEN];
    payload[..16].copy_from_slice(b"PIONEER BDR-US04");
    payload[16..20].copy_from_slice(&0x6123_789Au32.to_le_bytes());
    payload
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

/// Choose a registered host strategy using only live drive identity and the
/// supplied envelope. No updater package or sidecar is a runtime input.
/// Unknown and ambiguous structures fail closed; exact OEM hashes only
/// upgrade evidence status, not command selection.
pub fn select_oem_profile(drive_product: &str, envelope: &[u8]) -> Result<OemUpdateProfile> {
    let banner =
        parse_banner(envelope).ok_or_else(|| anyhow!("invalid Pioneer envelope banner"))?;
    if !(IMAGE_MIN..=IMAGE_MAX).contains(&envelope.len()) || !envelope.len().is_multiple_of(0x100) {
        bail!("Pioneer envelope length is outside the supported profile range or not 256-byte aligned");
    }
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
    let control = match profile {
        OemUpdateProfile::Ud04V111Normal
            if banner.model.eq_ignore_ascii_case("BDR-UD04")
                && banner.file_type.eq_ignore_ascii_case("Normal") =>
        {
            ud04_oem_control_payload()
        }
        OemUpdateProfile::Ud04V111Normal => {
            bail!("UD04 1.11 OEM transcript requires a BDR-UD04 Normal envelope")
        }
        OemUpdateProfile::S09V130Normal
            if banner.model.eq_ignore_ascii_case("BDR-S09")
                && banner.revision == "1.30"
                && banner.hardware.eq_ignore_ascii_case("SAT 8600")
                && banner.destination.eq_ignore_ascii_case("ID43")
                && banner.file_type.eq_ignore_ascii_case("Normal") =>
        {
            s09_v130_oem_control_payload()
        }
        OemUpdateProfile::S09V130Normal => {
            bail!("S09 1.30 OEM transcript requires a BDR-S09 1.30 SAT 8600 ID43 Normal envelope")
        }
    };
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

/// Data-out portion of the supplied UD03/UD04 Autoflasher's main update
/// branch, for the exact two resources supplied with that program. Its x86
/// transfer loop sends Kernel on 07/FE in 0x8000-byte chunks and Normal on
/// 07/F0. This omits setup, the alternate entry-state branch, status and
/// completion handling; it performs no device I/O.
pub fn offline_ud04_autoflasher_data_out<'a>(
    kernel: &'a [u8],
    normal: &'a [u8],
) -> Result<Vec<OemTransfer<'a>>> {
    const KERNEL_SHA256: &str = "36996326ae5eaa369ef34a8434514ca137b31a3f144af0955c2d12f4a8b2ea83";
    const NORMAL_SHA256: &str = "8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141";
    if kernel.len() != 0x11200
        || format!("{:x}", Sha256::digest(kernel)) != KERNEL_SHA256
        || normal.len() != 0x1d7700
        || format!("{:x}", Sha256::digest(normal)) != NORMAL_SHA256
    {
        bail!("resources do not match the supplied UD04 Autoflasher package");
    }
    for (role, image) in [("Kernel", kernel), ("Normal", normal)] {
        let banner = parse_banner(image).ok_or_else(|| anyhow!("{role} banner missing"))?;
        if !banner.model.eq_ignore_ascii_case("BDR-UD04")
            || !banner.hardware.eq_ignore_ascii_case("SAT 8A10")
            || !banner.destination.eq_ignore_ascii_case("GENERAL")
            || !banner.file_type.eq_ignore_ascii_case(role)
        {
            bail!("{role} banner does not match the supplied UD04 resources");
        }
    }
    let control = ud04_autoflasher_control_payload();
    transfer::data_out(
        &control,
        normal,
        Some(transfer::KernelTransfer::LinearFe(kernel)),
    )
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

/// Run every hard-refuse check before any 3B 04 FF write hits the wire.
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

// ---- The Pioneer DriveFamily impl ------------------------------------------

/// Pioneer OEM protocol backend: identity and offline planning are available;
/// backup and live writes remain gated on restorable-backup evidence.
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
        Ok((identity.vendor.eq_ignore_ascii_case("PIONEER")
            && identity.product.starts_with("BDR-")
            && super::read_buffer_f1_ok(dev))
        .then_some(super::ProbeEvidence {
            family: Family::Pioneer,
            backend_name: self.backend_name(),
            discriminator: "PIONEER BDR INQUIRY + READ BUFFER F1",
        }))
    }
    fn offline_plan(&self, req: &super::FlashRequest) -> Option<Result<()>> {
        Some(crate::engine::plan_pioneer_offline(
            &req.input,
            req.input_kind,
            &req.drive_model,
            req.allow_crossflash,
            req.verbose,
            req.execute,
            self,
        ))
    }
    fn family(&self) -> Family {
        Family::Pioneer
    }
    fn backup_extension(&self) -> Option<&'static str> {
        Some("tar")
    }
    fn validate_backup_template(&self, template: Option<&[u8]>) -> Result<()> {
        let template = template.ok_or_else(|| {
            anyhow::anyhow!("Pioneer encrypted backup requires a matching signed OEM template")
        })?;
        crate::pioneer_backup::validate_template(template)
    }
    fn capture_backup_with_template(
        &self,
        dev: &mut dyn ScsiDevice,
        template: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let template = template.ok_or_else(|| {
            anyhow::anyhow!("Pioneer encrypted backup requires a matching signed OEM template")
        })?;
        crate::pioneer_backup::capture_reference_backup(dev, template)
    }
    fn validate_backup(&self, bytes: &[u8], target_model: &str) -> Result<Vec<u8>> {
        crate::pioneer_backup::validate_reference_backup(bytes, target_model)
    }
    fn is_supported(&self) -> bool {
        false
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
            "UD04 OEM offline transcript: 3B 04 FF entry (256 B control), \
             then {} raw-envelope chunks of at most {} B via 3B 07 F0, \
             then 3B 05 FF finish (256 B control) and status polling. \
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
