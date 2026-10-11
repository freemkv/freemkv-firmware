//! MediaTek MT1959 / MT1939 drive family — the only fully-implemented family.
//!
//! One file, all MTK commands: identity/dump reads, the WRITE BUFFER flash
//! sequence, the enc transport envelope, and the per-unit tar model. The generic
//! orchestration that drives these lives in [`crate::engine`]; this module is
//! pure chip primitives (CDBs + framing), no file I/O and no printing.
//!
//! ## flash is a DUMB verbatim writer
//! The flasher writes the given image to the drive **verbatim** and never
//! modifies it: no DE byte, no downgrade magic, no per-unit splice, no CMAC
//! resign — those are *firmware modification* and belong to a separate future
//! tool. flash's whole job is (1) back up, (2) write the bytes, (3) verify.
//!
//! ## enc transport envelope
//! [`enc_needed`] decides on every flash whether the drive needs the AES-128-ECB
//! `enc` envelope (a known-open question); it currently defaults to plaintext.
//! `--enc`/`--no-enc` are a hidden expert override. When enc is active the whole
//! image is [`enc_transform`]ed before streaming.
//!
//! ## the flash sequence
//! A 2 MiB image is programmed over a fixed ordered sequence of 12-byte SCSI
//! CDBs: PROBE (READ BUFFER) → READY (TEST UNIT READY) → PREPARE (WRITE BUFFER
//! mode 1) → 128× STREAM (WRITE BUFFER mode 6, 16 KiB) → COMMIT (WRITE BUFFER
//! mode 7) → READY → STATUS (REQUEST SENSE). The drive erases+programs flash
//! when the 2 MiB upload completes (the last STREAM chunk) — COMMIT is a
//! trailing handshake, not the burn.
//!
//! ## `--mode` is currently informational on MTK
//! [`FlashMode`] (main vs. full) does not change MTK behavior: the full 2 MiB
//! image is always streamed and the commit handshake is always sent
//! regardless of the selected mode — the drive programs on completion either
//! way.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};

pub(crate) mod backup;
pub(crate) mod crossflash;
pub(crate) mod file_info;
pub mod oem;

use super::{Capabilities, DriveFamily, Family};
use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;

// ---- Region geometry and wire constants (from `mediatek_optical`) -----------

pub use mediatek_optical::cdb;
use mediatek_optical::layout;

/// Boot banner / metadata region offset.
pub const ROM_003000_OFFSET: u32 = layout::BANNER.start as u32;
/// Boot banner / metadata region length.
pub const ROM_003000_LEN: u32 = layout::BANNER.len as u32;
/// Identity-page region offset.
pub const ROM_1EC000_OFFSET: u32 = layout::DESCRIPTOR.start as u32;
/// Identity-page region length (256 B).
pub const ROM_1EC000_LEN: u32 = layout::DESCRIPTOR.len as u32;
/// Per-unit calibration region offset.
pub const ROM_1F0000_OFFSET: u32 = layout::CALIBRATION.start as u32;
/// Per-unit calibration region length (64 KiB).
pub const ROM_1F0000_LEN: u32 = layout::CALIBRATION.len as u32;

/// Per-member cap for [`UserDump::read_tar`] — hard ceiling on how many bytes
/// a single tar entry may carry before we refuse. The largest legitimate
/// member is `rom_1F0000.bin` at 64 KiB; the cap sits well above that so
/// firmware/ROM regions never bump against it, but low enough that a hostile
/// tar cannot force a large allocation before the per-member length gate in
/// `UserDump::from_members` runs.
pub const READ_TAR_MEMBER_CAP: usize = 256 * 1024;
/// INQUIRY allocation length used by the identity flow.
pub const INQUIRY_LEN: u16 = cdb::INQUIRY_ALLOC;
/// Initial GET CONFIGURATION allocation length for the fd_* field descriptors.
pub const FD_LEN: u16 = 28;
/// GET CONFIGURATION feature code carrying the ASCII serial number (fd_sn.bin).
pub const FEATURE_SERIAL: u16 = cdb::FEATURE_SERIAL;
/// GET CONFIGURATION feature code carrying the ASCII firmware date (fd_fwdate.bin).
pub const FEATURE_FWDATE: u16 = cdb::FEATURE_FIRMWARE_DATE;
/// Expected full firmware image size (2 MiB).
pub const IMAGE_SIZE: usize = layout::IMAGE_SIZE;
/// Streaming chunk size for the flash sequence, 16 KiB.
pub const CHUNK: usize = cdb::CHUNK;

/// Ordered tar member names for a per-unit dump.
pub const MEMBER_NAMES: [&str; 6] = [
    "rom_003000.bin",
    "rom_1EC000.bin",
    "rom_1F0000.bin",
    "inq.bin",
    "fd_fwdate.bin",
    "fd_sn.bin",
];

/// AES-128-ECB encrypt the whole image in place (the `enc` transport envelope).
pub fn enc_transform(image: &mut [u8]) -> Result<()> {
    mediatek_optical::enc::encrypt(image).map_err(|e| anyhow!(e))
}

/// Select the format for the implemented MTK update route.
///
/// This route sends a validated plaintext image. There is no general-purpose
/// encryption probe here; a different controller's protocol must provide its
/// own transport policy rather than asking the user to guess.
pub fn enc_needed(_dev: &mut dyn ScsiDevice) -> bool {
    false
}

// ---- Dump plan --------------------------------------------------------------

/// How a single dump member is acquired from the drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acquire {
    /// READ BUFFER mode 6 at `offset` for `len` bytes.
    ReadBuffer {
        /// Register offset.
        offset: u32,
        /// Byte count.
        len: u32,
    },
    /// Standard INQUIRY for `alloc` bytes.
    Inquiry {
        /// Allocation length.
        alloc: u16,
    },
    /// GET CONFIGURATION single-feature descriptor for `alloc` bytes.
    GetConfig {
        /// Feature code.
        feature: u16,
        /// Allocation length.
        alloc: u16,
    },
}

impl Acquire {
    /// Issue this acquisition against a device and return the raw bytes.
    pub fn run(&self, dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
        match *self {
            Acquire::ReadBuffer { offset, len } => {
                let cdb = cdb::read_memory(offset, len);
                let data = dev.command_in(&cdb, len as usize)?;
                // A per-unit ROM region is a fixed size; a short transfer means
                // an incomplete read. Refuse it rather than silently writing a
                // truncated region into a backup the operator will trust.
                if data.len() != len as usize {
                    bail!(
                        "short read of ROM region at 0x{offset:06X}: got {} of {} bytes",
                        data.len(),
                        len
                    );
                }
                Ok(data)
            }
            Acquire::Inquiry { alloc } => {
                let cdb = cdb::inquiry(alloc);
                let mut data = dev.command_in(&cdb, alloc as usize)?;
                log_inquiry(&data, Some(alloc as usize));
                if data.len() >= 5 {
                    let needed = 5 + usize::from(data[4]);
                    if needed > alloc as usize {
                        data = dev.command_in(&cdb::inquiry(needed as u16), needed)?;
                        log_inquiry(&data, Some(needed));
                    }
                }
                validate_inquiry(&data)?;
                Ok(data)
            }
            Acquire::GetConfig { feature, alloc } => {
                let cdb = cdb::get_configuration(feature, alloc);
                let mut data = dev.command_in(&cdb, alloc as usize)?;
                log_field_descriptor(feature, &data, Some(alloc as usize));
                if data.len() >= 12 {
                    let needed = 12 + usize::from(data[11]);
                    if needed > alloc as usize {
                        crate::diagnostics::record(format!("MediaTek feature 0x{feature:04X}: header requires {needed} bytes; expanding allocation from {alloc}"));
                        let cdb = cdb::get_configuration(feature, needed as u16);
                        data = dev.command_in(&cdb, needed)?;
                        log_field_descriptor(feature, &data, Some(needed));
                    }
                }
                validate_field_descriptor(&data, feature)?;
                Ok(data)
            }
        }
    }
}

/// One planned dump member: its tar name and how it is read.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    /// tar member name.
    pub name: &'static str,
    /// Acquisition command.
    pub acquire: Acquire,
}

/// The ordered plan of six regions captured by a per-unit dump.
#[derive(Debug, Clone)]
pub struct DumpPlan {
    /// The six regions, in tar order.
    pub regions: Vec<Region>,
}

impl Default for DumpPlan {
    fn default() -> Self {
        Self::new()
    }
}

impl DumpPlan {
    /// The canonical per-unit dump plan (six regions, in tar order).
    pub fn new() -> Self {
        Self {
            regions: vec![
                Region {
                    name: "rom_003000.bin",
                    acquire: Acquire::ReadBuffer {
                        offset: ROM_003000_OFFSET,
                        len: ROM_003000_LEN,
                    },
                },
                Region {
                    name: "rom_1EC000.bin",
                    acquire: Acquire::ReadBuffer {
                        offset: ROM_1EC000_OFFSET,
                        len: ROM_1EC000_LEN,
                    },
                },
                Region {
                    name: "rom_1F0000.bin",
                    acquire: Acquire::ReadBuffer {
                        offset: ROM_1F0000_OFFSET,
                        len: ROM_1F0000_LEN,
                    },
                },
                Region {
                    name: "inq.bin",
                    acquire: Acquire::Inquiry { alloc: INQUIRY_LEN },
                },
                Region {
                    name: "fd_fwdate.bin",
                    acquire: Acquire::GetConfig {
                        feature: FEATURE_FWDATE,
                        alloc: FD_LEN,
                    },
                },
                Region {
                    name: "fd_sn.bin",
                    acquire: Acquire::GetConfig {
                        feature: FEATURE_SERIAL,
                        alloc: FD_LEN,
                    },
                },
            ],
        }
    }

    /// Execute every region read against a live device, returning a [`UserDump`].
    pub fn execute(&self, dev: &mut dyn ScsiDevice) -> Result<UserDump> {
        let mut members = Vec::with_capacity(self.regions.len());
        for region in &self.regions {
            let data = region
                .acquire
                .run(dev)
                .with_context(|| format!("reading dump region {}", region.name))?;
            members.push((region.name, data));
        }
        UserDump::from_members(members)
    }
}

// ---- UserDump ---------------------------------------------------------------

/// The six per-unit regions captured by a dump, in tar order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDump {
    /// Boot banner / metadata (offset 0x003000, 32 B).
    pub rom_003000: Vec<u8>,
    /// Identity page (offset 0x1EC000, 256 B).
    pub rom_1ec000: Vec<u8>,
    /// Per-unit calibration NVRAM (offset 0x1F0000, 64 KiB).
    pub rom_1f0000: Vec<u8>,
    /// Complete standard INQUIRY response (variable length).
    pub inq: Vec<u8>,
    /// Complete fw-date GET CONFIG feature descriptor (variable length).
    pub fd_fwdate: Vec<u8>,
    /// Complete serial-number GET CONFIG feature descriptor (variable length).
    pub fd_sn: Vec<u8>,
}

impl UserDump {
    /// Build a [`UserDump`] from `(name, data)` members in any order.
    ///
    /// ROM members must match their fixed on-drive sizes to prevent restore
    /// overruns. INQUIRY and GET CONFIGURATION metadata use declared lengths;
    /// their headers must describe complete, bounded replies.
    pub fn from_members(members: Vec<(&str, Vec<u8>)>) -> Result<Self> {
        let mut rom_003000 = None;
        let mut rom_1ec000 = None;
        let mut rom_1f0000 = None;
        let mut inq = None;
        let mut fd_fwdate = None;
        let mut fd_sn = None;
        for (name, data) in members {
            let slot = match name {
                "rom_003000.bin" => &mut rom_003000,
                "rom_1EC000.bin" => &mut rom_1ec000,
                "rom_1F0000.bin" => &mut rom_1f0000,
                "inq.bin" => &mut inq,
                "fd_fwdate.bin" => &mut fd_fwdate,
                "fd_sn.bin" => &mut fd_sn,
                other => bail!("unexpected dump member '{}'", super::sanitize_ascii(other)),
            };
            if slot.is_some() {
                bail!("duplicate dump member '{name}'");
            }
            *slot = Some(data);
        }
        // Load slots, then per-member size gate — reject any tar whose member
        // length doesn't match the fixed on-drive region size.
        let check_len = |slot: Option<Vec<u8>>, name: &str, want: usize| -> Result<Vec<u8>> {
            let data = slot.ok_or_else(|| anyhow!("missing dump member '{name}'"))?;
            if data.len() != want {
                bail!(
                    "dump member '{name}' has length {} — expected exactly {want} bytes; \
                     invalid backup member",
                    data.len()
                );
            }
            Ok(data)
        };
        let check_descriptor = |slot: Option<Vec<u8>>, name: &str, feature| -> Result<Vec<u8>> {
            let data = slot.ok_or_else(|| anyhow!("missing dump member '{name}'"))?;
            validate_field_descriptor(&data, feature)
                .with_context(|| format!("invalid dump member '{name}'"))?;
            Ok(data)
        };
        Ok(Self {
            rom_003000: check_len(rom_003000, "rom_003000.bin", ROM_003000_LEN as usize)?,
            rom_1ec000: check_len(rom_1ec000, "rom_1EC000.bin", ROM_1EC000_LEN as usize)?,
            rom_1f0000: check_len(rom_1f0000, "rom_1F0000.bin", ROM_1F0000_LEN as usize)?,
            inq: {
                let data = inq.ok_or_else(|| anyhow!("missing dump member 'inq.bin'"))?;
                validate_inquiry(&data).context("invalid dump member 'inq.bin'")?;
                data
            },
            fd_fwdate: check_descriptor(fd_fwdate, "fd_fwdate.bin", FEATURE_FWDATE)?,
            fd_sn: check_descriptor(fd_sn, "fd_sn.bin", FEATURE_SERIAL)?,
        })
    }

    /// The six members as `(name, bytes)` pairs, in canonical tar order.
    pub fn members(&self) -> [(&'static str, &[u8]); 6] {
        [
            ("rom_003000.bin", &self.rom_003000),
            ("rom_1EC000.bin", &self.rom_1ec000),
            ("rom_1F0000.bin", &self.rom_1f0000),
            ("inq.bin", &self.inq),
            ("fd_fwdate.bin", &self.fd_fwdate),
            ("fd_sn.bin", &self.fd_sn),
        ]
    }

    /// Decoded serial number, if the descriptor parses. Sanitized for display
    /// (a malicious/garbled drive cannot inject terminal escapes).
    pub fn serial(&self) -> Option<String> {
        parse_field_descriptor(&self.fd_sn).map(|d| super::sanitize_ascii(&d.ascii))
    }

    /// Decoded firmware date, if the descriptor parses.
    pub fn fw_date(&self) -> Option<String> {
        parse_field_descriptor(&self.fd_fwdate).map(|d| super::sanitize_ascii(&d.ascii))
    }

    /// Write the dump as a `.tar` with compatible member names/order.
    pub fn write_tar<W: Write>(&self, w: W) -> Result<()> {
        let mut builder = tar::Builder::new(w);
        for (name, data) in self.members() {
            let mut header = tar::Header::new_gnu();
            header.set_path(name)?;
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder.append(&header, data)?;
        }
        builder.into_inner()?.flush()?;
        Ok(())
    }

    /// Serialize the dump to an in-memory `.tar` byte vector.
    pub fn to_tar_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write_tar(&mut buf)?;
        Ok(buf)
    }

    /// Read a dump-style `.tar` back into a [`UserDump`].
    ///
    /// Per-member size is capped BEFORE `read_to_end` — the
    /// `UserDump::from_members` per-member length gate that follows would
    /// reject an oversized member, but only AFTER we'd already allocated the
    /// full attacker-controlled length into memory. Cap the tar-header-
    /// declared size (`entry.size()`) at [`READ_TAR_MEMBER_CAP`] and refuse
    /// early, so a hostile ~16 GiB tar member cannot force a large-buffer
    /// allocation just to be told "wrong size" by `from_members`.
    pub fn read_tar<R: Read>(r: R) -> Result<Self> {
        let mut archive = tar::Archive::new(r);
        let mut members = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let name = entry
                .path()?
                .to_str()
                .context("non-UTF8 tar member name")?
                .to_string();
            // Header-declared size — early refusal against oversized inputs.
            let declared = entry.size();
            if declared > READ_TAR_MEMBER_CAP as u64 {
                bail!(
                    "tar member '{}' declares {declared} bytes (> {READ_TAR_MEMBER_CAP} cap); \
                     refusing to allocate a buffer this large before the length gate runs",
                    super::sanitize_ascii(&name)
                );
            }
            // Read into a capacity-hinted buffer; `take` bounds the actual
            // bytes read too, so a mismatched header (declared < actual)
            // still can't blow past the cap.
            let mut data = Vec::with_capacity(declared as usize);
            entry
                .by_ref()
                .take(READ_TAR_MEMBER_CAP as u64 + 1)
                .read_to_end(&mut data)?;
            if data.len() > READ_TAR_MEMBER_CAP {
                bail!(
                    "tar member '{}' body exceeded the {READ_TAR_MEMBER_CAP}-byte cap",
                    super::sanitize_ascii(&name)
                );
            }
            let canonical = MEMBER_NAMES
                .iter()
                .copied()
                .find(|m| *m == name)
                .with_context(|| {
                    format!("unexpected dump member '{}'", super::sanitize_ascii(&name))
                })?;
            members.push((canonical, data));
        }
        Self::from_members(members)
    }

    /// Parse a dump-style `.tar` from bytes.
    pub fn from_tar_bytes(bytes: &[u8]) -> Result<Self> {
        Self::read_tar(bytes)
    }
}

// ---- Field descriptor parsing -----------------------------------------------

/// A decoded GET CONFIGURATION field descriptor (fd_sn / fd_fwdate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptor {
    /// Feature code (0x0108 = serial, 0x010C = fw date).
    pub feature: u16,
    /// Additional-length byte from the descriptor header.
    pub add_len: u8,
    /// Trimmed ASCII payload (serial number or firmware date).
    pub ascii: String,
}

/// Parse a REQUEST SENSE payload into `(sense_key, asc, ascq)`.
pub fn parse_sense(data: &[u8]) -> Option<(u8, u8, u8)> {
    mediatek_optical::sense::parse(data)
}

/// MEDIUM (0x3), HARDWARE (0x4) and ABORTED (0xB): the sense keys that prove a
/// programming failure on the MTK flash path.
pub fn sense_key_is_fatal(key: u8) -> bool {
    mediatek_optical::sense::is_flash_fault(key)
}

// INQUIRY's additional length counts bytes after its five-byte header.
// Preserve full replies (including any transport padding), never synthesize bytes.
fn validate_inquiry(data: &[u8]) -> Result<()> {
    log_inquiry(data, None);
    let result = check_inquiry(data);
    log_metadata_verdict("INQUIRY", &result);
    result
}

fn check_inquiry(data: &[u8]) -> Result<()> {
    if !(36..=260).contains(&data.len()) {
        bail!("INQUIRY: expected 36..=260 bytes, got {}", data.len());
    }
    let declared = 5 + usize::from(data[4]);
    if declared < 36 || declared > data.len() {
        bail!(
            "INQUIRY: expected complete identity of {declared} declared bytes, got {}",
            data.len()
        );
    }
    Ok(())
}

fn log_inquiry(data: &[u8], allocation: Option<usize>) {
    crate::diagnostics::record(format!(
        "MediaTek INQUIRY metadata: allocation={allocation:?} returned={} declared_total={:?} raw_prefix={:02x?} omitted_bytes={}",
        data.len(), data.get(4).map(|n| 5 + usize::from(*n)),
        &data[..data.len().min(512)], data.len().saturating_sub(512)
    ));
}

fn log_metadata_verdict(kind: &str, result: &Result<()>) {
    let verdict = match result {
        Ok(()) => "accepted: complete response".to_owned(),
        Err(error) => format!("rejected: {error:#}"),
    };
    crate::diagnostics::record(format!("MediaTek {kind} metadata validation: {verdict}"));
}

// GET CONFIGURATION has an eight-byte response header followed by a four-byte
// feature header and up to 255 additional bytes. Allocation is a ceiling, not
// a required response size. These metadata bytes are never written to ROM.
fn validate_field_descriptor(data: &[u8], expected: u16) -> Result<()> {
    log_field_descriptor(expected, data, None);
    let result = check_field_descriptor(data, expected);
    log_metadata_verdict(&format!("feature 0x{expected:04X}"), &result);
    result
}

fn check_field_descriptor(data: &[u8], expected: u16) -> Result<()> {
    if !(12..=267).contains(&data.len()) {
        bail!(
            "feature 0x{expected:04X}: expected 12..=267 response bytes, got {}",
            data.len()
        );
    }
    let feature = u16::from_be_bytes([data[8], data[9]]);
    if feature != expected {
        bail!("expected feature 0x{expected:04X}, got 0x{feature:04X}");
    }
    let needed = 12 + usize::from(data[11]);
    let declared = u64::from(u32::from_be_bytes(data[..4].try_into().unwrap())) + 4;
    if declared != needed as u64 {
        bail!("feature 0x{expected:04X}: inconsistent headers: expected {needed} total bytes from feature length, response declares {declared}");
    }
    if data.len() < needed {
        bail!("feature 0x{expected:04X}: incomplete response: expected {needed} declared bytes, got {}", data.len());
    }
    if expected == FEATURE_SERIAL {
        let serial = &data[12..needed];
        if serial.is_empty() || !serial.len().is_multiple_of(4) {
            bail!("feature 0x{expected:04X}: expected a nonempty serial field padded to a multiple of four bytes");
        }
        if !serial.iter().all(|b| (0x20..=0x7e).contains(b)) {
            bail!(
                "feature 0x{expected:04X}: expected ASCII graphic serial bytes with space padding"
            );
        }
    }
    Ok(())
}

fn log_field_descriptor(feature: u16, data: &[u8], allocation: Option<usize>) {
    let response_total = data
        .get(..4)
        .map(|bytes| u64::from(u32::from_be_bytes(bytes.try_into().unwrap())) + 4);
    let returned_feature = data
        .get(8..10)
        .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()));
    let additional_length = data.get(11).copied();
    let feature_total = additional_length.map(|n| 12 + usize::from(n));
    crate::diagnostics::record(format!(
        "MediaTek GET CONFIGURATION metadata: requested_feature=0x{feature:04X} allocation={allocation:?} returned={} returned_feature={returned_feature:?} response_declared_total={response_total:?} additional_length={additional_length:?} feature_declared_total={feature_total:?} raw_prefix={:02x?} omitted_bytes={}",
        data.len(), &data[..data.len().min(512)], data.len().saturating_sub(512)
    ));
}

/// Parse a GET CONFIGURATION single-feature descriptor (fd_sn / fd_fwdate).
pub fn parse_field_descriptor(data: &[u8]) -> Option<FieldDescriptor> {
    if data.len() < 12 {
        return None;
    }
    let feature = u16::from_be_bytes([data[8], data[9]]);
    let add_len = data[11];
    let end = 12 + add_len as usize;
    if end > data.len() {
        return None;
    }
    let ascii = String::from_utf8_lossy(&data[12..end])
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string();
    Some(FieldDescriptor {
        feature,
        add_len,
        ascii,
    })
}

// ---- Flash sequence plan (dry-run renderer) ---------------------------------

/// Data-phase direction of a planned flash step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    In,
    Out,
    None,
}

impl Dir {
    fn token(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
            Dir::None => "---",
        }
    }
}

const LABEL_PROBE: &str = "PROBE";
const LABEL_READY: &str = "READY";
const LABEL_PREPARE: &str = "PREPARE";
const LABEL_STREAM: &str = "STREAM";
const LABEL_COMMIT: &str = "COMMIT";
const LABEL_STATUS: &str = "STATUS";

/// One planned step of the flash sequence.
#[derive(Debug, Clone, Copy)]
struct FlashStep {
    label: &'static str,
    cdb: [u8; 12],
    dir: Dir,
    data_len: usize,
}

impl FlashStep {
    fn stream_offset(&self) -> u32 {
        ((self.cdb[3] as u32) << 16) | ((self.cdb[4] as u32) << 8) | (self.cdb[5] as u32)
    }

    fn render(&self) -> String {
        let hex = self
            .cdb
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let detail = match self.dir {
            Dir::In => format!("alloc={}", self.data_len),
            Dir::Out if self.label == LABEL_STREAM => {
                format!("data={} @0x{:06X}", self.data_len, self.stream_offset())
            }
            Dir::Out => format!("data={}", self.data_len),
            Dir::None => String::new(),
        };
        format!(
            "{:<8}{:<3}  {}   {}",
            self.label,
            self.dir.token(),
            hex,
            detail
        )
        .trim_end()
        .to_string()
    }
}

/// Assemble the full ordered flash plan for an `image_len`-byte image streamed
/// in `chunk`-byte writes.
fn flash_sequence(image_len: usize, chunk: usize) -> Result<Vec<FlashStep>> {
    if image_len != IMAGE_SIZE {
        bail!(
            "flash sequence is defined only for a {IMAGE_SIZE}-byte (2 MiB) image, got {image_len}"
        );
    }
    if chunk == 0 || chunk > 0xFFFF || !image_len.is_multiple_of(chunk) {
        bail!("chunk {chunk} does not evenly divide the {image_len}-byte image (and must fit u16)");
    }
    let mut steps = Vec::with_capacity(image_len / chunk + 6);
    steps.push(FlashStep {
        label: LABEL_PROBE,
        cdb: cdb::probe(),
        dir: Dir::In,
        data_len: cdb::PROBE_LEN,
    });
    steps.push(FlashStep {
        label: LABEL_READY,
        cdb: cdb::test_unit_ready(),
        dir: Dir::None,
        data_len: 0,
    });
    steps.push(FlashStep {
        label: LABEL_PREPARE,
        cdb: cdb::enter_update(),
        dir: Dir::Out,
        data_len: 0,
    });
    let mut offset = 0usize;
    while offset < image_len {
        steps.push(FlashStep {
            label: LABEL_STREAM,
            cdb: cdb::transfer(offset as u32, chunk as u16),
            dir: Dir::Out,
            data_len: chunk,
        });
        offset += chunk;
    }
    steps.push(FlashStep {
        label: LABEL_COMMIT,
        cdb: cdb::finish(),
        dir: Dir::Out,
        data_len: 0,
    });
    steps.push(FlashStep {
        label: LABEL_READY,
        cdb: cdb::test_unit_ready(),
        dir: Dir::None,
        data_len: 0,
    });
    steps.push(FlashStep {
        label: LABEL_STATUS,
        cdb: cdb::request_sense(),
        dir: Dir::In,
        data_len: cdb::REQUEST_SENSE_LEN,
    });
    Ok(steps)
}

/// Render the flash sequence for human review (the dry-run output).
fn describe_sequence(steps: &[FlashStep], verbose: bool) -> String {
    use crate::style::human_size;
    use std::fmt::Write as _;

    let stream_total: usize = steps
        .iter()
        .filter(|s| s.label == LABEL_STREAM)
        .map(|s| s.data_len)
        .sum();
    let chunk = steps
        .iter()
        .find(|s| s.label == LABEL_STREAM)
        .map(|s| s.data_len)
        .unwrap_or(0);
    let count = steps.iter().filter(|s| s.label == LABEL_STREAM).count();

    // Clean, human-readable plan by default — no CDB hex.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "upload:    {} streamed verbatim as {} x {} chunks, then commit + verify",
        human_size(stream_total),
        count,
        human_size(chunk)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "  ** POINT OF NO RETURN **");
    let _ = writeln!(
        out,
        "  The drive erases and reprograms its flash the instant the full {} upload",
        human_size(stream_total)
    );
    let _ = writeln!(out, "  lands. This cannot be undone.");

    // Raw SCSI CDBs only when explicitly asked (-v/--verbose).
    if verbose {
        let _ = writeln!(out);
        let _ = writeln!(out, "raw SCSI sequence ({} steps):", steps.len());
        let mut i = 0usize;
        while i < steps.len() {
            if steps[i].label == LABEL_STREAM {
                let start = i;
                let mut j = i;
                while j < steps.len() && steps[j].label == LABEL_STREAM {
                    j += 1;
                }
                let cnt = j - start;
                let _ = writeln!(out, "  #{:02} {}", start + 1, steps[start].render());
                if cnt > 2 {
                    let _ = writeln!(
                        out,
                        "      ... {} identical STREAM chunks collapsed ({} total) ...",
                        cnt,
                        human_size(stream_total)
                    );
                }
                if cnt >= 2 {
                    let _ = writeln!(out, "  #{:02} {}", j, steps[j - 1].render());
                }
                i = j;
            } else {
                let _ = writeln!(out, "  #{:02} {}", i + 1, steps[i].render());
                i += 1;
            }
        }
    }
    out
}

// ---- Protocol probe ----------------------------------------------------------

/// Read the MT19xx boot banner, or `None` when the drive refuses the read.
pub(crate) fn read_mt19_banner(dev: &mut dyn ScsiDevice) -> Option<String> {
    // The 0x3000 ROM buffer is exactly ROM_003000_LEN (32 B); asking for more
    // makes the drive reject the read with ILLEGAL REQUEST.
    let data = dev
        .command_in(
            &cdb::read_memory(ROM_003000_OFFSET, ROM_003000_LEN),
            ROM_003000_LEN as usize,
        )
        .ok()?;
    let id = mediatek_optical::Identity::parse(&[0; mediatek_optical::INQUIRY_LEN], &data, &[])?;
    let banner = id.banner().to_owned();
    (!banner.is_empty()).then_some(banner)
}

/// True iff GET CONFIGURATION returns a complete firmware-date feature
/// (0x010C), one half of the MT19xx protocol probe.
pub(crate) fn get_config_is_mtk(dev: &mut dyn ScsiDevice) -> bool {
    match (Acquire::GetConfig {
        feature: FEATURE_FWDATE,
        alloc: 32,
    })
    .run(dev)
    {
        Ok(_) => true,
        Err(error) => {
            crate::diagnostics::record(format!("MediaTek feature probe did not match: {error:#}"));
            false
        }
    }
}

/// True iff the drive's boot banner at `0x003000` carries the ASCII **`MT19`**
/// family signature ("MT1959 Boot ..." / "MT1939 Boot ..."). Backstops the
/// standard MMC feature check so a compliant non-MTK drive that also
/// implements feature 0x010C cannot be misclassified as MTK.
pub(crate) fn has_mt19_banner(dev: &mut dyn ScsiDevice) -> bool {
    let Ok(rom) = dev.command_in(
        &cdb::read_memory(ROM_003000_OFFSET, ROM_003000_LEN),
        ROM_003000_LEN as usize,
    ) else {
        return false;
    };
    rom.len() == ROM_003000_LEN as usize
        && mediatek_optical::Identity::parse(&[0; mediatek_optical::INQUIRY_LEN], &rom, &[])
            .is_some_and(|id| id.is_mt19())
}

/// Read `len` bytes at `offset`, retrying once: the chip gate must not fail
/// open on a transient read error.
fn read_exact_retry(dev: &mut dyn ScsiDevice, offset: u32, len: u32) -> Option<Vec<u8>> {
    (0..2).find_map(|_| {
        dev.command_in(&cdb::read_memory(offset, len), len as usize)
            .ok()
            .filter(|data| data.len() == len as usize)
    })
}

/// The drive's controller generation as `(descriptor tag, boot banner)`. The
/// descriptor's `MTEKMT19xx` tag is authoritative; the banner names the
/// bootloader generation and reads `MT1959 Boot` on some MT1939 parts.
fn read_chip_sources(
    dev: &mut dyn ScsiDevice,
) -> (
    Option<mediatek_optical::Chip>,
    Option<mediatek_optical::Chip>,
) {
    let tag = read_exact_retry(dev, ROM_1EC000_OFFSET, ROM_1EC000_LEN)
        .and_then(|d| mediatek_optical::Chip::from_tag(&d));
    let banner = read_exact_retry(dev, ROM_003000_OFFSET, ROM_003000_LEN)
        .and_then(|b| mediatek_optical::Chip::from_banner(&b));
    (tag, banner)
}

/// The drive's controller generation for display: the descriptor tag, else
/// the boot banner.
pub(crate) fn read_chip(dev: &mut dyn ScsiDevice) -> Option<mediatek_optical::Chip> {
    let (tag, banner) = read_chip_sources(dev);
    tag.or(banner)
}

/// The chip gate (never overridable): the image's chip generation must equal
/// the drive's. The drive's descriptor tag decides. The banner is accepted
/// only for an image that itself carries no identity tag (some MT1939 builds),
/// because a banner can name the wrong generation. Anything unreadable refuses.
fn ensure_same_chip(dev: &mut dyn ScsiDevice, image: &[u8]) -> Result<mediatek_optical::Chip> {
    let info = freemkv_chipset::detect_chip(image)
        .context("identifying the image's controller generation")?;
    let (tag, banner) = read_chip_sources(dev);
    let drive = match (tag, info.confidence) {
        (Some(chip), _) => chip,
        (None, freemkv_chipset::Confidence::BannerFallback) => banner.context(
            "could not read this drive's controller generation (MT1959/MT1939) from its \
             identity descriptor or boot banner; refusing to flash",
        )?,
        (None, freemkv_chipset::Confidence::TagString) => bail!(
            "could not read this drive's identity descriptor to confirm its controller \
             generation (MT1959/MT1939); refusing to flash"
        ),
    };
    if info.family != drive {
        bail!(
            "image is {} firmware but this drive is {drive} silicon — refusing to flash \
             across chip generations. This gate cannot be overridden.",
            info.family
        );
    }
    Ok(drive)
}

/// The boot-page gate. A drive read (boot page equal to the mirror at
/// `0x10000`) is never flashable: writing it would store the read-back page in
/// place of the boot page, which the integrity table does not cover. Without
/// `--force`, the boot page must also be one the OEM catalog knows.
fn ensure_flashable_boot_page(image: &[u8], forced: bool) -> Result<()> {
    if mediatek_optical::image::is_drive_read(image) {
        bail!(
            "this is a raw drive read (its boot page is the read-back copy), not a flashable \
             image — refusing to flash. Restore from a freemkv backup .bin, or the vendor's \
             update image. This gate cannot be overridden."
        );
    }
    let boot = &image[..mediatek_optical::layout::BOOT_PAGE.len];
    if !forced && !oem::catalog().knows_boot_page(boot) {
        bail!(
            "the image's boot page is not one any known OEM build stores — refusing to flash \
             an image whose boot page may not start the drive"
        );
    }
    Ok(())
}

/// After the commit trailer: TEST UNIT READY (best-effort) and REQUEST SENSE.
/// Hard-fail ONLY on a sense key that proves a programming failure; every other
/// outcome is left to read-back verify and firmware re-identification.
fn post_commit_status(dev: &mut dyn ScsiDevice) -> Result<()> {
    if let Err(error) = dev.command_in(&cdb::test_unit_ready(), 0) {
        crate::diagnostics::record(format!("MediaTek post-commit readiness: {error:#}"));
    }
    let sense = match dev.command_in(&cdb::request_sense(), cdb::REQUEST_SENSE_LEN) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("warning: post-flash REQUEST SENSE failed: {error:#}");
            Vec::new()
        }
    };
    match parse_sense(&sense) {
        // Hard-fail ONLY on an unambiguous programming failure (see
        // `sense_key_is_fatal`). Every other key is non-fatal here — the
        // drive re-enumeration is the authority.
        Some((key, asc, ascq)) if sense_key_is_fatal(key) => {
            bail!(
                "drive reported an error after flash — {}; the flash may have FAILED",
                crate::platform::describe_sense(key, asc, ascq)
            );
        }
        // Unparseable/short sense: the burn already completed and TEST UNIT
        // READY passed, so do not conclude failure — but surface it, since
        // read-back verify is the remaining check.
        None => {
            eprintln!(
                "warning: could not parse the post-flash REQUEST SENSE response ({} bytes); relying on read-back verify",
                sense.len()
            );
        }
        // Any other key (0x0/0x1 clean, 0x2/0x6 benign transient, or an
        // unexpected 0x5/0x7/…): not hard-failed here — post-flash identity
        // re-enumeration + read-back verify are the authorities.
        _ => {}
    }
    Ok(())
}

// ---- The MTK family ---------------------------------------------------------

/// The MediaTek MT19xx drive family.
pub struct Mtk;

impl DriveFamily for Mtk {
    fn backend_name(&self) -> &'static str {
        "mtk19xx"
    }

    fn probe(
        &self,
        dev: &mut dyn ScsiDevice,
        identity: &super::Identity,
    ) -> Result<Option<super::ProbeEvidence>> {
        // A Pioneer INQUIRY is enough to rule out MT19xx. Do not issue MTK
        // vendor ROM reads at this unrelated controller.
        if identity.vendor.eq_ignore_ascii_case("PIONEER") {
            return Ok(None);
        }
        Ok(
            (get_config_is_mtk(dev) && has_mt19_banner(dev)).then_some(super::ProbeEvidence {
                family: Family::Mtk,
                backend_name: self.backend_name(),
                discriminator: "MMC 0x010C + MT19 boot ROM banner",
            }),
        )
    }

    fn identity(&self, dev: &mut dyn ScsiDevice) -> super::Identity {
        let mut identity = super::read_identity(dev);
        identity.banner = read_mt19_banner(dev);
        identity
    }

    fn backup_extension(&self) -> Option<&'static str> {
        Some("bin")
    }

    fn backup_notice(&self, bytes: &[u8]) -> super::BackupNotice {
        backup::notice(bytes)
    }

    fn describe_file(&self, image: &[u8]) -> Option<Result<()>> {
        file_info::describe(image)
    }

    fn print_device_info(&self, dev: &mut dyn ScsiDevice) {
        let chip = read_chip(dev).map_or("Not reported", |c| c.label());
        crate::output::field("Chipset", chip);
        println!("{}", crate::style::kv("chipset", chip));
    }

    fn print_flash_notes(&self, image: &[u8], drive_model: &str, allow_crossflash: bool) {
        if let Some(info) =
            crossflash::preview_crossflash(image, drive_model, Family::Mtk, allow_crossflash)
        {
            crossflash::print_crossflash_banner(&info);
        }
    }

    fn classify_input(&self, path: &std::path::Path, _bytes: &[u8]) -> super::InputKind {
        super::sniff_input(path)
    }

    fn verification_ranges(&self, image: &[u8]) -> Result<Vec<(usize, usize)>> {
        let Some(entries) = crate::cmac::parse_table(image).ok() else {
            return Ok(Vec::new());
        };
        Ok(entries
            .iter()
            .filter(|entry| entry.is_active())
            .filter_map(|entry| {
                let start = (entry.start as usize).max(0x1000);
                let end = entry.end as usize;
                (start <= end).then_some((start, end))
            })
            .collect())
    }

    fn capture_backup(&self, dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
        backup::capture(dev, self)
    }

    fn dump_is_raw(&self) -> bool {
        true
    }

    fn capture_dump(&self, dev: &mut dyn ScsiDevice, _force: bool) -> Result<Vec<u8>> {
        let (image, readable, gaps) = self.read_full_image(dev)?;
        if readable == 0 {
            bail!("no MediaTek memory was readable; no dump saved");
        }
        crate::output::field(
            "Memory captured",
            format!("{readable} of {} bytes", image.len()),
        );
        if !gaps.is_empty() {
            let message = format!("Unreadable ranges filled with FF: {gaps:#x?}");
            crate::output::field("Dump gaps", &message);
            eprintln!("{message}");
        }
        Ok(image)
    }

    fn validate_forced_image(&self, dev: &mut dyn ScsiDevice, image: &[u8]) -> Result<()> {
        if image.len() != self.image_size() {
            bail!("firmware must be exactly {} bytes", self.image_size());
        }
        if !crate::cmac::verify(image) {
            bail!("firmware image fails its AES-CMAC integrity check");
        }
        // The boot-page and chip gates survive --force.
        ensure_flashable_boot_page(image, true)?;
        ensure_same_chip(dev, image)?;
        Ok(())
    }

    fn validate_forced_backup(&self, bytes: &[u8], _target_model: &str) -> Result<Vec<u8>> {
        backup::decode(bytes, self.image_size())
    }

    fn validate_backup(&self, bytes: &[u8], target_model: &str) -> Result<Vec<u8>> {
        backup::validate(bytes, target_model, self.image_size())
    }

    fn validate_image(
        &self,
        dev: &mut dyn ScsiDevice,
        image: &[u8],
        drive_product: &str,
        allow_crossflash: bool,
    ) -> Result<()> {
        if image.len() != self.image_size() {
            bail!(
                "firmware .bin must be exactly {} bytes, got {}",
                self.image_size(),
                image.len()
            );
        }
        if !crate::cmac::verify(image) {
            bail!(
                "firmware image fails its AES-CMAC integrity check — refusing to flash. \
                 A mis-signed or corrupted image is rejected by the drive's boot \
                 authenticator and can brick the drive."
            );
        }
        ensure_flashable_boot_page(image, false)?;
        let fine_family = Some(ensure_same_chip(dev, image)?);
        crossflash::ensure_image_matches_drive(
            image,
            drive_product,
            Family::Mtk,
            allow_crossflash,
            fine_family,
        )?;
        Ok(())
    }
    fn family(&self) -> Family {
        Family::Mtk
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::all()
    }

    fn read_full_image(&self, dev: &mut dyn ScsiDevice) -> Result<super::FullImage> {
        // The MTK full-image read (mode6/buf0 sweep) lives in `probe`; this trait
        // method is the entry point the engine calls.
        crate::probe::read_full_image(dev)
    }

    fn read_surface_map(
        &self,
        dev: &mut dyn ScsiDevice,
        ident: &super::Identity,
        image: &[u8],
        gaps: &[(usize, usize)],
    ) -> Result<Option<(String, String)>> {
        let map_ident = crate::probe::MapIdent {
            vendor: ident.vendor.as_str(),
            product: ident.product.as_str(),
            revision: ident.revision.as_str(),
            banner: ident.banner.as_deref(),
        };
        let (json, md) = crate::probe::build_map(dev, &map_ident, image, gaps)?;
        Ok(Some((json, md)))
    }

    fn image_size(&self) -> usize {
        IMAGE_SIZE
    }

    fn chunk_size(&self) -> usize {
        CHUNK
    }

    fn envelope(
        &self,
        dev: &mut dyn ScsiDevice,
        image: &[u8],
        enc_override: Option<bool>,
    ) -> Result<(Vec<u8>, bool)> {
        let enc = enc_override.unwrap_or_else(|| enc_needed(dev));
        let mut payload = image.to_vec();
        if enc {
            enc_transform(&mut payload)?;
        }
        Ok((payload, enc))
    }

    fn flash_plan(&self, image_len: usize, verbose: bool) -> Result<String> {
        let seq = flash_sequence(image_len, CHUNK)?;
        Ok(describe_sequence(&seq, verbose))
    }

    fn wait_ready(&self, dev: &mut dyn ScsiDevice) -> Result<()> {
        use std::time::{Duration, Instant};
        // After the last chunk the drive keeps programming and reports TEST UNIT
        // READY as an error until done. Poll until the transport returns Ok. If
        // the ceiling elapses without a good reply the drive is still busy or
        // has genuinely faulted — either way the flash is NOT settled and the
        // caller MUST NOT continue as if it were.
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let error = match dev.command_in(&cdb::test_unit_ready(), 0) {
                Ok(_) => break,
                Err(error) => error,
            };
            crate::diagnostics::record(format!("MediaTek post-flash readiness: {error:#}"));
            if Instant::now() >= deadline {
                bail!(
                    "drive did not settle after the flash burn within 45 s — TEST UNIT READY \
                     never came back Ok. The flash may have FAILED, or the drive is hung; do \
                     NOT trust the exit code as success. Physically power-cycle the drive and \
                    re-verify its firmware identity before shipping. Last error: {error:#}"
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        // Post-settle sense check. `flash_close`'s REQUEST SENSE fires BEFORE
        // this wait, i.e. against a still-programming drive whose sense is
        // transient (mid-program). A hardware fault that only manifests after
        // programming completes would not be caught by that early check —
        // catch it here, on the settled drive, where the sense reflects the
        // final flash outcome. Same "hard fail keys" list as `flash_close`
        // (MEDIUM 0x3, HARDWARE 0x4, ABORTED 0xB); every other key here is
        // benign (drive settled Ok but had a stale UNIT ATTENTION etc.).
        //
        // If the sense query itself errors or returns unparseable bytes,
        // WARN — silently swallowing the failure would narrow the backstop
        // back down to relying on downstream read-back verify alone, and the
        // operator has no way to know that happened. Matches the sibling
        // `flash_close` behaviour on unparseable sense.
        let sense = match dev.command_in(&cdb::request_sense(), cdb::REQUEST_SENSE_LEN) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "warning: post-settle REQUEST SENSE errored ({e:#}); relying on read-back \
                     verify — the drive settled but its final sense state is unknown."
                );
                Vec::new()
            }
        };
        match parse_sense(&sense) {
            Some((key, asc, ascq)) if sense_key_is_fatal(key) => {
                bail!(
                    "post-settle sense reports a flash fault — {}; the flash may have FAILED. \
                     Physically confirm the drive's firmware identity before shipping.",
                    crate::platform::describe_sense(key, asc, ascq)
                );
            }
            Some(_) => {}
            None if !sense.is_empty() => {
                eprintln!(
                    "warning: post-settle REQUEST SENSE returned an unparseable {}-byte reply; \
                     relying on read-back verify.",
                    sense.len()
                );
            }
            None => {}
        }
        Ok(())
    }

    /// Read-only readiness handshake for a dry run: PROBE and TEST UNIT READY,
    /// no writes.
    fn preflight(&self, dev: &mut dyn ScsiDevice) -> Result<()> {
        // PROBE is a real ROM read and must succeed. TEST UNIT READY is a faithful
        // handshake: flashed with no disc, a healthy drive answers benign no-medium
        // (key 0x2 ASC 0x3A); any OTHER not-ready reason aborts before PREPARE.
        let probe = dev.command_in(&cdb::probe(), cdb::PROBE_LEN)?;
        if probe.len() != cdb::PROBE_LEN {
            bail!(
                "short MediaTek preflight ROM read: got {} of {} bytes",
                probe.len(),
                cdb::PROBE_LEN
            );
        }
        let _ = dev.command_in(&cdb::test_unit_ready(), 0)?;
        Ok(())
    }

    fn firmware_report(
        &self,
        dev: &mut dyn ScsiDevice,
    ) -> Result<Option<crate::drive::fw_ident::FwReport>> {
        // The two firmware-code windows a live drive exposes (rom_1F0000 is
        // per-unit calibration and deliberately excluded from the fingerprint).
        let rom_003000 = Acquire::ReadBuffer {
            offset: ROM_003000_OFFSET,
            len: ROM_003000_LEN,
        }
        .run(dev)?;
        let rom_1ec000 = Acquire::ReadBuffer {
            offset: ROM_1EC000_OFFSET,
            len: ROM_1EC000_LEN,
        }
        .run(dev)?;
        Ok(Some(crate::drive::fw_ident::report(
            &rom_003000,
            &rom_1ec000,
        )))
    }

    /// Stream the whole payload through `mediatek_optical`'s flash session:
    /// PROBE + TEST UNIT READY + PREPARE, the 16 KiB transfers, then the commit
    /// trailer. `_mode` is informational on MTK: the drive programs flash when
    /// the last chunk of the full 2 MiB image lands.
    fn flash_stream(
        &self,
        dev: &mut dyn ScsiDevice,
        payload: &[u8],
        _mode: FlashMode,
        progress: &mut dyn FnMut(usize),
    ) -> Result<()> {
        use crate::drive::transport::{mtk_err, ScsiTransport, SharedDevice};
        let shared = SharedDevice::new(dev);
        {
            let mut transport = ScsiTransport::flash(&shared);
            let mut session = mediatek_optical::drive::enter_update(&mut transport)
                .map_err(mtk_err)
                .context(
                    "MediaTek preflight/prepare failed before any firmware data was sent; the drive \
                     may be in update mode — power-cycle it before retrying",
                )?;
            let mut sent = 0usize;
            for piece in payload.chunks(CHUNK) {
                session.write(sent as u32, piece).map_err(mtk_err).with_context(|| {
                    format!(
                        "firmware write failed at offset {sent:#x}, length {}; drive may contain partial firmware",
                        piece.len()
                    )
                })?;
                sent += piece.len();
                progress(sent);
            }
            // The burn completed on the final chunk; the commit is a trailer the
            // reinitializing drive may answer with a transient CHECK CONDITION.
            if let Err(error) = session.finish().map_err(mtk_err) {
                eprintln!("MediaTek commit trailer returned an error: {error:#}; checking completion and read-back");
            }
        }
        shared.with(post_commit_status)
    }

    fn readback(&self, dev: &mut dyn ScsiDevice, offset: usize, len: usize) -> Result<Vec<u8>> {
        let cdb = cdb::read_memory(offset as u32, len as u32);
        dev.command_in(&cdb, len)
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
