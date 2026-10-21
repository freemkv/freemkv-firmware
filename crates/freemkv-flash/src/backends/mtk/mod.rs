//! MediaTek MT1959 / MT1939 drive family.
//!
//! Identity and dump reads, the flash session, the `enc` transport envelope
//! and the per-unit tar model. CDBs come from `mediatek_optical`; backup,
//! crossflash, file reports and the two-stage flash are submodules.
//!
//! The flash is a verbatim writer: it never modifies the image (no downgrade
//! byte, per-unit splice or CMAC re-sign). It backs up, writes the bytes and
//! verifies. The active receiver determines the transport encoding.
//!
//! `mediatek_optical::update` owns the update: the gates against the installed
//! firmware (chip, hardware family), the session's commands, readiness timing
//! and read-back. This backend owns the drive: identity reads, the backup,
//! model checks, progress and the post-flash identity. `FlashMode` does not
//! change the session.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};

pub(crate) mod backup;
#[cfg(test)]
pub(crate) mod bulk_receiver_fixture;
pub(crate) mod crossflash;
pub(crate) mod file_info;
#[cfg(test)]
#[path = "fixture_tests.rs"]
pub(crate) mod fixture;
mod flash;
pub mod fwdump;
mod receiver_reference;
mod recovery;
pub(crate) use flash::decide_offline;

/// The routing facts the offline crossflash pre-filter compares: the hardware
/// family and the image's model.
pub(crate) fn offline_prefilter(bytes: &[u8]) -> crate::crossflash::Prefilter {
    crate::crossflash::Prefilter {
        platform: crate::crossflash::Platform::Mediatek,
        family: mediatek_optical::image::family(bytes).map(|f| f.to_string()),
        model: crossflash::Build::of_image(bytes).ok().map(|b| b.product),
        normal_only: false,
    }
}
pub mod fw_ident;
pub(crate) mod inspect;
pub mod oem;

use crate::backend::{
    read_identity, Backend, BackendId, BackupFacet, BackupFormat, BackupNotice, Descriptor,
    DetailsFacet, DeviceAccess, DumpFacet, FileFacet, FileFormat, FirmwareReport, FlashFacet,
    FormatRole, Identity, Match, ReadDevice,
};
use crate::platform::ScsiDevice;
use mediatek_optical::update::{Direction, Step};

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

/// Read the active receiver and its required transfer encoding.
/// Detection belongs to `mediatek_optical`; this adapter supplies shared SCSI I/O.
pub fn detect_receiver(dev: &mut ReadDevice<'_>) -> Result<mediatek_optical::receiver::Receiver> {
    let shared = crate::transport::SharedDevice::new(dev);
    let mut transport = crate::transport::ScsiTransport::reads(&shared);
    let mode =
        mediatek_optical::receiver::detect_mode(&mut transport).map_err(anyhow::Error::new)?;
    mediatek_optical::receiver::detect(&mut transport, &mode).map_err(anyhow::Error::new)
}

/// Lightweight read-only planning probe. Executable authorization completes
/// entry detection after the backup destination and capture gates.
pub fn probe_receiver_encoding(
    dev: &mut ReadDevice<'_>,
) -> Result<mediatek_optical::receiver::Receiver> {
    let shared = crate::transport::SharedDevice::new(dev);
    let mut transport = crate::transport::ScsiTransport::reads(&shared);
    let mode =
        mediatek_optical::receiver::detect_mode(&mut transport).map_err(|e| anyhow!("{e}"))?;
    mediatek_optical::receiver::detect_encoding(&mut transport, &mode).map_err(|e| anyhow!("{e}"))
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
                other => bail!(
                    "unexpected dump member '{}'",
                    crate::backend::sanitize_ascii(other)
                ),
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
        parse_field_descriptor(&self.fd_sn).map(|d| crate::backend::sanitize_ascii(&d.ascii))
    }

    /// Decoded firmware date, if the descriptor parses.
    pub fn fw_date(&self) -> Option<String> {
        parse_field_descriptor(&self.fd_fwdate).map(|d| crate::backend::sanitize_ascii(&d.ascii))
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
                    crate::backend::sanitize_ascii(&name)
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
                    crate::backend::sanitize_ascii(&name)
                );
            }
            let canonical = MEMBER_NAMES
                .iter()
                .copied()
                .find(|m| *m == name)
                .with_context(|| {
                    format!(
                        "unexpected dump member '{}'",
                        crate::backend::sanitize_ascii(&name)
                    )
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

/// One step as the verbose dry run prints it.
fn render(step: &Step) -> String {
    let hex = step
        .cdb
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let (token, detail) = match step.direction {
        Direction::In => ("in", format!("alloc={}", step.length)),
        Direction::Out if step.label == STREAM => {
            let offset = u32::from_be_bytes([0, step.cdb[3], step.cdb[4], step.cdb[5]]);
            ("out", format!("data={} @0x{offset:06X}", step.length))
        }
        Direction::Out => ("out", format!("data={}", step.length)),
        Direction::None => ("---", String::new()),
    };
    format!("{:<8}{:<3}  {}   {}", step.label, token, hex, detail)
        .trim_end()
        .to_string()
}

/// The label of a firmware chunk write.
const STREAM: &str = "STREAM";

/// Render the flash sequence for human review (the dry-run output).
fn describe_sequence(steps: &[Step], verbose: bool) -> String {
    use crate::style::human_size;
    use std::fmt::Write as _;

    let stream_total: usize = steps
        .iter()
        .filter(|s| s.label == STREAM)
        .map(|s| s.length)
        .sum();
    let chunk = steps
        .iter()
        .find(|s| s.label == STREAM)
        .map(|s| s.length)
        .unwrap_or(0);
    let count = steps.iter().filter(|s| s.label == STREAM).count();

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
            if steps[i].label == STREAM {
                let start = i;
                let mut j = i;
                while j < steps.len() && steps[j].label == STREAM {
                    j += 1;
                }
                let cnt = j - start;
                let _ = writeln!(out, "  #{:02} {}", start + 1, render(&steps[start]));
                if cnt > 2 {
                    let _ = writeln!(
                        out,
                        "      ... {} identical STREAM chunks collapsed ({} total) ...",
                        cnt,
                        human_size(stream_total)
                    );
                }
                if cnt >= 2 {
                    let _ = writeln!(out, "  #{:02} {}", j, render(&steps[j - 1]));
                }
                i = j;
            } else {
                let _ = writeln!(out, "  #{:02} {}", i + 1, render(&steps[i]));
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

/// The drive's identity descriptor and its boot banner: what the chip and family
/// gates compare an image with. The chip generation is decided by the banner, so
/// the banner is ALWAYS read (never skipped for a "tagged" drive — the tag is a
/// stale vendor label). Unreadable regions stay empty.
pub(crate) fn live_identity(dev: &mut dyn ScsiDevice) -> mediatek_optical::Identity {
    let descriptor = read_exact_retry(dev, ROM_1EC000_OFFSET, ROM_1EC000_LEN).unwrap_or_default();
    let banner = read_exact_retry(dev, ROM_003000_OFFSET, ROM_003000_LEN).unwrap_or_default();
    mediatek_optical::Identity::parse(&[0; mediatek_optical::INQUIRY_LEN], &banner, &descriptor)
        .expect("a full-length INQUIRY")
}

/// The drive's controller generation for display, decided by its boot banner.
pub(crate) fn read_chip(dev: &mut dyn ScsiDevice) -> Option<mediatek_optical::Chip> {
    live_identity(dev).chip()
}

/// The boot-page gate. A drive read (boot page equal to the mirror at
/// `0x10000`) is never flashable: writing it would store the read-back page in
/// place of the boot page, which the integrity table does not cover. The boot
/// page must also be one the OEM catalog knows.
fn ensure_flashable_boot_page(image: &[u8]) -> Result<()> {
    if mediatek_optical::image::is_drive_read(image) {
        bail!(
            "this is a raw drive read (its boot page is the read-back copy), not a flashable \
             image — refusing to flash. Restore from a freemkv backup .bin, or the vendor's \
             update image. This gate cannot be overridden."
        );
    }
    let boot = &image[..mediatek_optical::layout::BOOT_PAGE.len];
    if !oem::catalog().knows_boot_page(boot) {
        bail!(
            "the image's boot page is not one any known OEM build stores — refusing to flash \
             an image whose boot page may not start the drive"
        );
    }
    Ok(())
}

/// Whether `bytes` are a tar holding only 0.10.x backup members.
fn is_legacy_archive(bytes: &[u8]) -> bool {
    if bytes.get(257..262) != Some(b"ustar") {
        return false;
    }
    let mut archive = tar::Archive::new(bytes);
    let Ok(entries) = archive.entries() else {
        return false;
    };
    let mut names = 0;
    for entry in entries {
        let Some(name) = entry
            .ok()
            .and_then(|e| Some(e.path().ok()?.to_str()?.to_string()))
        else {
            return false;
        };
        if !(MEMBER_NAMES.contains(&name.as_str())
            || name == "backup.toml"
            || name == "firmware.bin")
        {
            return false;
        }
        names += 1;
    }
    names > 0
}

// ---- The MTK family ---------------------------------------------------------

/// A full MediaTek firmware image (a vendor update or a freemkv backup `.bin`).
pub const IMAGE: FileFormat = FileFormat {
    id: "mtk-image",
    label: "MediaTek firmware image",
    extensions: &["bin"],
    role: FormatRole::Image,
};

/// A validated release TAR, containing final firmware and an optional intermediate.
pub const PACKAGE: FileFormat = FileFormat {
    id: "mtk-package",
    label: "MediaTek release package",
    extensions: &["tar"],
    role: FormatRole::Package,
};

/// A freemkv 0.10.x MediaTek backup archive, restored through its firmware.
pub const LEGACY_TAR: FileFormat = FileFormat {
    id: "mtk-legacy-tar",
    label: "MediaTek 0.10.x backup archive",
    extensions: &["tar"],
    role: FormatRole::Backup,
};

/// What the MediaTek backend declares.
pub static DESCRIPTOR: Descriptor = Descriptor {
    id: BackendId("mtk19xx"),
    display_name: "MediaTek MT19xx",
    flash_summary: Some("MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)"),
    formats: &[IMAGE, PACKAGE, LEGACY_TAR],
};

/// The MediaTek MT19xx drive family.
pub struct Mtk;

impl Backend for Mtk {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    fn probe(&self, dev: &mut ReadDevice<'_>, identity: &Identity) -> Result<Option<Match>> {
        // A Pioneer INQUIRY is enough to rule out MT19xx. Do not issue MTK
        // vendor ROM reads at this unrelated controller.
        if identity.vendor.eq_ignore_ascii_case("PIONEER") {
            return Ok(None);
        }
        Ok(
            (get_config_is_mtk(dev) && has_mt19_banner(dev)).then_some(Match {
                backend: DESCRIPTOR.id,
                evidence: "MMC 0x010C + MT19 boot ROM banner",
            }),
        )
    }

    fn identity(&self, dev: &mut ReadDevice<'_>) -> Identity {
        let mut identity = read_identity(dev);
        identity.banner = read_mt19_banner(dev);
        identity
    }

    fn recovery(&self) -> Option<&dyn crate::backend::RecoveryFacet> {
        Some(self)
    }

    fn files(&self) -> Option<&dyn FileFacet> {
        Some(self)
    }
    fn details(&self) -> Option<&dyn DetailsFacet> {
        Some(self)
    }
    fn backup(&self) -> Option<&dyn BackupFacet> {
        Some(self)
    }
    fn dump(&self) -> Option<&dyn DumpFacet> {
        Some(self)
    }
    fn flash(&self) -> Option<&dyn FlashFacet> {
        Some(self)
    }
    fn inspect(&self) -> Option<&dyn crate::backend::InspectFacet> {
        Some(self)
    }
}

impl FileFacet for Mtk {
    /// A tar of exactly the 0.10.x backup members is structural; a MediaTek
    /// chip signature found anywhere else is heuristic.
    fn recognize(&self, bytes: &[u8]) -> Option<crate::backend::Recognized> {
        use crate::backend::{Confidence, Recognized};
        if crate::mediatek_package::Package::parse(bytes).is_ok() {
            return Some(Recognized {
                format: &PACKAGE,
                confidence: Confidence::Structural,
            });
        }
        if is_legacy_archive(bytes) {
            return Some(Recognized {
                format: &LEGACY_TAR,
                confidence: Confidence::Structural,
            });
        }
        file_info::classify_file(bytes).chip.map(|_| Recognized {
            format: &IMAGE,
            confidence: Confidence::Heuristic,
        })
    }

    fn describe(&self, image: &[u8], _: &crate::backend::Recognized) -> Option<Result<()>> {
        // A 0.10.x legacy archive carries the firmware inside a tar; its boot
        // banner (the chip signal) is not at a fixed offset of the archive, so
        // rebuild the flashable image first and describe that. A raw .bin is
        // described directly.
        if let Ok(package) = crate::mediatek_package::Package::parse(image) {
            return file_info::describe(package.firmware());
        }
        if is_legacy_archive(image) {
            let rebuilt = match backup::backup_image(image, IMAGE_SIZE) {
                Ok(img) => img,
                Err(e) => return Some(Err(e)),
            };
            return file_info::describe(&rebuilt);
        }
        file_info::describe(image)
    }

    fn classify_input(&self, path: &std::path::Path, bytes: &[u8]) -> &'static FileFormat {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) if ext.eq_ignore_ascii_case("tar") => {
                if is_legacy_archive(bytes) {
                    &LEGACY_TAR
                } else {
                    &PACKAGE
                }
            }
            _ => &IMAGE,
        }
    }
}

impl DetailsFacet for Mtk {
    fn rows(
        &self,
        dev: &mut ReadDevice<'_>,
        _read: &crate::backend::InfoSoFar<'_>,
        slot: crate::report::Slot,
    ) -> Vec<crate::report::Row> {
        if slot != crate::report::Slot::End {
            return Vec::new();
        }
        let chip = read_chip(dev).map_or("Not reported", |c| c.label());
        let value = crate::report::Value::text(chip);
        vec![crate::report::Row::new(
            "chipset",
            Some("Chipset"),
            Some("chipset"),
            value,
        )]
    }

    fn post_flash_identity(&self, dev: &mut ReadDevice<'_>) -> Result<Option<FirmwareReport>> {
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
        let report = fw_ident::report(&rom_003000, &rom_1ec000);
        Ok(Some(FirmwareReport {
            descriptor: report.descriptor,
            fingerprint: report.fingerprint,
            matched: report.matched.map(|entry| (entry.desc, entry.source)),
        }))
    }
}

impl BackupFacet for Mtk {
    fn format(&self) -> BackupFormat {
        BackupFormat {
            extension: "bin",
            infix: "backup",
        }
    }

    fn capture(&self, dev: &mut ReadDevice<'_>) -> Result<Vec<u8>> {
        backup::capture(dev)
    }

    fn notice(&self, bytes: &[u8]) -> BackupNotice {
        backup::notice(bytes)
    }

    fn validate(&self, bytes: &[u8], target_model: &str) -> Result<Vec<u8>> {
        backup::validate(bytes, target_model, IMAGE_SIZE)
    }
}

impl DumpFacet for Mtk {
    fn capture(&self, mut dev: DeviceAccess<'_, '_>) -> Result<Vec<u8>> {
        let (image, readable, gaps) = crate::probe::read_full_image(dev.scsi())?;
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
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
