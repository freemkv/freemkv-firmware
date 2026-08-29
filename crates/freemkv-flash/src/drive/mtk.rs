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

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};

use super::{DriveFamily, Family, RestoreRegion};
use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;

// ---- Region geometry --------------------------------------------------------

/// Boot banner / metadata region offset.
pub const ROM_003000_OFFSET: u32 = 0x003000;
/// Boot banner / metadata region length.
pub const ROM_003000_LEN: u32 = 0x20;
/// Identity-page region offset.
pub const ROM_1EC000_OFFSET: u32 = 0x1EC000;
/// Identity-page region length (256 B).
pub const ROM_1EC000_LEN: u32 = 0x100;
/// Per-unit calibration NVRAM region offset.
pub const ROM_1F0000_OFFSET: u32 = 0x1F0000;
/// Per-unit calibration NVRAM region length (64 KiB).
pub const ROM_1F0000_LEN: u32 = 0x10000;
/// INQUIRY allocation length used by the identity flow.
pub const INQUIRY_LEN: u16 = 96;
/// GET CONFIGURATION allocation length for the fd_* field descriptors.
pub const FD_LEN: u16 = 28;
/// GET CONFIGURATION feature code carrying the ASCII serial number (fd_sn.bin).
pub const FEATURE_SERIAL: u16 = 0x0108;
/// GET CONFIGURATION feature code carrying the ASCII firmware date (fd_fwdate.bin).
pub const FEATURE_FWDATE: u16 = 0x010C;
/// READ BUFFER / WRITE BUFFER mode used by the MT19xx register path.
pub const MODE_6: u8 = 0x06;
/// READ BUFFER buffer id used for the per-unit ROM regions.
pub const ROM_BUFFER_ID: u8 = 0x00;

/// Expected full firmware image size (2 MiB).
pub const IMAGE_SIZE: usize = 0x200000;
/// Streaming chunk size for the flash sequence, 16 KiB.
pub const CHUNK: usize = 0x4000;
/// WRITE_BUFFER buffer id used by the MT19xx flash path.
pub const FLASH_BUFFER_ID: u8 = 0x00;
/// PROBE READ BUFFER allocation length (bytes read from the model page).
pub const PROBE_ALLOC: usize = 0x100;
/// DRAM offset read by the PROBE for the model-signature check.
pub const PROBE_MODEL_OFFSET: u32 = 0x1E_C000;
/// REQUEST SENSE allocation length.
pub const REQUEST_SENSE_ALLOC: usize = 16;

/// AES-128-ECB key for the `enc` transport envelope.
///
/// Applied to the whole image before streaming **only when [`enc_needed`] (or an
/// explicit override) selects enc**; see [`enc_transform`]. This is a
/// host-embedded, non-secret transport key — not the vendor signed-update layer.
pub const ENC_KEY: [u8; 16] = [
    0x5e, 0x9e, 0x4f, 0x00, 0x94, 0xef, 0x20, 0xab, 0x52, 0xe3, 0x5e, 0x73, 0x6a, 0xcb, 0x23, 0x24,
];

/// Ordered tar member names for a per-unit dump.
pub const MEMBER_NAMES: [&str; 6] = [
    "rom_003000.bin",
    "rom_1EC000.bin",
    "rom_1F0000.bin",
    "inq.bin",
    "fd_fwdate.bin",
    "fd_sn.bin",
];

// ---- CDB builders (pure, testable) ------------------------------------------

/// Build a READ BUFFER CDB (opcode 0x3C, 10 bytes).
pub fn cdb_read_buffer(mode: u8, buffer_id: u8, offset: u32, len: u32) -> [u8; 10] {
    [
        0x3C,
        mode & 0x1f,
        buffer_id,
        (offset >> 16) as u8,
        (offset >> 8) as u8,
        offset as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00,
    ]
}

/// Build a standard INQUIRY CDB (opcode 0x12) for `alloc_len` bytes.
pub fn cdb_inquiry(alloc_len: u16) -> [u8; 6] {
    [
        0x12,
        0x00,
        0x00,
        (alloc_len >> 8) as u8,
        alloc_len as u8,
        0x00,
    ]
}

/// Build a GET CONFIGURATION CDB (opcode 0x46) for a single `feature` (RT=0x02).
pub fn cdb_get_config(feature: u16, alloc_len: u16) -> [u8; 10] {
    [
        0x46,
        0x02,
        (feature >> 8) as u8,
        feature as u8,
        0x00,
        0x00,
        0x00,
        (alloc_len >> 8) as u8,
        alloc_len as u8,
        0x00,
    ]
}

/// Build a targeted WRITE BUFFER CDB (opcode 0x3B, 10 bytes) — used by `.tar`
/// restore for a whole region in one write (`len` may exceed 64 KiB - 1).
pub fn cdb_write_buffer(mode: u8, buffer_id: u8, offset: u32, len: u32) -> [u8; 10] {
    [
        0x3B,
        mode & 0x1f,
        buffer_id,
        (offset >> 16) as u8,
        (offset >> 8) as u8,
        offset as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00,
    ]
}

/// PROBE — READ BUFFER mode 6 @ 0x1EC000, 0x100 bytes (data-in). The returned
/// buffer carries a model signature that freemkv-flash does NOT validate
/// host-side.
pub fn cdb_read_probe() -> [u8; 12] {
    [
        0x3C, 0x06, 0x00, 0x1E, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// READY — TEST UNIT READY, all-zero CDB (poll).
pub fn cdb_test_unit_ready() -> [u8; 12] {
    [0x00; 12]
}

/// PREPARE — WRITE BUFFER mode 1, "enter-download / pre-erase" (len 0). CDB[9]=0x0B.
pub fn cdb_wb_prepare() -> [u8; 12] {
    [
        0x3B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00,
    ]
}

/// STREAM — WRITE BUFFER mode 6 "download microcode with offsets" (data-out).
///
/// `offset` is the absolute byte offset (big-endian, CDB[3..5]); `len` is
/// big-endian in CDB[6..8] (a 0x4000 chunk lands as `00 40 00`).
pub fn cdb_wb_data(offset: u32, len: u16) -> [u8; 12] {
    [
        0x3B,
        0x06,
        0x00,
        (offset >> 16) as u8,
        (offset >> 8) as u8,
        offset as u8,
        0x00,
        (len >> 8) as u8,
        len as u8,
        0x00,
        0x00,
        0x00,
    ]
}

/// COMMIT — WRITE BUFFER mode 7 "download microcode + save" (len 0). The `1B 12`
/// magic sits in CDB[10..11].
pub fn cdb_wb_commit() -> [u8; 12] {
    [
        0x3B, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x12,
    ]
}

/// STATUS — REQUEST SENSE (data-in), the progress/status poll. These are the
/// exact bytes the drive's own flasher issues (byte 4 is `0x80` there, not the
/// SPC allocation length); the actual transfer is capped by the caller's buffer
/// ([`REQUEST_SENSE_ALLOC`] = 16). Left byte-for-byte so the drive sees what it
/// expects rather than an SPC-strict form it was never tested against.
pub fn cdb_request_sense() -> [u8; 12] {
    [
        0x03, 0x00, 0x00, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// AES-128-ECB encrypt the whole image in place (the `enc` transport envelope).
pub fn enc_transform(image: &mut [u8]) -> Result<()> {
    if image.len() % 16 != 0 {
        bail!(
            "enc: image length {} is not a multiple of the AES block size",
            image.len()
        );
    }
    let cipher = Aes128::new(GenericArray::from_slice(&ENC_KEY));
    for chunk in image.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(())
}

/// Decide whether this drive needs the `enc` transport envelope.
///
/// Whether a given drive *requires* the AES-128-ECB wrap (vs. accepting a
/// plaintext image) is a KNOWN-OPEN question, not yet resolvable without a
/// controlled hardware test against a matching base image. Until then this
/// defaults to plaintext (`false`) and flash stays a dry-run planner: no real
/// write ships on an unproven assumption.
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
                let cdb = cdb_read_buffer(MODE_6, ROM_BUFFER_ID, offset, len);
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
                let cdb = cdb_inquiry(alloc);
                dev.command_in(&cdb, alloc as usize)
            }
            Acquire::GetConfig { feature, alloc } => {
                let cdb = cdb_get_config(feature, alloc);
                dev.command_in(&cdb, alloc as usize)
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
    /// INQUIRY response (96 B).
    pub inq: Vec<u8>,
    /// fw-date GET CONFIG feature descriptor (28 B).
    pub fd_fwdate: Vec<u8>,
    /// serial-number GET CONFIG feature descriptor (28 B).
    pub fd_sn: Vec<u8>,
}

impl UserDump {
    /// Build a [`UserDump`] from `(name, data)` members in any order.
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
        let take = |slot: Option<Vec<u8>>, name: &str| {
            slot.ok_or_else(|| anyhow!("missing dump member '{name}'"))
        };
        Ok(Self {
            rom_003000: take(rom_003000, "rom_003000.bin")?,
            rom_1ec000: take(rom_1ec000, "rom_1EC000.bin")?,
            rom_1f0000: take(rom_1f0000, "rom_1F0000.bin")?,
            inq: take(inq, "inq.bin")?,
            fd_fwdate: take(fd_fwdate, "fd_fwdate.bin")?,
            fd_sn: take(fd_sn, "fd_sn.bin")?,
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
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
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
///
/// Supports fixed-format sense (response code 0x70/0x71: key in byte 2 low
/// nibble, ASC in byte 12, ASCQ in byte 13) and descriptor-format sense
/// (response code 0x72/0x73: key in byte 1 low nibble, ASC in byte 2, ASCQ in
/// byte 3). Returns `None` if the payload is too short or has an unrecognized
/// response code.
pub fn parse_sense(data: &[u8]) -> Option<(u8, u8, u8)> {
    let response_code = *data.first()?;
    match response_code {
        0x70 | 0x71 => {
            if data.len() < 14 {
                return None;
            }
            Some((data[2] & 0x0F, data[12], data[13]))
        }
        0x72 | 0x73 => {
            if data.len() < 4 {
                return None;
            }
            Some((data[1] & 0x0F, data[2], data[3]))
        }
        _ => None,
    }
}

/// Parse a GET CONFIGURATION single-feature descriptor (fd_sn / fd_fwdate).
pub fn parse_field_descriptor(data: &[u8]) -> Option<FieldDescriptor> {
    if data.len() < 12 {
        return None;
    }
    let feature = u16::from_be_bytes([data[8], data[9]]);
    let add_len = data[11];
    let end = (12 + add_len as usize).min(data.len());
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
    if chunk == 0 || chunk > 0xFFFF || image_len % chunk != 0 {
        bail!("chunk {chunk} does not evenly divide the {image_len}-byte image (and must fit u16)");
    }
    let mut steps = Vec::with_capacity(image_len / chunk + 6);
    steps.push(FlashStep {
        label: LABEL_PROBE,
        cdb: cdb_read_probe(),
        dir: Dir::In,
        data_len: PROBE_ALLOC,
    });
    steps.push(FlashStep {
        label: LABEL_READY,
        cdb: cdb_test_unit_ready(),
        dir: Dir::None,
        data_len: 0,
    });
    steps.push(FlashStep {
        label: LABEL_PREPARE,
        cdb: cdb_wb_prepare(),
        dir: Dir::Out,
        data_len: 0,
    });
    let mut offset = 0usize;
    while offset < image_len {
        steps.push(FlashStep {
            label: LABEL_STREAM,
            cdb: cdb_wb_data(offset as u32, chunk as u16),
            dir: Dir::Out,
            data_len: chunk,
        });
        offset += chunk;
    }
    steps.push(FlashStep {
        label: LABEL_COMMIT,
        cdb: cdb_wb_commit(),
        dir: Dir::Out,
        data_len: 0,
    });
    steps.push(FlashStep {
        label: LABEL_READY,
        cdb: cdb_test_unit_ready(),
        dir: Dir::None,
        data_len: 0,
    });
    steps.push(FlashStep {
        label: LABEL_STATUS,
        cdb: cdb_request_sense(),
        dir: Dir::In,
        data_len: REQUEST_SENSE_ALLOC,
    });
    Ok(steps)
}

/// Render the flash sequence for human review (the dry-run output).
fn describe_sequence(steps: &[FlashStep]) -> String {
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

    let mut out = String::new();
    let _ = writeln!(
        out,
        "image {stream_total} B, chunk {chunk} B, {} steps total",
        steps.len()
    );
    let _ = writeln!(
        out,
        "(NOTE: the tool streams the operator-supplied image VERBATIM; it performs \
         NO host-side image/model cross-check)"
    );

    let mut i = 0usize;
    while i < steps.len() {
        if steps[i].label == LABEL_STREAM {
            let start = i;
            let mut j = i;
            while j < steps.len() && steps[j].label == LABEL_STREAM {
                j += 1;
            }
            let count = j - start;
            let _ = writeln!(out, "#{:02} {}", start + 1, steps[start].render());
            if count > 2 {
                let _ = writeln!(
                    out,
                    "    ... {} identical-shape STREAM chunks (collapsed): off \
                     0x000000..0x{:06X} step 0x{:04X}, {} B streamed total ...",
                    count, stream_total, chunk, stream_total
                );
            }
            if count >= 2 {
                let _ = writeln!(out, "#{:02} {}", j, steps[j - 1].render());
            }
            i = j;
        } else {
            let _ = writeln!(out, "#{:02} {}", i + 1, steps[i].render());
            i += 1;
        }
    }
    let last_stream = steps
        .iter()
        .rposition(|s| s.label == LABEL_STREAM)
        .map(|p| p + 1);
    if let Some(n) = last_stream {
        let _ = writeln!(
            out,
            "!! POINT OF NO RETURN = last STREAM chunk (#{n}): the drive erases+programs flash \
             when the 2 MiB upload completes. COMMIT (mode 7) is a drive-ignored handshake, \
             not the burn. Aborting after #{n} does NOT undo the flash."
        );
    }
    out
}

// ---- The MTK family ---------------------------------------------------------

/// The MediaTek MT19xx drive family.
pub struct Mtk;

impl DriveFamily for Mtk {
    fn family(&self) -> Family {
        Family::Mtk
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn read_dump(&self, dev: &mut dyn ScsiDevice) -> Result<UserDump> {
        DumpPlan::new().execute(dev)
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

    fn flash_plan(&self, image_len: usize) -> Result<String> {
        let seq = flash_sequence(image_len, CHUNK)?;
        Ok(describe_sequence(&seq))
    }

    /// `_mode` is currently informational only: on MTK the full 2 MiB image is
    /// always streamed and the commit handshake in [`Self::flash_close`] is
    /// always sent regardless of [`FlashMode::Main`] vs [`FlashMode::Full`] —
    /// the drive programs on completion either way.
    fn preflight(&self, dev: &mut dyn ScsiDevice) -> Result<()> {
        // PROBE is a real ROM read and must succeed. TEST UNIT READY is a
        // drive-faithful handshake: firmware is flashed with NO disc loaded, so a
        // healthy drive answers NOT READY / "medium not present" (key 0x2 ASC
        // 0x3A) — the normal state, which the transport treats as benign (see
        // `platform::is_no_medium`). Any OTHER not-ready reason (spinning-up,
        // faulted, wrong medium) propagates the transport's decoded error here
        // and aborts before the caller reaches the irreversible PREPARE.
        let _ = dev.command_in(&cdb_read_probe(), PROBE_ALLOC)?;
        let _ = dev.command_in(&cdb_test_unit_ready(), 0)?;
        Ok(())
    }

    fn flash_open(&self, dev: &mut dyn ScsiDevice, _mode: FlashMode) -> Result<()> {
        self.preflight(dev)?;
        // PREPARE is the one data-out that must land (strict).
        dev.command_out(&cdb_wb_prepare(), &[])
    }

    fn flash_chunk(&self, dev: &mut dyn ScsiDevice, offset: usize, bytes: &[u8]) -> Result<()> {
        dev.command_out(&cdb_wb_data(offset as u32, bytes.len() as u16), bytes)
    }

    /// `_mode` is currently informational only: on MTK the commit handshake
    /// (COMMIT + READY + STATUS below) is always sent regardless of
    /// [`FlashMode::Main`] vs [`FlashMode::Full`] — the drive programs on
    /// completion of the streamed 2 MiB either way.
    fn flash_close(&self, dev: &mut dyn ScsiDevice, _mode: FlashMode) -> Result<()> {
        // The burn already completed on the final STREAM chunk. COMMIT + READY are
        // status trailers, and the drive is mid-reinit — it legitimately answers
        // these with a transient CHECK CONDITION (UNIT ATTENTION *or* NOT READY),
        // which the strict transport refuses. That is expected here and must NOT
        // be read as a failed flash, so both are best-effort: their transport
        // result is deliberately discarded. REQUEST SENSE is likewise best-effort
        // (a drive that cannot even return sense is caught by read-back verify);
        // the ONLY hard-failure signal is a real programming fault in its parsed
        // sense key below.
        let _ = dev.command_out(&cdb_wb_commit(), &[]);
        let _ = dev.command_in(&cdb_test_unit_ready(), 0);
        let sense = dev
            .command_in(&cdb_request_sense(), REQUEST_SENSE_ALLOC)
            .unwrap_or_default();
        match parse_sense(&sense) {
            // Bail ONLY on a genuine programming failure: MEDIUM ERROR (0x3),
            // HARDWARE ERROR (0x4), ABORTED COMMAND (0xB). A microcode program
            // normally leaves a benign transient key — NOT READY (0x2) or, most
            // often, UNIT ATTENTION (0x6, "parameters/microcode changed") — and
            // 0x0/0x1 are benign; treating those as failure would falsely report
            // a SUCCESSFUL irreversible flash as a brick.
            Some((key, asc, ascq)) if matches!(key, 0x3 | 0x4 | 0xB) => {
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
            _ => {}
        }
        Ok(())
    }

    fn readback(&self, dev: &mut dyn ScsiDevice, offset: usize, len: usize) -> Result<Vec<u8>> {
        let cdb = cdb_read_buffer(MODE_6, FLASH_BUFFER_ID, offset as u32, len as u32);
        dev.command_in(&cdb, len)
    }

    fn restore_regions<'a>(&self, dump: &'a UserDump) -> Vec<RestoreRegion<'a>> {
        vec![
            RestoreRegion {
                label: "rom_1EC000.bin",
                offset: ROM_1EC000_OFFSET,
                bytes: &dump.rom_1ec000,
            },
            RestoreRegion {
                label: "rom_1F0000.bin",
                offset: ROM_1F0000_OFFSET,
                bytes: &dump.rom_1f0000,
            },
        ]
    }

    fn write_region(&self, dev: &mut dyn ScsiDevice, offset: u32, bytes: &[u8]) -> Result<()> {
        let cdb = cdb_write_buffer(MODE_6, FLASH_BUFFER_ID, offset, bytes.len() as u32);
        dev.command_out(&cdb, bytes)
    }
}

#[cfg(test)]
#[path = "mtk_tests.rs"]
mod tests;
