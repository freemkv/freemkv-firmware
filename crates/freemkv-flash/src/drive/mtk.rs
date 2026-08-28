//! MediaTek MT1959 / MT1939 drive family — the only fully-implemented family.
//!
//! This module absorbs the former `dump.rs` (per-unit region capture + tar) and
//! `flash.rs` (WRITE_BUFFER streaming + safety gate) into one place.
//!
//! ## flash is a DUMB verbatim writer
//! The flasher writes the given file to the drive **verbatim** and never
//! modifies the image: no DE byte, no downgrade magic, no per-unit splice, no
//! CMAC resign — those are *firmware modification* and belong to a separate
//! future tool (`freemkv-forge`). flash's entire job is (1) back up via a
//! pre-flash dump, (2) write the bytes, (3) read-back verify.
//!
//! ## enc is an auto-detected transport envelope
//! [`enc_needed`] decides on every flash whether the drive needs the AES-128-ECB
//! `enc` envelope (research in progress — see ENC_DETECT_RESEARCH.md); it
//! currently defaults to plaintext. `--enc`/`--no-enc` exist only as a hidden
//! expert override. When enc is active the whole image is [`enc_transform`]ed
//! before streaming.

use std::io::{Read, Write};
use std::path::Path;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};

use super::{DriveFamily, Family, FlashRequest, InputKind};
use crate::platform::ScsiDevice;

// ---- Region geometry --------------------------------------------------------

/// Boot banner / metadata region offset.
pub const ROM_003000_OFFSET: u32 = 0x003000;
/// Boot banner / metadata region length.
pub const ROM_003000_LEN: u32 = 0x20;
/// Identity-page region offset (the DE byte at 0x1EC056 lives here).
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

/// Expected full firmware image size (2 MB).
pub const IMAGE_SIZE: usize = 0x200000;
/// Default WRITE_BUFFER / READ_BUFFER chunk size in bytes (32 KiB).
pub const DEFAULT_CHUNK: usize = 0x8000;
/// WRITE_BUFFER buffer id used by the MT19xx flash path.
pub const FLASH_BUFFER_ID: u8 = 0x00;

/// AES-128-ECB key for the `enc` transport envelope.
///
/// Applied to the whole image before streaming **only when [`enc_needed`]
/// (or an explicit override) selects enc**; see [`enc_transform`].
pub const ENC_KEY: [u8; 16] = [
    0x5e, 0x9e, 0x4f, 0x00, 0x94, 0xef, 0x20, 0xab, 0x52, 0xe3, 0x5e, 0x73, 0x6a, 0xcb, 0x23, 0x24,
];

/// Ordered tar member names, matching a `dump_user` capture byte-for-byte.
pub const MEMBER_NAMES: [&str; 6] = [
    "rom_003000.bin",
    "rom_1EC000.bin",
    "rom_1F0000.bin",
    "inq.bin",
    "fd_fwdate.bin",
    "fd_sn.bin",
];

// ---- CDB builders (pure, testable) ------------------------------------------

/// Build a READ BUFFER CDB (opcode 0x3C).
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

/// Build a WRITE BUFFER CDB (opcode 0x3B).
///
/// `commit` sets the low control-byte bit — the `full`-mode commit flag that
/// tells the drive to commit the freshly-streamed 2 MB image.
pub fn cdb_write_buffer(mode: u8, buffer_id: u8, offset: u32, len: u32, commit: bool) -> [u8; 10] {
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
        if commit { 0x01 } else { 0x00 },
    ]
}

/// AES-128-ECB encrypt the whole image in place (the `enc` transport envelope).
///
/// Applied before streaming only when [`enc_needed`] (or an explicit override)
/// selects enc. The key is host-embedded and non-secret; this is transport
/// wrapping, not the vendor signed-update layer, and does not touch CMAC.
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
                dev.command_in(&cdb, len as usize)
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
                other => bail!("unexpected dump member '{other}'"),
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
                .with_context(|| format!("unexpected dump member '{name}'"))?;
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

/// Back up a drive's per-unit regions (the pre-flash dump primitive).
pub fn dump_user(dev: &mut dyn ScsiDevice) -> Result<UserDump> {
    DumpPlan::new().execute(dev)
}

// ---- enc auto-detection -----------------------------------------------------

/// Decide whether this drive needs the `enc` transport envelope.
///
/// PROVEN false for MT1959: enc is NEVER needed — send plaintext always.
/// Verified across 5 BU40N images (stock and MK) — no AES key/S-box/tables in
/// any image, so no MT1959 firmware can consume an AES-ECB payload; and both
/// stock and MK compare the banner at image+0x3000 as PLAINTEXT
/// (`FUN_00003544`), so an enc'd image fails the banner match (0/16) and is
/// rejected. An enc stream would BREAK the flash, not enable it. The forum's
/// "use enc for original fw" has no evidence in the MT1959 hoard (likely a
/// different drive generation). See ENC_DETECT_RESEARCH.md.
///
/// The hook is retained so a future non-MTK family can override per-drive; for
/// MediaTek it is a confirmed constant, not a stub.
pub fn enc_needed(_dev: &mut dyn ScsiDevice) -> bool {
    false
}

// ---- Flash plan (WRITE_BUFFER streaming) ------------------------------------

/// A planned flash operation, ready to be executed or dry-run.
///
/// The whole 2 MB image is streamed for both `main` and `full`; `full` only
/// sets the commit flag bit on the final WRITE_BUFFER. Always plaintext.
#[derive(Debug, Clone)]
pub struct FlashPlan {
    /// SCSI WRITE_BUFFER mode (always 6 for the MT19xx path).
    pub mode: u8,
    /// Chunk size.
    pub chunk: usize,
    /// Whether to set the `full`-mode commit flag on the final chunk.
    pub commit: bool,
    /// The exact bytes streamed to the drive (plaintext, or enc-enveloped).
    pub payload: Vec<u8>,
}

impl FlashPlan {
    /// Prepare a flash plan from a full image, the commit flag, and enc choice.
    ///
    /// When `enc` is true the whole image is AES-128-ECB enveloped before
    /// streaming; otherwise the payload is the verbatim image.
    pub fn prepare(image: &[u8], commit: bool, enc: bool) -> Result<Self> {
        let mut payload = image.to_vec();
        if enc {
            enc_transform(&mut payload)?;
        }
        Ok(Self {
            mode: MODE_6,
            chunk: DEFAULT_CHUNK,
            commit,
            payload,
        })
    }

    /// Number of WRITE_BUFFER chunks this plan will issue.
    pub fn chunk_count(&self) -> usize {
        self.payload.len().div_ceil(self.chunk)
    }

    /// Execute the chunked WRITE_BUFFER upload against a live device.
    pub fn execute(&self, dev: &mut dyn ScsiDevice) -> Result<()> {
        let mut offset = 0usize;
        let last_start = self.payload.len().saturating_sub(self.chunk);
        for chunk in self.payload.chunks(self.chunk) {
            let is_last = offset >= last_start;
            let cdb = cdb_write_buffer(
                self.mode,
                FLASH_BUFFER_ID,
                offset as u32,
                chunk.len() as u32,
                self.commit && is_last,
            );
            dev.command_out(&cdb, chunk)?;
            offset += chunk.len();
        }
        Ok(())
    }

    /// Read back the streamed range and hard-error on any mismatch.
    pub fn verify_readback(&self, dev: &mut dyn ScsiDevice) -> Result<()> {
        let mut offset = 0usize;
        for chunk in self.payload.chunks(self.chunk) {
            let cdb = cdb_read_buffer(MODE_6, FLASH_BUFFER_ID, offset as u32, chunk.len() as u32);
            let got = dev.command_in(&cdb, chunk.len())?;
            if got != chunk {
                bail!(
                    "read-back verify failed at 0x{offset:06X}: {} bytes differ",
                    got.iter().zip(chunk).filter(|(a, b)| a != b).count()
                );
            }
            offset += chunk.len();
        }
        Ok(())
    }
}

// ---- Safety gate ------------------------------------------------------------

/// A blocked flash attempt, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyBlock(pub String);

/// Inputs to the pre-flash safety gate.
#[derive(Debug, Clone)]
pub struct SafetyContext<'a> {
    /// Model reported by the connected drive (INQUIRY product).
    pub drive_model: &'a str,
    /// Model string detected in the firmware image (may be empty).
    pub firmware_model: &'a str,
    /// User acknowledged the bricking risk (`--i-understand-risk`).
    pub acknowledged_risk: bool,
    /// User allowed a model mismatch (`--allow-cross-flash`).
    pub allow_cross_flash: bool,
}

/// Evaluate the safety gate. `Ok(())` means the flash may proceed.
///
/// An empty `firmware_model` cannot be cross-checked, so cross-flash is only
/// blocked when a model was detected and it does not match the drive.
pub fn check_safety(ctx: &SafetyContext<'_>) -> Result<(), SafetyBlock> {
    if !ctx.acknowledged_risk {
        return Err(SafetyBlock(
            "refusing to flash without --i-understand-risk (flashing can permanently brick the drive)"
                .to_string(),
        ));
    }
    if !ctx.firmware_model.is_empty() && !ctx.allow_cross_flash {
        let matches = ctx.drive_model.eq_ignore_ascii_case(ctx.firmware_model)
            || ctx.drive_model.contains(ctx.firmware_model)
            || ctx.firmware_model.contains(ctx.drive_model);
        if !matches {
            return Err(SafetyBlock(format!(
                "drive model '{}' does not match firmware model '{}'; refuse cross-flash without --allow-cross-flash",
                ctx.drive_model, ctx.firmware_model
            )));
        }
    }
    Ok(())
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

    fn dump(&self, dev: &mut dyn ScsiDevice, out: &Path) -> Result<()> {
        let dump = dump_user(dev)?;
        for (name, data) in dump.members() {
            println!("  {name:<16} {} bytes", data.len());
        }
        let tar = dump.to_tar_bytes()?;
        std::fs::write(out, &tar).with_context(|| format!("writing {}", out.display()))?;
        if let Some(sn) = parse_field_descriptor(&dump.fd_sn) {
            println!("serial:  {}", sn.ascii);
        }
        if let Some(fw) = parse_field_descriptor(&dump.fd_fwdate) {
            println!("fw-date: {}", fw.ascii);
        }
        println!("wrote {} ({} bytes, 6 members).", out.display(), tar.len());
        Ok(())
    }

    fn flash(&self, dev: &mut dyn ScsiDevice, req: &FlashRequest) -> Result<()> {
        run_flash(dev, req)
    }
}

/// Orchestrate the MTK flash (or dry-run): dump-first, splice, downgrade,
/// stream, verify. See the module docs and the design's "flash transport".
fn run_flash(dev: &mut dyn ScsiDevice, req: &FlashRequest) -> Result<()> {
    match req.input_kind {
        InputKind::Tar => flash_from_tar(dev, req),
        InputKind::Bin => flash_from_bin(dev, req),
    }
}

/// Restore per-unit regions from a `.tar` (targeted writes, not a full stream).
fn flash_from_tar(dev: &mut dyn ScsiDevice, req: &FlashRequest) -> Result<()> {
    let dump = UserDump::from_tar_bytes(&req.input).context("parsing .tar restore input")?;
    println!("== flash plan (restore from .tar) ==");
    println!(
        "restore rom_1EC000: 0x{:06X} ({} B)",
        ROM_1EC000_OFFSET,
        dump.rom_1ec000.len()
    );
    println!(
        "restore rom_1F0000: 0x{:06X} ({} B)",
        ROM_1F0000_OFFSET,
        dump.rom_1f0000.len()
    );

    if !req.execute {
        println!("\nDRY RUN: no SCSI writes issued. Re-run with --execute to restore.");
        return Ok(());
    }
    if !req.acknowledged_risk {
        bail!("refusing to write without --i-understand-risk");
    }

    let regions = [
        (ROM_1EC000_OFFSET, &dump.rom_1ec000),
        (ROM_1F0000_OFFSET, &dump.rom_1f0000),
    ];
    println!("\nEXECUTING restore — do not power off or disconnect the drive...");
    for (offset, data) in regions {
        let cdb = cdb_write_buffer(MODE_6, FLASH_BUFFER_ID, offset, data.len() as u32, false);
        dev.command_out(&cdb, data)?;
        let rb = cdb_read_buffer(MODE_6, FLASH_BUFFER_ID, offset, data.len() as u32);
        let got = dev.command_in(&rb, data.len())?;
        if got != *data {
            bail!("read-back verify failed for region 0x{offset:06X}");
        }
    }
    println!("restore complete and verified.");
    Ok(())
}

/// Flash a full `.bin` image VERBATIM: dump-first (backup only), stream, verify.
fn flash_from_bin(dev: &mut dyn ScsiDevice, req: &FlashRequest) -> Result<()> {
    if req.input.len() != IMAGE_SIZE {
        bail!(
            "firmware .bin must be exactly {IMAGE_SIZE} bytes, got {}",
            req.input.len()
        );
    }

    // ALWAYS attempt a pre-flash dump (backup ONLY — never spliced into the
    // image). On failure, abort unless --rescue-no-dump.
    let mut backup_summary = String::from("skipped (--rescue-no-dump)");
    match dump_user(dev) {
        Ok(dump) => {
            if let Some(out) = &req.predump_out {
                let tar = dump.to_tar_bytes()?;
                std::fs::write(out, &tar)
                    .with_context(|| format!("saving pre-flash dump to {}", out.display()))?;
                backup_summary = format!("saved {} ({} bytes)", out.display(), tar.len());
            } else {
                backup_summary = "captured (not saved: no -o given)".to_string();
            }
        }
        Err(e) => {
            if !req.rescue_no_dump {
                bail!(
                    "pre-flash per-unit dump failed ({e}); aborting. \
                     Use --rescue-no-dump ONLY to flash a drive that can no longer be read."
                );
            }
            println!("WARNING: pre-flash dump failed ({e}); --rescue-no-dump: proceeding without a backup.");
        }
    }

    // enc decision: always auto-detected; --enc/--no-enc is a hidden override.
    let enc = req.enc_override.unwrap_or_else(|| enc_needed(dev));
    let commit = req.mode == crate::manifest::FlashMode::Full;
    let plan = FlashPlan::prepare(&req.input, commit, enc)?;

    println!("== flash plan (verbatim) ==");
    println!("device:         {}", dev.describe());
    println!("drive model:    {}", ident_or_unknown(&req.drive_model));
    println!("mode:           {:?}", req.mode);
    println!("pre-flash dump: {backup_summary}");
    println!(
        "envelope:       {}",
        if enc {
            "enc (AES-128-ECB)"
        } else {
            "plaintext"
        }
    );
    println!(
        "stream range:   0x000000-0x1FFFFF in {} chunk(s) of {} B (commit={})",
        plan.chunk_count(),
        plan.chunk,
        commit
    );

    if !req.execute {
        println!("\nDRY RUN: no SCSI writes issued. Re-run with --execute to flash.");
        return Ok(());
    }

    // Full safety gate only on the write path. The image is not modified, so the
    // cross-flash model check is caller-supplied (empty => cannot cross-check).
    let ctx = SafetyContext {
        drive_model: &req.drive_model,
        firmware_model: &req.firmware_model,
        acknowledged_risk: req.acknowledged_risk,
        allow_cross_flash: req.allow_cross_flash,
    };
    if let Err(block) = check_safety(&ctx) {
        bail!("SAFETY GATE: {}", block.0);
    }

    println!("\nEXECUTING flash — do not power off or disconnect the drive...");
    plan.execute(dev)?;
    println!(
        "stream complete ({} bytes); verifying...",
        plan.payload.len()
    );
    plan.verify_readback(dev)?;
    println!("flash complete and read-back verified.");
    Ok(())
}

fn ident_or_unknown(s: &str) -> &str {
    if s.is_empty() {
        "<unknown>"
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::MockScsiDevice;

    fn full_image(fill: u8) -> Vec<u8> {
        vec![fill; IMAGE_SIZE]
    }

    fn sample_dump(a: u8, b: u8) -> UserDump {
        UserDump {
            rom_003000: vec![0; ROM_003000_LEN as usize],
            rom_1ec000: vec![a; ROM_1EC000_LEN as usize],
            rom_1f0000: vec![b; ROM_1F0000_LEN as usize],
            inq: vec![0; 96],
            fd_fwdate: vec![0; 28],
            fd_sn: vec![0; 28],
        }
    }

    #[test]
    fn read_buffer_cdb_layouts() {
        assert_eq!(
            cdb_read_buffer(MODE_6, ROM_BUFFER_ID, 0x1EC000, 0x100),
            [0x3C, 0x06, 0x00, 0x1E, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn write_buffer_commit_flag() {
        assert_eq!(cdb_write_buffer(0x06, 0, 0x8000, 0x8000, false)[9], 0x00);
        assert_eq!(cdb_write_buffer(0x06, 0, 0x8000, 0x8000, true)[9], 0x01);
    }

    #[test]
    fn get_config_cdb_layouts() {
        assert_eq!(
            cdb_get_config(FEATURE_FWDATE, FD_LEN),
            [0x46, 0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00]
        );
    }

    #[test]
    fn dump_plan_issues_expected_cdbs() {
        let mut dev = MockScsiDevice::new();
        let dump = DumpPlan::new().execute(&mut dev).unwrap();
        assert_eq!(dump.rom_1ec000.len(), 0x100);
        assert_eq!(dump.rom_1f0000.len(), 0x10000);
        assert_eq!(dev.reads.len(), 6);
        assert_eq!(dev.reads[0][0], 0x3C);
        assert_eq!(dev.reads[3][0], 0x12);
        assert_eq!(&dev.reads[4][2..4], &[0x01, 0x0C]);
        assert_eq!(&dev.reads[5][2..4], &[0x01, 0x08]);
    }

    #[test]
    fn enc_transform_roundtrips_and_needs_block_multiple() {
        let mut short = vec![0u8; 17];
        assert!(enc_transform(&mut short).is_err());
        let mut block = vec![0u8; 16];
        enc_transform(&mut block).unwrap();
        assert_ne!(block, vec![0u8; 16]);
    }

    #[test]
    fn enc_needed_defaults_to_plaintext() {
        let mut dev = MockScsiDevice::new();
        assert!(
            !enc_needed(&mut dev),
            "enc must default off until research lands"
        );
    }

    fn bin_req(image: Vec<u8>, execute: bool) -> FlashRequest {
        FlashRequest {
            input: image,
            input_kind: InputKind::Bin,
            mode: crate::manifest::FlashMode::Full,
            execute,
            rescue_no_dump: false,
            allow_cross_flash: false,
            acknowledged_risk: execute,
            enc_override: None,
            drive_model: "BU40N".into(),
            firmware_model: String::new(),
            predump_out: None,
        }
    }

    #[test]
    fn flash_dry_run_writes_nothing_but_reads_for_backup_dump() {
        let mut dev = MockScsiDevice::new();
        let req = bin_req(full_image(0x11), false);
        run_flash(&mut dev, &req).unwrap();
        // Dry run performs the pre-flash read-only backup dump but issues NO writes.
        assert!(dev.writes.is_empty(), "dry-run must not write");
        assert!(
            !dev.reads.is_empty(),
            "dry-run still reads for the backup + plan"
        );
    }

    #[test]
    fn flash_rejects_wrong_size_bin() {
        let mut dev = MockScsiDevice::new();
        let req = bin_req(vec![0u8; 1024], false);
        assert!(run_flash(&mut dev, &req).is_err());
    }

    #[test]
    fn flash_execute_streams_verbatim_and_verifies() {
        // All-zero plaintext image so the mock's zero-fill read-back matches.
        let mut dev = MockScsiDevice::new();
        let req = bin_req(full_image(0x00), true);
        run_flash(&mut dev, &req).unwrap();
        // 2 MB / 32 KiB = 64 write chunks, all WRITE_BUFFER (0x3B).
        assert_eq!(dev.writes.len(), IMAGE_SIZE / DEFAULT_CHUNK);
        assert!(dev.writes.iter().all(|(cdb, _)| cdb[0] == 0x3B));
        // The bytes streamed are the verbatim image (unmodified).
        assert!(dev
            .writes
            .iter()
            .all(|(_, data)| data.iter().all(|&b| b == 0)));
    }

    #[test]
    fn safety_requires_ack_and_blocks_mismatch() {
        let no_ack = SafetyContext {
            drive_model: "BU40N",
            firmware_model: "BU40N",
            acknowledged_risk: false,
            allow_cross_flash: false,
        };
        assert!(check_safety(&no_ack).is_err());

        let mismatch = SafetyContext {
            drive_model: "BU40N",
            firmware_model: "WH16NS60",
            acknowledged_risk: true,
            allow_cross_flash: false,
        };
        assert!(check_safety(&mismatch).is_err());
        let allowed = SafetyContext {
            allow_cross_flash: true,
            ..mismatch
        };
        assert!(check_safety(&allowed).is_ok());
    }

    #[test]
    fn tar_round_trip() {
        let dump = sample_dump(0x22, 0x33);
        let bytes = dump.to_tar_bytes().unwrap();
        assert_eq!(UserDump::from_tar_bytes(&bytes).unwrap(), dump);
    }

    #[test]
    fn parse_field_descriptor_serial() {
        let mut data = vec![
            0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x03, 0x10,
        ];
        data.extend_from_slice(b"009HANK118975   ");
        let fd = parse_field_descriptor(&data).unwrap();
        assert_eq!(fd.feature, FEATURE_SERIAL);
        assert_eq!(fd.ascii, "009HANK118975");
    }
}
