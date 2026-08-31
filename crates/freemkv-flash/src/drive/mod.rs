//! Chip-family layer: classification + the per-family command trait.
//!
//! This is one of the two independent plug-in layers (the other is
//! [`crate::platform`]). [`classify`] identifies the silicon [`Family`] using
//! only proven discriminators; [`for_family`] returns the matching
//! [`DriveFamily`] implementation.
//!
//! A [`DriveFamily`] exposes **only chip primitives** — identity, per-unit dump
//! capture, and the flash open/chunk/close/read-back steps. It does no file
//! I/O and prints nothing. The generic orchestration (reading the input file,
//! the pre-flash backup, the dry-run plan, the streaming loop, verification, and
//! the safety gate) lives once in [`crate::engine`] and drives any family
//! through this trait. Only [`mtk`] is fully implemented; the others classify
//! positive but return `Unsupported`.

use anyhow::Result;

use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;

pub mod fw_ident;
pub mod mtk;
pub mod pioneer;
pub mod renesas;

pub use mtk::UserDump;

/// A full firmware read: `(image, readable byte count, not-exposed `(start,end)`
/// gaps)`. The image is the whole [`DriveFamily::image_size`] span; every offset
/// a drive doesn't map to a read is filled (e.g. `0xFF`) and recorded as a gap.
/// (Aliased so the trait signature stays under clippy's complex-type lint.)
pub type FullImage = (Vec<u8>, usize, Vec<(usize, usize)>);

/// The silicon family of a connected optical drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// MediaTek MT19xx (MT1959 / MT1939). Supported.
    Mtk,
    /// Pioneer silicon. Classified, not supported.
    Pioneer,
    /// HL-DT-ST / Renesas silicon. Classified, not supported.
    Renesas,
    /// Could not be classified. Fail-safe: never flashed.
    Unknown,
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Family::Mtk => "MediaTek MT19xx",
            Family::Pioneer => "Pioneer",
            Family::Renesas => "Renesas",
            Family::Unknown => "Unknown",
        })
    }
}

/// Standard INQUIRY identity fields plus the boot banner, for `info`.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// T10 vendor id (INQUIRY bytes 8..16), trimmed.
    pub vendor: String,
    /// Product id (INQUIRY bytes 16..32), trimmed.
    pub product: String,
    /// Product revision (INQUIRY bytes 32..36), trimmed.
    pub revision: String,
    /// "MT19xx Boot" banner (READ BUFFER mode 6 @ 0x3000), if any.
    pub banner: Option<String>,
}

pub(crate) fn trim_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string()
}

/// Sanitize a drive-supplied ASCII string for safe display: keeps printable
/// bytes (0x20..=0x7e) and replaces everything else (including terminal
/// control/escape sequences a malicious or malfunctioning drive could return)
/// with `.`.
pub(crate) fn sanitize_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            if ('\u{20}'..='\u{7e}').contains(&c) {
                c
            } else {
                '.'
            }
        })
        .collect()
}

/// Read INQUIRY + boot banner for the `info` command (best-effort).
pub fn read_identity(dev: &mut dyn ScsiDevice) -> Identity {
    let mut id = Identity::default();
    if let Ok(data) = dev.command_in(&mtk::cdb_inquiry(96), 96) {
        if data.len() >= 36 {
            id.vendor = sanitize_ascii(&trim_ascii(&data[8..16]));
            id.product = sanitize_ascii(&trim_ascii(&data[16..32]));
            id.revision = sanitize_ascii(&trim_ascii(&data[32..36]));
        }
    }
    // The 0x3000 ROM buffer is exactly ROM_003000_LEN (32 B); asking for more
    // makes the drive reject the read with ILLEGAL REQUEST (invalid field in
    // CDB), which is why the banner previously always came back empty.
    let cdb = mtk::cdb_read_buffer(
        mtk::MODE_6,
        mtk::ROM_BUFFER_ID,
        mtk::ROM_003000_OFFSET,
        mtk::ROM_003000_LEN,
    );
    if let Ok(data) = dev.command_in(&cdb, mtk::ROM_003000_LEN as usize) {
        let end = data
            .iter()
            .position(|&b| b == 0 || !(0x20..0x7f).contains(&b))
            .unwrap_or(data.len());
        let banner = trim_ascii(&data[..end]);
        if !banner.is_empty() {
            id.banner = Some(banner);
        }
    }
    id
}

/// Classify a drive using only proven discriminators.
///
/// * GET_CONFIG 0x46 feature 0x010C echoing `01 0C` ⇒ [`Family::Mtk`].
/// * READ_BUFFER buffer-id 0xF1 succeeding ⇒ Pioneer / Renesas (an INQUIRY
///   vendor of `RENESAS` picks Renesas; otherwise Pioneer).
/// * neither ⇒ [`Family::Unknown`].
pub fn classify(dev: &mut dyn ScsiDevice) -> Family {
    if get_config_is_mtk(dev) {
        return Family::Mtk;
    }
    if read_buffer_f1_ok(dev) {
        if let Ok(data) = dev.command_in(&mtk::cdb_inquiry(96), 96) {
            if data.len() >= 16 && trim_ascii(&data[8..16]).eq_ignore_ascii_case("RENESAS") {
                return Family::Renesas;
            }
        }
        return Family::Pioneer;
    }
    Family::Unknown
}

fn get_config_is_mtk(dev: &mut dyn ScsiDevice) -> bool {
    let cdb = mtk::cdb_get_config(mtk::FEATURE_FWDATE, 32);
    matches!(dev.command_in(&cdb, 32), Ok(d) if d.len() >= 10 && d[8] == 0x01 && d[9] == 0x0C)
}

fn read_buffer_f1_ok(dev: &mut dyn ScsiDevice) -> bool {
    let cdb = mtk::cdb_read_buffer(0x00, 0xF1, 0x0000, 8);
    matches!(dev.command_in(&cdb, 8), Ok(d) if d.iter().any(|&b| b != 0))
}

/// How the flash input file was sniffed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// A full 2 MB firmware image.
    Bin,
    /// A per-unit dump tar (restore those regions).
    Tar,
}

/// Sniff the flash input kind from a path's extension (`.tar` => tar, else bin).
pub fn sniff_input(path: &std::path::Path) -> InputKind {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("tar") => InputKind::Tar,
        _ => InputKind::Bin,
    }
}

/// A fully-resolved flash request handed to [`crate::engine`].
#[derive(Debug, Clone)]
pub struct FlashRequest {
    /// The raw input file bytes.
    pub input: Vec<u8>,
    /// Whether the input is a full `.bin` or a per-unit `.tar`.
    pub input_kind: InputKind,
    /// Streaming mode (`main` vs `full`). NOTE: on MTK (the only implemented
    /// family) this is currently informational only — the full 2 MiB image is
    /// always streamed and the commit handshake is always sent regardless of
    /// which mode is selected.
    pub mode: FlashMode,
    /// Actually issue writes (otherwise dry-run).
    pub execute: bool,
    /// Allow flashing without a successful pre-flash backup dump.
    pub rescue_no_dump: bool,
    /// User acknowledged the bricking risk.
    pub acknowledged_risk: bool,
    /// Hidden expert override for the enc envelope (`Some(true/false)` forces).
    pub enc_override: Option<bool>,
    /// Drive model (INQUIRY product), shown in the flash plan.
    pub drive_model: String,
    /// Show the raw SCSI CDB sequence in the plan (default: clean summary only).
    pub verbose: bool,
    /// Where to save the pre-flash backup dump, if anywhere.
    pub predump_out: Option<std::path::PathBuf>,
}

/// A per-unit region to restore from a `.tar` dump (targeted write).
#[derive(Debug, Clone, Copy)]
pub struct RestoreRegion<'a> {
    /// Human label (the tar member name).
    pub label: &'static str,
    /// Absolute ROM offset the region is written to.
    pub offset: u32,
    /// The region bytes.
    pub bytes: &'a [u8],
}

/// A chip family's command primitives.
///
/// Every method is a pure chip operation — no file I/O, no printing. The
/// generic [`crate::engine`] composes these into the `info` / `dump` / `flash`
/// commands. A new family only has to supply its own CDBs; the engine loop is
/// unchanged.
pub trait DriveFamily {
    /// The family this implementation handles.
    fn family(&self) -> Family;

    /// Whether the WRITE (flash) path is actually implemented (only MTK today).
    fn is_supported(&self) -> bool;

    /// Whether the read-only DUMP path is implemented. Dump is a strict subset
    /// of full support: Pioneer/Renesas can dump (read-only) without allowing
    /// flash. Defaults to [`Self::is_supported`], so a fully-supported family
    /// dumps and an unsupported stub does neither.
    fn dump_supported(&self) -> bool {
        self.is_supported()
    }

    /// Read INQUIRY + boot banner (the `info` primitive). Standard for all
    /// families, so provided by default.
    fn identity(&self, dev: &mut dyn ScsiDevice) -> Identity {
        read_identity(dev)
    }

    /// Capture the per-unit backup regions (the `dump` primitive).
    fn read_dump(&self, dev: &mut dyn ScsiDevice) -> Result<UserDump>;

    /// Read the entire firmware image (the `dump --everything` primitive):
    /// `(image, readable_bytes, gaps)`, graceful — any offset the drive doesn't
    /// expose is filled and recorded as a gap. Read-only.
    ///
    /// Default: an "unsupported" error, so a family with no full-image read path
    /// makes the engine omit `firmware.bin` from the dump rather than panic.
    fn read_full_image(&self, _dev: &mut dyn ScsiDevice) -> Result<FullImage> {
        Err(anyhow::anyhow!(
            "full-image dump not supported for the {} family",
            self.family()
        ))
    }

    /// Build the read-surface map (`map.json` + `map.md`) for the `dump`
    /// everything-tar, from an ALREADY-READ `image` and its `gaps` (from
    /// [`Self::read_full_image`]) plus the `ident` header. Read-only.
    ///
    /// Default: `Ok(None)` — a family with no surface map simply omits it from
    /// the dump tar.
    fn read_surface_map(
        &self,
        _dev: &mut dyn ScsiDevice,
        _ident: &Identity,
        _image: &[u8],
        _gaps: &[(usize, usize)],
    ) -> Result<Option<(String, String)>> {
        Ok(None)
    }

    /// Full firmware image size in bytes (e.g. 2 MiB).
    fn image_size(&self) -> usize;

    /// Streaming chunk size in bytes (e.g. 16 KiB).
    fn chunk_size(&self) -> usize;

    /// Envelope the whole image before streaming. Returns the payload bytes and
    /// whether the enc wrap was applied.
    fn envelope(
        &self,
        dev: &mut dyn ScsiDevice,
        image: &[u8],
        enc_override: Option<bool>,
    ) -> Result<(Vec<u8>, bool)>;

    /// Human-readable dry-run plan for an `image_len`-byte flash. `verbose` adds
    /// the raw SCSI CDB sequence; the default is a clean plain-language summary.
    fn flash_plan(&self, image_len: usize, verbose: bool) -> Result<String>;

    /// Wait (read-only, bounded) for the drive to finish programming after the
    /// last chunk, before read-back verify. Default: no wait.
    fn wait_ready(&self, _dev: &mut dyn ScsiDevice) -> Result<()> {
        Ok(())
    }

    /// Read-only readiness handshake (PROBE + TEST UNIT READY) — issues NO write.
    /// The engine runs this during a dry-run so a not-ready drive is surfaced
    /// before the operator commits to `--execute`. Default: no-op.
    fn preflight(&self, _dev: &mut dyn ScsiDevice) -> Result<()> {
        Ok(())
    }

    /// Identify the installed firmware (read-only) by reading the two readable
    /// firmware-code windows and matching the built-in catalog. Default: none.
    fn firmware_report(&self, _dev: &mut dyn ScsiDevice) -> Result<Option<fw_ident::FwReport>> {
        Ok(None)
    }

    /// Open a flash session (preflight + prepare). One data-out command.
    fn flash_open(&self, dev: &mut dyn ScsiDevice, mode: FlashMode) -> Result<()>;

    /// Stream one chunk at absolute `offset`.
    fn flash_chunk(&self, dev: &mut dyn ScsiDevice, offset: usize, bytes: &[u8]) -> Result<()>;

    /// Close a flash session (commit + ready + status).
    fn flash_close(&self, dev: &mut dyn ScsiDevice, mode: FlashMode) -> Result<()>;

    /// Read back `len` bytes at `offset` (the engine uses this for verify).
    fn readback(&self, dev: &mut dyn ScsiDevice, offset: usize, len: usize) -> Result<Vec<u8>>;

    /// Map a per-unit dump onto the targeted regions a `.tar` restore writes.
    fn restore_regions<'a>(&self, dump: &'a UserDump) -> Vec<RestoreRegion<'a>>;

    /// Write one targeted region verbatim (the `.tar` restore primitive).
    fn write_region(&self, dev: &mut dyn ScsiDevice, offset: u32, bytes: &[u8]) -> Result<()>;
}

/// Return the [`DriveFamily`] implementation for a classified [`Family`].
pub fn for_family(family: Family) -> Box<dyn DriveFamily> {
    match family {
        Family::Mtk => Box::new(mtk::Mtk),
        Family::Pioneer => Box::new(pioneer::Pioneer),
        Family::Renesas => Box::new(renesas::Renesas),
        Family::Unknown => Box::new(UnknownFamily),
    }
}

/// The MTK-gate error message, shared by `dump` and `flash`.
pub fn unsupported_family_error(family: Family) -> anyhow::Error {
    anyhow::anyhow!(
        "This is a {family} drive. freemkv-flash currently supports MediaTek MT19xx only. \
         Aborting — no commands sent."
    )
}

/// Implement [`DriveFamily`] for a classified-but-unsupported family: every
/// command that would touch the drive returns the MTK-gate error, so no dump or
/// flash CDB is ever issued. Used by the Pioneer / Renesas / Unknown stubs.
#[macro_export]
macro_rules! unsupported_drive_family {
    ($ty:ty, $family:expr) => {
        impl $crate::drive::DriveFamily for $ty {
            fn family(&self) -> $crate::drive::Family {
                $family
            }
            fn is_supported(&self) -> bool {
                false
            }
            fn read_dump(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
            ) -> ::anyhow::Result<$crate::drive::UserDump> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn image_size(&self) -> usize {
                0
            }
            fn chunk_size(&self) -> usize {
                0
            }
            fn envelope(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _image: &[u8],
                _enc_override: ::core::option::Option<bool>,
            ) -> ::anyhow::Result<(::std::vec::Vec<u8>, bool)> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_plan(
                &self,
                _image_len: usize,
                _verbose: bool,
            ) -> ::anyhow::Result<::std::string::String> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_open(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _mode: $crate::manifest::FlashMode,
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_chunk(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: usize,
                _bytes: &[u8],
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_close(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _mode: $crate::manifest::FlashMode,
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn readback(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: usize,
                _len: usize,
            ) -> ::anyhow::Result<::std::vec::Vec<u8>> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn restore_regions<'a>(
                &self,
                _dump: &'a $crate::drive::UserDump,
            ) -> ::std::vec::Vec<$crate::drive::RestoreRegion<'a>> {
                ::std::vec::Vec::new()
            }
            fn write_region(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: u32,
                _bytes: &[u8],
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
        }
    };
}

/// Fallback family for [`Family::Unknown`]: refuses everything.
struct UnknownFamily;
unsupported_drive_family!(UnknownFamily, Family::Unknown);

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
