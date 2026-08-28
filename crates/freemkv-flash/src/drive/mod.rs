//! Chip-family layer: classification + per-family dump/flash logic.
//!
//! This is the second of the two independent plug-in layers (the other is
//! [`crate::platform`]). [`classify`] identifies the silicon [`Family`] using
//! only proven discriminators; [`for_family`] returns the matching
//! [`DriveFamily`] implementation. Only [`mtk`] is fully implemented; the
//! others classify positive but return `Unsupported` from dump/flash.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;

pub mod mtk;
pub mod pioneer;
pub mod renesas;

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

fn trim_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string()
}

/// Read INQUIRY + boot banner for the `info` command (best-effort).
pub fn identity(dev: &mut dyn ScsiDevice) -> Identity {
    let mut id = Identity::default();
    if let Ok(data) = dev.command_in(&mtk::cdb_inquiry(96), 96) {
        if data.len() >= 36 {
            id.vendor = trim_ascii(&data[8..16]);
            id.product = trim_ascii(&data[16..32]);
            id.revision = trim_ascii(&data[32..36]);
        }
    }
    let cdb = mtk::cdb_read_buffer(mtk::MODE_6, mtk::ROM_BUFFER_ID, 0x3000, 64);
    if let Ok(data) = dev.command_in(&cdb, 64) {
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
pub fn sniff_input(path: &Path) -> InputKind {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("tar") => InputKind::Tar,
        _ => InputKind::Bin,
    }
}

/// A fully-resolved flash request handed to a [`DriveFamily`].
#[derive(Debug, Clone)]
pub struct FlashRequest {
    /// The raw input file bytes.
    pub input: Vec<u8>,
    /// Whether the input is a full `.bin` or a per-unit `.tar`.
    pub input_kind: InputKind,
    /// Streaming mode (`main` vs `full` commit flag).
    pub mode: FlashMode,
    /// Actually issue writes (otherwise dry-run).
    pub execute: bool,
    /// Allow flashing without a successful pre-flash backup dump.
    pub rescue_no_dump: bool,
    /// Permit a drive/firmware model mismatch.
    pub allow_cross_flash: bool,
    /// User acknowledged the bricking risk.
    pub acknowledged_risk: bool,
    /// Hidden expert override for the enc envelope (`Some(true/false)` forces).
    pub enc_override: Option<bool>,
    /// Drive model (INQUIRY product) for the safety gate.
    pub drive_model: String,
    /// Firmware model detected out-of-band (empty => no cross-check).
    pub firmware_model: String,
    /// Where to save the pre-flash backup dump, if anywhere.
    pub predump_out: Option<PathBuf>,
}

/// A chip family's dump/flash behaviour.
pub trait DriveFamily {
    /// The family this implementation handles.
    fn family(&self) -> Family;
    /// Whether dump/flash are actually implemented (only MTK today).
    fn is_supported(&self) -> bool;
    /// Read the per-unit regions and write an interoperable `.tar` to `out`.
    fn dump(&self, dev: &mut dyn ScsiDevice, out: &Path) -> Result<()>;
    /// Flash `req` to the drive (or print a dry-run plan).
    fn flash(&self, dev: &mut dyn ScsiDevice, req: &FlashRequest) -> Result<()>;
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

/// Fallback family for [`Family::Unknown`]: refuses everything.
struct UnknownFamily;

impl DriveFamily for UnknownFamily {
    fn family(&self) -> Family {
        Family::Unknown
    }
    fn is_supported(&self) -> bool {
        false
    }
    fn dump(&self, _dev: &mut dyn ScsiDevice, _out: &Path) -> Result<()> {
        bail!("{}", unsupported_family_error(Family::Unknown))
    }
    fn flash(&self, _dev: &mut dyn ScsiDevice, _req: &FlashRequest) -> Result<()> {
        bail!("{}", unsupported_family_error(Family::Unknown))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::MockScsiDevice;

    #[test]
    fn classify_mtk_from_get_config_010c() {
        let mut dev = MockScsiDevice::mtk();
        assert_eq!(classify(&mut dev), Family::Mtk);
    }

    #[test]
    fn classify_pioneer_from_read_buffer_f1() {
        let mut dev = MockScsiDevice::pioneer();
        assert_eq!(classify(&mut dev), Family::Pioneer);
    }

    #[test]
    fn classify_unknown_when_no_discriminator() {
        // Empty mock: GET_CONFIG zero-fills (no 01 0C), RB-0xF1 zero-fills.
        let mut dev = MockScsiDevice::new();
        assert_eq!(classify(&mut dev), Family::Unknown);
    }

    #[test]
    fn sniff_picks_tar_vs_bin() {
        assert_eq!(sniff_input(Path::new("dump.tar")), InputKind::Tar);
        assert_eq!(sniff_input(Path::new("fw.bin")), InputKind::Bin);
        assert_eq!(sniff_input(Path::new("image")), InputKind::Bin);
    }

    #[test]
    fn mtk_gate_blocks_non_mtk_dump_and_flash() {
        for fam in [Family::Pioneer, Family::Renesas, Family::Unknown] {
            let handler = for_family(fam);
            assert!(!handler.is_supported());
            let mut dev = MockScsiDevice::new();
            assert!(handler.dump(&mut dev, Path::new("/dev/null")).is_err());
            // No dump/flash CDBs may have been issued on the gated path.
            assert!(dev.writes.is_empty());
        }
    }
}
