//! Optical-drive detection and platform classification.
//!
//! Detection primitives (implemented over the [`ScsiDevice`] trait so the CDB
//! construction is transport-independent and unit-testable):
//!
//! * `INQUIRY` (0x12) — vendor / product / revision strings.
//! * `GET CONFIGURATION` (0x46) feature `0x010C` — MediaTek drives return a
//!   populated vendor descriptor; the chip-id string region lives inside it.
//! * `READ BUFFER` (0x3C) mode 6, offset `0x3000` — the "MT19xx Boot" banner.
//!   The banner text (`MT1959` vs `MT1939`) is the platform-A / platform-B
//!   discriminator.
//! * Pioneer `READ BUFFER` (0x3C) mode 0, buffer id `0xF1` — Pioneer/Renesas
//!   vendor probe.

use anyhow::Result;

use crate::scsi::ScsiDevice;

/// Coarse silicon platform of a connected drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipClass {
    /// MediaTek MT1959 (platform A).
    MediaTekMt1959,
    /// MediaTek MT1939 (platform B).
    MediaTekMt1939,
    /// Pioneer / Renesas silicon.
    PioneerRenesas,
    /// Could not be classified. Fail-safe: never flash an Unknown.
    Unknown,
}

impl std::fmt::Display for ChipClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ChipClass::MediaTekMt1959 => "MediaTek MT1959 (platform A)",
            ChipClass::MediaTekMt1939 => "MediaTek MT1939 (platform B)",
            ChipClass::PioneerRenesas => "Pioneer/Renesas",
            ChipClass::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

/// Standard INQUIRY fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InquiryData {
    /// T10 vendor identification (bytes 8..16), trimmed.
    pub vendor: String,
    /// Product identification (bytes 16..32), trimmed.
    pub product: String,
    /// Product revision level (bytes 32..36), trimmed.
    pub revision: String,
}

/// Everything a probe managed to collect from a drive.
#[derive(Debug, Clone, Default)]
pub struct DriveProbe {
    /// INQUIRY result, if it succeeded.
    pub inquiry: Option<InquiryData>,
    /// Chip-id string extracted from GET CONFIGURATION 0x010C, if present.
    pub chip_id: Option<String>,
    /// "MT19xx Boot" banner read from READ BUFFER mode 6 @ 0x3000, if present.
    pub boot_banner: Option<String>,
    /// Whether the Pioneer RB-0xF1 vendor probe returned data.
    pub pioneer_vendor: bool,
}

// ---- CDB builders (pure, testable) ------------------------------------------

/// Build a standard INQUIRY CDB (opcode 0x12) for `alloc_len` bytes.
pub fn cdb_inquiry(alloc_len: u16) -> [u8; 6] {
    [
        0x12,
        0x00,
        0x00,
        (alloc_len >> 8) as u8,
        (alloc_len & 0xff) as u8,
        0x00,
    ]
}

/// Build a GET CONFIGURATION CDB (opcode 0x46) for a single `feature`.
///
/// RT field = 0x02 (return only the named feature descriptor).
pub fn cdb_get_config(feature: u16, alloc_len: u16) -> [u8; 10] {
    [
        0x46,
        0x02,
        (feature >> 8) as u8,
        (feature & 0xff) as u8,
        0x00,
        0x00,
        0x00,
        (alloc_len >> 8) as u8,
        (alloc_len & 0xff) as u8,
        0x00,
    ]
}

/// Build a READ BUFFER CDB (opcode 0x3C).
///
/// `mode` is the low 5 bits of byte 1, `buffer_id` byte 2, `offset` bytes 3..6,
/// `alloc_len` bytes 6..9.
pub fn cdb_read_buffer(mode: u8, buffer_id: u8, offset: u32, alloc_len: u32) -> [u8; 10] {
    [
        0x3C,
        mode & 0x1f,
        buffer_id,
        (offset >> 16) as u8,
        (offset >> 8) as u8,
        offset as u8,
        (alloc_len >> 16) as u8,
        (alloc_len >> 8) as u8,
        alloc_len as u8,
        0x00,
    ]
}

// ---- Probes -----------------------------------------------------------------

fn trim_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string()
}

/// Run INQUIRY and parse the standard identification fields.
pub fn probe_inquiry(dev: &mut dyn ScsiDevice) -> Result<InquiryData> {
    let data = dev.command_in(&cdb_inquiry(96), 96)?;
    Ok(parse_inquiry(&data))
}

/// Parse a standard INQUIRY data buffer.
pub fn parse_inquiry(data: &[u8]) -> InquiryData {
    let get = |a: usize, b: usize| {
        if data.len() >= b {
            trim_ascii(&data[a..b])
        } else {
            String::new()
        }
    };
    InquiryData {
        vendor: get(8, 16),
        product: get(16, 32),
        revision: get(32, 36),
    }
}

/// Read the "MT19xx Boot" banner via READ BUFFER mode 6 @ 0x3000.
pub fn probe_boot_banner(dev: &mut dyn ScsiDevice) -> Result<String> {
    let cdb = cdb_read_buffer(0x06, 0x00, 0x3000, 64);
    let data = dev.command_in(&cdb, 64)?;
    Ok(extract_banner(&data))
}

/// Extract the printable ASCII banner from a READ BUFFER response.
pub fn extract_banner(data: &[u8]) -> String {
    let end = data
        .iter()
        .position(|&b| b == 0 || !(0x20..0x7f).contains(&b))
        .unwrap_or(data.len());
    trim_ascii(&data[..end])
}

/// Attempt the GET CONFIGURATION 0x010C vendor probe and extract a chip-id.
pub fn probe_chip_id(dev: &mut dyn ScsiDevice) -> Result<Option<String>> {
    let cdb = cdb_get_config(0x010C, 256);
    let data = dev.command_in(&cdb, 256)?;
    Ok(extract_chip_id(&data))
}

/// Pull the longest printable-ASCII run (>= 4 chars) out of a GET CONFIG
/// feature descriptor as the candidate chip-id string.
pub fn extract_chip_id(data: &[u8]) -> Option<String> {
    // Skip the 8-byte GET CONFIG header + 4-byte feature header if present.
    let start = 12.min(data.len());
    let mut best = String::new();
    let mut cur = String::new();
    for &b in &data[start..] {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() > best.len() {
                best = cur.clone();
            }
            cur.clear();
        }
    }
    if cur.len() > best.len() {
        best = cur;
    }
    let best = best.trim().to_string();
    if best.len() >= 4 {
        Some(best)
    } else {
        None
    }
}

/// Pioneer/Renesas vendor probe: READ BUFFER mode 0, buffer id 0xF1.
pub fn probe_pioneer(dev: &mut dyn ScsiDevice) -> bool {
    let cdb = cdb_read_buffer(0x00, 0xF1, 0x0000, 8);
    matches!(dev.command_in(&cdb, 8), Ok(d) if d.iter().any(|&b| b != 0))
}

/// Run the full probe sequence, tolerating individual command failures.
pub fn probe(dev: &mut dyn ScsiDevice) -> DriveProbe {
    let inquiry = probe_inquiry(dev).ok();
    let chip_id = probe_chip_id(dev).ok().flatten();
    let boot_banner = probe_boot_banner(dev).ok().filter(|s| !s.is_empty());
    let pioneer_vendor = probe_pioneer(dev);
    DriveProbe {
        inquiry,
        chip_id,
        boot_banner,
        pioneer_vendor,
    }
}

// ---- Classification ---------------------------------------------------------

/// Classify a probed drive into a [`ChipClass`].
///
/// Rules (fail-safe: anything ambiguous returns [`ChipClass::Unknown`]):
///
/// 1. Boot banner is the primary MTK A/B discriminator: a banner containing
///    `MT1959` => platform A, `MT1939` => platform B.
/// 2. Failing the banner, the GET CONFIG chip-id string is consulted for the
///    same `MT1959` / `MT1939` substrings.
/// 3. Pioneer/Renesas is identified by the RB-0xF1 vendor probe or a Pioneer
///    INQUIRY vendor string.
///
/// TODO(a-vs-b-final): the definitive MT1959-A vs MT1939-B discriminator is
/// being finalised by another agent. When that rule lands, plug it in at the
/// marked point below; until then we rely on the boot-banner substring, which
/// is known-correct for the images in hand but may need a secondary check
/// (e.g. a specific GET CONFIG descriptor byte) for edge silicon.
pub fn classify(probe: &DriveProbe) -> ChipClass {
    // 1. Boot banner (strongest signal we have today).
    if let Some(banner) = &probe.boot_banner {
        let up = banner.to_ascii_uppercase();
        if up.contains("MT1959") {
            return ChipClass::MediaTekMt1959;
        }
        if up.contains("MT1939") {
            return ChipClass::MediaTekMt1939;
        }
    }

    // 2. GET CONFIG chip-id string fallback.
    if let Some(chip) = &probe.chip_id {
        let up = chip.to_ascii_uppercase();
        if up.contains("MT1959") {
            return ChipClass::MediaTekMt1959;
        }
        if up.contains("MT1939") {
            return ChipClass::MediaTekMt1939;
        }
    }

    // 3. Pioneer / Renesas.
    if probe.pioneer_vendor {
        return ChipClass::PioneerRenesas;
    }
    if let Some(inq) = &probe.inquiry {
        if inq.vendor.eq_ignore_ascii_case("PIONEER") {
            return ChipClass::PioneerRenesas;
        }
    }

    // TODO(a-vs-b-final): final MTK-A/B rule plugs in here. If we reach this
    // point we could not distinguish silicon from the banner/chip-id; refuse
    // rather than guess.
    ChipClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inquiry_cdb_layout() {
        assert_eq!(cdb_inquiry(96), [0x12, 0x00, 0x00, 0x00, 0x60, 0x00]);
    }

    #[test]
    fn get_config_cdb_layout() {
        assert_eq!(
            cdb_get_config(0x010C, 256),
            [0x46, 0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn read_buffer_cdb_layout() {
        // mode 6, id 0, offset 0x3000, len 64
        assert_eq!(
            cdb_read_buffer(0x06, 0x00, 0x3000, 64),
            [0x3C, 0x06, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn parse_inquiry_fields() {
        let mut buf = vec![0u8; 96];
        buf[8..16].copy_from_slice(b"HL-DT-ST");
        buf[16..32].copy_from_slice(b"BD-RE  BU40N    ");
        buf[32..36].copy_from_slice(b"1.02");
        let inq = parse_inquiry(&buf);
        assert_eq!(inq.vendor, "HL-DT-ST");
        assert_eq!(inq.product, "BD-RE  BU40N");
        assert_eq!(inq.revision, "1.02");
    }

    #[test]
    fn banner_extraction_stops_at_nul() {
        let mut buf = *b"MT1959 Boot BU5 \0\0garbage";
        buf[20] = 0xff;
        assert_eq!(extract_banner(&buf), "MT1959 Boot BU5");
    }

    #[test]
    fn classify_mt1959_from_banner() {
        let p = DriveProbe {
            boot_banner: Some("MT1959 Boot BU5".into()),
            ..Default::default()
        };
        assert_eq!(classify(&p), ChipClass::MediaTekMt1959);
    }

    #[test]
    fn classify_mt1939_from_banner() {
        let p = DriveProbe {
            boot_banner: Some("MT1939 Boot".into()),
            ..Default::default()
        };
        assert_eq!(classify(&p), ChipClass::MediaTekMt1939);
    }

    #[test]
    fn classify_chip_id_fallback() {
        let p = DriveProbe {
            chip_id: Some("MT1959AV".into()),
            ..Default::default()
        };
        assert_eq!(classify(&p), ChipClass::MediaTekMt1959);
    }

    #[test]
    fn classify_pioneer_probe() {
        let p = DriveProbe {
            pioneer_vendor: true,
            ..Default::default()
        };
        assert_eq!(classify(&p), ChipClass::PioneerRenesas);
    }

    #[test]
    fn classify_unknown_is_failsafe() {
        assert_eq!(classify(&DriveProbe::default()), ChipClass::Unknown);
    }
}
