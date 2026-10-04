//! Embedded OEM control-key table (`pioneer_keys.bin`): a gzip'd JSON map from a
//! Pioneer controller id (the 16-bit value in a drive's/image's `SAT xxxx`
//! hardware tag) to that model's 16-byte OEM control descriptor, its per-OEM-tag
//! key table, and its unmatched-tag fallback key.
//!
//! Built from the audited Pioneer autoflasher model-key extraction
//! (`pioneer-autoflasher-model-keys-v1`), so every row is fact. This replaces the
//! old hand-baked per-model control payloads: the flasher now resolves a drive's
//! controller id, looks the row up here, and builds the 256-byte control buffer
//! generically (descriptor + key little-endian). Keyed by controller id — never
//! by INQUIRY model string — so the model-string collisions (one product mapping
//! to several controller ids with different keys) cannot be silently resolved.
//!
//! Loaded lazily and only when needed (a Pioneer flash), mirroring
//! `crate::pioneer_k` / `crate::pioneer_n`, so the MTK path and startup pay
//! nothing.

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use serde::Deserialize;

/// The default OEM lookup tag used by the self/OEM-update control path.
pub const DEFAULT_TAG: &str = "GENERAL";

/// A resolved OEM control row for one controller id.
pub struct KeyEntry {
    /// The 16-byte OEM control descriptor copied to `payload[0..16]`.
    pub descriptor: [u8; 16],
    /// Per-OEM-tag keys (tag trimmed of padding, e.g. `GENERAL`, `ID43`).
    pub keys: HashMap<String, u32>,
    /// Key serialized when the drive's OEM tag matches no row above.
    pub fallback: u32,
}

impl KeyEntry {
    /// The key for an OEM `tag` (trimmed), or [`None`] if the tag is absent.
    pub fn key_for_tag(&self, tag: &str) -> Option<u32> {
        self.keys.get(tag.trim()).copied()
    }

    /// Build the 256-byte OEM control buffer: descriptor at `[0..16]`, `key`
    /// little-endian at `[16..20]`, zero tail. This is the exact shape the OEM
    /// updater copies over its zero-initialized shared buffer.
    pub fn control_payload(&self, key: u32) -> [u8; 0x100] {
        let mut payload = [0u8; 0x100];
        payload[..16].copy_from_slice(&self.descriptor);
        payload[16..20].copy_from_slice(&key.to_le_bytes());
        payload
    }
}

#[derive(Deserialize)]
struct RawEntry {
    desc: String,
    keys: HashMap<String, String>,
    fb: String,
}

const PIONEER_KEYS: &[u8] = include_bytes!("pioneer_keys.bin");

fn table() -> &'static HashMap<u16, KeyEntry> {
    static TABLE: OnceLock<HashMap<u16, KeyEntry>> = OnceLock::new();
    // A malformed embedded table degrades to "no controller ids known" (every
    // flash fails the key lookup and refuses) rather than aborting at startup.
    TABLE.get_or_init(|| parse(PIONEER_KEYS).unwrap_or_default())
}

fn parse(gz: &[u8]) -> Result<HashMap<u16, KeyEntry>, String> {
    let mut json = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut json)
        .map_err(|e| format!("pioneer_keys.bin gunzip: {e}"))?;
    let raw: HashMap<String, RawEntry> =
        serde_json::from_str(&json).map_err(|e| format!("pioneer_keys.bin json: {e}"))?;
    let mut out = HashMap::with_capacity(raw.len());
    for (cid, v) in raw {
        let controller_id =
            u16::from_str_radix(&cid, 16).map_err(|e| format!("controller id {cid}: {e}"))?;
        let descriptor: [u8; 16] = hex_decode(&v.desc)?
            .try_into()
            .map_err(|_| format!("{cid}: descriptor must be 16 bytes"))?;
        let mut keys = HashMap::with_capacity(v.keys.len());
        for (tag, key) in v.keys {
            keys.insert(tag, parse_u32(&key)?);
        }
        out.insert(
            controller_id,
            KeyEntry {
                descriptor,
                keys,
                fallback: parse_u32(&v.fb)?,
            },
        );
    }
    Ok(out)
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(hex, 16).map_err(|e| format!("key {s}: {e}"))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex: {e}")))
        .collect()
}

/// Look up the OEM control row for a controller id. `None` means this controller
/// id is not in the audited table (the flash must refuse rather than guess).
pub fn lookup(controller_id: u16) -> Option<&'static KeyEntry> {
    table().get(&controller_id)
}

/// Parse a controller id from a `SAT xxxx` hardware tag (as it appears in a
/// Pioneer banner's `Hardware Version :` field) or a bare hex string. The SAT
/// value is the controller id in hex, e.g. `"SAT 8A10"` / `"8A10"` -> `0x8A10`.
pub fn controller_id_from_sat(hardware: &str) -> Option<u16> {
    let token = hardware
        .trim()
        .strip_prefix("SAT")
        .or_else(|| hardware.trim().strip_prefix("sat"))
        .unwrap_or(hardware)
        .trim();
    u16::from_str_radix(token, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_table_is_populated() {
        let n = table().len();
        assert!(n > 800, "expected the full controller-id table, got {n}");
    }

    #[test]
    fn ud04_controller_resolves_to_oem_descriptor_and_general_key() {
        let e = lookup(0x8A10).expect("0x8A10 must be in the table");
        assert_eq!(&e.descriptor, b"PIONEER BDR-US04");
        assert_eq!(e.key_for_tag(DEFAULT_TAG), Some(0xFD23_6642));
        // The autoflasher fallback (unmatched OEM tag) for this controller.
        assert_eq!(e.fallback, 0x6123_789A);
    }

    #[test]
    fn control_payload_has_descriptor_then_le_key_then_zero_tail() {
        let e = lookup(0x8A10).unwrap();
        let payload = e.control_payload(e.key_for_tag(DEFAULT_TAG).unwrap());
        assert_eq!(&payload[..16], b"PIONEER BDR-US04");
        assert_eq!(&payload[16..20], &[0x42, 0x66, 0x23, 0xFD]);
        assert!(payload[20..].iter().all(|&b| b == 0));
    }

    #[test]
    fn sat_tag_and_bare_hex_both_resolve_the_controller_id() {
        assert_eq!(controller_id_from_sat("SAT 8A10"), Some(0x8A10));
        assert_eq!(controller_id_from_sat("8A10"), Some(0x8A10));
        assert_eq!(controller_id_from_sat("SAT 8600"), Some(0x8600));
        assert_eq!(controller_id_from_sat("nonsense"), None);
    }

    #[test]
    fn unknown_controller_is_a_miss() {
        assert!(lookup(0xFFFF).is_none());
    }

    #[test]
    fn s09_controller_carries_the_id43_rebadge_key() {
        // S09 (SAT 8600) uses its ID43 destination tag, not GENERAL.
        let e = lookup(0x8600).expect("0x8600 must be in the table");
        assert_eq!(&e.descriptor, b"PIONEER  BDR-209");
        assert_eq!(e.key_for_tag("ID43"), Some(0xCE1F_2B98));
    }
}
