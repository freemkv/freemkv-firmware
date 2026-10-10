//! Embedded OEM control-key table (`keys.bin`): a gzip'd JSON map from a
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
//! `crate::drive::pioneer::k` / `crate::drive::pioneer::n`, so the MTK path and startup pay
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

const PIONEER_KEYS: &[u8] = include_bytes!("keys.bin");

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
        .map_err(|e| format!("keys.bin gunzip: {e}"))?;
    let raw: HashMap<String, RawEntry> =
        serde_json::from_str(&json).map_err(|e| format!("keys.bin json: {e}"))?;
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

pub use crate::drive::pioneer::flash_plan::controller_id_from_sat;

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
