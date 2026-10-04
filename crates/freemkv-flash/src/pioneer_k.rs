//! Embedded OEM kernel table (`pioneer_k.bin`): a gzip'd JSON map from a
//! decoded-kernel-image SHA-256 to that kernel's true OEM revision/date and the
//! key material needed to reconstruct a byte-exact OEM kernel envelope.
//!
//! Built ONLY from our hoard's OEM kernel update files, so every entry is fact.
//! A drive's kernel is never dated in its own body (it reads `00/00/00`), and
//! the wrapper date only survives in the OEM distribution file — so this table
//! is the only way to recover a kernel's real revision/date, and it also carries
//! the OEM encoding key so a recognized kernel backs up byte-for-byte identical
//! to OEM. An unrecognized kernel gets honest zero placeholders instead.
//!
//! Loaded lazily and only when needed (a Pioneer backup), so the MTK path and
//! startup pay nothing.

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use serde::Deserialize;

/// Key material to regenerate the OEM kernel key table.
pub enum KeyMaterial {
    /// 24-bit LCG seed; expanded to the key table by the codec.
    Seed(u32),
    /// Raw `0x1000`-byte front-key table, used verbatim (non-LCG kernels).
    Raw(Vec<u8>),
}

/// A resolved OEM kernel record.
pub struct KernelEntry {
    /// Real OEM "Revision Level" (earliest release this kernel binary shipped in).
    pub revision: String,
    /// Real OEM "Generated Date" (`YY/MM/DD`, earliest release).
    pub date: String,
    /// Key material to reproduce the OEM key table byte-for-byte.
    pub key: KeyMaterial,
}

#[derive(Deserialize)]
struct RawEntry {
    version: String,
    date: String,
    #[serde(default)]
    seed: Option<String>,
    #[serde(default)]
    key_hex: Option<String>,
}

const PIONEER_K: &[u8] = include_bytes!("pioneer_k.bin");

fn table() -> &'static HashMap<String, KernelEntry> {
    static TABLE: OnceLock<HashMap<String, KernelEntry>> = OnceLock::new();
    // A malformed embedded table degrades to "no OEM kernels known" (every
    // backup becomes an honest 0000 candidate) rather than aborting.
    TABLE.get_or_init(|| parse(PIONEER_K).unwrap_or_default())
}

fn parse(gz: &[u8]) -> Result<HashMap<String, KernelEntry>, String> {
    let mut json = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut json)
        .map_err(|e| format!("pioneer_k.bin gunzip: {e}"))?;
    let raw: HashMap<String, RawEntry> =
        serde_json::from_str(&json).map_err(|e| format!("pioneer_k.bin json: {e}"))?;
    let mut out = HashMap::with_capacity(raw.len());
    for (hash, v) in raw {
        let key = match (v.seed, v.key_hex) {
            (Some(s), None) => {
                let hex = s.strip_prefix("0x").unwrap_or(&s);
                KeyMaterial::Seed(
                    u32::from_str_radix(hex, 16).map_err(|e| format!("seed {s}: {e}"))?,
                )
            }
            (None, Some(h)) => KeyMaterial::Raw(hex_decode(&h)?),
            _ => return Err(format!("{hash}: need exactly one of seed/key_hex")),
        };
        out.insert(
            hash,
            KernelEntry {
                revision: v.version,
                date: v.date,
                key,
            },
        );
    }
    Ok(out)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length key_hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("key_hex: {e}")))
        .collect()
}

/// Look up an OEM kernel by its decoded-image SHA-256 (lowercase hex). `None`
/// means this kernel is not one of our known OEM kernels.
pub fn lookup(image_sha256: &str) -> Option<&'static KernelEntry> {
    table().get(image_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_table_parses_and_has_entries() {
        let n = table().len();
        assert!(n > 100, "expected the full OEM kernel table, got {n}");
    }

    #[test]
    fn ud04_kernel_resolves_to_real_oem_label_and_raw_key() {
        // The UD04 kernel is the carried-forward 2017 build: its real label is
        // 1.00 / 17/02/10 (not its Normal's 1.14), and it uses a non-LCG raw key.
        let e = lookup("ba8547d3da87fc32d8d14a8eb2f39fdea9c6c0ac7e6ba91ff3ecd174f8e45e41")
            .expect("UD04 kernel must be in the table");
        assert_eq!(e.revision, "1.00");
        assert_eq!(e.date, "17/02/10");
        match &e.key {
            KeyMaterial::Raw(b) => assert_eq!(b.len(), 0x1000, "UD04 front key is 4 KiB"),
            KeyMaterial::Seed(_) => panic!("UD04 kernel must carry a raw key, not a seed"),
        }
    }

    #[test]
    fn unknown_kernel_is_a_miss() {
        assert!(lookup(&"0".repeat(64)).is_none());
    }

    #[test]
    fn every_row_has_well_formed_key_material() {
        for e in table().values() {
            assert!(!e.revision.is_empty() && !e.date.is_empty());
            if let KeyMaterial::Raw(b) = &e.key {
                assert_eq!(b.len(), 0x1000);
            }
        }
    }
}
