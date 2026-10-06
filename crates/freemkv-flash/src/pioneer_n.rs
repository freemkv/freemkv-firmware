//! Embedded OEM normal table (`pioneer_n.bin`): a gzip'd JSON map from a
//! decoded-normal-image SHA-256 to that normal's true OEM revision/date, its LCG
//! encoding seed, and the verbatim OEM ECDSA signature block needed to rebuild a
//! byte-exact OEM normal envelope.
//!
//! Built ONLY from our hoard's OEM normal update files, so every entry is fact.
//! A reconstructed normal is byte-for-byte identical to OEM only when its decoded
//! image is recognized here: the seed reproduces the exact key table and
//! ciphertext, and the stored signature is stamped verbatim (the signature is a
//! real ECDSA value that cannot be re-derived without the OEM private key). An
//! unrecognized normal gets an honest zero seed and an all-zero signature region
//! — the obvious "not OEM / unverified" sentinel.
//!
//! Loaded lazily and only when needed (a Pioneer backup), mirroring
//! `crate::pioneer_k`, so the MTK path and startup pay nothing.

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use serde::Deserialize;

/// A resolved OEM normal record.
pub struct NormalEntry {
    /// Real OEM "Revision Level" (earliest release this normal binary shipped in).
    pub revision: String,
    /// Real OEM "Generated Date" (`YY/MM/DD`, earliest release).
    pub date: String,
    /// 24-bit LCG seed; expanded to the normal key table by the codec.
    pub seed: u32,
    /// Verbatim OEM signature block (`0x50` bytes at `0x170..0x1c0`).
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
struct RawEntry {
    version: String,
    date: String,
    seed: String,
    sig_hex: String,
}

const PIONEER_N: &[u8] = include_bytes!("pioneer_n.bin");

fn table() -> &'static HashMap<String, NormalEntry> {
    static TABLE: OnceLock<HashMap<String, NormalEntry>> = OnceLock::new();
    // A malformed embedded table degrades to "no OEM normals known" (every
    // backup normal becomes an honest zero sentinel) rather than aborting.
    TABLE.get_or_init(|| parse(PIONEER_N).unwrap_or_default())
}

fn parse(gz: &[u8]) -> Result<HashMap<String, NormalEntry>, String> {
    let mut json = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut json)
        .map_err(|e| format!("pioneer_n.bin gunzip: {e}"))?;
    let raw: HashMap<String, RawEntry> =
        serde_json::from_str(&json).map_err(|e| format!("pioneer_n.bin json: {e}"))?;
    let mut out = HashMap::with_capacity(raw.len());
    for (hash, v) in raw {
        let hex = v.seed.strip_prefix("0x").unwrap_or(&v.seed);
        let seed = u32::from_str_radix(hex, 16).map_err(|e| format!("seed {}: {e}", v.seed))?;
        let signature = hex_decode(&v.sig_hex)?;
        if signature.len() != 0x50 {
            return Err(format!("{hash}: signature must be 0x50 bytes"));
        }
        out.insert(
            hash,
            NormalEntry {
                revision: v.version,
                date: v.date,
                seed,
                signature,
            },
        );
    }
    Ok(out)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length sig_hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("sig_hex: {e}")))
        .collect()
}

/// Look up an OEM normal by its decoded-image SHA-256 (lowercase hex). `None`
/// means this normal is not one of our known OEM normals.
pub fn lookup(image_sha256: &str) -> Option<&'static NormalEntry> {
    table().get(image_sha256)
}

#[cfg(test)]
#[path = "pioneer_n_tests.rs"]
mod tests;
