//! The AACS bus-encryption Known-Answer-Test (the content-read differential).
//!
//! The KAT proves a flashed freemkv build **strips AACS bus encryption** on
//! `READ(10)`: a fixed set of AACS aligned units read off the reference disc must
//! come back byte-identical to a golden capture taken on known-good MK /
//! LibreDrive firmware. Four checks per aligned unit (mirrors the out-of-tree
//! `private-repo/tests/kat/kat_probe.rs`, which is the reference):
//!
//!   1. `ts47`     — seed byte[4] == 0x47 (MPEG-TS sync ⇒ seed clear in transit)
//!   2. `cpi`      — (unit byte[0] & 0xC0) == 0xC0 (Copy Permission Indicator set)
//!   3. `aacs_enc` — AACS-at-rest ciphertext still present: `(unit[0] & 0xC0) != 0`
//!   4. `sha_match`— sha256(unit) == the golden reference bin (byte-identical)
//!
//! If bus encryption is still ON the seed is scrambled (`byte[4] != 0x47`) and the
//! hash mismatches, so the unit FAILS. The golden `mkref_unit*.bin` reference
//! files are **licensed ripped-disc material** and are NEVER vendored into this
//! public repo — they are read at run time from a directory named by
//! `--kat-dir` / `FREEMKV_KAT_DIR` (pointing at `private-repo/tests/kat`). The
//! checks + geometry here are self-contained so the harness keeps its scsi-only
//! `libfreemkv` dependency (no ripping tree, no dependency cycle).

use std::path::{Path, PathBuf};

/// Default first content LBA of the reference disc's feature title (mirrors
/// `mkref_manifest.json` `start_lba` = 11712 / 0x2dc0). Overridable per-step.
pub const DEFAULT_START_LBA: u32 = 11712;
/// Default number of aligned units the KAT reads (manifest `n_units`).
pub const DEFAULT_N_UNITS: u32 = 8;
/// Default aligned-unit stride in 2048-byte sectors (manifest
/// `unit_stride_sectors` = 3, i.e. read every 3rd sector).
pub const DEFAULT_STRIDE_SECTORS: u16 = 3;
/// Default aligned-unit length in bytes (3 × 2048 = 6144; manifest
/// `aligned_unit.bytes`). Also the number of sectors read per unit == stride.
pub const DEFAULT_UNIT_LEN: usize = 6144;

/// Resolved KAT geometry for one run (from the step spec, else the defaults).
#[derive(Debug, Clone, Copy)]
pub struct KatGeom {
    /// First content LBA to read.
    pub start_lba: u32,
    /// How many aligned units to read + compare.
    pub n_units: u32,
    /// Sector stride between successive units.
    pub stride_sectors: u16,
    /// Bytes per aligned unit (== `stride_sectors` × 2048).
    pub unit_len: usize,
}

impl Default for KatGeom {
    fn default() -> Self {
        Self {
            start_lba: DEFAULT_START_LBA,
            n_units: DEFAULT_N_UNITS,
            stride_sectors: DEFAULT_STRIDE_SECTORS,
            unit_len: DEFAULT_UNIT_LEN,
        }
    }
}

impl KatGeom {
    /// The LBA of aligned unit `i` (`start_lba + i × stride_sectors`).
    pub fn lba_of(&self, i: u32) -> u32 {
        self.start_lba + i * self.stride_sectors as u32
    }

    /// The golden reference bin path for unit `i` in `dir` (`mkref_unit{i}.bin`).
    pub fn ref_path(dir: &Path, i: u32) -> PathBuf {
        dir.join(format!("mkref_unit{i}.bin"))
    }
}

/// The per-unit verdict of the four KAT checks.
#[derive(Debug, Clone)]
pub struct UnitVerdict {
    /// Aligned-unit index.
    pub index: u32,
    /// LBA it was read from.
    pub lba: u32,
    /// seed byte[4] == 0x47 (MPEG-TS sync visible).
    pub ts47: bool,
    /// (unit[0] & 0xC0) == 0xC0 (CPI bits set).
    pub cpi: bool,
    /// (unit[0] & 0xC0) != 0 (AACS-at-rest ciphertext still present).
    pub aacs_enc: bool,
    /// sha256(read) == sha256(golden) AND bytes equal.
    pub sha_match: bool,
    /// sha256 of the bytes read off the drive (hex).
    pub sha_hex: String,
    /// A read/reference error message, if the unit could not be evaluated.
    pub error: Option<String>,
}

impl UnitVerdict {
    /// True only when all four checks pass and there was no error.
    pub fn pass(&self) -> bool {
        self.error.is_none() && self.ts47 && self.cpi && self.aacs_enc && self.sha_match
    }
}

/// libfreemkv `aacs_unit_encrypted(unit, BdTs)`, inlined: an AACS-at-rest unit on
/// a UHD/BD (BdTs) still carries its CPI bits, so ciphertext-present ⇔
/// `(unit[0] & 0xC0) != 0`. (Bus-decrypted-but-still-at-rest-encrypted content
/// keeps these bits; over-decrypted content would zero them.)
pub fn aacs_unit_encrypted(unit: &[u8]) -> bool {
    unit.first().is_some_and(|&b| (b & 0xC0) != 0)
}

/// Evaluate one aligned unit read off the drive against its golden reference
/// bytes. `read` is what came back over `READ(10)`; `golden` is the reference
/// file's contents (already read by the caller).
pub fn check_unit(index: u32, lba: u32, read: &[u8], golden: &[u8]) -> UnitVerdict {
    let sha_hex = sha256_hex(read);
    let ts47 = read.get(4) == Some(&0x47);
    let cpi = read.first().is_some_and(|&b| (b & 0xC0) == 0xC0);
    let aacs_enc = aacs_unit_encrypted(read);
    let sha_match = read == golden && sha_hex == sha256_hex(golden);
    UnitVerdict {
        index,
        lba,
        ts47,
        cpi,
        aacs_enc,
        sha_match,
        sha_hex,
        error: None,
    }
}

/// A unit that could not be read/compared (transport error, missing reference).
pub fn error_unit(index: u32, lba: u32, msg: String) -> UnitVerdict {
    UnitVerdict {
        index,
        lba,
        ts47: false,
        cpi: false,
        aacs_enc: false,
        sha_match: false,
        sha_hex: String::new(),
        error: Some(msg),
    }
}

// ── minimal, self-contained SHA-256 (FIPS 180-4) — no external crate dep, so the
//    harness keeps its scsi-only libfreemkv dependency. Ported verbatim from the
//    reference kat_probe.rs. ────────────────────────────────────────────────────
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    len: usize,
    total: u64,
}
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
impl Sha256 {
    fn new() -> Self {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            len: 0,
            total: 0,
        }
    }
    fn block(h: &mut [u32; 8], b: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = *h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.len > 0 {
            let need = 64 - self.len;
            let take = need.min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len == 64 {
                let b = self.buf;
                Self::block(&mut self.h, &b);
                self.len = 0;
            } else {
                return;
            }
        }
        while data.len() >= 64 {
            Self::block(&mut self.h, &data[..64]);
            data = &data[64..];
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.len = data.len();
    }
    fn finish(mut self) -> [u8; 32] {
        let bits = self.total * 8;
        self.update(&[0x80]);
        while self.len != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

/// Lowercase hex sha256 of `b`.
pub fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    h.finish().iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn geometry_strides_by_sectors() {
        let g = KatGeom::default();
        assert_eq!(g.lba_of(0), 11712);
        assert_eq!(g.lba_of(1), 11715);
        assert_eq!(g.lba_of(7), 11733);
    }

    #[test]
    fn clear_unit_passes_all_four_checks() {
        // A "clear" aligned unit: CPI bits set (byte0 0xC0), TS sync at [4], and
        // the golden bytes identical to what we read.
        let mut unit = vec![0u8; DEFAULT_UNIT_LEN];
        unit[0] = 0xC7; // (0xC7 & 0xC0)==0xC0 → cpi + aacs_enc
        unit[4] = 0x47; // MPEG-TS sync
        let v = check_unit(0, 11712, &unit, &unit);
        assert!(v.ts47 && v.cpi && v.aacs_enc && v.sha_match);
        assert!(v.pass());
    }

    #[test]
    fn bus_encrypted_unit_fails() {
        // Bus encryption ON: the seed is scrambled — no TS sync, CPI bits noise,
        // and it does not match the golden reference.
        let mut golden = vec![0u8; DEFAULT_UNIT_LEN];
        golden[0] = 0xC7;
        golden[4] = 0x47;
        let mut scrambled = vec![0x5Au8; DEFAULT_UNIT_LEN];
        scrambled[0] = 0x11; // (0x11 & 0xC0)==0 → cpi false, aacs_enc false
        scrambled[4] = 0x99; // not 0x47
        let v = check_unit(0, 11712, &scrambled, &golden);
        assert!(!v.ts47 && !v.cpi && !v.sha_match);
        assert!(!v.pass());
    }

    #[test]
    fn aacs_encrypted_predicate() {
        assert!(aacs_unit_encrypted(&[0xC0]));
        assert!(aacs_unit_encrypted(&[0x80]));
        assert!(!aacs_unit_encrypted(&[0x00]));
        assert!(!aacs_unit_encrypted(&[0x3F]));
        assert!(!aacs_unit_encrypted(&[]));
    }
}
