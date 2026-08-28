//! MT1959 firmware AES-CMAC integrity model.
//!
//! The stock MediaTek MT1959 firmware image carries a 16-entry integrity table
//! at file offset `0x10400`. Each entry is 28 bytes, little-endian:
//!
//! ```text
//! struct cmac_entry {          // Python struct '<3L16s', size 28
//!     u32 enabled;             // 0x00000001 = active, 0xFFFFFFFF = unused
//!     u32 start;               // file offset, inclusive
//!     u32 end;                 // file offset, inclusive
//!     u8  cmac[16];            // stored digest (byte-reversed, see below)
//! };
//! ```
//!
//! Digest recipe (reproduced byte-for-byte against real stock images):
//! 1. Read bytes `[start ..= end]`.
//! 2. Byte-reverse each 16-byte block in place.
//! 3. `digest = AES-CMAC(KEY, reversed_data)`.
//! 4. Byte-reverse the 16-byte digest and store it at `entry + 12`.
//!
//! The CMAC key is symmetric and public (integrity, not confidentiality):
//! `BD209408E35E526A36235234434FE8AB`. Anyone with the key can re-sign; the MAC
//! exists to reject accidental corruption and unsigned third-party images.
//!
//! Re-sign ordering matters: the entry whose range covers the table region
//! (`0x10400`) hashes the *other* entries' digest bytes, so it must be computed
//! last, after every data range has been written back.

use aes::Aes128;
use cmac::{Cmac, Mac};

/// Public AES-CMAC integrity key for MT1959 firmware.
pub const CMAC_KEY: [u8; 16] = [
    0xBD, 0x20, 0x94, 0x08, 0xE3, 0x5E, 0x52, 0x6A, 0x36, 0x23, 0x52, 0x34, 0x43, 0x4F, 0xE8, 0xAB,
];

/// File offset of the integrity table.
pub const TABLE_OFFSET: usize = 0x10400;
/// Number of table entries.
pub const ENTRY_COUNT: usize = 16;
/// Size of a single table entry in bytes.
pub const ENTRY_SIZE: usize = 28;
/// `enabled` sentinel for an active entry.
pub const ENABLED: u32 = 0x0000_0001;

/// A parsed integrity-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmacEntry {
    /// Index within the table (0..16).
    pub index: usize,
    /// File offset of this entry's 28 bytes.
    pub entry_off: usize,
    /// `enabled` word.
    pub enabled: u32,
    /// Inclusive start file offset of the covered range.
    pub start: u32,
    /// Inclusive end file offset of the covered range.
    pub end: u32,
    /// Stored (byte-reversed) digest as it sits in the file.
    pub stored: [u8; 16],
}

impl CmacEntry {
    /// Whether this entry participates in verification / signing.
    pub fn is_active(&self) -> bool {
        self.enabled == ENABLED
    }

    /// Whether this entry's covered range includes the integrity table itself.
    pub fn covers_table(&self) -> bool {
        (self.start as usize) <= TABLE_OFFSET && (self.end as usize) >= TABLE_OFFSET
    }
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Parse all 16 table entries. Returns an error if the image is too small.
pub fn parse_table(image: &[u8]) -> Result<Vec<CmacEntry>, CmacError> {
    let table_end = TABLE_OFFSET + ENTRY_COUNT * ENTRY_SIZE;
    if image.len() < table_end {
        return Err(CmacError::ImageTooSmall {
            need: table_end,
            got: image.len(),
        });
    }
    let mut out = Vec::with_capacity(ENTRY_COUNT);
    for index in 0..ENTRY_COUNT {
        let entry_off = TABLE_OFFSET + index * ENTRY_SIZE;
        let enabled = read_u32_le(image, entry_off);
        let start = read_u32_le(image, entry_off + 4);
        let end = read_u32_le(image, entry_off + 8);
        let mut stored = [0u8; 16];
        stored.copy_from_slice(&image[entry_off + 12..entry_off + 28]);
        out.push(CmacEntry {
            index,
            entry_off,
            enabled,
            start,
            end,
            stored,
        });
    }
    Ok(out)
}

/// Reverse each 16-byte block of `data` in place (final short block reversed too).
fn reverse_blocks(data: &mut [u8]) {
    for chunk in data.chunks_mut(16) {
        chunk.reverse();
    }
}

/// Compute the stored-form (byte-reversed) digest for a covered range.
///
/// Returns the 16 bytes exactly as they should appear in the file at `entry+12`.
pub fn compute_stored_digest(image: &[u8], start: u32, end: u32) -> Result<[u8; 16], CmacError> {
    let start = start as usize;
    let end = end as usize;
    if end < start || end >= image.len() {
        return Err(CmacError::BadRange { start, end });
    }
    let mut data = image[start..=end].to_vec();
    reverse_blocks(&mut data);

    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(&CMAC_KEY)
        .expect("AES-128 key length is always valid for CMAC");
    mac.update(&data);
    let tag = mac.finalize().into_bytes();

    let mut digest = [0u8; 16];
    digest.copy_from_slice(&tag);
    digest.reverse(); // step 4: byte-reverse the digest before storing
    Ok(digest)
}

/// Result of verifying one entry.
#[derive(Debug, Clone, Copy)]
pub struct EntryVerdict {
    /// The entry that was checked.
    pub entry: CmacEntry,
    /// Freshly computed stored-form digest.
    pub computed: [u8; 16],
    /// Whether `computed == entry.stored`.
    pub matches: bool,
}

/// Verify every active entry. Returns a per-entry verdict list.
pub fn verify_detailed(image: &[u8]) -> Result<Vec<EntryVerdict>, CmacError> {
    let table = parse_table(image)?;
    let mut verdicts = Vec::new();
    for entry in table {
        if !entry.is_active() {
            continue;
        }
        let computed = compute_stored_digest(image, entry.start, entry.end)?;
        verdicts.push(EntryVerdict {
            matches: computed == entry.stored,
            entry,
            computed,
        });
    }
    Ok(verdicts)
}

/// Return `true` iff every active entry's stored digest matches a fresh compute.
pub fn verify(image: &[u8]) -> bool {
    match verify_detailed(image) {
        Ok(v) => !v.is_empty() && v.iter().all(|e| e.matches),
        Err(_) => false,
    }
}

/// Recompute and write back every active entry's digest, returning the new image.
///
/// Data ranges are signed first; any entry that covers the table region
/// (`0x10400`) is signed last, over the already-updated table bytes.
pub fn resign(image: &[u8]) -> Result<Vec<u8>, CmacError> {
    let mut img = image.to_vec();
    let table = parse_table(&img)?;

    // Pass 1: data ranges (those that do not cover the table).
    for entry in table.iter().filter(|e| e.is_active() && !e.covers_table()) {
        let digest = compute_stored_digest(&img, entry.start, entry.end)?;
        img[entry.entry_off + 12..entry.entry_off + 28].copy_from_slice(&digest);
    }
    // Pass 2: table-covering ranges, over the now-updated table bytes.
    for entry in table.iter().filter(|e| e.is_active() && e.covers_table()) {
        let digest = compute_stored_digest(&img, entry.start, entry.end)?;
        img[entry.entry_off + 12..entry.entry_off + 28].copy_from_slice(&digest);
    }
    Ok(img)
}

/// Errors from the CMAC layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmacError {
    /// Image is smaller than the integrity table requires.
    ImageTooSmall {
        /// Required minimum length.
        need: usize,
        /// Actual length.
        got: usize,
    },
    /// A table entry described an out-of-bounds or inverted range.
    BadRange {
        /// Range start.
        start: usize,
        /// Range end.
        end: usize,
    },
}

impl std::fmt::Display for CmacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CmacError::ImageTooSmall { need, got } => {
                write!(f, "image too small: need {need} bytes, got {got}")
            }
            CmacError::BadRange { start, end } => {
                write!(f, "bad CMAC range: start=0x{start:x} end=0x{end:x}")
            }
        }
    }
}

impl std::error::Error for CmacError {}
