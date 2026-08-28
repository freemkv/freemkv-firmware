//! freemkv-firmware: optical-drive firmware flasher + firmware-build pipeline.
//!
//! Modules:
//! * [`scsi`] — transport abstraction ([`scsi::ScsiDevice`]) with a real Linux
//!   SG_IO backend and a build-everywhere stub for macOS/Windows.
//! * [`detect`] — INQUIRY / GET CONFIG / READ BUFFER probes and platform
//!   classification ([`detect::ChipClass`]).
//! * [`manifest`] — TOML firmware-image manifest.
//! * [`flash`] — WRITE_BUFFER chunked upload, the `enc` AES transform, and the
//!   pre-flash safety gate.
//! * [`cmac`] — MT1959 AES-CMAC integrity verify / resign.

#![deny(missing_docs)]

pub mod cmac;
pub mod detect;
pub mod flash;
pub mod manifest;
pub mod scsi;

/// Compute the CRC32 (IEEE) of a byte slice, as stored in the manifest.
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}
