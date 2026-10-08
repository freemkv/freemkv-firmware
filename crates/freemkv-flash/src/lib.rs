//! freemkv-flash: standalone, multi-OS optical-drive firmware backup and flasher.
//!
//! Layers:
//! * [`platform`] — OS SCSI pass-through transport ([`platform::ScsiDevice`])
//!   with a real Linux `SG_IO` backend, Windows/macOS stubs, and a
//!   [`platform::MockScsiDevice`] for host-independent tests.
//! * [`drive`] — chip-family classification ([`drive::Family`],
//!   [`drive::classify`]) and the per-family command trait
//!   ([`drive::DriveFamily`]); [`drive::mtk`] is the only fully-implemented one.
//! * [`engine`] — the generic, chip-agnostic `info`/`backup`/`flash` orchestration
//!   that drives a [`drive::DriveFamily`] through its trait primitives.
//!
//! Supporting modules: [`cmac`] (MT1959 AES-CMAC verify/resign) and [`manifest`]
//! (defines the [`manifest::FlashMode`] enum).

#![deny(missing_docs)]

#[macro_use]
pub mod output;

pub mod diagnostics;

pub mod cmac;
pub mod drive;
pub mod engine;
/// Declarative per-family/brand flash instruction sets + the 18-brand catalog.
pub mod flashset;
/// Signature-driven drive-family identification for a firmware IMAGE.
pub mod imageid;
pub mod inspection;
pub mod manifest;
/// Offline reconstruction of Pioneer backup candidates from captured images.
pub mod pioneer_backup;
/// Read-only validation of extractor-produced Pioneer firmware bundles.
pub mod pioneer_bundle;
/// Live Pioneer OEM flash executor — crate-private so the gate chain in `engine`
/// (--execute/--i-understand-risk, tray guard, backup-first) cannot be bypassed.
pub(crate) mod pioneer_flash;
pub mod pioneer_flash_plan;
/// Embedded OEM kernel label/key table (pioneer_k.bin), loaded lazily for Pioneer.
mod pioneer_k;
/// Historical OEM control-key test oracles, excluded from production.
#[cfg(test)]
mod pioneer_keys;
/// Embedded OEM normal seed/signature table (pioneer_n.bin), loaded lazily for Pioneer.
mod pioneer_n;
pub mod platform;
pub mod probe;
pub mod style;
pub mod workflow;

/// Compute the CRC32 (IEEE) of a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

/// Address-oriented Pioneer diagnostic captures.
pub mod pioneer_dump;
