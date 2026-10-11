//! freemkv-flash: standalone, multi-OS optical-drive firmware backup and flasher.
//!
//! Layers:
//! * [`platform`] — OS SCSI pass-through transport ([`platform::ScsiDevice`])
//!   with a real Linux `SG_IO` backend, Windows/macOS stubs, and a
//!   [`platform::MockScsiDevice`] for host-independent tests.
//! * [`backend`] — backend identity, file formats and the explicit registry;
//!   [`drive`] — the per-backend command trait ([`drive::DriveFamily`]);
//!   [`backends`] holds the protocol implementations.
//! * [`engine`] — the generic, chip-agnostic `info`/`backup`/`flash` orchestration
//!   that drives a [`drive::DriveFamily`] through its trait primitives.
//!
//! Supporting modules: [`cmac`] (MT1959 AES-CMAC verify/resign) and [`manifest`]
//! (defines the [`manifest::FlashMode`] enum).

#![deny(missing_docs)]

#[macro_use]
pub mod output;

pub mod diagnostics;

pub mod backend;
pub mod backends;
pub mod cmac;
pub mod drive;
pub mod engine;
/// Declarative per-family/brand flash instruction sets + the 18-brand catalog.
pub mod flashset;
/// Signature-driven drive-family identification for a firmware IMAGE.
pub mod imageid;
pub mod inspection;
pub mod manifest;
pub mod platform;
pub mod probe;
pub mod style;
/// The single `Transport` adapter between `ScsiDevice` and the protocol crates.
pub mod transport;
pub mod workflow;

/// Compute the CRC32 (IEEE) of a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
#[path = "golden_tests.rs"]
mod golden_tests;
