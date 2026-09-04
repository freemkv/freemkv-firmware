//! freemkv-flash: standalone, multi-OS optical-drive firmware flasher/dumper.
//!
//! Layers:
//! * [`platform`] — OS SCSI pass-through transport ([`platform::ScsiDevice`])
//!   with a real Linux `SG_IO` backend, Windows/macOS stubs, and a
//!   [`platform::MockScsiDevice`] for host-independent tests.
//! * [`drive`] — chip-family classification ([`drive::Family`],
//!   [`drive::classify`]) and the per-family command trait
//!   ([`drive::DriveFamily`]); [`drive::mtk`] is the only fully-implemented one.
//! * [`engine`] — the generic, chip-agnostic `info`/`dump`/`flash` orchestration
//!   that drives a [`drive::DriveFamily`] through its trait primitives.
//!
//! Supporting modules: [`cmac`] (MT1959 AES-CMAC verify/resign) and [`manifest`]
//! (defines the [`manifest::FlashMode`] enum).

#![deny(missing_docs)]

pub mod cmac;
pub mod drive;
pub mod engine;
/// Declarative per-family/brand flash instruction sets + the 18-brand catalog.
pub mod flashset;
pub mod manifest;
pub mod platform;
pub mod probe;
pub mod style;

/// Compute the CRC32 (IEEE) of a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}
