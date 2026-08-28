//! freemkv-flash: standalone, multi-OS optical-drive firmware flasher/dumper.
//!
//! Two independent plug-in layers:
//! * [`platform`] — OS SCSI pass-through transport ([`platform::ScsiDevice`])
//!   with a real Linux `SG_IO` backend, Windows/macOS stubs, and a
//!   [`platform::MockScsiDevice`] for host-independent tests.
//! * [`drive`] — chip-family classification ([`drive::Family`],
//!   [`drive::classify`]) and per-family dump/flash logic ([`drive::mtk`] is the
//!   only fully-implemented family).
//!
//! Supporting modules: [`cmac`] (MT1959 AES-CMAC verify/resign) and [`manifest`]
//! (firmware-image manifest / flash mode).

#![deny(missing_docs)]

pub mod cmac;
pub mod drive;
pub mod manifest;
pub mod platform;

/// Compute the CRC32 (IEEE) of a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}
