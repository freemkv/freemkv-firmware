//! freemkv-flash: standalone, multi-OS optical-drive firmware backup and flasher.
//!
//! Layers:
//! * [`platform`] — OS SCSI pass-through transport ([`platform::ScsiDevice`])
//!   with a real Linux `SG_IO` backend, Windows/macOS stubs, and a
//!   [`platform::MockScsiDevice`] for host-independent tests.
//! * [`backend`] — the backend contract ([`backend::Backend`] and its facets),
//!   devices and the explicit registry; [`backends`] holds the protocol
//!   implementations.
//! * [`engine`] — the generic, chip-agnostic `info`/`backup`/`flash` orchestration
//!   that drives a [`backend::Backend`] through its facets and write gates.
//!
//! Supporting modules: [`cmac`] (MT1959 AES-CMAC verify/resign) and [`manifest`]
//! (defines the [`manifest::FlashMode`] enum).

#![deny(missing_docs)]

#[macro_use]
pub mod output;

pub mod diagnostics;
pub mod recovery_diagnostics;
mod runtime_clock;

pub mod backend;
pub mod backends;
pub mod cmac;
pub mod crossflash;
pub mod engine;
pub mod firmware_comparison;
/// Declarative per-family/brand flash instruction sets + the 18-brand catalog.
pub mod flashset;
/// Signature-driven drive-family identification for a firmware IMAGE.
pub mod imageid;
pub mod inspection;
pub mod manifest;
pub mod mediatek_package;
pub mod platform;
pub mod probe;
pub mod report;
pub mod standard;
pub mod style;
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

#[cfg(test)]
pub(crate) fn kernel_handoff_fixture(kernel: &mut [u8]) {
    // Synthetic startup and RAM-programmer signatures, kept away from decoder
    // fixtures. Every test that authorizes Kernel replacement needs this proof.
    kernel[0x20..0x30].copy_from_slice(&[
        1, 0, 0x6d, 0xf3, 1, 0, 0x6d, 0xf4, 0x7a, 7, 0, 0, 0x80, 0, 4, 0x80,
    ]);
    kernel[0xe000..0xe016].copy_from_slice(&[
        0x7a, 0, 0, 0x40, 0xe1, 0, 0x7a, 1, 0, 0x40, 0xe1, 0x10, 0x7a, 2, 0, 0, 0x28, 0, 0x5e,
        0x40, 0xf0, 0,
    ]);
    kernel[0xe100..0xe108].copy_from_slice(&[0xf9, 0x80, 3, 9, 0x5e, 0x40, 0, 0x20]);
}

pub mod package;

/// Shared user-interface message catalogs; never used to translate diagnostic logs.
pub mod localization;

/// Terminal parsing and localized error presentation shared by both tools.
pub mod cli;
/// Localizable customer guidance; diagnostic errors preserve their complete source chains.
pub mod user_error;

mod firmware_capture;
