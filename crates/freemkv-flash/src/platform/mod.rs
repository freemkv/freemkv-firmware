//! OS transport layer: SCSI pass-through abstraction.
//!
//! This is one of the two independent plug-in layers (the other is [`crate::drive`]).
//! Every backend implements [`ScsiDevice`]; [`open`] performs compile-time OS
//! selection:
//!
//! * Linux — real `SG_IO` ioctl ([`linux`]).
//! * Windows — SPTI `IOCTL_SCSI_PASS_THROUGH_DIRECT` ([`windows`], stub).
//! * macOS — IOKit `SCSITaskDeviceInterface` ([`mac`], stub).
//!
//! A programmable [`MockScsiDevice`] is always available so unit and
//! integration tests can exercise the drive/flash logic on any host (including
//! macOS CI) without touching real hardware.

use anyhow::Result;

/// Direction of the data phase for a SCSI command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// No data phase.
    None,
    /// Data flows device -> host (e.g. INQUIRY, READ_BUFFER).
    FromDevice,
    /// Data flows host -> device (e.g. WRITE_BUFFER).
    ToDevice,
}

/// A raw SCSI device capable of issuing CDBs.
pub trait ScsiDevice {
    /// Issue a data-in command; returns up to `alloc_len` bytes.
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>>;

    /// Issue a data-out command, sending `data` to the device.
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()>;

    /// Human-readable identity of the underlying transport/device path.
    fn describe(&self) -> String;
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::SgioDevice;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::SptiDevice;

#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "macos")]
pub use mac::IokitDevice;

mod mock;
pub use mock::MockScsiDevice;

/// Open the platform's real SCSI backend for `path`.
///
/// `writable` requests write access to the device: the read-only `info` / `dump`
/// commands pass `false` (so they never require write permission), and only
/// `flash` passes `true`. Compile-time OS selection: Linux uses a real `SG_IO`
/// device; Windows/macOS use their (currently stub) native transports. Any other
/// target has no backend and returns an error.
pub fn open(path: &str, writable: bool) -> Result<Box<dyn ScsiDevice>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(SgioDevice::open(path, writable)?))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(SptiDevice::open(path, writable)?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(IokitDevice::open(path, writable)?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = writable;
        anyhow::bail!("no SCSI pass-through backend for this OS (device {path})")
    }
}
