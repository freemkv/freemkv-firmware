//! SCSI transport abstraction.
//!
//! The near-term target is Linux via the SG_IO ioctl. Other platforms build
//! against a stub backend so the whole crate compiles everywhere; a real
//! Windows SPTI backend and a macOS backend are future work.

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

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub use stub::StubDevice;

/// Open the platform's default SCSI backend for `path`.
///
/// On Linux this is a real SG_IO device; elsewhere it is a stub that errors on
/// any actual I/O but lets the tool build and run non-I/O subcommands.
pub fn open(path: &str) -> Result<Box<dyn ScsiDevice>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(SgioDevice::open(path)?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Box::new(StubDevice::open(path)?))
    }
}
