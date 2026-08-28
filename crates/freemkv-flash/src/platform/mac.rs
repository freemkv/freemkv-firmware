//! macOS IOKit SCSI backend (stub).
//!
//! The intended implementation drives the IOKit `SCSITaskDeviceInterface`
//! (`MMCDeviceInterface`) against an IOKit service / BSD name. It is not yet
//! wired up; the type exists so the crate compiles on macOS and returns a clear
//! "unimplemented" error rather than silently doing nothing.

use anyhow::{bail, Result};

use super::ScsiDevice;

/// A SCSI device reached through the macOS IOKit interface (not yet implemented).
pub struct IokitDevice {
    path: String,
}

impl IokitDevice {
    /// "Open" a macOS IOKit device for an IOKit service / BSD name.
    ///
    /// Construction succeeds so callers can report identity; any real command
    /// returns an unimplemented error.
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self {
            path: path.to_string(),
        })
    }
}

impl ScsiDevice for IokitDevice {
    fn command_in(&mut self, _cdb: &[u8], _alloc_len: usize) -> Result<Vec<u8>> {
        bail!(
            "macOS IOKit (SCSITaskDeviceInterface) backend is not implemented yet (device {})",
            self.path
        )
    }

    fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
        bail!(
            "macOS IOKit (SCSITaskDeviceInterface) backend is not implemented yet (device {})",
            self.path
        )
    }

    fn describe(&self) -> String {
        format!("iokit://{} (unimplemented)", self.path)
    }
}
