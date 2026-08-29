//! Windows SPTI SCSI backend (stub).
//!
//! The intended implementation drives `IOCTL_SCSI_PASS_THROUGH_DIRECT`
//! (SPTI) against `\\.\CdRomN`. It is not yet wired up; the type exists so the
//! crate compiles on Windows and returns a clear "unimplemented" error rather
//! than silently doing nothing.

use anyhow::{bail, Result};

use super::ScsiDevice;

/// A SCSI device reached through the Windows SPTI interface (not yet implemented).
pub struct SptiDevice {
    path: String,
}

impl SptiDevice {
    /// "Open" a Windows SPTI device handle for `\\.\CdRomN`.
    ///
    /// Construction succeeds so callers can report identity; any real command
    /// returns an unimplemented error.
    pub fn open(path: &str, _writable: bool) -> Result<Self> {
        Ok(Self {
            path: path.to_string(),
        })
    }
}

impl ScsiDevice for SptiDevice {
    fn command_in(&mut self, _cdb: &[u8], _alloc_len: usize) -> Result<Vec<u8>> {
        bail!(
            "Windows SPTI (IOCTL_SCSI_PASS_THROUGH_DIRECT) backend is not implemented yet (device {})",
            self.path
        )
    }

    fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
        bail!(
            "Windows SPTI (IOCTL_SCSI_PASS_THROUGH_DIRECT) backend is not implemented yet (device {})",
            self.path
        )
    }

    fn describe(&self) -> String {
        format!("spti://{} (unimplemented)", self.path)
    }
}
