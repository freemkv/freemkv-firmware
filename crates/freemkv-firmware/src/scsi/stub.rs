//! Non-Linux stub SCSI backend.
//!
//! Builds and constructs fine, but any real command errors out. This keeps the
//! CLI usable on macOS/Windows for the offline subcommands (`list`, CMAC
//! verify/resign, dry-run flash planning) while the real SPTI/macOS transports
//! remain TODO.

use anyhow::{bail, Result};

use super::ScsiDevice;

/// A do-nothing SCSI device for platforms without a real backend yet.
pub struct StubDevice {
    path: String,
}

impl StubDevice {
    /// "Open" a stub device. Never fails; performs no I/O.
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self {
            path: path.to_string(),
        })
    }
}

impl ScsiDevice for StubDevice {
    fn command_in(&mut self, _cdb: &[u8], _alloc_len: usize) -> Result<Vec<u8>> {
        bail!(
            "SCSI SG_IO backend is Linux-only; no real transport on this platform yet (device {})",
            self.path
        )
    }

    fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
        bail!(
            "SCSI SG_IO backend is Linux-only; no real transport on this platform yet (device {})",
            self.path
        )
    }

    fn describe(&self) -> String {
        format!("stub://{} (no SCSI on this platform)", self.path)
    }
}
