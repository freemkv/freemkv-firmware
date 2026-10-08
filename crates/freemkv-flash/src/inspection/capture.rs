//! Cancellation between commands in a live inspection capture.
use super::Control;
use crate::platform::{MediumStatus, ScsiDevice};
use anyhow::Result;

pub(super) struct CancellableDevice<'a> {
    pub device: &'a mut dyn ScsiDevice,
    pub control: &'a Control,
}
impl ScsiDevice for CancellableDevice<'_> {
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
        self.control.check()?;
        self.device.command_in(cdb, alloc_len)
    }
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.control.check()?;
        self.device.command_out(cdb, data)
    }
    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.control.check()?;
        self.device.command_out_strict(cdb, data)
    }
    fn describe(&self) -> String {
        self.device.describe()
    }
    fn medium_status(&mut self) -> Result<MediumStatus> {
        self.control.check()?;
        self.device.medium_status()
    }
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
