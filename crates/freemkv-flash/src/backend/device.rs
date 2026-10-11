//! Read-only device handles. A backend's read-only operations receive a
//! [`ReadDevice`], which refuses every data-out command except the read-unlock
//! commands the backend declares. Writable handles come only from the engine's
//! gates (`engine::gates::WriteDevice`).

use anyhow::{bail, Result};

use crate::platform::{MediumStatus, ScsiDevice};

/// A data-out command a backend declares, matched by CDB.
pub struct CdbPattern {
    /// What the command is, for refusals and reviews.
    pub label: &'static str,
    /// Whether a CDB is this command.
    pub matches: fn(&[u8]) -> bool,
}

/// Whether `cdb` matches any of `patterns`.
pub(crate) fn declared(patterns: &[CdbPattern], cdb: &[u8]) -> bool {
    patterns.iter().any(|p| (p.matches)(cdb))
}

/// The refusal for an undeclared data-out command.
pub(crate) fn refuse(cdb: &[u8]) -> anyhow::Error {
    let hex: String = cdb.iter().map(|b| format!("{b:02x}")).collect();
    anyhow::anyhow!(
        "refused data-out command {hex}: a read-only operation may only send its \
         backend's declared read-unlock commands"
    )
}

/// A device lent to a read-only operation.
pub struct ReadDevice<'d> {
    dev: &'d mut dyn ScsiDevice,
    allowed: &'static [CdbPattern],
}

impl<'d> ReadDevice<'d> {
    /// Wrap `dev`, allowing only the data-out commands in `allowed`.
    pub fn new(dev: &'d mut dyn ScsiDevice, allowed: &'static [CdbPattern]) -> Self {
        Self { dev, allowed }
    }

    fn check(&self, cdb: &[u8]) -> Result<()> {
        if !declared(self.allowed, cdb) {
            bail!(refuse(cdb));
        }
        Ok(())
    }
}

impl ScsiDevice for ReadDevice<'_> {
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
        self.dev.command_in(cdb, alloc_len)
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.check(cdb)?;
        self.dev.command_out(cdb, data)
    }

    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.check(cdb)?;
        self.dev.command_out_strict(cdb, data)
    }

    fn describe(&self) -> String {
        self.dev.describe()
    }

    fn medium_status(&mut self) -> Result<MediumStatus> {
        self.dev.medium_status()
    }
}

/// The device a dump or recovery receives: read-only, or a write grant the
/// engine issued after that operation's gates passed.
pub enum DeviceAccess<'a, 'd> {
    /// Read-only access.
    Read(&'a mut ReadDevice<'d>),
    /// A gated write grant.
    Write(&'a mut crate::engine::gates::WriteDevice<'d>),
}

impl<'d> DeviceAccess<'_, 'd> {
    /// The device for reads (and, under a write grant, writes).
    pub fn scsi(&mut self) -> &mut dyn ScsiDevice {
        match self {
            Self::Read(dev) => &mut **dev,
            Self::Write(dev) => &mut **dev,
        }
    }

    /// The write grant, when the engine issued one.
    pub fn writer(&mut self) -> Option<&mut crate::engine::gates::WriteDevice<'d>> {
        match self {
            Self::Read(_) => None,
            Self::Write(dev) => Some(&mut **dev),
        }
    }
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
