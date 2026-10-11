//! Write grants. A [`WriteDevice`] is the only handle through which a backend
//! may send undeclared data-out commands, and only this module can create one,
//! each time after its operation's gates have passed:
//!
//! | grant | gates |
//! |---|---|
//! | `flash` | `--execute`, risk acknowledgement, a saved pre-flash backup (the tray is checked by the caller, twice) |
//! | `recovery` | `--execute` and risk acknowledgement; no tray check and no backup, by design |
//! | `dump` | the dump command itself; limited to the dump's declared commands |

use anyhow::{bail, Result};

use crate::backend::device::{declared, refuse, CdbPattern};
use crate::backend::FlashRequest;
use crate::platform::{MediumStatus, ScsiDevice};

/// A device lent to a write the engine has authorized.
pub struct WriteDevice<'d> {
    dev: &'d mut dyn ScsiDevice,
    /// `Some` limits data-out to the listed commands (a dump grant).
    limit: Option<&'static [CdbPattern]>,
}

/// Proof that the mandatory pre-flash backup was captured, saved and verified.
pub(in crate::engine) struct SavedBackup {
    /// The `backup:` summary line.
    pub(in crate::engine) summary: String,
    /// The captured bytes: the installed firmware.
    pub(in crate::engine) bytes: Vec<u8>,
}

fn grant<'d>(dev: &'d mut dyn ScsiDevice, limit: Option<&'static [CdbPattern]>) -> WriteDevice<'d> {
    WriteDevice { dev, limit }
}

/// Grant a flash write: requires `--execute`, the risk acknowledgement and the
/// saved backup.
pub(in crate::engine) fn flash<'d>(
    dev: &'d mut dyn ScsiDevice,
    req: &FlashRequest,
    _backup: &SavedBackup,
) -> Result<WriteDevice<'d>> {
    if !req.execute {
        bail!("refusing to write firmware on a dry run");
    }
    if let Err(block) = super::check_safety(req.acknowledged_risk) {
        bail!("SAFETY GATE: {}", block.0);
    }
    Ok(grant(dev, None))
}

/// Grant a recovery write: requires `--execute` and the risk acknowledgement.
pub(in crate::engine) fn recovery(
    dev: &mut dyn ScsiDevice,
    execute: bool,
    acknowledged_risk: bool,
) -> Result<WriteDevice<'_>> {
    if !execute {
        bail!("refusing to write firmware on a recovery dry run");
    }
    if !acknowledged_risk {
        bail!("refusing recovery without acknowledging the risk");
    }
    Ok(grant(dev, None))
}

/// Grant a dump the data-out commands it declares, and nothing else.
pub(in crate::engine) fn dump<'d>(
    dev: &'d mut dyn ScsiDevice,
    writes: &'static [CdbPattern],
) -> WriteDevice<'d> {
    grant(dev, Some(writes))
}

/// An ungated grant for test harnesses that drive an executor directly.
#[cfg(test)]
pub(crate) fn ungated_for_tests(dev: &mut dyn ScsiDevice) -> WriteDevice<'_> {
    grant(dev, None)
}

impl WriteDevice<'_> {
    fn check(&self, cdb: &[u8]) -> Result<()> {
        match self.limit {
            Some(limit) if !declared(limit, cdb) => Err(refuse(cdb)),
            _ => Ok(()),
        }
    }
}

impl ScsiDevice for WriteDevice<'_> {
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

#[cfg(test)]
#[path = "gates_tests.rs"]
mod tests;
