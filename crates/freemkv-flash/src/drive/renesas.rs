//! HL-DT-ST / Renesas drive family (stub).
//!
//! Classifies positive (READ_BUFFER 0xF1 succeeds, Renesas INQUIRY vendor) but
//! dump/flash are not implemented; both return an `Unsupported` error so the
//! MTK-gate keeps a Renesas drive safe.

use std::path::Path;

use anyhow::Result;

use super::{unsupported_family_error, DriveFamily, Family, FlashRequest};
use crate::platform::ScsiDevice;

/// The Renesas drive family (classified, unsupported).
pub struct Renesas;

impl DriveFamily for Renesas {
    fn family(&self) -> Family {
        Family::Renesas
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn dump(&self, _dev: &mut dyn ScsiDevice, _out: &Path) -> Result<()> {
        Err(unsupported_family_error(Family::Renesas))
    }

    fn flash(&self, _dev: &mut dyn ScsiDevice, _req: &FlashRequest) -> Result<()> {
        Err(unsupported_family_error(Family::Renesas))
    }
}
