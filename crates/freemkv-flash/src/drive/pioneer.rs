//! Pioneer drive family (stub).
//!
//! Classifies positive (READ_BUFFER 0xF1 succeeds) but dump/flash are not
//! implemented; both return an `Unsupported` error so the MTK-gate keeps a
//! Pioneer drive safe.

use std::path::Path;

use anyhow::Result;

use super::{unsupported_family_error, DriveFamily, Family, FlashRequest};
use crate::platform::ScsiDevice;

/// The Pioneer drive family (classified, unsupported).
pub struct Pioneer;

impl DriveFamily for Pioneer {
    fn family(&self) -> Family {
        Family::Pioneer
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn dump(&self, _dev: &mut dyn ScsiDevice, _out: &Path) -> Result<()> {
        Err(unsupported_family_error(Family::Pioneer))
    }

    fn flash(&self, _dev: &mut dyn ScsiDevice, _req: &FlashRequest) -> Result<()> {
        Err(unsupported_family_error(Family::Pioneer))
    }
}
