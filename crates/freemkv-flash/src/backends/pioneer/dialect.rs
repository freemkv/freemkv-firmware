//! Select the OEM update-entry dialect from decoded installed firmware.
//! Product strings are display data, never an entry-protocol authority.

use anyhow::{bail, Context, Result};
use pioneer_optical::{envelope::Envelope, DriveClass, Identity};

#[cfg(test)]
pub(super) fn from_kernel(kernel: &[u8]) -> Result<DriveClass> {
    let decoded = Envelope::load(kernel)
        .context("installed Kernel could not be decoded to establish the update-entry dialect")?;
    from_decoded(&decoded)
}

pub(super) fn from_decoded(kernel: &Envelope) -> Result<DriveClass> {
    kernel
        .update_dialect()
        .context("installed Kernel has no unique recognized update-entry dialect signature")
}

pub(super) fn check_live_identity(
    identity: &Identity,
    hardware: &str,
    kernel_tag: &str,
) -> Result<()> {
    if identity.device_type() != 0x05 || identity.vendor() != "PIONEER" {
        bail!("live drive is not a Pioneer optical receiver; refusing before any write");
    }
    if identity.platform() != hardware || identity.kernel_tag() != kernel_tag {
        bail!("live receiver identity differs from the captured installed firmware; refusing before any write");
    }
    Ok(())
}

#[cfg(test)]
#[path = "dialect_tests.rs"]
mod tests;
