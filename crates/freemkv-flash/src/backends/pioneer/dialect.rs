//! Select the OEM update-entry dialect from decoded installed firmware.
//! Product strings are display data, never an entry-protocol authority.

use anyhow::{bail, Context, Result};
use pioneer_optical::{
    envelope::{decode_envelope, Layout},
    image::kernel_marker_policy,
    DriveClass, Identity,
};

pub(super) fn from_kernel(kernel: &[u8]) -> Result<DriveClass> {
    let decoded = decode_envelope(kernel)
        .context("installed Kernel could not be decoded to establish the update-entry dialect")?;
    from_decoded(decoded.info().layout, &decoded.image)
}

pub(super) fn from_decoded(layout: Layout, image: &[u8]) -> Result<DriveClass> {
    let class = match layout {
        Layout::KernelFront | Layout::KernelDerived if kernel_marker_policy(image).is_some() => {
            DriveClass::Bd
        }
        Layout::KernelLegacyLe | Layout::KernelRom | Layout::SparseChecksum => DriveClass::Dvr,
        _ => bail!("installed Kernel has no unique recognized update-entry dialect signature"),
    };
    Ok(class)
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
