//! Recovery prepares supplied receiver evidence and delegates execution to optical.
use crate::backend::{UpdateOutcome, WriteDevice};
use crate::backends::pioneer::classify_flash_input;
use crate::platform::ScsiDevice;
#[cfg(test)]
use anyhow::bail;
use anyhow::{ensure, Context, Result};
use pioneer_optical::envelope::{Envelope, Update};
use pioneer_optical::receiver::{ExecutionMode, PreparedUpdate, Receiver};
use pioneer_optical::{cdb, Identity};
#[cfg(test)]
use std::time::Duration;

pub(crate) struct Plan {
    prepared: PreparedUpdate,
    reencoded: bool,
    #[cfg(test)]
    control: [u8; 256],
}

pub(crate) struct Current {
    kernel: Envelope,
    normal: Envelope,
}

/// A failed or partial live capture asks for a supplied Current file.
pub(super) fn captured_current(capture: Result<Vec<u8>>) -> Result<Current> {
    capture
        .and_then(|bytes| Current::load(&bytes))
        .map_err(|source| crate::backend::CurrentFirmwareRequired { source }.into())
}

impl Current {
    pub(crate) fn load(bytes: &[u8]) -> Result<Self> {
        let (kernel, normal) = classify_flash_input(bytes)?;
        let kernel =
            Envelope::load(&kernel.context("Current firmware must include Kernel and Normal")?)
                .context("decoding Current Kernel")?;
        let normal = Envelope::load_with_kernel(
            &normal.context("Current firmware must include Kernel and Normal")?,
            &kernel,
        )
        .context("decoding Current Normal")?;
        ensure!(
            kernel.info().kind == pioneer_optical::ComponentKind::Kernel
                && normal.info().kind == pioneer_optical::ComponentKind::Normal,
            "Current firmware must contain Kernel and Normal components"
        );
        ensure!(
            kernel.update_dialect().is_some(),
            "Current Kernel update protocol is unsupported; no firmware written"
        );
        Receiver::detect_with_kernel(&normal, &kernel).context(
            "Current firmware receiver requirements are unsupported; no firmware written",
        )?;
        ensure!(
            kernel.info().vendor == normal.info().vendor,
            "Current Kernel and Normal vendors disagree; no firmware written"
        );
        Ok(Self { kernel, normal })
    }
}

impl Plan {
    #[cfg(test)]
    pub(crate) fn prepare(current: &[u8], target: &[u8]) -> Result<Self> {
        Self::with_current(&Current::load(current)?, target)
    }

    pub(crate) fn with_current(current: &Current, target: &[u8]) -> Result<Self> {
        let (kernel, normal) = classify_flash_input(target)?;
        let kernel = kernel.context("Firmware to flash must include Kernel and Normal")?;
        let normal = normal.context("Firmware to flash must include Kernel and Normal")?;
        let target = super::normal_prepare::pair(&kernel, &normal)?;
        let reencoded = target.normal_transfer() != normal;
        Self::assemble(&current.kernel, &current.normal, target, reencoded)
    }

    #[cfg(test)]
    fn from_updates(current: Update, target: Update) -> Result<Self> {
        let original = target.normal_transfer();
        let bytes = super::normal_prepare::prepare(target.kernel(), target.normal(), original)?;
        let changed = bytes != original;
        let target = if changed {
            super::normal_prepare::load_pair(target.kernel_transfer(), &bytes)?
        } else {
            target
        };
        Self::assemble(current.kernel(), current.normal(), target, changed)
    }

    fn assemble(
        kernel: &Envelope,
        normal: &Envelope,
        target: Update,
        reencoded: bool,
    ) -> Result<Self> {
        let receiver = Receiver::detect_with_kernel(normal, kernel)
            .context("Current firmware receiver requirements are unsupported")?;
        #[cfg(test)]
        let control = receiver.entry_control(&normal.image[..16])?;
        let prepared = receiver
            .prepare(target)
            .map_err(super::flash::preparation_error)?;
        Ok(Self {
            prepared,
            reencoded,
            #[cfg(test)]
            control,
        })
    }

    pub(crate) fn was_reencoded(&self) -> bool {
        self.reencoded
    }
    pub(crate) fn requires_restoration(&self) -> bool {
        self.prepared.restoration_kernel_transfer().is_some()
    }
    pub(crate) fn execute(&self, dev: &mut WriteDevice<'_>) -> Result<UpdateOutcome> {
        super::flash::execute_prepared(
            dev,
            super::flash::PreparedFlash::Complete(&self.prepared),
            ExecutionMode::Recovery,
        )
    }
    #[cfg(test)]
    fn run(
        &self,
        dev: &mut WriteDevice<'_>,
        sleep: &mut impl FnMut(Duration),
    ) -> Result<UpdateOutcome> {
        super::flash::execute_with_sleep(
            dev,
            super::flash::PreparedFlash::Complete(&self.prepared),
            ExecutionMode::Recovery,
            sleep,
        )
    }
}

#[cfg(test)]
fn be32_sum_zero(body: &[u8]) -> bool {
    super::flash_plan::be32_sum_zero(body)
}

/// The refusal for a drive that is not a Pioneer receiver.
pub(crate) const NOT_A_RECEIVER: &str = "Recovery requires a supported Pioneer-protocol optical drive; supply its Current firmware to identify an OEM receiver, or use Flash for supported MediaTek firmware. No firmware written";

/// Check protocol eligibility before firmware reads, even for a dry run.
#[cfg(test)]
pub(crate) fn identify_receiver(dev: &mut dyn ScsiDevice) -> Result<Identity> {
    find_receiver(dev)?.context(NOT_A_RECEIVER)
}

/// [`identify_receiver`], with a drive that is not a Pioneer optical drive
/// as `None` (read-only: INQUIRY, then the vendor identity).
#[cfg(test)]
pub(crate) fn find_receiver(dev: &mut dyn ScsiDevice) -> Result<Option<Identity>> {
    find_receiver_with_current(dev, None)
}

/// Supplied decoded receiver code authorizes the vendor identity probe for OEM
/// drives. A vendor name alone never selects an additional protocol probe.
pub(crate) fn find_receiver_with_current(
    dev: &mut dyn ScsiDevice,
    current: Option<&Current>,
) -> Result<Option<Identity>> {
    let inquiry = dev
        .command_in(
            &cdb::inquiry(pioneer_optical::INQUIRY_LEN as u8),
            pioneer_optical::INQUIRY_LEN,
        )
        .context("Recovery could not identify the selected drive; no firmware written")?;
    ensure!(
        inquiry.len() >= pioneer_optical::INQUIRY_LEN,
        "Recovery received a truncated drive identity; no firmware written"
    );
    let field = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes)
            .trim_matches([' ', '\0'])
            .to_owned()
    };
    let expected_vendor = current.map_or("PIONEER", |c| c.kernel.info().vendor.as_str());
    if inquiry[0] & 0x1f != 5 || field(&inquiry[8..16]) != expected_vendor {
        return Ok(None);
    }
    // The verified loader may only expose a partial product/platform identity.
    // Running Normal firmware must match the supplied installed model first.
    if let Some(current) = current {
        if field(&inquiry[32..36]) != "0000"
            && field(&inquiry[16..32]).split_whitespace().last()
                != Some(current.normal.info().model.as_str())
        {
            return Ok(None);
        }
    }
    let vendor = dev
        .command_in(&cdb::vendor_identity(), pioneer_optical::IDENTITY_LEN)
        .context("Recovery could not read the Pioneer receiver identity; no firmware written")?;
    let identity = Identity::parse(&inquiry, &vendor)
        .context("Recovery received a truncated Pioneer receiver identity; no firmware written")?;
    if let Some(current) = current {
        if identity.revision() != "0000" && !current.normal.targets(&identity) {
            return Ok(None);
        }
    }
    Ok(Some(identity))
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
pub(super) mod tests;
