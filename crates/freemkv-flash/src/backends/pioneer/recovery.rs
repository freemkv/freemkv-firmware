//! Recovery prepares supplied receiver evidence and delegates execution to optical.
use crate::backend::{UpdateOutcome, WriteDevice};
use crate::backends::pioneer::classify_flash_input;
use crate::platform::ScsiDevice;
#[cfg(test)]
use anyhow::bail;
use anyhow::{ensure, Context, Result};
#[cfg(test)]
use pioneer_optical::cdb;
use pioneer_optical::envelope::{Envelope, Update};
use pioneer_optical::receiver::{ExecutionMode, PreparedUpdate, Receiver};
use pioneer_optical::Identity;
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

/// Validated target bytes retained while Current is acquired.
pub(crate) struct Target {
    update: Update,
    reencoded: bool,
}

impl Target {
    pub(crate) fn load(bytes: &[u8]) -> Result<Self> {
        let (kernel, normal) = classify_flash_input(bytes)
            .map_err(|e| e.context(crate::user_error::IssueCode::FirmwareInvalid))?;
        let kernel = kernel.context(crate::user_error::IssueCode::FirmwareInvalid)?;
        let normal = normal.context(crate::user_error::IssueCode::FirmwareInvalid)?;
        let update = super::normal_prepare::pair(&kernel, &normal)?;
        let reencoded = update.normal_transfer() != normal;
        Ok(Self { update, reencoded })
    }

    pub(crate) fn bind(self, current: &Current, bypass_family_check: bool) -> Result<Plan> {
        Plan::assemble_policy(
            &current.kernel,
            &current.normal,
            self.update,
            self.reencoded,
            bypass_family_check,
        )
    }
}

impl crate::backend::PreparedRecoveryUpdate for Plan {
    fn execute(&self, dev: &mut WriteDevice<'_>) -> Result<UpdateOutcome> {
        Plan::execute(self, dev)
    }
}

/// A failed or partial live capture asks for a supplied Current file.
pub(super) fn captured_current(capture: Result<Vec<u8>>) -> Result<Current> {
    capture
        .and_then(|bytes| Current::load(&bytes))
        .map_err(|source| crate::backend::CurrentFirmwareRequired { source }.into())
}

impl Current {
    pub(crate) fn load(bytes: &[u8]) -> Result<Self> {
        let (kernel, normal) = classify_flash_input(bytes)
            .map_err(|e| e.context(crate::user_error::IssueCode::FirmwareInvalid))?;
        let kernel =
            Envelope::load(&kernel.context(crate::user_error::IssueCode::CurrentIncomplete)?)
                .map_err(super::flash::preparation_error)
                .context("decoding Current Kernel")?;
        let normal = Envelope::load_with_kernel(
            &normal.context(crate::user_error::IssueCode::CurrentIncomplete)?,
            &kernel,
        )
        .map_err(super::flash::preparation_error)
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
        Receiver::detect_with_kernel(&normal, &kernel)
            .map_err(super::flash::preparation_error)
            .context(
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
    pub(crate) fn with_family_override(
        current: &Current,
        target: &[u8],
        bypass: bool,
    ) -> Result<Self> {
        Self::with_current_policy(current, target, bypass)
    }
    #[cfg(test)]
    pub(crate) fn prepare(current: &[u8], target: &[u8]) -> Result<Self> {
        Self::with_current(&Current::load(current)?, target)
    }

    #[cfg(test)]
    pub(crate) fn with_current(current: &Current, target: &[u8]) -> Result<Self> {
        Self::with_current_policy(current, target, false)
    }

    #[cfg(test)]
    pub(crate) fn with_current_policy(
        current: &Current,
        target: &[u8],
        bypass_family_check: bool,
    ) -> Result<Self> {
        Target::load(target)?.bind(current, bypass_family_check)
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

    #[cfg(test)]
    fn assemble(
        kernel: &Envelope,
        normal: &Envelope,
        target: Update,
        reencoded: bool,
    ) -> Result<Self> {
        Self::assemble_policy(kernel, normal, target, reencoded, false)
    }

    fn assemble_policy(
        kernel: &Envelope,
        normal: &Envelope,
        target: Update,
        reencoded: bool,
        bypass_family_check: bool,
    ) -> Result<Self> {
        let receiver = Receiver::detect_with_kernel(normal, kernel)
            .context("Current firmware receiver requirements are unsupported")?;
        #[cfg(test)]
        let control = receiver.entry_control(&normal.image[..16])?;
        let target_model = target.normal().info().model.clone();
        let prepared = if bypass_family_check {
            receiver.prepare_without_family_check(target)
        } else {
            receiver.prepare(target)
        }
        .map_err(|error| {
            if matches!(
                &error,
                pioneer_optical::receiver::PreparationError::Compatibility(
                    pioneer_optical::receiver::Error::FamilyMismatch { .. }
                )
            ) {
                anyhow::Error::new(crate::backend::HardwareMismatch {
                    installed_model: normal.info().model.clone(),
                    target_model,
                    source: super::flash::preparation_error(error),
                })
            } else {
                super::flash::preparation_error(error)
            }
        })?;
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
    pub(crate) fn bridge_warnings(&self) -> Vec<String> {
        super::bridge_warnings(&self.prepared)
    }
    #[cfg(test)]
    pub(crate) fn requires_restoration(&self) -> bool {
        self.prepared.final_stage_kernel_transfer().is_some()
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

/// Shared protocol evidence identifies OEM drives; Current binds the installed receiver.
pub(crate) fn find_receiver_with_current(
    dev: &mut dyn ScsiDevice,
    current: Option<&Current>,
) -> Result<Option<Identity>> {
    use crate::backend::detection::{self, Conclusion, Evidence};
    let detection = detection::detect(dev)?;
    let identity = match detection.conclusion {
        Conclusion::Detected(Evidence::Pioneer(evidence)) => evidence.identity().clone(),
        Conclusion::Ambiguous => anyhow::bail!("ambiguous firmware protocol; no firmware written"),
        Conclusion::Unknown => match detection.pioneer_identity {
            Some(id) if id.revision() == "0000" => {
                if current.is_none() {
                    return Err(crate::backend::CurrentFirmwareRequired {
                        source: anyhow::anyhow!(
                            "Loader revision 0000 has incomplete protocol identity; a validated Current firmware reference is required before recovery"
                        ),
                    }
                    .into());
                }
                id
            }
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    if let Some(current) = current {
        if identity.vendor() != current.kernel.info().vendor
            || (identity.revision() != "0000" && !current.normal.targets(&identity))
        {
            return Ok(None);
        }
    }
    Ok(Some(identity))
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
pub(super) mod tests;
