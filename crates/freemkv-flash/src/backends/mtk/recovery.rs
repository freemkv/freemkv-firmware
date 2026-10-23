//! Explicit MediaTek recovery: no backup, installed-firmware or family policy.
use super::Mtk;
use crate::backend::{
    DeviceAccess, ReadDevice, RecoveryFacet, RecoveryTarget, UpdateFailure, UpdateOutcome,
    WriteDevice,
};
use crate::transport::{ScsiTransport, SharedDevice};
use anyhow::{anyhow, Result};
use mediatek_optical::{recovery, update::FlashTransport};

struct RecoveryReceiver {
    receiver: recovery::Receiver,
}

impl RecoveryFacet for Mtk {
    fn accepts_current_for_identification(&self) -> bool {
        true
    }
    fn requires_current(&self) -> bool {
        false
    }
    fn identify(&self, dev: &mut ReadDevice<'_>) -> Result<Option<RecoveryTarget>> {
        self.identify_with_current(dev, None)
    }
    fn identify_with_current(
        &self,
        dev: &mut ReadDevice<'_>,
        current: Option<&[u8]>,
    ) -> Result<Option<RecoveryTarget>> {
        let shared = SharedDevice::new(dev);
        let mut reads = ScsiTransport::reads(&shared);
        let result = match current {
            Some(current) => {
                let envelope = mediatek_optical::envelope::Envelope::load(current)?;
                recovery::Receiver::identify_reference(&mut reads, &envelope).map(Some)
            }
            None => recovery::Receiver::identify(&mut reads),
        };
        crate::diagnostics::record(format!(
            "MediaTek recovery identification: {}",
            reads.read_summary()
        ));
        let summary = reads.read_summary();
        match result {
            Err(error)
                if current.is_none()
                    && matches!(
                        &error,
                        recovery::Error::Receiver(
                            mediatek_optical::receiver::Error::Unknown
                                | mediatek_optical::receiver::Error::UnknownEntry
                                | mediatek_optical::receiver::Error::Read(_)
                        )
                    ) =>
            {
                Err(crate::backend::CurrentFirmwareRequired {
                    source: anyhow::Error::new(error).context(summary),
                }
                .into())
            }
            result => result.map_err(anyhow::Error::new).map(|receiver| {
                receiver.map(|receiver| {
                    RecoveryTarget::new(
                        format!(
                            "{} {:?} ({:?})",
                            receiver.chip(),
                            receiver.mode(),
                            receiver.encoding()
                        ),
                        RecoveryReceiver { receiver },
                    )
                })
            }),
        }
    }

    fn unidentified(&self) -> &'static str {
        "no recognized MediaTek recovery receiver; readable chip banner and receiver signature required"
    }
    fn recover(
        &self,
        mut dev: DeviceAccess<'_, '_>,
        receiver: &RecoveryTarget,
        _current: Option<&[u8]>,
        target: &[u8],
    ) -> Result<UpdateOutcome> {
        let bound = receiver
            .state::<RecoveryReceiver>()
            .map_err(|error| UpdateFailure::before_write("recovery preparation", error))?;
        let plan = bound
            .receiver
            .prepare(target)
            .map_err(|e| UpdateFailure::before_write("recovery preparation", anyhow!("{e}")))?;
        crate::output::field(
            "Receiver code source",
            if plan.plan().receiver().provenance()
                == mediatek_optical::receiver::reference::Provenance::CurrentReference
            {
                "Selected Current file; live identity and build metadata matched"
            } else {
                "Live drive reads"
            },
        );
        crate::output::field(
            "Recovery",
            "No backup; model, family and rollback policy bypassed",
        );
        crate::output::field(
            "Receiver",
            format!(
                "{:?}; header {:?}; body {:?}",
                plan.mode(),
                plan.plan().encoding().header,
                plan.plan().encoding().body
            ),
        );
        let Some(writer) = dev.writer() else {
            crate::output::field(
                "Recovery",
                "Prepared MediaTek image; dry run, no firmware written",
            );
            return Ok(UpdateOutcome::Planned);
        };
        execute(writer, &plan)
    }
}

fn execute(
    writer: &mut WriteDevice<'_>,
    plan: &recovery::PreparedRecovery,
) -> Result<UpdateOutcome> {
    super::flash::log_transfer(plan.plan());
    let (result, accepted_bytes, upload_complete, entry_attempted) = {
        let shared = SharedDevice::new(&mut *writer);
        let (mut reads, mut writes) =
            (ScsiTransport::reads(&shared), ScsiTransport::flash(&shared));
        let mut runtime = super::flash::Runtime::new();
        let result = plan.flash_completed(
            FlashTransport {
                reads: &mut reads,
                writes: &mut writes,
            },
            &mut runtime,
        );
        (
            result,
            runtime.payload_bytes_accepted(),
            runtime.upload_complete(),
            writes.empty_write_attempted(),
        )
    };
    let completion = result.map_err(|error| {
        if matches!(
            &error,
            recovery::Error::Flash(mediatek_optical::update::FlashError::Entry(_))
        ) {
            crate::recovery_diagnostics::entry_failure(writer, &error.to_string());
        }
        let (phase, write_started) = match &error {
            recovery::Error::Flash(error) => super::flash::failure_phase(error),
            recovery::Error::Startup => ("target startup confirmation", true),
            _ => ("recovery receiver preflight", false),
        };
        let progress =
            match &error {
                recovery::Error::Flash(mediatek_optical::update::FlashError::Entry(_))
                    if entry_attempted =>
                {
                    crate::backend::UpdateProgress::EntryAttempted
                }
                recovery::Error::Flash(mediatek_optical::update::FlashError::Entry(_)) => {
                    crate::backend::UpdateProgress::Preflight
                }
                recovery::Error::Flash(mediatek_optical::update::FlashError::Transfer {
                    ..
                }) if accepted_bytes == 0 => crate::backend::UpdateProgress::PayloadAttempted,
                recovery::Error::Flash(mediatek_optical::update::FlashError::Transfer {
                    ..
                }) => crate::backend::UpdateProgress::PayloadAccepted,
                recovery::Error::Startup => crate::backend::UpdateProgress::UploadComplete,
                recovery::Error::Flash(_) if upload_complete => {
                    crate::backend::UpdateProgress::UploadComplete
                }
                recovery::Error::Flash(_) if accepted_bytes > 0 => {
                    crate::backend::UpdateProgress::PayloadAccepted
                }
                recovery::Error::Flash(_) => crate::backend::UpdateProgress::PayloadAttempted,
                _ => crate::backend::UpdateProgress::Preflight,
            };
        let source = match error {
            recovery::Error::Flash(error) => super::flash::flash_error(error),
            error => anyhow::Error::new(error),
        };
        source
            .context("MediaTek recovery failed")
            .context(UpdateFailure {
                phase: phase.into(),
                write_started: write_started
                    && progress != crate::backend::UpdateProgress::Preflight,
                progress,
                payload_bytes_accepted: Some(accepted_bytes),
                temporary_firmware: false,
                completed_stages: vec![],
            })
    })?;
    let mut evidence = super::flash::completion_evidence(completion);
    evidence.completed_stages.push("recovery".into());
    Ok(UpdateOutcome::Completed(evidence))
}
