//! Explicit MediaTek recovery: no backup, installed-firmware or family policy.
use super::Mtk;
use crate::backend::{
    DeviceAccess, ReadDevice, RecoveryFacet, RecoveryTarget, UpdateFailure, UpdateOutcome,
    WriteDevice,
};
use crate::transport::{ScsiTransport, SharedDevice};
use anyhow::Result;
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
        use crate::backend::detection::{self, Conclusion, Evidence};
        let detected = detection::detect(dev)?;
        let boot = detected.identity.revision == "BOOT";
        match detected.conclusion {
            Conclusion::Detected(Evidence::Mediatek(_)) => {}
            Conclusion::Ambiguous => {
                anyhow::bail!("ambiguous firmware protocol; no firmware written")
            }
            _ => return Ok(None),
        }
        let shared = SharedDevice::new(dev);
        let mut reads = ScsiTransport::reads(&shared);
        let result = match current {
            Some(current) => {
                let envelope =
                    mediatek_optical::envelope::Envelope::load(current).map_err(|e| {
                        anyhow::Error::new(e).context(crate::user_error::IssueCode::CurrentInvalid)
                    })?;
                if boot {
                    // Current describes an application, not the active BOOT receiver.
                    // Validate the file above, but derive the receiver from live code;
                    // prepare still checks target integrity and chip compatibility.
                    crate::diagnostics::record("MediaTek BOOT recovery: using live boot receiver evidence; Current application reference is not used for receiver binding");
                    recovery::Receiver::identify(&mut reads)
                } else {
                    recovery::Receiver::identify_reference(&mut reads, &envelope).map(Some)
                }
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
            result => result
                .map_err(|error| {
                    use mediatek_optical::CodedError;
                    let issue = crate::user_error::IssueCode::from(error.kind());
                    anyhow::Error::new(error).context(issue)
                })
                .map(|receiver| {
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
    fn prepare(
        &self,
        _dev: &mut ReadDevice<'_>,
        receiver: &RecoveryTarget,
        _current: Option<&[u8]>,
        target: &[u8],
        bypass_family_check: bool,
    ) -> Result<Box<dyn crate::backend::PreparedRecoveryUpdate>> {
        if bypass_family_check {
            return Err(crate::backend::UnsupportedFamilyOverride.into());
        }
        let bound = receiver
            .state::<RecoveryReceiver>()
            .map_err(|error| UpdateFailure::before_write("recovery preparation", error))?;
        crate::output::publish(crate::output::Event::Phase {
            phase: "preparing",
            component: "filter.firmware",
            done: None,
            total: None,
        });
        let plan = bound.receiver.prepare(target).map_err(|e| {
            use mediatek_optical::CodedError;
            let issue = crate::user_error::IssueCode::from(e.kind());
            UpdateFailure::before_write(
                "recovery preparation",
                anyhow::Error::new(e).context(issue),
            )
        })?;
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
        Ok(Box::new(Prepared(plan)))
    }

    fn recover(
        &self,
        mut dev: DeviceAccess<'_, '_>,
        receiver: &RecoveryTarget,
        current: Option<&[u8]>,
        target: &[u8],
    ) -> Result<UpdateOutcome> {
        let plan = self.prepare(
            &mut ReadDevice::for_backend(dev.scsi(), self),
            receiver,
            current,
            target,
            false,
        )?;
        let Some(writer) = dev.writer() else {
            crate::output::field(
                "Recovery",
                "Prepared MediaTek image; dry run, no firmware written",
            );
            return Ok(UpdateOutcome::Planned);
        };
        plan.execute(writer)
    }
}

struct Prepared(recovery::PreparedRecovery);

impl crate::backend::PreparedRecoveryUpdate for Prepared {
    fn execute(&self, dev: &mut WriteDevice<'_>) -> Result<UpdateOutcome> {
        execute(dev, &self.0)
    }
}

fn execute(
    writer: &mut WriteDevice<'_>,
    plan: &recovery::PreparedRecovery,
) -> Result<UpdateOutcome> {
    super::flash::log_transfer(plan.plan());
    let (result, accepted_bytes, upload_complete, entry_attempted, payload_attempted) = {
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
            writes.payload_write_attempted(),
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
            recovery::Error::Startup(_) => ("target startup confirmation", true),
            _ => (
                "recovery receiver checks",
                entry_attempted || payload_attempted,
            ),
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
                recovery::Error::Startup(_) => crate::backend::UpdateProgress::UploadComplete,
                recovery::Error::Flash(_) if upload_complete => {
                    crate::backend::UpdateProgress::UploadComplete
                }
                recovery::Error::Flash(_) if accepted_bytes > 0 => {
                    crate::backend::UpdateProgress::PayloadAccepted
                }
                recovery::Error::Flash(_) => crate::backend::UpdateProgress::PayloadAttempted,
                _ if upload_complete => crate::backend::UpdateProgress::UploadComplete,
                _ if accepted_bytes > 0 => crate::backend::UpdateProgress::PayloadAccepted,
                _ if payload_attempted => crate::backend::UpdateProgress::PayloadAttempted,
                _ if entry_attempted => crate::backend::UpdateProgress::EntryAttempted,
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
