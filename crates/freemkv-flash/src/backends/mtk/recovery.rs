//! Explicit MediaTek recovery: no backup, installed-firmware or family policy.
use super::receiver_reference::{self, Reference};
use super::Mtk;
use crate::backend::{DeviceAccess, ReadDevice, RecoveryFacet, RecoveryTarget, WriteDevice};
use crate::transport::{ScsiTransport, SharedDevice};
use anyhow::{anyhow, Result};
use mediatek_optical::{recovery, update::FlashTransport};

struct RecoveryReceiver {
    receiver: recovery::Receiver,
    reference: Option<Reference>,
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
        let result = recovery::Receiver::identify(&mut reads);
        crate::diagnostics::record(format!(
            "MediaTek recovery identification: {}",
            reads.read_summary()
        ));
        let summary = reads.read_summary();
        let (result, reference) = match result {
            Err(error)
                if matches!(
                    &error,
                    recovery::Error::Receiver(
                        mediatek_optical::receiver::Error::Unknown
                            | mediatek_optical::receiver::Error::UnknownEntry
                            | mediatek_optical::receiver::Error::Read(_)
                    )
                ) && current.is_some() =>
            {
                crate::diagnostics::record(format!("MediaTek live receiver analysis failed: {error}; checking explicit Current reference"));
                let reference = Reference::bind(&mut reads, current.expect("guarded Current"))?;
                let analysis = std::cell::Cell::new(true);
                let mut source = ScsiTransport::reads(&shared)
                    .receiver_source(Some(reference.image()), &analysis);
                let result = recovery::Receiver::identify(&mut source);
                reference.revalidate(&mut reads)?;
                (result, Some(reference))
            }
            other => (other, None),
        };
        result
            .map_err(|e| anyhow!("Unable to read or identify the running firmware's receiver code from the drive. Select the firmware currently installed as Current instead of Read from drive. For BH16NS40 INTM, choose intermediate.bin from the TAR, not the original 1.V1 or target 1.V9. No target firmware was sent. Diagnostic detail: {e}. {summary}. Encoding was not guessed."))
            .map(|r| {
                r.map(|receiver| {
                    RecoveryTarget::new(
                        format!(
                            "{} {:?} ({:?})",
                            receiver.chip(),
                            receiver.mode(),
                            receiver.encoding()
                        ),
                        RecoveryReceiver { receiver, reference },
                    )
                })
            })
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
    ) -> Result<()> {
        let bound = receiver.state::<RecoveryReceiver>()?;
        let plan = bound.receiver.prepare(target).map_err(|e| anyhow!("{e}"))?;
        crate::output::field(
            "Receiver code source",
            if bound.reference.is_some() {
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
            format!("{:?}; {:?} transfer", plan.mode(), plan.encoding()),
        );
        let Some(writer) = dev.writer() else {
            crate::output::field(
                "Recovery",
                "Prepared MediaTek image; dry run, no firmware written",
            );
            return Ok(());
        };
        execute(writer, &plan, bound.reference.as_ref())
    }
}

fn execute(
    writer: &mut WriteDevice<'_>,
    plan: &recovery::PreparedRecovery,
    reference: Option<&Reference>,
) -> Result<()> {
    let result = {
        let shared = SharedDevice::new(&mut *writer);
        let (mut reads, writes) = (ScsiTransport::reads(&shared), ScsiTransport::flash(&shared));
        if let Some(reference) = reference {
            reference.revalidate(&mut reads)?;
        }
        let analysis = std::cell::Cell::new(true);
        let mut reads = reads.receiver_source(reference.map(Reference::image), &analysis);
        let mut writes = writes.starts_session(&analysis);
        let mut runtime = super::flash::Runtime::new();
        plan.flash(
            FlashTransport {
                reads: &mut reads,
                writes: &mut writes,
            },
            &mut runtime,
        )
    };
    let verified = match result {
        Ok(verified) => verified,
        Err(recovery::Error::Flash(
            ref error @ mediatek_optical::update::FlashError::Incomplete { .. },
        )) => {
            receiver_reference::confirm_started(writer, plan.plan().image())?;
            receiver_reference::limited_verification(&error.to_string());
            return Ok(());
        }
        Err(error) => {
            if matches!(
                &error,
                recovery::Error::Flash(mediatek_optical::update::FlashError::Entry(_))
            ) {
                crate::recovery_diagnostics::entry_failure(writer, &error.to_string());
            } else {
                crate::diagnostics::record(format!("Recovery original failure: {error}; broad diagnostics skipped because programming state is not proven idle"));
            }
            return Err(anyhow!("MediaTek recovery failed: {error}"));
        }
    };
    crate::output::field(
        "Recovery",
        format!(
            "Target firmware running; {} protected bytes verified",
            verified.checked
        ),
    );
    Ok(())
}
