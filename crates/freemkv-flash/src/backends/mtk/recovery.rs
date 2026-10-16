//! Explicit MediaTek recovery: no backup, installed-firmware or family policy.
use super::Mtk;
use crate::backend::{DeviceAccess, ReadDevice, RecoveryFacet, RecoveryTarget, WriteDevice};
use crate::transport::{ScsiTransport, SharedDevice};
use anyhow::{anyhow, Result};
use mediatek_optical::{recovery, update::FlashTransport};

impl RecoveryFacet for Mtk {
    fn requires_current(&self) -> bool {
        false
    }
    fn identify(&self, dev: &mut ReadDevice<'_>) -> Result<Option<RecoveryTarget>> {
        let shared = SharedDevice::new(dev);
        let mut reads = ScsiTransport::reads(&shared);
        recovery::Receiver::identify(&mut reads)
            .map_err(|e| anyhow!("{e}"))
            .map(|r| {
                r.map(|receiver| {
                    RecoveryTarget::new(
                        format!(
                            "{} {:?} ({:?})",
                            receiver.chip(),
                            receiver.mode(),
                            receiver.encoding()
                        ),
                        receiver,
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
        let receiver = receiver.state::<recovery::Receiver>()?;
        let plan = receiver.prepare(target).map_err(|e| anyhow!("{e}"))?;
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
        execute(writer, &plan)
    }
}

fn execute(writer: &mut WriteDevice<'_>, plan: &recovery::PreparedRecovery) -> Result<()> {
    let shared = SharedDevice::new(writer);
    let (mut reads, mut writes) = (ScsiTransport::reads(&shared), ScsiTransport::flash(&shared));
    let mut runtime = super::flash::Runtime::new();
    let verified = plan
        .flash(
            FlashTransport {
                reads: &mut reads,
                writes: &mut writes,
            },
            &mut runtime,
        )
        .map_err(|e| anyhow!("MediaTek recovery failed: {e}"))?;
    crate::output::field(
        "Recovery",
        format!(
            "Target firmware running; {} protected bytes verified",
            verified.checked
        ),
    );
    Ok(())
}
