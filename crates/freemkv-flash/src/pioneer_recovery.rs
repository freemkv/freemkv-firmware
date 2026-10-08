//! Recovery with user-supplied receiver evidence, no implicit firmware reads.
use crate::drive::pioneer::classify_flash_input;
use crate::drive::pioneer_transport::{self as transport, flash_err, ScsiTransport, SharedDevice};
use crate::platform::ScsiDevice;
use anyhow::{bail, ensure, Context, Result};
use pioneer_optical::{cdb, envelope::Update, image::ReceiverControl, Identity, Role};
use std::time::Duration;

pub(crate) struct Plan {
    control: [u8; 256],
    target: Update,
}

fn pair(bytes: &[u8], label: &str) -> Result<Update> {
    let (kernel, normal) = classify_flash_input(bytes)?;
    let kernel = kernel.with_context(|| format!("{label} must include Kernel and Normal"))?;
    let normal = normal.with_context(|| format!("{label} must include Kernel and Normal"))?;
    let result = Update::load(&kernel, &normal);
    if matches!(
        result,
        Err(pioneer_optical::envelope::UpdateError::Authentication)
    ) && normal
        .get(0x170..0x1c0)
        .is_some_and(|signature| signature.iter().all(|b| *b == 0))
    {
        bail!("{label} has no Normal signature, but its Kernel requires one. Use a signed OEM package for the firmware to flash; an unsigned backup can still be used as Current firmware");
    }
    result.with_context(|| format!("cannot decode {label}"))
}

impl Plan {
    pub(crate) fn prepare(current: &[u8], target: &[u8]) -> Result<Self> {
        let (kernel, normal) = classify_flash_input(current)?;
        let kernel = pioneer_optical::envelope::Envelope::load(
            &kernel.context("Current firmware must include Kernel and Normal")?,
        )
        .context("decoding Current Kernel")?;
        let normal = pioneer_optical::envelope::Envelope::load_with_kernel(
            &normal.context("Current firmware must include Kernel and Normal")?,
            &kernel,
        )
        .context("decoding Current Normal")?;
        ensure!(
            kernel.info().kind == pioneer_optical::ComponentKind::Kernel
                && normal.info().kind == pioneer_optical::ComponentKind::Normal,
            "Current firmware must contain Kernel and Normal components"
        );
        Self::from_normal_image(&normal.image, pair(target, "Firmware to flash")?)
    }

    #[cfg(test)]
    fn from_updates(current: Update, target: Update) -> Result<Self> {
        Self::from_normal_image(&current.normal().image, target)
    }

    fn from_normal_image(image: &[u8], target: Update) -> Result<Self> {
        // Extract credentials from supplied code, never from a controller table
        // or a pretend live descriptor. The user asserts this receiver reference.
        let policy = pioneer_optical::image::receiver_control(image)
            .context("Current firmware has an unsupported receiver entry handler")?;
        let descriptor = image
            .get(..16)
            .context("Current firmware has no descriptor")?;
        ensure!(
            descriptor.starts_with(b"PIONEER "),
            "invalid Current firmware descriptor"
        );
        let mut control = [0; 256];
        control[..16].copy_from_slice(descriptor);
        if let ReceiverControl::Key(key) = policy {
            control[16..20].copy_from_slice(&key);
        }
        Ok(Self { control, target })
    }

    pub(crate) fn execute(&self, dev: &mut dyn ScsiDevice) -> Result<()> {
        self.run(dev, &mut |duration| std::thread::sleep(duration))
    }

    fn run(&self, dev: &mut dyn ScsiDevice, sleep: &mut impl FnMut(Duration)) -> Result<()> {
        let identity = transport::identify(dev).context("reading receiver operating mode")?;
        ensure!(
            identity.vendor() == "PIONEER",
            "Recovery requires a Pioneer receiver"
        );
        let class = identity
            .class()
            .context("receiver does not report a supported update dialect")?;
        crate::diagnostics::record(format!("Recovery receiver: product={} revision={} platform={} kernel_tag={} normal_tag={} code={}", identity.product(), identity.revision(), identity.platform(), identity.kernel_tag(), identity.normal_tag(), identity.code()));
        let updating = in_update_mode(&identity);
        crate::output::field(
            "Recovery mode",
            if updating {
                "Already in update mode; entry skipped"
            } else {
                "Entering update mode"
            },
        );
        if !updating {
            let shared = SharedDevice::new(dev);
            let mut transport = ScsiTransport::flash(&shared);
            pioneer_optical::drive::enter_update(&mut transport, class, &self.control)
                .map_err(flash_err)
                .context("update entry failed; no firmware transferred")?;
            sleep(Duration::from_secs(1));
        }
        for (role, bytes) in [
            (Role::Kernel, self.target.kernel_transfer()),
            (Role::Normal, self.target.normal_transfer()),
        ] {
            ensure!(
                !bytes.is_empty() && bytes.len() <= 0x100_0000,
                "invalid transfer size"
            );
            let mut progress = crate::style::Progress::new(
                match role {
                    Role::Kernel => "Recovering Kernel",
                    Role::Normal => "Recovering Normal",
                },
                bytes.len(),
            );
            for (index, chunk) in bytes.chunks(0x8000).enumerate() {
                let offset = index * 0x8000;
                dev.command_out_strict(&cdb::transfer(role, offset as u32, chunk.len() as u32), chunk)
                    .with_context(|| format!("{role:?} write failed at {offset:#x}; firmware may be partial; write was not retried"))?;
                progress.set(offset + chunk.len());
            }
            if role == Role::Kernel {
                sleep(Duration::from_secs(2));
            }
        }
        dev.command_out_strict(&cdb::finish(), &self.control)
            .context("firmware transferred but finish command failed")?;
        sleep(Duration::from_secs(2));
        // No readback: prove normal operation through identity and readiness.
        // NO MEDIUM is normal for an empty recovered optical drive.
        for attempt in 0..=180 {
            let _ = dev.command_in(&cdb::get_event_status(), 8);
            let ready = dev.command_in(&cdb::test_unit_ready(), 0);
            if let Err(error) = &ready {
                crate::diagnostics::record(format!("Recovery readiness poll {attempt}: {error:#}"));
            }
            let usable = ready.is_ok()
                || ready
                    .as_ref()
                    .err()
                    .and_then(crate::platform::sense_triplet)
                    .is_some_and(|(key, asc, _)| key == 2 && asc == 0x3a);
            if usable {
                if let Ok(id) = transport::identify(dev) {
                    crate::diagnostics::record(format!("Recovery post-write identity: revision={} kernel_tag={} normal_tag={} code={}", id.revision(), id.kernel_tag(), id.normal_tag(), id.code()));
                    if !id.revision().is_empty()
                        && !id.revision().starts_with("000")
                        && !id.normal_tag().is_empty()
                    {
                        crate::output::field("Recovery", format!("Firmware transferred; normal mode reported (revision {}). No firmware readback performed.", id.revision()));
                        return Ok(());
                    }
                }
            }
            if attempt < 180 {
                sleep(Duration::from_millis(500));
            }
        }
        bail!("firmware transferred, but return to normal mode could not be verified within 90 seconds; save the diagnostic log")
    }
}

fn in_update_mode(id: &Identity) -> bool {
    id.revision() == "0000" && id.normal_tag().is_empty() && !id.kernel_tag().is_empty()
}

#[cfg(test)]
#[path = "pioneer_recovery_tests.rs"]
mod tests;
