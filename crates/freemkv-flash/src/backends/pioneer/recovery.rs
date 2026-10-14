//! Recovery with user-supplied receiver evidence, no implicit firmware reads.
//!
//! EXPERIMENTAL cross-receiver recover (hardware-unproven). When the drive's
//! installed Kernel belongs to a different receiver class than the target
//! package (a drive stuck after a same-hardware crossflash), `recover`
//! re-encodes the target Normal into the installed Kernel's receive transport
//! (its XOR-skip offsets, rotation, derived-key pad and authentication) so the
//! installed loader decodes it to the identical zero-checksum body, then writes
//! the untouched target Kernel and the re-encoded Normal. The end-state resident
//! body is byte-identical OEM. The re-encode is PROVEN OFFLINE here (it must
//! decode under the installed Kernel to the identical body with a zero BE32
//! checksum, or recover refuses); it is not yet proven on hardware, so it stays
//! recover-only. A fresh, caller-owned signature is applied: the drive's
//! acceptance of it is part of what is hardware-unproven.
use crate::backend::WriteDevice;
use crate::backends::pioneer::classify_flash_input;
use crate::platform::ScsiDevice;
use crate::transport::{self as transport, flash_err, ScsiTransport, SharedDevice};
use anyhow::{anyhow, bail, ensure, Context, Result};
use pioneer_optical::envelope::builder::{
    encode_normal_for_kernel, NormalKeySource, NormalSignature,
};
use pioneer_optical::envelope::signature::SigningKey;
use pioneer_optical::envelope::{decode_envelope_with_kernel, Envelope, Update, UpdateError};
use pioneer_optical::{cdb, image::ReceiverControl, Identity, Role};
use std::time::Duration;

pub(crate) struct Plan {
    control: [u8; 256],
    kernel_transfer: Vec<u8>,
    normal_transfer: Vec<u8>,
    /// True when the Normal was re-encoded for the installed Kernel's receiver
    /// transport rather than written as the target package shipped it.
    reencoded: bool,
}

/// The big-endian 32-bit additive checksum a resident Kernel requires to be zero
/// before it programs a decoded body. A trailing partial word counts as failed.
fn be32_sum_zero(body: &[u8]) -> bool {
    let (words, rest) = body.as_chunks::<4>();
    rest.is_empty()
        && words
            .iter()
            .fold(0u32, |s, w| s.wrapping_add(u32::from_be_bytes(*w)))
            == 0
}

/// Load the target package to flash, with the Normal-signature guidance, and
/// enforce the boot-time (model, variant) pairing on the written pair.
fn load_target(bytes: &[u8]) -> Result<(Update, Vec<u8>, Vec<u8>)> {
    let (kernel, normal) = classify_flash_input(bytes)?;
    let kernel = kernel.context("Firmware to flash must include Kernel and Normal")?;
    let normal = normal.context("Firmware to flash must include Kernel and Normal")?;
    let result = Update::load(&kernel, &normal);
    if matches!(result, Err(UpdateError::Authentication))
        && normal
            .get(0x170..0x1c0)
            .is_some_and(|signature| signature.iter().all(|b| *b == 0))
    {
        bail!("Firmware to flash has no Normal signature, but its Kernel requires one. Use a signed OEM package for the firmware to flash; an unsigned backup can still be used as Current firmware");
    }
    let update = result.context("cannot decode Firmware to flash")?;
    crate::backends::pioneer::flash_plan::validate_component_headers(Some(&kernel), Some(&normal))
        .map_err(|e| anyhow!("Firmware to flash: {e}"))?;
    Ok((update, kernel, normal))
}

impl Plan {
    pub(crate) fn prepare(current: &[u8], target: &[u8]) -> Result<Self> {
        let (kernel, normal) = classify_flash_input(current)?;
        let installed_kernel =
            Envelope::load(&kernel.context("Current firmware must include Kernel and Normal")?)
                .context("decoding Current Kernel")?;
        let installed_normal = Envelope::load_with_kernel(
            &normal.context("Current firmware must include Kernel and Normal")?,
            &installed_kernel,
        )
        .context("decoding Current Normal")?;
        ensure!(
            installed_kernel.info().kind == pioneer_optical::ComponentKind::Kernel
                && installed_normal.info().kind == pioneer_optical::ComponentKind::Normal,
            "Current firmware must contain Kernel and Normal components"
        );
        let (target, _target_kernel, target_normal) = load_target(target)?;
        Self::assemble(
            &installed_kernel,
            &installed_normal.image,
            target,
            Some(&target_normal),
        )
    }

    #[cfg(test)]
    fn from_updates(current: Update, target: Update) -> Result<Self> {
        Self::assemble(current.kernel(), &current.normal().image, target, None)
    }

    /// True when the Normal was re-encoded for the installed Kernel.
    pub(crate) fn was_reencoded(&self) -> bool {
        self.reencoded
    }

    fn assemble(
        installed_kernel: &Envelope,
        installed_normal_image: &[u8],
        target: Update,
        target_normal_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let control = control_from_image(installed_normal_image)?;
        // Same-family gate: refuse a genuinely cross-family recover when both
        // sides profile. An unrecognized synthetic image profiles to `None` and
        // is carried by the offline re-encode proof below instead.
        if let (Some(i), Some(t)) = (
            pioneer_optical::image::family(installed_normal_image),
            target.family(),
        ) {
            ensure!(
                i == t,
                "recover refused: the installed firmware is family {i} but the target is family \
                 {t} (different hardware family)"
            );
        }
        let (normal_transfer, reencoded) =
            normal_transfer_for_installed(installed_kernel, &target, target_normal_bytes)?;
        Ok(Self {
            control,
            kernel_transfer: target.kernel_transfer().to_vec(),
            normal_transfer,
            reencoded,
        })
    }

    pub(crate) fn execute(&self, dev: &mut WriteDevice<'_>) -> Result<()> {
        self.run(dev, &mut |duration| std::thread::sleep(duration))
    }

    fn run(&self, dev: &mut WriteDevice<'_>, sleep: &mut impl FnMut(Duration)) -> Result<()> {
        let identity = identify_receiver(dev)?;
        let class = identity.class().context("unsupported recovery dialect")?;
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
            (Role::Kernel, self.kernel_transfer.as_slice()),
            (Role::Normal, self.normal_transfer.as_slice()),
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
                        crate::output::field("Recovery", crate::report::Value::text(&format!("Firmware transferred; normal mode reported (revision {}). No firmware readback performed.", id.revision())));
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

/// The update-entry control block, built from the installed firmware image: a
/// descriptor and (for a keyed receiver) the entry key. Extracted from supplied
/// code, never from a controller table or a pretend live descriptor.
fn control_from_image(image: &[u8]) -> Result<[u8; 256]> {
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
    Ok(control)
}

/// The Normal transfer the installed Kernel will receive. When the installed
/// Kernel already decodes the target Normal to the identical zero-checksum body
/// (same receiver transport), the target's own transfer is written unchanged.
/// Otherwise the target Normal body is re-encoded for the installed Kernel's
/// receiver transport and proven offline to decode, under that Kernel, to the
/// identical zero-checksum body before its continuous transfer is returned.
///
/// Returns the transfer bytes and whether a re-encode was performed.
fn normal_transfer_for_installed(
    installed_kernel: &Envelope,
    target: &Update,
    target_normal_bytes: Option<&[u8]>,
) -> Result<(Vec<u8>, bool)> {
    let want = &target.normal().image;
    // Fast path: the installed Kernel is the target's own receiver class, so it
    // decodes the shipped Normal to the identical zero-checksum body. (Without
    // the raw target Normal — the in-process test path — assume this path; the
    // re-encode below needs the raw bytes.)
    let Some(bytes) = target_normal_bytes else {
        return Ok((target.normal_transfer().to_vec(), false));
    };
    if decode_envelope_with_kernel(bytes, installed_kernel)
        .is_some_and(|d| &d.image == want && be32_sum_zero(&d.image))
    {
        return Ok((target.normal_transfer().to_vec(), false));
    }
    // Cross-receiver recover: re-encode the target Normal body for the installed
    // Kernel's receiver transport.
    let header = bytes.get(..0x200).context("target Normal has no header")?;
    let key = match target.normal().encoding_seed() {
        Some(seed) => NormalKeySource::Seed(seed),
        None => bail!(
            "recover refused: the target Normal has no recoverable encoding seed, so it cannot \
             be re-encoded for the installed Kernel's receiver transport"
        ),
    };
    // A fresh, caller-owned signature: self-consistent for the installed Kernel's
    // authentication scheme. Whether the drive trusts it is hardware-unproven.
    let signer = SigningKey::random()
        .map_err(|e| anyhow!("recover: could not create a signing key: {e}"))?;
    let reencoded = encode_normal_for_kernel(
        &installed_kernel.image,
        want,
        header,
        key,
        NormalSignature::Sign(&signer),
    )
    .map_err(|e| {
        anyhow!(
            "recover refused: the target Normal cannot be re-encoded for the installed Kernel's \
             receiver transport (not offline-provable): {e:?}"
        )
    })?;
    // Offline proof under the ACTUAL installed Kernel: the re-encoded Normal must
    // decode to the identical body with a zero BE32 checksum.
    let proof = decode_envelope_with_kernel(&reencoded, installed_kernel).context(
        "recover refused: the re-encoded Normal does not decode under the installed Kernel",
    )?;
    ensure!(
        &proof.image == want && be32_sum_zero(&proof.image),
        "recover refused: the re-encoded Normal does not decode to the identical zero-checksum \
         body under the installed Kernel"
    );
    let transfer = proof.normal_transfer_image().context(
        "recover refused: the re-encoded Normal has no continuous transfer representation",
    )?;
    Ok((transfer, true))
}

/// The refusal for a drive that is not a Pioneer receiver.
pub(crate) const NOT_A_RECEIVER: &str = "Recovery currently supports Pioneer optical drives only; use Flash for supported MediaTek firmware. No firmware written";

/// Check protocol eligibility before firmware reads, even for a dry run.
pub(crate) fn identify_receiver(dev: &mut dyn ScsiDevice) -> Result<Identity> {
    find_receiver(dev)?.context(NOT_A_RECEIVER)
}

/// [`identify_receiver`], with a drive that is not a Pioneer optical drive
/// as `None` (read-only: INQUIRY, then the vendor identity).
pub(crate) fn find_receiver(dev: &mut dyn ScsiDevice) -> Result<Option<Identity>> {
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
    if inquiry[0] & 0x1f != 5 || &inquiry[8..16] != b"PIONEER " {
        return Ok(None);
    }
    let vendor = dev
        .command_in(&cdb::vendor_identity(), pioneer_optical::IDENTITY_LEN)
        .context("Recovery could not read the Pioneer receiver identity; no firmware written")?;
    let identity = Identity::parse(&inquiry, &vendor)
        .context("Recovery received a truncated Pioneer receiver identity; no firmware written")?;
    ensure!(
        identity.class().is_some(),
        "Recovery does not support this receiver's update dialect; no firmware written"
    );
    Ok(Some(identity))
}

fn in_update_mode(id: &Identity) -> bool {
    id.revision() == "0000" && id.normal_tag().is_empty() && !id.kernel_tag().is_empty()
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
