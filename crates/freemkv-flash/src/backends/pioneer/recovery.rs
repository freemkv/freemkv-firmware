//! Recovery with user-supplied receiver evidence, no implicit firmware reads.
//! The installed Kernel receives its replacement, then the incoming Kernel
//! receives Normal. Preserve the paired Normal's encoding and OEM signature.
use crate::backend::WriteDevice;
use crate::backends::pioneer::classify_flash_input;
use crate::platform::ScsiDevice;
use crate::transport::{self as transport, flash_err, ScsiTransport, SharedDevice};
use anyhow::{anyhow, bail, ensure, Context, Result};
use pioneer_optical::drive::{Data, Segment, Transport};
use pioneer_optical::envelope::{Envelope, Update};
use pioneer_optical::receiver::transport as kernel_transport;
use pioneer_optical::{cdb, image::ReceiverControl, receiver::Receiver, Identity, Role};
use std::time::Duration;

pub(crate) struct Plan {
    dialect: pioneer_optical::DriveClass,
    installed_hardware: String,
    installed_kernel_tag: String,
    control: [u8; 256],
    kernel_transfer: Vec<u8>,
    normal_transfer: Vec<u8>,
    /// A gated installed Kernel needs an accepted temporary marker before the
    /// original OEM Kernel can be restored by the newly installed loader.
    restoration_kernel_transfer: Option<Vec<u8>>,
    first_kernel_image: Vec<u8>,
    final_kernel_image: Vec<u8>,
    restoration_control: Option<[u8; 256]>,
    restoration_dialect: Option<pioneer_optical::DriveClass>,
    restoration_hardware: String,
    restoration_kernel_tag: String,
    restoration_receive: kernel_transport::KernelReceive,
    /// How the installed loader receives a Kernel, decided from the decoded
    /// Kernel body (same family as the installed drive, enforced by the family
    /// gate), so the write segments match the loader — not a linear stream.
    receive: kernel_transport::KernelReceive,
    /// True when Normal's transport encoding or authentication was prepared
    /// locally rather than written as the target package shipped it.
    reencoded: bool,
    startup_setting: pioneer_optical::startup::Setting,
}

struct Pass<'a> {
    control: &'a [u8; 256],
    kernel: &'a [u8],
    normal: &'a [u8],
    receive: kernel_transport::KernelReceive,
    restoration: bool,
}

/// The big-endian 32-bit additive checksum a resident Kernel requires to be zero
/// before it programs a decoded body. Single source of truth in `flash_plan`
/// (empty body and trailing partial word both fail).
#[cfg(test)]
fn be32_sum_zero(body: &[u8]) -> bool {
    crate::backends::pioneer::flash_plan::be32_sum_zero(body)
}

/// Readiness poll after a recover write: this many attempts, 500 ms apart, so
/// the "within N seconds" ceiling in the failure message is half this count.
const READINESS_POLLS: usize = 180;

/// Load the target package to flash, with the Normal-signature guidance, and
/// enforce the boot-time (model, variant) pairing on the written pair.
fn load_target(bytes: &[u8]) -> Result<(Update, Vec<u8>)> {
    let (kernel, normal) = classify_flash_input(bytes)?;
    let kernel = kernel.context("Firmware to flash must include Kernel and Normal")?;
    let normal = normal.context("Firmware to flash must include Kernel and Normal")?;
    let update = super::normal_prepare::load_pair(&kernel, &normal)?;
    crate::backends::pioneer::flash_plan::validate_component_headers(Some(&kernel), Some(&normal))
        .map_err(|e| anyhow!("Firmware to flash: {e}"))?;
    // Refuse a target whose envelope tail cannot be reproduced, exactly as the
    // flash path does: the re-encode rebuilds the Normal from the decoded body,
    // so an unrecoverable tail would be silently dropped from the written image.
    crate::backends::pioneer::flash_plan::ensure_no_unrecovered_tail(Some(&kernel), Some(&normal))
        .map_err(|e| anyhow!("Firmware to flash: {e}"))?;
    Ok((update, normal))
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
        let (target, target_normal) = load_target(target)?;
        Self::assemble(
            &installed_kernel,
            &installed_normal,
            target,
            Some(&target_normal),
        )
    }

    #[cfg(test)]
    fn from_updates(current: Update, target: Update) -> Result<Self> {
        Self::assemble(current.kernel(), current.normal(), target, None)
    }

    /// True when Normal's transfer encoding or authentication changed locally.
    pub(crate) fn was_reencoded(&self) -> bool {
        self.reencoded
    }

    pub(crate) fn requires_restoration(&self) -> bool {
        self.restoration_kernel_transfer.is_some()
    }

    fn assemble(
        installed_kernel: &Envelope,
        installed_normal: &Envelope,
        target: Update,
        target_normal_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let dialect = super::dialect::from_decoded(installed_kernel)?;
        let control = control_from_image(&installed_normal.image)?;
        let startup_setting = pioneer_optical::startup::setting(&target.normal().image)
            .map_err(|_| anyhow!("target startup checks are ambiguous; no firmware was written"))?;
        // Same hardware family remains mandatory across the Kernel handoff.
        match (
            pioneer_optical::image::family(&installed_normal.image),
            target.family(),
        ) {
            (Some(i), Some(t)) => ensure!(
                i == t,
                "recover refused: the installed firmware is family {i} but the target is family \
                 {t} (different hardware family)"
            ),
            (None, None) => {}
            (installed, _) => bail!(
                "recover refused: cannot confirm the target is the installed drive's hardware \
                 family — {} is unrecognized; refusing (fail closed)",
                if installed.is_none() {
                    "the installed firmware"
                } else {
                    "the target"
                }
            ),
        }
        // Kernel programming hands off before Normal is transferred. The target
        // Kernel, not the old installed Kernel, receives this Normal.
        let (normal_transfer, reencoded) = if let Some(bytes) = target_normal_bytes {
            let encoded = super::normal_prepare::prepare(target.kernel(), target.normal(), bytes)?;
            let changed = encoded != bytes;
            let normal = Envelope::load_with_kernel(&encoded, target.kernel())?;
            (
                normal
                    .normal_transfer_image()
                    .context("Normal has no transfer representation")?,
                changed,
            )
        } else {
            (target.normal_transfer().to_vec(), false)
        };
        // Recovery must use the same receiver-derived marker and two-pass
        // restoration policy as Flash. Sending an OEM 0xFF marker straight to
        // a gated WX1DM loader is rejected at the final Kernel chunk.
        let receiver = Receiver::detect_with_kernel(installed_normal, installed_kernel)
            .context("Current firmware receiver requirements are unsupported")?;
        let prepared = receiver
            .prepare(target.clone())
            .map_err(super::flash::preparation_error)?;
        let restoration_kernel_transfer = prepared
            .restoration_kernel_transfer()
            .map(ToOwned::to_owned);
        let restoration_control = if restoration_kernel_transfer.is_some() {
            Some(control_from_image(&target.normal().image)?)
        } else {
            None
        };
        let restoration_dialect = if restoration_kernel_transfer.is_some() {
            Some(super::dialect::from_decoded(target.kernel())?)
        } else {
            None
        };
        Ok(Self {
            dialect,
            installed_hardware: installed_kernel.info().hardware_version.clone(),
            installed_kernel_tag: installed_kernel.info().kernel_version.clone(),
            control,
            kernel_transfer: prepared.kernel_transfer().to_vec(),
            normal_transfer,
            restoration_kernel_transfer,
            first_kernel_image: prepared.first_kernel_image().to_vec(),
            final_kernel_image: prepared.final_kernel_image().to_vec(),
            restoration_control,
            restoration_dialect,
            restoration_hardware: target.kernel().info().hardware_version.clone(),
            restoration_kernel_tag: target.kernel().info().kernel_version.clone(),
            restoration_receive: kernel_transport::detect(prepared.first_kernel_image()),
            // Detect on the decoded Kernel body (the loader's own code), never
            // the transformed wire bytes, or the fingerprint would be scrambled.
            receive: kernel_transport::detect(&installed_kernel.image),
            reencoded,
            startup_setting,
        })
    }

    pub(crate) fn execute(&self, dev: &mut WriteDevice<'_>) -> Result<()> {
        self.run(dev, &mut |duration| std::thread::sleep(duration))
    }

    fn run(&self, dev: &mut WriteDevice<'_>, sleep: &mut impl FnMut(Duration)) -> Result<()> {
        let identity = identify_receiver(dev)?;
        crate::diagnostics::record(format!("Recovery receiver: product={} revision={} platform={} kernel_tag={} normal_tag={} code={}", identity.product(), identity.revision(), identity.platform(), identity.kernel_tag(), identity.normal_tag(), identity.code()));
        let updating = in_update_mode(&identity);
        let first = Pass {
            control: &self.control,
            kernel: &self.kernel_transfer,
            normal: &self.normal_transfer,
            receive: self.receive,
            restoration: false,
        };
        if !updating {
            super::dialect::check_live_identity(
                &identity,
                &self.installed_hardware,
                &self.installed_kernel_tag,
            )?;
            let setting = self.startup_setting;
            super::flash::report_startup_setting(setting);
            let shared = SharedDevice::new(dev);
            let mut transport = ScsiTransport::flash(&shared);
            pioneer_optical::startup::migration::execute(
                &mut transport,
                setting.parameter,
                setting.value,
                |guard| {
                    let mut device = MigrationDevice { transport: guard };
                    self.run_after_identity(&mut device, self.dialect, false, &first, sleep)
                },
            )
            .map_err(|error| anyhow!("Pioneer recovery startup-setting update: {error}"))?;
        } else {
            crate::diagnostics::record("Recovery startup setting: skipped because the drive is already in update mode; Normal's parameter command is unavailable");
            self.run_after_identity(dev, self.dialect, true, &first, sleep)?;
        }
        if let Some(kernel) = &self.restoration_kernel_transfer {
            verify_kernel_readback(dev, &self.first_kernel_image)
                .context("temporary Kernel was transferred but readback failed; pristine restoration was not started")?;
            let identity = identify_receiver(dev).context(
                "cannot identify the temporary receiver; pristine restoration was not started",
            )?;
            super::dialect::check_live_identity(
                &identity,
                &self.restoration_hardware,
                &self.restoration_kernel_tag,
            )
            .context("temporary receiver identity changed; pristine restoration was not started")?;
            let restoration = Pass {
                control: self
                    .restoration_control
                    .as_ref()
                    .expect("prepared restoration control"),
                kernel,
                normal: &self.normal_transfer,
                receive: self.restoration_receive,
                restoration: true,
            };
            crate::diagnostics::record("Recovery: restoring pristine OEM Kernel in a second pass");
            self.run_after_identity(
                dev,
                self.restoration_dialect.expect("prepared restoration dialect"),
                false,
                &restoration,
                sleep,
            )
            .context("pristine Kernel restoration did not complete; the temporary Kernel may remain installed")?;
            verify_kernel_readback(dev, &self.final_kernel_image)
                .context("pristine Kernel restoration finished but readback did not verify")?;
            crate::output::field("Recovery", "Pristine OEM Kernel restored and verified");
        }
        Ok(())
    }

    fn run_after_identity(
        &self,
        dev: &mut dyn ScsiDevice,
        class: pioneer_optical::DriveClass,
        updating: bool,
        pass: &Pass<'_>,
        sleep: &mut impl FnMut(Duration),
    ) -> Result<()> {
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
            pioneer_optical::drive::enter_update(&mut transport, class, pass.control)
                .map_err(flash_err)
                .context("update entry failed; no firmware transferred")?;
            sleep(Duration::from_secs(1));
        }
        // The installed loader decides how a Kernel is received. Most BD 10xx
        // loaders stage it in two regions at distinct wire offsets rather than
        // one linear stream; the shared planner emits the exact segments (same
        // logic the non-recover flash path uses), so flash and recover deliver a
        // Kernel identically.
        let mut storage = [Segment::PLACEHOLDER; 3];
        let plan =
            kernel_transport::plan(Some(pass.kernel), pass.normal, pass.receive, &mut storage)
                .map_err(|_| {
                    anyhow!(
                "recover refused: the installed Kernel's receive layout is not recognised, so a \
                 safe transfer plan cannot be built; refusing before any write"
            )
                })?;
        // Validate every segment before the first write: an oversized, empty or
        // misaligned span must be refused up front, never discovered only after
        // the Kernel is already written (which would leave the drive half-flashed
        // in update mode). The transfer offset is a 24-bit CDB field, so a length
        // above IMAGE_MAX (0x00ff_ff00) or an offset/length not 256-aligned would
        // truncate the offset mid-session.
        for segment in plan.segments {
            let end = segment.dest_offset as usize + segment.bytes.len();
            ensure!(
                (super::IMAGE_MIN..=super::IMAGE_MAX).contains(&segment.bytes.len())
                    && segment.bytes.len().is_multiple_of(0x100)
                    && (segment.dest_offset as usize).is_multiple_of(0x100)
                    && end <= super::IMAGE_MAX,
                "invalid transfer size"
            );
        }
        let last_kernel = plan.segments.iter().rposition(|s| s.role == Role::Kernel);
        let mut current: Option<Role> = None;
        let mut progress = crate::style::Progress::new("Recovering", 0);
        let mut done = 0usize;
        for (index, segment) in plan.segments.iter().enumerate() {
            if current != Some(segment.role) {
                current = Some(segment.role);
                done = 0;
                let total: usize = plan
                    .segments
                    .iter()
                    .filter(|s| s.role == segment.role)
                    .map(|s| s.bytes.len())
                    .sum();
                progress = crate::style::Progress::new(
                    match segment.role {
                        Role::Kernel => "Recovering Kernel",
                        Role::Normal => "Recovering Normal",
                    },
                    total,
                );
            }
            let role = segment.role;
            for (chunk_index, chunk) in segment.bytes.chunks(super::FLASH_CHUNK).enumerate() {
                let offset = segment.dest_offset + (chunk_index * super::FLASH_CHUNK) as u32;
                let sent = dev.command_out_strict(
                    &cdb::transfer_with_id(segment.buffer_id, offset, chunk.len() as u32),
                    chunk,
                );
                match &sent {
                    Ok(()) => crate::diagnostics::record(format!(
                        "Recovery WRITE BUFFER chunk: role={role:?} offset={offset:#x} length={} result=ok",
                        chunk.len()
                    )),
                    Err(error) => crate::diagnostics::record(format!(
                        "Recovery WRITE BUFFER chunk: role={role:?} offset={offset:#x} length={} result=FAILED sense={:?}: {error:#}",
                        chunk.len(),
                        crate::platform::sense_triplet(error)
                    )),
                }
                sent.with_context(|| format!("{role:?} write failed at {offset:#x}; firmware may be partial; write was not retried"))?;
                done += chunk.len();
                progress.set(done);
            }
            if Some(index) == last_kernel {
                sleep(Duration::from_secs(2));
            }
        }
        dev.command_out_strict(&cdb::finish(), pass.control)
            .context("firmware transferred but finish command failed")?;
        sleep(Duration::from_secs(2));
        // No readback: prove normal operation through identity and readiness.
        // NO MEDIUM is normal for an empty recovered optical drive.
        let mut last_status = String::from("no readiness response");
        for attempt in 0..=READINESS_POLLS {
            // The loader permits REQUEST SENSE while programming. Other
            // commands can take its busy early return and never reach the
            // restart check, even once programming has completed. Neither
            // sense nor event success establishes Normal-mode readiness.
            match dev.command_in(&cdb::request_sense(18), 18) {
                Ok(sense) => crate::diagnostics::record(format!(
                    "Recovery status poll {attempt}: REQUEST SENSE bytes={sense:02x?}"
                )),
                Err(error) => crate::diagnostics::record(format!(
                    "Recovery status poll {attempt}: REQUEST SENSE failed: {error:#}"
                )),
            }
            let _ = dev.command_in(&cdb::get_event_status(), 8);
            let ready = dev.command_in(&cdb::test_unit_ready(), 0);
            if let Err(error) = &ready {
                crate::diagnostics::record(format!("Recovery readiness poll {attempt}: {error:#}"));
                last_status = match crate::platform::sense_triplet(error) {
                    Some((2, 4, 2)) => "drive requires initialization (sense 02/04/02)".into(),
                    Some((key, asc, ascq)) => {
                        format!("drive not ready (sense {key:02x}/{asc:02x}/{ascq:02x})")
                    }
                    None => "readiness command failed; see diagnostic log".into(),
                };
            }
            let usable = ready.is_ok()
                || ready
                    .as_ref()
                    .err()
                    .and_then(crate::platform::sense_triplet)
                    .is_some_and(|(key, asc, _)| key == 2 && asc == 0x3a);
            if usable {
                match transport::identify(dev) {
                    Ok(id) => {
                        crate::diagnostics::record(format!("Recovery post-write identity: revision={} kernel_tag={} normal_tag={} code={}", id.revision(), id.kernel_tag(), id.normal_tag(), id.code()));
                        if !id.revision().is_empty()
                            && !id.revision().starts_with("000")
                            && !id.normal_tag().is_empty()
                        {
                            if pass.restoration {
                                crate::diagnostics::record(format!("Pristine Kernel restoration: normal mode reported (revision {})", id.revision()));
                            } else if self.restoration_kernel_transfer.is_some() {
                                crate::diagnostics::record(format!("Temporary Kernel pass: normal mode reported (revision {}); checking Kernel before OEM restoration", id.revision()));
                            } else {
                                crate::output::field("Recovery", crate::report::Value::text(&format!("Firmware transferred; normal mode reported (revision {}). No firmware readback performed.", id.revision())));
                            }
                            return Ok(());
                        }
                        last_status = format!(
                            "drive identity is still not Normal (revision {:?}, Normal tag {:?})",
                            id.revision(),
                            id.normal_tag()
                        );
                    }
                    Err(error) => {
                        crate::diagnostics::record(format!(
                            "Recovery post-write identity failed: {error:#}"
                        ));
                        last_status = "drive identity could not be read; see diagnostic log".into();
                    }
                }
            }
            if attempt < READINESS_POLLS {
                sleep(Duration::from_millis(500));
            }
        }
        bail!("firmware transferred, but return to normal mode could not be verified within {} seconds; last status: {last_status}. Do not repeat the flash automatically; save the diagnostic log", READINESS_POLLS / 2)
    }
}

/// A temporary compatibility Kernel is never followed by a second write until
/// the drive reports its exact decoded bytes. Verify the pristine Kernel too.
fn verify_kernel_readback(dev: &mut dyn ScsiDevice, expected: &[u8]) -> Result<()> {
    ensure!(expected.len() == 0x10000, "invalid expected Kernel length");
    for (index, chunk) in expected.chunks(0x8000).enumerate() {
        let address = pioneer_optical::image::KERNEL_BASE + (index * 0x8000) as u32;
        let actual = crate::transport::read_memory_exact(dev, address, chunk.len() as u32)
            .with_context(|| format!("reading Kernel at {address:#x}"))?;
        ensure!(
            actual.len() == chunk.len(),
            "short Kernel readback at {address:#x}"
        );
        if let Some(offset) = actual.iter().zip(chunk).position(|(a, b)| a != b) {
            bail!("Kernel readback differs at {:#x}", address + offset as u32);
        }
    }
    Ok(())
}

/// Send every recovery command through the migration guard so a failed update
/// never restores the old parameter after any firmware command was attempted.
struct MigrationDevice<'a, 't, T: Transport> {
    transport: &'a mut pioneer_optical::startup::migration::FlashTransport<'t, T>,
}

impl<T: Transport<Error = anyhow::Error>> ScsiDevice for MigrationDevice<'_, '_, T> {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; len];
        let count = self.transport.exec(cdb, Data::In(&mut bytes))?;
        ensure!(count <= len, "recovery transport returned too many bytes");
        bytes.truncate(count);
        Ok(bytes)
    }

    fn command_out(&mut self, cdb: &[u8], bytes: &[u8]) -> Result<()> {
        self.command_out_strict(cdb, bytes)
    }

    fn command_out_strict(&mut self, cdb: &[u8], bytes: &[u8]) -> Result<()> {
        let count = self.transport.exec(cdb, Data::Out(bytes))?;
        ensure!(
            count == bytes.len(),
            "short recovery write: {count}/{} bytes",
            bytes.len()
        );
        Ok(())
    }

    fn describe(&self) -> String {
        "Pioneer recovery startup transaction".into()
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
    Ok(Some(identity))
}

fn in_update_mode(id: &Identity) -> bool {
    id.revision() == "0000" && id.normal_tag().is_empty() && !id.kernel_tag().is_empty()
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
