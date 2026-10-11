//! The MediaTek update in the engine's two stages: `plan` validates the image
//! against the drive (size, CMAC, boot page, chip generation, model) before
//! any backup; `execute` streams it, waits for programming to finish, reads
//! back the integrity-protected ranges and re-identifies the firmware.

use anyhow::{bail, Context, Result};

use super::{
    backup, cdb, crossflash, describe_sequence, enc_needed, enc_transform,
    ensure_flashable_boot_page, ensure_same_chip, flash_sequence, parse_sense, post_commit_status,
    sense_key_is_fatal, Mtk, CHUNK, DESCRIPTOR, IMAGE_SIZE,
};
use crate::backend::{
    AuthorizedPlan, DetailsFacet, FlashFacet, FlashPlan, FlashRequest, FormatRole, PlanLine,
    ReadDevice, SavedBackup, WriteDevice,
};
use crate::platform::ScsiDevice;
use crate::style;

/// What `plan` decided: the image to verify against and the bytes to stream.
struct Plan {
    image: Vec<u8>,
    payload: Vec<u8>,
}

impl FlashFacet for Mtk {
    fn plan(&self, dev: &mut ReadDevice<'_>, req: &FlashRequest) -> Result<FlashPlan> {
        let format = req.input_format;
        if !DESCRIPTOR.owns(format) {
            bail!(
                "a {} cannot be flashed to this {} drive",
                format.label,
                DESCRIPTOR.id
            );
        }
        let mut notes = Vec::new();
        let image = match format.role {
            // A backup archive restores its firmware image only; its per-unit
            // members are reference data, never written.
            FormatRole::Backup => {
                let firmware = backup::validate(&req.input, &req.drive_model, IMAGE_SIZE)?;
                notes.push(PlanLine::Header(
                    "== reflash backup firmware (per-unit data retained as reference) ==".into(),
                ));
                firmware
            }
            FormatRole::Image | FormatRole::Package => req.input.clone(),
        };
        self.validate_image(dev, &image, &req.drive_model)?;
        let (payload, enc) = self.envelope(dev, &image, req.enc_override)?;
        let mut block = vec![
            PlanLine::Header("== flash plan ==".into()),
            PlanLine::Field("device", dev.describe()),
            PlanLine::Field("drive", style::ident_or_unknown(&req.drive_model).into()),
            PlanLine::Field(
                "firmware",
                format!(
                    "{} ({} envelope)",
                    style::human_size(payload.len()),
                    if enc { "encrypted" } else { "plaintext" }
                ),
            ),
            PlanLine::Backup,
            PlanLine::Text(String::new()),
        ];
        let sequence = flash_sequence(payload.len(), CHUNK)?;
        block.push(PlanLine::Block(describe_sequence(&sequence, req.verbose)));
        let mut plan = FlashPlan::new(Plan { image, payload });
        plan.notes = notes;
        plan.dry_run = block.clone();
        plan.after_backup = block;
        Ok(plan)
    }

    fn preflight(&self, dev: &mut ReadDevice<'_>, _plan: &FlashPlan) -> Result<Vec<PlanLine>> {
        if let Err(e) = self.readiness(dev) {
            bail!("read-only preflight failed: {e}");
        }
        Ok(vec![
            PlanLine::Ok(
                "preflight",
                "transport ready; backup capture is checked only on execute".into(),
            ),
            PlanLine::Spaced(Box::new(PlanLine::Warning(
                "DRY RUN: no firmware writes or backup capture. Execute may still fail if a \
                 complete rollback image cannot be read."
                    .into(),
            ))),
        ])
    }

    fn authorize(
        &self,
        _dev: &mut ReadDevice<'_>,
        plan: FlashPlan,
        _backup: &SavedBackup,
    ) -> Result<AuthorizedPlan> {
        plan.state::<Plan>()?;
        Ok(AuthorizedPlan::new(plan, ()))
    }

    fn execute(&self, dev: &mut WriteDevice<'_>, authorized: &AuthorizedPlan) -> Result<()> {
        let plan: &Plan = authorized.plan.state()?;
        println!(
            "\n{}",
            style::bold("EXECUTING flash — do not power off or disconnect the drive...")
        );
        let mut progress = style::Progress::new("flashing firmware", plan.payload.len());
        self.stream(dev, &plan.payload, &mut |sent| progress.set(sent))?;
        println!(
            "upload complete {}",
            style::dim(&format!(
                "({}); waiting for the drive to finish programming...",
                style::human_size(plan.payload.len())
            ))
        );
        let dev = &mut ReadDevice::new(dev, &[]);
        // The drive keeps programming after the last chunk; reading back
        // earlier would surface a mid-program error on a good flash.
        self.wait_ready(dev)?;
        println!("verifying...");
        verify_readback(self, dev, &plan.image)?;
        confirm_identity(self, dev)
    }
}

/// Compare the image's integrity-protected ranges with a read-back. Mutable
/// per-unit regions and the remapped boot page are excluded; a differing or
/// unreadable protected byte fails, since identity alone proves nothing.
fn verify_readback(mtk: &Mtk, dev: &mut ReadDevice<'_>, image: &[u8]) -> Result<()> {
    let protected = mtk.verification_ranges(image);
    let is_protected = |pos: usize| protected.iter().any(|&(s, e)| pos >= s && pos <= e);
    let (mut checked, mut differing, mut unverified) = (0usize, 0usize, 0usize);
    let mut first_bad: Option<(usize, u8, u8)> = None;
    let mut offset = 0usize;
    for piece in image.chunks(CHUNK) {
        let has_protected = (offset..offset + piece.len()).any(&is_protected);
        match mtk.readback(dev, offset, piece.len()) {
            Ok(got) if got.len() == piece.len() => {
                for (i, (a, b)) in got.iter().zip(piece).enumerate() {
                    let pos = offset + i;
                    if !is_protected(pos) {
                        continue;
                    }
                    checked += 1;
                    if a != b {
                        differing += 1;
                        first_bad.get_or_insert((pos, *a, *b));
                    }
                }
            }
            // A protected chunk that errored or came back short stays
            // unverified, so success must not be claimed for it.
            result if has_protected => {
                unverified += 1;
                let reason = match result {
                    Ok(data) => format!("short read: {}/{}", data.len(), piece.len()),
                    Err(error) => format!("{error:#}"),
                };
                crate::diagnostics::record(format!(
                    "read-back incomplete: offset={offset:#x} length={} reason={reason}",
                    piece.len()
                ));
            }
            _ => {}
        }
        offset += piece.len();
    }
    if let Some((pos, read, wrote)) = first_bad {
        bail!(
            "read-back verify FAILED at 0x{pos:06X}: an integrity-protected byte differs \
             (read 0x{read:02X}, wrote 0x{wrote:02X}) — the image did not program cleanly \
             ({differing} of {checked} protected bytes differ)."
        );
    }
    if protected.is_empty() {
        println!(
            "{}",
            style::dim_line(
                "  read-back cross-check: image carries no integrity table; \
                 relying on the drive's firmware identity below."
            )
        );
    } else if unverified > 0 {
        bail!(
            "flash complete but read-back INCOMPLETE: could not read back {unverified} \
             integrity-protected chunk(s) ({} verified). Do NOT trust the exit code as \
             success — physically confirm the drive's firmware identity before shipping.",
            style::human_size(checked),
        );
    } else {
        println!(
            "{}",
            style::status_line(
                "flash complete",
                &format!(
                    "{} of integrity-protected regions verified",
                    style::human_size(checked)
                ),
                style::Status::Ok
            )
        );
    }
    println!(
        "{}",
        style::dim_line(
            "  Integrity is enforced on-device: the drive recomputes CMAC at boot and \
             rejects a bad image. The firmware identity below is the real result."
        )
    );
    Ok(())
}

/// The re-read firmware identity is the authoritative proof that the new
/// image is resident and booted, so an unreadable identity fails the flash.
fn confirm_identity(mtk: &Mtk, dev: &mut ReadDevice<'_>) -> Result<()> {
    match mtk.post_flash_identity(dev) {
        Ok(Some(r)) => {
            let name = match r.matched {
                Some((desc, _)) => desc.to_string(),
                None => r.descriptor.unwrap_or_else(|| "unrecognized".into()),
            };
            println!(
                "{}",
                style::kv("firmware now", &format!("{name}  [{}]", r.fingerprint))
            );
            Ok(())
        }
        Ok(None) => bail!(
            "flash complete but drive did not report a firmware identity — the drive is \
             likely still re-enumerating or has failed to come back. Physically confirm \
             the drive is alive (`info /dev/sgX`) before treating this flash as successful."
        ),
        Err(e) => bail!(
            "flash complete but firmware-identity read-back errored ({e:#}); the drive \
             is not confirmed running the new image. Physically re-verify before \
             shipping."
        ),
    }
}

impl Mtk {
    /// Validate an image against this drive before any write (read-only):
    /// size, CMAC, a stored boot page, chip generation and model.
    pub(crate) fn validate_image(
        &self,
        dev: &mut ReadDevice<'_>,
        image: &[u8],
        drive_product: &str,
    ) -> Result<()> {
        if image.len() != IMAGE_SIZE {
            bail!(
                "firmware .bin must be exactly {} bytes, got {}",
                IMAGE_SIZE,
                image.len()
            );
        }
        if !crate::cmac::verify(image) {
            bail!(
                "firmware image fails its AES-CMAC integrity check — refusing to flash. \
                 A mis-signed or corrupted image is rejected by the drive's boot \
                 authenticator and can brick the drive."
            );
        }
        ensure_flashable_boot_page(image)?;
        let fine_family = Some(ensure_same_chip(dev, image)?);
        crossflash::ensure_image_matches_drive(image, drive_product, fine_family)
    }

    /// The payload to stream and whether the enc envelope was applied.
    pub(crate) fn envelope(
        &self,
        dev: &mut ReadDevice<'_>,
        image: &[u8],
        enc_override: Option<bool>,
    ) -> Result<(Vec<u8>, bool)> {
        let enc = enc_override.unwrap_or_else(|| enc_needed(dev));
        let mut payload = image.to_vec();
        if enc {
            enc_transform(&mut payload)?;
        }
        Ok((payload, enc))
    }

    /// Read-only readiness handshake: PROBE must return the full ROM read;
    /// TEST UNIT READY must answer (benign no-medium included).
    pub(crate) fn readiness(&self, dev: &mut ReadDevice<'_>) -> Result<()> {
        let probe = dev.command_in(&cdb::probe(), cdb::PROBE_LEN)?;
        if probe.len() != cdb::PROBE_LEN {
            bail!(
                "short MediaTek preflight ROM read: got {} of {} bytes",
                probe.len(),
                cdb::PROBE_LEN
            );
        }
        let _ = dev.command_in(&cdb::test_unit_ready(), 0)?;
        Ok(())
    }

    /// Stream the whole payload through `mediatek_optical`'s flash session:
    /// PROBE + TEST UNIT READY + PREPARE, the 16 KiB transfers, then the
    /// commit trailer. The drive programs when the last chunk lands.
    pub(crate) fn stream(
        &self,
        dev: &mut WriteDevice<'_>,
        payload: &[u8],
        progress: &mut dyn FnMut(usize),
    ) -> Result<()> {
        use crate::transport::{mtk_err, ScsiTransport, SharedDevice};
        let shared = SharedDevice::new(dev);
        {
            let mut transport = ScsiTransport::flash(&shared);
            let mut session = mediatek_optical::drive::enter_update(&mut transport)
                .map_err(mtk_err)
                .context(
                    "MediaTek PROBE, TEST UNIT READY or PREPARE failed before any firmware data was \
                     sent; if PREPARE was reached the drive may be in update mode — power-cycle \
                     it before retrying",
                )?;
            let mut sent = 0usize;
            for piece in payload.chunks(CHUNK) {
                session.write(sent as u32, piece).map_err(mtk_err).with_context(|| {
                    format!(
                        "firmware write failed at offset {sent:#x}, length {}; drive may contain partial firmware",
                        piece.len()
                    )
                })?;
                sent += piece.len();
                progress(sent);
            }
            // The burn completed on the final chunk; the reinitializing drive
            // may answer the commit trailer with a transient CHECK CONDITION.
            if let Err(error) = session.finish().map_err(mtk_err) {
                eprintln!("MediaTek commit trailer returned an error: {error:#}; checking completion and read-back");
            }
        }
        shared.with(post_commit_status)
    }

    /// Wait (read-only, bounded at 45 s) for programming to finish, then
    /// check the settled sense. A drive that never settles fails the flash.
    pub(crate) fn wait_ready(&self, dev: &mut ReadDevice<'_>) -> Result<()> {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let error = match dev.command_in(&cdb::test_unit_ready(), 0) {
                Ok(_) => break,
                Err(error) => error,
            };
            crate::diagnostics::record(format!("MediaTek post-flash readiness: {error:#}"));
            if Instant::now() >= deadline {
                bail!(
                    "drive did not settle after the flash burn within 45 s — TEST UNIT READY \
                     never came back Ok. The flash may have FAILED, or the drive is hung; do \
                     NOT trust the exit code as success. Physically power-cycle the drive and \
                    re-verify its firmware identity before shipping. Last error: {error:#}"
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        // Same fatal-sense policy as `post_commit_status`; an unreadable sense
        // warns rather than being swallowed.
        let sense = match dev.command_in(&cdb::request_sense(), cdb::REQUEST_SENSE_LEN) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "warning: post-settle REQUEST SENSE errored ({e:#}); relying on read-back \
                     verify — the drive settled but its final sense state is unknown."
                );
                Vec::new()
            }
        };
        match parse_sense(&sense) {
            Some((key, asc, ascq)) if sense_key_is_fatal(key) => {
                bail!(
                    "post-settle sense reports a flash fault — {}; the flash may have FAILED. \
                     Physically confirm the drive's firmware identity before shipping.",
                    crate::platform::describe_sense(key, asc, ascq)
                );
            }
            Some(_) => {}
            None if !sense.is_empty() => {
                eprintln!(
                    "warning: post-settle REQUEST SENSE returned an unparseable {}-byte reply; \
                     relying on read-back verify.",
                    sense.len()
                );
            }
            None => {}
        }
        Ok(())
    }

    /// Inclusive byte ranges read-back must match: active CMAC entries,
    /// excluding the remapped boot area below 0x1000.
    pub(crate) fn verification_ranges(&self, image: &[u8]) -> Vec<(usize, usize)> {
        let Some(entries) = crate::cmac::parse_table(image).ok() else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|entry| entry.is_active())
            .filter_map(|entry| {
                let start = (entry.start as usize).max(0x1000);
                let end = entry.end as usize;
                (start <= end).then_some((start, end))
            })
            .collect()
    }

    /// Read back `len` bytes at `offset`.
    pub(crate) fn readback(
        &self,
        dev: &mut ReadDevice<'_>,
        offset: usize,
        len: usize,
    ) -> Result<Vec<u8>> {
        dev.command_in(&cdb::read_memory(offset as u32, len as u32), len)
    }
}
