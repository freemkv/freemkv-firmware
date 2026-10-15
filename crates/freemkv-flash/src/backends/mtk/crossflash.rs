//! The MT19xx model gate. An image of the drive's own model is admitted as
//! before. Another model is admitted only when the image and the drive are the
//! same hardware family — `mediatek_optical::image::family`, a content hash of
//! `chip·platform·loader·interface·medium·bd_write` — which the firmware proves
//! is its finest hardware distinction (14x/16x/UHD within a family are firmware
//! limits, not hardware; per-drive calibration lives on the drive and a
//! crossflash does not overwrite it). The chip, family and integrity gates are
//! `mediatek_optical::update`'s; nothing here can be switched on by a user.

use anyhow::{bail, Context, Result};
use mediatek_optical::image::Family;
use mediatek_optical::update::PrepareError;
use mediatek_optical::{layout, Identity};

/// Length of the boot banner at `0x3000` that a crossflash must keep.
pub(crate) const BANNER_LEN: usize = 16;

/// The refusal when the pre-flash backup would not re-admit as a crossflash
/// once the target has booted — the crossflash is not reversible, so refuse it.
pub(crate) const BACKUP_NOT_FLASHABLE_BACK: &str =
    "your backup could not be flashed back; refusing";

/// The identity descriptor's platform code (`+0x46`, e.g. `JB7`): one of the
/// hardware fields `mediatek_optical::image::family` hashes, and the one the
/// boot banner does not carry (BU3 and BU9 share a banner). The descriptor
/// holds it, so a crossflash can tell two families apart at the plan without
/// reading the drive's whole firmware.
const DESCRIPTOR_PLATFORM: core::ops::Range<usize> = 0x46..0x4C;

/// What the gates know about one firmware build: an image, a backup, or the
/// live drive's identity descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Build {
    pub vendor: String,
    pub product: String,
    pub revision: String,
    /// The hardware family, for a complete image or backup. `None` for the
    /// live drive, whose descriptor names its `platform` and `banner` but not
    /// the full family (that needs a complete read, done when the backup is
    /// captured).
    pub family: Option<Family>,
    /// The descriptor platform code; empty when there is no descriptor.
    pub platform: String,
    pub banner: [u8; BANNER_LEN],
}

impl Build {
    /// The facts of a complete image. `product` is the model the same-model
    /// gate has always compared; `vendor` is empty without a tagged descriptor.
    pub(crate) fn of_image(image: &[u8]) -> Result<Self> {
        let chip = freemkv_chipset::detect_chip(image)
            .context("input is not a recognizable MT19xx firmware image — refusing to flash")?;
        let mut banner = [0; BANNER_LEN];
        if let Some(bytes) = layout::BANNER.of(image) {
            banner.copy_from_slice(&bytes[..BANNER_LEN]);
        }
        let platform = layout::DESCRIPTOR
            .of(image)
            .map(|d| crate::backend::trim_ascii(&d[DESCRIPTOR_PLATFORM]))
            .unwrap_or_default();
        Ok(Self {
            vendor: if chip.descriptor_present {
                chip.vendor
            } else {
                String::new()
            },
            product: chip.model,
            revision: chip.rev,
            family: mediatek_optical::image::family(image),
            platform,
            banner,
        })
    }

    /// The live drive's facts from its identity descriptor. The full family
    /// needs a complete read, so it is `None`; the descriptor's `platform` and
    /// the `banner` carry the hardware fields the plan gates a crossflash on.
    pub(crate) fn of_drive(live: &Identity) -> Self {
        let descriptor = live.descriptor_bytes();
        let text = |range: core::ops::Range<usize>| {
            if live.has_descriptor() {
                crate::backend::trim_ascii(&descriptor[range])
            } else {
                String::new()
            }
        };
        let mut banner = [0; BANNER_LEN];
        banner.copy_from_slice(&live.banner_bytes()[..BANNER_LEN]);
        Self {
            vendor: text(0x00..0x08),
            product: live.descriptor_model().to_owned(),
            revision: text(0x18..0x1C),
            family: None,
            platform: text(DESCRIPTOR_PLATFORM),
            banner,
        }
    }

    /// `vendor product revision`, safe to print.
    pub(crate) fn label(&self) -> String {
        crate::backend::sanitize_ascii(&format!(
            "{} {} {}",
            self.vendor, self.product, self.revision
        ))
    }

    /// `vendor product`, safe to print.
    pub(crate) fn model(&self) -> String {
        crate::backend::sanitize_ascii(&format!("{} {}", self.vendor, self.product))
    }
}

/// What the model gate admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The image is the drive's model: the gate as it has always been.
    SameModel,
    /// Another model of the drive's hardware family.
    Crossflash,
}

fn unknown_drive() -> anyhow::Error {
    anyhow::anyhow!(
        "drive model is unknown (empty INQUIRY product) — refusing to flash \
         without confirming the image matches this drive"
    )
}

fn wrong_model(image_model: &str, product: &str) -> String {
    format!(
        "image is built for model {image_model:?} but this drive reports \
         {product:?} — refusing to flash a wrong-model image (pass \
         a compatible image)"
    )
}

/// The crossflash family-mismatch refusal, in the firmware's own family hashes
/// (the drive's, then the image's).
fn different_family(drive: Family, image: Family) -> String {
    format!("this image is for a different hardware family ({drive} vs {image}); refusing to flash")
}

/// The crossflash hardware-mismatch refusal when the drive's family is not yet
/// resolved (the plan has only its descriptor): the chip gate has already
/// matched the chip, so a differing platform or boot banner is a different
/// hardware family. Shown without a hash, which only a full read would give.
fn different_hardware(drive: &Build, image: &Build) -> String {
    format!(
        "this image is for a different hardware family than this drive (image platform {:?} \
         banner {:?} vs drive platform {:?} banner {:?}); refusing to flash",
        image.platform,
        banner_text(&image.banner),
        drive.platform,
        banner_text(&drive.banner),
    )
}

/// A boot banner as safe-to-print text.
fn banner_text(banner: &[u8; BANNER_LEN]) -> String {
    crate::backend::sanitize_ascii(String::from_utf8_lossy(banner).trim())
}

/// The unknown-family refusals, worded like the engine's `family_gate`.
fn unknown_family(error: PrepareError) -> String {
    super::flash::family_gate(&error).unwrap_or_else(|| {
        "could not determine the firmware family; flashing requires a known family".to_string()
    })
}

/// The image↔drive model decision before any backup, against the live identity
/// descriptor. A crossflash is gated on the hardware family: when the drive's
/// family is known (a backup or a fixture built it) on family equality, and at
/// the plan — where the drive is only its descriptor — on the family fields the
/// descriptor carries (platform and boot banner; the chip is already matched by
/// `PreparedUpdate::check`). The full family is re-checked once the backup is
/// read. An unknown drive model, an inconsistent identity, an identity-less
/// image, an unknown or different family is refused. An INTM (interim OEM)
/// build on either side is gated like any other build.
pub(crate) fn decide_plan(drive_product: &str, live: &Build, target: &Build) -> Result<Verdict> {
    let product = drive_product.trim();
    if product.is_empty() {
        return Err(unknown_drive());
    }
    if same_model(&target.product, product) {
        return Ok(Verdict::SameModel);
    }
    // A crossflash candidate: another model. An identity-less image is refused
    // as a wrong-model image, exactly as before crossflash existed.
    let legacy = wrong_model(&target.product, product);
    if target.product.is_empty() {
        bail!("{legacy}");
    }
    // The INQUIRY product and the identity descriptor's model must agree. They
    // are the same string formatted differently (INQUIRY trims the vendor
    // prefix and padding), so compare them the way the same-model gate does:
    // the descriptor model contains the INQUIRY product.
    if live.product.is_empty() || !same_model(&live.product, product) {
        bail!(
            "drive identity is inconsistent: INQUIRY reports {product:?} but its identity \
             descriptor reads {:?} — refusing to flash another model",
            crate::backend::sanitize_ascii(&live.product)
        );
    }
    // The image's family must be known: a crossflash fails closed otherwise.
    let Some(image_family) = target.family else {
        bail!("{}", unknown_family(PrepareError::UnknownTargetFamily));
    };
    match live.family {
        // The drive's full family is known (a backup, or a fixture): the exact
        // family gate runs now.
        Some(drive_family) if drive_family != image_family => {
            bail!("{}", different_family(drive_family, image_family))
        }
        Some(_) => {}
        // Only the descriptor is known: refuse a differing platform or boot
        // banner (the chip is already matched). A same-platform, same-banner
        // image of a different family is admitted now and caught by the exact
        // family gate once the backup is read.
        None if live.platform != target.platform || live.banner != target.banner => {
            bail!("{}", different_hardware(live, target))
        }
        None => {}
    }
    Ok(Verdict::Crossflash)
}

/// The same decision once the backup is read, with the backup as the installed
/// build: [`decide_plan`], then both families must be known and equal, and the
/// boot banners equal.
pub(crate) fn decide_authorized(
    drive_product: &str,
    installed: &Build,
    target: &Build,
) -> Result<Verdict> {
    let verdict = decide_plan(drive_product, installed, target)?;
    if verdict != Verdict::Crossflash {
        return Ok(verdict);
    }
    match (installed.family, target.family) {
        (None, _) => bail!("{}", unknown_family(PrepareError::UnknownInstalledFamily)),
        (_, None) => bail!("{}", unknown_family(PrepareError::UnknownTargetFamily)),
        (Some(installed), Some(target)) if installed != target => {
            bail!("{}", different_family(installed, target))
        }
        (Some(_), Some(_)) => {}
    }
    if installed.banner != target.banner || !installed.banner.starts_with(b"MT19") {
        bail!(
            "boot banner differs: installed {:?}, target {:?} — refusing to crossflash across \
             boot loaders",
            String::from_utf8_lossy(&installed.banner),
            String::from_utf8_lossy(&target.banner)
        );
    }
    Ok(verdict)
}

/// The backup must stay flashable once the drive runs the target: the decision
/// with the two swapped must re-admit as a crossflash.
pub(crate) fn decide_rollback(installed: &Build, target: &Build) -> Result<()> {
    let back =
        decide_authorized(&target.product, target, installed).context(BACKUP_NOT_FLASHABLE_BACK)?;
    if back != Verdict::Crossflash {
        bail!("{BACKUP_NOT_FLASHABLE_BACK}");
    }
    Ok(())
}

/// The plan-time verdict must still hold once the backup is read.
pub(crate) fn ensure_unchanged(plan: Verdict, now: Verdict) -> Result<()> {
    if plan != now {
        bail!(
            "drive changed between plan and backup: the backup's identity no longer gives \
             the plan's model decision — refusing to flash"
        );
    }
    Ok(())
}

/// Today's model test: the image's model contains the drive's product.
fn same_model(image_model: &str, product: &str) -> bool {
    image_model
        .to_ascii_uppercase()
        .contains(&product.to_ascii_uppercase())
}

/// Whether `image_model` is the drive's own model (the same-model fast path).
pub(crate) fn is_same_model(image_model: &str, drive_product: &str) -> bool {
    let product = drive_product.trim();
    !product.is_empty() && same_model(image_model, product)
}

/// The model-only decision (pure — unit-testable without a device): an unknown
/// drive model or a different one is refused. Backups use it.
pub(crate) fn decide_model(image_model: &str, drive_product: &str) -> Result<()> {
    let product = drive_product.trim();
    if product.is_empty() {
        return Err(unknown_drive());
    }
    if same_model(image_model, product) {
        return Ok(());
    }
    bail!("{}", wrong_model(image_model, product));
}

/// Enforce the model-only match: backup capture and legacy archives. See
/// [`decide_model`].
pub(crate) fn ensure_image_matches_drive(image: &[u8], drive_product: &str) -> Result<()> {
    decide_model(&Build::of_image(image)?.product, drive_product)
}

#[cfg(test)]
#[path = "crossflash_tests.rs"]
pub(crate) mod tests;
