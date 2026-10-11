//! The MT19xx image↔drive gate: the image's chip generation must match the
//! drive's silicon, and its model must be the drive's.

use anyhow::{bail, Context, Result};

/// The image↔drive decision core (pure — unit-testable without a device).
///
/// `drive_fine_family` is the drive's current silicon family, read from its
/// own firmware, when known. A known silicon that differs from the image's is
/// refused first, then any model mismatch or an unknown drive model.
pub(crate) fn decide_crossflash(
    image_family: freemkv_chipset::ChipFamily,
    image_model: &str,
    drive_product: &str,
    drive_fine_family: Option<freemkv_chipset::ChipFamily>,
) -> Result<()> {
    if let Some(df) = drive_fine_family {
        if df != image_family {
            bail!(
                "image is {} firmware but this drive is {} silicon — refusing to \
                 flash across chip families. This gate cannot be overridden.",
                image_family.label(),
                df.label()
            );
        }
    }
    let product = drive_product.trim();
    let model_matches = !product.is_empty()
        && image_model
            .to_ascii_uppercase()
            .contains(&product.to_ascii_uppercase());
    if model_matches {
        return Ok(());
    }
    if product.is_empty() {
        bail!(
            "drive model is unknown (empty INQUIRY product) — refusing to flash \
             without confirming the image matches this drive"
        );
    }
    bail!(
        "image is built for model {image_model:?} but this drive reports \
         {product:?} — refusing to flash a wrong-model image (pass \
         a compatible image)"
    );
}

/// Enforce the image↔drive match on the write path. See [`decide_crossflash`].
pub(crate) fn ensure_image_matches_drive(
    image: &[u8],
    drive_product: &str,
    drive_fine_family: Option<freemkv_chipset::ChipFamily>,
) -> Result<()> {
    let chip = freemkv_chipset::detect_chip(image)
        .context("input is not a recognizable MT19xx firmware image — refusing to flash")?;
    decide_crossflash(chip.family, &chip.model, drive_product, drive_fine_family)
}
