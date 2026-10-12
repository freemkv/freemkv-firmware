//! The MT19xx model gate: the image's model must be the drive's. The chip
//! and hardware-family gates are `mediatek_optical::update`'s.

use anyhow::{bail, Context, Result};

/// The image↔drive model decision (pure — unit-testable without a device).
/// An unknown drive model or a different one is refused.
pub(crate) fn decide_crossflash(image_model: &str, drive_product: &str) -> Result<()> {
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

/// Enforce the image↔drive model match on the write path. See
/// [`decide_crossflash`].
pub(crate) fn ensure_image_matches_drive(image: &[u8], drive_product: &str) -> Result<()> {
    let chip = freemkv_chipset::detect_chip(image)
        .context("input is not a recognizable MT19xx firmware image — refusing to flash")?;
    decide_crossflash(&chip.model, drive_product)
}
