//! The MT19xx image↔drive gate: chip generation (never overridable), model
//! match, and the authorized-crossflash path with its brick-risk warnings.

use anyhow::{bail, Context, Result};

use crate::style::{self, ident_or_unknown};

/// Details of an authorized CROSSFLASH (a deliberate flash of a DIFFERENT
/// same-chipset model's firmware). Present only when `--force` waived
/// a model mismatch; carries the brick-risk warnings to surface prominently.
#[derive(Debug)]
pub(crate) struct CrossflashInfo {
    pub image_model: String,
    pub drive_product: String,
    pub image_family: freemkv_chipset::ChipFamily,
    /// Loud warnings (DE-not-set / capability mismatch / unverified sub-family).
    pub warnings: Vec<String>,
}

/// The crossflash gate decision core (pure — unit-testable without a device).
///
/// `drive_fine_family` is the drive's CURRENT silicon family (from reading its
/// own firmware) when known. Returns `Ok(None)` for a normal same-model flash,
/// `Ok(Some(..))` for an authorized crossflash, and `Err` when it must refuse.
/// The chipset-family gate is NON-overridable: even with `allow_crossflash`, a
/// known drive silicon that differs from the image's is refused.
pub(crate) fn decide_crossflash(
    image_family: freemkv_chipset::ChipFamily,
    image_model: &str,
    drive_product: &str,
    drive_fine_family: Option<freemkv_chipset::ChipFamily>,
    de_enabled: bool,
    allow_crossflash: bool,
) -> Result<Option<CrossflashInfo>> {
    // Non-overridable sub-family gate: MT1959 image onto MT1939 silicon (or vice
    // versa) is an instant brick — refuse even with --force.
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
        return Ok(None); // normal same-model flash
    }

    if !allow_crossflash {
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

    // Crossflash authorized — collect brick-risk warnings.
    let mut warnings = Vec::new();
    if !de_enabled {
        warnings.push(
            "image is NOT downgrade-enabled (0x1EC056 != 0xDE) — the target drive will \
             likely REJECT a foreign image. Run the modify tool first (it sets the \
             downgrade byte)."
                .to_string(),
        );
    }
    let icap = freemkv_chipset::capability_for(image_model, image_family);
    if product.is_empty() {
        warnings.push(
            "drive model is unknown — cannot check media-capability compatibility; \
             proceed only if you are certain the drives are compatible."
                .to_string(),
        );
    } else {
        let dcap = freemkv_chipset::capability_for(product, image_family);
        if icap.media_class != dcap.media_class {
            warnings.push(format!(
                "media-class MISMATCH: image is {} but the drive model is {} — \
                 crossflashing across capability tiers can BRICK the drive.",
                icap.media_class.label(),
                dcap.media_class.label()
            ));
        }
    }
    if drive_fine_family.is_none() {
        warnings.push(
            "could not read the drive's current firmware to confirm its exact chipset \
             (MT1959 vs MT1939); the sub-family gate is verified at execute time — \
             ensure the image chipset matches the drive."
                .to_string(),
        );
    }

    Ok(Some(CrossflashInfo {
        image_model: image_model.to_string(),
        drive_product: product.to_string(),
        image_family,
        warnings,
    }))
}

/// Enforce the image↔drive match on the write path. Returns `Ok(Some(..))` when
/// an authorized crossflash is in effect (for labeling), `Ok(None)` for a normal
/// same-model flash, `Err` to refuse. See [`decide_crossflash`] for the gate.
pub(crate) fn ensure_image_matches_drive(
    image: &[u8],
    drive_product: &str,
    drive_family: crate::drive::Family,
    allow_crossflash: bool,
    drive_fine_family: Option<freemkv_chipset::ChipFamily>,
) -> Result<Option<CrossflashInfo>> {
    let chip = freemkv_chipset::detect_chip(image)
        .context("input is not a recognizable MT19xx firmware image — refusing to flash")?;

    // Family cross-gate: an MT19xx image (ChipFamily::Mt1959/Mt1939 are both
    // MediaTek silicon) must be flashed onto a drive that classified as MediaTek.
    // Refuse flashing across silicon families outright — never overridable.
    if drive_family != crate::drive::Family::Mtk {
        bail!(
            "image is {} (MediaTek) firmware but this drive classified as {} — \
             refusing to flash across silicon families",
            chip.family.label(),
            drive_family
        );
    }

    let de_enabled = image
        .get(freemkv_chipset::DESCRIPTOR_OFFSET + 0x56)
        .copied()
        == Some(0xDE);
    decide_crossflash(
        chip.family,
        &chip.model,
        drive_product,
        drive_fine_family,
        de_enabled,
        allow_crossflash,
    )
}

/// Best-effort crossflash preview for the (non-enforcing) flash plan / dry-run:
/// swallows every error so an unrecognizable image still prints a plan. Returns
/// `Some` only for a genuine authorized crossflash.
pub(crate) fn preview_crossflash(
    image: &[u8],
    drive_product: &str,
    drive_family: crate::drive::Family,
    allow_crossflash: bool,
) -> Option<CrossflashInfo> {
    if !allow_crossflash || drive_family != crate::drive::Family::Mtk {
        return None;
    }
    // drive_fine_family = None here: the plan is informational; the real
    // sub-family gate runs at execute time in ensure_image_matches_drive.
    ensure_image_matches_drive(image, drive_product, drive_family, true, None)
        .ok()
        .flatten()
}

/// Render the CROSSFLASH banner + warnings into the plan (shared by dry-run and
/// execute so the label is identical).
pub(crate) fn print_crossflash_banner(info: &CrossflashInfo) {
    println!(
        "{}",
        style::amber(&format!(
            "CROSSFLASH: {} <- {} ({} chipset) — EXPERIMENTAL, hardware-unvalidated",
            ident_or_unknown(&info.drive_product),
            info.image_model,
            info.image_family.label()
        ))
    );
    for w in &info.warnings {
        println!("{}", style::amber(&format!("  ! {w}")));
    }
}
