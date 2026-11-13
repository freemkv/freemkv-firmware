//! The MT19xx model gate, decided by `mediatek_optical::classify` (same model,
//! or a same-hardware-family crossflash; nothing here can be switched on by a
//! user). This adapter only phrases the library's typed refusals as the
//! flasher's errors: a hardware difference found at the plan is a
//! [`crate::backend::HardwareMismatch`].

use anyhow::{Context, Result};
use mediatek_optical::classify::{self, ModelRefusal};
pub(crate) use mediatek_optical::classify::{
    Build, Verdict, BACKUP_NOT_FLASHABLE_BACK, BANNER_LEN,
};
#[cfg(test)]
use mediatek_optical::envelope::Family;

/// The library's refusal as the flasher's error, keeping its cause chain.
fn refused(error: ModelRefusal) -> anyhow::Error {
    match error {
        ModelRefusal::Hardware {
            product,
            target_model,
            difference,
        } => crate::backend::HardwareMismatch {
            installed_model: product,
            target_model,
            source: anyhow::anyhow!(difference.to_string()),
        }
        .into(),
        ModelRefusal::NotReversible(Some(cause)) => {
            refused(*cause).context(BACKUP_NOT_FLASHABLE_BACK)
        }
        other => anyhow::anyhow!(other.to_string()),
    }
}

/// The image's build facts, refusing an image that names no MT19xx chip.
pub(crate) fn build_of_image(image: &[u8]) -> Result<Build> {
    Build::of_image(image)
        .map_err(anyhow::Error::new)
        .context("input is not a recognizable MT19xx firmware image — refusing to flash")
}

/// [`classify::decide_plan`]: the model decision before any backup.
pub(crate) fn decide_plan(drive_product: &str, live: &Build, target: &Build) -> Result<Verdict> {
    classify::decide_plan(drive_product, live, target).map_err(refused)
}

/// [`classify::decide_authorized`]: the decision once the backup is read.
pub(crate) fn decide_authorized(
    drive_product: &str,
    installed: &Build,
    target: &Build,
) -> Result<Verdict> {
    classify::decide_authorized(drive_product, installed, target).map_err(refused)
}

/// [`classify::decide_rollback`]: the backup must flash back afterwards.
pub(crate) fn decide_rollback(installed: &Build, target: &Build) -> Result<()> {
    classify::decide_rollback(installed, target).map_err(refused)
}

/// [`classify::ensure_unchanged`]: the plan's verdict must still hold.
pub(crate) fn ensure_unchanged(plan: Verdict, now: Verdict) -> Result<()> {
    classify::ensure_unchanged(plan, now).map_err(refused)
}

pub(crate) use classify::is_same_model;

/// [`classify::decide_model`]: the model-only decision backups use.
pub(crate) fn decide_model(image_model: &str, drive_product: &str) -> Result<()> {
    classify::decide_model(image_model, drive_product).map_err(refused)
}

/// Enforce the model-only match: backup capture and legacy archives.
pub(crate) fn ensure_image_matches_drive(image: &[u8], drive_product: &str) -> Result<()> {
    decide_model(&build_of_image(image)?.product, drive_product)
}

#[cfg(test)]
#[path = "crossflash_tests.rs"]
pub(crate) mod tests;
