//! MediaTek MT1959 engine.
//!
//! All chip knowledge lives in [`mt1959_build`](super::mt1959_build): the
//! scanner signature that proves the dispatch-record format, and the grounded
//! finds (CDB base, sense-setter, the `0x3C` handler) that are *derived from the
//! image*, never hardcoded. This module is just the [`Engine`] wiring; it
//! composes the dumb [`crate::thumb`] verbs against that knowledge.

use anyhow::Result;

use super::{CreateReport, Engine, ModifyReport};
use crate::family;

/// The MT1959 platform engine.
pub struct Mt1959Engine;

impl Engine for Mt1959Engine {
    fn name(&self) -> &'static str {
        "MT1959"
    }

    fn create(&self, image: &[u8]) -> Result<CreateReport> {
        self.build_report(image)
    }

    fn modify(&self, image: &[u8]) -> Result<ModifyReport> {
        let chip = family::detect_chip(image)?;
        let cap = family::capability_for(&chip.model, chip.family);
        self.build_modify(image, &chip, &cap)
    }
}
