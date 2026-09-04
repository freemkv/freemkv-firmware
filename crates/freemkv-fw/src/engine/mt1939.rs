//! MediaTek MT1939 engine (partial).
//!
//! MT1939 shares freemkv's CMAC integrity scheme with MT1959 byte-for-byte
//! (`freemkv_flash::cmac` re-signs it unchanged — proven across the MT1939 corpus,
//! `research/hoard-campaign-2026-09-03/reports/mt1939-engine-scope.md`), but its
//! SRAM map and vendor hook points differ, so the full lever set
//! (VID/AKE/Region/Speed) is pending a dedicated build. Today this engine applies
//! the one **family-agnostic** lever — the downgrade-enable (DE) byte in the
//! identity page — and reports the rest as pending, so an MT1939 image is
//! partially modified + reported rather than opaquely refused.

use anyhow::{anyhow, bail, Result};

use freemkv_flash::cmac;

use super::lever::{LeverId, LeverReport};
use super::{CreateReport, Engine, ModifyReport};
use crate::family;

/// Downgrade-enable byte offset within the MTEK identity page (`0x1EC056`).
const DE_OFF_IN_DESCRIPTOR: usize = 0x56;

/// The MT1939 platform engine (partial: DE-only today).
pub struct Mt1939Engine;

impl Engine for Mt1939Engine {
    fn name(&self) -> &'static str {
        "MT1939"
    }

    fn create(&self, _image: &[u8]) -> Result<CreateReport> {
        bail!(
            "MT1939 full build engine is pending — use `modify` for the supported \
             (downgrade-enable) lever; VID/AKE/Region/Speed need the MT1939 engine"
        )
    }

    fn modify(&self, image: &[u8]) -> Result<ModifyReport> {
        let chip = family::detect_chip(image)?;
        let cap = family::capability_for(&chip.model, chip.family);

        let mut out = image.to_vec();
        let mut levers = Vec::new();

        // Downgrade-enable (DE): family-agnostic identity-page byte.
        let de = if chip.descriptor_present {
            let off = family::DESCRIPTOR_OFFSET + DE_OFF_IN_DESCRIPTOR;
            if off >= out.len() {
                LeverReport::not_applicable(LeverId::DowngradeEnable, "identity page truncated")
            } else if out[off] == 0xDE {
                LeverReport::already(LeverId::DowngradeEnable, vec![("de_off", off as u32)])
            } else {
                out[off] = 0xDE;
                LeverReport::applied(LeverId::DowngradeEnable, vec![("de_off", off as u32)])
            }
        } else {
            LeverReport::not_applicable(LeverId::DowngradeEnable, "no MTEK identity page")
        };
        levers.push(de);

        // The rest are pending the dedicated MT1939 engine (signatures reversed;
        // see the engine-scope report — wiring is the next block).
        for id in [LeverId::RegionFree, LeverId::RawRead, LeverId::Speed] {
            levers.push(LeverReport::not_applicable(id, "MT1939 engine pending"));
        }

        if !levers.iter().any(|l| l.outcome.is_effective()) {
            bail!("nothing modifiable on this MT1939 image (no identity page for the DE byte)");
        }

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(ModifyReport {
            engine: "MT1939",
            family: chip.family.label().to_string(),
            vendor: chip.vendor.clone(),
            model: chip.model.clone(),
            rev: chip.rev.clone(),
            media: cap.media_class.label().to_string(),
            levers,
            image: signed,
        })
    }
}
