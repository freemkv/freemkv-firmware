//! Per-build SRAM placement policy over one immutable source analysis.
//! Static absence is not proof of runtime ownership or hardware writability.
use super::core::{FLASHWRITE_SCRATCH_OFF, NUM_FEATURES, SRAM_END, SRAM_LO};
use anyhow::{anyhow, Result};
use mediatek_optical::classify::analysis::RamReferences;

pub(super) struct SramPlacement {
    references: RamReferences,
    ceiling: u32,
}

impl SramPlacement {
    pub(super) fn inspect(image: &[u8]) -> Self {
        Self {
            references: RamReferences::inspect(image),
            ceiling: SRAM_END,
        }
    }

    pub(super) fn with_ceiling(mut self, ceiling: u32) -> Self {
        self.ceiling = ceiling;
        self
    }
    /// Reject overlap with observed static references or detected fill
    /// destinations, including a four-byte guard on each side, and reject
    /// storage beyond the SRAM placement ceiling. Passing this check does not
    /// establish runtime ownership or cover arbitrary indirect code.
    pub(super) fn assert_free(&self, base: u32, len: u32, what: &str) -> Result<()> {
        let lo = base
            .checked_sub(4)
            .ok_or_else(|| anyhow!("{what}: SRAM lower guard underflows"))?;
        let hi = base
            .checked_add(len)
            .and_then(|end| end.checked_add(4))
            .ok_or_else(|| anyhow!("{what}: SRAM upper guard overflows"))?;
        let ceiling = self.ceiling;
        if lo < SRAM_LO || hi > ceiling {
            return Err(anyhow!(
                "{what} cell {base:#010x}..{:#010x} is outside the supported SRAM placement range \
                 [{SRAM_LO:#010x}, {ceiling:#010x})",
                base + len
            )
            .context(freemkv_flash::user_error::IssueCode::UnsupportedFirmware));
        }
        let used = self.used_bytes();
        for a in lo..hi {
            if used.contains(&a) {
                return Err(anyhow!(
                    "{what} cell {base:#010x}..{:#010x} overlaps a code-referenced SRAM \
                     address {a:#010x} (+guard) — refusing to clobber live state",
                    base + len
                )
                .context(freemkv_flash::user_error::IssueCode::UnsupportedFirmware));
            }
        }
        Ok(())
    }

    /// Select the highest statically unreferenced gap that fits the flag/scratch
    /// footprint. Higher addresses are furthest from the OEM working-data region
    /// and least likely to collide with runtime fills the scanner cannot detect.
    pub(super) fn candidate(&self) -> Result<u32> {
        let used = self.used_bytes();
        let footprint = (FLASHWRITE_SCRATCH_OFF + 1).max(u32::from(NUM_FEATURES) + 1);
        let mut best: Option<u32> = None;
        let ceiling = self.ceiling;
        let mut start = SRAM_LO;
        for end in (SRAM_LO..=ceiling).filter(|a| *a == ceiling || used.contains(a)) {
            let candidate = (start + 4 + 3) & !3;
            if candidate + footprint + 4 <= end {
                best = Some(candidate);
            }
            start = end + 1;
        }
        best.ok_or_else(|| {
            anyhow!(
                "no statically unreferenced SRAM candidate fits the complete {footprint}-byte \
             flag/scratch footprint and guards below {ceiling:#010x}"
            )
        })
    }

    fn used_bytes(&self) -> std::collections::BTreeSet<u32> {
        let mut used = self.references.bytes().clone();
        for &(_, addr, len, private) in self.references.fills() {
            if len > 0 && !private {
                let lo = addr.max(SRAM_LO);
                let hi = addr.saturating_add(len).min(self.ceiling);
                for a in lo..hi {
                    used.insert(a);
                }
            }
        }
        used
    }
}
