//! Per-build SRAM placement policy over one immutable source analysis.
//! Static absence is not proof of runtime ownership or hardware writability.
use super::core::{FLASHWRITE_SCRATCH_OFF, NUM_FEATURES, SRAM_END, SRAM_LO};
use anyhow::{anyhow, Result};
use mediatek_optical::image::analysis::RamReferences;

pub(super) struct SramPlacement {
    references: RamReferences,
}

impl SramPlacement {
    pub(super) fn inspect(image: &[u8]) -> Self {
        Self {
            references: RamReferences::inspect(image),
        }
    }
    /// Reject overlap with observed static references, including a four-byte
    /// guard on each side, and reject storage beyond the conservative RAM ceiling.
    /// Passing this check does not establish runtime ownership or cover arbitrary
    /// indirect code. The modern fixed cell also has model-specific capture evidence.
    pub(super) fn assert_free(&self, base: u32, len: u32, what: &str) -> Result<()> {
        let lo = base
            .checked_sub(4)
            .ok_or_else(|| anyhow!("{what}: SRAM lower guard underflows"))?;
        let hi = base
            .checked_add(len)
            .and_then(|end| end.checked_add(4))
            .ok_or_else(|| anyhow!("{what}: SRAM upper guard overflows"))?;
        if lo < SRAM_LO || hi > SRAM_END {
            return Err(anyhow!(
                "{what} cell {base:#010x}..{:#010x} is outside the supported SRAM placement range \
                 [{SRAM_LO:#010x}, {SRAM_END:#010x})",
                base + len
            )
            .context(freemkv_flash::user_error::IssueCode::UnsupportedFirmware));
        }
        let used = self.references.bytes();
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

    /// Select a statically unreferenced candidate within the conservative RAM
    /// ceiling, reserving guards and the complete flag/scratch footprint.
    /// This is a placement candidate, not proof of runtime memory ownership.
    pub(super) fn candidate(&self) -> Result<u32> {
        let used = self.references.bytes();
        let footprint = (FLASHWRITE_SCRATCH_OFF + 1).max(u32::from(NUM_FEATURES) + 1);
        let mut best: Option<(u32, u32)> = None;
        let mut start = SRAM_LO;
        for end in (SRAM_LO..=SRAM_END).filter(|a| *a == SRAM_END || used.contains(a)) {
            let candidate = (start + 4 + 3) & !3; // leading guard, then word alignment
            if candidate + footprint + 4 <= end {
                let usable = end - candidate - 4;
                if best.is_none_or(|(_, previous)| usable > previous) {
                    best = Some((candidate, usable));
                }
            }
            start = end + 1;
        }
        best.map(|(base, _)| base).ok_or_else(|| {
            anyhow!(
                "no statically unreferenced SRAM candidate fits the complete {footprint}-byte \
             flag/scratch footprint and guards below {SRAM_END:#010x}"
            )
        })
    }
}
