//! MediaTek allocation policy over the codec's flash geometry. Erased bytes
//! are candidates only after subtracting metadata and drive-owned storage.
//! Authentication ranges may overlap; an allocation must fit a single range.

use anyhow::{anyhow, ensure, Result};
use freemkv_flash::cmac;
use mediatek_optical::layout;
use std::ops::Range;
use thumb_asm::{find_free_space_in, Fit};

/// No erased hole can hold an allocation without using reserved storage.
#[derive(Debug)]
pub struct NoCodeSpace {
    /// Required contiguous bytes, including the caller's capacity margin.
    pub need: usize,
}

impl std::fmt::Display for NoCodeSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no CMAC-covered free space of {} bytes outside reserved firmware regions",
            self.need
        )
    }
}

impl std::error::Error for NoCodeSpace {}

pub(crate) fn metadata_preserved(original: &[u8], output: &[u8]) -> bool {
    descriptors_equal(original, output)
        || coverage_retry(original).is_some_and(|plan| descriptors_equal(&plan.image, output))
}

fn descriptors_equal(original: &[u8], output: &[u8]) -> bool {
    original.len() == output.len()
        && (0..cmac::ENTRY_COUNT).all(|index| {
            let at = cmac::TABLE_OFFSET + index * cmac::ENTRY_SIZE;
            let len = if original.get(at..at + 4) == Some(&[0xff; 4]) {
                cmac::ENTRY_SIZE
            } else {
                12
            };
            original.get(at..at + len).is_some()
                && original.get(at..at + len) == output.get(at..at + len)
        })
}

pub(crate) fn validate_metadata(original: &[u8], output: &[u8]) -> Result<()> {
    ensure!(
        metadata_preserved(original, output),
        "internal error: generated firmware made an unplanned integrity-table change"
    );
    Ok(())
}

/// A single deterministic coverage extension, used only after an allocation
/// failure. Input bytes and unused table records are never used as code space.
pub(crate) struct CoverageRetry {
    pub image: Vec<u8>,
    pub entry: u32,
    pub old_end: u32,
    pub new_end: u32,
}

pub(crate) fn coverage_retry(image: &[u8]) -> Option<CoverageRetry> {
    use mediatek_optical::receiver::{analysis::ApplicationAnalysis, decoding::Value, programming};
    if image.len() != 0x200000 || super::core::is_freemkv_patched(image) || !cmac::verify(image) {
        return None;
    }
    let entries = cmac::parse_table(image).ok()?;
    if entries
        .iter()
        .any(|e| !matches!(e.enabled, 0 | 1 | u32::MAX))
    {
        return None;
    }
    let analysis = ApplicationAnalysis::inspect(image, 0)?;
    if analysis.conflicting_arguments() {
        return None;
    }
    let envelope = mediatek_optical::envelope::Envelope::load(image).ok()?;
    let receiver = mediatek_optical::receiver::Receiver::from_firmware(&envelope).ok()?;
    let mut bindings = analysis.ranges().iter().filter_map(|range| {
        let tail = range.acceptance.as_ref()?;
        let frame = range.state_slot.as_ref()?;
        if !(frame.prologue..tail.continuation).contains(&receiver.signature_address()) {
            return None;
        }
        let binding = programming::inspect_mode_three_wrapper(image, 0, tail.program_target)?;
        if binding.program.destination_cell != range.selection.offset_cell
            || binding.program.source_offset_cell != range.selection.start_cell
            || binding.program.remaining_cell != range.selection.length_cell
        {
            return None;
        }
        let staged = binding.program.staging_cell;
        let decoded = range.signature.is_some_and(|p| p.staging_cell == staged)
            || analysis.bulk_decoders().iter().any(|p| {
                p.selection_address == range.selection.address
                    && p.from_zero.source
                        == (Value::Loaded {
                            cell: staged,
                            offset: 0,
                        })
            });
        if !decoded {
            return None;
        }
        let check = analysis
            .integrity_selections()
            .iter()
            .find(|p| p.success == tail.address)?;
        programming::inspect_integrity_walker(image, 0, check.application_check, staged)?;
        Some(binding)
    });
    let binding = bindings.next()?;
    if bindings.next().is_some() {
        return None;
    }
    let reserved = reservations();
    let mut best: Option<(usize, usize, usize)> = None;
    for window in &binding.program.preserving_boot_spans {
        let mut at = window.start.max(super::core::CODE_REGION_START);
        while at < window.end {
            if image[at] != 0xff {
                at += 1;
                continue;
            }
            let start = at;
            while at < window.end && image[at] == 0xff {
                at += 1;
            }
            let end = at & !15;
            let aligned = (start + 3) & !3;
            if aligned >= end {
                continue;
            }
            for entry in &entries {
                if !entry.is_active() || entry.covers_table() {
                    continue;
                }
                let old_end = (entry.end as usize).checked_add(1)?;
                if old_end > start
                    || old_end < window.start
                    || entry.start & 15 != 0
                    || old_end & 15 != 0
                {
                    continue;
                }
                if reserved.iter().any(|r| old_end < r.end && end > r.start)
                    || entries.iter().any(|e| {
                        e.index != entry.index
                            && e.enabled != u32::MAX
                            && e.start <= e.end
                            && old_end <= e.end as usize
                            && end > e.start as usize
                    })
                {
                    continue;
                }
                let candidate = (end - aligned, entry.index, end - 1);
                if best.is_none_or(|previous| candidate.0 > previous.0) {
                    best = Some(candidate);
                }
            }
        }
    }
    let (_, index, new_end) = best?;
    let entry = entries.get(index)?;
    let mut output = image.to_vec();
    output[entry.entry_off + 8..entry.entry_off + 12]
        .copy_from_slice(&(new_end as u32).to_le_bytes());
    let output = cmac::resign(&output).ok()?;
    if !cmac::verify(&output) {
        return None;
    }
    Some(CoverageRetry {
        image: output,
        entry: index as u32,
        old_end: entry.end,
        new_end: new_end as u32,
    })
}

fn reservations() -> Vec<Range<usize>> {
    let mut out: Vec<_> = [
        layout::BOOT_AREA,
        layout::BANNER,
        layout::BOOT_MIRROR,
        layout::CMAC_TABLE,
        layout::DESCRIPTOR,
    ]
    .into_iter()
    .chain(layout::DRIVE_WRITTEN)
    .map(|r| r.start..r.end())
    .collect();
    // BOOT's stored CMAC and the application update signatures adjacent to
    // the integrity table are not instruction padding, including erased bytes.
    out.extend([0xfff0..0x10000, 0x105c0..0x10610]);
    out.sort_by_key(|r| r.start);
    out
}

fn subtract(mut windows: Vec<Range<usize>>, reserved: &[Range<usize>]) -> Vec<Range<usize>> {
    for blocked in reserved {
        windows = windows
            .into_iter()
            .flat_map(|r| {
                if blocked.end <= r.start || blocked.start >= r.end {
                    return vec![r];
                }
                let mut pieces = Vec::with_capacity(2);
                if r.start < blocked.start {
                    pieces.push(r.start..blocked.start);
                }
                if blocked.end < r.end {
                    pieces.push(blocked.end..r.end);
                }
                pieces
            })
            .collect();
    }
    windows
}

pub(super) fn find(image: &[u8], need: usize, code_start: usize) -> Result<u32> {
    ensure!(need > 0, "code allocation must contain at least one byte");
    let authenticated: Vec<_> = cmac::parse_table(image)?
        .into_iter()
        .filter(|e| e.is_active() && e.start <= e.end && (e.end as usize) < image.len())
        .map(|e| e.start as usize..e.end as usize + 1)
        .collect();
    let reserved = reservations();
    let safe = subtract(
        std::iter::once(code_start..image.len()).collect(),
        &reserved,
    );
    let mut whole = Vec::new();
    let mut clipped = Vec::new();
    for window in safe {
        let mut at = window.start;
        while at < window.end {
            if image[at] != 0xff {
                at += 1;
                continue;
            }
            let start = at;
            while at < window.end && image[at] == 0xff {
                at += 1;
            }
            let aligned = (start + 3) & !3;
            for coverage in &authenticated {
                let lo = start.max(coverage.start);
                let hi = at.min(coverage.end);
                if lo < hi {
                    clipped.push(lo..hi);
                }
                if coverage.start <= aligned && at <= coverage.end && aligned < at {
                    whole.push(aligned..at);
                }
            }
        }
    }
    // Preserve established whole-run placements, then consider boundary clips.
    // The generic Thumb toolkit owns alignment, capacity and deterministic fit.
    let at = find_free_space_in(image, need, 4, &whole, Fit::Largest)
        .or_else(|| find_free_space_in(image, need, 4, &clipped, Fit::Largest))
        .ok_or_else(|| {
            anyhow::Error::new(NoCodeSpace { need })
                .context(freemkv_flash::user_error::IssueCode::FirmwareNoCodeSpace)
        })?;
    let end = at
        .checked_add(need)
        .ok_or_else(|| anyhow!("code allocation overflow"))?;
    ensure!(
        authenticated.iter().any(|r| r.start <= at && end <= r.end),
        "code allocation crosses integrity coverage"
    );
    ensure!(
        reserved.iter().all(|r| end <= r.start || at >= r.end),
        "code allocation overlaps reserved firmware storage"
    );
    Ok(u32::try_from(at)?)
}
