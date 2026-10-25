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
        "internal error: generated firmware changed integrity-table descriptors or unused records"
    );
    Ok(())
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
