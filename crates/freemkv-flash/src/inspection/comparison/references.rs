//! Correspondence of provider-established references across aligned regions.
use super::engine::{ChangeKind, RegionComparison};
use super::FirmwareAnalysis;
use std::ops::Range;
fn equal_ranges(result: &RegionComparison) -> Vec<(Range<usize>, usize)> {
    let (mut a, mut b) = (0, 0);
    let mut ranges = Vec::new();
    for c in &result.changes {
        if c.left.start > a && c.left.start - a == c.right.start - b {
            ranges.push((a..c.left.start, b));
        }
        a = c.left.end;
        b = c.right.end;
    }
    if result.left_size > a && result.left_size - a == result.right_size - b {
        ranges.push((a..result.left_size, b));
    }
    ranges
}
fn mapped(ranges: &[(Range<usize>, usize)], offset: usize) -> Option<usize> {
    let i = ranges
        .partition_point(|(r, _)| r.start <= offset)
        .checked_sub(1)?;
    let (r, b) = &ranges[i];
    r.contains(&offset).then_some(b + offset - r.start)
}

// Require a contiguous target context, not an isolated matching entry byte.
const TARGET_CONTEXT_BYTES: usize = 8;
fn mapped_target(ranges: &[(Range<usize>, usize)], offset: usize) -> Option<usize> {
    let end = offset.checked_add(TARGET_CONTEXT_BYTES)?;
    let (range, destination) = ranges
        .iter()
        .find(|(range, _)| range.start <= offset && end <= range.end)?;
    Some(destination + offset - range.start)
}

pub(super) fn normalize(
    left: &FirmwareAnalysis,
    right: &FirmwareAnalysis,
    results: &mut [RegionComparison],
) {
    let maps: Vec<_> = results
        .iter()
        .filter_map(|r| {
            let a = left.regions.iter().find(|a| Some(a.id) == r.left)?;
            let b = right.regions.iter().find(|b| Some(b.id) == r.right)?;
            Some((a.address?, b.address?, equal_ranges(r), a.size()))
        })
        .collect();
    for result in results {
        let (Some(a), Some(b)) = (
            left.regions.iter().find(|a| Some(a.id) == result.left),
            right.regions.iter().find(|b| Some(b.id) == result.right),
        ) else {
            continue;
        };
        let ranges = equal_ranges(result);
        for change in &mut result.changes {
            if change.kind == ChangeKind::Unresolved || change.left.len() != change.right.len() {
                continue;
            }
            let i = a
                .references
                .partition_point(|r| r.operand.start <= change.left.start);
            let Some(ar) = i.checked_sub(1).and_then(|i| a.references.get(i)) else {
                continue;
            };
            if change.left.end > ar.operand.end {
                continue;
            }
            let Some(start) = mapped(&ranges, ar.instruction.start) else {
                continue;
            };
            let j = b
                .references
                .partition_point(|r| r.instruction.start < start);
            let Some(br) = b.references.get(j).filter(|r| r.instruction.start == start) else {
                continue;
            };
            if ar.instruction.len() != br.instruction.len()
                || change.right.start < br.operand.start
                || change.right.end > br.operand.end
                || mapped(&ranges, ar.instruction.end) != Some(br.instruction.end)
                || a.bytes().get(ar.instruction.start..ar.operand.start)
                    != b.bytes().get(br.instruction.start..br.operand.start)
            {
                continue;
            }
            let agrees = maps.iter().any(|(old, new, map, size)| {
                let Some(offset) = ar
                    .target
                    .checked_sub(*old)
                    .and_then(|v| usize::try_from(v).ok())
                    .filter(|v| *v < *size)
                else {
                    return false;
                };
                mapped_target(map, offset).and_then(|v| new.checked_add(v as u64))
                    == Some(br.target)
            });
            if agrees {
                change.kind = ChangeKind::RelocatedReference;
                change.targets = Some((ar.target, br.target));
            }
        }
    }
}
