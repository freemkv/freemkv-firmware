use super::engine::{ChangeKind, RegionComparison};
use super::FirmwareAnalysis;
use std::ops::Range;
pub(super) fn classify(
    left: &FirmwareAnalysis,
    right: &FirmwareAnalysis,
    results: &mut [RegionComparison],
) {
    for r in results {
        let (Some(ai), Some(bi)) = (r.left, r.right) else {
            continue;
        };
        let (Some(a), Some(b)) = (
            left.regions.iter().find(|r| r.id == ai),
            right.regions.iter().find(|r| r.id == bi),
        ) else {
            continue;
        };
        for c in &mut r.changes {
            if c.kind != ChangeKind::DataChanged {
                continue;
            }
            let inside = |ranges: &[Range<usize>], c: &Range<usize>| {
                ranges.iter().any(|r| r.start <= c.start && r.end >= c.end)
            };
            if inside(&a.metadata, &c.left) && inside(&b.metadata, &c.right) {
                c.kind = ChangeKind::Metadata;
            }
        }
    }
}
