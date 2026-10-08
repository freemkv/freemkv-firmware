//! Bounded, deterministic byte alignment. Unknown semantics remain explicit.
use super::{check, Control, FirmwareAnalysis, Options, Progress, Region};
use anyhow::Result;
use serde::Serialize;
use std::ops::Range;

/// Classification of a range difference.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangeKind {
    /// Bytes present only in the right source.
    Added,
    /// Bytes present only in the left source.
    Removed,
    /// Both ranges differ; semantics are not established.
    DataChanged,
    /// Provider-established reference to a corresponding mapped target.
    RelocatedReference,
    /// Recognized descriptive/derived metadata, excluded from content changes.
    Metadata,
    /// A work or reporting budget prevented resolution.
    Unresolved,
}
impl ChangeKind {
    /// Whether the change is excluded from substantive content counts.
    pub fn is_excluded(self) -> bool {
        matches!(self, Self::RelocatedReference | Self::Metadata)
    }
}
/// A change in logical-region coordinates, not encrypted-file coordinates.
#[derive(Clone, Debug, Serialize)]
pub struct Change {
    /// Nature of the difference.
    pub kind: ChangeKind,
    /// Range on the left.
    pub left: Range<usize>,
    /// Range on the right.
    pub right: Range<usize>,
    /// Original and relocated target addresses, when verified.
    pub targets: Option<(u64, u64)>,
}
/// Results for one corresponding region pair.
#[derive(Clone, Debug, Serialize)]
pub struct RegionComparison {
    /// Left region ID, absent for an unmatched right region.
    pub left: Option<usize>,
    /// Right region ID, absent for an unmatched left region.
    pub right: Option<usize>,
    /// Logical size on the left.
    pub left_size: usize,
    /// Logical size on the right.
    pub right_size: usize,
    /// Exactly equal bytes found by alignment, counted once on each side.
    pub equal_bytes: usize,
    /// Changed ranges, including unresolved remainders.
    pub changes: Vec<Change>,
    /// Positional differences in matching validated table structures.
    pub tables: Vec<super::tables::TableComparison>,
}
/// Symmetric accounting across both sources' decoded/expanded region bytes.
/// Compressed storage is replaced by expanded content, never counted twice.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Accounting {
    /// Sum of both sources' logical byte lengths.
    pub total: usize,
    /// Changed bytes, excluding metadata, relocations and unresolved work.
    pub changed: usize,
    /// Bytes that a resource limit prevented from comparing.
    pub unresolved: usize,
}
impl Accounting {
    /// Percent different after alignment and verified exclusions.
    /// None denotes an empty comparison, not established equality.
    pub fn difference_percent(self) -> Option<f64> {
        (self.total != 0).then(|| 100.0 * self.changed as f64 / self.total as f64)
    }
}
impl RegionComparison {
    /// Count both sides symmetrically so additions and removals retain their sizes.
    pub fn accounting(&self) -> Accounting {
        let mut result = Accounting {
            total: self.left_size + self.right_size,
            ..Accounting::default()
        };
        for change in &self.changes {
            let size = change.left.len() + change.right.len();
            match change.kind {
                ChangeKind::Unresolved => result.unresolved += size,
                kind if !kind.is_excluded() => result.changed += size,
                _ => {}
            }
        }
        result
    }
}
/// A structured comparison. It does not establish behavioral equivalence.
#[derive(Clone, Debug, Serialize)]
pub struct Comparison {
    /// Same hardware family, or None if either family is unavailable.
    pub same_family: Option<bool>,
    /// Per-region findings.
    pub regions: Vec<RegionComparison>,
    /// True only for identical complete decoded components.
    pub identical_decoded: bool,
    /// True when this comparison has no unresolved work or source diagnostics.
    pub complete: bool,
    /// Explanation of the current normalization coverage.
    pub coverage: &'static str,
}

impl FirmwareAnalysis {
    /// Compare logical regions, aligning moved byte runs without ignoring
    /// constants or unresolved address operands. Different families are allowed.
    pub fn compare(
        &self,
        other: &FirmwareAnalysis,
        options: Options,
        observer: &Control,
    ) -> Result<Comparison> {
        // Canonical orientation makes correspondence independent of the caller's
        // A/B order. Findings are restored to caller coordinates afterward.
        let reverse = (&self.identity.sha256, &self.identity.component)
            > (&other.identity.sha256, &other.identity.component);
        let mut result = if reverse {
            other.compare_ordered(self, options, observer)?
        } else {
            self.compare_ordered(other, options, observer)?
        };
        if reverse {
            for region in &mut result.regions {
                std::mem::swap(&mut region.left, &mut region.right);
                std::mem::swap(&mut region.left_size, &mut region.right_size);
                for change in &mut region.changes {
                    std::mem::swap(&mut change.left, &mut change.right);
                    change.kind = match change.kind {
                        ChangeKind::Added => ChangeKind::Removed,
                        ChangeKind::Removed => ChangeKind::Added,
                        other => other,
                    };
                    change.targets = change.targets.map(|(a, b)| (b, a));
                }
                for table in &mut region.tables {
                    std::mem::swap(&mut table.left_records, &mut table.right_records);
                    for change in &mut table.changes {
                        std::mem::swap(&mut change.left, &mut change.right);
                    }
                }
            }
        }
        Ok(result)
    }

    fn compare_ordered(
        &self,
        other: &FirmwareAnalysis,
        options: Options,
        observer: &Control,
    ) -> Result<Comparison> {
        let mut progress = Progress {
            control: observer,
            last: None,
        };
        let observer = &mut progress;
        let mut regions = Vec::new();
        let mut used = vec![false; other.regions.len()];
        for (i, left) in self.regions.iter().enumerate() {
            check(observer, "Comparing regions", i, self.regions.len())?;
            let exact: Vec<_> = other
                .regions
                .iter()
                .enumerate()
                .filter(|(j, r)| {
                    !used[*j]
                        && left.representation == r.representation
                        && left.sha256 == r.sha256
                        && left.bytes() == r.bytes()
                })
                .map(|(j, _)| j)
                .collect();
            let matched = if exact.len() == 1 {
                exact.first().copied()
            } else {
                // A directory index is only a structural pairing, not evidence
                // of equal purpose. Changed bytes remain changes.
                other
                    .regions
                    .iter()
                    .enumerate()
                    .find(|(j, r)| {
                        !used[*j]
                            && r.representation == left.representation
                            && r.pairing_key == left.pairing_key
                    })
                    .map(|(j, _)| j)
            };
            if let Some(j) = matched {
                used[j] = true;
                regions.push(align(left, &other.regions[j], options, observer)?);
            } else {
                regions.push(unmatched(Some(left), None));
            }
        }
        for (i, region) in other.regions.iter().enumerate() {
            if !used[i] {
                regions.push(unmatched(None, Some(region)));
            }
        }
        super::references::normalize(self, other, &mut regions);
        super::metadata::classify(self, other, &mut regions);
        let complete = !regions
            .iter()
            .flat_map(|r| &r.changes)
            .any(|c| c.kind == ChangeKind::Unresolved)
            && self.complete
            && other.complete;
        Ok(Comparison { same_family: self.identity.family.as_ref().zip(other.identity.family.as_ref()).map(|(a,b)| self.identity.family_scheme == other.identity.family_scheme && a == b),
            identical_decoded: complete && self.identity.component == other.identity.component && self.identity.sha256 == other.identity.sha256,
            complete, regions, coverage: "Decoded bytes aligned; provider-established control-flow relocations are separate from content changes. Unresolved operands and unclassified data remain differences." })
    }
}
fn unmatched(a: Option<&Region>, b: Option<&Region>) -> RegionComparison {
    let left_size = a.map_or(0, Region::size);
    let right_size = b.map_or(0, Region::size);
    RegionComparison {
        left: a.map(|r| r.id),
        right: b.map(|r| r.id),
        left_size,
        right_size,
        equal_bytes: 0,
        tables: Vec::new(),
        changes: vec![Change {
            kind: if a.is_none() {
                ChangeKind::Added
            } else {
                ChangeKind::Removed
            },
            left: 0..left_size,
            right: 0..right_size,
            targets: None,
        }],
    }
}
fn align(
    a: &Region,
    b: &Region,
    options: Options,
    observer: &mut Progress<'_>,
) -> Result<RegionComparison> {
    let (left, right) = (a.bytes(), b.bytes());
    let mut out = RegionComparison {
        left: Some(a.id),
        right: Some(b.id),
        left_size: left.len(),
        right_size: right.len(),
        equal_bytes: 0,
        changes: Vec::new(),
        tables: super::tables::compare(&a.tables, &b.tables),
    };
    if left == right {
        out.equal_bytes = left.len();
        return Ok(out);
    }
    let (anchors, completed) = super::alignment::anchors(left, right, options.work, observer)?;
    if !completed {
        out.changes.push(Change {
            kind: ChangeKind::Unresolved,
            left: 0..left.len(),
            right: 0..right.len(),
            targets: None,
        });
        return Ok(out);
    }
    let (mut i, mut j) = (0, 0);
    for (a, b, n) in anchors
        .into_iter()
        .chain(std::iter::once((left.len(), right.len(), 0)))
    {
        check(observer, "Comparing aligned content", i, left.len())?;
        if out.changes.len() >= options.findings.saturating_sub(1) {
            out.changes.push(Change {
                kind: ChangeKind::Unresolved,
                left: i..left.len(),
                right: j..right.len(),
                targets: None,
            });
            return Ok(out);
        }
        gap(left, right, i..a, j..b, &mut out, options.findings);
        out.equal_bytes += n;
        i = a + n;
        j = b + n;
    }
    Ok(out)
}
fn gap(
    left: &[u8],
    right: &[u8],
    a: Range<usize>,
    b: Range<usize>,
    out: &mut RegionComparison,
    limit: usize,
) {
    let (mut i, mut j) = (a.start, b.start);
    while i < a.end && j < b.end {
        if out.changes.len() >= limit.saturating_sub(1) {
            out.changes.push(Change {
                kind: ChangeKind::Unresolved,
                left: i..a.end,
                right: j..b.end,
                targets: None,
            });
            return;
        }
        if left[i] == right[j] {
            i += 1;
            j += 1;
            out.equal_bytes += 1;
            continue;
        }
        let (x, y) = (i, j);
        while i < a.end && j < b.end && left[i] != right[j] {
            i += 1;
            j += 1;
        }
        out.changes.push(Change {
            kind: ChangeKind::DataChanged,
            left: x..i,
            right: y..j,
            targets: None,
        });
    }
    if i < a.end || j < b.end {
        out.changes.push(Change {
            kind: if i == a.end {
                ChangeKind::Added
            } else {
                ChangeKind::Removed
            },
            left: i..a.end,
            right: j..b.end,
            targets: None,
        });
    }
}
