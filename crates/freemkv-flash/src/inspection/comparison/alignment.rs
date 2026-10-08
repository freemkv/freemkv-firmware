//! Unique content anchors followed by a longest ordered correspondence chain.
use super::{check, Progress};
use anyhow::Result;
use std::collections::HashMap;

type Anchor = (usize, usize, usize);
type Anchors = (Vec<Anchor>, bool);

const WIDTH: usize = 16;
const SAMPLE: usize = 8;
const MAX_INDEX_ENTRIES: usize = 2_000_000;
const POLL: usize = 4096;

fn fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}
/// Exact matched ranges (left start, right start, length), never overlapping.
pub(super) fn anchors(
    a: &[u8],
    b: &[u8],
    budget: usize,
    observer: &mut Progress<'_>,
) -> Result<Anchors> {
    let mut remaining = budget;
    let (primary, completed) = find(a, b, WIDTH, SAMPLE, &mut remaining, observer)?;
    if !completed {
        return Ok((primary, false));
    }
    let mut refined = Vec::new();
    let (mut left, mut right) = (0, 0);
    for (x, y, n) in primary
        .into_iter()
        .chain(std::iter::once((a.len(), b.len(), 0)))
    {
        // Re-index between the global anchors at byte granularity. This catches
        // short insertions and deletions that positional gap comparison misses.
        if x > left && y > right {
            let (local, complete) =
                find(&a[left..x], &b[right..y], 8, 1, &mut remaining, observer)?;
            if !complete {
                return Ok((Vec::new(), false));
            }
            refined.extend(local.into_iter().map(|(i, j, n)| (left + i, right + j, n)));
        }
        if n != 0 {
            refined.push((x, y, n));
        }
        left = x + n;
        right = y + n;
    }
    Ok((refined, true))
}
fn find(
    a: &[u8],
    b: &[u8],
    width: usize,
    sample: usize,
    remaining: &mut usize,
    observer: &mut Progress<'_>,
) -> Result<Anchors> {
    let stride = (b.len().div_ceil(MAX_INDEX_ENTRIES)).max(1);
    let mut index = HashMap::new();
    for offset in (0..b.len().saturating_sub(width - 1)).step_by(stride) {
        if *remaining < width {
            return Ok((Vec::new(), false));
        }
        *remaining -= width;
        if offset % POLL == 0 {
            check(observer, "Indexing content", offset, b.len())?;
        }
        let key = fingerprint(&b[offset..offset + width]);
        index
            .entry(key)
            .and_modify(|entry| *entry = None)
            .or_insert(Some(offset));
    }
    let mut candidates = Vec::new();
    for offset in (0..a.len().saturating_sub(width - 1)).step_by(sample) {
        if *remaining < width {
            return Ok((Vec::new(), false));
        }
        *remaining -= width;
        if offset % POLL == 0 {
            check(observer, "Matching content", offset, a.len())?;
        }
        if let Some(Some(other)) = index.get(&fingerprint(&a[offset..offset + width])) {
            if a[offset..offset + width] == b[*other..*other + width] {
                candidates.push((offset, *other));
            }
        }
    }
    // Increasing right offsets select the global order-preserving chain,
    // avoiding a greedy early match skipping a large unchanged middle.
    let mut tails: Vec<usize> = Vec::new();
    let mut previous = vec![None; candidates.len()];
    for (i, &(_, right)) in candidates.iter().enumerate() {
        if i % POLL == 0 {
            check(observer, "Ordering matches", i, candidates.len())?;
        }
        let position = tails.partition_point(|&j| candidates[j].1 < right);
        if position > 0 {
            previous[i] = Some(tails[position - 1]);
        }
        if position == tails.len() {
            tails.push(i)
        } else {
            tails[position] = i
        }
    }
    let mut ordered = Vec::new();
    let mut current = tails.last().copied();
    while let Some(i) = current {
        ordered.push(candidates[i]);
        current = previous[i];
    }
    ordered.reverse();
    let mut out = Vec::new();
    let (mut last_a, mut last_b) = (0, 0);
    for (mut x, mut y) in ordered {
        if x < last_a || y < last_b {
            continue;
        }
        while x > last_a && y > last_b && a[x - 1] == b[y - 1] {
            x -= 1;
            y -= 1;
        }
        let (mut end_a, mut end_b) = (x, y);
        while end_a < a.len() && end_b < b.len() && a[end_a] == b[end_b] {
            end_a += 1;
            end_b += 1;
            if end_a % POLL == 0 {
                check(observer, "Extending matches", end_a, a.len())?;
            }
        }
        out.push((x, y, end_a - x));
        last_a = end_a;
        last_b = end_b;
    }
    Ok((out, true))
}
