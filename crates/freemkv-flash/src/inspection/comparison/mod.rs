//! Pairwise comparison of provider-neutral, single-source analysis facts.
//! Firmware parsing and instruction decoding belong to each provider.
mod alignment;
mod engine;
mod metadata;
mod references;
mod tables;
use super::Control;
use anyhow::Result;
pub(super) use engine::ChangeKind;
use std::ops::Range;

#[derive(Clone, Debug)]
pub(super) struct Identity {
    pub component: String,
    pub sha256: String,
    pub family: Option<String>,
    pub family_scheme: String,
}
#[derive(Clone, Debug)]
pub(super) struct FirmwareAnalysis {
    pub identity: Identity,
    pub regions: Vec<Region>,
    pub complete: bool,
}
#[derive(Clone, Debug)]
pub(super) struct Region {
    pub id: usize,
    pub name: String,
    pub address: Option<u64>,
    pub metadata: Vec<Range<usize>>,
    pub representation: Representation,
    pub pairing_key: String,
    pub sha256: String,
    pub tables: Vec<Table>,
    pub references: Vec<Reference>,
    pub bytes: Vec<u8>,
}
impl Region {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Representation {
    Decoded,
    Expanded,
}
#[derive(Clone, Debug)]
pub(super) struct Reference {
    pub instruction: Range<usize>,
    pub operand: Range<usize>,
    pub target: u64,
}
#[derive(Clone, Debug)]
pub(super) struct Table {
    pub format: String,
    pub record_width: usize,
    pub records: Vec<String>,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Options {
    pub work: usize,
    pub findings: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            work: 50_000_000,
            findings: 100_000,
        }
    }
}
struct Progress<'a> {
    control: &'a Control,
    last: Option<(&'static str, usize)>,
}
fn check(
    progress: &mut Progress<'_>,
    stage: &'static str,
    done: usize,
    total: usize,
) -> Result<()> {
    progress.control.check()?;
    if progress.last.is_none_or(|(previous, count)| {
        previous != stage || done.saturating_sub(count) >= 65536 || done == total
    }) {
        crate::output::publish(crate::output::Event::Progress {
            label: stage.into(),
            done,
            total,
        });
        progress.last = Some((stage, done));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
