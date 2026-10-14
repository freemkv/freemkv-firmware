//! Offline crossflash decisions: which firmware a drive running one package can
//! be flashed to, decided by the exact gates `flash` runs before any write, with
//! the installed package standing in for the drive (and its pre-flash backup).
//! Anything that lists crossflash options should use these decisions rather
//! than re-implement the rule.

use anyhow::Result;

/// The firmware platform a set of packages belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// Pioneer installer tars (Kernel+Normal or Normal-only components).
    Pioneer,
    /// MediaTek MT19xx complete images.
    Mediatek,
}

/// Whether `flash` admits `target` on a drive whose installed firmware is
/// `installed` (refusal reason on `Err`).
pub fn admits(platform: Platform, installed: &[u8], target: &[u8]) -> Result<()> {
    crate::backend::registry::decide_offline(platform, installed, target)
}

/// Every admitted `(installed, target)` pair of distinct packages, as indices
/// into `packages`, sorted. Pairs the family gate refuses are skipped without a
/// full decision (a cheap, exact pre-filter); every other pair runs [`admits`].
pub fn links(platform: Platform, packages: &[&[u8]]) -> Vec<(usize, usize)> {
    let keys: Vec<Prefilter> = packages
        .iter()
        .map(|p| Prefilter::of(platform, p))
        .collect();
    let candidates: Vec<(usize, usize)> = (0..packages.len())
        .flat_map(|i| (0..packages.len()).map(move |j| (i, j)))
        .filter(|&(i, j)| i != j && keys[i].may_admit(&keys[j]))
        .collect();
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    let chunk = candidates.len().div_ceil(workers).max(1);
    let mut admitted: Vec<(usize, usize)> = std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|pairs| {
                scope.spawn(move || {
                    pairs
                        .iter()
                        .copied()
                        .filter(|&(i, j)| admits(platform, packages[i], packages[j]).is_ok())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("crossflash worker panicked"))
            .collect()
    });
    admitted.sort_unstable();
    admitted
}

/// What decides, without the full gates, that a pair can never be admitted.
/// Each backend computes it from the bytes (`registry::offline_prefilter`).
pub(crate) struct Prefilter {
    pub(crate) platform: Platform,
    /// The family the flasher's family gate compares (`None`: unknown, which
    /// the gate refuses — except a Pioneer Normal-only target, see below).
    pub(crate) family: Option<String>,
    /// Pioneer: the controller id (SAT). MediaTek: the image's model.
    pub(crate) model: Option<String>,
    /// Pioneer: the package has no Kernel. Its family is computed with the
    /// installed Kernel, and it can only be a same-SAT (same controller) target.
    pub(crate) normal_only: bool,
}

impl Prefilter {
    fn of(platform: Platform, bytes: &[u8]) -> Self {
        crate::backend::registry::offline_prefilter(platform, bytes)
    }

    /// False only when the flasher's routing must refuse the pair. Pioneer: the
    /// family gate runs first, and a Normal-only target can only be a
    /// same-controller flash (a crossflash needs a Kernel). MediaTek: a
    /// same-model image (the image model contains the drive's) skips the family
    /// gate, so it stays a candidate.
    fn may_admit(&self, target: &Prefilter) -> bool {
        let same_family = self.family.is_some() && self.family == target.family;
        match (self.platform, &self.model, &target.model) {
            (Platform::Pioneer, _, _) if target.normal_only => {
                self.model.is_some() && self.model == target.model
            }
            (Platform::Pioneer, _, _) => same_family,
            (Platform::Mediatek, Some(drive), Some(image)) => {
                same_family
                    || image
                        .to_ascii_uppercase()
                        .contains(&drive.to_ascii_uppercase())
            }
            (Platform::Mediatek, _, _) => same_family,
        }
    }
}
