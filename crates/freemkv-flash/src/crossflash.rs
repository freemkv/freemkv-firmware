//! Offline crossflash decisions: which firmware a drive running one package can
//! be flashed to, decided by the exact gates `flash` runs before any write, with
//! the installed package standing in for the drive (and its pre-flash backup).
//! Anything that lists crossflash options should use these decisions rather
//! than re-implement the rule.

use anyhow::Result;

/// Shared direct-transfer compatibility result. Only Yes permits writing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    /// The existing flash path admits the transfer.
    Yes,
    /// Known same-hardware transition requiring an unimplemented adapter.
    SoftNo,
    /// Incompatible, invalid, or insufficiently understood transition.
    HardNo,
}

/// Offline decision returned to catalogue and diagnostic consumers.
#[derive(Debug, serde::Serialize)]
pub struct Decision {
    /// Yes, soft_no or hard_no.
    pub status: CompatibilityStatus,
    /// Explanation for a refusal; absent for an admitted transfer.
    pub reason: Option<String>,
}

/// Classify typed errors, never message text. Unknown evidence is a hard no.
pub(crate) fn refusal_status(mut error: &(dyn std::error::Error + 'static)) -> CompatibilityStatus {
    loop {
        if matches!(
            error.downcast_ref::<pioneer_optical::image::KernelHandoffError>(),
            Some(pioneer_optical::image::KernelHandoffError::Mismatch { .. })
        ) {
            return CompatibilityStatus::SoftNo;
        }
        match error.source() {
            Some(source) => error = source,
            None => return CompatibilityStatus::HardNo,
        }
    }
}

/// Run the same complete admission checks as Flash and retain refusal kind.
pub fn decide(platform: Platform, installed: &[u8], target: &[u8]) -> Decision {
    match admits(platform, installed, target) {
        Ok(()) => Decision {
            status: CompatibilityStatus::Yes,
            reason: None,
        },
        Err(error) => Decision {
            status: refusal_status(error.as_ref()),
            reason: Some(format!("{error:#}")),
        },
    }
}

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
    if platform == Platform::Mediatek {
        let installed_package = (installed.get(257..262) == Some(b"ustar"))
            .then(|| crate::mediatek_package::Package::parse(installed))
            .transpose()?;
        let target_package = (target.get(257..262) == Some(b"ustar"))
            .then(|| crate::mediatek_package::Package::parse(target))
            .transpose()?;
        let installed = installed_package
            .as_ref()
            .map_or(installed, |p| p.firmware());
        if let Some(package) = &target_package {
            if let Some(intermediate) = package.intermediate() {
                crate::backend::registry::decide_offline(platform, installed, intermediate)?;
                return crate::backend::registry::decide_offline(
                    platform,
                    intermediate,
                    package.firmware(),
                );
            }
            return crate::backend::registry::decide_offline(
                platform,
                installed,
                package.firmware(),
            );
        }
        return crate::backend::registry::decide_offline(platform, installed, target);
    }
    crate::backend::registry::decide_offline(platform, installed, target)
}

/// Every admitted `(installed, target)` pair of distinct packages, as indices
/// into `packages`, sorted. Pairs the family gate refuses are skipped without a
/// full decision (a cheap, exact pre-filter); every other pair runs [`admits`].
pub fn links(platform: Platform, packages: &[&[u8]]) -> Vec<(usize, usize)> {
    classified_links(platform, packages)
        .into_iter()
        .filter_map(|(i, j, status)| (status == CompatibilityStatus::Yes).then_some((i, j)))
        .collect()
}

/// Admitted and known future-adapter candidates; hard refusals stay unlisted.
pub fn classified_links(
    platform: Platform,
    packages: &[&[u8]],
) -> Vec<(usize, usize, CompatibilityStatus)> {
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
    let mut admitted: Vec<(usize, usize, CompatibilityStatus)> = std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|pairs| {
                scope.spawn(move || {
                    pairs
                        .iter()
                        .copied()
                        .filter_map(|(i, j)| {
                            let status = decide(platform, packages[i], packages[j]).status;
                            (status != CompatibilityStatus::HardNo).then_some((i, j, status))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("crossflash worker panicked"))
            .collect()
    });
    admitted.sort_unstable_by_key(|&(i, j, _)| (i, j));
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
        if platform == Platform::Mediatek {
            if let Ok(package) = crate::mediatek_package::Package::parse(bytes) {
                return crate::backend::registry::offline_prefilter(platform, package.firmware());
            }
        }
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
