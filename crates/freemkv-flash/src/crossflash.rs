//! Offline crossflash decisions: which firmware a drive running one package can
//! be flashed to, decided by the exact gates `flash` runs before any write, with
//! the installed package standing in for the drive (and its pre-flash backup).
//! Anything that lists crossflash options should use these decisions rather
//! than re-implement the rule.

use anyhow::Result;

/// Offline compatibility result. Conditional routes need live preflight checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    /// The existing flash path admits the transfer.
    Yes,
    /// Prepared correction requires live read-only prerequisites.
    Conditional,
    /// Known same-hardware transition requiring an unimplemented adapter.
    SoftNo,
    /// Incompatible, invalid, or insufficiently understood transition.
    HardNo,
}

/// Offline decision returned to catalogue and diagnostic consumers.
#[derive(Debug, serde::Serialize)]
pub struct Decision {
    /// Yes, conditional, soft_no or hard_no.
    pub status: CompatibilityStatus,
    /// Explanation for a refusal; absent for an admitted transfer.
    pub reason: Option<String>,
    /// Prepared alternatives; empty for an unlisted refusal.
    pub routes: Vec<Route>,
}

/// A prepared alternative for one explicit installed/target pair.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Route {
    /// Allowed, conditional, or future.
    pub status: RouteStatus,
    /// Read-only conditions enforced by the prepared firmware executor.
    pub requirements: Vec<RouteRequirement>,
}

/// Catalogue route availability, separate from legacy diagnostic verdicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    /// Prepared by the flash admission gates.
    Allowed,
    /// Prepared, subject to live read-only prerequisites.
    Conditional,
    /// A known transition awaits an implemented adapter.
    Future,
}

/// A filter-owned condition; no persistent write is authorized by this value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteRequirement {
    /// An existing parameter word must match before any firmware write.
    ParameterWord {
        /// Filter that proved this prerequisite.
        filter: String,
        /// Native parameter index.
        parameter: u16,
        /// Required existing value.
        value: u16,
    },
}

/// Internal planner result keeps typed refusal explanations with its routes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Evaluation {
    pub(crate) routes: Vec<Route>,
    pub(crate) reason: Option<String>,
}

#[derive(Debug)]
struct RouteRefusal {
    status: CompatibilityStatus,
    reason: String,
}
impl std::fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}
impl std::error::Error for RouteRefusal {}

/// Classify typed errors, never message text. Unknown evidence is a hard no.
pub(crate) fn refusal_status(mut error: &(dyn std::error::Error + 'static)) -> CompatibilityStatus {
    loop {
        if let Some(refusal) = error.downcast_ref::<RouteRefusal>() {
            return refusal.status;
        }
        if let Some(status) = crate::backend::registry::refusal_status(error) {
            return status;
        }
        match error.source() {
            Some(source) => error = source,
            None => return CompatibilityStatus::HardNo,
        }
    }
}

/// Run the same complete admission checks as Flash and retain refusal kind.
pub fn decide(platform: Platform, installed: &[u8], target: &[u8]) -> Decision {
    match evaluate(platform, installed, target) {
        Ok(Evaluation { mut routes, reason }) => {
            routes.sort();
            routes.dedup();
            let status = if routes.iter().any(|r| r.status == RouteStatus::Allowed) {
                CompatibilityStatus::Yes
            } else if routes.iter().any(|r| r.status == RouteStatus::Conditional) {
                CompatibilityStatus::Conditional
            } else {
                CompatibilityStatus::SoftNo
            };
            Decision {
                status,
                reason: match status {
                    CompatibilityStatus::SoftNo => reason,
                    CompatibilityStatus::Conditional => Some("Read-only live correction prerequisites must hold before firmware transfer".into()),
                    _ => None,
                },
                routes,
            }
        }
        Err(error) => {
            let status = refusal_status(error.as_ref());
            let routes = if status == CompatibilityStatus::SoftNo {
                vec![Route {
                    status: RouteStatus::Future,
                    requirements: Vec::new(),
                }]
            } else {
                Vec::new()
            };
            Decision {
                status,
                reason: Some(format!("{error:#}")),
                routes,
            }
        }
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

impl Platform {
    /// Platform of a flash input: a MediaTek package or image, a Pioneer tar, or a
    /// bare Pioneer Normal `.enc`.
    pub fn of_input(target: &[u8]) -> Self {
        crate::backend::registry::input_platform(target)
    }
}

/// Whether `flash` admits `target` on a drive whose installed firmware is
/// `installed` (refusal reason on `Err`).
fn evaluate(platform: Platform, installed: &[u8], target: &[u8]) -> Result<Evaluation> {
    crate::backend::registry::offline_evaluate(platform, installed, target)
}

/// Every alternative of one stage combines with every alternative of the next.
/// A combination is future when either stage is.
pub(crate) fn compose_routes(first: &[Route], second: &[Route]) -> Vec<Route> {
    let mut routes = Vec::new();
    for a in first {
        for b in second {
            let status = if a.status == RouteStatus::Future || b.status == RouteStatus::Future {
                RouteStatus::Future
            } else if a.status == RouteStatus::Conditional || b.status == RouteStatus::Conditional {
                RouteStatus::Conditional
            } else {
                RouteStatus::Allowed
            };
            let mut requirements = a.requirements.clone();
            requirements.extend(b.requirements.iter().cloned());
            requirements.sort();
            requirements.dedup();
            if requirements.iter().enumerate().any(|(index, requirement)| {
                let RouteRequirement::ParameterWord {
                    parameter, value, ..
                } = requirement;
                requirements[index + 1..].iter().any(|other| {
                    let RouteRequirement::ParameterWord {
                        parameter: other_parameter,
                        value: other_value,
                        ..
                    } = other;
                    parameter == other_parameter && value != other_value
                })
            }) {
                continue;
            }
            routes.push(Route {
                status,
                requirements,
            });
        }
    }
    routes.sort();
    routes.dedup();
    routes
}

/// The pair ran all common admission gates. Only a typed adapter refusal
/// deferred by that pipeline becomes Future; every other refusal is returned.
pub(crate) fn collect_route(result: Result<()>) -> Result<Evaluation> {
    match result {
        Ok(()) => Ok(Evaluation {
            routes: vec![Route {
                status: RouteStatus::Allowed,
                requirements: Vec::new(),
            }],
            reason: None,
        }),
        Err(error) if refusal_status(error.as_ref()) == CompatibilityStatus::SoftNo => {
            Ok(Evaluation {
                routes: vec![Route {
                    status: RouteStatus::Future,
                    requirements: Vec::new(),
                }],
                reason: Some(format!("{error:#}")),
            })
        }
        Err(error) => Err(error),
    }
}

/// Whether a route is admitted without unresolved live prerequisites.
pub fn admits(platform: Platform, installed: &[u8], target: &[u8]) -> Result<()> {
    let decision = decide(platform, installed, target);
    if decision.status == CompatibilityStatus::Yes {
        return Ok(());
    }
    Err(RouteRefusal {
        status: decision.status,
        reason: decision
            .reason
            .unwrap_or_else(|| "no admitted route".into()),
    }
    .into())
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
pub fn classified_routes(platform: Platform, packages: &[&[u8]]) -> Vec<(usize, usize, Route)> {
    // Reuse only package-local immutable evidence. Unsupported or incomplete
    // packages retain the ordinary path, including its exact typed refusals.
    // Package validation uses the same worker bound as pair evaluation.
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    let package_chunk = packages.len().div_ceil(workers).max(1);
    // Prefilter fingerprints only. Pair admission runs through the single
    // flasher decision path [`decide`] — the same one `--why` and the live
    // flasher use — so the website graph can never deviate from what Flash does.
    let keys: Vec<Prefilter> = std::thread::scope(|scope| {
        let handles: Vec<_> = packages
            .chunks(package_chunk)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|b| Prefilter::of(platform, b))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("package validation worker panicked"))
            .collect()
    });
    let candidates: Vec<(usize, usize)> = (0..packages.len())
        .flat_map(|i| (0..packages.len()).map(move |j| (i, j)))
        .filter(|&(i, j)| i != j && keys[i].may_admit(&keys[j]))
        .collect();
    // Pair costs vary substantially by family. Claim one pair at a time so
    // workers finishing cheap candidates can help with the expensive ones.
    // Relaxed ordering suffices: the counter only assigns immutable work.
    let next_pair = std::sync::atomic::AtomicUsize::new(0);
    let completed_pairs = std::sync::atomic::AtomicUsize::new(0);
    let started = std::time::Instant::now();
    let pair_workers = workers.min(candidates.len());
    eprintln!(
        "{platform:?}: {} scheduled pairs, {pair_workers} workers",
        candidates.len()
    );
    let mut admitted: Vec<(usize, usize, Route)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..pair_workers)
            .map(|_| {
                let candidates = &candidates;
                let next_pair = &next_pair;
                let completed_pairs = &completed_pairs;
                scope.spawn(move || {
                    let mut admitted = Vec::new();
                    while let Some(&(i, j)) =
                        candidates.get(next_pair.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    {
                        let routes = decide(platform, packages[i], packages[j]).routes;
                        admitted.extend(routes.into_iter().map(|route| (i, j, route)));
                        let completed =
                            completed_pairs.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        if completed.is_multiple_of(1000) && completed < candidates.len() {
                            eprintln!(
                                "{platform:?}: {completed}/{} pairs completed ({:.1}s)",
                                candidates.len(),
                                started.elapsed().as_secs_f64()
                            );
                        }
                    }
                    admitted
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("crossflash worker panicked"))
            .collect()
    });
    eprintln!(
        "{platform:?}: {}/{} pairs completed ({:.1}s)",
        completed_pairs.load(std::sync::atomic::Ordering::Relaxed),
        candidates.len(),
        started.elapsed().as_secs_f64()
    );
    admitted.sort_unstable_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
    admitted
}

/// Compatibility projection of the unified route evaluator.
pub fn classified_links(
    platform: Platform,
    packages: &[&[u8]],
) -> Vec<(usize, usize, CompatibilityStatus)> {
    let mut pairs = std::collections::BTreeMap::new();
    for (i, j, route) in classified_routes(platform, packages) {
        let status = match route.status {
            RouteStatus::Allowed => CompatibilityStatus::Yes,
            RouteStatus::Conditional => CompatibilityStatus::Conditional,
            RouteStatus::Future => CompatibilityStatus::SoftNo,
        };
        pairs.entry((i, j)).or_insert(status);
    }
    pairs
        .into_iter()
        .map(|((i, j), status)| (i, j, status))
        .collect()
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
    pub(crate) fn may_admit(&self, target: &Prefilter) -> bool {
        use crate::firmware_comparison::FamilyRelationship;
        // Both fingerprints came from current backend analyzers in this process.
        let namespace = |platform| match platform {
            Platform::Pioneer => "current-pioneer",
            Platform::Mediatek => "current-mediatek",
        };
        let same_family = FamilyRelationship::compare(
            self.family
                .as_deref()
                .map(|id| (namespace(self.platform), id)),
            target
                .family
                .as_deref()
                .map(|id| (namespace(target.platform), id)),
        ) == FamilyRelationship::Same;
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

#[cfg(test)]
mod route_tests {
    use super::*;
    fn route(status: RouteStatus) -> Route {
        Route {
            status,
            requirements: Vec::new(),
        }
    }
    #[test]
    fn intermediate_stages_are_future_when_either_stage_is() {
        let first = [route(RouteStatus::Allowed)];
        let second = [route(RouteStatus::Allowed), route(RouteStatus::Future)];
        assert_eq!(
            compose_routes(&first, &second),
            vec![route(RouteStatus::Allowed), route(RouteStatus::Future)]
        );
        assert_eq!(
            compose_routes(&[route(RouteStatus::Future)], &second),
            vec![route(RouteStatus::Future)]
        );
    }
    #[test]
    fn intermediate_stages_preserve_read_only_requirements() {
        let required = RouteRequirement::ParameterWord {
            filter: "phase".into(),
            parameter: 0x28f,
            value: 1,
        };
        let conditional = Route {
            status: RouteStatus::Conditional,
            requirements: vec![required.clone()],
        };
        assert_eq!(
            compose_routes(
                &[route(RouteStatus::Allowed)],
                std::slice::from_ref(&conditional)
            ),
            std::slice::from_ref(&conditional)
        );
        assert_eq!(
            compose_routes(
                std::slice::from_ref(&conditional),
                std::slice::from_ref(&conditional)
            ),
            std::slice::from_ref(&conditional)
        );
        assert_eq!(
            compose_routes(&[conditional], &[route(RouteStatus::Future)]),
            [Route {
                status: RouteStatus::Future,
                requirements: vec![required],
            }]
        );
    }

    #[test]
    fn stages_cannot_require_conflicting_values_of_one_read_only_word() {
        let stage = |filter: &str, value| Route {
            status: RouteStatus::Conditional,
            requirements: vec![RouteRequirement::ParameterWord {
                filter: filter.into(),
                parameter: 0x28f,
                value,
            }],
        };
        assert!(compose_routes(&[stage("phase", 1)], &[stage("other", 0)]).is_empty());
        let compatible = compose_routes(&[stage("phase", 1)], &[stage("other", 1)]);
        assert_eq!(compatible.len(), 1);
        assert_eq!(compatible[0].requirements.len(), 2);
    }

    #[test]
    fn only_a_typed_adapter_refusal_becomes_a_future_route() {
        use pioneer_optical::image::KernelHandoffError;
        let future = collect_route(Err(KernelHandoffError::Mismatch {
            installed: 0x400100,
            target: 0x400200,
        }
        .into()))
        .unwrap();
        assert_eq!(future.routes, vec![route(RouteStatus::Future)]);
        assert!(future
            .reason
            .as_deref()
            .unwrap()
            .contains("Kernel handoff mismatch"));
        assert!(collect_route(Err(KernelHandoffError::UnknownTarget.into())).is_err());
        // No persistent-bank conversion exists under any policy.
        use pioneer_optical::startup::bank::{Error, Storage};
        let storage = |base| Storage::KernelSequences {
            sequences: [base, base + 1],
            bases: [base + 2, base + 3],
        };
        assert!(collect_route(Err(Error::ConversionRequired {
            installed: storage(1),
            target: storage(5),
        }
        .into()))
        .is_err());
        assert_eq!(
            collect_route(Ok(())).unwrap(),
            Evaluation {
                routes: vec![route(RouteStatus::Allowed)],
                reason: None
            }
        );
    }
}

#[cfg(test)]
mod platform_tests {
    use super::*;
    #[test]
    fn bare_pioneer_normal_is_pioneer_and_other_inputs_keep_their_platform() {
        let mut enc = vec![0u8; 512];
        let header = b"********  Copyright(c) 2000 Pioneer Corporation\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11.\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
        enc[..header.len()].copy_from_slice(header);
        assert_eq!(Platform::of_input(&enc), Platform::Pioneer);
        let bin = include_bytes!("../tests/fixtures/HL-DT-ST_BU40N_N1.02_2017-12-08.bin");
        assert_eq!(Platform::of_input(bin), Platform::Mediatek);
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(Platform::of_input(&tar), Platform::Pioneer);
    }
}
