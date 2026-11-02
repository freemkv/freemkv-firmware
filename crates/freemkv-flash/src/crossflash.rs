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
    /// Implemented transition requiring live original-hardware evidence.
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

/// A live prerequisite attached to a specific prepared route. Requirements
/// within one route are AND; separate routes for the same pair are OR.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteRequirement {
    /// Real factory hardware, independently checked before any write.
    OriginalHardware {
        /// Complete factory platform token.
        platform: String,
        /// Optional exact product prefix.
        prefix: Option<String>,
        /// Optional exact product suffix.
        suffix: Option<String>,
    },
}

/// A prepared alternative for one explicit installed/target pair.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Route {
    /// Allowed, conditional, or future.
    pub status: RouteStatus,
    /// Every listed prerequisite must hold for this alternative.
    pub requirements: Vec<RouteRequirement>,
}

/// Catalogue route availability, separate from legacy diagnostic verdicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    /// Prepared without any extra hardware predicate.
    Allowed,
    /// Prepared with explicit live prerequisites.
    Conditional,
    /// A known transition awaits an implemented adapter.
    Future,
}

/// Internal planner result keeps typed refusal explanations with its routes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Evaluation {
    pub(crate) routes: Vec<Route>,
    pub(crate) reason: Option<String>,
}

/// Classify typed errors, never message text. Unknown evidence is a hard no.
pub(crate) fn refusal_status(mut error: &(dyn std::error::Error + 'static)) -> CompatibilityStatus {
    loop {
        if matches!(
            error.downcast_ref::<pioneer_optical::startup::bank::Error>(),
            Some(pioneer_optical::startup::bank::Error::ConversionRequired { .. })
        ) {
            return CompatibilityStatus::SoftNo;
        }
        if matches!(
            error.downcast_ref::<pioneer_optical::image::KernelHandoffError>(),
            Some(pioneer_optical::image::KernelHandoffError::Mismatch { .. })
        ) {
            return CompatibilityStatus::SoftNo;
        }
        if matches!(
            error.downcast_ref::<pioneer_optical::settings::adaptation::Error>(),
            Some(pioneer_optical::settings::adaptation::Error::OriginalRequired)
        ) {
            return CompatibilityStatus::Conditional;
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
                    CompatibilityStatus::Conditional => Some(
                        "original factory hardware must satisfy a listed route before any write"
                            .into(),
                    ),
                    CompatibilityStatus::SoftNo => reason,
                    _ => None,
                },
                routes,
            }
        }
        Err(error) => {
            let mut status = refusal_status(error.as_ref());
            // Missing evidence without a fully prepared predicate is not a route.
            if status == CompatibilityStatus::Conditional {
                status = CompatibilityStatus::HardNo;
            }
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

/// Whether `flash` admits `target` on a drive whose installed firmware is
/// `installed` (refusal reason on `Err`).
fn evaluate(platform: Platform, installed: &[u8], target: &[u8]) -> Result<Evaluation> {
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
                let first =
                    crate::backend::registry::offline_routes(platform, installed, intermediate)?;
                let second = crate::backend::registry::offline_routes(
                    platform,
                    intermediate,
                    package.firmware(),
                )?;
                let mut reasons: Vec<_> = [first.reason, second.reason]
                    .into_iter()
                    .flatten()
                    .collect();
                reasons.sort();
                reasons.dedup();
                return Ok(Evaluation {
                    routes: compose_routes(&first.routes, &second.routes),
                    reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
                });
            }
            return crate::backend::registry::offline_routes(
                platform,
                installed,
                package.firmware(),
            );
        }
        return crate::backend::registry::offline_routes(platform, installed, target);
    }
    crate::backend::registry::offline_routes(platform, installed, target)
}

/// Every alternative of one stage combines with every alternative of the next.
/// Stage prerequisites accumulate as AND; alternative combinations remain OR.
fn compose_routes(first: &[Route], second: &[Route]) -> Vec<Route> {
    let mut routes = Vec::new();
    for a in first {
        for b in second {
            let mut requirements = a.requirements.clone();
            requirements.extend(b.requirements.iter().cloned());
            requirements.sort();
            requirements.dedup();
            let status = if a.status == RouteStatus::Future || b.status == RouteStatus::Future {
                RouteStatus::Future
            } else if requirements.is_empty() {
                RouteStatus::Allowed
            } else {
                RouteStatus::Conditional
            };
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

/// Every context ran all common admission gates. Only a typed adapter refusal
/// deferred by that pipeline becomes Future, with that context's predicates.
/// One failed alternative cannot erase another successful or future route.
pub(crate) fn collect_routes(
    contexts: impl IntoIterator<Item = (Vec<RouteRequirement>, Result<Vec<RouteRequirement>>)>,
) -> Result<Evaluation> {
    let mut routes = Vec::new();
    let mut reasons = Vec::new();
    let mut refusals = Vec::new();
    for (context, result) in contexts {
        let (status, mut requirements) = match result {
            Ok(requirements) => (
                if requirements.is_empty() {
                    RouteStatus::Allowed
                } else {
                    RouteStatus::Conditional
                },
                requirements,
            ),
            Err(error) if refusal_status(error.as_ref()) == CompatibilityStatus::SoftNo => {
                reasons.push(format!("{error:#}"));
                (RouteStatus::Future, context)
            }
            Err(error) => {
                refusals.push(error);
                continue;
            }
        };
        requirements.sort();
        requirements.dedup();
        routes.push(Route {
            status,
            requirements,
        });
    }
    routes.sort();
    routes.dedup();
    if routes.is_empty() {
        refusals.sort_by_key(|error| format!("{error:#}"));
        return Err(refusals
            .into_iter()
            .next()
            .unwrap_or_else(|| anyhow::anyhow!("no supported original-hardware context")));
    }
    reasons.sort();
    reasons.dedup();
    Ok(Evaluation {
        routes,
        reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
    })
}

/// Whether a fully prepared route has no additional live prerequisites.
/// Conditional routes are available through [`decide`], with exact predicates.
pub fn admits(platform: Platform, installed: &[u8], target: &[u8]) -> Result<()> {
    let routes = evaluate(platform, installed, target)?;
    anyhow::ensure!(
        routes
            .routes
            .iter()
            .any(|r| r.status == RouteStatus::Allowed && r.requirements.is_empty()),
        pioneer_optical::settings::adaptation::Error::OriginalRequired
    );
    Ok(())
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
    let mut admitted: Vec<(usize, usize, Route)> = std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|pairs| {
                scope.spawn(move || {
                    pairs
                        .iter()
                        .copied()
                        .flat_map(|(i, j)| {
                            decide(platform, packages[i], packages[j])
                                .routes
                                .into_iter()
                                .map(move |route| (i, j, route))
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
mod adaptation_tests {
    use super::*;
    #[test]
    fn missing_original_evidence_is_conditional_but_native_mismatch_is_not() {
        use pioneer_optical::settings::adaptation::Error;
        assert_eq!(
            refusal_status(&Error::OriginalRequired),
            CompatibilityStatus::Conditional
        );
        for error in [Error::OriginalMismatch, Error::Guard, Error::Registry] {
            assert_eq!(refusal_status(&error), CompatibilityStatus::HardNo);
        }
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;
    fn hardware(platform: &str, prefix: Option<&str>) -> RouteRequirement {
        RouteRequirement::OriginalHardware {
            platform: platform.into(),
            prefix: prefix.map(Into::into),
            suffix: None,
        }
    }
    #[test]
    fn intermediate_stages_preserve_and_requirements_and_or_alternatives() {
        let broad = hardware("UD02", None);
        let narrow = hardware("UD02", Some("BDR"));
        let first = [Route {
            status: RouteStatus::Conditional,
            requirements: vec![broad.clone()],
        }];
        let second = [
            Route {
                status: RouteStatus::Allowed,
                requirements: vec![],
            },
            Route {
                status: RouteStatus::Conditional,
                requirements: vec![narrow.clone()],
            },
        ];
        let result = compose_routes(&first, &second);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&Route {
            status: RouteStatus::Conditional,
            requirements: vec![broad.clone()]
        }));
        assert!(result.contains(&Route {
            status: RouteStatus::Conditional,
            requirements: vec![broad, narrow]
        }));
    }
    #[test]
    fn future_and_hard_refusal_context_order_cannot_erase_a_route() {
        use pioneer_optical::startup::bank::{Error, Storage};
        let contexts = || {
            vec![
                (
                    vec![hardware("UD02", None)],
                    Err(Error::ConversionRequired {
                        installed: Storage::KernelSequences {
                            sequences: [1, 2],
                            bases: [3, 4],
                        },
                        target: Storage::KernelSequences {
                            sequences: [5, 6],
                            bases: [7, 8],
                        },
                    }
                    .into()),
                ),
                (
                    vec![hardware("UD03", None)],
                    Err(pioneer_optical::settings::adaptation::Error::OriginalMismatch.into()),
                ),
            ]
        };
        let forward = collect_routes(contexts()).unwrap();
        let reverse = collect_routes(contexts().into_iter().rev()).unwrap();
        assert_eq!(forward, reverse);
        assert!(forward
            .reason
            .as_deref()
            .unwrap()
            .contains("persistent bank format"));
        assert_eq!(
            forward.routes,
            vec![Route {
                status: RouteStatus::Future,
                requirements: vec![hardware("UD02", None)]
            }]
        );
    }
}
