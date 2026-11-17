//! Offline crossflash decisions: which firmware a drive running one package can
//! be flashed to, decided by the exact gates `flash` runs before any write, with
//! the installed package standing in for the drive (and its pre-flash backup).
//! Anything that lists crossflash options should use these decisions rather
//! than re-implement the rule.

use anyhow::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    decide_from(evaluate(platform, installed, target))
}

/// Turn an evaluation result into the final decision. The single post-processing
/// step shared by `decide` (bytes in) and the offline catalogue scan's
/// pre-decoded path, so both yield byte-identical verdicts.
pub(crate) fn decide_from(result: Result<Evaluation>) -> Decision {
    match result {
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

/// The registered backend a set of packages belongs to, named by its route
/// namespace (the package-tree directory, e.g. `pioneer`). Crossflash never
/// matches on a vendor: every decision goes through the backend's facet.
#[derive(Clone, Copy)]
pub struct Platform(pub(crate) &'static dyn crate::backend::registry::Offline);

impl Platform {
    /// Platform of a flash input, by the registered backends' input claims.
    pub fn of_input(target: &[u8]) -> Self {
        Self(
            crate::backend::registry::offline()
                .find(|backend| backend.claims(target))
                .expect("the last registered evaluator claims every input"),
        )
    }
    /// Every registered platform, in claim order.
    pub fn all() -> impl Iterator<Item = Self> {
        crate::backend::registry::offline().map(Self)
    }
    /// The platform whose route namespace is `id`.
    pub fn by_id(id: &str) -> Option<Self> {
        crate::backend::registry::offline_by_id(id).map(Self)
    }
    /// Route namespace and package-tree directory.
    pub fn id(self) -> &'static str {
        self.0.id()
    }
    pub(crate) fn backend(self) -> &'static dyn crate::backend::registry::Offline {
        self.0
    }
}
impl PartialEq for Platform {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for Platform {}
impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// Whether `flash` admits `target` on a drive whose installed firmware is
/// `installed` (refusal reason on `Err`).
fn evaluate(platform: Platform, installed: &[u8], target: &[u8]) -> Result<Evaluation> {
    platform.backend().evaluate(installed, target)
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
    // Decode each package ONCE. The per-pair path otherwise re-untars and
    // re-clones each firmware out of its tar for every pair it appears in
    // (hundreds of times) — that allocation churn, not the decision logic, was
    // the cost. A package that cannot be prepared (e.g. Normal-only) is `None`
    // and its pairs fall back to the ordinary byte path (identical verdict).
    let prepared: Vec<Option<crate::backend::registry::OfflinePrepared>> =
        std::thread::scope(|scope| {
            let handles: Vec<_> = packages
                .chunks(package_chunk)
                .map(|chunk| {
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|b| platform.backend().prepare(b))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("package decode worker panicked"))
                .collect()
        });
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
                let prepared = &prepared;
                scope.spawn(move || {
                    let mut admitted = Vec::new();
                    while let Some(&(i, j)) =
                        candidates.get(next_pair.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    {
                        // Same decision core as `decide` (and the live flasher),
                        // fed the decode-once evidence when both sides have it;
                        // otherwise the ordinary byte path. Verdicts are identical.
                        let routes = match (&prepared[i], &prepared[j]) {
                            (Some(installed), Some(target)) => {
                                decide_from(platform.backend().evaluate_prepared(installed, target))
                                    .routes
                            }
                            _ => decide(platform, packages[i], packages[j]).routes,
                        };
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
/// Each backend computes it from the bytes (its offline facet).
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
        platform.backend().prefilter(bytes)
    }

    /// False only when the flasher's routing must refuse the pair; the
    /// platform's facet owns its routing rule over the family comparison.
    pub(crate) fn may_admit(&self, target: &Prefilter) -> bool {
        use crate::firmware_comparison::FamilyRelationship;
        // Both fingerprints came from current backend analyzers in this
        // process; the platform's route namespace scopes them.
        let same_family = FamilyRelationship::compare(
            self.family.as_deref().map(|id| (self.platform.id(), id)),
            target
                .family
                .as_deref()
                .map(|id| (target.platform.id(), id)),
        ) == FamilyRelationship::Same;
        self.platform.backend().may_admit(self, target, same_family)
    }
}

/// Usage text shown by `--help`.
pub const CLI_USAGE: &str = "Usage: freemkv-crossflash <package directory>\n       freemkv-crossflash --why [--json] <installed> <target>";

/// Run the offline evaluator for command-line `args` (without the program name).
/// The result is the standard-output text.
pub fn cli(args: &[String]) -> Result<String> {
    if args == ["--help"] || args == ["-h"] {
        return Ok(CLI_USAGE.into());
    }
    if let [flag, json, installed, target] = args {
        if flag == "--why" && json == "--json" {
            let (installed, target) = read_pair(Path::new(installed), Path::new(target))?;
            let decision = decide(Platform::of_input(&target), &installed, &target);
            return Ok(serde_json::to_string(&decision)?);
        }
    }
    if let [flag, installed, target] = args {
        if flag == "--why" {
            return why(Path::new(installed), Path::new(target));
        }
    }
    let [root] = args else {
        return Err(anyhow::anyhow!(
            "usage: freemkv-crossflash <package directory> or --why [--json] <installed> <target>"
        )
        .context(crate::user_error::IssueCode::CommandOptions));
    };
    let mut groups: BTreeMap<(String, Route), Vec<String>> = BTreeMap::new();
    let mut evaluated_packages = Vec::new();
    for platform in Platform::all() {
        let dir = platform.id();
        let (ids, bytes) = read_packages(&Path::new(root).join(dir), "tar")?;
        let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let found = classified_routes(platform, &refs);
        eprintln!(
            "{dir}: {} packages, {} route alternatives",
            ids.len(),
            found.len()
        );
        evaluated_packages.extend(ids.iter().cloned());
        for (i, j, route) in found {
            groups
                .entry((ids[i].clone(), route))
                .or_default()
                .push(ids[j].clone());
        }
    }
    evaluated_packages.sort();
    evaluated_packages.dedup();
    let groups: Vec<_> = groups
        .into_iter()
        .map(|((source, route), mut targets)| {
            targets.sort();
            targets.dedup();
            serde_json::json!({"source": source, "status": route.status, "requirements": route.requirements, "targets": targets})
        })
        .collect();
    let doc = serde_json::json!({
        "format": "freemkv-crossflash-routes",
        "version": 3,
        "freemkv_flash": env!("CARGO_PKG_VERSION"),
        "evaluated_packages": evaluated_packages,
        "groups": groups,
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

fn read_pair(installed: &Path, target: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    use anyhow::Context;
    let read = |p: &Path| std::fs::read(p).with_context(|| format!("reading {}", p.display()));
    Ok((read(installed)?, read(target)?))
}

/// The flasher's verdict for one installed/target pair.
fn why(installed: &Path, target: &Path) -> Result<String> {
    let (installed, target) = read_pair(installed, target)?;
    let decision = decide(Platform::of_input(&target), &installed, &target);
    verdict(&decision)
}

/// One-line verdict text: admitted, the conditional routes, or the refusal reason.
pub fn verdict(decision: &Decision) -> Result<String> {
    Ok(match decision.status {
        CompatibilityStatus::Yes => "admitted".into(),
        CompatibilityStatus::Conditional => {
            format!("conditional: {}", serde_json::to_string(&decision.routes)?)
        }
        _ => format!(
            "refused: {}",
            decision.reason.as_deref().unwrap_or("no supported route")
        ),
    })
}

/// Every `<sha256>.<ext>` in `dir`, sorted by name: (ids, bytes).
pub fn read_packages(dir: &Path, ext: &str) -> Result<(Vec<String>, Vec<Vec<u8>>)> {
    use anyhow::Context;
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    paths.retain(|p| p.extension().is_some_and(|e| e == ext));
    paths.sort();
    let mut ids = Vec::with_capacity(paths.len());
    let mut bytes = Vec::with_capacity(paths.len());
    for path in paths {
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .with_context(|| format!("bad package name {}", path.display()))?;
        ids.push(id.to_string());
        bytes.push(std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?);
    }
    Ok((ids, bytes))
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
        use pioneer_optical::classify::KernelHandoffError;
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
        assert_eq!(Platform::of_input(&enc).id(), "pioneer");
        let bin = include_bytes!("../tests/fixtures/HL-DT-ST_BU40N_N1.02_2017-12-08.bin");
        assert_eq!(Platform::of_input(bin).id(), "mediatek");
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(Platform::of_input(&tar).id(), "pioneer");
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }
    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "freemkv-crossflash-{}",
            crate::diagnostics::new_operation_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn decision(status: CompatibilityStatus, reason: Option<&str>) -> Decision {
        Decision {
            status,
            reason: reason.map(str::to_owned),
            routes: vec![Route {
                status: RouteStatus::Conditional,
                requirements: Vec::new(),
            }],
        }
    }

    #[test]
    fn help_flags_print_only_the_usage() {
        for flag in ["--help", "-h"] {
            assert_eq!(cli(&args(&[flag])).unwrap(), CLI_USAGE);
        }
        assert!(cli(&args(&["--help", "extra"])).is_err());
    }

    #[test]
    fn malformed_argument_lists_are_usage_errors() {
        for list in [
            args(&[]),
            args(&["a", "b"]),
            args(&["--bogus", "--json", "a", "b"]),
            args(&["--why", "-x", "a", "b"]),
            args(&["a", "b", "c", "d", "e"]),
        ] {
            let error = cli(&list).unwrap_err();
            assert!(
                format!("{error:#}").contains("usage"),
                "{list:?}: {error:#}"
            );
        }
    }

    #[test]
    fn why_reports_refusals_and_unreadable_files() {
        let dir = scratch();
        let (a, b) = (dir.join("a.bin"), dir.join("b.bin"));
        std::fs::write(&a, b"not firmware").unwrap();
        std::fs::write(&b, b"also not firmware").unwrap();
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());
        let text = cli(&args(&["--why", a, b])).unwrap();
        assert!(text.starts_with("refused: "), "{text}");
        let json = cli(&args(&["--why", "--json", a, b])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["status"], "hard_no");
        assert!(value["routes"].as_array().unwrap().is_empty());
        let missing = dir.join("missing.bin");
        let error = cli(&args(&["--why", a, missing.to_str().unwrap()])).unwrap_err();
        assert!(format!("{error:#}").contains("reading"), "{error:#}");
        let error = cli(&args(&["--why", "--json", missing.to_str().unwrap(), a])).unwrap_err();
        assert!(format!("{error:#}").contains("reading"), "{error:#}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verdict_distinguishes_every_status() {
        assert_eq!(
            verdict(&decision(CompatibilityStatus::Yes, None)).unwrap(),
            "admitted"
        );
        let conditional = verdict(&decision(CompatibilityStatus::Conditional, Some("x"))).unwrap();
        assert!(conditional.starts_with("conditional: [{"), "{conditional}");
        assert!(conditional.contains("\"conditional\""), "{conditional}");
        assert_eq!(
            verdict(&decision(CompatibilityStatus::SoftNo, Some("later"))).unwrap(),
            "refused: later"
        );
        assert_eq!(
            verdict(&decision(CompatibilityStatus::HardNo, None)).unwrap(),
            "refused: no supported route"
        );
    }

    #[test]
    fn read_packages_returns_sorted_matching_files_with_their_bytes() {
        let dir = scratch();
        std::fs::write(dir.join("b.tar"), [2u8, 2]).unwrap();
        std::fs::write(dir.join("a.tar"), [1u8]).unwrap();
        std::fs::write(dir.join("c.txt"), [3u8]).unwrap();
        std::fs::write(dir.join("noext"), [4u8]).unwrap();
        let (ids, bytes) = read_packages(&dir, "tar").unwrap();
        assert_eq!(ids, ["a", "b"]);
        assert_eq!(bytes, [vec![1u8], vec![2u8, 2]]);
        let (ids, bytes) = read_packages(&dir, "txt").unwrap();
        assert_eq!((ids, bytes), (vec!["c".to_string()], vec![vec![3u8]]));
        let error = read_packages(&dir.join("absent"), "tar").unwrap_err();
        assert!(format!("{error:#}").contains("reading"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scan_lists_every_evaluated_package_sorted_across_platforms() {
        let dir = scratch();
        let ids: Vec<&str> = Platform::all().map(Platform::id).collect();
        for (n, id) in ids.iter().enumerate() {
            let sub = dir.join(id);
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join(format!("pkg{}.tar", ids.len() - n)), b"junk").unwrap();
            std::fs::write(sub.join("ignored.txt"), b"junk").unwrap();
        }
        let json = cli(&args(&[dir.to_str().unwrap()])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["format"], "freemkv-crossflash-routes");
        assert_eq!(value["version"], 3);
        let evaluated: Vec<String> = (1..=ids.len()).map(|n| format!("pkg{n}")).collect();
        assert_eq!(value["evaluated_packages"], serde_json::json!(evaluated));
        assert!(value["groups"].as_array().unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(cli(&args(&[dir.to_str().unwrap()])).is_err());
    }

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crate::crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crate::crc32(b""), 0);
        assert_ne!(crate::crc32(b"a"), crate::crc32(b"b"));
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;

    fn route(status: RouteStatus) -> Route {
        Route {
            status,
            requirements: Vec::new(),
        }
    }
    fn evaluation(statuses: &[RouteStatus], reason: Option<&str>) -> Result<Evaluation> {
        Ok(Evaluation {
            routes: statuses.iter().copied().map(route).collect(),
            reason: reason.map(str::to_owned),
        })
    }

    #[test]
    fn route_statuses_pick_the_strongest_verdict_and_its_reason() {
        use RouteStatus::*;
        let yes = decide_from(evaluation(&[Future, Allowed, Conditional], Some("why")));
        assert_eq!(yes.status, CompatibilityStatus::Yes);
        assert_eq!(yes.reason, None);
        let conditional = decide_from(evaluation(&[Future, Conditional], Some("why")));
        assert_eq!(conditional.status, CompatibilityStatus::Conditional);
        assert_eq!(
            conditional.reason.as_deref(),
            Some("Read-only live correction prerequisites must hold before firmware transfer")
        );
        let soft = decide_from(evaluation(&[Future], Some("not yet")));
        assert_eq!(soft.status, CompatibilityStatus::SoftNo);
        assert_eq!(soft.reason.as_deref(), Some("not yet"));
        let none = decide_from(evaluation(&[], Some("nothing")));
        assert_eq!(none.status, CompatibilityStatus::SoftNo);
        assert_eq!(none.reason.as_deref(), Some("nothing"));
    }

    #[test]
    fn duplicate_routes_collapse_and_sort() {
        use RouteStatus::*;
        let decision = decide_from(evaluation(&[Future, Allowed, Future, Allowed], None));
        assert_eq!(
            decision.routes,
            vec![route(Allowed), route(Future)],
            "sorted and deduplicated"
        );
    }

    #[test]
    fn typed_refusals_keep_their_status_and_text() {
        let refusal = RouteRefusal {
            status: CompatibilityStatus::SoftNo,
            reason: "adapter pending".into(),
        };
        assert_eq!(refusal.to_string(), "adapter pending");
        let decision = decide_from(Err(anyhow::Error::new(refusal)));
        assert_eq!(decision.status, CompatibilityStatus::SoftNo);
        assert_eq!(decision.reason.as_deref(), Some("adapter pending"));
        assert_eq!(decision.routes, vec![route(RouteStatus::Future)]);
        let hard = decide_from(Err(anyhow::anyhow!("unknown evidence")));
        assert_eq!(hard.status, CompatibilityStatus::HardNo);
        assert!(hard.routes.is_empty());
    }

    #[test]
    fn platforms_are_found_compared_and_printed_by_namespace() {
        let all: Vec<_> = Platform::all().collect();
        assert!(!all.is_empty());
        for platform in &all {
            let found = Platform::by_id(platform.id()).unwrap();
            assert!(found == *platform);
            assert_eq!(format!("{platform:?}"), platform.id());
        }
        if all.len() > 1 {
            assert!(all[0] != all[1]);
        }
        assert!(Platform::by_id("no-such-platform").is_none());
    }
}
