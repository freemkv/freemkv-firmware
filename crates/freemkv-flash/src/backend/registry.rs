//! The explicit backend registry: the only core module that names a backend.
//!
//! Adding a controller protocol means one entry here plus its module under
//! [`crate::backends`]. No source scan or vendor-name shortcut can make a new
//! protocol flashable.

use std::path::Path;

use anyhow::{bail, Result};

use super::{Backend, Confidence, FileFormat, Identity, Match, Recognized};
use crate::backends::{mtk, pioneer};
use crate::platform::ScsiDevice;

// Compatibility exports keep the public module paths stable without teaching
// shared consumers which backend owns their implementation.
pub use crate::backends::catalog::{flashset, imageid};
pub use mtk::{cmac, package as mediatek_package, probe};
pub use pioneer::transport as pioneer_transport;

static MTK: mtk::Mtk = mtk::Mtk;
static PIONEER: pioneer::Pioneer = pioneer::Pioneer::new();

/// A backend's offline crossflash evaluator. [`crate::crossflash`] reaches
/// backends only through this facet; each implementation delegates to its
/// backend module. `id` names the package-tree directory and the namespace of
/// the backend's family fingerprints.
pub(crate) trait Offline: Sync {
    /// Package-tree directory and route namespace (`pioneer`, `mediatek`).
    fn id(&self) -> &'static str;
    /// Whether a flash input is this backend's firmware (probe order applies).
    fn claims(&self, input: &[u8]) -> bool;
    /// Routing facts the scan pre-filters pairs on.
    fn prefilter(&self, bytes: &[u8]) -> crate::crossflash::Prefilter;
    /// False only when the flasher's routing must refuse the pair.
    fn may_admit(
        &self,
        installed: &crate::crossflash::Prefilter,
        target: &crate::crossflash::Prefilter,
        same_family: bool,
    ) -> bool;
    /// The complete offline admission decision for one pair.
    fn evaluate(&self, installed: &[u8], target: &[u8]) -> Result<crate::crossflash::Evaluation>;
    /// Package-local evidence decoded once for the whole-catalogue scan.
    fn prepare(&self, _bytes: &[u8]) -> Option<OfflinePrepared> {
        None
    }
    /// [`Self::evaluate`] fed [`Self::prepare`]d evidence (identical verdict).
    fn evaluate_prepared(
        &self,
        installed: &OfflinePrepared,
        target: &OfflinePrepared,
    ) -> Result<crate::crossflash::Evaluation>;
}

/// Decode-once evidence for the whole-catalogue scan. Only Pioneer caches
/// (its tar untar/clone per pair was the cost); MediaTek decode is cheap, so
/// its pairs fall back to the ordinary byte path. Same decision core either way.
pub(crate) enum OfflinePrepared {
    Pioneer(pioneer::OfflinePrepared),
}

struct PioneerOffline;
impl Offline for PioneerOffline {
    fn id(&self) -> &'static str {
        "pioneer"
    }
    fn claims(&self, input: &[u8]) -> bool {
        mtk::package::Package::parse(input).is_err() && pioneer::routing::claims_platform(input)
    }
    fn prefilter(&self, bytes: &[u8]) -> crate::crossflash::Prefilter {
        pioneer::offline_prefilter(bytes)
    }
    fn may_admit(
        &self,
        installed: &crate::crossflash::Prefilter,
        target: &crate::crossflash::Prefilter,
        same_family: bool,
    ) -> bool {
        // The family gate runs first; a Normal-only target can only be a
        // same-controller flash (a crossflash needs a Kernel).
        if target.normal_only {
            installed.model.is_some() && installed.model == target.model
        } else {
            same_family
        }
    }
    fn evaluate(&self, installed: &[u8], target: &[u8]) -> Result<crate::crossflash::Evaluation> {
        pioneer::offline_routes(installed, target)
    }
    fn prepare(&self, bytes: &[u8]) -> Option<OfflinePrepared> {
        pioneer::offline_prepare(bytes)
            .ok()
            .map(OfflinePrepared::Pioneer)
    }
    fn evaluate_prepared(
        &self,
        installed: &OfflinePrepared,
        target: &OfflinePrepared,
    ) -> Result<crate::crossflash::Evaluation> {
        let (OfflinePrepared::Pioneer(i), OfflinePrepared::Pioneer(t)) = (installed, target);
        pioneer::offline_routes_prepared(i, t)
    }
}

struct MediatekOffline;
impl Offline for MediatekOffline {
    fn id(&self) -> &'static str {
        "mediatek"
    }
    fn claims(&self, input: &[u8]) -> bool {
        // Anything Pioneer does not claim is evaluated as MediaTek firmware.
        mtk::package::Package::parse(input).is_ok() || !pioneer::routing::claims_platform(input)
    }
    fn prefilter(&self, bytes: &[u8]) -> crate::crossflash::Prefilter {
        match crate::mediatek_package::Package::parse(bytes) {
            Ok(package) => mtk::offline_prefilter(package.firmware()),
            Err(_) => mtk::offline_prefilter(bytes),
        }
    }
    fn may_admit(
        &self,
        installed: &crate::crossflash::Prefilter,
        target: &crate::crossflash::Prefilter,
        same_family: bool,
    ) -> bool {
        // A same-model image (the image model contains the drive's) skips the
        // family gate, so it stays a candidate.
        match (&installed.model, &target.model) {
            (Some(drive), Some(image)) => {
                same_family
                    || image
                        .to_ascii_uppercase()
                        .contains(&drive.to_ascii_uppercase())
            }
            _ => same_family,
        }
    }
    fn evaluate(&self, installed: &[u8], target: &[u8]) -> Result<crate::crossflash::Evaluation> {
        mtk::routing::evaluate(installed, target)
    }
    fn evaluate_prepared(
        &self,
        _installed: &OfflinePrepared,
        _target: &OfflinePrepared,
    ) -> Result<crate::crossflash::Evaluation> {
        unreachable!("MediaTek prepares no offline evidence")
    }
}

/// Offline evaluators, in input-claim order (MediaTek packages first, then
/// Pioneer tars and bare Normal envelopes).
static OFFLINE: [&'static dyn Offline; 2] = [&PioneerOffline, &MediatekOffline];

/// Each backend's own crossflash platform handle (for backend code only).
pub(crate) const PIONEER_PLATFORM: crate::crossflash::Platform =
    crate::crossflash::Platform(&PioneerOffline);
pub(crate) const MEDIATEK_PLATFORM: crate::crossflash::Platform =
    crate::crossflash::Platform(&MediatekOffline);

/// Every registered offline evaluator.
pub(crate) fn offline() -> impl Iterator<Item = &'static dyn Offline> {
    OFFLINE.iter().copied()
}

/// The evaluator for the route namespace `id`.
pub(crate) fn offline_by_id(id: &str) -> Option<&'static dyn Offline> {
    offline().find(|backend| backend.id() == id)
}

/// Origin evidence is supplied by protocol file analysis, not the front end.
pub(crate) fn file_origin(bytes: &[u8]) -> crate::workflow::FileOrigin {
    pioneer::file_info::file_origin(bytes)
}

/// Probe order.
static BACKENDS: [&'static dyn Backend; 2] = [&MTK, &PIONEER];

/// Every registered protocol backend, in probe order.
pub fn backends() -> impl Iterator<Item = &'static dyn Backend> {
    BACKENDS.iter().copied()
}

/// A unique backend match, with device identity kept separate from the
/// controller protocol. Neither the vendor string nor the chip architecture
/// alone proves that a device accepts a backend's update commands.
pub struct Resolved {
    /// Device-reported vendor, product, revision and optional banner.
    pub identity: Identity,
    /// The matched backend.
    pub backend: &'static dyn Backend,
    /// Protocol signature independent of the device identity.
    pub matched: Match,
}

/// Probe OEM protocols first, then raw capture if none matches. Ambiguous OEM
/// matches fail closed rather than allowing registry order to select a writer.
pub fn resolve(dev: &mut dyn ScsiDevice) -> Result<Option<Resolved>> {
    resolve_detection(super::detection::detect(dev)?)
}

pub(crate) fn resolve_detection(
    detection: super::detection::Detection,
) -> Result<Option<Resolved>> {
    use super::detection::{Conclusion, Evidence};
    let (backend, evidence): (&'static dyn Backend, &'static str) = match detection.conclusion {
        Conclusion::Detected(Evidence::Mediatek(m)) => {
            // BOOT is recognized protocol evidence, but only Recovery can bind
            // its loader. Do not offer normal Flash/Backup merely from a banner.
            if !mtk::detection::normal_operations_available(&m) {
                return Ok(None);
            }
            (&MTK, "validated MT19 boot protocol signature")
        }
        Conclusion::Detected(Evidence::Pioneer(_)) => {
            (&PIONEER, "validated Pioneer CDB response contract")
        }
        Conclusion::Unknown => return Ok(None),
        Conclusion::Ambiguous => bail!(
            "ambiguous firmware protocol: Pioneer and MediaTek both matched; no firmware written"
        ),
    };
    Ok(Some(Resolved {
        identity: detection.identity,
        backend,
        matched: Match {
            backend: backend.descriptor().id,
            evidence,
        },
    }))
}

/// Compatibility adapter for backend callers; classification has one implementation.
pub(crate) fn probe_backend(
    dev: &mut dyn ScsiDevice,
    id: super::BackendId,
) -> Result<Option<Match>> {
    Ok(resolve(dev)?
        .filter(|r| r.matched.backend == id)
        .map(|r| r.matched))
}

/// The one recognizer: which backend's format `bytes` are. A structural claim
/// beats heuristic ones; two structural claims, or two heuristic claims with
/// no structural one, are an ambiguous file.
pub fn recognize(bytes: &[u8]) -> Result<Option<(&'static dyn Backend, Recognized)>> {
    recognize_among(backends(), bytes)
}

/// Reject proven corrupt recognized inputs before device discovery or opening.
/// Unknown formats keep the existing backend-specific selection behavior.
pub(crate) fn validate_flash_input(bytes: &[u8]) -> Result<()> {
    if let Some((backend, recognized)) = recognize(bytes)? {
        if let Some(files) = backend.files() {
            files.validate_flash_input(bytes, &recognized)?;
        }
    }
    Ok(())
}

/// [`recognize`] over an explicit backend list.
pub fn recognize_among<B: Backend + ?Sized + 'static>(
    candidates: impl IntoIterator<Item = &'static B>,
    bytes: &[u8],
) -> Result<Option<(&'static B, Recognized)>> {
    let claims: Vec<(&'static B, Recognized)> = candidates
        .into_iter()
        .filter_map(|b| Some((b, b.files()?.recognize(bytes)?)))
        .collect();
    let structural: Vec<_> = claims
        .iter()
        .filter(|(_, r)| r.confidence == Confidence::Structural)
        .collect();
    let pick = match (structural.as_slice(), claims.as_slice()) {
        ([one], _) => Some(**one),
        ([], []) => None,
        ([], [one]) => Some(*one),
        _ => {
            let names: Vec<_> = claims
                .iter()
                .map(|(b, r)| format!("{} ({})", r.format.label, b.descriptor().id))
                .collect();
            bail!("ambiguous file: it matches {}", names.join(" and "))
        }
    };
    Ok(pick)
}

/// The shared Flash/Recovery format policy for `backend`'s drive.
/// A recognized file is its recognized format whichever drive is attached (the
/// engine then refuses a foreign one). Otherwise a file named for another
/// backend's format is that format, else the drive's backend names it.
pub fn update_input_format(
    backend: &dyn Backend,
    path: &Path,
    bytes: &[u8],
) -> Result<Option<&'static FileFormat>> {
    if let Some((_, recognized)) = recognize(bytes)? {
        recognized.format.ensure_update_input()?;
        return Ok(Some(recognized.format));
    }
    let id = backend.descriptor().id;
    let foreign = backends()
        .filter(|other| other.descriptor().id != id)
        .filter_map(|other| other.files())
        .find_map(|files| files.claims_by_name(path));
    let format = foreign.or_else(|| backend.files().map(|f| f.classify_input(path, bytes)));
    if let Some(format) = format {
        format.ensure_update_input()?;
    }
    Ok(format)
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;

/// Informational family label for unsupported or legacy formats.
/// This evidence does not select a writer or authorize any operation.
pub(crate) fn catalog_family(bytes: &[u8]) -> Option<&'static str> {
    crate::backends::catalog::family(bytes)
}

/// Print the backend-owned fallback file report.
pub(crate) fn describe_catalog_file(bytes: &[u8], require_recognized: bool) -> Result<()> {
    crate::backends::catalog::describe(bytes, require_recognized)
}

pub(crate) fn refusal_status(
    error: &(dyn std::error::Error + 'static),
) -> Option<crate::crossflash::CompatibilityStatus> {
    pioneer::routing::refusal_status(error)
}
pub(crate) fn unsupported_backup_layout(error: &anyhow::Error) -> bool {
    pioneer::routing::unsupported_backup_layout(error)
}
pub(crate) use mtk::detection::probe as probe_mediatek;
pub(crate) use pioneer::detection::probe as probe_pioneer;
