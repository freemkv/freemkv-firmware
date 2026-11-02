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

static MTK: mtk::Mtk = mtk::Mtk;
static PIONEER: pioneer::Pioneer = pioneer::Pioneer::new();

pub(crate) fn offline_routes(
    platform: crate::crossflash::Platform,
    installed: &[u8],
    target: &[u8],
) -> Result<Vec<crate::crossflash::Route>> {
    match platform {
        crate::crossflash::Platform::Pioneer => pioneer::offline_routes(installed, target),
        crate::crossflash::Platform::Mediatek => {
            mtk::decide_offline(installed, target)?;
            Ok(vec![crate::crossflash::Route {
                status: crate::crossflash::RouteStatus::Allowed,
                requirements: Vec::new(),
            }])
        }
    }
}

/// Origin evidence is supplied by protocol file analysis, not the front end.
pub(crate) fn file_origin(bytes: &[u8]) -> crate::workflow::FileOrigin {
    pioneer::file_info::file_origin(bytes)
}

/// The routing facts [`crate::crossflash`] pre-filters pairs on.
pub(crate) fn offline_prefilter(
    platform: crate::crossflash::Platform,
    bytes: &[u8],
) -> crate::crossflash::Prefilter {
    use crate::crossflash::Platform;
    match platform {
        Platform::Pioneer => pioneer::offline_prefilter(bytes),
        Platform::Mediatek => mtk::offline_prefilter(bytes),
    }
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
            if m.identity().revision() == "BOOT" {
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
