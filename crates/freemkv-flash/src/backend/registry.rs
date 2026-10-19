//! The explicit backend registry: the only core module that names a backend.
//!
//! Adding a controller protocol means one entry here plus its module under
//! [`crate::backends`]. No source scan or vendor-name shortcut can make a new
//! protocol flashable.

use std::path::Path;

use anyhow::{bail, Result};

use super::{
    read_identity, Backend, Confidence, FileFormat, Identity, Match, ReadDevice, Recognized,
};
use crate::backends::{mtk, pioneer};
use crate::platform::ScsiDevice;

static MTK: mtk::Mtk = mtk::Mtk;
static PIONEER: pioneer::Pioneer = pioneer::Pioneer::new();

/// Origin evidence is supplied by protocol file analysis, not the front end.
pub(crate) fn file_origin(bytes: &[u8]) -> crate::workflow::FileOrigin {
    pioneer::file_info::file_origin(bytes)
}

/// The whole `flash` decision with no device (see [`crate::crossflash`]).
pub(crate) fn decide_offline(
    platform: crate::crossflash::Platform,
    installed: &[u8],
    target: &[u8],
) -> Result<()> {
    use crate::crossflash::Platform;
    match platform {
        Platform::Pioneer => pioneer::decide_offline(installed, target),
        Platform::Mediatek => mtk::decide_offline(installed, target),
    }
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

/// Run every registered, read-only protocol probe. Ambiguous matches fail
/// closed rather than allowing registry order to select a writer.
pub fn resolve(dev: &mut dyn ScsiDevice) -> Result<Option<Resolved>> {
    let identity = read_identity(&mut ReadDevice::without_unlocks(dev));
    let mut found: Option<(&'static dyn Backend, Match)> = None;
    for backend in backends() {
        let mut probe_dev = ReadDevice::for_backend(dev, backend);
        if let Some(matched) = backend.probe(&mut probe_dev, &identity)? {
            if matched.backend != backend.descriptor().id {
                bail!("backend probe returned an inconsistent backend id");
            }
            if let Some((_, prior)) = &found {
                bail!(
                    "ambiguous firmware protocol: {} ({}) and {} ({}) both matched",
                    prior.backend,
                    prior.evidence,
                    matched.backend,
                    matched.evidence
                );
            }
            found = Some((backend, matched));
        }
    }
    Ok(found.map(|(backend, matched)| Resolved {
        identity,
        backend,
        matched,
    }))
}

/// The one recognizer: which backend's format `bytes` are. A structural claim
/// beats heuristic ones; two structural claims, or two heuristic claims with
/// no structural one, are an ambiguous file.
pub fn recognize(bytes: &[u8]) -> Result<Option<(&'static dyn Backend, Recognized)>> {
    recognize_among(backends(), bytes)
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

/// The format of a flash input bound for `backend`'s drive, if it reads files.
/// A recognized file is its recognized format whichever drive is attached (the
/// engine then refuses a foreign one). Otherwise a file named for another
/// backend's format is that format, else the drive's backend names it.
pub fn flash_input_format(
    backend: &dyn Backend,
    path: &Path,
    bytes: &[u8],
) -> Result<Option<&'static FileFormat>> {
    if let Some((_, recognized)) = recognize(bytes)? {
        return Ok(Some(recognized.format));
    }
    let id = backend.descriptor().id;
    let foreign = backends()
        .filter(|other| other.descriptor().id != id)
        .filter_map(|other| other.files())
        .find_map(|files| files.claims_by_name(path));
    Ok(foreign.or_else(|| backend.files().map(|f| f.classify_input(path, bytes))))
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
