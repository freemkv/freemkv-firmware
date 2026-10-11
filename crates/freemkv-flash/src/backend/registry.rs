//! The explicit backend registry: the only core module that names a backend.
//!
//! Adding a controller protocol means one entry here plus its module under
//! [`crate::backends`]. No source scan or vendor-name shortcut can make a new
//! protocol flashable.

use std::path::Path;

use anyhow::{bail, Result};

use super::{read_identity, Backend, FileFormat, Identity, Match, ReadDevice};
use crate::backends::{mtk, pioneer};
use crate::platform::ScsiDevice;

static MTK: mtk::Mtk = mtk::Mtk;
static PIONEER: pioneer::Pioneer = pioneer::Pioneer::new();

/// Probe order.
static BACKENDS: [&'static dyn Backend; 2] = [&MTK, &PIONEER];

/// File-identification order. Pioneer's structural tar parse must precede
/// MediaTek's whole-file `MTEKMT19dd` search.
static FILE_ORDER: [&'static dyn Backend; 2] = [&PIONEER, &MTK];

/// Every registered protocol backend, in probe order.
pub fn backends() -> impl Iterator<Item = &'static dyn Backend> {
    BACKENDS.iter().copied()
}

/// Backends in file-identification order (not probe order).
pub fn file_backends() -> impl Iterator<Item = &'static dyn Backend> {
    FILE_ORDER.iter().copied()
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
    let identity = read_identity(&mut ReadDevice::new(dev, &[]));
    let mut found: Option<(&'static dyn Backend, Match)> = None;
    for backend in backends() {
        let mut probe_dev = ReadDevice::new(dev, backend.allowed_data_out());
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

/// The format of a flash input bound for `backend`'s drive, if it reads files.
/// A file named for another backend's format is that format whichever drive is
/// attached (the engine then refuses it); otherwise the drive's backend
/// classifies it.
pub fn flash_input_format(
    backend: &dyn Backend,
    path: &Path,
    bytes: &[u8],
) -> Option<&'static FileFormat> {
    let id = backend.descriptor().id;
    let foreign = backends()
        .filter(|other| other.descriptor().id != id)
        .filter_map(|other| other.files())
        .find_map(|files| files.claims_by_name(path));
    foreign.or_else(|| backend.files().map(|f| f.classify_input(path, bytes)))
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
