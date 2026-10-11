//! The explicit backend registry: the only core module that names a backend.
//!
//! Adding a controller protocol means one entry here plus its module under
//! [`crate::backends`]. No source scan or vendor-name shortcut can make a new
//! protocol flashable.

use std::path::Path;

use anyhow::{bail, Result};

use super::FileFormat;
use crate::backends::{mtk, pioneer};
use crate::drive::{read_identity, FirmwareBackend, Identity, ProbeEvidence};
use crate::platform::ScsiDevice;

static MTK: mtk::Mtk = mtk::Mtk;
static PIONEER: pioneer::Pioneer = pioneer::Pioneer::new();

/// Probe order.
static BACKENDS: [&'static dyn FirmwareBackend; 2] = [&MTK, &PIONEER];

/// File-identification order. Pioneer's structural tar parse must precede
/// MediaTek's whole-file `MTEKMT19dd` search.
static FILE_ORDER: [&'static dyn FirmwareBackend; 2] = [&PIONEER, &MTK];

/// Every registered protocol backend, in probe order.
pub fn backends() -> impl Iterator<Item = &'static dyn FirmwareBackend> {
    BACKENDS.iter().copied()
}

/// Backends in file-identification order (not probe order).
pub fn file_backends() -> impl Iterator<Item = &'static dyn FirmwareBackend> {
    FILE_ORDER.iter().copied()
}

/// A unique backend match, with device identity kept separate from the
/// controller protocol. Neither the vendor string nor the chip architecture
/// alone proves that a device accepts a backend's update commands.
pub struct Resolved {
    /// Device-reported vendor, product, revision and optional banner.
    pub identity: Identity,
    /// The matched backend.
    pub backend: &'static dyn FirmwareBackend,
    /// Protocol signature independent of the device identity.
    pub evidence: ProbeEvidence,
}

/// Run every registered, read-only protocol probe. Ambiguous matches fail
/// closed rather than allowing registry order to select a writer.
pub fn resolve(dev: &mut dyn ScsiDevice) -> Result<Option<Resolved>> {
    let identity = read_identity(dev);
    let mut found: Option<(&'static dyn FirmwareBackend, ProbeEvidence)> = None;
    for backend in backends() {
        if let Some(evidence) = backend.probe(dev, &identity)? {
            if evidence.backend != backend.descriptor().id {
                bail!("backend probe returned an inconsistent backend id");
            }
            if let Some((_, prior)) = &found {
                bail!(
                    "ambiguous firmware protocol: {} ({}) and {} ({}) both matched",
                    prior.backend,
                    prior.discriminator,
                    evidence.backend,
                    evidence.discriminator
                );
            }
            found = Some((backend, evidence));
        }
    }
    Ok(found.map(|(backend, evidence)| Resolved {
        identity,
        backend,
        evidence,
    }))
}

/// The format of a flash input bound for `backend`'s drive. A file named for
/// another backend's format is that format whichever drive is attached (the
/// engine then refuses it); otherwise the drive's backend classifies it.
pub fn flash_input_format(
    backend: &dyn FirmwareBackend,
    path: &Path,
    bytes: &[u8],
) -> &'static FileFormat {
    let id = backend.descriptor().id;
    backends()
        .filter(|other| other.descriptor().id != id)
        .find_map(|other| other.claims_by_name(path))
        .unwrap_or_else(|| backend.classify_input(path, bytes))
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
