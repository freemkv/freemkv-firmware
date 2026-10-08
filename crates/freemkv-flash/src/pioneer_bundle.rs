//! Strict, read-only intake for Pioneer envelope packages. Distributed
//! installer tars hold only firmware envelopes; internal extractor bundles
//! may additionally carry a manifest. Neither format authorizes a write.

use std::collections::HashSet;
use std::io::Read;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::drive::pioneer::parse_banner;

const MAX_COMPONENT: u64 = 8 << 20;

/// Firmware component role, derived from the envelope header's `File Type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Main/Normal envelope.
    Main,
    /// Separate Kernel envelope.
    Kernel,
    /// Format not established.
    Unknown,
}

/// One validated bundle member with its source metadata.
#[derive(Debug)]
pub struct Component {
    /// Safe tar member path.
    pub path: String,
    /// Extractor-assigned role.
    pub role: Role,
    /// Verified raw envelope bytes.
    pub bytes: Vec<u8>,
    /// Header-derived model if available.
    pub model: Option<String>,
    /// Header-derived revision if available.
    pub revision: Option<String>,
    /// Header-derived hardware if available.
    pub hardware: Option<String>,
    /// Extractor candidate classification, retained as evidence only.
    pub candidate: String,
}

/// Validated package. Source fields are populated only for internal extractor
/// bundles; distributed installer tars intentionally contain no provenance.
#[derive(Debug)]
pub struct Bundle {
    /// Original extractor input name.
    pub source_name: String,
    /// Manifest-reported hash of the original input (unverified here).
    pub source_sha256: String,
    /// Manifest-reported original input size (unverified here).
    pub source_size: u64,
    /// Every component, with its hash checked against actual tar bytes.
    pub components: Vec<Component>,
    /// Download package or explicitly assembled installer package.
    pub is_installer: bool,
    /// User-facing model named by an installer package, if present.
    pub public_model: Option<String>,
    /// Model printed in the actual Kernel and Normal envelope banners.
    pub embedded_model: Option<String>,
}

impl Bundle {
    /// Read a distributable Pioneer package made solely of envelope files.
    /// Roles and identity come from each envelope's own banner, never names.
    fn from_envelope_tar_bytes(bytes: &[u8], allow_kernel_only: bool) -> Result<Self> {
        let mut archive = tar::Archive::new(bytes);
        let mut components = Vec::new();
        let mut seen_names = HashSet::new();
        let mut model: Option<String> = None;
        let mut hardware: Option<String> = None;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() || entry.size() > MAX_COMPONENT {
                bail!("invalid Pioneer envelope tar member");
            }
            let path = entry
                .path()?
                .to_str()
                .context("non-UTF8 tar path")?
                .to_owned();
            let member_name = path.strip_prefix("components/").unwrap_or(&path);
            if member_name.is_empty()
                || member_name.contains('/')
                || member_name.contains('\\')
                || path == "."
                || path == ".."
                || member_name == "."
                || member_name == ".."
                || !seen_names.insert(path.clone())
            {
                bail!("unsafe or duplicate Pioneer envelope name");
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            let banner = parse_banner(&data).context("Pioneer envelope banner missing")?;
            if banner.model.is_empty() || banner.hardware.is_empty() || banner.revision.is_empty() {
                bail!("Pioneer envelope identity is incomplete");
            }
            let role = match banner.file_type.as_str() {
                "Normal" => Role::Main,
                "Kernel" => Role::Kernel,
                other => bail!("unsupported Pioneer envelope File Type {other:?}"),
            };
            if model.as_deref().is_some_and(|m| m != banner.model)
                || hardware.as_deref().is_some_and(|h| h != banner.hardware)
            {
                bail!("Pioneer package envelopes disagree on model or hardware");
            }
            model.get_or_insert_with(|| banner.model.clone());
            hardware.get_or_insert_with(|| banner.hardware.clone());
            components.push(Component {
                path,
                role,
                bytes: data,
                model: Some(banner.model),
                revision: Some(banner.revision),
                hardware: Some(banner.hardware),
                candidate: String::new(),
            });
            if components.len() > 2 {
                bail!("Pioneer installer has more than two envelopes");
            }
        }
        if !matches!(components.as_slice(), [a] if a.role == Role::Main)
            && !(allow_kernel_only
                && matches!(components.as_slice(), [a] if a.role == Role::Kernel))
            && !matches!(components.as_slice(), [a, b]
                if matches!((a.role, b.role), (Role::Kernel, Role::Main) | (Role::Main, Role::Kernel)))
        {
            bail!("Pioneer installer requires one Normal and at most one Kernel");
        }
        Ok(Self {
            source_name: String::new(),
            source_sha256: String::new(),
            source_size: 0,
            components,
            is_installer: true,
            public_model: None,
            embedded_model: model,
        })
    }

    /// Parse an envelope-only tar: two `components/*.enc` members (or one
    /// Normal). We do NOT read or require any `manifest.json` sidecar — role,
    /// model, revision, hardware all come from the envelope header directly
    /// (`File Type`, `ID`, `Revision Level`, `Hardware Version`). Every tar
    /// member must be an envelope, so a `manifest.json` member is rejected.
    /// A flashable bundle always carries a Normal; a Kernel-only tar is refused.
    pub fn from_tar_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_envelope_tar_bytes(bytes, false)
    }

    /// Like [`Bundle::from_tar_bytes`] but also accepts a Kernel-only archive: the
    /// partial backup written when the Normal region could not be read. Only for
    /// backup validation/inspection — never for building a flash input.
    pub fn from_backup_tar_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_envelope_tar_bytes(bytes, true)
    }

    /// Return the sole Normal envelope only when no other component needs a
    /// Kernel or unknown strategy. No implicit multi-component selection.
    pub fn sole_normal_only(&self) -> Result<&Component> {
        match self.components.as_slice() {
            [component] if component.role == Role::Main => Ok(component),
            _ => {
                let inventory = self
                    .components
                    .iter()
                    .map(|c| {
                        format!(
                            "{:?}/{} ({})",
                            c.role,
                            crate::style::printable(
                                c.hardware.as_deref().unwrap_or("hardware unknown")
                            ),
                            crate::style::printable(&c.path)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("bundle needs explicit multi-component selection; no audited Kernel/unknown transfer strategy is registered; validated components: {inventory}")
            }
        }
    }
}

#[cfg(test)]
#[path = "pioneer_bundle_tests.rs"]
mod tests;
