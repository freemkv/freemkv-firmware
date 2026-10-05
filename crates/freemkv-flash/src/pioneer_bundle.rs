//! Strict, read-only intake for Pioneer envelope packages. Distributed
//! installer tars hold only firmware envelopes; internal extractor bundles
//! may additionally carry a manifest. Neither format authorizes a write.

use std::collections::HashSet;
use std::io::Read;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::drive::pioneer::parse_banner;
use crate::drive::pioneer::{BoundedOemProfile, BOUNDED_PROFILES};

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
    fn from_envelope_tar_bytes(bytes: &[u8]) -> Result<Self> {
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
    /// (`File Type`, `ID`, `Revision Level`, `Hardware Version`). Any
    /// `manifest.json` present in the tar is ignored.
    pub fn from_tar_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_envelope_tar_bytes(bytes)
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
                            c.hardware.as_deref().unwrap_or("hardware unknown"),
                            c.path
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("bundle needs explicit multi-component selection; no audited Kernel/unknown transfer strategy is registered; validated components: {inventory}")
            }
        }
    }

    /// Bind a two-component bundle to one exact-resource bounded-flow host
    /// profile. Source provenance is reported but cannot be reverified from
    /// this archive; both component bytes must match the pinned PE resources.
    /// Packages with two matching updater executables remain ambiguous.
    pub fn select_bounded_profile(
        &self,
    ) -> Result<(&'static BoundedOemProfile, &Component, &Component)> {
        if !self.source_sha256.is_empty()
            && BOUNDED_PROFILES.iter().any(|profile| {
                profile.source_sha256 == self.source_sha256
                    && profile.source_name == self.source_name
                    && !profile.unique_executable
            })
        {
            bail!("package has multiple matching updater executables; explicit variant selection is required");
        }
        let [first, second] = self.components.as_slice() else {
            bail!("bounded OEM profile requires exactly one Kernel and one Normal component");
        };
        let (kernel, normal) = match (first.role, second.role) {
            (Role::Kernel, Role::Main) => (first, second),
            (Role::Main, Role::Kernel) => (second, first),
            _ => bail!("bounded OEM profile requires one Kernel and one Normal component"),
        };
        let kernel_banner = parse_banner(&kernel.bytes).context("Kernel banner missing")?;
        let normal_banner = parse_banner(&normal.bytes).context("Normal banner missing")?;
        if kernel_banner.model != normal_banner.model
            || kernel_banner.hardware != normal_banner.hardware
        {
            bail!("Kernel and Normal banner model/hardware disagree");
        }
        let kernel_hash = format!("{:x}", Sha256::digest(&kernel.bytes));
        let normal_hash = format!("{:x}", Sha256::digest(&normal.bytes));
        let matches = BOUNDED_PROFILES
            .iter()
            .filter(|profile| {
                (self.source_sha256.is_empty()
                    || (profile.source_sha256 == self.source_sha256
                        && profile.source_name == self.source_name))
                    && profile.kernel_len == kernel.bytes.len()
                    && profile.kernel_sha256 == kernel_hash
                    && profile.normal_len == normal.bytes.len()
                    && profile.normal_sha256 == normal_hash
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [profile] if profile.unique_executable => Ok((profile, kernel, normal)),
            [] => bail!("no pinned bounded OEM profile matches both resource hashes"),
            _ => bail!("ambiguous pinned bounded OEM profiles"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Vec<u8> {
        let mut image = vec![0u8; 0x1d7000];
        let head = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11 .\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
        image[..head.len()].copy_from_slice(head);
        image
    }

    fn tar_member<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &str, data: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }

    /// Build an envelope-only tar (`components/kernel.enc` + `components/normal.enc`),
    /// deriving the Kernel from the Normal fixture by flipping its `File Type`.
    fn envelope_only_tar(duplicate_normal: bool) -> Vec<u8> {
        let normal = image();
        let mut kernel = image();
        let marker = b"File Type : Normal.";
        let pos = kernel.windows(marker.len()).position(|w| w == marker).unwrap();
        kernel[pos..pos + marker.len()].copy_from_slice(b"File Type : Kernel.");
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(&mut tar, "components/kernel.enc", if duplicate_normal { &normal } else { &kernel });
            tar_member(&mut tar, "components/normal.enc", &normal);
            tar.finish().unwrap();
        }
        out
    }

    #[test]
    fn envelope_only_tar_uses_headers_for_role_not_member_names() {
        let bundle = Bundle::from_tar_bytes(&envelope_only_tar(false)).unwrap();
        assert!(bundle.is_installer);
        assert_eq!(bundle.components.len(), 2);
        assert_eq!(bundle.components[0].role, Role::Kernel);
        assert_eq!(bundle.components[1].role, Role::Main);
        assert_eq!(bundle.embedded_model.as_deref(), Some("BDR-UD04"));
        // Two Normals (no Kernel) is a bundle-shape error.
        assert!(Bundle::from_tar_bytes(&envelope_only_tar(true)).is_err());
    }

    #[test]
    fn sole_normal_bundle_selectable() {
        let normal = image();
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(&mut tar, "components/normal.enc", &normal);
            tar.finish().unwrap();
        }
        let bundle = Bundle::from_tar_bytes(&out).unwrap();
        assert_eq!(bundle.sole_normal_only().unwrap().bytes, image());
    }

    #[test]
    fn tar_with_non_envelope_sidecar_is_rejected() {
        // A tar containing anything other than Pioneer envelopes (e.g. a stale
        // manifest.json) fails: the flasher derives everything from the
        // envelope header and does not accept sidecar metadata of any kind.
        let normal = image();
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(&mut tar, "manifest.json", b"{}");
            tar_member(&mut tar, "components/normal.enc", &normal);
            tar.finish().unwrap();
        }
        assert!(Bundle::from_tar_bytes(&out).is_err());
    }

    #[test]
    fn envelope_without_banner_is_rejected() {
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(&mut tar, "components/normal.enc", &vec![0u8; 0x1000]);
            tar.finish().unwrap();
        }
        assert!(Bundle::from_tar_bytes(&out).is_err());
    }
}
