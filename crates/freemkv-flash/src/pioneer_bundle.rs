//! Strict, read-only intake for Pioneer envelope packages. Distributed
//! installer tars hold only firmware envelopes; internal extractor bundles
//! may additionally carry a manifest. Neither format authorizes a write.

use std::collections::{HashMap, HashSet};
use std::io::Read;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::drive::pioneer::parse_banner;
use crate::drive::pioneer::{BoundedOemProfile, BOUNDED_PROFILES};

const MAX_MANIFEST: u64 = 1 << 20;
const MAX_COMPONENT: u64 = 8 << 20;
const MAX_COMPONENTS: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    version: u32,
    source: Option<Source>,
    selection_status: Option<String>,
    selection: Option<String>,
    transfer_strategy: Option<String>,
    kernel_selection_status: Option<String>,
    kernel_selection_reason: Option<String>,
    model: Option<String>,
    public_model: Option<String>,
    embedded_model: Option<String>,
    hardware: Option<String>,
    components: Vec<ComponentRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    name: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentRecord {
    path: String,
    role: Role,
    sha256: String,
    size: u64,
    model: Option<String>,
    revision: Option<String>,
    hardware: Option<String>,
    #[serde(default)]
    candidate: Option<String>,
    #[serde(default, rename = "resource_name")]
    _resource_name: Option<String>,
    #[serde(default)]
    source: Option<Source>,
    #[serde(default)]
    source_package_name: Option<String>,
    #[serde(default)]
    source_package_sha256: Option<String>,
    #[serde(default)]
    source_package_path: Option<String>,
    #[serde(default)]
    source_member: Option<String>,
}

/// Firmware component role asserted by the extractor manifest.
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

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_component_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("components/") else {
        return false;
    };
    !name.is_empty()
        && !name.bytes().any(|b| b == b'/' || b == 92)
        && name != "."
        && name != ".."
        && !name.contains("..")
        && name.ends_with(".enc")
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

    /// Parse an envelope-only installer tar or a version-1 internal bundle.
    /// Tar links, duplicate members, and unexpected files fail.
    pub fn from_tar_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() >= 100 && &bytes[..13] != b"manifest.json" {
            return Self::from_envelope_tar_bytes(bytes);
        }
        let mut archive = tar::Archive::new(bytes);
        let mut files = HashMap::new();
        let mut first = true;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                bail!("Pioneer bundle contains a non-file tar member");
            }
            let path = entry
                .path()?
                .to_str()
                .context("non-UTF8 tar path")?
                .to_owned();
            if first && path != "manifest.json" {
                bail!("Pioneer bundle must begin with manifest.json");
            }
            first = false;
            if path != "manifest.json" && !valid_component_path(&path) {
                bail!("unsafe or unexpected Pioneer bundle member {path:?}");
            }
            if files.contains_key(&path) {
                bail!("duplicate Pioneer bundle member {path:?}");
            }
            let limit = if path == "manifest.json" {
                MAX_MANIFEST
            } else {
                MAX_COMPONENT
            };
            if entry.size() > limit || files.len() > MAX_COMPONENTS {
                bail!("Pioneer bundle member or member count exceeds limit");
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            files.insert(path, data);
        }
        let manifest_bytes = files
            .remove("manifest.json")
            .context("missing manifest.json")?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
        let is_installer = manifest.format == "pioneer-installer-package";
        let embedded_model = manifest
            .embedded_model
            .as_deref()
            .or(manifest.model.as_deref());
        if manifest.version != 1
            || !matches!(
                manifest.format.as_str(),
                "pioneer-firmware-bundle" | "pioneer-installer-package"
            )
            || manifest.components.is_empty()
            || manifest.components.len() > MAX_COMPONENTS
        {
            bail!("unsupported or incomplete Pioneer bundle manifest");
        }
        if is_installer {
            if !matches!(
                manifest.selection.as_deref(),
                Some("explicit" | "source-contained" | "carried-forward" | "normal-only")
            ) || manifest.transfer_strategy.as_deref() != Some("unverified")
                || !matches!(manifest.components.len(), 1 | 2)
                || manifest.model.as_deref().unwrap_or_default().is_empty()
                || manifest
                    .public_model
                    .as_deref()
                    .is_some_and(|model| Some(model) != manifest.model.as_deref())
                || embedded_model.unwrap_or_default().is_empty()
                || manifest.hardware.as_deref().unwrap_or_default().is_empty()
                || manifest.source.is_some()
                || manifest.selection_status.is_some()
            {
                bail!("invalid Pioneer installer manifest");
            }
        } else if manifest.selection_status.as_deref() != Some("unresolved")
            || manifest.selection.is_some()
            || manifest.transfer_strategy.is_some()
            || manifest.model.is_some()
            || manifest.public_model.is_some()
            || manifest.embedded_model.is_some()
            || manifest.hardware.is_some()
            || manifest
                .source
                .as_ref()
                .is_none_or(|source| !valid_hash(&source.sha256) || source.name.is_empty())
        {
            bail!("invalid Pioneer download manifest");
        }
        let source = manifest
            .source
            .clone()
            .or_else(|| {
                manifest
                    .components
                    .first()
                    .and_then(|rec| rec.source.clone())
            })
            .context("Pioneer package lacks source provenance")?;
        if !valid_hash(&source.sha256) || source.name.is_empty() {
            bail!("invalid Pioneer package source provenance");
        }
        let mut seen = HashSet::new();
        let mut components = Vec::with_capacity(manifest.components.len());
        for rec in manifest.components {
            if !valid_component_path(&rec.path)
                || !valid_hash(&rec.sha256)
                || rec.size > MAX_COMPONENT
                || !seen.insert(rec.path.clone())
            {
                bail!("invalid or duplicate Pioneer bundle component path/hash/size");
            }
            if is_installer
                && (!matches!(rec.role, Role::Main | Role::Kernel)
                    || rec.model.as_deref() != embedded_model
                    || rec.hardware.as_deref() != manifest.hardware.as_deref()
                    || rec
                        .source
                        .as_ref()
                        .is_none_or(|source| !valid_hash(&source.sha256) || source.name.is_empty())
                    || rec
                        .source_package_name
                        .as_deref()
                        .unwrap_or_default()
                        .is_empty()
                    || rec
                        .source_package_sha256
                        .as_deref()
                        .is_none_or(|hash| !valid_hash(hash))
                    || rec.source_package_path.as_deref().is_some_and(|path| {
                        path.starts_with('/')
                            || path.contains("..")
                            || !path.ends_with(".firmware.tar")
                    })
                    || rec
                        .source_member
                        .as_deref()
                        .is_none_or(|path| !valid_component_path(path)))
            {
                bail!("invalid Pioneer installer component provenance");
            }
            let data = files
                .remove(&rec.path)
                .with_context(|| format!("missing Pioneer bundle component {}", rec.path))?;
            if data.len() as u64 != rec.size
                || format!("{:x}", Sha256::digest(&data)) != rec.sha256.to_ascii_lowercase()
            {
                bail!(
                    "Pioneer bundle component {} fails size or SHA-256",
                    rec.path
                );
            }
            if matches!(rec.role, Role::Main | Role::Kernel) {
                let banner = parse_banner(&data)
                    .with_context(|| format!("component {} lacks Pioneer banner", rec.path))?;
                let expected_type = if rec.role == Role::Main {
                    "Normal"
                } else {
                    "Kernel"
                };
                if !banner.file_type.eq_ignore_ascii_case(expected_type)
                    || rec
                        .model
                        .as_deref()
                        .is_some_and(|x| !x.eq_ignore_ascii_case(&banner.model))
                    || rec
                        .revision
                        .as_deref()
                        .is_some_and(|x| x != banner.revision)
                    || rec
                        .hardware
                        .as_deref()
                        .is_some_and(|x| !x.eq_ignore_ascii_case(&banner.hardware))
                {
                    bail!(
                        "component {} role or metadata disagrees with its banner",
                        rec.path
                    );
                }
            }
            components.push(Component {
                path: rec.path,
                role: rec.role,
                bytes: data,
                model: rec.model,
                revision: rec.revision,
                hardware: rec.hardware,
                candidate: rec.candidate.unwrap_or_default(),
            });
        }
        if !files.is_empty() {
            bail!("Pioneer bundle has members absent from manifest");
        }
        if is_installer
            && !matches!(
                components.as_slice(),
                [a] if a.role == Role::Main
            )
            && !matches!(components.as_slice(), [a, b]
                if matches!((a.role, b.role), (Role::Kernel, Role::Main) | (Role::Main, Role::Kernel)))
        {
            bail!("Pioneer installer requires Normal with at most one Kernel");
        }
        if is_installer {
            let normal_only = components.len() == 1;
            if normal_only != (manifest.selection.as_deref() == Some("normal-only"))
                || manifest.kernel_selection_status.as_deref()
                    != Some(if normal_only {
                        "unavailable"
                    } else {
                        "available"
                    })
                || (normal_only
                    && !matches!(
                        manifest.kernel_selection_reason.as_deref(),
                        Some(
                            "no-earlier-kernel"
                                | "ambiguous-previous-kernel"
                                | "nonnumeric-revision"
                                | "ambiguous-source-kernel"
                        )
                    ))
                || (!normal_only && manifest.kernel_selection_reason.is_some())
            {
                bail!("Pioneer installer selection conflicts with component inventory");
            }
        }
        Ok(Self {
            source_name: source.name,
            source_sha256: source.sha256,
            source_size: source.size,
            components,
            is_installer,
            public_model: manifest.model,
            embedded_model: manifest.embedded_model,
        })
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
    use serde_json::json;

    fn image() -> Vec<u8> {
        let mut image = vec![0u8; 0x1d7000];
        let head = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11 .\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
        image[..head.len()].copy_from_slice(head);
        image
    }

    fn tar_member<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &str, data: &[u8]) {
        let mut header = tar::Header::new_gnu();
        // Raw header path allows this test to exercise the reader's traversal
        // defense even when tar::Header::set_path rejects it first.
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }

    fn bundle(paths: &[&str], bad_hash: bool) -> Vec<u8> {
        bundle_with_role(paths, bad_hash, "main", "Normal")
    }

    fn bundle_with_role(paths: &[&str], bad_hash: bool, role: &str, file_type: &str) -> Vec<u8> {
        let mut image = image();
        if file_type == "Kernel" {
            let needle = b"File Type : Normal.";
            let pos = image
                .windows(needle.len())
                .position(|w| w == needle)
                .unwrap();
            image[pos..pos + needle.len()].copy_from_slice(b"File Type : Kernel.");
        }
        let components: Vec<_> = paths
            .iter()
            .map(|path| {
                json!({
                    "path": path, "role": role, "sha256": if bad_hash { "0".repeat(64) } else { format!("{:x}", Sha256::digest(&image)) },
                    "size": image.len(), "model": "BDR-UD04", "revision": "1.11",
                    "hardware": "SAT 8A10", "candidate": "normal"
                })
            })
            .collect();
        let manifest = json!({
            "format":"pioneer-firmware-bundle", "version":1,
            "source":{"name":"local-updater.exe","sha256":"0".repeat(64),"size":42},
            "selection_status":"unresolved", "components":components
        });
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(
                &mut tar,
                "manifest.json",
                &serde_json::to_vec(&manifest).unwrap(),
            );
            for path in paths {
                tar_member(&mut tar, path, &image);
            }
            tar.finish().unwrap();
        }
        out
    }

    fn installer(bad_hash: bool) -> Vec<u8> {
        installer_with_public("BDR-UD04", bad_hash)
    }

    fn installer_with_public(public_model: &str, bad_hash: bool) -> Vec<u8> {
        let mut kernel = image();
        let mut normal = image();
        for (bytes, revision) in [(&mut kernel, b"1.00"), (&mut normal, b"1.14")] {
            let pos = bytes.windows(4).position(|w| w == b"1.11").unwrap();
            bytes[pos..pos + 4].copy_from_slice(revision);
        }
        let pos = kernel
            .windows(b"File Type : Normal.".len())
            .position(|w| w == b"File Type : Normal.")
            .unwrap();
        kernel[pos..pos + b"File Type : Normal.".len()].copy_from_slice(b"File Type : Kernel.");
        let source = json!({"name":"updater.zip","sha256":"a".repeat(64),"size":123});
        let records = [
            ("components/kernel.enc", "kernel", "1.00", &kernel),
            ("components/normal.enc", "main", "1.14", &normal),
        ].into_iter().map(|(path, role, revision, bytes)| json!({
            "path": path, "role": role,
            "sha256": if bad_hash && role == "main" { "0".repeat(64) } else { format!("{:x}", Sha256::digest(bytes)) },
            "size": bytes.len(), "model": "BDR-UD04", "revision": revision,
            "hardware": "SAT 8A10", "source": source,
            "source_package_name": "download.firmware.tar",
            "source_package_sha256": "b".repeat(64), "source_member": path,
        })).collect::<Vec<_>>();
        let manifest = json!({
            "format": "pioneer-installer-package", "version": 1,
            "selection": "carried-forward", "transfer_strategy": "unverified",
            "kernel_selection_status": "available",
            "model": public_model, "public_model": public_model,
            "embedded_model": "BDR-UD04", "hardware": "SAT 8A10", "components": records,
        });
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(
                &mut tar,
                "manifest.json",
                &serde_json::to_vec(&manifest).unwrap(),
            );
            tar_member(&mut tar, "components/kernel.enc", &kernel);
            tar_member(&mut tar, "components/normal.enc", &normal);
            tar.finish().unwrap();
        }
        out
    }

    fn normal_only_installer(selection: &str, status: &str) -> Vec<u8> {
        let normal = image();
        let path = "components/normal.enc";
        let source = json!({"name":"updater.exe","sha256":"a".repeat(64),"size":123});
        let manifest = json!({
            "format":"pioneer-installer-package", "version":1,
            "selection":selection, "transfer_strategy":"unverified",
            "kernel_selection_status":status,
            "kernel_selection_reason":"no-earlier-kernel",
            "model":"BDR-UD04", "public_model":"BDR-UD04",
            "embedded_model":"BDR-UD04", "hardware":"SAT 8A10",
            "components":[{
                "path":path, "role":"main", "sha256":format!("{:x}", Sha256::digest(&normal)),
                "size":normal.len(), "model":"BDR-UD04", "revision":"1.11",
                "hardware":"SAT 8A10", "source":source,
                "source_package_name":"download.firmware.tar",
                "source_package_sha256":"b".repeat(64), "source_member":path
            }]
        });
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(
                &mut tar,
                "manifest.json",
                &serde_json::to_vec(&manifest).unwrap(),
            );
            tar_member(&mut tar, path, &normal);
            tar.finish().unwrap();
        }
        out
    }

    fn envelope_only_tar(duplicate_normal: bool) -> Vec<u8> {
        let normal = image();
        let mut kernel = image();
        let marker = b"File Type : Normal.";
        let pos = kernel
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap();
        kernel[pos..pos + marker.len()].copy_from_slice(b"File Type : Kernel.");
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            tar_member(
                &mut tar,
                "S8A10000.100",
                if duplicate_normal { &normal } else { &kernel },
            );
            tar_member(&mut tar, "S8A10001.114", &normal);
            tar.finish().unwrap();
        }
        out
    }

    #[test]
    fn installer_accepts_distinct_kernel_and_normal_revisions() {
        let bundle = Bundle::from_tar_bytes(&installer(false)).unwrap();
        assert!(bundle.is_installer);
        assert_eq!(bundle.components.len(), 2);
        assert_eq!(bundle.components[0].revision.as_deref(), Some("1.00"));
        assert_eq!(bundle.components[1].revision.as_deref(), Some("1.14"));
        assert!(Bundle::from_tar_bytes(&installer(true)).is_err());
    }

    #[test]
    fn installer_keeps_public_model_separate_from_embedded_banner() {
        let bundle = Bundle::from_tar_bytes(&installer_with_public("BDR-UD03", false)).unwrap();
        assert_eq!(bundle.public_model.as_deref(), Some("BDR-UD03"));
        assert_eq!(bundle.embedded_model.as_deref(), Some("BDR-UD04"));
        assert!(bundle
            .components
            .iter()
            .all(|c| c.model.as_deref() == Some("BDR-UD04")));
    }

    #[test]
    fn normal_only_installer_is_explicit_and_inventory_checked() {
        let bundle =
            Bundle::from_tar_bytes(&normal_only_installer("normal-only", "unavailable")).unwrap();
        assert!(bundle.is_installer);
        assert_eq!(bundle.sole_normal_only().unwrap().bytes, image());
        assert!(
            Bundle::from_tar_bytes(&normal_only_installer("carried-forward", "unavailable"))
                .is_err()
        );
        assert!(
            Bundle::from_tar_bytes(&normal_only_installer("normal-only", "available")).is_err()
        );
    }

    #[test]
    fn envelope_only_tar_uses_headers_not_member_names() {
        let bundle = Bundle::from_tar_bytes(&envelope_only_tar(false)).unwrap();
        assert!(bundle.is_installer);
        assert_eq!(bundle.components.len(), 2);
        assert_eq!(bundle.components[0].role, Role::Kernel);
        assert_eq!(bundle.components[1].role, Role::Main);
        assert_eq!(bundle.embedded_model.as_deref(), Some("BDR-UD04"));
        assert!(Bundle::from_tar_bytes(&envelope_only_tar(true)).is_err());
    }

    #[test]
    fn sole_main_validates_and_is_selectable() {
        let bytes = bundle(&["components/ud04.enc"], false);
        let bundle = Bundle::from_tar_bytes(&bytes).unwrap();
        assert_eq!(bundle.sole_normal_only().unwrap().bytes, image());
    }

    #[test]
    fn tampered_component_hash_fails() {
        let bytes = bundle(&["components/ud04.enc"], true);
        assert!(Bundle::from_tar_bytes(&bytes).is_err());
    }

    #[test]
    fn two_mains_are_ambiguous_and_cannot_plan() {
        let bytes = bundle(&["components/one.enc", "components/two.enc"], false);
        let bundle = Bundle::from_tar_bytes(&bytes).unwrap();
        assert!(bundle.sole_normal_only().is_err());
    }

    #[test]
    fn path_traversal_fails() {
        let bytes = bundle(&["components/../evil.enc"], false);
        assert!(Bundle::from_tar_bytes(&bytes).is_err());
    }

    #[test]
    fn component_role_must_match_file_type_in_both_directions() {
        let normal_as_kernel =
            bundle_with_role(&["components/ud04.enc"], false, "kernel", "Normal");
        assert!(Bundle::from_tar_bytes(&normal_as_kernel).is_err());
        let kernel_as_main = bundle_with_role(&["components/ud04.enc"], false, "main", "Kernel");
        assert!(Bundle::from_tar_bytes(&kernel_as_main).is_err());
    }
}
