//! MediaTek release packages shared by Flash and Modify.
//! Source collections are not release packages and are deliberately rejected.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read};

/// On-disk package discriminator.
pub const FORMAT: &str = "freemkv-mediatek-package";
/// A firmware member's role in an explicitly packaged update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Intermediate firmware, never modified by Modify.
    Intermediate,
    /// The final firmware to install or modify.
    Firmware,
}
/// One hash-bound member of a release package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Component {
    /// Relative archive member path.
    pub path: String,
    /// SHA-256 of its unencrypted bytes.
    pub sha256: String,
    /// Explicit role, checked against the embedded revision.
    pub role: Role,
}
/// Release metadata; extra provenance is preserved by modification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Must equal [`FORMAT`].
    pub format: String,
    /// Supported schema version is one.
    pub version: u32,
    /// Ordered intermediate (if present) then final firmware.
    pub components: Vec<Component>,
    /// Source-derived relationship evidence, required for paired updates.
    pub pairing: Option<serde_json::Value>,
    /// Other metadata retained verbatim at the JSON value level.
    #[serde(flatten)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}
/// Validated archive contents.
#[derive(Clone, Debug)]
pub struct Package {
    /// Metadata bound to the firmware members.
    pub manifest: Manifest,
    members: BTreeMap<String, Vec<u8>>,
}
/// SHA-256 in lower-case hexadecimal.
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
impl Package {
    /// Assemble explicitly described members, validating the serialized contract.
    pub fn from_parts(manifest: Manifest, members: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let package = Self { manifest, members };
        Self::parse(&package.encode()?)
    }

    /// Parse a bounded TAR, rejecting duplicate, undeclared or unsafe members.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "MediaTek package is too large"
        );
        let mut archive = tar::Archive::new(bytes);
        let mut members = BTreeMap::new();
        for entry in archive.entries().context("reading MediaTek TAR")? {
            let mut entry = entry?;
            ensure!(
                entry.header().entry_type().is_file(),
                "package contains a non-file member"
            );
            let path = entry.path()?.to_string_lossy().into_owned();
            ensure!(
                !path.is_empty()
                    && !path.contains('\\')
                    && path
                        .split('/')
                        .all(|p| !p.is_empty() && p != "." && p != ".." && !p.contains(':')),
                "unsafe package member path"
            );
            ensure!(members.len() < 3, "unexpected package members");
            ensure!(entry.size() <= 2 * 1024 * 1024, "package member too large");
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            ensure!(
                members.insert(path, data).is_none(),
                "duplicate package member"
            );
        }
        let manifest: Manifest = serde_json::from_slice(
            members
                .remove("manifest.json")
                .context("package lacks manifest.json")?
                .as_slice(),
        )?;
        ensure!(
            manifest.format == FORMAT && manifest.version == 1,
            "unsupported MediaTek release package"
        );
        ensure!(
            matches!(manifest.components.len(), 1 | 2),
            "package needs one final image and at most one intermediate"
        );
        ensure!(
            members.len() == manifest.components.len(),
            "undeclared or missing package member"
        );
        if manifest.components.len() == 2 {
            ensure!(
                manifest.components[0].role == Role::Intermediate,
                "first stage must be intermediate"
            );
            let evidence = manifest
                .pairing
                .as_ref()
                .context("paired package lacks extraction-derived pairing evidence")?;
            ensure!(
                matches!(
                    evidence["basis"].as_str(),
                    Some(
                        "vpd-declared-target-and-stage-layout"
                            | "lg-rcdata-103-final-105-intermediate"
                    )
                ),
                "unsupported pairing evidence"
            );
            let hash = |v: &serde_json::Value| {
                v.as_str().is_some_and(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            };
            ensure!(
                hash(&evidence["source"]["sha256"])
                    && hash(&evidence["container_sha256"])
                    && hash(&evidence["final_sha256"]),
                "incomplete source pairing evidence"
            );
            ensure!(
                evidence["intermediate_sha256"].as_str()
                    == Some(manifest.components[0].sha256.as_str()),
                "pairing evidence names a different intermediate"
            );
            if manifest.metadata.get("modified") != Some(&serde_json::Value::Bool(true)) {
                ensure!(
                    evidence["final_sha256"].as_str()
                        == Some(manifest.components[1].sha256.as_str()),
                    "pairing evidence names a different final firmware"
                );
            }
        }
        ensure!(
            manifest.components.last().unwrap().role == Role::Firmware,
            "package lacks final firmware"
        );
        let mut paths = std::collections::BTreeSet::new();
        for component in &manifest.components {
            ensure!(
                paths.insert(&component.path),
                "duplicate component declaration"
            );
            let data = members
                .get(&component.path)
                .context("missing declared firmware")?;
            ensure!(data.len() == 0x200000, "firmware must be 2 MiB");
            ensure!(digest(data) == component.sha256, "firmware hash mismatch");
            let is_intm = &data[0x1ec018..0x1ec01c] == b"INTM";
            ensure!(
                is_intm == (component.role == Role::Intermediate),
                "component role disagrees with embedded revision"
            );
        }
        Ok(Self { manifest, members })
    }
    /// Final image, which Modify is allowed to change.
    pub fn firmware(&self) -> &[u8] {
        &self.members[&self.manifest.components.last().unwrap().path]
    }
    /// Intermediate image, if this is a paired release.
    pub fn intermediate(&self) -> Option<&[u8]> {
        (self.manifest.components.len() == 2)
            .then(|| self.members[&self.manifest.components[0].path].as_slice())
    }
    /// Replace only the final image, update its hash, and serialize the TAR.
    pub fn replace_firmware(mut self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        ensure!(
            bytes.len() == 0x200000 && &bytes[0x1ec018..0x1ec01c] != b"INTM",
            "replacement must be final firmware"
        );
        self.manifest
            .metadata
            .insert("modified".into(), serde_json::Value::Bool(true));
        let final_member = self.manifest.components.last_mut().unwrap();
        final_member.sha256 = digest(&bytes);
        self.members.insert(final_member.path.clone(), bytes);
        self.encode()
    }
    /// Serialize with deterministic TAR headers.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            let mut members = self.members.clone();
            members.insert(
                "manifest.json".into(),
                serde_json::to_vec_pretty(&self.manifest)?,
            );
            for (path, data) in members {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                tar.append_data(&mut header, path, data.as_slice())?;
            }
            tar.finish()?;
        }
        // Round-trip the complete contract before returning an output file.
        Self::parse(&out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn package() -> Package {
        let mut intm = vec![1; 0x200000];
        intm[0x1ec018..0x1ec01c].copy_from_slice(b"INTM");
        let mut final_image = vec![2; 0x200000];
        final_image[0x1ec018..0x1ec01c].copy_from_slice(b"1.V9");
        let members =
            BTreeMap::from([("intm.bin".into(), intm), ("final.bin".into(), final_image)]);
        let components: Vec<Component> = [
            ("intm.bin", Role::Intermediate),
            ("final.bin", Role::Firmware),
        ]
        .into_iter()
        .map(|(p, role)| Component {
            path: p.into(),
            sha256: digest(&members[p]),
            role,
        })
        .collect();
        let pairing = serde_json::json!({"basis":"vpd-declared-target-and-stage-layout",
            "source":{"sha256":"a".repeat(64)}, "container_sha256":"b".repeat(64),
            "intermediate_sha256":components[0].sha256,"final_sha256":components[1].sha256});
        Package::from_parts(
            Manifest {
                format: FORMAT.into(),
                version: 1,
                components,
                pairing: Some(pairing),
                metadata: BTreeMap::new(),
            },
            members,
        )
        .unwrap()
    }
    #[test]
    fn replacement_preserves_intermediate_and_pairing() {
        let original = package();
        let before = original.encode().unwrap();
        let parsed = Package::parse(&before).unwrap();
        let mut modified = parsed.firmware().to_vec();
        modified[0x12345] ^= 1;
        let out = parsed.replace_firmware(modified.clone()).unwrap();
        let after = Package::parse(&out).unwrap();
        assert_eq!(after.firmware(), modified);
        assert_eq!(after.intermediate(), original.intermediate());
        assert_eq!(after.manifest.pairing, original.manifest.pairing);
        assert_ne!(
            after.manifest.components[1].sha256,
            original.manifest.components[1].sha256
        );
    }
    #[test]
    fn recovery_requires_selection_and_returns_only_that_member() {
        let p = package();
        let bytes = p.encode().unwrap();
        let select = crate::workflow::recovery_target;
        let error = select(&bytes, None).unwrap_err();
        assert!(format!("{error:#}").contains("--member"));
        assert_eq!(
            crate::workflow::user_error(&error).id,
            "errors.command_options"
        );
        assert_eq!(
            select(&bytes, Some("intm.bin")).unwrap(),
            p.intermediate().unwrap()
        );
        assert_eq!(select(&bytes, Some("final.bin")).unwrap(), p.firmware());
        assert!(select(&bytes, Some("missing.bin")).is_err());
    }

    #[test]
    fn hash_role_and_missing_pair_evidence_are_rejected() {
        let mut p = package();
        p.manifest.pairing = None;
        assert!(p.encode().is_err());
        let mut p = package();
        p.manifest.components[1].sha256 = "0".repeat(64);
        assert!(p.encode().is_err());
        let mut p = package();
        p.manifest.components.swap(0, 1);
        assert!(p.encode().is_err());
        assert!(Package::parse(&vec![0; 0x200000]).is_err());
    }
}
