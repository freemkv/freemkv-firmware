//! MediaTek package operations exposed through the file facet.
use anyhow::Result;

pub(super) fn claims(input: &[u8]) -> Result<bool> {
    if input.get(257..262) != Some(b"ustar") {
        return Ok(false);
    }
    let mut archive = tar::Archive::new(input);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == std::path::Path::new("manifest.json") {
            use std::io::Read;
            let mut data = Vec::new();
            entry.by_ref().take(1024 * 1024).read_to_end(&mut data)?;
            let manifest: serde_json::Value = serde_json::from_slice(&data)?;
            return Ok(manifest["format"] == super::package::FORMAT);
        }
    }
    Ok(false)
}

pub(super) fn recovery_target(input: &[u8], member: Option<&str>) -> Result<Vec<u8>> {
    let package = super::package::Package::parse(input)?;
    let components = &package.manifest.components;
    let selected = match member {
        Some(path) => components
            .iter()
            .position(|c| c.path == path)
            .ok_or_else(|| {
                anyhow::anyhow!("unknown recovery member {path}")
                    .context(crate::user_error::IssueCode::CommandOptions)
            })?,
        None if components.len() == 1 => 0,
        None => {
            return Err(anyhow::anyhow!(
                "choose exactly one recovery member with --member: {}",
                components
                    .iter()
                    .map(|c| c.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .context(crate::user_error::IssueCode::CommandOptions))
        }
    };
    Ok(
        if components[selected].role == super::package::Role::Intermediate {
            package.intermediate().expect("validated intermediate")
        } else {
            package.firmware()
        }
        .to_vec(),
    )
}

/// Optionally wrap a standalone final image or saved BIN backup as a TAR.
/// No intermediate relationship is invented by this conversion.
pub(super) fn wrap_image(image: Vec<u8>) -> Result<Vec<u8>> {
    use super::package::{digest, Component, Manifest, Package, Role, FORMAT};
    use std::collections::BTreeMap;
    crate::crossflash::admits(crate::crossflash::Platform::Mediatek, &image, &image)?;
    let manifest = Manifest {
        format: FORMAT.into(),
        version: 1,
        components: vec![Component {
            path: "firmware.bin".into(),
            sha256: digest(&image),
            role: Role::Firmware,
        }],
        pairing: None,
        metadata: BTreeMap::new(),
    };
    Package::from_parts(manifest, BTreeMap::from([("firmware.bin".into(), image)]))?.encode()
}
