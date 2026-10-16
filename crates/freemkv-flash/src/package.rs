//! Package member selection for recovery front ends.
use anyhow::{bail, Result};

/// Select exactly one MediaTek member; other backend packages remain intact.
pub fn recovery_target(input: &[u8], member: Option<&str>) -> Result<Vec<u8>> {
    // Recognize the manifest discriminator, without accepting malformed MTK
    // packages as another backend's input.
    let mut archive = tar::Archive::new(input);
    let mut mediatek = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == std::path::Path::new("manifest.json") {
            use std::io::Read;
            let mut data = Vec::new();
            entry.by_ref().take(1024 * 1024).read_to_end(&mut data)?;
            let manifest: serde_json::Value = serde_json::from_slice(&data)?;
            mediatek = manifest["format"] == crate::mediatek_package::FORMAT;
        }
    }
    if mediatek {
        let package = crate::mediatek_package::Package::parse(input)?;
        let components = &package.manifest.components;
        let selected = match member {
            Some(path) => components
                .iter()
                .position(|c| c.path == path)
                .ok_or_else(|| anyhow::anyhow!("unknown recovery member {path}"))?,
            None if components.len() == 1 => 0,
            None => bail!(
                "choose exactly one recovery member with --member: {}",
                components
                    .iter()
                    .map(|c| c.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        return Ok(
            if components[selected].role == crate::mediatek_package::Role::Intermediate {
                package.intermediate().expect("validated intermediate")
            } else {
                package.firmware()
            }
            .to_vec(),
        );
    }
    if member.is_some() {
        bail!("--member is only supported for MediaTek release packages");
    }
    Ok(input.to_vec())
}

/// Selectable recovery members; non-selectable backend packages return none.
pub fn recovery_members(input: &[u8]) -> Result<Vec<String>> {
    if let Ok(package) = crate::mediatek_package::Package::parse(input) {
        return Ok(package
            .manifest
            .components
            .into_iter()
            .map(|c| c.path)
            .collect());
    }
    Ok(Vec::new())
}

/// Optionally wrap a standalone final image or saved BIN backup as a TAR.
/// No intermediate relationship is invented by this conversion.
pub fn wrap_image(image: Vec<u8>) -> Result<Vec<u8>> {
    use crate::mediatek_package::{digest, Component, Manifest, Package, Role, FORMAT};
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
