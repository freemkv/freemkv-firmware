//! Firmware image manifest.
//!
//! A manifest is a TOML file listing available firmware images, each tagged
//! with the drive model it belongs to, the silicon platform (A/B), and whether
//! it is OEM-stock or a freemkv image.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Silicon platform an image targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chip {
    /// MediaTek MT1959 (platform A).
    #[serde(rename = "A")]
    A,
    /// MediaTek MT1939 (platform B).
    #[serde(rename = "B")]
    B,
}

/// Provenance of a firmware image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Vendor OEM-stock firmware.
    Oem,
    /// freemkv (patched) firmware.
    Freemkv,
}

/// How the image is streamed to the drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlashMode {
    /// Main code band only.
    Main,
    /// Full 2 MB image.
    Full,
    /// Encrypted (AES-128-ECB host transport wrapping).
    Enc,
}

/// One firmware image entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareImage {
    /// Drive model, e.g. `BU40N`.
    pub model: String,
    /// Silicon platform.
    pub chip: Chip,
    /// Firmware version string.
    pub version: String,
    /// OEM-stock vs freemkv.
    pub kind: Kind,
    /// Path to the image file (relative to the manifest or absolute).
    pub path: String,
    /// CRC32 of the image file (for integrity display).
    pub crc32: u32,
    /// Flash mode to use.
    pub flash_mode: FlashMode,
    /// Whether this image sets the downgrade-enable gate.
    #[serde(default)]
    pub downgrade_enable: bool,
}

/// A parsed manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// All images in the manifest.
    #[serde(default, rename = "image")]
    pub images: Vec<FirmwareImage>,
}

impl Manifest {
    /// Load and parse a manifest from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading manifest {}", path.display()))?;
        let manifest: Manifest = toml::from_str(&text)
            .with_context(|| format!("parsing manifest {}", path.display()))?;
        Ok(manifest)
    }

    /// Group images by `(model, kind)`, preserving encounter order.
    pub fn grouped(&self) -> Vec<((&str, Kind), Vec<&FirmwareImage>)> {
        let mut order: Vec<(&str, Kind)> = Vec::new();
        let mut groups: Vec<Vec<&FirmwareImage>> = Vec::new();
        for img in &self.images {
            let key = (img.model.as_str(), img.kind);
            match order.iter().position(|k| *k == key) {
                Some(i) => groups[i].push(img),
                None => {
                    order.push(key);
                    groups.push(vec![img]);
                }
            }
        }
        order.into_iter().zip(groups).collect()
    }
}
