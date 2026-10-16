//! Preserve the input container while modifying only its final firmware.
use anyhow::Result;
use freemkv_flash::mediatek_package::Package;

/// A standalone image or a validated MediaTek release TAR.
pub struct Artifact {
    image: Vec<u8>,
    package: Option<Package>,
}
impl Artifact {
    /// Identify a TAR by its header, and validate its manifest before editing.
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        if bytes.get(257..262) == Some(b"ustar") {
            let package = Package::parse(&bytes)?;
            Ok(Self {
                image: package.firmware().to_vec(),
                package: Some(package),
            })
        } else {
            Ok(Self {
                image: bytes,
                package: None,
            })
        }
    }
    /// The non-INTM image to inspect or modify.
    pub fn image(&self) -> &[u8] {
        &self.image
    }
    /// Rebuild the original container, preserving intermediate bytes exactly.
    pub fn output(self, image: Vec<u8>) -> Result<Vec<u8>> {
        match self.package {
            Some(package) => package.replace_firmware(image),
            None => Ok(image),
        }
    }
}
