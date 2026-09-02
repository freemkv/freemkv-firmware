//! Flash mode enum.
//!
//! Defines [`FlashMode`], the streaming mode shared by the CLI, the engine,
//! and the per-family [`crate::drive::DriveFamily`] trait.

use serde::{Deserialize, Serialize};

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
