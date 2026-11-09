//! Hardware-confirmed UHD results.
//!
//! The Modify tool advertises `unrestricted` (the UHD unlock) as a working
//! feature only for a modified image whose output has been confirmed to read
//! UHD media on a real drive. Applying the byte patch and passing the
//! structural audit is NOT proof that a drive gains UHD: the media conversion
//! rewrites recognition and geometry, but the physical read path (optical
//! parameters, controller completion, high-layer calibration) and AACS 2.0
//! authentication are not established by a static build. See the "MediaTek UHD"
//! initiative.
//!
//! Each entry is the SHA-256 of a *modified* image (this tool's output, the
//! `output_sha256` of a capabilities record) that a human confirmed reads UHD
//! on hardware. The commit that adds an entry records the exact drive, its
//! firmware revision and the disc used. An empty list means nothing has been
//! confirmed yet, so the tool reports UHD as "applies-unproven" everywhere.
pub const HARDWARE_CONFIRMED_UHD: &[&str] = &[];

/// How sure we are that an image's UHD unlock actually works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UhdQualification {
    /// The image cannot apply the UHD unlock at all.
    Unavailable,
    /// The unlock patch applies and audits, but no drive has been confirmed.
    AppliesUnproven,
    /// A real drive was confirmed to read UHD with this exact output.
    HardwareConfirmed,
}

impl UhdQualification {
    /// Stable report spelling.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::AppliesUnproven => "applies-unproven",
            Self::HardwareConfirmed => "hardware-confirmed",
        }
    }
}

/// Whether a drive has been confirmed to read UHD with this exact modified output.
pub fn uhd_confirmed(output_sha256: &str) -> bool {
    HARDWARE_CONFIRMED_UHD.contains(&output_sha256)
}

/// Qualification for a modified output: hardware-confirmed when its hash is on
/// the list, otherwise applies-unproven. The report downgrades this to
/// `Unavailable` when the image cannot apply the unlock at all.
pub fn uhd_for(output_sha256: &str) -> UhdQualification {
    if uhd_confirmed(output_sha256) {
        UhdQualification::HardwareConfirmed
    } else {
        UhdQualification::AppliesUnproven
    }
}

/// [`uhd_for`] keyed by the output image's bytes.
pub fn uhd_for_image(output: &[u8]) -> UhdQualification {
    use sha2::{Digest, Sha256};
    let sha = Sha256::digest(output)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    uhd_for(&sha)
}
