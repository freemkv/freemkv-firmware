//! Pioneer-specific offline catalogue provenance and refusal classification.
use crate::crossflash::CompatibilityStatus;

pub(crate) fn refusal_status(
    error: &(dyn std::error::Error + 'static),
) -> Option<CompatibilityStatus> {
    if matches!(
        error.downcast_ref::<pioneer_optical::image::KernelHandoffError>(),
        Some(pioneer_optical::image::KernelHandoffError::Mismatch { .. })
    ) {
        return Some(CompatibilityStatus::SoftNo);
    }
    None
}

pub(crate) fn unsupported_backup_layout(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<pioneer_optical::envelope::NormalLayoutError>(),
        Some(pioneer_optical::envelope::NormalLayoutError::Unsupported)
    )
}

pub(crate) fn claims_platform(target: &[u8]) -> bool {
    target.get(257..262) == Some(b"ustar") || pioneer_optical::ident::parse_banner(target).is_some()
}
