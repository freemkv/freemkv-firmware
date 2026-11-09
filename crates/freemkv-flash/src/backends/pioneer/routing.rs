//! Pioneer-specific offline catalogue provenance and refusal classification.
use crate::crossflash::{CompatibilityStatus, Route, RouteRequirement, RouteStatus};

/// Attach catalogue provenance from a codec-validated source OEM descriptor.
/// This does not authorize an update or remove any original-hardware guard.
pub(crate) fn bind_native_product(
    routes: &mut [Route],
    native: Option<pioneer_optical::production::ProductCode<'_>>,
) {
    for route in routes {
        route.native_supported = route.status != RouteStatus::Future
            && route
                .requirements
                .iter()
                .all(|requirement| match requirement {
                    RouteRequirement::OriginalHardware {
                        platform,
                        prefix,
                        suffix,
                    } => native.is_some_and(|product| {
                        pioneer_optical::settings::routing::ProductSelector {
                            platform,
                            prefix: prefix.as_deref(),
                            suffix: suffix.as_deref(),
                        }
                        .matches(product)
                    }),
                });
    }
}

pub(crate) fn refusal_status(
    error: &(dyn std::error::Error + 'static),
) -> Option<CompatibilityStatus> {
    if matches!(
        error.downcast_ref::<pioneer_optical::startup::bank::Error>(),
        Some(pioneer_optical::startup::bank::Error::ConversionRequired { .. })
    ) {
        return Some(CompatibilityStatus::SoftNo);
    }
    if matches!(
        error.downcast_ref::<pioneer_optical::image::KernelHandoffError>(),
        Some(pioneer_optical::image::KernelHandoffError::Mismatch { .. })
    ) {
        return Some(CompatibilityStatus::SoftNo);
    }
    if matches!(
        error.downcast_ref::<pioneer_optical::settings::adaptation::Error>(),
        Some(pioneer_optical::settings::adaptation::Error::OriginalRequired)
    ) {
        return Some(CompatibilityStatus::Conditional);
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
