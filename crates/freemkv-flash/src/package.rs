//! Package operations dispatched through registered backend file facets.
use anyhow::{Context, Result};

/// Select a recovery member according to the owning backend's package contract.
pub fn recovery_target(input: &[u8], member: Option<&str>) -> Result<Vec<u8>> {
    for backend in crate::backend::registry::backends() {
        if let Some(result) = backend
            .files()
            .and_then(|files| files.recovery_package(input, member))
        {
            return result;
        }
    }
    anyhow::ensure!(
        member.is_none(),
        anyhow::anyhow!("--member is not supported for this input")
            .context(crate::user_error::IssueCode::CommandOptions)
    );
    if input.get(257..262) != Some(b"ustar") {
        let (_, recognized) = crate::backend::registry::recognize(input)?
            .context("unrecognized update input; select a supported firmware image or package")?;
        recognized.format.ensure_update_input()?;
    }
    Ok(input.to_vec())
}

/// Selectable recovery members; non-selectable backend packages return none.
pub fn recovery_members(input: &[u8]) -> Result<Vec<String>> {
    for backend in crate::backend::registry::backends() {
        if let Some(members) = backend
            .files()
            .and_then(|files| files.recovery_members(input))
        {
            return members;
        }
    }
    Ok(Vec::new())
}

/// Wrap a standalone image using its backend's release package contract.
pub fn wrap_image(image: Vec<u8>) -> Result<Vec<u8>> {
    let (backend, _) =
        crate::backend::registry::recognize(&image)?.context("unrecognized firmware image")?;
    backend
        .files()
        .context("backend has no file support")?
        .wrap_image(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_owned_package_retains_backend_validation_error() {
        let manifest = br#"{"format":"freemkv-mediatek-package","version":99,"components":[]}"#;
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", &manifest[..])
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        assert_eq!(
            recovery_target(&bytes, None).unwrap_err().to_string(),
            "unsupported MediaTek release package"
        );
    }

    #[test]
    fn member_selection_cannot_be_applied_to_an_unowned_input() {
        let error = recovery_target(&[0; 512], Some("firmware.bin")).unwrap_err();
        assert!(error.is::<crate::user_error::IssueCode>());
        assert!(recovery_members(&[0; 512]).unwrap().is_empty());
    }
}
