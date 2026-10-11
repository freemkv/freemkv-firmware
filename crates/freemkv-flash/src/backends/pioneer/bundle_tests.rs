use super::*;

fn image() -> Vec<u8> {
    let mut image = vec![0u8; 0x1d7000];
    let head = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   BDR-UD04.\r\nRevision Level : 1.11 .\r\nHardware Version : SAT 8A10.\r\nDestination : GENERAL.\r\nFile Type : Normal.\r\n";
    image[..head.len()].copy_from_slice(head);
    image
}

fn tar_member<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, data).unwrap();
}

/// Build an envelope-only tar (`components/kernel.enc` + `components/normal.enc`),
/// deriving the Kernel from the Normal fixture by flipping its `File Type`.
fn envelope_only_tar(duplicate_normal: bool) -> Vec<u8> {
    let normal = image();
    let mut kernel = image();
    let marker = b"File Type : Normal.";
    let pos = kernel
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap();
    kernel[pos..pos + marker.len()].copy_from_slice(b"File Type : Kernel.");
    let mut out = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut out);
        tar_member(
            &mut tar,
            "components/kernel.enc",
            if duplicate_normal { &normal } else { &kernel },
        );
        tar_member(&mut tar, "components/normal.enc", &normal);
        tar.finish().unwrap();
    }
    out
}

#[test]
fn selection_error_inventory_sanitizes_member_names() {
    let normal = image();
    let mut kernel = image();
    let marker = b"File Type : Normal.";
    let pos = kernel
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap();
    kernel[pos..pos + marker.len()].copy_from_slice(b"File Type : Kernel.");
    let mut out = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut out);
        tar_member(&mut tar, "components/k\u{1b}[31m.enc", &kernel);
        tar_member(&mut tar, "components/normal.enc", &normal);
        tar.finish().unwrap();
    }
    let bundle = Bundle::from_tar_bytes(&out).unwrap();
    let err = format!("{:#}", bundle.sole_normal_only().unwrap_err());
    assert!(!err.contains('\x1b'), "{err:?}");
}

#[test]
fn envelope_only_tar_uses_headers_for_role_not_member_names() {
    let bundle = Bundle::from_tar_bytes(&envelope_only_tar(false)).unwrap();
    assert!(bundle.is_installer);
    assert_eq!(bundle.components.len(), 2);
    assert_eq!(bundle.components[0].role, Role::Kernel);
    assert_eq!(bundle.components[1].role, Role::Main);
    assert_eq!(bundle.embedded_model.as_deref(), Some("BDR-UD04"));
    // Two Normals (no Kernel) is a bundle-shape error.
    assert!(Bundle::from_tar_bytes(&envelope_only_tar(true)).is_err());
}

#[test]
fn sole_normal_bundle_selectable() {
    let normal = image();
    let mut out = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut out);
        tar_member(&mut tar, "components/normal.enc", &normal);
        tar.finish().unwrap();
    }
    let bundle = Bundle::from_tar_bytes(&out).unwrap();
    assert_eq!(bundle.sole_normal_only().unwrap().bytes, image());
}

#[test]
fn tar_with_non_envelope_sidecar_is_rejected() {
    // A tar containing anything other than Pioneer envelopes (e.g. a stale
    // manifest.json) fails: the flasher derives everything from the
    // envelope header and does not accept sidecar metadata of any kind.
    let normal = image();
    let mut out = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut out);
        tar_member(&mut tar, "manifest.json", b"{}");
        tar_member(&mut tar, "components/normal.enc", &normal);
        tar.finish().unwrap();
    }
    assert!(Bundle::from_tar_bytes(&out).is_err());
}

#[test]
fn envelope_without_banner_is_rejected() {
    let mut out = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut out);
        tar_member(&mut tar, "components/normal.enc", &vec![0u8; 0x1000]);
        tar.finish().unwrap();
    }
    assert!(Bundle::from_tar_bytes(&out).is_err());
}
