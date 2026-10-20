use super::*;

const PR1AME: &[u8] = include_bytes!("../../../tests/fixtures/pioneer/pr1ame_1_05_kernel.enc");
const DVR_109: &[u8] = include_bytes!("../../../tests/fixtures/pioneer/dvr_109_1_58_kernel.enc");

fn pr1ame_identity(product: &[u8; 16], hardware: &[u8; 8], tag: &[u8; 8]) -> Identity {
    let mut inquiry = [0u8; pioneer_optical::INQUIRY_LEN];
    let mut vendor = [0u8; pioneer_optical::IDENTITY_LEN];
    inquiry[0] = 0x05;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(product);
    inquiry[32..36].copy_from_slice(b"1.05");
    vendor[16..24].copy_from_slice(hardware);
    vendor[24..32].copy_from_slice(tag);
    Identity::parse(&inquiry, &vendor).unwrap()
}

#[test]
fn pr1ame_1_05_hoard_kernel_selects_bd_without_product_name_gate() {
    // The exact 1.05 Kernel reconstructed from the user's captured PR1AME,
    // held in the firmware hoard under SAT 8000 / ID90. This is the preflight
    // that 0.13.3 refused because its INQUIRY product is "BDR-PR1AME".
    let header = pioneer_optical::envelope::header_info(PR1AME).unwrap();
    assert_eq!(header.hardware_version, "SAT 8000");
    assert_eq!(header.kernel_version, "ID90");
    assert_eq!(from_kernel(PR1AME).unwrap(), DriveClass::Bd);
    let id = pr1ame_identity(b"BDR-PR1AME      ", b"SAT 8000", b"ID90    ");
    assert_eq!(id.class(), None, "the old name gate reproduces the bug");
    check_live_identity(&id, &header.hardware_version, &header.kernel_version).unwrap();

    // The display name is irrelevant to dialect selection; the firmware and
    // the live vendor receiver's hardware/tag agreement are what matter.
    let renamed = pr1ame_identity(b"UNUSUAL PRODUCT ", b"SAT 8000", b"ID90    ");
    check_live_identity(&renamed, &header.hardware_version, &header.kernel_version).unwrap();
    for (hardware, tag) in [(b"SAT 8800", b"ID90    "), (b"SAT 8000", b"ID88    ")] {
        let wrong = pr1ame_identity(b"BDR-PR1AME      ", hardware, tag);
        assert!(
            check_live_identity(&wrong, &header.hardware_version, &header.kernel_version).is_err()
        );
    }
}

#[test]
fn held_dvr_kernel_selects_handshake_and_corrupt_kernel_refuses() {
    assert_eq!(from_kernel(DVR_109).unwrap(), DriveClass::Dvr);
    assert!(from_kernel(&PR1AME[..128]).is_err());
    let mut corrupt = PR1AME.to_vec();
    corrupt[0] = 0;
    assert!(from_kernel(&corrupt).is_err());
}

#[test]
fn all_held_pioneer_bd_and_dvr_kernels_have_unambiguous_dialects() {
    let Some(root) = std::env::var_os("FREEMKV_PIONEER_HOARD") else {
        return;
    };
    let mut counts = [0usize; 3];
    fn visit(dir: &std::path::Path, counts: &mut [usize; 3]) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(&path, counts);
            } else if path.extension().is_some_and(|e| e == "enc")
                && path.parent().is_some_and(|p| p.ends_with("kernel"))
            {
                let metadata: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(path.with_extension("enc.json")).unwrap(),
                )
                .unwrap();
                let id = metadata["header"]["id"].as_str().unwrap_or("");
                let expected = if id.contains("DVD-RW") {
                    Some(DriveClass::Dvr)
                } else if id.contains("BD-") || id.contains("BDR-") {
                    Some(DriveClass::Bd)
                } else {
                    None
                };
                let actual = from_kernel(&std::fs::read(&path).unwrap())
                    .unwrap_or_else(|e| panic!("{}: {e:#}", path.display()));
                counts[2] += 1;
                if let Some(expected) = expected {
                    assert_eq!(actual, expected, "{}", path.display());
                    counts[usize::from(expected == DriveClass::Dvr)] += 1;
                }
            }
        }
    }
    visit(std::path::Path::new(&root), &mut counts);
    assert!(
        counts[0] >= 292,
        "BD corpus unexpectedly shrank: {counts:?}"
    );
    assert!(
        counts[1] >= 61,
        "DVR corpus unexpectedly shrank: {counts:?}"
    );
    assert!(
        counts[2] >= 393,
        "Kernel corpus unexpectedly shrank: {counts:?}"
    );
}
