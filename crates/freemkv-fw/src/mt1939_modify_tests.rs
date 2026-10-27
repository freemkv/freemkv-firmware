//! Normal Modify regression and full-corpus tests. No alternate authoring path.
use crate::boot::{BootFeature, BootSettings};
use crate::engine;
use sha2::{Digest, Sha256};

fn checked_modify(image: &[u8], settings: &BootSettings) -> engine::ModifyReport {
    let (report, support) = crate::api::modify_with_defaults(image, settings).unwrap();
    for feature in BootFeature::ALL {
        assert!(support.supports(feature), "{feature:?}");
    }
    let (stored, stored_support) = crate::boot::inspect(&report.image).unwrap().unwrap();
    for feature in BootFeature::ALL {
        assert_eq!(stored.value(feature), settings.value(feature));
        assert!(stored_support.supports(feature));
    }
    // Reconfigure the already-built image through the same API used by the app.
    // Only assert advertised choices: Speed and Region intentionally use fewer.
    for feature in BootFeature::ALL {
        for value in [0, 1, 255] {
            if !support.supports_value(feature, value) {
                continue;
            }
            let text = match value {
                0 => "off",
                1 => "on",
                _ => "oem",
            };
            let mut changed = stored.clone();
            // Speed/Region use user-facing names for their enabled state.
            let text = match (feature, value) {
                (BootFeature::Speed, 1) => "uncapped",
                (BootFeature::Region, 1) => "free",
                _ => text,
            };
            changed.set(feature, text).unwrap();
            let (updated, updated_support) =
                crate::api::modify_with_defaults(&report.image, &changed).unwrap();
            assert!(updated_support.supports_value(feature, value));
            assert_eq!(
                crate::boot::inspect(&updated.image)
                    .unwrap()
                    .unwrap()
                    .0
                    .value(feature),
                changed.value(feature)
            );
            assert!(freemkv_flash::cmac::verify(&updated.image));
            freemkv_flash::crossflash::admits(
                freemkv_flash::crossflash::Platform::Mediatek,
                image,
                &updated.image,
            )
            .unwrap();
        }
    }
    assert!(engine::audit::audit_image(image, &report).ok());
    freemkv_flash::crossflash::admits(
        freemkv_flash::crossflash::Platform::Mediatek,
        image,
        &report.image,
    )
    .unwrap();
    report
}

#[test]
fn normal_classic_modify_installs_the_complete_group_and_roundtrips_settings() {
    let original = include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
    for setting in ["oem", "on", "off"] {
        let settings = BootSettings::parse(&[format!("unrestricted={setting}")]).unwrap();
        let report = checked_modify(original, &settings);
        assert!(report
            .levers
            .iter()
            .flat_map(|l| &l.hooks)
            .any(|h| h.id == "uhd-conversion"));
        let signed = crate::api::sign(&report.image, None).unwrap().image;
        assert!(crate::boot::inspect(&signed)
            .unwrap()
            .unwrap()
            .1
            .supports(BootFeature::Unrestricted));
    }
}

#[test]
fn normal_modify_corpus_has_complete_editable_settings() {
    let Ok(path) = std::env::var("FREEMKV_NORMAL_MODIFY_CORPUS") else {
        return;
    };
    let hoard = std::path::PathBuf::from(std::env::var("FREEMKV_NORMAL_MODIFY_HOARD").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut records = Vec::new();
    for row in manifest["images"].as_array().unwrap() {
        let data = std::fs::read(hoard.join(row["path"].as_str().unwrap())).unwrap();
        let digest = |b: &[u8]| format!("{:x}", Sha256::digest(b));
        assert_eq!(digest(&data), row["sha256"].as_str().unwrap());
        let report = checked_modify(&data, &BootSettings::standard());
        records.push(serde_json::json!({"input_sha256":digest(&data),"output_sha256":digest(&report.image),"settings":"all advertised choices reconfigured through normal Modify","audit":"passed","offline_admission":"passed"}));
    }
    if let Ok(path) = std::env::var("FREEMKV_NORMAL_MODIFY_OUTPUT") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &serde_json::json!({"path":"normal Modify","images":records}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}
