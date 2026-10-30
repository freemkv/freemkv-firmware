//! Normal Modify regression and full-corpus tests. No alternate authoring path.
use crate::boot::{BootFeature, BootSettings};
use crate::engine;
use sha2::{Digest, Sha256};

fn checked_modify(image: &[u8], settings: &BootSettings) -> engine::ModifyReport {
    let (report, support) = crate::api::modify_with_defaults(image, settings).unwrap();
    let (stored, stored_support) = crate::boot::inspect(&report.image).unwrap().unwrap();
    for feature in BootFeature::ALL {
        assert_eq!(stored.value(feature), settings.value(feature));
        assert_eq!(stored_support.supports(feature), support.supports(feature));
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
fn normal_classic_modify_preserves_native_detection_and_refuses_uhd_settings() {
    let original = include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
    let report = checked_modify(original, &BootSettings::standard());
    assert!(!crate::boot::BootSupport::from_modify(&report).supports(BootFeature::Unrestricted));
    assert!(!report
        .levers
        .iter()
        .flat_map(|l| &l.hooks)
        .any(|h| h.id == "uhd-conversion"));
    let di = mediatek_optical::image::analysis::ClassicDi::detect(original).unwrap();
    assert_eq!(
        &report.image[di.prevalidation..di.layer_store + 2],
        &original[di.prevalidation..di.layer_store + 2]
    );
    for setting in ["on", "off"] {
        let settings = BootSettings::parse(&[format!("unrestricted={setting}")]).unwrap();
        assert!(crate::api::modify_with_defaults(original, &settings).is_err());
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

/// Exercise held images with partial support too: only advertised choices may
/// be selected, and absence of editable settings is a valid, explicit outcome.
#[test]
fn held_modify_corpus_roundtrips_every_advertised_choice() {
    use std::io::Write;
    let Ok(path) = std::env::var("FREEMKV_HELD_MODIFY_CORPUS") else {
        return;
    };
    let hoard = std::path::PathBuf::from(std::env::var("FREEMKV_NORMAL_MODIFY_HOARD").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut output =
        std::fs::File::create(std::env::var("FREEMKV_HELD_MODIFY_OUTPUT").unwrap()).unwrap();
    for row in manifest["images"].as_array().unwrap() {
        let data = std::fs::read(hoard.join(row["path"].as_str().unwrap())).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&data)),
            row["sha256"].as_str().unwrap()
        );
        let (report, support) =
            crate::api::modify_with_defaults(&data, &BootSettings::standard()).unwrap();
        assert!(engine::audit::audit_image(&data, &report).ok());
        assert!(freemkv_flash::cmac::verify(&report.image));
        freemkv_flash::crossflash::admits(
            freemkv_flash::crossflash::Platform::Mediatek,
            &data,
            &report.image,
        )
        .unwrap();
        let stored = crate::boot::inspect(&report.image).unwrap();
        let mut choices = 0;
        for feature in BootFeature::ALL {
            if !support.supports(feature) {
                continue;
            }
            let (settings, reopened_support) =
                stored.as_ref().expect("advertised settings must reopen");
            assert!(reopened_support.supports(feature));
            for value in [0, 1, 255] {
                if !support.supports_value(feature, value) {
                    continue;
                }
                let text = match (feature, value) {
                    (BootFeature::Speed, 1) => "uncapped",
                    (BootFeature::Region, 1) => "free",
                    (_, 0) => "off",
                    (_, 1) => "on",
                    _ => "oem",
                };
                let mut changed = settings.clone();
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
                    &data,
                    &updated.image,
                )
                .unwrap();
                choices += 1;
            }
        }
        writeln!(output, "{}", serde_json::json!({"input_sha256": row["sha256"], "output_sha256":format!("{:x}", Sha256::digest(&report.image)), "advertised_choices_tested":choices, "audit":"passed", "integrity":"passed", "admission":"passed"})).unwrap();
        output.flush().unwrap();
    }
}
