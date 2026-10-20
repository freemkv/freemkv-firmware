use super::*;
use crate::{
    api,
    engine::{self, mt1959::Mt1959Engine},
};

fn fixture() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    ))
    .unwrap()
}
fn settings(args: &[&str]) -> BootSettings {
    BootSettings::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
}

#[test]
fn parser_preserves_shipping_defaults_and_rejects_ambiguous_requests() {
    assert_eq!(
        BootSettings::standard().flags(),
        [255, 255, 255, 1, 1, 255, 255]
    );
    assert_eq!(
        settings(&["hrl=off", "enc=off", "speed=uncapped", "region=free"]).flags(),
        [255, 1, 1, 1, 1, 0, 0]
    );
    assert_eq!(settings(&["unrestricted=off"]).flags()[3..5], [0, 0]);
    for args in [
        vec!["hrl=on", "hrl=off"],
        vec!["enc=off", "encryption=on"],
        vec!["hrl=wipe"],
        vec!["region=bd:a"],
        vec!["speed=cap:255"],
        vec!["unknown=on"],
        vec!["off"],
    ] {
        assert!(
            BootSettings::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).is_err(),
            "{args:?}"
        );
    }
    assert_eq!(
        settings(&["hrl=passthrough"]).value(BootFeature::Hrl),
        "oem"
    );
}

#[test]
fn saved_settings_cannot_override_boot_but_runtime_reset_uses_same_defaults() {
    let defaults = settings(&[
        "hrl=off",
        "encryption=off",
        "unrestricted=off",
        "speed=uncapped",
        "region=free",
    ]);
    let base = 0x02000e40;
    let bytes = Mt1959Engine
        .build_boot_init_with_defaults(base, 0x1234, &defaults)
        .unwrap();
    let mut regs = [0u32; 16];
    let mut ram = [42u8; 7];
    // Execute the boot prefix until it restores OEM arguments. No flash read is
    // permitted: both cold and warm startup must be independent of saved NV.
    for initial in [0u8, 1, 255] {
        ram.fill(initial);
        for pc in (0..bytes.len()).step_by(2) {
            let op = u16::from_le_bytes(bytes[pc..pc + 2].try_into().unwrap());
            if op == 0xbc0f {
                break;
            }
            match op {
                0xb51f => {} // preserve registers on stack
                op if op & 0xf800 == 0x4800 => {
                    let at = ((pc + 4) & !3) + usize::from(op & 255) * 4;
                    regs[usize::from((op >> 8) & 7)] =
                        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                }
                op if op & 0xf800 == 0x2000 => {
                    regs[usize::from((op >> 8) & 7)] = u32::from(op & 255)
                }
                op if op & 0xf800 == 0x7000 => {
                    let address = regs[usize::from((op >> 3) & 7)] + u32::from((op >> 6) & 31);
                    ram[(address - base) as usize] = regs[usize::from(op & 7)] as u8;
                }
                _ => panic!("unexpected boot instruction {op:04x}; review startup behavior"),
            }
        }
        assert_eq!(ram, defaults.flags());
    }
    let (report, support) = api::modify_with_defaults(&fixture(), &defaults).unwrap();
    assert!(BootFeature::ALL.into_iter().all(|f| support.supports(f)));
    let record = read_record(&report.image).unwrap().unwrap();
    for (i, site) in record.sites.iter().enumerate() {
        assert_eq!(
            &report.image[*site..*site + 28],
            stores(&defaults.flags(), if i == 2 { 6 } else { 0 })
        );
    }
    assert!(engine::audit::audit_image(&fixture(), &report).ok());
}

#[test]
fn new_images_can_be_reconfigured_and_reset_without_reinjecting_hooks() {
    let (first, support) =
        api::modify_with_defaults(&fixture(), &BootSettings::standard()).unwrap();
    assert!(support.has_boot());
    let custom = settings(&["hrl=off", "encryption=off"]);
    let (second, _) = api::modify_with_defaults(&first.image, &custom).unwrap();
    let (loaded, _) = inspect(&second.image).unwrap().unwrap();
    assert_eq!(loaded.flags(), custom.flags());
    let (reset, _) = api::modify_with_defaults(&second.image, &BootSettings::standard()).unwrap();
    assert_eq!(
        reset.image, first.image,
        "Reset must restore the original image byte for byte"
    );
    assert!(api::verify(&second.image, None).unwrap().ok);
}

#[test]
fn corrupt_or_ambiguous_records_are_refused_even_if_resigned() {
    let (report, _) = api::modify_with_defaults(&fixture(), &BootSettings::standard()).unwrap();
    let record = read_record(&report.image).unwrap().unwrap();
    let mut corrupt = report.image.clone();
    corrupt[record.sites[0]] ^= 1;
    let corrupt = freemkv_flash::cmac::resign(&corrupt).unwrap();
    assert!(inspect(&corrupt).is_err());
    let mut duplicate = report.image.clone();
    duplicate.extend_from_slice(&report.image[record.offset..record.offset + RECORD_LEN]);
    assert!(inspect(&duplicate).is_err());
}

#[test]
fn explicit_unsupported_features_and_legacy_modified_images_are_refused() {
    assert!(settings(&["hrl=oem"])
        .validate(&BootSupport::default())
        .is_err());
    let legacy = Mt1959Engine.build_report(&fixture()).unwrap();
    let error = api::modify_with_defaults(&legacy.image, &settings(&["hrl=off"]))
        .err()
        .unwrap();
    assert!(error.to_string().contains("original OEM image"));
}

#[test]
fn strict_and_modify_share_the_same_boot_image() {
    let defaults = settings(&["hrl=off", "encryption=off"]);
    let strict = api::create_with_defaults(&fixture(), &defaults).unwrap();
    let (modified, _) = api::modify_with_defaults(&fixture(), &defaults).unwrap();
    assert_eq!(strict.image(), modified.image);
}

#[test]
fn paired_tar_modification_preserves_intermediate_and_source_evidence() {
    use freemkv_flash::mediatek_package::{digest, Component, Manifest, Package, Role, FORMAT};
    use std::collections::BTreeMap;
    let original = fixture();
    let mut intermediate = original.clone();
    intermediate[0x1ec018..0x1ec01c].copy_from_slice(b"INTM");
    let components = vec![
        Component {
            path: "intm.bin".into(),
            sha256: digest(&intermediate),
            role: Role::Intermediate,
        },
        Component {
            path: "final.bin".into(),
            sha256: digest(&original),
            role: Role::Firmware,
        },
    ];
    let pairing_json = format!(
        r#"{{"basis":"vpd-declared-target-and-stage-layout","source":{{"sha256":"{}"}},"container_sha256":"{}","intermediate_sha256":"{}","final_sha256":"{}"}}"#,
        "a".repeat(64),
        "b".repeat(64),
        components[0].sha256,
        components[1].sha256
    );
    let manifest = Manifest {
        format: FORMAT.into(),
        version: 1,
        components,
        pairing: Some(pairing_json.parse().unwrap()),
        metadata: BTreeMap::new(),
    };
    let package = Package::from_parts(
        manifest,
        BTreeMap::from([
            ("intm.bin".into(), intermediate.clone()),
            ("final.bin".into(), original),
        ]),
    )
    .unwrap();
    let artifact = crate::artifact::Artifact::parse(package.encode().unwrap()).unwrap();
    let defaults = settings(&["hrl=off"]);
    let (report, _) = api::modify_with_defaults(artifact.image(), &defaults).unwrap();
    let edited = Package::parse(&artifact.output(report.image).unwrap()).unwrap();
    assert_eq!(edited.intermediate(), Some(intermediate.as_slice()));
    assert_eq!(edited.manifest.pairing, package.manifest.pairing);
    assert_eq!(
        edited.manifest.components[1].sha256,
        digest(edited.firmware())
    );
    assert_eq!(
        inspect(edited.firmware()).unwrap().unwrap().0.flags(),
        defaults.flags()
    );
}
