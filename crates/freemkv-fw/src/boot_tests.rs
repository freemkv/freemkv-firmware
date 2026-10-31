use super::*;

#[test]
fn classic_emitted_boot_and_region_hrl_controls_are_reported() {
    let image = include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
    let (_, support) = api::modify_with_defaults(image, &BootSettings::standard()).unwrap();
    assert!(
        support.has_boot(),
        "classic emission must report the boot hook it installed"
    );
    assert!(support.supports(BootFeature::Region));
    assert!(support.supports(BootFeature::Hrl));
    assert!(support.supports(BootFeature::Speed));
    assert!(support.supports_value(BootFeature::Unrestricted, 1));
    assert!(support.supports_value(BootFeature::Unrestricted, 255));
    assert!(!support.supports_value(BootFeature::Unrestricted, 0));
}

#[test]
fn wh_auth_hook_exposes_and_roundtrips_all_three_proven_choices() {
    let image = include_bytes!("../tests/fixtures/WH16NS58_OEM_1.V9.bin");
    let (report, support) =
        crate::api::modify_with_defaults(image, &BootSettings::standard()).unwrap();
    assert!(
        support.supports(BootFeature::Unrestricted),
        "the emitted widening hook is a usable On setting"
    );
    assert!(support.supports_value(BootFeature::Unrestricted, 1));
    assert!(support.supports_value(BootFeature::Unrestricted, 255));
    assert!(support.supports_value(BootFeature::Unrestricted, 0));
    assert!(!support.supports_value(BootFeature::Unrestricted, 17));
    let (_, restored) = inspect(&report.image).unwrap().unwrap();
    assert!(restored.supports_value(BootFeature::Unrestricted, 0));
    let off = settings(&["unrestricted=off"]);
    assert!(off.validate(&restored).is_ok());
    let (off_image, _) = update(&report.image, &off).unwrap().unwrap();
    assert_eq!(
        inspect(&off_image)
            .unwrap()
            .unwrap()
            .0
            .value(BootFeature::Unrestricted),
        "off"
    );
    let oem = settings(&["unrestricted=oem"]);
    let (changed, _) = update(&report.image, &oem).unwrap().unwrap();
    assert_eq!(
        inspect(&changed)
            .unwrap()
            .unwrap()
            .0
            .value(BootFeature::Unrestricted),
        "oem"
    );
    assert!(BootSettings::standard()
        .report_json(&support, "{}")
        .contains("\"choices\":[\"oem\",\"on\",\"off\"]"));
}

#[test]
fn existing_partial_capability_records_do_not_gain_off_from_new_engine_support() {
    let image = include_bytes!("../tests/fixtures/WH16NS58_OEM_1.V9.bin");
    let (report, _) = api::modify_with_defaults(image, &BootSettings::standard()).unwrap();
    let mut legacy = report.image;
    let record = legacy
        .windows(16)
        .position(|w| w == RECORD_MAGIC_V3)
        .unwrap();
    legacy[record + 23] |= LIMITED_UNRESTRICTED;
    let legacy = freemkv_flash::cmac::resign(&legacy).unwrap();
    let (_, support) = inspect(&legacy).unwrap().unwrap();
    assert!(support.supports_value(BootFeature::Unrestricted, 1));
    assert!(support.supports_value(BootFeature::Unrestricted, 255));
    assert!(!support.supports_value(BootFeature::Unrestricted, 0));
    assert!(update(&legacy, &settings(&["unrestricted=off"])).is_err());
}

#[test]
fn tight_bu40n_v105_has_room_for_exact_boot_metadata_after_all_hooks() {
    let image = include_bytes!("../tests/fixtures/BU40N_OEM_1.05.bin");
    let (report, support) = crate::api::modify_with_defaults(image, &BootSettings::standard())
        .expect("the fixed boot record must not request unused assembler headroom");
    assert!(support.has_boot());
    assert!(report.levers.iter().any(|l| l
        .facts
        .iter()
        .any(|(k, v)| *k == "auth_cell_stub_va" && *v != 0)));
    assert!(crate::engine::validate_metadata(image, &report.image).is_ok());
    assert!(freemkv_flash::cmac::verify(&report.image));
}
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

#[test]
fn editable_settings_do_not_require_boot_to_follow_the_handler() {
    let mut image = fixture();
    let defaults = BootSettings::standard();
    let boot = 0x1000;
    let handler = 0x2000;
    let reset = stores(&defaults.flags(), 0);
    let fallback = stores(&defaults.flags(), 6);
    image[boot..boot + 64].fill(0);
    image[boot..boot + reset.len()].copy_from_slice(&reset);
    image[handler..handler + reset.len()].copy_from_slice(&reset);
    image[handler + reset.len()..handler + reset.len() + fallback.len()].copy_from_slice(&fallback);
    attach(
        &mut image,
        handler,
        reset.len() + fallback.len(),
        boot,
        &defaults,
        &BootSupport {
            boot: true,
            mask: 31,
        },
    )
    .unwrap();
    assert_eq!(inspect(&image).unwrap().unwrap().0, defaults);
    let changed = settings(&["unrestricted=off"]);
    let (updated, _) = update(&image, &changed).unwrap().unwrap();
    assert_eq!(
        inspect(&updated).unwrap().unwrap().0.flags(),
        changed.flags()
    );
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
    // Both cold and warm initialization ignore saved NV state.
    for initial in [0u8, 1, 255] {
        let mut ram = [initial; 32];
        execute_boot_prefix(&bytes, base, &mut ram);
        assert_eq!(&ram[..7], &defaults.flags());
        assert!(ram[7..].iter().all(|b| *b == initial));
    }
    let (report, support) = api::modify_with_defaults(&fixture(), &defaults).unwrap();
    assert!(BootFeature::ALL.into_iter().all(|f| support.supports(f)));
    let record = read_record(&report.image).unwrap().unwrap();
    for (i, site) in record.sites.iter().enumerate() {
        if record.shared_reset && i == 2 {
            assert_eq!(*site, 0);
            continue;
        }
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
    let record = read_record(&second.image).unwrap().unwrap();
    assert!(record.shared_reset);
    assert_eq!(record.sites[2], 0);
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
    assert_eq!(
        freemkv_flash::workflow::user_error(&error).id,
        "errors.already_modified"
    );
    assert!(format!("{error:#}").contains("original OEM image"));
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

#[test]
fn shared_reset_records_refuse_a_forged_third_instruction_site() {
    let (report, _) = api::modify_with_defaults(&fixture(), &BootSettings::standard()).unwrap();
    let record = read_record(&report.image).unwrap().unwrap();
    assert!(record.shared_reset);
    let mut corrupt = report.image;
    corrupt[record.offset + 32..record.offset + 36]
        .copy_from_slice(&(record.sites[1] as u32).to_le_bytes());
    let corrupt = freemkv_flash::cmac::resign(&corrupt).unwrap();
    assert!(inspect(&corrupt)
        .unwrap_err()
        .to_string()
        .contains("empty third site"));
}

#[test]
fn normal_modify_refuses_a_raw_drive_dump_before_creating_unflashable_output() {
    let mut image = fixture();
    let mirror = image[0x10000..0x10400].to_vec();
    image[..0x400].copy_from_slice(&mirror);
    assert!(mediatek_optical::image::is_drive_read(&image));
    let error = crate::api::modify_with_defaults(&image, &BootSettings::standard()).unwrap_err();
    assert!(format!("{error:#}").contains("raw MediaTek drive dump"));
    assert_eq!(
        error.downcast_ref::<freemkv_flash::user_error::IssueCode>(),
        Some(&freemkv_flash::user_error::IssueCode::UnsupportedFirmware)
    );
}

fn execute_boot_prefix(bytes: &[u8], base: u32, ram: &mut [u8]) {
    let mut regs = [0u32; 16];
    for pc in (0..bytes.len()).step_by(2) {
        use thumb_asm::isa::Operand;
        let ins = thumb_asm::isa::decode_at(&bytes, pc).expect("decoded boot instruction");
        match ins.mnemonic {
            "push" => {}
            "pop" => break, // argument restore ends the initialization prefix
            "ldr" => {
                let Some(Operand::Reg(dest)) = ins.operands.get(0) else {
                    panic!("LDR destination");
                };
                regs[usize::from(dest.num())] = thumb_asm::analysis::literal_value(&bytes, pc)
                    .expect("initialization prefix loads only literals");
            }
            "mov" => {
                let Some(Operand::Reg(dest)) = ins.operands.get(0) else {
                    panic!("MOV destination");
                };
                regs[usize::from(dest.num())] = match ins.operands.get(1) {
                    Some(Operand::Imm(value)) => value as u32,
                    Some(Operand::Reg(source)) => regs[usize::from(source.num())],
                    _ => panic!("MOV source"),
                };
            }
            "strb" => {
                let (Some(Operand::Reg(source)), Some(Operand::Mem(memory))) =
                    (ins.operands.get(0), ins.operands.get(1))
                else {
                    panic!("STRB operands");
                };
                assert!(memory.index.is_none() && memory.add);
                let address = regs[usize::from(memory.base.num())] + memory.offset;
                ram[(address - base) as usize] = regs[usize::from(source.num())] as u8;
            }
            _ => panic!("unexpected boot instruction {ins:?}; review startup behavior"),
        }
    }
}

#[test]
fn private_uhd_identity_boot_reset_preserves_features_and_flash_scratch() {
    use crate::engine::core::{FLASHWRITE_SCRATCH_OFF, UHD_IDENTITY_OFF};
    let base = 0x02000e40;
    let defaults = BootSettings::standard();
    let bytes = Mt1959Engine
        .build_boot_init_with_private_identity(
            base,
            0x1234,
            &defaults,
            Some(base + UHD_IDENTITY_OFF),
        )
        .unwrap();
    for initial in [0, 1, 0xff] {
        let mut ram = [initial; 32];
        execute_boot_prefix(&bytes, base, &mut ram);
        assert_eq!(&ram[..7], &defaults.flags());
        assert_eq!(ram[UHD_IDENTITY_OFF as usize], 0);
        for (offset, value) in ram.iter().enumerate().skip(7) {
            if offset != UHD_IDENTITY_OFF as usize {
                assert_eq!(*value, initial);
            }
        }
        assert_eq!(ram[FLASHWRITE_SCRATCH_OFF as usize], initial);
    }
    for overlap in [base, base + 3, base + FLASHWRITE_SCRATCH_OFF] {
        assert!(Mt1959Engine
            .build_boot_init_with_private_identity(base, 0x1234, &defaults, Some(overlap),)
            .is_err());
    }
}
