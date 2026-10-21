//! BU40N OEM bytes through Modify, package routing and the real flash engine.
//! All device commands terminate at an in-memory transport; no hardware opens.
use std::path::{Path, PathBuf};

use freemkv_flash::{
    backend::{registry, Backend, FlashRequest, UpdateOutcome},
    backends::mtk::Mtk,
    engine,
    manifest::FlashMode,
    mediatek_package::{digest, Component, Manifest, Package, Role, FORMAT},
    platform::MockScsiDevice,
    workflow::Preconfirmed,
};
use freemkv_fw::{
    api,
    artifact::Artifact,
    boot::{BootFeature, BootSettings},
    engine::audit::audit_image,
};

const OEM_SHA: &str = "221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4";
const PUBLISHED: [&str; 7] = [
    "0a47d1e62779f5180248b9ab5b3f3ec4b2dde183d14e205477e3f3e9894b8c33",
    "2762f7cf5b60fc0b9be352e59aa6cb6f5413c6d91b1843f4048c0a29f1048884",
    "88a0ed80c03fcfcebf9ba880f153b3f5128afdb304eae612eb68f2a001901e40",
    "b7ef4a97234093d598f2f7b5047cab8dbbbf2193a508df44f7e41c31f8b7a51f",
    "d3b71fe391f8a5d37c1c406e326a4f266a0b4ba332d56e3a1769b20306d9244b",
    "e696b7bb36ced8010b2a0b8dd0b233d97633c01ebb4ef5944d4ec8d410b1cd5b",
    "ed07c986bebfeeffc1c062e52f51cad068a2bc6ef7e76132308c00513da6d6cd",
];

fn roundtrip(bytes: Vec<u8>) {
    let original = Package::parse(&bytes).unwrap();
    let current = original.firmware().to_vec();
    assert!(api::verify(&current, None).unwrap().ok);
    let artifact = Artifact::parse(bytes).unwrap();
    let defaults = BootSettings::standard();
    let (report, support) = api::modify_with_defaults(artifact.image(), &defaults).unwrap();
    let audit = audit_image(&current, &report);
    assert!(audit.ok(), "{:#?}", audit.failures().collect::<Vec<_>>());
    assert!(BootFeature::ALL.into_iter().all(|f| support.supports(f)));
    let target = report.image.clone();
    assert_ne!(target, current, "Modify must change the OEM image");
    assert!(api::verify(&target, None).unwrap().ok);
    assert_eq!(
        freemkv_fw::boot::inspect(&target).unwrap().unwrap().0,
        defaults
    );
    let modified_tar = artifact.output(target.clone()).unwrap();
    let modified = Package::parse(&modified_tar).unwrap();
    assert_eq!(modified.firmware(), target);
    assert_eq!(modified.manifest.components[0].sha256, digest(&target));
    assert_eq!(modified.intermediate(), None);

    let dir = tempfile::tempdir().unwrap();
    for (name, input, format) in [
        ("modified.tar", modified_tar, "mtk-package"),
        ("modified.bin", target.clone(), "mtk-image"),
    ] {
        let (backend, recognized) = registry::recognize(&input).unwrap().unwrap();
        assert_eq!(backend.descriptor().id, Mtk.descriptor().id);
        assert_eq!(recognized.format.id, format);
        let backup = dir.path().join(format!("{name}.backup.tar"));
        let mut request = FlashRequest {
            current: None,
            input,
            input_format: recognized.format,
            mode: FlashMode::Full,
            execute: false,
            acknowledged_risk: true,
            enc_override: None,
            drive_model: "BD-RE BU40N".into(),
            verbose: false,
            predump_out: Some(backup.clone()),
        };
        let mut dev = MockScsiDevice::echoing().with_firmware_image(current.clone());
        assert_eq!(
            engine::flash(&mut dev, &Mtk, &request, &mut Preconfirmed).unwrap(),
            UpdateOutcome::Planned
        );
        assert!(dev.writes.is_empty(), "preview must send no writes");
        assert!(!backup.exists(), "preview must not capture a backup");
        request.execute = true;
        let outcome = engine::flash(&mut dev, &Mtk, &request, &mut Preconfirmed).unwrap();
        assert!(outcome.fully_verified(), "{outcome:#?}");
        let saved = std::fs::read(&backup).unwrap();
        let restored = Mtk
            .backup()
            .unwrap()
            .validate(&saved, &request.drive_model)
            .unwrap();
        assert_eq!(&restored[0x10400..0x1e0000], &current[0x10400..0x1e0000]);
        let streamed: Vec<u8> = dev
            .writes
            .iter()
            .filter(|(cdb, _)| cdb[0] == 0x3b && cdb[1] == 6)
            .flat_map(|(_, data)| data.iter().copied())
            .collect();
        assert_eq!(
            streamed, target,
            "{name}: transfer changed the target bytes"
        );
        assert_eq!(
            dev.writes.first().unwrap().0,
            freemkv_flash::backends::mtk::cdb::enter_update()
        );
        assert_eq!(
            dev.writes.last().unwrap().0,
            freemkv_flash::backends::mtk::cdb::finish()
        );
        eprintln!("PASS {name}: Modify, CMAC, routing, preview, backup, transfer and readback");
    }
}

#[test]
fn clean_bu40n_100_modifies_and_flashes_as_tar_and_bin() {
    let image = include_bytes!("fixtures/BU40N_OEM_1.00.bin").to_vec();
    assert_eq!(digest(&image), OEM_SHA);
    let package = Package::from_parts(
        Manifest {
            format: FORMAT.into(),
            version: 1,
            components: vec![Component {
                path: "firmware.bin".into(),
                sha256: OEM_SHA.into(),
                role: Role::Firmware,
            }],
            pairing: None,
            metadata: Default::default(),
        },
        [("firmware.bin".into(), image)].into(),
    )
    .unwrap();
    roundtrip(package.encode().unwrap());
}

#[test]
#[ignore = "requires FREEMKV_BU40N_PACKAGES with the seven website BU40N 1.00 TARs"]
fn every_published_bu40n_100_package_modifies_and_flashes() {
    let root = PathBuf::from(std::env::var_os("FREEMKV_BU40N_PACKAGES").unwrap());
    for sha in PUBLISHED {
        let name = format!("BU40N_1.00_{}.tar", &sha[..8]);
        let bytes = std::fs::read(Path::new(&root).join(&name)).unwrap();
        assert_eq!(
            digest(&bytes),
            sha,
            "{name}: must use exact published bytes"
        );
        eprintln!("Checking {name}");
        roundtrip(bytes);
    }
}
