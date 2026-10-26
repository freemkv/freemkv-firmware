//! Offline research builds. Ordinary Modify deliberately does not call this path.
//! Building and admitting a candidate is not evidence of physical UHD reading.
use crate::boot::{BootFeature, BootSettings, BootSupport};
use crate::engine::lever::{HookReport, LeverId, LeverReport};
use crate::engine::mt1959::Mt1959Engine;
use crate::{engine, family};
use anyhow::{ensure, Result};
use mediatek_optical::image::analysis::{AuthCell, AuthCellVariant};
use sha2::{Digest, Sha256};

fn fact(report: &engine::ModifyReport, key: &str) -> Result<u32> {
    report
        .levers
        .iter()
        .flat_map(|l| &l.facts)
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .ok_or_else(|| anyhow::anyhow!("missing research build prerequisite {key}"))
}

fn candidate(image: &[u8], defaults: &BootSettings) -> Result<(engine::ModifyReport, BootSupport)> {
    ensure!(
        family::detect_chip(image)?.family == family::ChipFamily::Mt1939,
        "research candidate requires a native MT1939 image"
    );
    ensure!(
        !engine::core::is_freemkv_patched(image),
        "select an original image"
    );
    freemkv_flash::cmac::validate_flags(image)?;
    let contract = AuthCell::detect(image)?;
    ensure!(
        contract.variant() == AuthCellVariant::R0StateR1Alternate,
        "research candidate requires the selected classic VID/auth contract"
    );
    let mut report = engine::detect(image)?.modify_with_defaults(image, defaults)?;
    let (handler, length, boot, flags) = (
        fact(&report, "handler_va")?,
        fact(&report, "handler_len")?,
        fact(&report, "boot_stub_va")?,
        fact(&report, "flag_base")?,
    );
    ensure!(
        handler != 0 && length != 0 && boot != 0 && flags != 0,
        "research candidate requires a complete base and boot contract"
    );
    let (site, bytes) = Mt1959Engine.auth_cell_widen_detour(image, flags)?;
    ensure!(
        report.image.get(site..site + 4) == image.get(site..site + 4),
        "another hook already owns the authentication site"
    );
    let stub = Mt1959Engine.free_space(&report.image, bytes.len())?;
    let branch = thumb_asm::encode_bl(site, stub)
        .ok_or_else(|| anyhow::anyhow!("research authentication branch out of range"))?;
    thumb_asm::write(&mut report.image, stub as usize, &bytes);
    thumb_asm::write(&mut report.image, site, &branch);
    crate::install_guard::verify_branch(
        &report.image,
        site,
        thumb_asm::BranchKind::Bl,
        stub,
        "research classic authentication",
    )?;
    let raw = report
        .levers
        .iter_mut()
        .find(|l| l.id == LeverId::RawRead)
        .ok_or_else(|| anyhow::anyhow!("research candidate requires the raw-read path"))?;
    ensure!(
        raw.outcome.is_effective(),
        "the raw-read path was not emitted"
    );
    raw.facts.extend([
        ("auth_cell_site", site as u32),
        ("auth_cell_stub_va", stub),
        ("auth_cell_refusal", 1),
        ("auth_cell_native_refusal", contract.refusal() as u32),
    ]);
    raw.hooks.push(HookReport::applied(
        "auth-cell",
        "research-R0StateR1Alternate",
    ));
    let support = BootSupport::from_modify(&report);
    ensure!(support.has_boot(), "research build has no boot settings");
    defaults.validate(&support)?;
    crate::boot::attach(
        &mut report.image,
        handler as usize,
        length as usize,
        boot as usize,
        defaults,
        &support,
    )?;
    report
        .levers
        .push(LeverReport::applied(LeverId::BootSettings, vec![]));
    engine::validate_metadata(image, &report.image)?;
    ensure!(
        engine::audit::audit_image(image, &report).ok(),
        "research candidate failed structural audit"
    );
    Ok((report, support))
}

#[test]
fn classic_uhd_research_candidates_roundtrip_all_settings_without_promoting_standard_support() {
    let image = include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
    let before = image.to_vec();
    let (_, ordinary) = crate::api::modify_with_defaults(image, &BootSettings::standard()).unwrap();
    assert!(!ordinary.supports(BootFeature::Unrestricted));
    for setting in ["oem", "on", "off"] {
        let defaults = BootSettings::parse(&[format!("unrestricted={setting}")]).unwrap();
        let (report, support) = candidate(image, &defaults).unwrap();
        for value in [0, 1, 255] {
            assert!(support.supports_value(BootFeature::Unrestricted, value));
        }
        let (stored, stored_support) = crate::boot::inspect(&report.image).unwrap().unwrap();
        assert_eq!(stored.value(BootFeature::Unrestricted), setting);
        assert!(stored_support.supports(BootFeature::Unrestricted));
        assert!(engine::audit::audit_image(image, &report).ok());
        assert_eq!(&image[..], &before[..]);
    }
}

#[test]
fn classic_uhd_research_refuses_another_chip_or_an_already_modified_source() {
    let modern = include_bytes!("../tests/fixtures/BU40N_OEM_1.00.bin");
    assert!(candidate(modern, &BootSettings::standard()).is_err());
    let original = include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
    let (modified, _) = candidate(original, &BootSettings::standard()).unwrap();
    assert!(candidate(&modified.image, &BootSettings::standard()).is_err());
}

#[test]
fn classic_uhd_research_corpus_builds_without_changing_originals() {
    let Ok(manifest) = std::env::var("FREEMKV_MT1939_UHD_SOURCES") else {
        return;
    };
    let hoard = std::path::PathBuf::from(std::env::var("FREEMKV_MT1939_UHD_HOARD").unwrap());
    let output = std::env::var("FREEMKV_MT1939_UHD_OUTPUT")
        .ok()
        .map(std::path::PathBuf::from);
    if let Some(dir) = &output {
        std::fs::create_dir_all(dir).unwrap();
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest).unwrap()).unwrap();
    let mut records = Vec::new();
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    for item in manifest["images"].as_array().unwrap() {
        let hash = item["sha256"].as_str().unwrap();
        let source = hoard.join(item["path"].as_str().unwrap());
        let image = std::fs::read(&source).unwrap();
        assert_eq!(digest(&image), hash);
        for setting in ["oem", "on", "off"] {
            let defaults = BootSettings::parse(&[format!("unrestricted={setting}")]).unwrap();
            let (report, _) = candidate(&image, &defaults).unwrap();
            let filename = format!("{hash}.{setting}.uhd-research.bin");
            let record = serde_json::json!({"input_sha256":hash,"source":item["path"],
                "output_sha256":digest(&report.image),"file":filename,"setting":setting,
                "structural_audit":"passed","physical_uhd_validation":false,
                "auth_site":fact(&report,"auth_cell_site").unwrap(),
                "auth_stub":fact(&report,"auth_cell_stub_va").unwrap()});
            if let Some(dir) = &output {
                std::fs::write(dir.join(&filename), &report.image).unwrap();
            }
            records.push(record);
        }
        assert_eq!(digest(&std::fs::read(&source).unwrap()), hash);
    }
    assert_eq!(
        records.len(),
        72,
        "expected three settings for each of the 24 reviewed sources"
    );
    if let Some(dir) = &output {
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "scope":"research candidates only; not approved hoard or website firmware", "images":records
        })).unwrap()).unwrap();
    }
}
