//! Isolated hardware-detection experiment; unreachable from production Modify.
use crate::boot::{BootSettings, BootSupport};
use crate::engine::{self, lever::LeverId, mt1959::Mt1959Engine, mtk_uhd};
use sha2::{Digest, Sha256};

fn build(image: &[u8], read_path: bool, bu40n: bool) -> (engine::ModifyReport, serde_json::Value) {
    assert!(
        !bu40n || read_path,
        "BU40N port requires full routing group"
    );
    let chip = crate::family::detect_chip(image).unwrap();
    let cap = crate::family::capability_for(&chip.model, chip.family);
    let defaults = BootSettings::parse(&["unrestricted=on".to_string()]).unwrap();
    let mut report = if read_path {
        Mt1959Engine.build_modify_classic_with_defaults(image, &chip, &cap, &defaults)
    } else {
        Mt1959Engine.build_detection_baseline_classic(image, &chip, &cap, &defaults)
    }
    .unwrap();
    let fact = |name: &str| {
        report
            .levers
            .iter()
            .flat_map(|l| &l.facts)
            .find(|(key, _)| *key == name)
            .unwrap()
            .1
    };
    let flags = fact("flag_base");
    let (handler, handler_len, boot) = (
        fact("handler_va"),
        fact("handler_len"),
        fact("boot_stub_va"),
    );
    assert_eq!(
        report
            .levers
            .iter()
            .flat_map(|l| &l.hooks)
            .any(|hook| hook.id == "uhd-conversion"),
        read_path
    );
    let candidate = if bu40n {
        mtk_uhd::di_bu40n_candidate(image, flags)
    } else {
        mtk_uhd::di_detection_candidate(image, flags)
    }
    .unwrap();
    let site = candidate.contract.prevalidation;
    if read_path {
        let previous = mtk_uhd::di_prevalidation_candidate(image, flags).unwrap();
        let branch = thumb_asm::isa::decode_at(&report.image, site).unwrap();
        assert_eq!(branch.mnemonic, "bl");
        let old_stub = branch.branch_target().unwrap() as usize;
        assert_eq!(
            &report.image[old_stub..old_stub + previous.bytes.len()],
            previous.bytes
        );
        report.image[old_stub..old_stub + previous.bytes.len()]
            .copy_from_slice(&image[old_stub..old_stub + previous.bytes.len()]);
        report.image[site..site + candidate.original.len()].copy_from_slice(&candidate.original);
    }
    assert_eq!(
        &report.image[site..site + candidate.original.len()],
        candidate.original
    );
    let stub = Mt1959Engine
        .free_space(&report.image, candidate.bytes.len())
        .unwrap();
    let mut install = thumb_asm::encode_bl(site, stub).unwrap().to_vec();
    install.extend_from_slice(&[0xc0, 0x46, 0xc0, 0x46]);
    thumb_asm::write(&mut report.image, site, &install);
    thumb_asm::write(&mut report.image, stub as usize, &candidate.bytes);
    crate::install_guard::verify_branch(
        &report.image,
        site,
        thumb_asm::BranchKind::Bl,
        stub,
        "experimental detection",
    )
    .unwrap();
    // The detection-only image retains the base capability record; its research
    // default is fixed On without advertising complete Unrestricted support.
    let support = BootSupport::from_modify(&report);
    crate::boot::attach(
        &mut report.image,
        handler as usize,
        handler_len as usize,
        boot as usize,
        &defaults,
        &support,
    )
    .unwrap();
    report.image = crate::api::sign(&report.image, None).unwrap().image;
    assert!(engine::audit::audit_image(image, &report).ok());
    engine::validate_metadata(image, &report.image).unwrap();
    freemkv_flash::crossflash::admits(
        freemkv_flash::crossflash::Platform::Mediatek,
        image,
        &report.image,
    )
    .unwrap();
    assert_eq!(
        &report.image[stub as usize..stub as usize + candidate.bytes.len()],
        candidate.bytes
    );
    let plan = mtk_uhd::UhdConversionPlan::inspect(image).unwrap();
    let other_sites = plan
        .routing_candidates(image, flags)
        .unwrap()
        .into_iter()
        .map(|part| (part.site, part.original))
        .chain(
            plan.auxiliary_candidates(image, flags)
                .unwrap()
                .into_iter()
                .map(|part| (part.site, part.original)),
        );
    for (site, original) in other_sites {
        assert_eq!(
            report.image[site..site + original.len()] == original,
            !read_path
        );
    }
    let raw = report
        .levers
        .iter()
        .find(|l| l.id == LeverId::RawRead)
        .unwrap();
    assert_eq!(
        raw.facts.iter().any(|(key, _)| *key == "auth_cell_stub_va"),
        read_path
    );
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let receipt = serde_json::json!({
        "policy":"experimental candidate; no physical detection/read claim",
        "source_sha256":digest(image), "output_sha256":digest(&report.image),
        "model":chip.model, "revision":chip.rev,
        "flag_base":flags, "unrestricted":if read_path { "On; complete experimental group" } else { "fixed On; detection-only build does not advertise complete support" },
        "state":candidate.contract.state, "site":site, "stub_va":stub,
        "stub":candidate.bytes, "original":candidate.original,
        "entry":candidate.contract.entry, "format":candidate.contract.format,
        "format_flag":candidate.contract.format_flag, "layer_store":candidate.contract.layer_store,
        "epilogue":candidate.contract.epilogue,
        "formats":[1,5], "read_path":read_path,
        "bu40n_attribute_validation":bu40n,
        "bu40n_reference_sha256":if bu40n { Some("221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4") } else { None },
        "installed_conversion_components":if read_path { "complete group plus format-one recognition" } else { "DiscInformation only" },
        "checks":["base structural audit","metadata","CMAC","offline Flash admission","installed branch/stub","other routing sites match selected group"],
    });
    (report, receipt)
}

#[test]
fn detection_only_build_keeps_native_read_routing() {
    build(
        include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin"),
        false,
        false,
    );
}

#[test]
fn reading_experiment_retains_complete_routing_group() {
    build(
        include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin"),
        true,
        false,
    );
}

#[test]
fn bu40n_experiment_installs_with_complete_routing_group() {
    build(
        include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin"),
        true,
        true,
    );
}

#[test]
fn build_selected_detection_candidate() {
    let Ok(input) = std::env::var("FREEMKV_DETECTION_SOURCE") else {
        return;
    };
    let output = std::path::PathBuf::from(std::env::var("FREEMKV_DETECTION_OUTPUT").unwrap());
    let image = std::fs::read(input).unwrap();
    let expected = std::env::var("FREEMKV_DETECTION_SOURCE_SHA256").unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&image)), expected);
    let read_path = std::env::var("FREEMKV_DETECTION_READ_PATH").as_deref() == Ok("1");
    let bu40n = std::env::var("FREEMKV_DETECTION_BU40N").as_deref() == Ok("1");
    let (report, receipt) = build(&image, read_path, bu40n);
    std::fs::write(
        output.with_extension("json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    std::fs::write(&output, &report.image).unwrap();
    println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
}
