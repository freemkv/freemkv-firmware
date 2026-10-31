//! Research builds only: DI acceptance versus the first post-DI mode selector.
use crate::boot::{BootSettings, BootSupport};
use crate::engine::{self, mt1939_research as research, mt1959::Mt1959Engine};
use mediatek_optical::image::analysis::ClassicConsumerKind;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn build(
    image: &[u8],
    initialize_mode: bool,
    reacquisition_mode: bool,
) -> (Vec<u8>, serde_json::Value) {
    let chip = crate::family::detect_chip(image).unwrap();
    let cap = crate::family::capability_for(&chip.model, chip.family);
    // Explicit test-only authoring: the production API still refuses this default.
    let defaults = BootSettings::parse(&["unrestricted=on".to_string()]).unwrap();
    let mut report = Mt1959Engine
        .build_modify_classic_with_defaults(image, &chip, &cap, &defaults)
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
    let (flags, handler, handler_len, boot) = (
        fact("flag_base"),
        fact("handler_va"),
        fact("handler_len"),
        fact("boot_stub_va"),
    );
    let plan = research::UhdConversionPlan::inspect(image).unwrap();
    // Production now installs a complete group. Verify it first, then restore
    // its source spans solely for this explicitly partial research comparison.
    // Ordinary Modify never performs this restoration.
    plan.verify(image, &report.image, flags).unwrap();
    for patch in plan.prepared_patches(image, flags).unwrap() {
        report.image[patch.site..patch.site + patch.original.len()]
            .copy_from_slice(&patch.original);
    }
    for lever in &mut report.levers {
        lever.hooks.retain(|h| h.id != "uhd-conversion");
        lever
            .facts
            .retain(|(key, _)| *key != "uhd_conversion_count");
    }
    let candidates = plan.auxiliary_candidates(image, flags).unwrap();
    let mode_candidates: Vec<_> = candidates
        .iter()
        .filter(|part| part.area == ClassicConsumerKind::MediaDefaults)
        .collect();
    assert_eq!(
        mode_candidates.len(),
        1,
        "one source-bound post-DI mode role required"
    );
    let mut installed = Vec::new();
    let selected = |area| {
        (initialize_mode && area == ClassicConsumerKind::MediaDefaults)
            || (reacquisition_mode && area == ClassicConsumerKind::DiMode)
    };
    assert_eq!(
        candidates.iter().filter(|part| selected(part.area)).count(),
        usize::from(initialize_mode) + usize::from(reacquisition_mode),
        "each requested initialization role must bind exactly once"
    );
    for part in candidates.iter().filter(|part| selected(part.area)) {
        assert_eq!(
            &report.image[part.site..part.site + part.original.len()],
            part.original
        );
        let stub = Mt1959Engine
            .free_space(&report.image, part.bytes.len())
            .unwrap();
        assert!(matches!(part.original.len(), 4 | 6));
        let mut redirect = thumb_asm::encode_bl(part.site, stub).unwrap().to_vec();
        if part.original.len() == 6 {
            redirect.extend_from_slice(&[0xc0, 0x46]);
        }
        thumb_asm::write(&mut report.image, part.site, &redirect);
        thumb_asm::write(&mut report.image, stub as usize, &part.bytes);
        crate::install_guard::verify_branch(
            &report.image,
            part.site,
            thumb_asm::BranchKind::Bl,
            stub,
            "initialization mode research",
        )
        .unwrap();
        installed.push(serde_json::json!({
            "role":format!("{:?}", part.area), "site":part.site, "entry":part.caller.entry(),
            "stub_va":stub, "stub":part.bytes, "original":part.original,
        }));
    }
    let di = research::di_detection_candidate(image, flags).unwrap();
    let stub = Mt1959Engine
        .free_space(&report.image, di.bytes.len())
        .unwrap();
    let site = di.contract.prevalidation;
    assert_eq!(&report.image[site..site + di.original.len()], di.original);
    let mut branch = thumb_asm::encode_bl(site, stub).unwrap().to_vec();
    branch.extend_from_slice(&[0xc0, 0x46, 0xc0, 0x46]);
    thumb_asm::write(&mut report.image, site, &branch);
    thumb_asm::write(&mut report.image, stub as usize, &di.bytes);
    crate::install_guard::verify_branch(
        &report.image,
        site,
        thumb_asm::BranchKind::Bl,
        stub,
        "DI research",
    )
    .unwrap();
    // Every other routing component stays native, including read and acquisition.
    for part in plan
        .routing_candidates(image, flags)
        .unwrap()
        .iter()
        .map(|p| (p.site, &p.original))
        .chain(
            candidates
                .iter()
                .filter(|p| !selected(p.area))
                .map(|p| (p.site, &p.original)),
        )
    {
        assert_eq!(&report.image[part.0..part.0 + part.1.len()], part.1);
    }
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
    let receipt = serde_json::json!({
        "policy":"research comparison only; acquisition, detection and reading unproven",
        "producer_version":env!("CARGO_PKG_VERSION"),
        "source_sha256":digest(image), "output_sha256":digest(&report.image),
        "flag_base":flags, "state":di.contract.state, "site":site, "stub_va":stub,
        "stub":di.bytes, "original":di.original, "entry":di.contract.entry,
        "format":di.contract.format, "format_flag":di.contract.format_flag,
        "layer_store":di.contract.layer_store, "epilogue":di.contract.epilogue,
        "formats":[1,5], "read_path":false, "initialization_mode":initialize_mode,
        "reacquisition_mode":reacquisition_mode,
        "mode_entry":mode_candidates[0].caller.entry(),
        "installed_initialization_components":installed,
    });
    (report.image, receipt)
}

#[test]
fn mode_comparison_keeps_read_and_acquisition_components_native() {
    build(
        include_bytes!("../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin"),
        true,
        true,
    );
}

#[test]
fn build_selected_initialization_comparison() {
    let Ok(source) = std::env::var("FREEMKV_MT1939_RESEARCH_SOURCE") else {
        return;
    };
    let image = std::fs::read(source).unwrap();
    assert_eq!(
        digest(&image),
        std::env::var("FREEMKV_MT1939_RESEARCH_SHA256").unwrap()
    );
    let output = std::path::PathBuf::from(std::env::var("FREEMKV_MT1939_RESEARCH_OUTPUT").unwrap());
    for (initialize_mode, reacquisition_mode, suffix) in [
        (false, false, "baseline"),
        (true, false, "mode"),
        (true, true, "reacquisition"),
    ] {
        let (image, receipt) = build(&image, initialize_mode, reacquisition_mode);
        std::fs::write(output.with_extension(format!("{suffix}.bin")), image).unwrap();
        std::fs::write(
            output.with_extension(format!("{suffix}.json")),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
    }
}
