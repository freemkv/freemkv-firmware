//! Device-free Pioneer planning regressions; no extra public CLI command.

use freemkv_flash::drive::{pioneer::Pioneer, InputKind};
use freemkv_flash::engine::plan_pioneer_offline;
use freemkv_flash::pioneer_bundle::{Bundle, Role};
use sha2::{Digest, Sha256};
use std::process::Command;

#[test]
fn public_cli_has_only_info_backup_and_flash() {
    let help = Command::new(env!("CARGO_BIN_EXE_freemkv-flash"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let output = String::from_utf8(help.stdout).unwrap();
    assert!(output.contains("info"));
    assert!(output.contains("backup"));
    assert!(output.contains("flash"));
    assert!(!output.contains("plan-pioneer"));
}

fn configured_bundle(name: &str) -> Option<Vec<u8>> {
    let path = std::env::var_os(name)?;
    Some(std::fs::read(path).expect("configured Pioneer bundle is readable"))
}

#[test]
fn audited_normal_bundle_still_plans_without_a_device() {
    let Some(bytes) = configured_bundle("PIONEER_UD04_BUNDLE_FIXTURE") else {
        return;
    };
    plan_pioneer_offline(
        &bytes,
        InputKind::PioneerBundle,
        "BDR-UD04",
        false,
        false,
        false,
        &Pioneer::new(),
    )
    .unwrap();
}

#[test]
fn supplied_ud04_kernel_and_normal_plan_matches_autoflasher_path() {
    let Some(bytes) = configured_bundle("PIONEER_UD04_AUTOFLASHER_BUNDLE_FIXTURE") else {
        return;
    };
    plan_pioneer_offline(
        &bytes,
        InputKind::PioneerBundle,
        "BDR-UD04",
        false,
        false,
        false,
        &Pioneer::new(),
    )
    .unwrap();
    let bundle = Bundle::from_tar_bytes(&bytes).unwrap();
    let kernel = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .unwrap();
    let normal = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .unwrap();
    let steps = freemkv_flash::drive::pioneer::offline_ud04_autoflasher_data_out(
        &kernel.bytes,
        &normal.bytes,
    )
    .unwrap();
    assert_eq!(steps.len(), 64);
    let mut digest = Sha256::new();
    for step in &steps {
        digest.update(step.cdb);
        digest.update(&step.data);
    }
    assert_eq!(
        format!("{:x}", digest.finalize()),
        "b7d0d1d955711050b6ea6d38d66218669476e06e98e2d3dd46c8dcccbaa33815"
    );
}

#[test]
fn audited_single_updater_bundle_plans_and_dual_variant_fails_closed() {
    if let Some(bytes) = configured_bundle("PIONEER_BOUNDED_SINGLE_BUNDLE_FIXTURE") {
        plan_pioneer_offline(
            &bytes,
            InputKind::PioneerBundle,
            "BDR-212M",
            false,
            false,
            false,
            &Pioneer::new(),
        )
        .unwrap();
    }
    if let Some(bytes) = configured_bundle("PIONEER_BOUNDED_DUAL_BUNDLE_FIXTURE") {
        assert!(plan_pioneer_offline(
            &bytes,
            InputKind::PioneerBundle,
            "BDR-209",
            false,
            false,
            false,
            &Pioneer::new(),
        )
        .is_err());
    }
}
