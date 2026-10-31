//! Build through the production API and export source-bound execution contracts.
//! Files are private test inputs; stdout contains only the result manifest.
use anyhow::{ensure, Context, Result};
use freemkv_fw::{api, artifact::Artifact, boot::BootSettings, engine};
use mediatek_optical::image::analysis::{ClassicSpeed, ResponseIo};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let source = PathBuf::from(args.next().context("source")?);
    let directory = PathBuf::from(args.next().context("private output directory")?);
    let input = std::fs::read(source)?;
    std::fs::create_dir_all(&directory)?;
    let source_hash = digest(&input);
    let artifact = match Artifact::parse(input) {
        Ok(a) => a,
        Err(_) => {
            println!(
                "{}",
                json!({"input_sha256":source_hash,"status":"invalid-input"})
            );
            return Ok(());
        }
    };
    let original = artifact.image();
    let defaults = BootSettings::standard();
    let (report, support) = match api::modify_with_defaults(original, &defaults) {
        Ok(value) => value,
        Err(error) => {
            let issue = freemkv_flash::workflow::user_error(&error);
            println!(
                "{}",
                json!({"input_sha256":source_hash,"status":"unsupported","reason":issue.id,"detail":format!("{error:#}")})
            );
            return Ok(());
        }
    };
    let structural = engine::audit::audit_image(original, &report);
    if !structural.ok() {
        let failures: Vec<_> = structural
            .failures()
            .map(|c| json!({"lever":c.lever,"what":c.what,"detail":c.detail}))
            .collect();
        std::fs::write(directory.join("failed-original.bin"), original)?;
        std::fs::write(directory.join("failed-produced.bin"), &report.image)?;
        std::fs::write(directory.join("failed-api-report.json"), report.to_json())?;
        std::fs::write(
            directory.join("audit-failure.json"),
            serde_json::to_vec_pretty(&json!({
                "input_sha256":source_hash,"canonical_sha256":digest(original),
                "output_sha256":digest(&report.image),"failures":failures
            }))?,
        )?;
        anyhow::bail!(
            "output structural audit: {}",
            serde_json::to_string(&failures)?
        );
    }
    ensure!(api::verify(&report.image, None)?.ok, "output integrity");
    freemkv_flash::crossflash::admits(
        freemkv_flash::crossflash::Platform::Mediatek,
        original,
        &report.image,
    )?;
    let mut serialized: Value =
        serde_json::from_str(&defaults.report_json(&support, &report.to_json()))?;
    let facts: std::collections::BTreeMap<_, _> = report
        .levers
        .iter()
        .flat_map(|lever| lever.facts.iter().copied())
        .collect();
    let core = engine::mt1959::Mt1959Engine;
    let mut contracts = json!({});
    if facts.contains_key("handler_va") {
        let boot_site = *facts.get("boot_init_site").context("boot site")? as usize;
        let boot_stub = *facts.get("boot_stub_va").context("boot stub")? as usize;
        let flags = thumb_asm::analysis::literal_value(&report.image, boot_stub + 2)
            .context("installed boot flags literal")?;
        ensure!(
            facts.get("flag_base").is_none_or(|v| *v == flags),
            "flag-base disagreement"
        );
        let boot_target = thumb_asm::isa::decode_at(original, boot_site)
            .filter(|i| i.mnemonic == "bl")
            .and_then(|i| i.branch_target())
            .context("native boot call")?;
        let record_off = facts["record_off"] as usize;
        let original_handler =
            u32::from_le_bytes(original[record_off + 4..record_off + 8].try_into()?) & !1;
        contracts["base"] = json!({"handler":facts["handler_va"],"handler_len":facts["handler_len"],
            "original_handler":original_handler,"flags":flags,
            "cdb":core.find_cdb_base(original)?,"writer":ResponseIo::inspect(original)?.writer(),
            "native_reset":core.find_aacs_session_reset(original).ok(),
            "boot_site":boot_site,"boot_stub":boot_stub,"boot_target":boot_target,
            "defaults":defaults.flags()});
    }
    if facts.get("speed_tail_site").is_some_and(|v| *v != 0) {
        let role = ClassicSpeed::detect(original)?;
        ensure!(
            facts["speed_tail_site"] as usize == role.site(),
            "classic speed role"
        );
        contracts["speed"] = json!({"variant":"classic","entry":role.entry(),"site":role.site(),
            "media_cell":role.media_cell(),"maximum_cell":role.maximum_cell()});
    } else if facts.get("speed_gate").is_some_and(|v| *v != 0) {
        let (gate, index) = core.find_speed_gate(original)?;
        ensure!(gate == facts["speed_gate"], "speed role");
        let site = gate as usize + 4;
        let exit = thumb_asm::isa::decode_at(original, site + 2)
            .filter(|i| i.mnemonic == "b" && i.cond == Some(thumb_asm::Cond::Hi))
            .and_then(|i| i.branch_target())
            .context("native ramp exit")?;
        contracts["speed"] = json!({"variant":"ramp","site":site,"index":index,
            "fallthrough":site+4,"exit":exit});
    }
    if let Some(&site) = facts.get("auth_cell_site") {
        let site = site as usize;
        let comparison = u16::from_le_bytes(original[site..site + 2].try_into()?);
        ensure!(
            matches!(comparison, 0x280c | 0x290c),
            "auth comparison contract"
        );
        let branch = thumb_asm::isa::decode_at(original, site + 2)
            .filter(|i| i.mnemonic == "b" && i.cond == Some(thumb_asm::Cond::Ne))
            .and_then(|i| i.branch_target())
            .context("auth native refusal edge")?;
        contracts["auth_cell"] = json!({"site":site, "deny":branch,
            "value_register":(comparison >> 8) & 7,
            "native_refusal": mediatek_optical::image::analysis::AuthCell::detect(original).ok().filter(|c| c.variant() == mediatek_optical::image::analysis::AuthCellVariant::R0StateR1Alternate).map(|c| c.refusal())});
    }
    let media_sites: Vec<_> = ["bd_site", "uhd_site"]
        .into_iter()
        .filter_map(|name| {
            facts
                .get(name)
                .filter(|&&site| site != 0)
                .map(|&site| json!({"role":name,"site":site}))
        })
        .collect();
    if !media_sites.is_empty() {
        ensure!(media_sites.len() == 2, "only one media gate was installed");
        contracts["media_gates"] = json!(media_sites);
    }
    let advertised: std::collections::BTreeMap<_, _> = freemkv_fw::boot::BootFeature::ALL
        .iter()
        .map(|f| (f.key(), f.choices()))
        .collect();
    contracts["advertised_boot_choices"] = json!(advertised);
    contracts["facts"] = json!(facts);
    contracts["classic_application_readiness"] =
        match engine::mt1939_uhd::UhdConversionPlan::inspect(original) {
            Ok(plan) => {
                json!({"status":"source-bound","remaining_contracts":plan.remaining_contracts(),
            "complete_group_ready":plan.require_complete_conversion().is_ok()})
            }
            Err(error) => json!({"status":"not-bound","reason":format!("{error:#}")}),
        };
    contracts["media_conversion_sites"] = json!([]);
    contracts["media_conversion_helpers"] = json!([]);
    if report.levers.iter().flat_map(|l| &l.hooks).any(|h| {
        h.id == "uhd-conversion"
            && h.variant
                .as_ref()
                .is_some_and(|v| v.starts_with("complete media group:"))
    }) {
        let flags = contracts["base"]["flags"]
            .as_u64()
            .context("conversion flags")? as u32;
        let classic = report.levers.iter().flat_map(|l| &l.hooks).any(|h| {
            h.id == "uhd-conversion"
                && h.variant
                    .as_ref()
                    .is_some_and(|v| v.starts_with("complete media group: classic "))
        });
        let mut metadata = std::collections::BTreeMap::<usize, Value>::new();
        let patches: Vec<(String, usize, Vec<u8>, Vec<u8>)> = if classic {
            let plan = engine::mt1939_uhd::UhdConversionPlan::inspect(original)?;
            plan.require_complete_conversion()?;
            contracts["conversion_state"] = json!(plan.state_address());
            macro_rules! routing { ($items:expr)=>{for c in $items {
                metadata.insert(c.site,json!({"kind":"selection","accept":c.accept,"reject":c.reject,
                    "region_start":c.region_start,"calculation_end":c.calculation_end,"state":plan.state_address()}));
            }}; }
            routing!(plan.routing_candidates(original, flags)?);
            routing!(plan.auxiliary_candidates(original, flags)?);
            routing!(plan.completion_candidates(original, flags)?);
            routing!(plan.position_candidates(original, flags)?);
            routing!(plan.position_setup_candidates(original, flags)?);
            let (decode, ranges) = plan.read_position_candidates(original, flags)?;
            routing!(ranges);
            metadata.insert(
                decode.contract.decode.site(),
                json!({"kind":"read_position_decode",
                "accept":decode.contract.decode.accept(),"reject":decode.contract.decode.reject(),
                "layer_one":decode.contract.layer_one,"layer_zero":decode.contract.layer_zero,
                "position":decode.contract.position,"position_register":decode.contract.position_register,
                "state":plan.state_address()}),
            );
            let parameter = plan.parameter_candidate(original, flags)?;
            if let Some(c) = plan.calibration_candidate(original, flags)? {
                metadata.insert(c.contract.site,json!({"kind":"calibration","original_base":c.contract.original_base,
                    "base_adjustment":c.contract.base_adjustment,
                    "rate_count":parameter.contract.rate_count,
                    "coefficients_are_runtime":parameter.contract.coefficients_are_runtime,
                    "c8_coefficients":c.contract.c7_coefficients,"continuation":c.contract.site+6,"state":plan.state_address()}));
            }
            contracts["native_parameter_getter"] = json!({"variant":format!("{:?}",parameter.contract.variant),
                "entry":parameter.contract.entry,"lookup":parameter.contract.lookup,"rates":parameter.contract.rates,
                "rate_count":parameter.contract.rate_count,"coefficients_are_runtime":parameter.contract.coefficients_are_runtime,
                "coefficients":parameter.contract.coefficients,"oem_coefficients":parameter.contract.oem_coefficients,
                "state":plan.state_address(),"returns":parameter.contract.caller.returns(),
                "scope":"Source-bound full-getter diagnostic context; final-selector tests do not establish complete C7 calibration-profile equivalence"});
            if let Some(c) = parameter.hook {
                routing!([c]);
            }
            if let Ok(di) = mediatek_optical::image::analysis::ClassicDi::detect(original) {
                metadata.insert(di.prevalidation,json!({"kind":"di","state":di.state,"entry":di.entry,
                    "replay_continuation":di.replay_continuation,"format":di.format,"format_flag":di.format_flag,
                    "layers":di.layers,"layer_store":di.layer_store,"epilogue":di.epilogue,"one_register":di.one_register}));
            } else {
                let di = mediatek_optical::image::analysis::LegacyStackDi::detect(original)?;
                let mut info = json!({"kind":"legacy_di_admission","state":di.state,"entry":di.caller.entry(),
                    "frame_bytes":di.caller.stack_bytes(),"prevalidation":di.prevalidation,
                    "replay_continuation":di.replay_continuation,"format":di.format,"format_flag":di.format_flag,
                    "layers":di.layers,"layer_store":di.layer_store,"after_layers":di.after_layers,
                    "stack_block":di.stack_block,"identifier_offset":di.identifier_offset,
                    "state_register":di.state_register,"returns":di.caller.returns()});
                metadata.insert(di.prevalidation, info.clone());
                info["kind"] = json!("legacy_di_layers");
                metadata.insert(di.layers, info);
            }
            use mediatek_optical::image::analysis::{ClassicConsumer, ClassicConsumerKind};
            contracts["preserved_native_workflows"] = match ClassicConsumer::inspect_kind(
                original,
                plan.state_address(),
                ClassicConsumerKind::ReadBoundary,
            ) {
                Ok(c) => {
                    ensure!(
                        c.entry_media_family == Some(0xf),
                        "recovery family guard not established"
                    );
                    let start = c.caller.entry();
                    let end = c
                        .caller
                        .returns()
                        .iter()
                        .copied()
                        .max()
                        .context("recovery native returns")?
                        + 2;
                    ensure!(
                        original.get(start..end) == report.image.get(start..end),
                        "F-family recovery workflow changed"
                    );
                    json!([{"role":"F-family ReadBoundary recovery","entry_media_family":15,"start":start,"end":end,
                        "selector":c.selection.site(),"source_span_sha256":digest(&original[start..end]),"output_span_sha256":digest(&report.image[start..end]),
                        "status":"source-span-preserved","limits":"Native span identity only; no state-immutability or complete hardware lifecycle claim"}])
                }
                Err(error) => {
                    json!([{"role":"F-family ReadBoundary recovery","status":"not-bound; not required or modified for ROM reading",
                    "reason":error.to_string(),"limits":"No absence or dynamic reachability claim"}])
                }
            };
            plan.prepared_patches(original, flags)?
                .into_iter()
                .map(|c| (c.role, c.site, c.original, c.bytes))
                .collect()
        } else {
            let plan = engine::mt1959_uhd::Plan::inspect(original, flags)?;
            ensure!(
                plan.pending().is_empty(),
                "installed incomplete media conversion"
            );
            plan.candidates()
                .iter()
                .map(|c| {
                    (
                        c.gap.id().to_owned(),
                        c.site,
                        c.original.clone(),
                        c.bytes.clone(),
                    )
                })
                .collect()
        };
        let mut helpers = Vec::new();
        for (role, site, old, bytes) in patches {
            let target = thumb_asm::isa::decode_at(&report.image, site)
                .filter(|i| i.mnemonic == "bl")
                .and_then(|i| i.branch_target())
                .context("installed conversion BL")? as usize;
            ensure!(
                report.image.get(target..target + bytes.len()) == Some(bytes.as_slice()),
                "installed conversion helper differs"
            );
            helpers.push(json!({"role":role,"site":site,"target":target,"original_bytes":old,
                "original_sha256":digest(&old),"helper_sha256":digest(&bytes),"helper_len":bytes.len(),
                "contract":metadata.get(&site)}));
        }
        contracts["media_conversion_sites"] = json!(helpers
            .iter()
            .map(|c| c["site"].as_u64().unwrap())
            .collect::<Vec<_>>());
        contracts["media_conversion_helpers"] = json!(helpers);
    }
    let canonical_hash = digest(original);
    let output_hash = digest(&report.image);
    std::fs::write(directory.join("original.bin"), original)?;
    std::fs::write(directory.join("modified.bin"), &report.image)?;
    serialized["execution_contracts"] = contracts;
    std::fs::write(
        directory.join("modify.json"),
        serde_json::to_vec_pretty(&serialized)?,
    )?;
    println!(
        "{}",
        json!({"input_sha256":source_hash,"canonical_sha256":canonical_hash,
        "output_sha256":output_hash,"status":if report.applied_count()>0 {"supported"} else {"unchanged"},
        "engine":report.engine,"report":"modify.json"})
    );
    Ok(())
}
