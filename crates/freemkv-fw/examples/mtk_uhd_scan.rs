//! Read-only instruction-contract survey; does not infer physical UHD capability.
//! Usage: cargo run -p freemkv-fw --example mtk_uhd_scan -- OUTPUT.json [--modify-pairs] ROOT ...
use anyhow::{bail, Context, Result};
use mediatek_optical::image::analysis::{
    AuthCell, ClassicCalibration, ClassicConsumer, ClassicDi, ClassicParameter, ClassicPosition,
    ClassicPositionSetup, ClassicReadCompletion, ClassicReadPosition, CommandDispatch, MediaGate,
    UhdArea, UhdAreas,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn collect(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            collect(&entry?.path(), files)?;
        }
    } else if path.extension().is_some_and(|e| e == "bin") {
        files.push(path.to_owned());
    }
    Ok(())
}

fn has_tar_header(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..512) else {
        return false;
    };
    let octal = |field: &[u8]| {
        std::str::from_utf8(field)
            .ok()
            .and_then(|s| usize::from_str_radix(s.trim_matches(['\0', ' ']), 8).ok())
    };
    let checksum: usize = header
        .iter()
        .enumerate()
        .map(|(i, &b)| usize::from(if (148..156).contains(&i) { b' ' } else { b }))
        .sum();
    header[0] != 0
        && octal(&header[148..156]) == Some(checksum)
        && octal(&header[124..136]).is_some_and(|size| size <= bytes.len() - 512)
}

fn scan(bytes: &[u8]) -> Value {
    // A tar member's relative branches can still resemble firmware while its
    // absolute literals address the wrong load base. Never classify that source
    // as executable firmware. V7 headers may have no ustar magic.
    if has_tar_header(bytes) {
        return json!({"classification":"non_firmware_container", "di_recognition":"unknown",
            "explicit_roles":0, "legacy_roles":0, "unknown_roles":7, "state_cell":null,
            "areas":UhdArea::ALL.iter().map(|role|json!({"role":format!("{role:?}"),
                "evidence":"unknown", "error":"normalize_archive_member_first"})).collect::<Vec<_>>(),
            "access_policy":"not_determined_by_this_scan", "physical_reading":"not_determined_by_this_scan"});
    }
    let analysis = UhdAreas::inspect(bytes);
    let mut areas = Vec::new();
    let mut native = 0;
    let mut legacy = 0;
    let mut missing = 0;
    let mut recognition = "unknown";
    for role in UhdArea::ALL {
        match analysis.area(role) {
            Ok(contract) => {
                let evidence = match contract.selects_c7() {
                    Some(true) => {
                        native += 1;
                        "explicit_u_or_c7"
                    }
                    Some(false) => {
                        legacy += 1;
                        "recognized_legacy_path"
                    }
                    None => "hardware_policy_only",
                };
                if role == UhdArea::DiscInformation {
                    recognition = evidence;
                }
                areas.push(json!({"role":format!("{role:?}"), "evidence":evidence,
                    "variant":contract.variant(), "site":contract.site(), "length":contract.length(),
                    "literals":contract.literals().iter().map(|p| json!({"instruction":p.instruction,"value":p.value})).collect::<Vec<_>>(),
                    "edges":contract.edges().iter().map(|p| json!({"instruction":p.instruction,"target":p.target})).collect::<Vec<_>>() }));
            }
            Err(error) => {
                missing += 1;
                areas.push(json!({"role":format!("{role:?}"),"evidence":"unknown", "error":format!("{error:?}")}));
            }
        }
    }
    let state = analysis.state_address();
    let legacy_dependencies = if legacy != 0 {
        state.as_ref().ok().map(|&cell| {
            let result = |name: &str,
                          value: std::result::Result<
                String,
                mediatek_optical::image::analysis::Error,
            >| {
                match value {
                    Ok(contract) => json!({"role":name,"bound":true,"contract":contract}),
                    Err(error) => json!({"role":name,"bound":false,"error":format!("{error:?}")}),
                }
            };
            vec![
                result("DI", ClassicDi::detect(bytes).map(|c| format!("{c:?}"))),
                result(
                    "auxiliary_selectors",
                    ClassicConsumer::inspect(bytes, cell).map(|c| format!("{c:?}")),
                ),
                result(
                    "position",
                    ClassicPosition::detect(bytes, cell).map(|c| format!("{c:?}")),
                ),
                result(
                    "position_setup",
                    ClassicPositionSetup::detect(bytes, cell).map(|c| format!("{c:?}")),
                ),
                result(
                    "read_position",
                    ClassicReadPosition::detect(bytes, cell).map(|c| format!("{c:?}")),
                ),
                result(
                    "parameters",
                    ClassicParameter::detect(bytes, cell).map(|c| format!("{c:?}")),
                ),
                result(
                    "calibration",
                    ClassicCalibration::detect(bytes, cell).map(|c| format!("{c:?}")),
                ),
                result(
                    "completion",
                    ClassicReadCompletion::inspect(bytes, cell).map(|c| format!("{c:?}")),
                ),
            ]
        })
    } else {
        None
    };
    let classification = if missing != 0 || state.is_err() {
        "unknown_or_partial"
    } else if native == 6 {
        "native_uhd_code_in_reviewed_roles"
    } else if legacy == 6 {
        "legacy_code_in_reviewed_roles"
    } else {
        "mixed_reviewed_roles"
    };
    let protocol = CommandDispatch::inspect(bytes).map(|dispatch| {
        dispatch.records().iter().filter(|record| matches!(record.opcode,0x00|0x03|0x28|0x46|0xa3|0xa4|0xa8|0xad))
            .map(|record|json!({"opcode":record.opcode,"record":record.off,"flags":record.flags,"handler":record.handler}))
            .collect::<Vec<_>>()
    });
    let media_gate = MediaGate::inspect(bytes).map(|gate|json!({"variant":format!("{:?}",gate.variant()),
        "anchor":gate.anchor(),"uhd_site":gate.uhd_site(),"bd_site":gate.bd_site(),"deny":gate.deny()}));
    let auth_cell = AuthCell::detect(bytes).map(|gate| format!("{gate:?}"));
    let sense_setter = freemkv_fw::engine::mt1959::Mt1959Engine.sense_setter(bytes);
    json!({"classification":classification,"di_recognition":recognition,
        "explicit_roles":native,"legacy_roles":legacy,"unknown_roles":missing,
        "state_cell":state.as_ref().ok(), "state_binding_error":state.err().map(|e|format!("{e:?}")),
        "areas":areas,"legacy_dependencies":legacy_dependencies,
        "native_commands":protocol.as_ref().ok(),"native_commands_error":protocol.err().map(|e|format!("{e:?}")),
        "media_gate":media_gate.as_ref().ok(),"media_gate_error":media_gate.err().map(|e|format!("{e:?}")),
        "auth_cell":auth_cell.as_ref().ok(),"auth_cell_error":auth_cell.err().map(|e|format!("{e:?}")),
        "sense_setter":sense_setter.ok(),
        "access_policy":"not_determined_by_this_scan", "physical_reading":"not_determined_by_this_scan"})
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let output = args
        .next()
        .context("usage: mtk_uhd_scan OUTPUT.json ROOT ...")?;
    let mut files = Vec::new();
    let mut modify_pairs = false;
    for root in args {
        if root == "--modify-pairs" {
            modify_pairs = true;
        } else {
            collect(Path::new(&root), &mut files)?;
        }
    }
    if files.is_empty() {
        bail!("no .bin inputs");
    }
    files.sort();
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    let mut totals = BTreeMap::<String, usize>::new();
    let mut unidentified = 0;
    for path in files {
        let bytes = std::fs::read(&path)?;
        let hash = format!("{:x}", Sha256::digest(&bytes));
        if !seen.insert(hash.clone()) {
            continue;
        }
        // Identification labels the report only. Missing banners and other
        // chip generations must still be scanned, not silently excluded.
        let chip = freemkv_fw::family::detect_chip(&bytes).ok();
        if chip.is_none() {
            unidentified += 1;
        }
        let evidence = scan(&bytes);
        let pair = if modify_pairs {
            let defaults = freemkv_fw::boot::BootSettings::parse(&["unrestricted=on".to_owned()])?;
            Some(
                match freemkv_fw::api::modify_with_defaults(&bytes, &defaults) {
                    Ok((report, _)) => {
                        let regions = evidence["areas"].as_array().unwrap().iter().filter_map(|area| {
                        let start = area["site"].as_u64()? as usize;
                        let length = area["length"].as_u64()? as usize;
                        Some(json!({"role":area["role"], "site":start, "length":length,
                            "original_region_unchanged":bytes[start..start+length] == report.image[start..start+length]}))
                    }).collect::<Vec<_>>();
                        json!({"status":"built_offline_not_hardware_tested",
                        "output_sha256":format!("{:x}",Sha256::digest(&report.image)),
                        "reviewed_regions":regions, "modified_scan":scan(&report.image),
                        "levers":report.levers.iter().map(|lever| json!({"id":format!("{:?}",lever.id),
                            "outcome":format!("{:?}",lever.outcome), "facts":lever.facts,
                            "hooks":lever.hooks.iter().map(|hook| json!({"id":hook.id,"variant":hook.variant,"reason":hook.reason})).collect::<Vec<_>>()
                        })).collect::<Vec<_>>()})
                    }
                    Err(error) => json!({"status":"refused", "error":format!("{error:#}")}),
                },
            )
        } else {
            None
        };
        *totals
            .entry(evidence["classification"].as_str().unwrap().to_owned())
            .or_default() += 1;
        let sidecar = path.with_extension("bin.json");
        let provenance = if sidecar.is_file() {
            Some(serde_json::from_slice::<Value>(&std::fs::read(sidecar)?)?)
        } else {
            None
        };
        rows.push(
            json!({"path":path,"sha256":hash,"bytes":bytes.len(),"model":chip.as_ref().map(|c| &c.model),
            "family":chip.as_ref().map(|c| c.family.label()),"provenance":provenance,"uhd_code":evidence,"our_modified_pair":pair}),
        );
        if rows.len() % 25 == 0 {
            eprintln!("scanned {} distinct MediaTek images", rows.len());
        }
    }
    std::fs::write(
        output,
        serde_json::to_vec_pretty(&json!({
            "schema":"mtk-uhd-code-evidence-v1", "producer_version":env!("CARGO_PKG_VERSION"),
            "limits":"Seven reviewed instruction roles only; no proof of complete acquisition, density handling, access permission, or physical reading. Unknown is not absence. Signatures never select by model or hash.",
            "unidentified_inputs_scanned":unidentified,"images":rows,"totals":totals
        }))?,
    )?;
    eprintln!("finished: {} distinct images; {totals:?}", rows.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::scan;

    #[test]
    fn native_and_legacy_code_have_distinct_evidence_without_hardware_claims() {
        let native = scan(include_bytes!("../tests/fixtures/BU40N_OEM_1.00.bin"));
        let legacy = scan(include_bytes!(
            "../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin"
        ));
        assert_eq!(
            native["classification"],
            "native_uhd_code_in_reviewed_roles"
        );
        assert_eq!(legacy["classification"], "legacy_code_in_reviewed_roles");
        for result in [&native, &legacy] {
            assert_eq!(result["physical_reading"], "not_determined_by_this_scan");
            assert_eq!(result["access_policy"], "not_determined_by_this_scan");
        }
    }

    #[test]
    fn unrecognized_bytes_remain_unknown() {
        let result = scan(&vec![0xff; 4096]);
        assert_eq!(result["classification"], "unknown_or_partial");
        assert_eq!(result["di_recognition"], "unknown");
        assert_eq!(result["unknown_roles"], 7);
    }

    #[test]
    fn v7_tar_wrapped_firmware_requires_payload_normalization() {
        let payload = include_bytes!("../tests/fixtures/BU40N_OEM_1.00.bin");
        let mut archive = vec![0_u8; 512 + payload.len()];
        archive[..12].copy_from_slice(b"firmware.bin");
        let size = format!("{:011o}\0", payload.len());
        archive[124..136].copy_from_slice(size.as_bytes());
        archive[148..156].fill(b' ');
        let sum: usize = archive[..512].iter().map(|&b| usize::from(b)).sum();
        archive[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        archive[512..].copy_from_slice(payload);
        assert_eq!(scan(&archive)["classification"], "non_firmware_container");
        assert_eq!(
            scan(payload)["classification"],
            "native_uhd_code_in_reviewed_roles"
        );
    }
}
