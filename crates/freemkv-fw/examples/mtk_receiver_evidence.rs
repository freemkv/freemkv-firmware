//! Read-only receiver evidence for allocation research; never authorizes changes.
use mediatek_optical::receiver::analysis::ApplicationAnalysis;

fn routing_evidence<R: std::fmt::Debug>(
    c: &freemkv_fw::engine::mtk_uhd::UhdRoutingCandidate<R>,
    bypass: Option<usize>,
) -> serde_json::Value {
    serde_json::json!({
        "area":format!("{:?}",c.area),"site":c.site,"original":c.original,
        "accept":c.accept,"reject":c.reject,"stub":c.bytes,
        "region_start":c.region_start,"calculation_end":c.calculation_end,
        "caller":{"entry":c.caller.entry(),"stack_bytes":c.caller.stack_bytes(),"returns":c.caller.returns()},
        "bypass":bypass,
    })
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: mtk_receiver_evidence IMAGE"))?;
    let image = std::fs::read(path)?;
    if let Some(offset) = std::env::args().nth(2) {
        if matches!(
            offset.as_str(),
            "installed-hrl" | "installed-region" | "installed-encryption"
        ) {
            let report: serde_json::Value = serde_json::from_slice(&std::fs::read(
                std::env::args()
                    .nth(3)
                    .ok_or_else(|| anyhow::anyhow!("report path required"))?,
            )?)?;
            let modified = std::fs::read(
                std::env::args()
                    .nth(4)
                    .ok_or_else(|| anyhow::anyhow!("modified image required"))?,
            )?;
            let facts: std::collections::BTreeMap<_, _> = report["levers"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("missing levers"))?
                .iter()
                .flat_map(|lever| lever["facts"].as_object().into_iter().flatten())
                .filter_map(|(key, value)| value.as_u64().map(|v| (key.as_str(), v as usize)))
                .collect();
            if offset == "installed-encryption" {
                use thumb_asm::isa::{Operand, Reg};
                let engine = freemkv_fw::engine::mt1959::Mt1959Engine;
                let gate = *facts
                    .get("gatea_gate")
                    .ok_or_else(|| anyhow::anyhow!("missing VID gate"))?;
                let candidates: Vec<_> = [gate, gate + 18]
                    .into_iter()
                    .filter(|at| {
                        thumb_asm::isa::decode_at(&image, *at).is_some_and(|i| {
                            i.mnemonic == "cmp"
                                && i.operands.get(0) == Some(Operand::Reg(Reg(0)))
                                && i.operands.get(1) == Some(Operand::Imm(6))
                        })
                    })
                    .collect();
                anyhow::ensure!(candidates.len() == 1, "ambiguous VID comparison");
                let gate_site = candidates[0];
                let branch = thumb_asm::isa::decode_at(&image, gate_site + 2)
                    .ok_or_else(|| anyhow::anyhow!("missing VID branch"))?;
                anyhow::ensure!(
                    branch.mnemonic == "b" && branch.cond == Some(thumb_asm::Cond::Ne),
                    "VID comparison has no native BNE"
                );
                let gate_stub = facts["gatea_stub_va"];
                let flag_loads: Vec<_> = [gate_stub, gate_stub + 2]
                    .into_iter()
                    .filter_map(|at| thumb_asm::analysis::literal_value(&modified, at))
                    .collect();
                anyhow::ensure!(
                    flag_loads.len() == 1,
                    "missing or ambiguous encryption flag load"
                );
                let flag_slot = flag_loads[0];
                let ake_site = facts["ake_site"];
                let ake = thumb_asm::isa::decode_at(&image, ake_site)
                    .ok_or_else(|| anyhow::anyhow!("missing AKE instructions"))?;
                let variant = if ake.mnemonic == "lsr" {
                    "classic-shift"
                } else if ake.mnemonic == "bl" {
                    "shared-call"
                } else {
                    anyhow::ensure!(ake.mnemonic == "mov", "unknown AKE entry");
                    "reject-tail"
                };
                let agid = if facts.contains_key("gatea_authed") {
                    engine.find_vid_agid_struct_classic(&image)?
                } else {
                    engine.find_vid_agid_struct(&image)?
                };
                println!(
                    "{}",
                    serde_json::json!({"flag_slot":flag_slot,
                    "gate_site":gate_site,"accept":gate_site+4,"deny":branch.branch_target(),
                    "agid":agid,"reset":engine.find_aacs_session_reset(&image)?,
                    "setter":engine.find_vid_gate_setter(&image)?,"ake_site":ake_site,
                    "variant":variant,"deny_site":facts.get("deny_site")})
                );
                return Ok(());
            }
            if offset == "installed-region" {
                let stub = *facts
                    .get("region_stub_va")
                    .ok_or_else(|| anyhow::anyhow!("missing region stub"))?;
                let anchor = *facts
                    .get("region_emitter")
                    .ok_or_else(|| anyhow::anyhow!("missing region emitter"))?;
                let flag_slot = thumb_asm::analysis::literal_value(&modified, stub)
                    .ok_or_else(|| anyhow::anyhow!("missing region flag load"))?;
                let installed = thumb_asm::isa::decode_at(&modified, anchor + 6)
                    .ok_or_else(|| anyhow::anyhow!("missing region install"))?;
                anyhow::ensure!(
                    installed.mnemonic == "bl" && installed.branch_target() == Some(stub as u32),
                    "region install does not reach its reported stub"
                );
                println!(
                    "{}",
                    serde_json::json!({"entry":anchor,"flag_slot":flag_slot})
                );
                return Ok(());
            }
            let stub = *facts
                .get("hrl_stub_va")
                .ok_or_else(|| anyhow::anyhow!("missing HRL stub"))?;
            let flag_slot = thumb_asm::analysis::literal_value(&modified, stub + 2)
                .ok_or_else(|| anyhow::anyhow!("missing HRL flag load"))?;
            let mut sites = Vec::new();
            for (key, site) in &facts {
                if !key.starts_with("hrl_site") || *site == 0 {
                    continue;
                }
                let branch = thumb_asm::isa::decode_at(&image, site + 2)
                    .ok_or_else(|| anyhow::anyhow!("invalid native HRL branch"))?;
                anyhow::ensure!(
                    branch.mnemonic == "b" && branch.cond == Some(thumb_asm::Cond::Ne),
                    "native HRL branch is not BNE"
                );
                let installed = thumb_asm::isa::decode_at(&modified, *site)
                    .ok_or_else(|| anyhow::anyhow!("missing installed HRL branch"))?;
                anyhow::ensure!(
                    installed.mnemonic == "bl" && installed.branch_target() == Some(stub as u32),
                    "HRL install does not reach its reported stub"
                );
                let mut cursor = site + 4;
                let mut clean_end = None;
                for _ in 0..2 {
                    use thumb_asm::isa::{Operand, Reg};
                    let instruction = thumb_asm::isa::decode_at(&image, cursor)
                        .ok_or_else(|| anyhow::anyhow!("invalid HRL clean continuation"))?;
                    anyhow::ensure!(
                        matches!(instruction.mnemonic, "ldr" | "ldrb") && !instruction.sets_flags,
                        "HRL clean continuation needs further dataflow review"
                    );
                    anyhow::ensure!(!instruction.operands.as_slice().skip(1).any(|operand|
                        matches!(operand, Operand::Reg(Reg(0))) ||
                        matches!(operand, Operand::Mem(m) if m.base == Reg(0) || m.index.is_some_and(|(reg,_)|reg==Reg(0)))),
                        "HRL result is consumed before being replaced");
                    cursor += instruction.len();
                    if instruction.operands.get(0) == Some(Operand::Reg(Reg(0))) {
                        clean_end = Some(cursor);
                        break;
                    }
                }
                anyhow::ensure!(clean_end.is_some(), "HRL clean result lifetime is unproven");
                sites.push(serde_json::json!({"site":site,"revoke":branch.branch_target(),"clean_end":clean_end}));
            }
            println!(
                "{}",
                serde_json::json!({"flag_slot":flag_slot,"sites":sites})
            );
            return Ok(());
        }
        if offset == "ram-references" {
            let map = mediatek_optical::image::analysis::RamReferences::inspect(&image);
            println!(
                "{}",
                serde_json::json!({"bytes":map.bytes(),"incomplete":map.incomplete(),"calls":map.calls(),"uses":map.uses(),"fills":map.fills()})
            );
            return Ok(());
        }
        if offset == "speed-policy" {
            let p = mediatek_optical::image::analysis::NativeSpeedPolicy::detect(&image)?;
            println!(
                "{}",
                serde_json::json!({"variant":p.variant,"entry":p.entry,"length":p.length,
                "media_cell":p.media_cell,"maximum_cell":p.maximum_cell,"optimum_cell":p.optimum_cell,
                "hardware_cell":p.hardware_cell,"clamp":{"entry":p.clamp.entry,"compare":p.clamp.compare,
                "after_clamp":p.clamp.after_clamp,"request_register":p.clamp.request_register}})
            );
            return Ok(());
        }
        if offset == "uhd-conversion" {
            use freemkv_fw::engine::mtk_uhd::{
                emit_di_layers, emit_di_recognition, UhdConversionPlan,
            };
            use mediatek_optical::image::analysis::UhdArea;
            let plan = UhdConversionPlan::inspect(&image)?;
            let flags = 0x0200f000;
            let candidates = plan.routing_candidates(&image, flags)?;
            // Install both arithmetic selectors together in CPU tests. Their
            // native rejection paths share a branch, so isolated tests cannot
            // establish that the final pair has valid continuations.
            let calculation_group: Vec<_> = candidates.iter()
                .filter(|c| c.calculation_end.is_some()).enumerate()
                .map(|(index, c)| {
                    let stub_va = 0x1fc000 + index as u32 * 0x800;
                    Ok(serde_json::json!({"site":c.site,"stub_va":stub_va,
                        "branch":thumb_asm::encode_bl(c.site, stub_va)
                            .ok_or_else(|| anyhow::anyhow!("calculation test branch out of range"))?,
                        "stub":c.bytes}))
                }).collect::<anyhow::Result<_>>()?;
            let mut records: Vec<_> = candidates
                .iter()
                .map(|c| {
                    routing_evidence(
                        c,
                        if c.area == UhdArea::ParameterNibble {
                            Some(plan.areas().area(c.area).unwrap().edges()[0].target)
                        } else {
                            None
                        },
                    )
                })
                .collect();
            records.extend(
                plan.auxiliary_candidates(&image, flags)?
                    .iter()
                    .map(|c| routing_evidence(c, None)),
            );
            records.extend(
                plan.position_candidates(&image, flags)?
                    .iter()
                    .map(|c| routing_evidence(c, None)),
            );
            let parameter = plan.parameter_candidate(&image, flags)?;
            if let Some(hook) = &parameter.hook {
                let mut record = routing_evidence(hook, Some(parameter.contract.lookup));
                record["area"] = serde_json::json!("ParameterTable");
                records.push(record);
            }
            records.extend(
                plan.position_setup_candidates(&image, flags)?
                    .iter()
                    .map(|c| routing_evidence(c, None)),
            );
            let (read_position, range_candidates) = plan.read_position_candidates(&image, flags)?;
            records.extend(range_candidates.iter().map(|c| routing_evidence(c, None)));
            records.extend(
                plan.completion_candidates(&image, flags)?
                    .iter()
                    .map(|c| routing_evidence(c, None)),
            );
            let completion = mediatek_optical::image::analysis::ClassicReadCompletion::inspect(
                &image,
                plan.state_address(),
            )?;
            let calibration = plan.calibration_candidate(&image, flags)?;
            let di = freemkv_fw::engine::mtk_uhd::di_prevalidation_candidate(&image, flags).ok();
            println!(
                "{}",
                serde_json::json!({
                    "policy":"research component emission only; no image is written or UHD capability enabled",
                    "state":plan.state_address(), "flag_base":flags,
                    "calculation_group":calculation_group,
                    "pending":plan.remaining_contracts(),
                    "read_position":{"entry":read_position.contract.entry,"site":read_position.contract.decode.site(),
                        "position":read_position.contract.position,"layer":read_position.contract.layer,
                        "cached_layer":read_position.contract.cached_layer,"status":read_position.contract.status,
                        "stub":read_position.bytes,"original":read_position.original},
                    "calibration":calibration.as_ref().map(|c|serde_json::json!({
                        "entry":c.contract.caller.entry(),"site":c.contract.site,"resume":c.contract.site+6,
                        "original_base":c.contract.original_base,"coefficients":c.contract.c7_coefficients,
                        "original":c.original,"stub":c.bytes,
                        "caller":{"entry":c.contract.caller.entry(),"stack_bytes":c.contract.caller.stack_bytes(),"returns":c.contract.caller.returns()}
                    })),
                    "completion":{"recovery_region":completion.recovery_region,"recovery_end":completion.recovery_end,
                        "recovery_state_load":completion.recovery_state_load,"recovery_state_register":completion.recovery_state_register,
                        "recovery_request_register":completion.recovery_request_register,"recovery_flag_register":completion.recovery_flag_register,"recovery_caller":{"entry":completion.recovery_caller.entry(),"returns":completion.recovery_caller.returns()},"controller_region":completion.controller_region,"controller_end":completion.controller_region+0x6c,
                        "boundary_region":completion.boundary_region,"boundary_end":completion.boundary_end,"boundaries":completion.boundaries},
                    "parameter_profile":{
                        "variant":format!("{:?}",parameter.contract.variant),
                        "entry":parameter.contract.entry,"lookup":parameter.contract.lookup,
                        "rates":parameter.contract.rates,"coefficients":parameter.contract.coefficients,
                        "oem_coefficients":parameter.contract.oem_coefficients,
                        "patch_required":parameter.hook.is_some(),
                    },
                    "di_recognition":emit_di_recognition(flags)?, "di_layers":emit_di_layers(flags)?,
                    "di_entry":di.as_ref().map(|d| serde_json::json!({
                        "entry":d.contract.entry,"epilogue":d.contract.epilogue,
                        "site":d.contract.prevalidation,"resume":d.contract.replay_continuation,
                        "format":d.contract.format,"format_flag":d.contract.format_flag,"layers":d.contract.layers,
                        "layer_store":d.contract.layer_store,"one_register":d.contract.one_register,
                        "stub":d.bytes,"original":d.original,
                        "caller":{"entry":d.caller.entry(),"stack_bytes":d.caller.stack_bytes(),"returns":d.caller.returns()},
                    })),
                    "areas":UhdArea::ALL.iter().map(|&area| {
                        let contract = plan.areas().area(area).unwrap();
                        serde_json::json!({"area":format!("{area:?}"),"variant":contract.variant(),
                            "site":contract.site(),"action":format!("{:?}",plan.action(area).unwrap())})
                    }).collect::<Vec<_>>(),
                    "candidates":records,
                })
            );
            return Ok(());
        }
        if offset == "classic-speed-candidate" {
            let role = mediatek_optical::image::analysis::ClassicSpeed::detect(&image)?;
            let stub = freemkv_fw::engine::mt1959::Mt1959Engine
                .build_speed_stub_classic(0x0200f000, role.maximum_cell())?;
            println!(
                "{}",
                serde_json::json!({"entry":role.entry(),"site":role.site(),
                "maximum_cell":role.maximum_cell(),"optimum_cell":role.optimum_cell(),
                "media_cell":role.media_cell(),"consumer":role.consumer(),"flag_base":0x0200f000u32,
                "stub":stub,"branch":thumb_asm::encode_b_wide(role.site(), 0x1ff000)})
            );
            return Ok(());
        }
        if offset == "application-evidence" {
            let base = std::env::args()
                .nth(3)
                .map(|value| u32::from_str_radix(value.trim_start_matches("0x"), 16))
                .transpose()?
                .unwrap_or(0);
            let analysis = ApplicationAnalysis::inspect(&image, base)
                .ok_or_else(|| anyhow::anyhow!("invalid analysis range"))?;
            println!(
                "{}",
                serde_json::json!({
                    "policy":"component evidence only; control flow and helper semantics still require binding",
                    "conflicting_arguments":analysis.conflicting_arguments(),
                    "integrity":analysis.integrity_selections().iter().map(|p| serde_json::json!({
                        "address":p.address,"boot_check":p.boot_check,"application_check":p.application_check,
                        "success":p.success,"failure":p.failure,
                    })).collect::<Vec<_>>(),
                    "ranges":analysis.ranges().iter().map(|r| serde_json::json!({
                        "selection":r.selection.address,"end":r.selection.end,
                        "offset_cell":r.selection.offset_cell,"start_cell":r.selection.start_cell,
                        "length_cell":r.selection.length_cell,"plain_signature":r.signature.is_some(),
                    "state_slot":r.state_slot.as_ref().map(|p| serde_json::json!({
                        "prologue":p.prologue,"stack_bytes":p.stack_bytes,"slot":p.slot,
                        "save_call":p.save_call,"store":p.store,"restore_call":p.restore_call,
                        "epilogue":p.epilogue,"return_path":p.return_path,
                    })),
                        "acceptance":r.acceptance.map(|p| serde_json::json!({
                            "address":p.address,"program_call":p.program_call,"program_target":p.program_target,
                            "tag_check":p.tag_check,"marker_check":format!("{:?}",p.marker_check),"before_program":p.before_program,
                        "source_pointer_register":p.source_pointer_register,"failure_pointer_register":p.failure_pointer_register,
                        "continuation":p.continuation,"saved_state_offset":p.saved_state_offset,
                        })),
                    })).collect::<Vec<_>>(),
                    "bulk":analysis.bulk_decoders().iter().map(|p| serde_json::json!({
                        "selection":p.selection_address,"header_call":p.header.address,
                        "body_call":p.from_zero.address,"decoder":p.from_zero.target,
                    })).collect::<Vec<_>>(),
                })
            );
            return Ok(());
        }
        if offset == "program-candidates" {
            use mediatek_optical::receiver::programming::inspect_program_loop;
            let candidates: Vec<_> = (0..image.len())
                .step_by(2)
                .filter_map(|at| {
                    let proof = inspect_program_loop(&image[at..])?;
                    Some(serde_json::json!({
                        "address":at,"variant":format!("{:?}",proof.variant),"destination_cell":proof.destination_cell,
                        "source_offset_cell":proof.source_offset_cell,
                        "remaining_cell":proof.remaining_cell,"staging_cell":proof.staging_cell,
                        "copy_pointer_cell":proof.copy_pointer_cell,
                        "preserving_boot_spans":proof.preserving_boot_spans.iter()
                            .map(|r| [r.start,r.end]).collect::<Vec<_>>(),
                    }))
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "policy":"loop evidence only; caller, integrity and wrapper binding required",
                    "candidates":candidates,
                })
            );
            return Ok(());
        }
        if offset == "receiver-plan" {
            use mediatek_optical::{
                envelope::Envelope, layout, receiver::Receiver, update::InstalledFirmware,
                Identity, INQUIRY_LEN,
            };
            let envelope = Envelope::load(&image)?;
            let canonical = envelope.image();
            let identity = Identity::parse(
                &[0; INQUIRY_LEN],
                layout::BANNER.of(canonical).unwrap(),
                layout::DESCRIPTOR.of(canonical).unwrap(),
            )
            .ok_or_else(|| anyhow::anyhow!("firmware has no recognized MediaTek identity"))?;
            let installed = InstalledFirmware::new(identity, canonical)?;
            let receiver = Receiver::from_firmware(&envelope)
                .map_err(|e| anyhow::anyhow!("receiver evidence: {e:?}"))?;
            let prepared = receiver.prepare(&envelope, &installed)?;
            println!(
                "receiver=0x{:x} encoding={:?} programmed={:?} preserved={:?}",
                receiver.signature_address(),
                prepared.plan().encoding(),
                prepared.plan().programmed_ranges(),
                prepared.plan().preserved_ranges()
            );
            return Ok(());
        }
        if offset == "auth-candidate" {
            use freemkv_fw::engine::mt1959::Mt1959Engine;
            use mediatek_optical::image::analysis::AuthCell;
            use sha2::{Digest, Sha256};
            let flag_base = if let Some(value) = std::env::args().nth(3) {
                u32::from_str_radix(value.trim_start_matches("0x"), 16)?
            } else {
                Mt1959Engine.find_free_sram_cell(&image)?
            };
            let contract = AuthCell::detect(&image)?;
            let (site, bytes) = Mt1959Engine.auth_cell_widen_detour(&image, flag_base)?;
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            println!(
                "{}",
                serde_json::json!({
                    "policy":"source-bound authentication control used by normal Modify",
                    "source_sha256":hex(&Sha256::digest(&image)),
                    "site":site,"fallback":contract.deny(),"refusal":contract.refusal(),
                    "state_address":contract.state_address(),"variant":format!("{:?}",contract.variant()),
                    "flag_base":flag_base,"stub_hex":hex(&bytes),
                })
            );
            return Ok(());
        }
        if let Some(value) = offset.strip_prefix("stores:") {
            let value = u32::from_str_radix(value.trim_start_matches("0x"), 16)?;
            for site in (0..image.len().saturating_sub(4)).step_by(2) {
                if thumb_asm::analysis::literal_value(&image, site) != Some(value) {
                    continue;
                }
                let Some(first) = thumb_asm::isa::decode_at(&image, site) else {
                    continue;
                };
                let Some(thumb_asm::Operand::Reg(pointer)) = first.operands.as_slice().next()
                else {
                    continue;
                };
                let mut pc = site + first.width.bytes();
                for _ in 0..24 {
                    let Some(instruction) = thumb_asm::isa::decode_at(&image, pc) else {
                        break;
                    };
                    let memory =
                        instruction
                            .operands
                            .as_slice()
                            .find_map(|operand| match operand {
                                thumb_asm::Operand::Mem(memory) => Some(memory),
                                _ => None,
                            });
                    if instruction.mnemonic == "strb"
                        && memory.is_some_and(|memory| {
                            memory.base == pointer && memory.offset == 0 && memory.index.is_none()
                        })
                    {
                        println!("direct store candidate at 0x{pc:x} via literal at 0x{site:x}");
                        let start = site.saturating_sub(8);
                        for line in thumb_asm::isa::disassemble(&image, start, start as u32, 24) {
                            println!("{line}");
                        }
                        break;
                    }
                    if instruction.is_branch() || instruction.writes_pc() {
                        break;
                    }
                    if !instruction.mnemonic.starts_with("str")
                        && !matches!(instruction.mnemonic, "cmp" | "cmn" | "tst")
                        && instruction.operands.as_slice().next()
                            == Some(thumb_asm::Operand::Reg(pointer))
                    {
                        break;
                    }
                    pc += instruction.width.bytes();
                }
            }
            return Ok(());
        }
        if let Some(value) = offset.strip_prefix("literal:") {
            let value = u32::from_str_radix(value.trim_start_matches("0x"), 16)?;
            for site in (0..image.len().saturating_sub(4)).step_by(2) {
                if thumb_asm::analysis::literal_value(&image, site) == Some(value) {
                    println!("literal reference at 0x{site:x}");
                    let start = site.saturating_sub(8);
                    for line in thumb_asm::isa::disassemble(&image, start, start as u32, 20) {
                        println!("{line}");
                    }
                }
            }
            return Ok(());
        }
        let offset = usize::from_str_radix(offset.trim_start_matches("0x"), 16)?;
        let count = std::env::args()
            .nth(3)
            .map(|n| n.parse())
            .transpose()?
            .unwrap_or(128);
        for line in thumb_asm::isa::disassemble(&image, offset, offset as u32, count) {
            println!("{line}");
        }
        return Ok(());
    }
    let analysis = ApplicationAnalysis::inspect(&image, 0)
        .ok_or_else(|| anyhow::anyhow!("invalid analysis range"))?;
    println!("{:#?}", analysis.integrity_selections());
    println!("{:#?}", analysis.ranges());
    Ok(())
}
