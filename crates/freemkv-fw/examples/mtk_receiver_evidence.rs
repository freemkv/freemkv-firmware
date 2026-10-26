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
        "caller":{"entry":c.caller.entry,"stack_bytes":c.caller.stack_bytes,"returns":c.caller.returns},
        "bypass":bypass,
    })
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: mtk_receiver_evidence IMAGE"))?;
    let image = std::fs::read(path)?;
    if let Some(offset) = std::env::args().nth(2) {
        if offset == "uhd-conversion" {
            use freemkv_fw::engine::mtk_uhd::{
                emit_di_layers, emit_di_recognition, UhdConversionPlan,
            };
            use mediatek_optical::image::analysis::UhdArea;
            let plan = UhdConversionPlan::inspect(&image)?;
            let flags = 0x0200f000;
            let candidates = plan.routing_candidates(&image, flags)?;
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
            let calibration = plan.calibration_candidate(&image, flags)?;
            let di = freemkv_fw::engine::mtk_uhd::di_prevalidation_candidate(&image, flags).ok();
            println!(
                "{}",
                serde_json::json!({
                    "policy":"research component emission only; no image is written or UHD capability enabled",
                    "state":plan.state_address(), "flag_base":flags,
                    "pending":plan.remaining_contracts(),
                    "read_position":{"entry":read_position.contract.entry,"site":read_position.contract.decode.site(),
                        "position":read_position.contract.position,"layer":read_position.contract.layer,
                        "cached_layer":read_position.contract.cached_layer,"status":read_position.contract.status,
                        "stub":read_position.bytes,"original":read_position.original},
                    "calibration":calibration.as_ref().map(|c|serde_json::json!({
                        "entry":c.contract.caller.entry,"site":c.contract.site,"resume":c.contract.site+6,
                        "original_base":c.contract.original_base,"coefficients":c.contract.c7_coefficients,
                        "original":c.original,"stub":c.bytes,
                        "caller":{"entry":c.contract.caller.entry,"stack_bytes":c.contract.caller.stack_bytes,"returns":c.contract.caller.returns}
                    })),
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
                        "caller":{"entry":d.caller.entry,"stack_bytes":d.caller.stack_bytes,"returns":d.caller.returns},
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
                .build_speed_stub_classic(0x0200f000, role.maximum_cell)?;
            println!(
                "{}",
                serde_json::json!({"entry":role.entry,"site":role.site,
                "maximum_cell":role.maximum_cell,"optimum_cell":role.optimum_cell,
                "media_cell":role.media_cell,"consumer":role.consumer,"flag_base":0x0200f000u32,
                "stub":stub,"branch":thumb_asm::encode_b_wide(role.site, 0x1ff000)})
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
                    "policy":"research-only; not enabled by classic Modify or website capabilities",
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
