//! Read-only receiver evidence for allocation research; never authorizes changes.
use mediatek_optical::receiver::analysis::ApplicationAnalysis;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: mtk_receiver_evidence IMAGE"))?;
    let image = std::fs::read(path)?;
    if let Some(offset) = std::env::args().nth(2) {
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
                    "site":site,"fallback":contract.deny(),"variant":format!("{:?}",contract.variant()),
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
