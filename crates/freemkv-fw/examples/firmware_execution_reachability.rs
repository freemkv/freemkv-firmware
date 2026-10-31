//! Source-bound candidate direct-call ancestry; never a proof of dynamic absence.
use anyhow::{Context, Result};
use mediatek_optical::image::analysis::{CommandDispatch, SavedLink};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let source = PathBuf::from(args.next().context("source")?);
    let output = PathBuf::from(args.next().context("output JSON")?);
    let targets: Vec<usize> = args
        .map(|value| usize::from_str_radix(value.trim_start_matches("0x"), 16))
        .collect::<std::result::Result<_, _>>()?;
    let image = std::fs::read(source)?;
    let commands = CommandDispatch::inspect(&image)?;
    let records: Vec<Value> = commands
        .records()
        .iter()
        .map(|r| json!({"opcode":r.opcode,"flags":r.flags,"handler":r.handler,"record":r.off}))
        .collect();
    let mut calls: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for site in (0..image.len().saturating_sub(4)).step_by(2) {
        let first = u16::from_le_bytes(image[site..site + 2].try_into()?);
        let second = u16::from_le_bytes(image[site + 2..site + 4].try_into()?);
        if first & 0xf800 != 0xf000 || !matches!(second & 0xf800, 0xe800 | 0xf800) {
            continue;
        }
        let Some(instruction) = thumb_asm::isa::decode_at(&image, site) else {
            continue;
        };
        if !matches!(instruction.mnemonic, "bl" | "blx") {
            continue;
        }
        if let Some(target) = instruction.branch_target() {
            calls.entry(target as usize).or_default().push(site);
        }
    }
    let mut rows = Vec::new();
    for target in targets {
        let first = image
            .get(target..target + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]));
        let (entry, entry_binding) = if first.is_some_and(|h| h & 0xff00 == 0xb500) {
            (
                target,
                json!({"kind":"explicit Thumb PUSH with LR at supplied entry"}),
            )
        } else {
            match SavedLink::detect(&image, target) {
                Ok(frame) => (
                    frame.entry(),
                    json!({"kind":"native saved-frame contract","stack_bytes":frame.stack_bytes()}),
                ),
                Err(error) => (
                    target,
                    json!({"kind":"unbound raw supplied address","error":error.to_string()}),
                ),
            }
        };
        let mut queue = VecDeque::from([(entry, 0_usize)]);
        let mut visited = BTreeSet::new();
        let mut nodes = Vec::new();
        while let Some((entry, depth)) = queue.pop_front() {
            if !visited.insert(entry) {
                continue;
            }
            let owners: Vec<_> = commands
                .records()
                .iter()
                .filter(|r| r.handler as usize & !1 == entry)
                .map(|r| json!({"opcode":r.opcode,"flags":r.flags,"record":r.off}))
                .collect();
            let mut edges = Vec::new();
            for &site in calls.get(&entry).into_iter().flatten() {
                match SavedLink::detect(&image, site) {
                    Ok(frame) => {
                        edges.push(json!({"site":site,"caller":frame.entry(),"saved_stack":frame.stack_bytes(),"frame_bound":true}));
                        if depth < 12 && visited.len() < 300 { queue.push_back((frame.entry(),depth+1)); }
                    }
                    Err(error) => edges.push(json!({"site":site,"caller":null,"frame_bound":false,"error":error.to_string()})),
                }
            }
            nodes.push(json!({"entry":entry,"depth":depth,"registered_command_handlers":owners,"candidate_direct_callers":edges}));
        }
        rows.push(json!({"target":target,"lookup_entry":entry,"entry_binding":entry_binding,"nodes":nodes}));
    }
    std::fs::write(
        output,
        serde_json::to_vec_pretty(&json!({
        "schema":"candidate-native-call-ancestry-v1","cargo_lock_sha256":format!("{:x}",Sha256::digest(include_bytes!("../../../Cargo.lock"))),"input_sha256":format!("{:x}",Sha256::digest(&image)),
        "scope":"Thumb BL/BLX candidate ancestry with native saved-frame and registered-dispatch bindings; literal-data false positives remain possible",
        "indirect_and_arm_callers_unresolved":true,"path_feasibility_qualified":false,"absence_qualified":false,
        "commands":records,"targets":rows}))?,
    )?;
    Ok(())
}
