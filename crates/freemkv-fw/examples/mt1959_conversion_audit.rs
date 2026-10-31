//! Inventory source-bound MT1959 conversion contracts. Never writes firmware.
use anyhow::{Context, Result};
use mediatek_optical::image::analysis::LegacyStackDi;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let scan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(args.next().context("scan JSON")?)?)?;
    let hoard = PathBuf::from(args.next().context("hoard root")?);
    let out = PathBuf::from(args.next().context("output JSON")?);
    let mut rows = Vec::new();
    for row in scan["images"].as_array().context("images")? {
        let data = std::fs::read(hoard.join(row["path"].as_str().context("path")?))?;
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&data))
                == row["sha256"].as_str().context("source hash")?,
            "source hash mismatch"
        );
        let plan = freemkv_fw::engine::mt1959_uhd::Plan::inspect(&data, 0x0200_0e40);
        let di = plan
            .as_ref()
            .ok()
            .filter(|p| {
                p.gaps()
                    .contains(&freemkv_fw::engine::mt1959_uhd::Gap::DiscInformation)
            })
            .map(|_| LegacyStackDi::detect(&data));
        rows.push(json!({"sha256":row["sha256"],
            "di_contract": di.as_ref().and_then(|d| d.as_ref().ok()).map(|d|json!({"prevalidation":d.prevalidation,"format":d.format,
                "layers":d.layers,"layer_store":d.layer_store,"state":d.state,"stack_block":d.stack_block,
                "identifier_offset":d.identifier_offset})),
            "plan":match plan {
                Ok(p)=>json!({"gaps":p.gaps().iter().map(|g|g.id()).collect::<Vec<_>>(),"pending":p.pending(),
                    "reverse_contract":p.reverse_arithmetic().map(|r|json!({"mode":r.mode,"divide":r.divide,
                        "mode_zero":r.mode_zero,"normalize":r.normalize,"site":r.site})),
                    "authentication_differences":p.authentication_differences().iter().map(|g|g.id()).collect::<Vec<_>>(),
                    "authentication_diagnostic_error":p.authentication_diagnostic_error(),
                    "candidates":p.candidates().iter().map(|c|json!({"gap":c.gap.id(),"site":c.site,"original":c.original,"bytes":c.bytes})).collect::<Vec<_>>()}),
                Err(e)=>json!({"error":format!("{e:#}")})}}));
    }
    std::fs::write(out, serde_json::to_vec_pretty(&rows)?)?;
    Ok(())
}
