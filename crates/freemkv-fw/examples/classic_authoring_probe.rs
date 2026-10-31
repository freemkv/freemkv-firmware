//! Report the strict classic builder error hidden by best-effort DE fallback.
use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let inventory: serde_json::Value =
        serde_json::from_slice(&std::fs::read(args.next().context("inventory")?)?)?;
    let hoard = PathBuf::from(args.next().context("hoard")?);
    let output = PathBuf::from(args.next().context("output")?);
    let mut rows = Vec::new();
    for row in inventory["images"].as_array().context("images")? {
        let data = std::fs::read(hoard.join(row["path"].as_str().context("path")?))?;
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&data)) == row["sha256"].as_str().context("hash")?,
            "source changed"
        );
        let chip = freemkv_fw::family::detect_chip(&data)?;
        let cap = freemkv_fw::family::capability_for(&chip.model, chip.family);
        let result =
            freemkv_fw::engine::mt1959::Mt1959Engine.build_modify_classic(&data, &chip, &cap);
        rows.push(json!({"sha256":row["sha256"],"model":chip.model,"result":match result {
            Ok(r)=>json!({"built":true,"conversion":r.levers.iter().flat_map(|l|&l.hooks).filter(|h|h.id=="uhd-conversion").map(|h|json!({"variant":h.variant,"reason":h.reason})).collect::<Vec<_>>()}),
            Err(e)=>json!({"error":format!("{e:#}")})}}));
    }
    std::fs::write(output, serde_json::to_vec_pretty(&rows)?)?;
    Ok(())
}
