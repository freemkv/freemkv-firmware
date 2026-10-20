//! Read-only census of decoded Pioneer Kernels for update-dialect research.
//! Usage: cargo run -p freemkv-flash --example pioneer_dialect_corpus -- <hoard/images/pioneer>
use anyhow::{Context, Result};
use pioneer_optical::envelope::decode_envelope;
use std::{collections::BTreeMap, path::Path};

fn walk(dir: &Path, counts: &mut BTreeMap<String, usize>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            walk(&path, counts)?;
        } else if path.extension().is_some_and(|e| e == "enc")
            && path.parent().is_some_and(|p| p.ends_with("kernel"))
        {
            let bytes = std::fs::read(&path)?;
            let label = path.with_extension("enc.json");
            let metadata: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&label).with_context(|| format!("{}", label.display()))?,
            )?;
            let id = metadata["header"]["id"].as_str().unwrap_or("");
            let expected = if id.contains("DVD-RW") {
                "DVR"
            } else if id.contains("BD-") || id.contains("BDR-") {
                "BD"
            } else {
                "other"
            };
            let result = match decode_envelope(&bytes) {
                Some(decoded) => format!(
                    "{} {:?} {:?}{}",
                    expected,
                    decoded.info().layout,
                    pioneer_optical::image::kernel_marker_policy(&decoded.image),
                    if expected == "other" {
                        format!(" {id}")
                    } else {
                        String::new()
                    }
                ),
                None => format!("{} undecoded", expected),
            };
            *counts.entry(result).or_default() += 1;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .context("need hoard/images/pioneer root")?;
    let mut counts = BTreeMap::new();
    walk(Path::new(&root), &mut counts)?;
    for (key, count) in counts {
        println!("{count:4} {key}");
    }
    Ok(())
}
