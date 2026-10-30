//! `freemkv-crossflash <dir>`: print admitted and known future crossflashes between
//! the firmware packages in `<dir>`, as JSON.
//!
//! Input is a content-addressed package tree (`pioneer/<sha256>.tar`,
//! `mediatek/<sha256>.tar`). Each package stands in
//! for a drive running it; a link `installed -> target` means `flash` would
//! admit `target` on that drive (see `freemkv_flash::crossflash`).
//!
//! `freemkv-crossflash --why <installed> <target>` prints the flasher's verdict
//! for one pair (refusal reason, or "admitted").

use anyhow::{Context, Result};
use freemkv_flash::crossflash::{admits, classified_links, decide, CompatibilityStatus, Platform};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn main() -> std::process::ExitCode {
    match freemkv_flash::user_error::read_only(freemkv_flash::diagnostics::run(
        "crossflash analysis",
        run,
    )) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            freemkv_flash::cli::print_error(&error);
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] || args.as_slice() == ["-h"] {
        println!("Usage: freemkv-crossflash <package directory>\n       freemkv-crossflash --why [--json] <installed> <target>");
        return Ok(());
    }
    if let [flag, json, installed, target] = args.as_slice() {
        if flag == "--why" && json == "--json" {
            let installed = std::fs::read(installed)?;
            let target = std::fs::read(target)?;
            let platform = platform(&target);
            println!(
                "{}",
                serde_json::to_string(&decide(platform, &installed, &target))?
            );
            return Ok(());
        }
    }
    if let [flag, installed, target] = args.as_slice() {
        if flag == "--why" {
            return why(Path::new(installed), Path::new(target));
        }
    }
    let [root] = args.as_slice() else {
        return Err(anyhow::anyhow!(
            "usage: freemkv-crossflash <package directory>\n       \
             freemkv-crossflash --why [--json] <installed> <target>"
        )
        .context(freemkv_flash::user_error::IssueCode::CommandOptions));
    };
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut conditional: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut future: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (dir, ext, platform) in [
        ("pioneer", "tar", Platform::Pioneer),
        ("mediatek", "tar", Platform::Mediatek),
    ] {
        let (ids, bytes) = read_packages(&Path::new(root).join(dir), ext)?;
        let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let found = classified_links(platform, &refs);
        eprintln!("{dir}: {} packages, {} links", ids.len(), found.len());
        for (i, j, status) in found {
            let graph = match status {
                CompatibilityStatus::Yes => &mut out,
                CompatibilityStatus::Conditional => &mut conditional,
                CompatibilityStatus::SoftNo => &mut future,
                CompatibilityStatus::HardNo => continue,
            };
            graph
                .entry(ids[i].clone())
                .or_default()
                .push(ids[j].clone());
        }
    }
    let doc = serde_json::json!({
        "format": "freemkv-crossflash-links",
        "version": 2,
        "freemkv_flash": env!("CARGO_PKG_VERSION"),
        "links": out,
        "future": future,
        "conditional": conditional,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

/// Print the flasher's verdict for one installed/target pair.
fn why(installed: &Path, target: &Path) -> Result<()> {
    let read = |p: &Path| std::fs::read(p).with_context(|| format!("reading {}", p.display()));
    let installed = read(installed)?;
    let target = read(target)?;
    let platform = platform(&target);
    match admits(platform, &installed, &target) {
        Ok(()) => println!("admitted"),
        Err(e) => println!("refused: {e:#}"),
    }
    Ok(())
}

fn platform(target: &[u8]) -> Platform {
    if freemkv_flash::mediatek_package::Package::parse(target).is_ok()
        || target.get(257..262) != Some(b"ustar")
    {
        Platform::Mediatek
    } else {
        Platform::Pioneer
    }
}

/// Every `<sha256>.<ext>` in `dir`, sorted by name: (ids, bytes).
fn read_packages(dir: &Path, ext: &str) -> Result<(Vec<String>, Vec<Vec<u8>>)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    paths.retain(|p| p.extension().is_some_and(|e| e == ext));
    paths.sort();
    let mut ids = Vec::with_capacity(paths.len());
    let mut bytes = Vec::with_capacity(paths.len());
    for path in paths {
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .with_context(|| format!("bad package name {}", path.display()))?;
        ids.push(id.to_string());
        bytes.push(std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?);
    }
    Ok((ids, bytes))
}
