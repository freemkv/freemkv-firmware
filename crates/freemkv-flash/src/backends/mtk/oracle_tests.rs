//! Golden verdict + transfer-plan oracle over a real MediaTek package tree.
//!
//! Characterization only (`#[ignore]`, needs the corpus): for every directed
//! pair of distinct packages, record the flasher's offline verdict (status,
//! refusal reason, routes) through the same `crossflash::decide` path
//! `classified_routes` uses, whether the pre-filter schedules it, and for every
//! admitted pair the SHA-256 of each receiver-bound transfer the executor would
//! write (stage by stage). Per package: the pre-filter facts and the backup
//! rebuild of a simulated drive read. Hashes and identity fields only.
//!
//! The mediatek-optical API rework must reproduce this manifest byte-for-byte:
//! `ORACLE_TREE=<dir with mediatek/<sha>.tar> ORACLE_OUT=<file> cargo test --release
//! -p freemkv-flash --lib backends::mtk::oracle_tests -- --ignored`

use super::*;
use crate::backends::mtk::package::{digest, Package};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// One receiver-bound stage: every byte stream and command the executor uses.
fn stage(prepared: &mediatek_optical::receiver::PreparedUpdate) -> serde_json::Value {
    let plan = prepared.plan();
    let steps: String = plan
        .steps()
        .iter()
        .map(|s| format!("{} {:02x?} {:?} {}\n", s.label, s.cdb, s.direction, s.length))
        .collect();
    serde_json::json!({
        "receiver": format!(
            "{:?} {:?} {:#x} {:?}",
            plan.receiver().mode(),
            plan.receiver().encoding(),
            plan.receiver().signature_address(),
            plan.receiver().provenance()
        ),
        "class": format!("{:?}", plan.class()),
        "encoding": format!("{:?}", plan.encoding()),
        "prepare_command": format!("{:?}", plan.prepare_command()),
        "programmed": format!("{:x?}", plan.programmed_ranges()),
        "preserved": format!("{:x?}", plan.preserved_ranges()),
        "image": digest(plan.image()),
        "transfer": digest(plan.transfer()),
        "steps": digest(steps.as_bytes()),
    })
}

fn err(e: &anyhow::Error) -> serde_json::Value {
    serde_json::json!({ "error": format!("{e:#}") })
}

/// The stages `flash` would write for `target` on a drive running `installed`,
/// with the installed image standing in for the live drive, its backup and its
/// receiver code (as the offline decision does).
fn correction(installed: &[u8], target: &[u8]) -> serde_json::Value {
    let installed = Package::parse(installed)
        .map(|p| p.firmware().to_vec())
        .unwrap_or_else(|_| installed.to_vec());
    let package = Package::parse(target).ok();
    let (image, final_image) = match &package {
        Some(p) => match p.intermediate() {
            Some(i) => (i.to_vec(), Some(p.firmware().to_vec())),
            None => (p.firmware().to_vec(), None),
        },
        None => (target.to_vec(), None),
    };
    let first = (|| -> Result<Executable> {
        let live = identity_of_image(&installed)?;
        let product = Build::of_image(&installed)?.product;
        let verdict =
            crossflash::decide_plan(&product, &Build::of_drive(&live), &Build::of_image(&image)?)?;
        let envelope = mediatek_optical::envelope::Envelope::load(&installed)?;
        let receiver = mediatek_optical::receiver::Receiver::from_firmware(&envelope)
            .map_err(|e| anyhow!("{e}"))?;
        authorize_bytes(&live, &product, verdict, &image, Some(&installed))?.bind(&receiver)
    })();
    let mut stages = vec![match &first {
        Ok(e) => stage(&e.prepared),
        Err(e) => err(e),
    }];
    if let Some(target) = &final_image {
        stages.push(match prepare_next_stage(&image, target) {
            Ok(e) => stage(&e.prepared),
            Err(e) => err(&e),
        });
    }
    serde_json::Value::Array(stages)
}

/// What a backup of a drive running `image` rebuilds to: the read (boot page
/// replaced by its mirror, as READ BUFFER returns it) through the catalog.
fn rebuild(image: &[u8]) -> serde_json::Value {
    let mut read = image.to_vec();
    if read.len() == IMAGE_SIZE {
        let page = mediatek_optical::layout::BOOT_PAGE.len;
        let mirror = mediatek_optical::layout::BOOT_MIRROR.start;
        let copy = read[mirror..mirror + page].to_vec();
        read[..page].copy_from_slice(&copy);
    }
    match mediatek_optical::oem::rebuild(&read, crate::backends::mtk::oem::catalog()) {
        Ok(r) => serde_json::json!({
            "image": digest(&r.image),
            "equals_input": r.image == image,
            "provenance": format!("{:?}", r.provenance),
        }),
        Err(e) => serde_json::json!({ "error": e.to_string() }),
    }
}

#[test]
#[ignore]
fn oracle_mediatek_verdicts_and_transfers_over_corpus() {
    let tree = std::env::var("ORACLE_TREE").expect("ORACLE_TREE");
    let out = std::env::var("ORACLE_OUT").expect("ORACLE_OUT");
    let dir = std::path::Path::new(&tree).join("mediatek");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "tar"))
        .collect();
    paths.sort();
    let ids: Vec<String> = paths
        .iter()
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    let bytes: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
    for (id, b) in ids.iter().zip(&bytes) {
        assert_eq!(&digest(b), id, "package name must be its sha256");
    }
    let keys: Vec<_> = bytes
        .iter()
        .map(|b| match Package::parse(b) {
            Ok(p) => crate::backend::registry::offline_prefilter(
                crate::crossflash::Platform::Mediatek,
                p.firmware(),
            ),
            Err(_) => crate::backend::registry::offline_prefilter(
                crate::crossflash::Platform::Mediatek,
                b,
            ),
        })
        .collect();

    let mut packages = String::new();
    for (i, b) in bytes.iter().enumerate() {
        let package = Package::parse(b);
        let firmware = package.as_ref().map(|p| p.firmware().to_vec());
        let row = serde_json::json!({
            "package": ids[i],
            "parse": package.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| format!("{e:#}")),
            "intermediate": package.as_ref().ok().and_then(|p| p.intermediate().map(digest)),
            "firmware": firmware.as_ref().ok().map(|f| digest(f)),
            "prefilter_family": keys[i].family,
            "prefilter_model": keys[i].model,
            "rebuild": firmware.as_ref().ok().map(|f| rebuild(f)),
        });
        writeln!(packages, "{}", serde_json::to_string(&row).unwrap()).unwrap();
    }

    let pairs: Vec<(usize, usize)> = (0..bytes.len())
        .flat_map(|i| (0..bytes.len()).map(move |j| (i, j)))
        .filter(|&(i, j)| i != j)
        .collect();
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let rows: BTreeMap<String, String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let (pairs, next, keys, bytes, ids) = (&pairs, &next, &keys, &bytes, &ids);
                scope.spawn(move || {
                    let mut rows = Vec::new();
                    while let Some(&(i, j)) =
                        pairs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    {
                        let decision = crate::crossflash::decide(
                            crate::crossflash::Platform::Mediatek,
                            &bytes[i],
                            &bytes[j],
                        );
                        let key = format!("{}>{}", ids[i], ids[j]);
                        let mut row = serde_json::json!({
                            "pair": key,
                            "scheduled": keys[i].may_admit(&keys[j]),
                            "status": decision.status,
                            "reason": decision.reason,
                            "routes": decision.routes,
                        });
                        if matches!(
                            decision.status,
                            crate::crossflash::CompatibilityStatus::Yes
                                | crate::crossflash::CompatibilityStatus::Conditional
                        ) {
                            row["correction"] = correction(&bytes[i], &bytes[j]);
                        }
                        rows.push((key, serde_json::to_string(&row).unwrap()));
                    }
                    rows
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });

    let slices: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let routes = crate::crossflash::classified_routes(crate::crossflash::Platform::Mediatek, &slices);
    let routes: String = routes
        .iter()
        .map(|(i, j, r)| format!("{}>{} {}\n", ids[*i], ids[*j], serde_json::to_string(r).unwrap()))
        .collect();

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut body = String::new();
    for row in rows.values() {
        let value: serde_json::Value = serde_json::from_str(row).unwrap();
        *counts
            .entry(value["status"].as_str().unwrap().to_string())
            .or_default() += 1;
        writeln!(body, "{row}").unwrap();
    }
    let header = serde_json::json!({
        "format": "freemkv-mediatek-verdict-oracle",
        "version": 1,
        "packages": ids.len(),
        "directed_pairs": pairs.len(),
        "scheduled": rows.values().filter(|r| r.contains("\"scheduled\":true")).count(),
        "status_counts": counts,
        "classified_routes_sha256": digest(routes.as_bytes()),
        "classified_routes": routes.lines().count(),
    });
    std::fs::write(&out, format!("{header}\n{packages}{body}")).unwrap();
    eprintln!("oracle: {header}");
}
