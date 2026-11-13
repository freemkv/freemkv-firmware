//! Golden Modify oracle over a real MediaTek corpus.
//!
//! Characterization only (`#[ignore]`, needs the corpus): for every distinct
//! image (each `.bin`, and each member image of a MediaTek release package),
//! record the SHA-256 of every Modify output the planner produces per boot
//! feature set, the report each build carries, the strict `create` build and
//! the capability query. Digests and identity fields only.
//!
//! The mediatek-optical API rework must reproduce this manifest byte-for-byte:
//! `ORACLE_INPUTS=<dir>:<dir> ORACLE_OUT=<file> cargo test --release -p freemkv-fw
//! --test mtk_modify_oracle -- --ignored`

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use freemkv_fw::boot::BootSettings;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for e in entries {
            collect(&e, out);
        }
    } else if path.extension().is_some_and(|e| e == "bin" || e == "tar") {
        out.push(path.to_path_buf());
    }
}

/// The feature sets: the shipping defaults, every public choice of every
/// feature on its own, everything OEM, and everything enabled.
fn feature_sets() -> Vec<(String, BootSettings)> {
    let mut sets = vec![("standard".to_string(), BootSettings::standard())];
    for feature in freemkv_fw::boot::BootFeature::ALL {
        for (value, _, _) in feature.choices() {
            let assignment = format!("{}={value}", feature.key());
            let settings = BootSettings::parse(std::slice::from_ref(&assignment)).unwrap();
            sets.push((assignment, settings));
        }
    }
    let all_oem: Vec<String> = freemkv_fw::boot::BootFeature::ALL
        .iter()
        .map(|f| format!("{}=oem", f.key()))
        .collect();
    sets.push(("all=oem".into(), BootSettings::parse(&all_oem).unwrap()));
    let all_on: Vec<String> = [
        "unrestricted=on",
        "hrl=off",
        "encryption=off",
        "speed=uncapped",
        "region=free",
    ]
    .map(String::from)
    .to_vec();
    sets.push(("all=on".into(), BootSettings::parse(&all_on).unwrap()));
    sets
}

fn row(image: &[u8]) -> serde_json::Value {
    let mut sets = serde_json::Map::new();
    for (name, settings) in feature_sets() {
        let value = match freemkv_fw::api::modify_with_defaults(image, &settings) {
            Ok((report, support)) => serde_json::json!({
                "image": digest(&report.image),
                "applied": report.applied_count(),
                "report": digest(report.to_json().as_bytes()),
                "support": format!("{support:?}"),
            }),
            Err(error) => serde_json::json!({ "error": format!("{error:#}") }),
        };
        sets.insert(name, value);
    }
    let create = match freemkv_fw::api::create(image) {
        Ok(outcome) => serde_json::json!({
            "image": digest(outcome.image()),
            "report": digest(format!("{:?}", outcome.report).as_bytes()),
        }),
        Err(error) => serde_json::json!({ "error": format!("{error:#}") }),
    };
    let capabilities = freemkv_fw::capabilities::report_json(image);
    let verify = match freemkv_fw::api::verify(image, None) {
        Ok(v) => serde_json::json!(format!("{:?} {} {}", v.verdicts.iter().map(|r| (r.index, r.start, r.end, r.ok)).collect::<Vec<_>>(), v.ok, v.scheme)),
        Err(error) => serde_json::json!({ "error": format!("{error:#}") }),
    };
    let sign = match freemkv_fw::api::sign(image, None) {
        Ok(v) => serde_json::json!(digest(&v.image)),
        Err(error) => serde_json::json!({ "error": format!("{error:#}") }),
    };
    serde_json::json!({
        "modify": sets,
        "create": create,
        "capabilities": serde_json::from_str::<serde_json::Value>(&capabilities)
            .unwrap_or_else(|_| serde_json::json!(digest(capabilities.as_bytes()))),
        "verify": verify,
        "sign": sign,
    })
}

#[test]
#[ignore]
fn oracle_mediatek_modify_outputs_over_corpus() {
    let inputs = std::env::var("ORACLE_INPUTS").expect("ORACLE_INPUTS");
    let out = std::env::var("ORACLE_OUT").expect("ORACLE_OUT");
    let mut files = Vec::new();
    for dir in inputs.split(':') {
        collect(Path::new(dir), &mut files);
    }
    let mut images: BTreeMap<String, (Vec<u8>, Vec<String>)> = BTreeMap::new();
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        let members: Vec<(String, Vec<u8>)> = if file.extension().is_some_and(|e| e == "tar") {
            let package = freemkv_flash::mediatek_package::Package::parse(&bytes).unwrap();
            let mut m = vec![(format!("{}:final", digest(&bytes)), package.firmware().to_vec())];
            if let Some(i) = package.intermediate() {
                m.push((format!("{}:intermediate", digest(&bytes)), i.to_vec()));
            }
            m
        } else {
            vec![(file.file_name().unwrap().to_string_lossy().into_owned(), bytes)]
        };
        for (label, data) in members {
            images
                .entry(digest(&data))
                .or_insert_with(|| (data, Vec::new()))
                .1
                .push(label);
        }
    }
    let list: Vec<(String, Vec<u8>, Vec<String>)> =
        images.into_iter().map(|(k, (d, s))| (k, d, s)).collect();
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let rows: BTreeMap<String, String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let (list, next) = (&list, &next);
                scope.spawn(move || {
                    let mut rows = Vec::new();
                    while let Some((id, data, sources)) =
                        list.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    {
                        let mut sources = sources.clone();
                        sources.sort();
                        sources.dedup();
                        let mut value = row(data);
                        value["sha256"] = serde_json::json!(id);
                        value["sources"] = serde_json::json!(sources);
                        rows.push((id.clone(), serde_json::to_string(&value).unwrap()));
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
    let mut body = String::new();
    for row in rows.values() {
        writeln!(body, "{row}").unwrap();
    }
    let header = serde_json::json!({
        "format": "freemkv-mediatek-modify-oracle",
        "version": 1,
        "images": rows.len(),
        "feature_sets": feature_sets().into_iter().map(|(n, _)| n).collect::<Vec<_>>(),
    });
    std::fs::write(&out, format!("{header}\n{body}")).unwrap();
    eprintln!("oracle: {header}");
}
