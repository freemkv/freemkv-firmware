//! Golden verdict + correction-output oracle over a real Pioneer package tree.
//!
//! Characterization only (`#[ignore]`, needs the private corpus): for every
//! directed pair the crossflash pre-filter schedules, record the flasher's
//! verdict (status, refusal reason, routes with required words) through the
//! SAME decision path `classified_routes` uses, and for every admitted pair the
//! SHA-256 of each prepared (corrected) transfer/image the executor would write.
//! Pairs the pre-filter drops are counted, not listed (their verdict is a
//! hard refusal by construction).
//!
//! The pioneer-optical consolidation must reproduce this manifest byte-for-byte:
//! `ORACLE_TREE=<dir with pioneer/<sha>.tar> ORACLE_OUT=<file> cargo test --release
//! -p freemkv-flash --all-features --lib backends::pioneer::oracle_tests -- --ignored`

use super::*;
use crate::backends::mtk::package::digest;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A Normal transfer re-signed for its receiving Kernel carries a fresh random
/// signature (`SigningKey::random`): hash it with the signature field zeroed,
/// and record separately that the signature verifies.
fn transfer_digest(bytes: &[u8]) -> serde_json::Value {
    use pioneer_optical::envelope::signature::{verify_normal_signature, SignatureCheck};
    let mut masked = bytes.to_vec();
    if let Some(signature) = masked.get_mut(0x170..0x1c0) {
        signature.fill(0);
    }
    serde_json::json!({
        "sha256_unsigned": digest(&masked),
        "signature": match verify_normal_signature(bytes) {
            SignatureCheck::ValidKeyAndCiphertext => "valid-key-and-ciphertext",
            SignatureCheck::ValidCiphertextOnly => "valid-ciphertext-only",
            SignatureCheck::Invalid => "invalid",
            _ => "other",
        },
    })
}

/// Hashes of every byte stream the executor would transfer, stage by stage.
fn correction(plan: &AuthorizedPlan) -> serde_json::Value {
    let prepared: &Prepared = plan.state().expect("pioneer plan");
    let opt = |b: Option<&[u8]>| b.map(digest);
    match (&prepared.complete, &prepared.normal) {
        (Some(complete), None) => serde_json::json!({
            "kind": "complete",
            "startup_setting": format!("{:?}", complete.startup_setting()),
            "stages": complete.stages().iter().map(|s| serde_json::json!({
                "bridge": format!("{:?}", s.bridge()),
                "kernel_image": opt(s.kernel_image()),
                "kernel_transfer": opt(s.kernel_transfer()),
                "normal_image": digest(s.normal_image()),
                "normal_transfer": transfer_digest(s.normal_transfer()),
            })).collect::<Vec<_>>(),
        }),
        (None, Some(normal)) => serde_json::json!({
            "kind": "normal",
            "startup_setting": format!("{:?}", normal.startup_setting()),
            "normal_image": digest(normal.normal_image()),
            "normal_transfer": transfer_digest(normal.normal_transfer()),
        }),
        _ => serde_json::json!({"kind": "incomplete"}),
    }
}

#[test]
#[ignore]
fn oracle_verdicts_and_corrections_over_corpus() {
    let tree = std::env::var("ORACLE_TREE").expect("ORACLE_TREE");
    let out = std::env::var("ORACLE_OUT").expect("ORACLE_OUT");
    let dir = std::path::Path::new(&tree).join("pioneer");
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
    let keys: Vec<_> = bytes.iter().map(|b| offline_prefilter(b)).collect();
    let prepared: Vec<Option<OfflinePrepared>> =
        bytes.iter().map(|b| offline_prepare(b).ok()).collect();
    let candidates: Vec<(usize, usize)> = (0..bytes.len())
        .flat_map(|i| (0..bytes.len()).map(move |j| (i, j)))
        .filter(|&(i, j)| i != j && keys[i].may_admit(&keys[j]))
        .collect();

    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let rows: BTreeMap<String, String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let (candidates, next, prepared, bytes, ids) =
                    (&candidates, &next, &prepared, &bytes, &ids);
                scope.spawn(move || {
                    let mut rows = Vec::new();
                    while let Some(&(i, j)) =
                        candidates.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    {
                        // The classified_routes split: decode-once when both
                        // sides prepared, otherwise the ordinary byte path.
                        let authorized = match (&prepared[i], &prepared[j]) {
                            (Some(a), Some(b)) => authorize_offline_prepared(a, b),
                            _ => authorize_offline(&bytes[i], &bytes[j]),
                        };
                        let prepared_bytes = authorized.as_ref().ok().map(correction);
                        let decision =
                            crate::crossflash::decide_from(offline_evaluation(authorized));
                        let mut row = serde_json::json!({
                            "status": decision.status,
                            "reason": decision.reason,
                            "routes": decision.routes,
                        });
                        // Admitted pairs only: a Future (soft-no) candidate has
                        // no write grant, so it has no correction output.
                        if matches!(
                            decision.status,
                            crate::crossflash::CompatibilityStatus::Yes
                                | crate::crossflash::CompatibilityStatus::Conditional
                        ) {
                            row["correction"] = prepared_bytes.expect("admitted pair authorized");
                        }
                        let key = format!("{}>{}", ids[i], ids[j]);
                        row["pair"] = serde_json::Value::String(key.clone());
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

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut body = String::new();
    for row in rows.values() {
        let status: serde_json::Value = serde_json::from_str(row).unwrap();
        *counts
            .entry(status["status"].as_str().unwrap().to_string())
            .or_default() += 1;
        writeln!(body, "{row}").unwrap();
    }
    let total = bytes.len() * (bytes.len() - 1);
    let header = serde_json::json!({
        "format": "freemkv-pioneer-verdict-oracle",
        "version": 1,
        "packages": ids.len(),
        "packages_prepared": prepared.iter().filter(|p| p.is_some()).count(),
        "directed_pairs": total,
        "prefilter_refused": total - candidates.len(),
        "scheduled": candidates.len(),
        "status_counts": counts,
    });
    std::fs::write(&out, format!("{header}\n{body}")).unwrap();
    eprintln!("oracle: {header}");
}
