//! THROWAWAY measurement harness (not a gate): drive `freemkv_fw::api::create`
//! (engine build_report + CMAC self-verify) over every de-wrapped OEM payload
//! listed in a TSV, and tally create+verify success per chip/lineage.
//!
//! TSV columns: payload_path \t chip \t brand \t model \t version \t orig_path
//! Point `FREEMKV_SCOREBOARD_TSV` at it; results go to stdout (`--nocapture`)
//! and to `FREEMKV_SCOREBOARD_OUT` if set.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// One frozen golden-KAT row (kept as JSON text so the harness needs no serde).
struct Kat {
    chip: String,
    model: String,
    input_sha: String,
    json: String,
}

#[derive(Clone)]
struct Row {
    path: String,
    chip: String,
    brand: String,
    model: String,
    version: String,
    orig: String,
}

fn lineage(image: &[u8]) -> &'static str {
    // Classic vs JB8-lineage MT1939 by banner at 0x3000; MT1959 otherwise.
    let banner = |needle: &[u8]| -> bool {
        image
            .get(0x3000..0x3000 + 0x40)
            .map(|w| w.windows(needle.len()).any(|c| c == needle))
            .unwrap_or(false)
    };
    if banner(b"MT1939 Boot") {
        "MT1939-classic"
    } else if banner(b"MT1959 Boot") {
        "MT1959-lineage"
    } else {
        "other-banner"
    }
}

#[test]
fn corpus_scoreboard() {
    let Ok(tsv) = std::env::var("FREEMKV_SCOREBOARD_TSV") else {
        eprintln!("skip: set FREEMKV_SCOREBOARD_TSV");
        return;
    };
    let text = std::fs::read_to_string(&tsv).expect("read tsv");
    let rows: Vec<Row> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Row {
                path: f[0].to_string(),
                chip: f.get(1).unwrap_or(&"").to_string(),
                brand: f.get(2).unwrap_or(&"").to_string(),
                model: f.get(3).unwrap_or(&"").to_string(),
                version: f.get(4).unwrap_or(&"").to_string(),
                orig: f.get(5).unwrap_or(&"").to_string(),
            }
        })
        .collect();

    let total = rows.len();
    // (chip, lineage) -> (pass, fail)
    let mut buckets: BTreeMap<(String, String), (u32, u32)> = BTreeMap::new();
    let mut pass = 0u32;
    let mut fail = 0u32;
    // failures: reason -> list of (chip/lineage, brand model version, detail)
    let mut failures: Vec<(String, String, String, String)> = Vec::new();
    let mut kats: Vec<Kat> = Vec::new();

    for r in &rows {
        let image = std::fs::read(&r.path).expect("read payload");
        let input_sha = sha256_hex(&image);
        let lin = lineage(&image).to_string();
        let key = (r.chip.clone(), lin.clone());
        let res = std::panic::catch_unwind(|| freemkv_fw::api::create(&image));
        let ok = matches!(&res, Ok(Ok(_)));

        // ---- golden-KAT row (reproducibility lock) ----
        let mut kj = String::new();
        let _ = write!(
            kj,
            "  {{\n    \"input_sha256\": {},\n    \"chip\": {},\n    \"model\": {},\n    \"version\": {},\n    \"lineage\": {},\n",
            json_str(&input_sha),
            json_str(&r.chip),
            json_str(&r.model),
            json_str(&r.version),
            json_str(&lin),
        );
        match &res {
            Ok(Ok(outcome)) => {
                let out_img = outcome.image();
                let rep = &outcome.report;
                let save_home = freemkv_fw::engine::mt1959::Mt1959Engine
                    .find_nv_block(&image)
                    .ok();
                // CMAC stored digests from a verify pass over the PRODUCED image.
                let mut digests = String::from("[");
                if let Ok(entries) = freemkv_flash::cmac::parse_table(out_img) {
                    let active: Vec<_> = entries.iter().filter(|e| e.is_active()).collect();
                    for (i, e) in active.iter().enumerate() {
                        if i > 0 {
                            digests.push(',');
                        }
                        let _ = write!(
                            digests,
                            "\n      {{ \"start\": {}, \"end\": {}, \"stored\": {} }}",
                            e.start,
                            e.end,
                            json_str(&hex(&e.stored))
                        );
                    }
                    if !active.is_empty() {
                        digests.push_str("\n    ");
                    }
                }
                digests.push(']');
                let _ = write!(
                    kj,
                    "    \"build_ok\": true,\n    \"output_sha256\": {},\n    \"handler_va\": {},\n    \"boot_init_site\": {},\n    \"boot_stub_va\": {},\n    \"save_home\": {},\n    \"cmac_regions\": {}\n  }}",
                    json_str(&sha256_hex(out_img)),
                    rep.handler_va,
                    rep.boot_init_site,
                    rep.boot_stub_va,
                    match save_home {
                        Some(v) => v.to_string(),
                        None => "null".to_string(),
                    },
                    digests,
                );
            }
            Ok(Err(e)) => {
                let _ = write!(
                    kj,
                    "    \"build_ok\": false,\n    \"error\": {}\n  }}",
                    json_str(&format!("{e:#}"))
                );
            }
            Err(_) => {
                let _ = write!(
                    kj,
                    "    \"build_ok\": false,\n    \"error\": {}\n  }}",
                    json_str("PANIC during create")
                );
            }
        }
        kats.push(Kat {
            chip: r.chip.clone(),
            model: r.model.clone(),
            input_sha: input_sha.clone(),
            json: kj,
        });

        if ok {
            pass += 1;
            buckets.entry(key).or_default().0 += 1;
        } else {
            fail += 1;
            buckets.entry(key).or_default().1 += 1;
            let detail = match res {
                Ok(Err(e)) => format!("{e:#}"),
                Ok(Ok(_)) => unreachable!(),
                Err(_) => "PANIC during create".to_string(),
            };
            failures.push((
                format!("{}/{}", r.chip, lin),
                format!("{} {} {}", r.brand, r.model, r.version),
                r.orig.clone(),
                detail,
            ));
        }
    }

    // Group failures by a normalized root-cause key (first line, addresses masked).
    let mut by_cause: BTreeMap<String, Vec<&(String, String, String, String)>> = BTreeMap::new();
    for f in &failures {
        let first = f.3.lines().next().unwrap_or("").to_string();
        // mask hex addresses so identical root causes group together
        let mut norm = String::new();
        let mut chars = first.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '0' && chars.peek() == Some(&'x') {
                norm.push_str("0x…");
                chars.next();
                while chars.peek().map(|c| c.is_ascii_hexdigit()).unwrap_or(false) {
                    chars.next();
                }
            } else {
                norm.push(c);
            }
        }
        by_cause.entry(norm).or_default().push(f);
    }

    let mut out = String::new();
    let _ = writeln!(out, "# freemkv-fw corpus build scoreboard\n");
    let _ = writeln!(
        out,
        "create+verify PASS: {pass}/{total}\ncreate+verify FAIL: {fail}/{total}\n"
    );

    let _ = writeln!(out, "## By chip / lineage\n");
    let _ = writeln!(out, "| chip | lineage | pass | fail | total |");
    let _ = writeln!(out, "|---|---|---:|---:|---:|");
    for ((chip, lin), (p, f)) in &buckets {
        let _ = writeln!(out, "| {chip} | {lin} | {p} | {f} | {} |", p + f);
    }

    let _ = writeln!(out, "\n## Failures grouped by root cause\n");
    for (cause, items) in &by_cause {
        let _ = writeln!(out, "### ({} images) {}\n", items.len(), cause);
        let _ = writeln!(out, "| chip/lineage | brand model ver | orig path |");
        let _ = writeln!(out, "|---|---|---|");
        for it in items {
            let _ = writeln!(out, "| {} | {} | {} |", it.0, it.1.trim(), it.2);
        }
        let _ = writeln!(out);
        // one representative full error
        let _ = writeln!(
            out,
            "<details><summary>full error</summary>\n\n```\n{}\n```\n</details>\n",
            items[0].3
        );
    }

    println!("{out}");
    if let Ok(dst) = std::env::var("FREEMKV_SCOREBOARD_OUT") {
        std::fs::write(&dst, &out).expect("write scoreboard");
        println!("wrote {dst}");
    }

    // ---- frozen golden-KAT manifest (reproducibility lock) ----
    if let Ok(dst) = std::env::var("FREEMKV_KAT_OUT") {
        // deterministic order: chip, then model, then input_sha
        kats.sort_by(|a, b| {
            a.chip
                .cmp(&b.chip)
                .then(a.model.cmp(&b.model))
                .then(a.input_sha.cmp(&b.input_sha))
        });
        let mut j = String::from("[\n");
        for (i, k) in kats.iter().enumerate() {
            if i > 0 {
                j.push_str(",\n");
            }
            j.push_str(&k.json);
        }
        j.push_str("\n]\n");
        std::fs::write(&dst, &j).expect("write kat");
        println!("wrote {dst} ({} rows)", kats.len());
    }
}
