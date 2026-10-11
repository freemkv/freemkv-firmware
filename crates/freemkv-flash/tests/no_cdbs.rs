//! Source-tree invariant: the flasher's protocol backends know no raw SCSI CDBs.
//!
//! Every Pioneer vendor command (identity, read-unlock knock, memory reads, OEM
//! update entry / transfer / finish, the DVR handshake) is issued by
//! `pioneer_optical`, and every MediaTek command (identity, memory reads, the
//! flash session) by `mediatek_optical`. The flasher's only contact with those
//! sequences is the one `Transport` adapter, `src/drive/transport.rs`, which
//! forwards the crates' CDBs untouched and so itself carries no opcode literals.
//!
//! This scans the production code of every Pioneer and MediaTek backend source
//! file (test modules and `*_tests.rs` are the byte-level oracles and are
//! exempt) for WRITE BUFFER / READ BUFFER opcode literals (`0x3B` / `0x3C`, or
//! the hex-text form `3B 0x` / `3C 0x`). Research tooling (`probe.rs`) and the
//! declarative brand catalog (`flashset.rs`) describe CDBs as data and are out
//! of scope.

use std::fs;
use std::path::{Path, PathBuf};

const ADAPTER: &str = "src/drive/transport.rs";

fn backend_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let in_backend_dir = path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "pioneer" || n == "mtk"));
            if name.ends_with(".rs")
                && !name.ends_with("_tests.rs")
                && (name.starts_with("pioneer") || in_backend_dir || path.ends_with(ADAPTER))
            {
                out.push(path);
            }
        }
    }
    out
}

/// Production portion of a source file: the source with every `#[cfg(test)]`
/// item (a test module, or a single test-only fn/impl/use) removed. Code after an
/// early test-only item stays visible to the scan.
fn production(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(i) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "#[cfg(test)]".len()..];
        // The annotated item ends at its balanced `{...}` block, or at a `;`
        // that comes before any `{` (e.g. `use ...;` / `mod tests;`).
        let brace = after.find('{');
        let semi = after.find(';');
        let end = match (brace, semi) {
            (Some(b), Some(s)) if s < b => s + 1,
            (Some(b), _) => {
                let mut depth = 0usize;
                let mut end = after.len();
                for (off, c) in after[b..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = b + off + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                end
            }
            (None, Some(s)) => s + 1,
            (None, None) => after.len(),
        };
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn opcode_hits(src: &str) -> Vec<String> {
    let lower = src.to_ascii_lowercase();
    let mut hits = Vec::new();
    for needle in ["0x3b", "0x3c", "3b 0", "3c 0"] {
        let mut from = 0;
        while let Some(i) = lower[from..].find(needle) {
            let at = from + i;
            let before_ok = at == 0 || !lower.as_bytes()[at - 1].is_ascii_hexdigit();
            let after = lower.as_bytes().get(at + needle.len());
            // `0x3b`/`0x3c` must not continue into a longer hex literal (0x3b00).
            let after_ok = needle.starts_with("0x") && after.is_none_or(|b| !b.is_ascii_hexdigit())
                || !needle.starts_with("0x");
            if before_ok && after_ok {
                hits.push(format!("`{needle}` at byte {at}"));
            }
            from = at + needle.len();
        }
    }
    hits
}

#[test]
fn no_backend_source_contains_a_write_or_read_buffer_opcode() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = backend_sources(root);
    assert!(
        files.iter().any(|f| f.ends_with(ADAPTER)),
        "scanner must cover the adapter"
    );
    assert!(
        files.iter().any(|f| f.ends_with("src/drive/mtk/mod.rs")),
        "scanner must cover the MediaTek backend"
    );
    let mut offenders = Vec::new();
    for file in files {
        let src = fs::read_to_string(&file).unwrap();
        for hit in opcode_hits(&production(&src)) {
            offenders.push(format!("{}: {hit}", file.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "raw CDB opcodes found outside the protocol crates:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn exactly_one_transport_adapter_exists_in_the_flasher() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut impls = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let src = fs::read_to_string(&path).unwrap();
                for _ in 0..transport_impls(&production(&src)) {
                    impls.push(path.clone());
                }
            }
        }
    }
    // One impl per protocol crate's trait (Pioneer + MediaTek), both in the adapter.
    assert_eq!(impls.len(), 2, "expected two Transport impls: {impls:?}");
    assert!(impls.iter().all(|p| p.ends_with(ADAPTER)), "{impls:?}");
}

/// Count `impl <optional::path::>Transport[<..>] for` lines (not `ScsiTransport`).
fn transport_impls(src: &str) -> usize {
    src.lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("impl"))
        .filter_map(|line| line.split_once(" for ").map(|(head, _)| head))
        .filter(|head| {
            let tr = head.rsplit(' ').next().unwrap_or("");
            let tr = tr.split('<').next().unwrap_or("");
            tr.rsplit("::").next() == Some("Transport")
        })
        .count()
}

#[test]
fn transport_impl_matcher_sees_qualified_paths_and_ignores_lookalikes() {
    assert_eq!(transport_impls("impl Transport for A {}"), 1);
    assert_eq!(transport_impls("impl<'a> Transport for A<'a> {}"), 1);
    assert_eq!(
        transport_impls("    impl mediatek_optical::drive::Transport for A {}"),
        1
    );
    assert_eq!(transport_impls("impl ScsiTransport for A {}"), 0);
    assert_eq!(transport_impls("impl a::ScsiTransport for A {}"), 0);
    assert_eq!(transport_impls("fn f() { /* Transport for */ }"), 0);
}

#[test]
fn production_keeps_code_after_an_early_test_only_item() {
    let src =
        "fn a() {}\n#[cfg(test)]\nfn helper() { let _ = \"0x3b\"; }\nfn prod() { let _ = 0x3b; }\n\
               #[cfg(test)]\nmod tests { fn t() { let _ = 0x3c; } }\n";
    let prod = production(src);
    assert!(
        !opcode_hits(&prod).is_empty(),
        "later production code was hidden"
    );
    assert!(!prod.contains("0x3c"), "test module must be excluded");
    assert_eq!(opcode_hits(&prod).len(), 1);
}
