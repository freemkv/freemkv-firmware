//! Source-tree invariant: the Pioneer flasher knows no raw SCSI CDBs.
//!
//! Every Pioneer vendor command (identity, read-unlock knock, memory reads, OEM
//! update entry / transfer / finish, the DVR handshake) is issued by
//! `pioneer_optical::drive::*`. The flasher's only contact with the wire is the
//! one `Transport` adapter, `src/drive/pioneer_transport.rs`, which forwards the
//! crate's CDBs untouched and so itself carries no opcode literals.
//!
//! This scans the production code of every Pioneer source file (test modules and
//! `*_tests.rs` are the byte-level oracles and are exempt) for WRITE BUFFER /
//! READ BUFFER opcode literals (`0x3B` / `0x3C`, or the hex-text form `3B 0x` /
//! `3C 0x`). The MediaTek backend (`drive/mtk.rs`, `probe.rs`, ...) is a different
//! protocol family that legitimately issues its own CDBs and is out of scope.

use std::fs;
use std::path::{Path, PathBuf};

const ADAPTER: &str = "src/drive/pioneer_transport.rs";

fn pioneer_sources(root: &Path) -> Vec<PathBuf> {
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
            let in_pioneer_dir = path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "pioneer"));
            if name.ends_with(".rs")
                && !name.ends_with("_tests.rs")
                && (name.starts_with("pioneer") || in_pioneer_dir)
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
fn no_pioneer_source_contains_a_write_or_read_buffer_opcode() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = pioneer_sources(root);
    assert!(
        files.iter().any(|f| f.ends_with(ADAPTER)),
        "scanner must cover the adapter"
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
        "raw CDB opcodes found outside pioneer_optical:\n{}",
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
                if production(&src).contains("impl Transport for") {
                    impls.push(path);
                }
            }
        }
    }
    assert_eq!(impls.len(), 1, "expected one Transport adapter: {impls:?}");
    assert!(impls[0].ends_with(ADAPTER));
}

#[test]
fn production_keeps_code_after_an_early_test_only_item() {
    let src = "fn a() {}\n#[cfg(test)]\nfn helper() { let _ = \"0x3b\"; }\nfn prod() { let _ = 0x3b; }\n\
               #[cfg(test)]\nmod tests { fn t() { let _ = 0x3c; } }\n";
    let prod = production(src);
    assert!(!opcode_hits(&prod).is_empty(), "later production code was hidden");
    assert!(!prod.contains("0x3c"), "test module must be excluded");
    assert_eq!(opcode_hits(&prod).len(), 1);
}
