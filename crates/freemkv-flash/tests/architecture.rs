//! Source-tree tripwires for the universal-backend design
//! (docs/design/universal-backend-gui.md). Each test scans the production
//! code of `src/` (no `*_tests.rs` files, no `#[cfg(test)]` items) with
//! comments and string literals removed, so prose cannot satisfy or trip it.

use std::fs;
use std::path::{Path, PathBuf};

use freemkv_flash::backend::FlashRequest;
use freemkv_flash::backends::pioneer;
use freemkv_flash::manifest::FlashMode;
use freemkv_flash::platform::MockScsiDevice;

/// One production source file: its path relative to the crate, its code with
/// comments and literals blanked, and its string literals.
struct Source {
    path: String,
    code: String,
    strings: Vec<String>,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn production_sources() -> Vec<Source> {
    let mut out = Vec::new();
    let mut stack = vec![root().join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "tests.rs" {
                continue;
            }
            let raw = fs::read_to_string(&path).unwrap();
            let (code, strings) = lex(&without_test_items(&raw));
            let rel = path.strip_prefix(root()).unwrap();
            out.push(Source {
                path: rel.to_string_lossy().replace('\\', "/"),
                code,
                strings,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// The source with every `#[cfg(test)]` item removed: a block, or an item,
/// field or statement that ends at a `;` or `,` outside brackets before any `{`.
fn without_test_items(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(i) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "#[cfg(test)]".len()..];
        let mut nesting = 0i32;
        let mut end = after.len();
        let mut prev = ' ';
        for (off, c) in after.char_indices() {
            match c {
                '(' | '[' => nesting += 1,
                '<' if prev != '-' && prev != '=' => nesting += 1,
                ')' | ']' => nesting -= 1,
                '>' if prev != '-' && prev != '=' => nesting -= 1,
                ';' | ',' if nesting <= 0 => {
                    end = off + 1;
                    break;
                }
                '{' => {
                    end = block_end(after, off);
                    break;
                }
                _ => {}
            }
            prev = c;
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// The offset just past the `}` matching the `{` at `open`.
fn block_end(text: &str, open: usize) -> usize {
    let mut depth = 0usize;
    for (off, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + off + 1;
                }
            }
            _ => {}
        }
    }
    text.len()
}

/// Split Rust source into code (comments, strings and char literals replaced
/// by spaces) and the contents of its string literals.
fn lex(src: &str) -> (String, Vec<String>) {
    let b: Vec<char> = src.chars().collect();
    let (mut code, mut strings) = (String::new(), Vec::new());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            code.push(' ');
        } else if c == 'r' && matches!(next, Some('"') | Some('#')) && !ident_char(&b, i) {
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) != Some(&'"') {
                code.push(c);
                i += 1;
                continue;
            }
            let close: String = std::iter::once('"')
                .chain("#".repeat(hashes).chars())
                .collect();
            let rest: String = b[j + 1..].iter().collect();
            let end = rest.find(&close).unwrap_or(rest.len());
            strings.push(rest[..end].to_string());
            i = j + 1 + rest[..end].chars().count() + close.chars().count();
            code.push_str(" \"\" ");
        } else if c == '"' {
            let mut s = String::new();
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' {
                    s.push(b[i]);
                    i += 1;
                }
                if i < b.len() {
                    s.push(b[i]);
                }
                i += 1;
            }
            i += 1;
            strings.push(s);
            code.push_str(" \"\" ");
        } else if c == '\'' && is_char_literal(&b, i) {
            i += 1;
            if b[i] == '\\' {
                i += 1;
            }
            while i < b.len() && b[i] != '\'' {
                i += 1;
            }
            i += 1;
            code.push_str(" ' ' ");
        } else {
            code.push(c);
            i += 1;
        }
    }
    (code, strings)
}

fn ident_char(b: &[char], i: usize) -> bool {
    i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_')
}

fn is_char_literal(b: &[char], i: usize) -> bool {
    matches!(
        (b.get(i + 1), b.get(i + 2)),
        (Some('\\'), _) | (Some(_), Some('\''))
    )
}

/// Byte offsets where `word` occurs as a whole identifier in `code`.
fn word_hits(code: &str, word: &str) -> Vec<usize> {
    let bytes = code.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    code.match_indices(word)
        .map(|(at, _)| at)
        .filter(|&at| {
            let before = at == 0 || !is_ident(bytes[at - 1]);
            let after = bytes.get(at + word.len()).is_none_or(|&b| !is_ident(b));
            before && after
        })
        .collect()
}

/// The body of `struct <name> { ... }` in `code`, if declared there.
fn struct_body<'a>(code: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("struct {name}");
    let at = code
        .match_indices(&needle)
        .map(|(at, _)| at)
        .find(|&at| matches!(code.as_bytes().get(at + needle.len()), Some(b' ' | b'<')))?;
    let open = at + code[at..].find('{')?;
    let close = open + code[open..].find('}')?;
    Some(&code[open + 1..close])
}

fn source<'a>(sources: &'a [Source], path: &str) -> &'a Source {
    sources
        .iter()
        .find(|s| s.path == path)
        .unwrap_or_else(|| panic!("{path} not found"))
}

// ---------------------------------------------------------------------------
// R2: the dead force / skip-backup / recover-flash paths are deleted
// ---------------------------------------------------------------------------

#[test]
fn force_and_skip_backup_paths_are_gone() {
    let sources = production_sources();
    let mut problems = Vec::new();
    for word in [
        "skip_backup",
        "validate_forced_image",
        "validate_forced_backup",
        "force_refusal",
        "prepare_without_family_check",
        "prepare_normal_without_family_check",
        "decide_recover_plan",
        "classify_forced",
        "capture_preflash_backup",
        "Forced",
    ] {
        for s in &sources {
            if !word_hits(&s.code, word).is_empty() {
                problems.push(format!("{}: `{word}`", s.path));
            }
        }
    }
    // Neither request type carries a bypass, and no flash-path code names one.
    for (path, name) in [
        ("src/backend/mod.rs", "FlashRequest"),
        ("src/workflow.rs", "FlashOptions"),
    ] {
        let body = struct_body(&source(&sources, path).code, name)
            .unwrap_or_else(|| panic!("{name} not in {path}"));
        for field in ["force", "recover", "skip_backup"] {
            if !word_hits(body, field).is_empty() {
                problems.push(format!("{path}: {name}.{field}"));
            }
        }
    }
    for path in [
        "src/main.rs",
        "src/workflow.rs",
        "src/engine.rs",
        "src/backends/mtk/mod.rs",
        "src/backends/pioneer/mod.rs",
        "src/backends/pioneer/flash.rs",
        "src/backends/pioneer/flash_plan.rs",
    ] {
        let s = source(&sources, path);
        if !word_hits(&s.code, "force").is_empty() {
            problems.push(format!("{path}: a `force` identifier"));
        }
        for text in ["--force", "--skip-backup", "--recover"] {
            if s.strings.iter().any(|l| l.contains(text)) {
                problems.push(format!("{path}: user text names `{text}`"));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");

    // Behaviour: an execute request without a backup destination never writes,
    // even when its plan (built before any backup) passes.
    let mut dev = MockScsiDevice::new();
    let request = FlashRequest {
        input: header_only_bundle(),
        input_format: &pioneer::PACKAGE,
        mode: FlashMode::Full,
        execute: true,
        acknowledged_risk: true,
        enc_override: None,
        drive_model: "BU40N".into(),
        verbose: false,
        predump_out: None,
    };
    let backend = pioneer::Pioneer::new();
    let error = freemkv_flash::engine::flash(
        &mut dev,
        &backend,
        &request,
        &mut freemkv_flash::workflow::Preconfirmed,
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("preflash backup path"),
        "{error:#}"
    );
    assert!(
        dev.writes.is_empty(),
        "a flash without a saved backup wrote"
    );
}

/// A Kernel+Normal package of header-only envelopes: it passes the pre-backup
/// plan checks and fails only once the installed firmware is consulted.
fn header_only_bundle() -> Vec<u8> {
    let envelope = |kind: &str| {
        let mut bytes = vec![0u8; 0x1000];
        let header = format!("********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   NEW-DRIVE\r\nRevision Level : 1.00\r\nHardware Version : SAT 8800\r\nKernel Version : ID60\r\nDestination : GENERAL\r\nFile Type : {kind}\r\n");
        bytes[..header.len()].copy_from_slice(header.as_bytes());
        bytes
    };
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("kernel.enc", envelope("Kernel")),
        ("normal.enc", envelope("Normal")),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    tar.into_inner().unwrap()
}

#[test]
fn scanner_sees_through_comments_and_strings() {
    let (code, strings) = lex("let a = \"force\"; // force\nlet b = r#\"x\"#; /* force */ c");
    assert!(word_hits(&code, "force").is_empty(), "{code}");
    assert_eq!(strings, ["force", "x"]);
    assert_eq!(word_hits("forced force_x force", "force").len(), 1);
    assert_eq!(
        without_test_items("a\n#[cfg(test)]\nmod t { fn x() {} }\nb"),
        "a\n\nb"
    );
    assert_eq!(
        without_test_items("S {\n#[cfg(test)]\nf: Option<(A, B)>,\ng: C }"),
        "S {\n\ng: C }"
    );
    assert!(Path::new(&root()).join("src/lib.rs").exists());
}

// ---------------------------------------------------------------------------
// R5: read_surface_map had no caller and is deleted with its map builder
// ---------------------------------------------------------------------------

#[test]
fn read_surface_map_is_gone() {
    let sources = production_sources();
    let mut problems = Vec::new();
    for word in [
        "read_surface_map",
        "build_map",
        "MapIdent",
        "analyze_command_table",
    ] {
        for s in &sources {
            if !word_hits(&s.code, word).is_empty() {
                problems.push(format!("{}: `{word}`", s.path));
            }
        }
    }
    for s in &sources {
        if s.strings.iter().any(|l| l.contains("map.json")) {
            problems.push(format!("{}: writes a map.json", s.path));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

// ---------------------------------------------------------------------------
// R2: write capability is a runtime handle only the engine's gates create
// ---------------------------------------------------------------------------

#[test]
fn write_device_constructed_only_in_engine_gates() {
    const GATES: &str = "src/engine/gates.rs";
    let sources = production_sources();
    let mut problems = Vec::new();
    let gates = source(&sources, GATES);
    let body = struct_body(&gates.code, "WriteDevice").expect("WriteDevice is defined in gates");
    if !word_hits(body, "pub").is_empty() {
        problems.push("WriteDevice has a public field".to_string());
    }
    for s in &sources {
        let defines = s.code.contains("struct WriteDevice");
        let literal = s.code.matches("WriteDevice {").count();
        if s.path != GATES && (defines || literal > 0) {
            problems.push(format!("{}: defines or builds a WriteDevice", s.path));
        }
        // Every function that hands out a WriteDevice is a gate, not public.
        for (at, _) in s
            .code
            .match_indices("-> Result<WriteDevice")
            .chain(s.code.match_indices("-> WriteDevice"))
        {
            let head = &s.code[s.code[..at].rfind("fn ").unwrap_or(0).saturating_sub(40)..at];
            let restricted = head.contains("pub(in crate::engine) fn") || !head.contains("pub");
            if s.path != GATES || !restricted {
                problems.push(format!(
                    "{}: a WriteDevice source outside the gates",
                    s.path
                ));
            }
        }
        // Grants are requested only by the engine.
        for grant in ["gates::flash(", "gates::recovery(", "gates::dump("] {
            if s.code.contains(grant) && !s.path.starts_with("src/engine") {
                problems.push(format!("{}: calls {grant}", s.path));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

// ---------------------------------------------------------------------------
// R5: "recover" means only the Recovery facet
// ---------------------------------------------------------------------------

#[test]
fn recover_names_only_the_recovery_facet() {
    let sources = production_sources();
    let mut problems = Vec::new();
    for s in &sources {
        for at in word_hits(&s.code, "recover") {
            let before = s.code[..at].trim_end();
            let after = s.code[at + "recover".len()..].trim_start();
            let ok = if before.ends_with("fn") && after.starts_with('(') {
                // A definition: the facet trait, its implementations, and the
                // engine/workflow entry points that run it.
                let enclosing = s.code[..at]
                    .rfind("\nimpl ")
                    .max(s.code[..at].rfind("\npub trait "))
                    .map(|i| &s.code[i..at]);
                let in_facet = enclosing.is_some_and(|e| {
                    e.trim_start()
                        .lines()
                        .next()
                        .is_some_and(|l| l.contains("RecoveryFacet"))
                });
                in_facet || ["src/engine.rs", "src/workflow.rs"].contains(&s.path.as_str())
            } else if (before.ends_with('.') || before.ends_with("::")) && after.starts_with('(') {
                ["src/main.rs", "src/workflow.rs", "src/engine.rs"].contains(&s.path.as_str())
            } else {
                // pioneer-optical's own `UpdateOptions::recover`, never requested.
                s.path == "src/backends/pioneer/flash.rs"
                    && after.starts_with(": false")
                    && s.code[..at].rfind("UpdateOptions {").is_some()
            };
            if !ok {
                let line = s.code[..at].lines().count();
                problems.push(format!("{}:{line}: `recover` outside Recovery", s.path));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

// ---------------------------------------------------------------------------
// R9: core modules reach backends only through the registry
// ---------------------------------------------------------------------------

#[test]
fn core_modules_name_no_backend() {
    let backends: Vec<String> = fs::read_dir(root().join("src/backends"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(backends.len() >= 2, "{backends:?}");
    let mut problems = Vec::new();
    for s in production_sources() {
        if s.path.starts_with("src/backends/") || s.path == "src/backend/registry.rs" {
            continue;
        }
        // The crate root declares the module tree; nothing else may name it.
        let code = s.code.replace("pub mod backends;", "");
        if code.contains("backends::") {
            problems.push(format!("{}: names the backends module", s.path));
        }
        for name in &backends {
            if code.contains(&format!("{name}::")) && !word_hits(&code, name).is_empty() {
                problems.push(format!("{}: names backend module `{name}`", s.path));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

// ---------------------------------------------------------------------------
// R9: front-end code names no vendor; that wording comes from descriptors
// ---------------------------------------------------------------------------

/// Vendor and chip-family names, matched case-insensitively.
const VENDOR_NAMES: &[&str] = &["pioneer", "mediatek", "mtk", "mt1959", "mt1939"];

/// Front-end exceptions: `(file, exact identifier or string literal, reason)`.
/// An entry that matches nothing fails the test, so the list cannot go stale.
const VENDOR_ALLOWLIST: &[(&str, &str, &str)] = &[
    (
        "freemkv-flash-gui/src/ui.rs",
        "pioneer",
        "TEMPORARY: the backup name guesses the format from the drive label",
    ),
    (
        "freemkv-flash-gui/src/ui.rs",
        "PIONEER",
        "TEMPORARY: the backup name guesses the format from the drive label",
    ),
    (
        "freemkv-flash-gui/src/ui.rs",
        "Pioneer identity",
        "TEMPORARY: cards are grouped by label instead of by report group",
    ),
    (
        "freemkv-flash-gui/src/ui.rs",
        "pioneer.analysis.semantic_coverage",
        "TEMPORARY: the inspect tree filters one backend's standing caveat by code",
    ),
];

/// The GUI crate's non-test sources plus the CLI's `main.rs` and `workflow.rs`,
/// as `(label, source)`.
fn front_end_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for file in ["src/main.rs", "src/workflow.rs"] {
        let src = fs::read_to_string(root().join(file)).unwrap();
        out.push((format!("freemkv-flash/{file}"), src));
    }
    let gui = root().join("../freemkv-flash-gui/src");
    let mut stack = vec![gui.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                stack.push(path);
            } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
                let rel = path.strip_prefix(&gui).unwrap().to_string_lossy();
                let label = format!("freemkv-flash-gui/src/{}", rel.replace('\\', "/"));
                out.push((label, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// Every identifier and string literal in the code of `src` (comments and
/// `#[cfg(test)]` items removed) that contains a vendor name.
fn vendor_mentions(src: &str) -> Vec<String> {
    let (code, strings) = lex(&without_test_items(src));
    let named = |text: &str| {
        let lower = text.to_ascii_lowercase();
        VENDOR_NAMES.iter().any(|v| lower.contains(v))
    };
    let identifiers = code
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|word| named(word))
        .map(str::to_string);
    let literals = strings.into_iter().filter(|s| named(s));
    identifiers.chain(literals).collect()
}

#[test]
fn cli_and_gui_text_name_no_vendor() {
    let sources = front_end_sources();
    assert!(
        sources.iter().any(|(f, _)| f.ends_with("gui/src/ui.rs")),
        "the GUI sources were not found"
    );
    let mut used = vec![false; VENDOR_ALLOWLIST.len()];
    let mut problems = Vec::new();
    for (file, src) in &sources {
        for mention in vendor_mentions(src) {
            let allowed = VENDOR_ALLOWLIST
                .iter()
                .position(|(f, text, _)| f == file && *text == mention);
            match allowed {
                Some(i) => used[i] = true,
                None => problems.push(format!("{file}: {mention:?}")),
            }
        }
    }
    for (entry, used) in VENDOR_ALLOWLIST.iter().zip(used) {
        if !used {
            problems.push(format!("stale allowlist entry: {entry:?}"));
        }
    }
    assert!(
        problems.is_empty(),
        "front-end code names a vendor; take the wording from the backend's \
         Descriptor or Report instead:\n{problems:#?}"
    );
}

#[test]
fn vendor_scan_skips_comments_and_tests() {
    let src = "/// Pioneer help\nfn a() { let mtk_x = \"MediaTek\"; } // MT1959\n\
               #[cfg(test)]\nmod t { fn b() { \"Pioneer\"; } }\n";
    assert_eq!(vendor_mentions(src), ["mtk_x", "MediaTek"]);
}

// ---------------------------------------------------------------------------
// R11: pioneer-optical stays pinned through the migration
// ---------------------------------------------------------------------------

#[test]
fn pioneer_optical_stays_pinned() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("pioneer-optical"))
        .expect("pioneer-optical dependency");
    assert!(
        line.contains("version = \"=0.12.4\""),
        "pioneer-optical must stay pinned to =0.12.4: {line}"
    );
}
