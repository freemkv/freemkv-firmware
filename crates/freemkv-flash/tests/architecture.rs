//! Source-tree tripwires for the universal-backend design
//! (docs/design/universal-backend-gui.md). Each test scans the production
//! code of `src/` (no `*_tests.rs` files, no `#[cfg(test)]` items) with
//! comments and string literals removed, so prose cannot satisfy or trip it.

use std::fs;
use std::path::{Path, PathBuf};

use freemkv_flash::drive::{FlashRequest, InputKind};
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

/// The source with every `#[cfg(test)]` item removed (a block, or an item that
/// ends at a `;` before any `{`).
fn without_test_items(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(i) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "#[cfg(test)]".len()..];
        let end = match (after.find('{'), after.find(';')) {
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
    let at = code.find(&format!("struct {name} "))?;
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
        ("src/drive/mod.rs", "FlashRequest"),
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
        "src/drive/mod.rs",
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

    // Behaviour: an execute request without a backup destination never writes.
    let mut dev = MockScsiDevice::new();
    let request = FlashRequest {
        input: vec![0; 0x20_0000],
        input_kind: InputKind::Bin,
        mode: FlashMode::Full,
        execute: true,
        acknowledged_risk: true,
        enc_override: None,
        drive_model: "BU40N".into(),
        verbose: false,
        predump_out: None,
        allow_crossflash: false,
    };
    let backend = freemkv_flash::backends::pioneer::Pioneer::new();
    let error = freemkv_flash::engine::flash(&mut dev, &backend, &request).unwrap_err();
    assert!(
        format!("{error:#}").contains("preflash backup path"),
        "{error:#}"
    );
    assert!(
        dev.writes.is_empty(),
        "a flash without a saved backup wrote"
    );
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
