//! Source-tree tripwires for the 0.12 universal-backend design. Each
//! test scans production code (no `*_tests.rs` files, no `#[cfg(test)]` items)
//! with comments removed, so prose cannot satisfy or trip it.

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
            if !scanned_name(&name) {
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

/// Whether [`production_sources`] scans a file of this name: Rust source that
/// is not a test module.
fn scanned_name(name: &str) -> bool {
    name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs"
}

/// The source with every `#[cfg(test)]` item removed. An item with a body ends
/// at its block; one without (a statement, a field, a `mod x;`) at the first
/// `;` outside brackets, or `,` outside brackets and generics, or where its
/// enclosing list closes. Comments and literals are skipped, so a `#[cfg(test)]`
/// in a doc comment strips nothing and a `;` in a string ends nothing.
fn without_test_items(src: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let b: Vec<char> = src.chars().collect();
    let attr: Vec<char> = ATTR.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if let Some((end, _)) = literal_at(&b, i) {
            out.extend(&b[i..end]);
            i = end;
        } else if b[i..].starts_with(&attr) {
            i = test_item_end(&b, i + attr.len());
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// The index just past the item that starts at `start` (after its
/// `#[cfg(test)]`). `<` counts as a bracket only when it opens generics
/// (`Option<`, `::<`), never as a comparison (`1 < 2`).
fn test_item_end(b: &[char], start: usize) -> usize {
    let (mut depth, mut angle) = (0i32, 0i32);
    let mut i = start;
    while i < b.len() {
        if let Some((end, _)) = literal_at(b, i) {
            i = end;
            continue;
        }
        let prev = if i > 0 { b[i - 1] } else { ' ' };
        match b[i] {
            '(' | '[' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return i,
            ')' | ']' => depth -= 1,
            '<' if prev.is_alphanumeric() || prev == '_' || prev == ':' => angle += 1,
            '>' if angle > 0 && !matches!(prev, '-' | '=' | ' ') => angle -= 1,
            ';' if depth == 0 => return i + 1,
            ',' if depth == 0 && angle == 0 => return i + 1,
            '{' if depth == 0 => return literal_block_end(b, i),
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// The index just past the `}` matching the `{` at `open`, skipping literals.
fn literal_block_end(b: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        if let Some((end, _)) = literal_at(b, i) {
            i = end;
            continue;
        }
        match b[i] {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
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

/// A comment, string or char literal in source.
enum Literal {
    Comment,
    Str(String),
    Char,
}

/// The comment or literal starting at `b[i]`, with the index just past it:
/// `//` and nested `/* */` comments; `"…"`, `b"…"` and `c"…"` strings;
/// `r"…"`, `r#"…"#`, `br"…"`, `br#"…"#`, `cr"…"` and `cr#"…"#` raw strings;
/// and `'x'`, `'\''` and `b'x'` char literals (a lifetime `'a` is code).
fn literal_at(b: &[char], i: usize) -> Option<(usize, Literal)> {
    let at = |k: usize| b.get(k).copied();
    let starts_token = !ident_char(b, i);
    match (at(i)?, at(i + 1)) {
        ('/', Some('/')) => {
            let end = (i..b.len()).find(|&k| b[k] == '\n').unwrap_or(b.len());
            Some((end, Literal::Comment))
        }
        ('/', Some('*')) => {
            let (mut depth, mut k) = (0, i);
            while k < b.len() {
                if b[k] == '/' && at(k + 1) == Some('*') {
                    depth += 1;
                    k += 2;
                } else if b[k] == '*' && at(k + 1) == Some('/') {
                    depth -= 1;
                    k += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    k += 1;
                }
            }
            Some((k.min(b.len()), Literal::Comment))
        }
        ('"', _) => Some(quoted(b, i + 1)),
        ('b' | 'c', Some('"')) if starts_token => Some(quoted(b, i + 2)),
        ('r', Some('"' | '#')) if starts_token => raw(b, i + 1),
        ('b' | 'c', Some('r')) if starts_token => raw(b, i + 2),
        ('b', Some('\'')) if starts_token => Some((char_end(b, i + 1), Literal::Char)),
        ('\'', _) if is_char_literal(b, i) => Some((char_end(b, i), Literal::Char)),
        _ => None,
    }
}

/// The escaped string whose contents start at `b[i]`.
fn quoted(b: &[char], mut i: usize) -> (usize, Literal) {
    let mut s = String::new();
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
    ((i + 1).min(b.len()), Literal::Str(s))
}

/// The raw string whose `#`s or opening quote start at `b[i]`; `None` for a raw
/// identifier (`r#match`) or a plain identifier.
fn raw(b: &[char], i: usize) -> Option<(usize, Literal)> {
    let hashes = b[i..].iter().take_while(|&&c| c == '#').count();
    if b.get(i + hashes) != Some(&'"') {
        return None;
    }
    let open = i + hashes + 1;
    let closes = |k: usize| b[k] == '"' && (1..=hashes).all(|h| b.get(k + h) == Some(&'#'));
    let close = (open..b.len()).find(|&k| closes(k)).unwrap_or(b.len());
    let end = (close + 1 + hashes).min(b.len());
    Some((end, Literal::Str(b[open..close].iter().collect())))
}

/// The index just past the char literal whose opening quote is `b[i]`.
fn char_end(b: &[char], i: usize) -> usize {
    let mut k = i + 1;
    if b.get(k) == Some(&'\\') {
        k += 2;
    } else {
        k += 1;
    }
    while k < b.len() && b[k] != '\'' {
        k += 1;
    }
    (k + 1).min(b.len())
}

/// Split Rust source into code (comments, strings and char literals replaced
/// by spaces) and the contents of its string literals.
fn lex(src: &str) -> (String, Vec<String>) {
    let b: Vec<char> = src.chars().collect();
    let (mut code, mut strings) = (String::new(), Vec::new());
    let mut i = 0;
    while i < b.len() {
        match literal_at(&b, i) {
            Some((end, literal)) => {
                match literal {
                    Literal::Comment => code.push(' '),
                    Literal::Str(s) => {
                        strings.push(s);
                        code.push_str(" \"\" ");
                    }
                    Literal::Char => code.push_str(" ' ' "),
                }
                i = end;
            }
            None => {
                code.push(b[i]);
                i += 1;
            }
        }
    }
    (code, strings)
}

fn ident_char(b: &[char], i: usize) -> bool {
    i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_')
}

/// Whether the `'` at `b[i]` opens a char literal rather than a lifetime: an
/// escape follows, or a single char and a closing quote.
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
    // The only family-gate waiver is the explicit Recovery path, where the
    // model requires fresh typed consent and the library retains its other
    // receiver, marker, integrity, restoration and handoff checks.
    let prepare_without_family_check: Vec<_> = sources
        .iter()
        .filter(|s| !word_hits(&s.code, "prepare_without_family_check").is_empty())
        .map(|s| s.path.as_str())
        .collect();
    assert_eq!(
        prepare_without_family_check,
        ["src/backends/pioneer/recovery.rs"]
    );
    let recovery = source(&sources, "src/backends/pioneer/recovery.rs");
    let recovery_code = tighten(&normalise(&recovery.code));
    assert!(recovery_code.contains(
        "let prepared=if bypass_family_check{receiver.prepare_without_family_check(target)}else{receiver.prepare(target)}"
    ));

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
        current: None,
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
    let issue = freemkv_flash::workflow::user_error(&error);
    assert_eq!(issue.id, "errors.backup_destination");
    assert_eq!(issue.consequence, Some("errors.update_blocked"));
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

#[test]
fn lexer_ends_every_literal_form_where_it_ends() {
    let (code, strings) = lex(r##"let a = b"\""; m_byte
        let b = br"\"; m_raw_byte
        let c = br#"x"y"#; m_raw_byte_hash
        let d = c"\""; m_c_str
        let e = cr"\"; m_raw_c
        let f = cr#"\"#; m_raw_c_hash
        let g = b'"'; m_byte_char
        let h = '"'; m_char
        let i = '\''; m_escaped_char
        fn j<'a>(x: &'a u8) -> &'a u8 { m_lifetime }
        let k = r#match; m_raw_ident
        let l = r"\"; m_raw"##);
    for marker in [
        "m_byte",
        "m_raw_byte",
        "m_raw_byte_hash",
        "m_c_str",
        "m_raw_c",
        "m_raw_c_hash",
        "m_byte_char",
        "m_char",
        "m_escaped_char",
        "m_lifetime",
        "match",
        "m_raw",
    ] {
        assert_eq!(word_hits(&code, marker).len(), 1, "{marker} hidden: {code}");
    }
    assert_eq!(
        strings,
        [r#"\""#, r"\", r#"x"y"#, r#"\""#, r"\", r"\", r"\"]
    );
}

#[test]
fn test_items_end_where_they_end() {
    // A comparison is not a generic bracket.
    assert_eq!(
        without_test_items("#[cfg(test)]\nlet _p = 1 < 2;\nm1 { }"),
        "\nm1 { }"
    );
    assert_eq!(
        without_test_items("#[cfg(test)]\nconst X: bool = 3 > 2 && 1 < 2;\nfn m2() {}"),
        "\nfn m2() {}"
    );
    // A `;` or `}` in a literal, or the attribute in a comment, ends nothing.
    assert_eq!(
        without_test_items("#[cfg(test)]\nconst S: &str = \"};\";\nm3"),
        "\nm3"
    );
    let doc = "/// #[cfg(test)]\nfn m4() {}";
    assert_eq!(without_test_items(doc), doc);
    // A field: generics hold commas; the last field ends at the closing brace.
    assert_eq!(
        without_test_items("S {\n#[cfg(test)]\nf: HashMap<A, B>,\nm5: C }"),
        "S {\n\nm5: C }"
    );
    assert_eq!(
        without_test_items("S { a: A,\n#[cfg(test)]\ng: Vec<Vec<u8>> }\nm6"),
        "S { a: A,\n}\nm6"
    );
    assert_eq!(
        without_test_items("#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod tests;\nm7"),
        "\nm7"
    );
}

/// How production code loads a file: `#[path = ".."]`, `include!("..")` (whose
/// target is `None` unless a plain literal) or `mod name;`.
#[derive(Debug, PartialEq)]
enum Link {
    Path(String),
    Include(Option<String>),
    Mod(String),
}

/// Every [`Link`] in lexed `code`, whose string literals are `strings` in order.
fn module_links(code: &str, strings: &[String]) -> Vec<Link> {
    let tight = tighten(code);
    // The literal whose `""` placeholder starts at `at`.
    let literal = |at: usize| strings.get(tight[..at].matches("\"\"").count()).cloned();
    let mut out = Vec::new();
    for at in word_hits(&tight, "path") {
        let rest = &tight[at + "path".len()..];
        if tight[..at].ends_with("#[") && rest.starts_with("=\"\"") {
            out.extend(literal(at + "path=".len()).map(Link::Path));
        }
    }
    for at in word_hits(&tight, "include") {
        let rest = &tight[at + "include".len()..];
        if rest.starts_with('!') {
            let plain = rest.starts_with("!(\"\")");
            let target = plain.then(|| literal(at + "include!(".len())).flatten();
            out.push(Link::Include(target));
        }
    }
    for at in word_hits(&tight, "mod") {
        let rest = &tight[at + "mod".len()..].trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && rest[name.len()..].starts_with(';') {
            out.push(Link::Mod(name));
        }
    }
    out
}

/// Production code loads only files the scan reads: every `#[path]` and
/// `include!` outside `#[cfg(test)]` names an existing, scanned `.rs` file, and
/// no `mod x;` loads a `tests.rs` or `*_tests.rs` file.
#[test]
fn production_code_loads_only_scanned_files() {
    let mut problems = Vec::new();
    let mut mods = 0;
    for s in production_sources() {
        let dir = root().join(&s.path);
        let dir = dir.parent().unwrap();
        let scanned = |target: &str| {
            let file = dir.join(target);
            let name = file.file_name().map(|n| n.to_string_lossy().into_owned());
            file.is_file()
                && file.starts_with(root().join("src"))
                && name.is_some_and(|n| scanned_name(&n))
        };
        for link in module_links(&s.code, &s.strings) {
            let ok = match &link {
                Link::Path(target) | Link::Include(Some(target)) => scanned(target),
                Link::Include(None) => false,
                Link::Mod(name) => {
                    mods += 1;
                    scanned_name(&format!("{name}.rs"))
                }
            };
            if !ok {
                problems.push(format!("{}: {link:?} loads a file the scan skips", s.path));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(mods >= 10, "the scan found only {mods} module declarations");
}

#[test]
fn module_links_find_every_loaded_file() {
    let src = "#[cfg(test)]\n#[path = \"a_tests.rs\"]\nmod tests;\n\
               #[path = \"x_tests.rs\"]\npub mod x;\n\
               #[cfg(any())]\n#[path=\"y.txt\"] mod y;\n\
               fn f() { include!(\"gen.in\"); include ! (concat!(env!(\"OUT_DIR\"), \"/g.rs\")); }\n\
               const T: &str = include_str!(\"t.txt\");\n\
               mod tests;\n\
               pub(crate) mod engine;\n\
               mod inline { }\n";
    let (code, strings) = lex(&without_test_items(src));
    assert_eq!(
        module_links(&code, &strings),
        [
            Link::Path("x_tests.rs".into()),
            Link::Path("y.txt".into()),
            Link::Include(Some("gen.in".into())),
            Link::Include(None),
            Link::Mod("x".into()),
            Link::Mod("y".into()),
            Link::Mod("tests".into()),
            Link::Mod("engine".into()),
        ]
    );
    assert!(scanned_name("engine.rs"));
    for name in ["x_tests.rs", "tests.rs", "y.txt", "gen.in"] {
        assert!(!scanned_name(name), "{name}");
    }
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

/// A read grant's data-out patterns come only from `Backend::allowed_data_out`
/// (`ReadDevice::new` is private), so only a registered backend may declare
/// them: no other module implements `Backend` or `allowed_data_out`.
#[test]
fn read_grant_patterns_come_only_from_backends() {
    let mut problems = Vec::new();
    let mut backends = 0;
    for s in production_sources() {
        let backend_module = s.path.starts_with("src/backends/");
        for at in word_hits(&s.code, "allowed_data_out") {
            let defines = s.code[..at].trim_end().ends_with("fn");
            if defines && !backend_module && s.path != "src/backend/mod.rs" {
                problems.push(format!("{}: defines allowed_data_out", s.path));
            }
        }
        for at in word_hits(&s.code, "impl") {
            let end = s.code[at..]
                .find(['{', ';'])
                .map_or(s.code.len(), |e| at + e);
            let head = strip_paths(&s.code[at..end]);
            let words: Vec<&str> = head.split_whitespace().collect();
            if words.windows(2).any(|w| w == ["Backend", "for"]) {
                backends += 1;
                if !backend_module {
                    problems.push(format!("{}: implements Backend", s.path));
                }
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(backends >= 2, "the scan found {backends} Backend impls");
}

/// The SCSI device layer: the trait, its implementations and wrappers, and
/// the transport bridge. Everything above it writes through a grant.
const DEVICE_LAYER: &[&str] = &[
    "src/platform/",
    "src/transport.rs",
    "src/backend/device.rs",
    "src/engine/gates.rs",
    "src/inspection/capture.rs",
];

/// What can only write the drive's firmware or settings: the strict data-out
/// call, the write transport, and the vendor crates' data-out entry points.
/// pioneer-optical: `drive::enter_update` (its `Session::write`/`finish`),
/// `drive::execute_update`, `drive::diagnostic_memory` (writes on `Data::Out`),
/// `logging::set_logging_ram`/`_persistent`, `receiver::Prepared*::flash` (via a
/// `FlashTransport`) and the settings writers `device::Device::set` and
/// `device::Writable::write` (implemented by `QuietDrive`, `PureRead` and
/// `DvdRegion`; `Device::write_setting` is crate-private, and the device and
/// settings modules have no `set_*` setters).
/// mediatek-optical: `drive::enter_update` (its `Session::write`/`finish`).
const WRITE_MARKERS: &[&str] = &[
    ".command_out_strict(",
    "ScsiTransport::flash(",
    "drive::enter_update(",
    "execute_update(",
    "diagnostic_memory(",
    "set_logging_",
    "FlashTransport",
    "Device::set(",
    "Writable",
];

/// What reaches the drive but may run under a read grant: the read transport,
/// a settings device over it (or lent by `standard::with_device`), and the
/// lenient data-out used for the read knock.
const READ_MARKERS: &[&str] = &[
    ".command_out(",
    "ScsiTransport::reads(",
    "Device::new(",
    "Device::with_settings_codec(",
    "with_device(",
];

/// What opens a settings device; with a [`SETTINGS_WRITES`] form in the same
/// function, that is a settings write whichever way it is spelled.
const SETTINGS_DEVICE: &[&str] = &[
    "Device::new(",
    "Device::with_settings_codec(",
    "with_device(",
];

/// The settings-write calls on a pioneer-optical `Device`, matched after
/// [`tighten`]: `d.set(..)`, `Device::set(..)`, `QuietDrive.write(d, ..)`,
/// `Writable::write(..)`.
const SETTINGS_WRITES: &[&str] = &[".set(", "::set(", ".write(", "::write(", "Writable"];

/// The vendor write functions, which production code names only by path so
/// the markers above see every call.
const WRITE_FNS: &[&str] = &[
    "enter_update",
    "execute_update",
    "diagnostic_memory",
    "set_logging_ram",
    "set_logging_persistent",
];

/// Modules and types whose paths the markers match; renaming or glob-importing
/// them would hide a call from the scan.
const MARKED_PATHS: &[&str] = &[
    "drive",
    "logging",
    "receiver",
    "device",
    "Device",
    "FlashTransport",
    "ScsiTransport",
    "SharedDevice",
];

/// Device parameters that may hold a read marker: each carries a runtime grant.
const GATED_HANDLES: &[&str] = &["WriteDevice", "ReadDevice", "DeviceAccess"];

/// Raw device parameters (after [`normalise`]): a marker beside one bypasses
/// every grant.
const RAW_HANDLES: &[&str] = &[
    "dyn ScsiDevice",
    "&ScsiTransport",
    "&mut ScsiTransport",
    ": ScsiTransport",
    "&SharedDevice",
    "&mut SharedDevice",
    ": SharedDevice",
];

/// A fn whose body holds a marker, with its signature normalised.
#[derive(Debug)]
struct Issuer {
    name: String,
    /// The `<...>` after the name, the parameters, and everything between `)`
    /// and the body (return type and `where` clause).
    generics: String,
    params: String,
    bounds: String,
    /// The body holds a write marker, not only read markers.
    writes: bool,
}

/// Why `f` reaches the drive outside its grant, if it does.
fn refusal(f: &Issuer) -> Option<&'static str> {
    let generic = [&f.generics, &f.params, &f.bounds]
        .iter()
        .any(|s| !word_hits(s, "Transport").is_empty())
        || [&f.generics, &f.bounds]
            .iter()
            .any(|s| !word_hits(s, "ScsiDevice").is_empty())
        || f.params.contains("impl ScsiDevice");
    if generic {
        return Some("takes a generic Transport/ScsiDevice");
    }
    let params = strip_paths(&f.params);
    if RAW_HANDLES.iter().any(|h| params.contains(h)) {
        return Some("takes a raw device beside its grant");
    }
    if f.writes {
        // A path-qualified grant (`&mut gates::WriteDevice`) counts; a DeviceAccess does
        // not, so a write sits in a function that takes the WriteDevice itself.
        let write_grant = params.contains("&mut WriteDevice") || params.contains(": WriteDevice");
        return (!write_grant).then_some("writes without a WriteDevice");
    }
    (!GATED_HANDLES.iter().any(|h| f.params.contains(h)))
        .then_some("reaches the drive without a grant")
}

/// `s` with module paths dropped (`gates::WriteDevice` → `WriteDevice`).
fn strip_paths(s: &str) -> String {
    let mut out = String::new();
    for (i, part) in s.split("::").enumerate() {
        if i > 0 {
            let keep = out.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
            out.truncate(keep.len());
        }
        out.push_str(part);
    }
    out
}

/// Whether `body` holds `marker`; a marker starting with an identifier must
/// start a word, so `ReadDevice::new(` is not `Device::new(`.
fn has_marker(body: &str, marker: &str) -> bool {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let word = marker.as_bytes().first().is_some_and(|&b| is_ident(b));
    body.match_indices(marker)
        .any(|(at, _)| !word || at == 0 || !is_ident(body.as_bytes()[at - 1]))
}

/// The offset just past the `>` matching the `<` at `open`; `->` and `=>` do
/// not close.
fn angle_end(text: &str, open: usize) -> usize {
    let (mut depth, mut prev) = (0usize, ' ');
    for (off, c) in text[open..].char_indices() {
        match c {
            '<' => depth += 1,
            '>' if prev != '-' && prev != '=' => {
                depth -= 1;
                if depth == 0 {
                    return open + off + 1;
                }
            }
            _ => {}
        }
        prev = c;
    }
    text.len()
}

/// Lexed `code` with lifetimes (`'a `, `'_, `) and turbofish generics removed,
/// so `&'a mut ScsiTransport` reads `&mut ScsiTransport` and `Device::<T>::new(`
/// reads `Device::new(`.
fn normalise(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    while i < code.len() {
        let rest = &code[i..];
        if rest.starts_with("::<") {
            i += angle_end(rest, 2);
            continue;
        }
        let mut chars = rest.chars();
        let c = chars.next().unwrap();
        let lifetime = c == '\'' && chars.next().is_some_and(|n| n.is_alphabetic() || n == '_');
        if lifetime {
            let len = 1 + rest[1..]
                .find(|n: char| !(n.is_alphanumeric() || n == '_'))
                .unwrap_or(rest.len() - 1);
            let after = rest[len..].trim_start();
            let after = after
                .strip_prefix([',', '+'])
                .map_or(after, str::trim_start);
            i = code.len() - after.len();
            continue;
        }
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// `code` with whitespace removed except between two identifier characters,
/// where one space stays: `d . set (` reads `d.set(`.
fn tighten(code: &str) -> String {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(code.len());
    let mut gap = false;
    for c in code.chars() {
        if c.is_whitespace() {
            gap = true;
            continue;
        }
        if gap && ident(c) && out.chars().next_back().is_some_and(ident) {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    out
}

/// A fn with a body in normalised code.
struct FnItem {
    name: String,
    /// The `<...>` after the name, the parameters, and everything between `)`
    /// and the body (return type and `where` clause).
    generics: String,
    params: String,
    bounds: String,
    body: String,
}

/// Every fn with a body in [`normalise`]d `code`.
fn fn_items(code: &str) -> Vec<FnItem> {
    let mut out = Vec::new();
    for at in word_hits(code, "fn") {
        let rest = code[at + 2..].trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let after_name = &rest[name.len()..];
        let generics_end = match after_name.trim_start().starts_with('<') {
            true => angle_end(after_name, after_name.find('<').unwrap()),
            false => 0,
        };
        let generics = &after_name[..generics_end];
        let Some(open) = after_name[generics_end..]
            .find('(')
            .map(|o| o + generics_end)
        else {
            continue;
        };
        let mut depth = 0usize;
        let mut close = after_name.len();
        for (off, c) in after_name[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + off;
                        break;
                    }
                }
                _ => {}
            }
        }
        let params = &after_name[open + 1..close];
        let tail = &after_name[close..];
        let Some(brace) = tail.find('{') else {
            continue;
        };
        if tail.find(';').is_some_and(|semi| semi < brace) {
            continue;
        }
        out.push(FnItem {
            name,
            generics: generics.to_string(),
            params: params.to_string(),
            bounds: tail[1..brace].to_string(),
            body: tail[brace..block_end(tail, brace)].to_string(),
        });
    }
    out
}

/// Every fn in lexed `code` whose body holds a write or read marker.
fn write_issuers(code: &str) -> Vec<Issuer> {
    let mut out = Vec::new();
    for f in fn_items(&normalise(code)) {
        let body = tighten(&f.body);
        // A helper handed the vendor settings `Device` counts too, whether as a
        // parameter, a returned closure's argument or a typed closure argument.
        let signature = tighten(&strip_paths(&format!(
            "{}({}){}",
            f.generics, f.params, f.bounds
        )));
        let settings_device = SETTINGS_DEVICE.iter().any(|m| has_marker(&body, m))
            || has_marker(&signature, "Device<")
            || has_marker(&strip_paths(&body), "Device<");
        let settings_write =
            settings_device && SETTINGS_WRITES.iter().any(|m| has_marker(&body, m));
        let writes = settings_write || WRITE_MARKERS.iter().any(|m| has_marker(&body, m));
        if writes || READ_MARKERS.iter().any(|m| has_marker(&body, m)) {
            out.push(Issuer {
                name: f.name,
                generics: f.generics,
                params: f.params,
                bounds: f.bounds,
                writes,
            });
        }
    }
    out
}

/// What a fn in lexed `code` lends: the [`HIDDEN_TYPES`] or `dyn ScsiDevice`
/// named in a closure parameter's arguments (`impl FnOnce(&mut X)`, `F:
/// Fn(X)`) or in its return type, as `(name, lent text)`. Every fn counts,
/// whatever its visibility: a trait method needs no `pub`.
fn lenders(code: &str) -> Vec<(String, String)> {
    let lent = |s: &str| {
        HIDDEN_TYPES.iter().any(|t| !word_hits(s, t).is_empty()) || s.contains("dyn ScsiDevice")
    };
    let mut out = Vec::new();
    for f in fn_items(&normalise(code)) {
        let sig = format!("{} {} {}", f.generics, f.params, f.bounds);
        let mut handed = Vec::new();
        for closure in ["Fn", "FnMut", "FnOnce"] {
            for at in word_hits(&sig, closure) {
                let rest = &sig[at + closure.len()..];
                if rest.starts_with('(') {
                    let mut depth = 0i32;
                    let close = rest
                        .char_indices()
                        .find(|&(_, c)| {
                            depth += match c {
                                '(' => 1,
                                ')' => -1,
                                _ => 0,
                            };
                            depth == 0
                        })
                        .map_or(rest.len(), |(i, _)| i);
                    handed.push(rest[1..close].to_string());
                }
            }
        }
        let ret = f.bounds.split(" where ").next().unwrap_or("");
        if let Some((_, ret)) = ret.split_once("->") {
            handed.push(ret.trim().to_string());
        }
        for h in handed.into_iter().filter(|h| lent(h)) {
            out.push((
                f.name.clone(),
                h.split_whitespace().collect::<Vec<_>>().join(" "),
            ));
        }
    }
    out
}

/// Every `use` in lexed `code` that would let a write call dodge the markers:
/// a vendor write fn imported by bare name, a glob over a marked module, or a
/// marked module or type renamed.
fn hiding_imports(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for at in word_hits(code, "use") {
        let rest = &code[at..];
        let stmt = &rest[..rest.find(';').unwrap_or(rest.len())];
        let names = |list: &[&str]| list.iter().any(|w| !word_hits(stmt, w).is_empty());
        let words: Vec<&str> = stmt
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect();
        let renamed = words
            .windows(3)
            .any(|w| w[1] == "as" && w[2] != "_" && MARKED_PATHS.contains(&w[0]))
            || renamed_self(stmt);
        let marked = names(MARKED_PATHS);
        if names(WRITE_FNS) || (marked && (stmt.contains('*') || renamed)) {
            out.push(stmt.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    out
}

/// Device and transport types a `type` alias or a wrapper struct could hide from
/// the scan: a method on the wrapper would write with no marker in sight.
const HIDDEN_TYPES: &[&str] = &["Device", "FlashTransport", "ScsiTransport", "SharedDevice"];

/// Wrappers allowed to hold a device type, each with why it cannot write ungated.
const ALLOWED_WRAPPERS: &[(&str, &str, &str)] = &[(
    "src/backends/pioneer/flash.rs",
    "struct Runtime<'a, 'd>",
    "built only inside execute_with_sleep from its WriteDevice; its methods only read",
)];

/// Migration now belongs to the optical executor. No app adapter may bypass
/// the ordinary write-grant checks.
const ALLOWED_MIGRATION_ISSUERS: &[(&str, &str, &str)] = &[];

/// Every `type` alias of, or struct wrapping, a [`HIDDEN_TYPES`] type in lexed
/// `code`; outside the device layer these are refused like a renaming `use`.
fn hiding_types(code: &str) -> Vec<String> {
    let names = |s: &str| HIDDEN_TYPES.iter().any(|t| !word_hits(s, t).is_empty());
    let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = Vec::new();
    for at in word_hits(code, "type") {
        let stmt = &code[at..at + code[at..].find(';').unwrap_or(code.len() - at)];
        if stmt.split_once('=').is_some_and(|(_, rhs)| names(rhs)) {
            out.push(flat(stmt));
        }
    }
    for kind in ["struct", "enum", "union"] {
        for at in word_hits(code, kind) {
            let rest = &code[at..];
            let end = match (rest.find('{'), rest.find(';')) {
                (Some(b), Some(semi)) if b < semi => block_end(rest, b),
                (Some(b), None) => block_end(rest, b),
                (_, Some(semi)) => semi,
                (None, None) => rest.len(),
            };
            let decl = &rest[..end.min(rest.len())];
            let head = decl.find(['{', '(']).unwrap_or(decl.len());
            // Everything after the name, so a generic default hides nothing.
            let name_end = kind.len()
                + decl[kind.len()..]
                    .find(|c: char| !(c.is_whitespace()))
                    .unwrap_or(0);
            let name_end = name_end
                + decl[name_end..]
                    .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .unwrap_or(decl.len() - name_end);
            if names(&decl[name_end..]) {
                out.push(flat(&decl[..head]));
            }
        }
    }
    out
}

/// Whether `stmt` renames a marked module through `{self as x}`: the module is
/// the path segment before the group holding that `self`.
fn renamed_self(stmt: &str) -> bool {
    let flat: String = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.match_indices("self as ").any(|(at, _)| {
        let mut depth = 0i32;
        let open = flat[..at].char_indices().rev().find(|&(_, c)| {
            depth += match c {
                '}' => 1,
                '{' => -1,
                _ => 0,
            };
            depth < 0
        });
        let module = open.map_or("", |(o, _)| {
            let path = flat[..o].trim_end_matches("::");
            path.rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("")
        });
        MARKED_PATHS.contains(&module)
    })
}

#[test]
fn write_issuers_take_the_write_grant() {
    let sources = production_sources();
    let (mut problems, mut issuers, mut wrappers, mut migration_issuers) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for s in &sources {
        for import in hiding_imports(&s.code) {
            problems.push(format!("{}: `{import}` hides a write call", s.path));
        }
        if DEVICE_LAYER.iter().any(|layer| s.path.starts_with(layer)) {
            continue;
        }
        for hidden in hiding_types(&s.code) {
            let allowed = ALLOWED_WRAPPERS
                .iter()
                .any(|(path, decl, _)| s.path == *path && hidden == *decl);
            if allowed {
                wrappers.push(format!("{}: {hidden}", s.path));
            } else {
                problems.push(format!("{}: `{hidden}` hides a device type", s.path));
            }
        }
        for f in write_issuers(&s.code) {
            if let Some(why) = refusal(&f) {
                if ALLOWED_MIGRATION_ISSUERS
                    .iter()
                    .any(|(path, name, _)| s.path == *path && f.name == *name)
                {
                    migration_issuers.push((s.path.clone(), f.name.clone()));
                } else {
                    problems.push(format!("{}: fn {}({}) {why}", s.path, f.name, f.params));
                }
            }
            issuers.push((f.name, f.writes));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    // The scan must still see the known executors, or it proves nothing.
    for (known, writes) in [
        ("execute_with_sleep", true),
        ("execute_stage", true),
        ("execute", true),
        ("enable_logging", true),
        ("capture", false),
        ("with_device", false),
    ] {
        assert!(
            issuers.iter().any(|i| *i == (known.to_string(), writes)),
            "{known} not scanned as writes={writes}: {issuers:?}"
        );
    }
    // A stale allowance would excuse a future wrapper of the same name.
    for (path, decl, _) in ALLOWED_WRAPPERS {
        let entry = format!("{path}: {decl}");
        assert!(
            wrappers.contains(&entry),
            "stale wrapper allowance: {entry}"
        );
    }
    for (path, name, _) in ALLOWED_MIGRATION_ISSUERS {
        assert!(
            migration_issuers.contains(&(path.to_string(), name.to_string())),
            "stale migration issuer allowance: {path}: {name}"
        );
    }
}

/// The names of the fns in `src` that [`write_issuers`] finds, and of those
/// [`refusal`] refuses.
fn scan(src: &str) -> (Vec<String>, Vec<String>) {
    let (code, _) = lex(&without_test_items(src));
    let found = write_issuers(&code);
    let names = found.iter().map(|f| f.name.clone()).collect();
    let refused = found
        .iter()
        .filter(|f| refusal(f).is_some())
        .map(|f| f.name.clone())
        .collect();
    (names, refused)
}

#[test]
fn write_issuer_scan_reads_signatures_and_bodies() {
    let (names, refused) = scan(
        "fn a(dev: &mut dyn ScsiDevice) { dev.command_out_strict(c, d); }\n\
         fn b(dev: &mut WriteDevice<'_>, f: impl Fn(u8)) { ScsiTransport::flash(&s); }\n\
         fn c(dev: &mut dyn ScsiDevice) { dev.command_in(c, 0); }\n\
         trait T { fn d(&self); }\n\
         fn e(dev: &mut dyn ScsiDevice) { dev.command_out(c, d); }\n\
         fn f(mut a: DeviceAccess<'_, '_>) { a.scsi().command_out(k, &[]); }\n\
         fn g(t: &mut ScsiTransport<'_, '_>) { logging::set_logging_ram(t, l, true); }\n\
         fn h(dev: &mut dyn ScsiDevice) { ReadDevice::new(dev, &[]); }\n\
         fn i(dev: &mut ReadDevice<'_>) { Device::new(&mut ScsiTransport::reads(&s)); }\n",
    );
    assert_eq!(names, ["a", "b", "e", "f", "g", "i"]);
    assert_eq!(refused, ["a", "e", "g"]);
}

#[test]
fn write_markers_need_the_write_grant() {
    let (names, refused) = scan(
        "fn r(dev: &mut ReadDevice<'_>) { drive::enter_update(&mut t, c, k); }\n\
         fn s(a: DeviceAccess<'_, '_>) { set_logging_ram(t, l, true); }\n\
         fn t(a: DeviceAccess<'_, '_>) {\n\
             if let DeviceAccess::Write(w) = a { drive::execute_update(w); }\n\
         }\n\
         fn u(a: &mut DeviceAccess<'_, '_>) { if let Some(w) = a.writer() { w.command_out_strict(c, d); } }\n\
         fn v(dev: &mut ReadDevice<'_>) { Device::set(&mut d, q, v); }\n\
         fn w(dev: &mut WriteDevice<'_>) { drive::enter_update(&mut t, c, k); }\n\
         fn x(dev: &mut ReadDevice<'_>) { dev.command_out(&knock(), &[]); }\n\
         fn y(dev: &mut ReadDevice<'_>) { with_device(dev, |d| d.set(QuietMode, v, p)); }\n\
         fn z(dev: &mut gates::WriteDevice<'_>) { drive::execute_update(t); }\n\
         fn q(dev: &mut ReadDevice<'_>) { Device::with_settings_codec(t, c).query(); }\n\
         fn h(d: &mut pioneer_optical::device::Device<'_, T>) { d.set(QuietMode, v, p); }\n\
         fn p(t: &mut crate::transport::ScsiTransport<'_, '_>, w: &mut WriteDevice<'_>) { ScsiTransport::flash(&s); }\n\
         fn o(r: &mut ReadDevice<'_>) { r.set_timeout(t); }\n\
         fn k(r: &mut ReadDevice<'_>, c: &Cell<u8>) { c.set(1); r.command_out(&knock(), &[]); }\n",
    );
    assert_eq!(
        names,
        ["r", "s", "t", "u", "v", "w", "x", "y", "z", "q", "h", "p", "k"]
    );
    assert_eq!(refused, ["r", "s", "t", "u", "v", "y", "h", "p"]);
    assert_eq!(
        strip_paths("a: &mut gates::WriteDevice<'_>"),
        "a: &mut WriteDevice<'_>"
    );
    assert_eq!(
        strip_paths("&mut crate::engine::gates::WriteDevice"),
        "&mut WriteDevice"
    );
}

#[test]
fn settings_writes_through_a_lent_device_need_the_write_grant() {
    let (names, refused) = scan(
        "fn a(dev: &mut ReadDevice<'_>) {\n\
             crate::standard::with_device(dev, |d| QuietDrive.write(d, QuietMode::Quiet, Persistence::Saved));\n\
         }\n\
         fn b(dev: &mut ReadDevice<'_>) { with_device(dev, |d| d . set (QuietDrive, v, p)); }\n\
         fn c(dev: &mut ReadDevice<'_>) { with_device(dev, |d| d\n.set(QuietDrive, v, p)); }\n\
         fn d(dev: &mut ReadDevice<'_>) { with_device(dev, |d| Writable::write(&PureRead, d, v, p)); }\n\
         fn e(dev: &mut ReadDevice<'_>) { with_device(dev, |d| <DvdRegion as W>::write(&DvdRegion, d, v, p)); }\n\
         fn f() -> impl FnOnce(&mut Device<'_, ScsiTransport<'_, '_>>) { |d| { d.set(QuietDrive, v, p); } }\n\
         fn g(dev: &mut ReadDevice<'_>) { let w = |d: &mut device::Device<'_, T>| d.set(q, v, p); go(dev, w); }\n\
         fn h(o: &Opened) { with_device(&mut ReadDevice::without_unlocks(o.raw()), |d| d.info()); }\n\
         fn i(dev: &mut ReadDevice<'_>) { with_device(dev, |d| d.get(DvdRegion)); }\n\
         fn j(dev: &mut ReadDevice<'_>) { standard::with_device(dev, |d| d.settings()); }\n",
    );
    assert_eq!(names, ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]);
    assert_eq!(refused, ["a", "b", "c", "d", "e", "f", "g", "h"]);
    assert_eq!(tighten("d . set (q,\n v)"), "d.set(q,v)");
    assert_eq!(tighten("pub fn  a"), "pub fn a");
}

#[test]
fn write_issuer_scan_sees_through_lifetimes_turbofish_and_generics() {
    let (names, refused) = scan(
        "fn a<'a>(t: &'a mut ScsiTransport<'a, 'a>, w: &mut WriteDevice<'a>) { ScsiTransport::flash(&s); }\n\
         fn b(s: &'_ SharedDevice<'_>, w: &mut WriteDevice<'_>) { execute_update(s); }\n\
         fn c(w: &mut WriteDevice<'_>) { Device::<ScsiTransport<'_, '_>>::new(&mut t); }\n\
         fn d(w: &mut WriteDevice<'_>) { Device::<T>::set(&mut d, q); }\n\
         fn e<T: Transport>(t: &mut T, w: &mut WriteDevice<'_>) { drive::enter_update(t, c, k); }\n\
         fn f(t: &mut impl Transport, w: &mut WriteDevice<'_>) { drive::execute_update(t); }\n\
         fn g<D>(d: &mut D, w: &mut WriteDevice<'_>) where D: ScsiDevice + ?Sized { d.command_out_strict(c, b); }\n\
         fn h<D: ScsiDevice + ?Sized>(d: &mut D, r: &mut ReadDevice<'_>) { d.command_out(c, b); }\n\
         fn i<F: Fn(u8) -> u8>(w: &mut WriteDevice<'_>, f: F) { drive::enter_update(t, c, k); }\n",
    );
    assert_eq!(names, ["a", "b", "c", "d", "e", "f", "g", "h", "i"]);
    assert_eq!(refused, ["a", "b", "e", "f", "g", "h"]);
    assert_eq!(
        normalise("x: &'a mut ScsiTransport<'a, 'b>, y: &'_ SharedDevice, z: T<'static + U>"),
        "x: &mut ScsiTransport<>, y: &SharedDevice, z: T<U>"
    );
    assert_eq!(
        normalise("Device::<A<B>>::new(v.iter().collect::<Vec<_>>())"),
        "Device::new(v.iter().collect())"
    );
}

#[test]
fn hiding_imports_are_refused() {
    let (code, _) = lex("use pioneer_optical::drive::enter_update;\n\
         use pioneer_optical::{drive::{self, execute_update as run}, Role};\n\
         use pioneer_optical::logging::*;\n\
         use pioneer_optical::drive as d;\n\
         use pioneer_optical::drive::{self as dr};\n\
         use pioneer_optical::device::Device as Dev;\n\
         use crate::transport::ScsiTransport as T;\n\
         use pioneer_optical::drive::{Data, Error, Transport};\n\
         use crate::transport::{self as transport, flash_err, ScsiTransport};\n\
         use mediatek_optical::drive::Data as MtkData;\n\
         use pioneer_optical::device::Device;\n\
         use std::fmt::Write as _;\n\
         pub use mediatek_optical::image::cmac::*;\n");
    assert_eq!(
        hiding_imports(&code),
        [
            "use pioneer_optical::drive::enter_update",
            "use pioneer_optical::{drive::{self, execute_update as run}, Role}",
            "use pioneer_optical::logging::*",
            "use pioneer_optical::drive as d",
            "use pioneer_optical::drive::{self as dr}",
            "use pioneer_optical::device::Device as Dev",
            "use crate::transport::ScsiTransport as T",
        ]
    );
}

#[test]
fn hiding_types_are_refused() {
    let (code, _) = lex("type Dev<'a> = Device<'a, ScsiTransport<'a, 'a>>;\n\
         pub(crate) type T = crate::transport::SharedDevice<'static>;\n\
         struct Wrap(Device<'static, X>);\n\
         struct Holder<'a> { inner: &'a mut FlashTransport<'a> }\n\
         type Bytes = Vec<u8>;\n\
         struct Plain { n: u32, dev: ReadDeviceInfo }\n\
         struct Unit;\n\
         pub enum Hide<'a> { T(ScsiTransport<'a, 'a>), N }\n\
         struct Defaulted<T = SharedDevice<'static>> { t: T }\n\
         enum Plain2 { A, B(u8) }\n");
    assert_eq!(
        hiding_types(&code),
        [
            "type Dev<'a> = Device<'a, ScsiTransport<'a, 'a>>",
            "type T = crate::transport::SharedDevice<'static>",
            "struct Wrap",
            "struct Holder<'a>",
            "struct Defaulted<T = SharedDevice<'static>>",
            "enum Hide<'a>",
        ]
    );
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
                    || (s.path == "src/backend/mod.rs"
                        && within_function(&s.code, at, "recover_with_family_override"))
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

/// Whether `at` is inside the body of a named function in lexed source.
fn within_function(code: &str, at: usize, name: &str) -> bool {
    let marker = format!("fn {name}");
    let Some(start) = code[..at].rfind(&marker) else {
        return false;
    };
    let Some(open) = code[start..].find('{').map(|offset| start + offset) else {
        return false;
    };
    at < block_end(code, open)
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

/// MediaTek backend code that may name a chip generation: `(file, mentions,
/// reason)`. The update path (plan, authorize, execute, backup, model gate)
/// names none: `mediatek_optical` decides chips and families.
const MTK_CHIP_MENTIONS: &[(&str, usize, &str)] = &[
    (
        "src/backends/mtk/file_info.rs",
        4,
        "the file report names the image's recipe and chip",
    ),
    (
        "src/backends/mtk/mod.rs",
        1,
        "the backend's flash summary names the proven chip",
    ),
];

/// Case-insensitive mentions of a MediaTek chip generation in `s`'s code and
/// string literals (comments excluded).
fn chip_mentions(s: &Source) -> usize {
    let count = |text: &str| {
        let lower = text.to_lowercase();
        lower.matches("mt1959").count() + lower.matches("mt1939").count()
    };
    count(&s.code) + s.strings.iter().map(|t| count(t)).sum::<usize>()
}

#[test]
fn mediatek_backend_names_no_chip_outside_reviewed_reports() {
    let mut found = Vec::new();
    for s in production_sources() {
        if s.path.starts_with("src/backends/mtk/") {
            let n = chip_mentions(&s);
            if n > 0 {
                found.push((s.path.clone(), n));
            }
        }
    }
    let allowed: Vec<(String, usize)> = MTK_CHIP_MENTIONS
        .iter()
        .map(|(path, n, _)| (path.to_string(), *n))
        .collect();
    assert_eq!(found, allowed, "MediaTek backend chip mentions changed");
}

#[test]
fn chip_mentions_skip_comments_and_count_strings() {
    let (code, strings) = lex("// MT1959\nlet c = Chip::Mt1939; let s = \"MT1959 Boot\";\n");
    let source = Source {
        path: String::new(),
        code,
        strings,
    };
    assert_eq!(chip_mentions(&source), 2);
}

// ---------------------------------------------------------------------------
// R9: front-end code names no vendor; that wording comes from descriptors
// ---------------------------------------------------------------------------

/// Vendor and chip-family names, matched case-insensitively.
const VENDOR_NAMES: &[&str] = &["pioneer", "mediatek", "mtk", "mt1959", "mt1939"];

/// Front-end exceptions: `(file, exact identifier or string literal, reason)`.
/// An entry that matches nothing fails the test, so the list cannot go stale.
const VENDOR_ALLOWLIST: &[(&str, &str, &str)] = &[];

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
// R11: Pioneer receive-placement and decoded-dialect API stay pinned
// ---------------------------------------------------------------------------

#[test]
fn optical_dependencies_stay_content_pinned() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    let lock = fs::read_to_string(root().join("../../Cargo.lock")).unwrap();
    for (name, version) in [("pioneer-optical", "1.5.0"), ("mediatek-optical", "1.2.0")] {
        let line = manifest
            .lines()
            .find(|line| line.trim_start().starts_with(name))
            .expect("optical dependency");
        assert!(
            line.contains(&format!("version = \"={version}\"")) && !line.contains("path ="),
            "{name} {version} must be pinned without a local path: {line}"
        );
        let package = lock
            .split("[[package]]")
            .find(|package| package.contains(&format!("name = \"{name}\"")))
            .expect("locked optical crate");
        assert!(package.contains(&format!("version = \"{version}\"")));
        if let Some((_, revision)) = line.split_once("rev = \"") {
            // Unpublished release candidates use an immutable source revision.
            let revision = revision.split('"').next().unwrap();
            assert!(revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(line.contains("git = \"https://github.com/MattJackson/"));
            assert!(package.contains(&format!("?rev={revision}#{revision}")));
            continue;
        }
        // Published releases retain exact registry versions and checksums.
        assert!(!line.contains("git ="));
        assert!(package.contains("registry+https://github.com/rust-lang/crates.io-index"));
        let checksum = package
            .lines()
            .find_map(|line| line.strip_prefix("checksum = \""))
            .unwrap()
            .trim_end_matches('"');
        assert!(checksum.len() == 64 && checksum.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn production_error_sinks_never_use_the_english_diagnostic_renderer() {
    let mut uses = Vec::new();
    for source in production_sources() {
        for at in word_hits(&source.code, "error_message") {
            uses.push((source.path.clone(), item_at(&items(&source.code), at)));
        }
    }
    assert_eq!(
        uses,
        [("src/workflow.rs".to_owned(), "fn error_message".to_owned())]
    );
}

/// Device-layer items that hold or lend a device type, as `(file, item,
/// reason)`: a [`hiding_types`] declaration or a [`lenders`] fn (`fn <name>
/// lends <type>`). Anything else the layer exported could carry a device type
/// past the census; an entry that matches nothing fails, so none goes stale.
const DEVICE_LAYER_REVIEWED: &[(&str, &str, &str)] = &[
    (
        "src/backend/device.rs",
        "fn scsi lends &mut dyn ScsiDevice",
        "DeviceAccess::scsi lends the ReadDevice or WriteDevice it holds as a \
         ScsiDevice, so that grant's own checks still apply to every command",
    ),
    (
        "src/platform/adapter.rs",
        "struct TransportDevice",
        "holds libfreemkv's OS transport (also named ScsiTransport, a different \
         type) below every grant; it never leaves the platform module",
    ),
    (
        "src/platform/mod.rs",
        "fn open lends Result<Box<dyn ScsiDevice>>",
        "opens the raw OS device for the workflows, which hand it to the engine \
         and registry; those reach a backend only through a ReadDevice or a \
         gates grant, and a fn holding a marker beside a raw device is refused",
    ),
    (
        "src/transport.rs",
        "fn with lends &mut dyn ScsiDevice",
        "SharedDevice::with lends back the device it wraps (outside the layer, \
         always a grant), never a transport or a settings Device",
    ),
    (
        "src/transport.rs",
        "struct ScsiTransport<'a, 'd>",
        "the transport's own definition, holding the SharedDevice it adapts",
    ),
];

#[test]
fn device_layer_exports_only_reviewed_device_holders() {
    let mut found = Vec::new();
    for s in production_sources() {
        if !DEVICE_LAYER.iter().any(|l| s.path.starts_with(l)) {
            continue;
        }
        for h in hiding_types(&s.code) {
            // Aliases are refused outright in `device_types_are_named_only_where_reviewed`.
            if !h.starts_with("type ") {
                found.push((s.path.clone(), h));
            }
        }
        for (name, lent) in lenders(&s.code) {
            found.push((s.path.clone(), format!("fn {name} lends {lent}")));
        }
    }
    let reviewed = |(path, item): &(String, String)| {
        DEVICE_LAYER_REVIEWED
            .iter()
            .any(|(p, i, _)| p == path && i == item)
    };
    let unreviewed: Vec<_> = found.iter().filter(|f| !reviewed(f)).collect();
    assert!(
        unreviewed.is_empty(),
        "the device layer holds or lends a device type in an unreviewed item: {unreviewed:#?}"
    );
    for (path, item, _) in DEVICE_LAYER_REVIEWED {
        assert!(
            found.iter().any(|(p, i)| p == path && i == item),
            "stale device-layer review: {path}: {item}"
        );
    }
}

#[test]
fn lenders_find_closures_and_returns_that_hand_out_a_device() {
    let (code, _) = lex("pub fn a<R>(d: &mut dyn ScsiDevice, f: impl FnOnce(&mut ScsiTransport<'_, '_>) -> R) -> R { x }\n\
         pub(crate) fn b<F: FnMut(&SharedDevice<'_>)>(f: F) { x }\n\
         fn c<F>(f: F) where F: Fn(&mut Device<'_, T>) { x }\n\
         pub fn d() -> FlashTransport<'static> { x }\n\
         pub fn e(&self, f: impl FnOnce(&mut dyn ScsiDevice)) { x }\n\
         pub fn reads(dev: &SharedDevice<'_>) -> Self { x }\n\
         pub fn writer(&mut self) -> Option<&mut WriteDevice<'_>> { x }\n\
         pub fn info(dev: &mut dyn ScsiDevice) -> Result<Identity> { x }\n\
         fn g(f: impl FnOnce((u8, u8), &mut ScsiTransport<'_, '_>)) { x }\n");
    let names: Vec<_> = lenders(&code)
        .into_iter()
        .map(|(name, lent)| format!("{name}: {lent}"))
        .collect();
    assert_eq!(
        names,
        [
            "a: &mut ScsiTransport<>",
            "b: &SharedDevice<>",
            "c: &mut Device<T>",
            "d: FlashTransport<>",
            "e: &mut dyn ScsiDevice",
            "g: (u8, u8), &mut ScsiTransport<>",
        ]
    );
}

/// Every mention of a [`HIDDEN_TYPES`] type outside the device layer, keyed by
/// file and enclosing item (see [`item_at`]): the reviewed write executors and
/// the standard settings reader. A new mention (an alias, enum, generic bound
/// or wrapper the shape scans miss) fails here until reviewed and counted, and
/// keying by item means dropping a mention from one item (a `use` replaced by
/// a full path) frees no slot for a new one, so this list is closed-world.
const DEVICE_TYPE_MENTIONS: &[(&str, &str, &str, usize)] = &[
    // File-derived receiver analysis takes only a ReadDevice grant.
    (
        "src/backends/mtk/receiver_reference.rs",
        "fn detect",
        "SharedDevice",
        1,
    ),
    (
        "src/backends/mtk/receiver_reference.rs",
        "fn detect",
        "ScsiTransport",
        1,
    ),
    // Dry-run encoding detection remains read-only and precedes backup capture.
    (
        "src/backends/mtk/mod.rs",
        "fn probe_receiver_encoding",
        "SharedDevice",
        1,
    ),
    (
        "src/backends/mtk/mod.rs",
        "fn probe_receiver_encoding",
        "ScsiTransport",
        1,
    ),
    (
        "src/backends/mtk/flash.rs",
        "fn execute_stage",
        "FlashTransport",
        1,
    ),
    (
        "src/backends/mtk/flash.rs",
        "fn execute_stage",
        "ScsiTransport",
        2,
    ),
    // The bound library plan revalidates using this shared read transport.
    (
        "src/backends/mtk/flash.rs",
        "fn execute_stage",
        "SharedDevice",
        1,
    ),
    // Detector adapters borrow only ReadDevice; library detection issues data-in only.
    (
        "src/backends/mtk/mod.rs",
        "fn detect_receiver",
        "ScsiTransport",
        1,
    ),
    (
        "src/backends/mtk/mod.rs",
        "fn detect_receiver",
        "SharedDevice",
        1,
    ),
    ("src/backends/mtk/flash.rs", "use", "FlashTransport", 1),
    (
        "src/backends/mtk/recovery.rs",
        "fn identify_with_current",
        "SharedDevice",
        1,
    ),
    (
        "src/backends/mtk/recovery.rs",
        "fn identify_with_current",
        "ScsiTransport",
        1,
    ),
    (
        "src/backends/mtk/recovery.rs",
        "fn execute",
        "SharedDevice",
        1,
    ),
    (
        "src/backends/mtk/recovery.rs",
        "fn execute",
        "ScsiTransport",
        2,
    ),
    (
        "src/backends/mtk/recovery.rs",
        "fn execute",
        "FlashTransport",
        1,
    ),
    ("src/backends/mtk/recovery.rs", "use", "SharedDevice", 1),
    ("src/backends/mtk/recovery.rs", "use", "ScsiTransport", 1),
    ("src/backends/mtk/recovery.rs", "use", "FlashTransport", 1),
    ("src/backends/mtk/flash.rs", "use", "ScsiTransport", 1),
    ("src/backends/mtk/flash.rs", "use", "SharedDevice", 1),
    (
        "src/backends/pioneer/dump.rs",
        "fn enable_logging",
        "ScsiTransport",
        1,
    ),
    (
        "src/backends/pioneer/dump.rs",
        "fn enable_logging",
        "SharedDevice",
        1,
    ),
    ("src/backends/pioneer/dump.rs", "use", "ScsiTransport", 1),
    ("src/backends/pioneer/dump.rs", "use", "SharedDevice", 1),
    (
        "src/backends/pioneer/flash.rs",
        "fn execute_with_sleep",
        "FlashTransport",
        1,
    ),
    (
        "src/backends/pioneer/flash.rs",
        "fn execute_with_sleep",
        "ScsiTransport",
        2,
    ),
    (
        "src/backends/pioneer/flash.rs",
        "fn execute_with_sleep",
        "SharedDevice",
        1,
    ),
    (
        "src/backends/pioneer/flash.rs",
        "struct Runtime",
        "SharedDevice",
        1,
    ),
    ("src/backends/pioneer/flash.rs", "use", "FlashTransport", 1),
    ("src/backends/pioneer/flash.rs", "use", "ScsiTransport", 1),
    ("src/backends/pioneer/flash.rs", "use", "SharedDevice", 1),
    ("src/standard.rs", "fn with_device", "Device", 2),
    ("src/standard.rs", "fn with_device", "ScsiTransport", 2),
    ("src/standard.rs", "fn with_device", "SharedDevice", 1),
    ("src/standard.rs", "use", "Device", 1),
    ("src/standard.rs", "use", "ScsiTransport", 1),
    ("src/standard.rs", "use", "SharedDevice", 1),
];

/// Item keywords whose spans key the census.
const ITEM_KINDS: &[&str] = &[
    "fn",
    "struct",
    "enum",
    "union",
    "impl",
    "trait",
    "type",
    "use",
    "mod",
    "const",
    "static",
    "macro_rules",
];

/// Every item in lexed `code` as `(start, end, label)`: the label is `use`,
/// `impl <header without generics>`, or `<kind> <name>`. A keyword counts only
/// in item position (after `;`, a brace, an attribute, `pub(..)` or a
/// qualifier), so `impl Trait` in a signature and `*const T` are not items.
fn items(code: &str) -> Vec<(usize, usize, String)> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for kind in ITEM_KINDS {
        for at in word_hits(code, kind) {
            let mut before = code[..at].trim_end();
            while let Some(word) = [
                "pub", "unsafe", "async", "const", "extern", "\"\"", "default",
            ]
            .iter()
            .find(|q| before.ends_with(**q) && !before[..before.len() - q.len()].ends_with(ident))
            {
                before = before[..before.len() - word.len()].trim_end();
            }
            if !(before.is_empty() || before.ends_with([';', '{', '}', ']', ')'])) {
                continue;
            }
            let rest = &code[at + kind.len()..];
            let name: String = rest
                .trim_start_matches([' ', '\n', '\t', '!'])
                .chars()
                .take_while(|&c| ident(c))
                .collect();
            if *kind != "impl"
                && *kind != "use"
                && (name.is_empty() || ["fn", "unsafe", "async", "extern"].contains(&name.as_str()))
            {
                continue;
            }
            let end = item_end(code, at, *kind == "use");
            let label = match *kind {
                "use" => "use".to_string(),
                "impl" => {
                    let head = &code[at..end];
                    let head = &head[..head.find(['{', ';']).unwrap_or(head.len())];
                    let head = head.split(" where ").next().unwrap_or(head);
                    let mut flat = String::new();
                    let mut depth = 0;
                    let mut prev = ' ';
                    for c in head.chars() {
                        match c {
                            '<' => depth += 1,
                            '>' if prev != '-' => depth -= 1,
                            _ if depth == 0 => flat.push(c),
                            _ => {}
                        }
                        prev = c;
                    }
                    flat.split_whitespace().collect::<Vec<_>>().join(" ")
                }
                _ => format!("{kind} {name}"),
            };
            out.push((at, end, label));
        }
    }
    out
}

/// The offset just past the item starting at `at`: its block, or its `;`
/// outside brackets (a `use` always ends at its `;`).
fn item_end(code: &str, at: usize, is_use: bool) -> usize {
    let mut depth = 0i32;
    for (off, c) in code[at..].char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ';' if depth <= 0 || is_use => return at + off + 1,
            '{' if depth <= 0 && !is_use => return block_end(code, at + off),
            _ => {}
        }
    }
    code.len()
}

/// The label of the innermost item in `items` holding offset `at`.
fn item_at(items: &[(usize, usize, String)], at: usize) -> String {
    items
        .iter()
        .filter(|(start, end, _)| (*start..*end).contains(&at))
        .max_by_key(|(start, _, _)| *start)
        .map_or_else(|| "(file)".to_string(), |(_, _, label)| label.clone())
}

/// `(item, type, count)` for every [`HIDDEN_TYPES`] mention in lexed `code`.
fn device_type_census(code: &str) -> Vec<(String, String, usize)> {
    let items = items(code);
    let mut out: Vec<(String, String, usize)> = Vec::new();
    for t in HIDDEN_TYPES {
        for at in word_hits(code, t) {
            let item = item_at(&items, at);
            match out.iter_mut().find(|(i, ty, _)| *i == item && ty == t) {
                Some(entry) => entry.2 += 1,
                None => out.push((item, t.to_string(), 1)),
            }
        }
    }
    out.sort();
    out
}

#[test]
fn device_types_are_named_only_where_reviewed() {
    let mut seen = Vec::new();
    let mut aliases = Vec::new();
    for s in production_sources() {
        if DEVICE_LAYER.iter().any(|l| s.path.starts_with(l)) {
            // The layer defines these types; an alias exported from it would carry
            // one past the census unseen.
            aliases.extend(
                hiding_types(&s.code)
                    .into_iter()
                    .filter(|h| h.starts_with("type "))
                    .map(|h| format!("{}: {h}", s.path)),
            );
            continue;
        }
        for (item, t, n) in device_type_census(&s.code) {
            seen.push((s.path.clone(), item, t, n));
        }
    }
    assert!(
        aliases.is_empty(),
        "device-layer aliases of device types: {aliases:#?}"
    );
    seen.sort();
    let mut expected: Vec<_> = DEVICE_TYPE_MENTIONS
        .iter()
        .map(|(p, i, t, n)| (p.to_string(), i.to_string(), t.to_string(), *n))
        .collect();
    expected.sort();
    let added: Vec<_> = seen.iter().filter(|r| !expected.contains(r)).collect();
    let gone: Vec<_> = expected.iter().filter(|r| !seen.contains(r)).collect();
    assert!(
        added.is_empty() && gone.is_empty(),
        "device types named outside the device layer changed; review the new use, \
         then update DEVICE_TYPE_MENTIONS\nnew: {added:#?}\ngone: {gone:#?}"
    );
}

#[test]
fn device_type_census_keys_by_item() {
    let census = |src: &str| device_type_census(&lex(src).0);
    let before = census(
        "use pioneer_optical::device::Device;\n\
         pub fn with<R>(f: impl FnOnce(&mut Device<'_, T>) -> R) -> R { f(&mut Device::new(t)) }\n",
    );
    assert_eq!(
        before,
        [
            ("fn with".to_string(), "Device".to_string(), 2),
            ("use".to_string(), "Device".to_string(), 1),
        ]
    );
    // The `use` replaced by full paths pays for a new wrapper: same per-file
    // count, different items.
    let traded = census(
        "pub fn with<R>(f: impl FnOnce(&mut d::Device<'_, T>) -> R) -> R { f(&mut d::Device::new(t)) }\n\
         #[cfg(any())]\npub enum Wrap<'a, T> { D(Device<'a, T>) }\n",
    );
    assert_eq!(
        traded,
        [
            ("enum Wrap".to_string(), "Device".to_string(), 1),
            ("fn with".to_string(), "Device".to_string(), 2),
        ]
    );
    let (code, _) = lex(
        "impl<'a> Foo<'a> for Bar<'a> where T: X { fn m(&self) { Device } }\n\
         pub(crate) const fn k() -> *const SharedDevice { x }\n\
         struct S { f: fn(u8) -> u8, d: ScsiTransport<'static, 'static> }\n",
    );
    assert_eq!(
        device_type_census(&code),
        [
            ("fn k".to_string(), "SharedDevice".to_string(), 1),
            ("fn m".to_string(), "Device".to_string(), 1),
            ("struct S".to_string(), "ScsiTransport".to_string(), 1),
        ]
    );
    let items = items(&code);
    assert_eq!(item_at(&items, 0), "impl Foo for Bar");
}
