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
/// `FlashTransport`) and the settings writer `device::Device::set`.
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
];

/// What reaches the drive but may run under a read grant: the read transport,
/// a settings device over it, and the lenient data-out used for the read knock.
const READ_MARKERS: &[&str] = &[
    ".command_out(",
    "ScsiTransport::reads(",
    "Device::new(",
    "Device::with_settings_codec(",
];

/// What opens a settings device; with a `.set(` in the same function, that is a
/// settings write whichever way `set` is spelled.
const SETTINGS_DEVICE: &[&str] = &[
    "Device::new(",
    "Device::with_settings_codec(",
    "with_device(",
];

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

/// Every fn in lexed `code` whose body holds a write or read marker.
fn write_issuers(code: &str) -> Vec<Issuer> {
    let code = normalise(code);
    let mut out = Vec::new();
    for at in word_hits(&code, "fn") {
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
        let body = &tail[brace..block_end(tail, brace)];
        // A helper handed the vendor settings `Device` counts too: `fn f(d: &mut Device<..>)`.
        let settings_device = SETTINGS_DEVICE.iter().any(|m| has_marker(body, m))
            || has_marker(&strip_paths(params), "Device<");
        let settings_write = settings_device && body.contains(".set(");
        let writes = settings_write || WRITE_MARKERS.iter().any(|m| has_marker(body, m));
        if writes || READ_MARKERS.iter().any(|m| has_marker(body, m)) {
            out.push(Issuer {
                name,
                generics: generics.to_string(),
                params: params.to_string(),
                bounds: tail[1..brace].to_string(),
                writes,
            });
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
    "built only inside execute_prepared from its WriteDevice; its methods only read",
)];

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
    for at in word_hits(code, "struct") {
        let rest = &code[at..];
        let end = match (rest.find('{'), rest.find(';')) {
            (Some(b), Some(semi)) if b < semi => block_end(rest, b),
            (Some(b), None) => block_end(rest, b),
            (_, Some(semi)) => semi,
            (None, None) => rest.len(),
        };
        let decl = &rest[..end.min(rest.len())];
        let head = decl.find(['{', '(']).unwrap_or(decl.len());
        if names(&decl[head..]) {
            out.push(flat(&decl[..head]));
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
    let (mut problems, mut issuers, mut wrappers) = (Vec::new(), Vec::new(), Vec::new());
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
                problems.push(format!("{}: fn {}({}) {why}", s.path, f.name, f.params));
            }
            issuers.push((f.name, f.writes));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    // The scan must still see the known executors, or it proves nothing.
    for (known, writes) in [
        ("execute_prepared", true),
        ("run", true),
        ("stream", true),
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
         struct Unit;\n");
    assert_eq!(
        hiding_types(&code),
        [
            "type Dev<'a> = Device<'a, ScsiTransport<'a, 'a>>",
            "type T = crate::transport::SharedDevice<'static>",
            "struct Wrap",
            "struct Holder<'a>",
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

/// Every mention of a [`HIDDEN_TYPES`] type outside the device layer, per file:
/// the reviewed write executors and the standard settings reader. A new mention
/// (an alias, enum, generic bound or wrapper the shape scans miss) fails here
/// until reviewed and counted, so this list is closed-world.
const DEVICE_TYPE_MENTIONS: &[(&str, &str, usize)] = &[
    ("src/backends/mtk/flash.rs", "ScsiTransport", 2),
    ("src/backends/mtk/flash.rs", "SharedDevice", 2),
    ("src/backends/pioneer/dump.rs", "ScsiTransport", 2),
    ("src/backends/pioneer/dump.rs", "SharedDevice", 2),
    ("src/backends/pioneer/flash.rs", "FlashTransport", 2),
    ("src/backends/pioneer/flash.rs", "ScsiTransport", 3),
    ("src/backends/pioneer/flash.rs", "SharedDevice", 3),
    ("src/backends/pioneer/recovery.rs", "ScsiTransport", 2),
    ("src/backends/pioneer/recovery.rs", "SharedDevice", 2),
    ("src/standard.rs", "Device", 3),
    ("src/standard.rs", "ScsiTransport", 3),
    ("src/standard.rs", "SharedDevice", 2),
];

#[test]
fn device_types_are_named_only_where_reviewed() {
    let mut seen = Vec::new();
    let mut aliases = Vec::new();
    for s in production_sources() {
        if DEVICE_LAYER.iter().any(|l| s.path.starts_with(l)) {
            // The layer defines these types; an alias exported from it would carry
            // one past the per-file count unseen.
            aliases.extend(
                hiding_types(&s.code)
                    .into_iter()
                    .filter(|h| h.starts_with("type ") || h.contains(" type "))
                    .map(|h| format!("{}: {h}", s.path)),
            );
            continue;
        }
        for t in HIDDEN_TYPES {
            let n = word_hits(&s.code, t).len();
            if n > 0 {
                seen.push((s.path.clone(), t.to_string(), n));
            }
        }
    }
    assert!(
        aliases.is_empty(),
        "device-layer aliases of device types: {aliases:#?}"
    );
    seen.sort();
    let mut expected: Vec<_> = DEVICE_TYPE_MENTIONS
        .iter()
        .map(|(p, t, n)| (p.to_string(), t.to_string(), *n))
        .collect();
    expected.sort();
    assert_eq!(
        seen, expected,
        "device types named outside the device layer changed; review the new use, then update DEVICE_TYPE_MENTIONS"
    );
}
