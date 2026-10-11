//! Source-scan guards for the neutral model and its shells [R10]. Sources are
//! embedded with `include_str!`, so every shell is checked on every host, not
//! only the one it compiles for.

const MODEL: &[(&str, &str)] = &[
    ("ui.rs", include_str!("ui.rs")),
    ("ops.rs", include_str!("ops.rs")),
    ("gui_gate.rs", include_str!("gui_gate.rs")),
];

const SHELLS: &[(&str, &str)] = &[
    ("egui_shell.rs", include_str!("egui_shell.rs")),
    ("mac.rs", include_str!("mac.rs")),
    ("mac/gate.rs", include_str!("mac/gate.rs")),
    ("windows.rs", include_str!("windows.rs")),
    ("windows/gate.rs", include_str!("windows/gate.rs")),
    ("win_layout.rs", include_str!("win_layout.rs")),
    ("linux.rs", include_str!("linux.rs")),
    ("linux/widgets.rs", include_str!("linux/widgets.rs")),
    ("linux/gate.rs", include_str!("linux/gate.rs")),
];

const TOOLKITS: &[&str] = &[
    "egui", "eframe", "objc2", "block2", "winsafe", "gtk", "adw", "rfd",
];

/// Code lines only: comments are prose and may name anything.
fn code(src: &str) -> impl Iterator<Item = (usize, &str)> {
    src.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim_start()))
        .filter(|(_, l)| !l.starts_with("//"))
}

fn names_crate(line: &str, krate: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices(krate).any(|(at, _)| {
        let before = at.checked_sub(1).map(|i| bytes[i]);
        let after = &line[at + krate.len()..];
        !matches!(before, Some(b) if b.is_ascii_alphanumeric() || b == b'_')
            && after.starts_with("::")
    })
}

#[test]
fn ui_model_is_toolkit_free() {
    let mut hits = Vec::new();
    for (file, src) in MODEL {
        for (n, line) in code(src) {
            for kit in TOOLKITS {
                if names_crate(line, kit) {
                    hits.push(format!("{file}:{n}: {kit}"));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "toolkit types in the neutral model: {hits:#?}"
    );
}

#[test]
fn every_shell_renders_only_the_ui_model() {
    let mut hits = Vec::new();
    for (file, src) in SHELLS {
        for (n, line) in code(src) {
            if names_crate(line, "freemkv_flash") || names_crate(line, "ops") {
                hits.push(format!("{file}:{n}: {line}"));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "shells must draw ui::View and send ui::Input only: {hits:#?}"
    );
}

/// The model reaches the core only through `workflow` and `report` (design §3).
#[test]
fn gui_model_imports_only_workflow_and_report() {
    let mut hits = Vec::new();
    for (file, src) in MODEL {
        for (n, line) in code(src) {
            for (at, _) in line.match_indices("freemkv_flash::") {
                let rest = &line[at + "freemkv_flash::".len()..];
                if !(rest.starts_with("workflow") || rest.starts_with("report")) {
                    hits.push(format!("{file}:{n}: {line}"));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the GUI model may import only freemkv_flash::{{workflow, report}}: {hits:#?}"
    );
}

#[test]
fn every_shell_source_is_scanned() {
    let listed: Vec<&str> = SHELLS.iter().chain(MODEL).map(|(f, _)| *f).collect();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut missing = Vec::new();
    for sub in ["", "linux", "mac", "windows"] {
        let Ok(entries) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = if sub.is_empty() {
                name
            } else {
                format!("{sub}/{name}")
            };
            let exempt = rel.ends_with("_tests.rs") || rel == "main.rs" || !rel.ends_with(".rs");
            if !exempt && !listed.contains(&rel.as_str()) {
                missing.push(rel);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "new GUI source files must be listed as MODEL or SHELLS: {missing:?}"
    );
}

/// The GUI gate is a debug-only hook: the model's module and each shell's gate are
/// compiled out of release builds.
#[test]
fn the_gui_gate_is_compiled_out_of_release_builds() {
    let main = include_str!("main.rs");
    assert!(
        main.contains("#[cfg(debug_assertions)]\n#[cfg_attr(not(feature = \"native\"), allow(dead_code))]\nmod gui_gate;"),
        "main.rs must declare gui_gate under cfg(debug_assertions)"
    );
    for (file, src) in [
        ("mac.rs", include_str!("mac.rs")),
        ("windows.rs", include_str!("windows.rs")),
        ("linux.rs", include_str!("linux.rs")),
    ] {
        assert!(
            src.contains("#[cfg(debug_assertions)]\nmod gate;"),
            "{file} must declare its gate under cfg(debug_assertions)"
        );
        for (n, line) in code(src) {
            if line.contains("gui_gate::") || line.contains("gate::") {
                let before: Vec<&str> = src.lines().take(n - 1).collect();
                let guarded = before
                    .iter()
                    .rev()
                    .take(12)
                    .any(|l| l.contains("cfg(debug_assertions)"));
                assert!(
                    guarded,
                    "{file}:{n}: a gate call outside cfg(debug_assertions)"
                );
            }
        }
    }
}
