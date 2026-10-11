//! Design-review tripwire: every finding (R1–R13) from the adversarial review of
//! the 0.12 universal-backend design must be guarded by a named test. A
//! missing test means the finding was not coded, and this fails.

use std::{fs, path::Path};

/// (finding, required test fn name). Names are exact; implementers create them.
const REQUIRED: &[(&str, &str)] = &[
    ("R1 two-stage flash", "flash_plan_needs_no_backup"),
    (
        "R1 two-stage flash",
        "flash_authorize_runs_pioneer_installed_gates_after_backup",
    ),
    (
        "R1 two-stage flash",
        "pioneer_confirmation_text_is_returned_not_prompted",
    ),
    (
        "R2 runtime write gate",
        "read_device_refuses_undeclared_data_out",
    ),
    (
        "R2 runtime write gate",
        "write_device_constructed_only_in_engine_gates",
    ),
    (
        "R2 runtime write gate",
        "flash_never_writes_without_saved_backup",
    ),
    (
        "R2 runtime write gate",
        "force_and_skip_backup_paths_are_gone",
    ),
    (
        "R2 runtime write gate",
        "recovery_write_requires_execute_and_ack",
    ),
    (
        "R2 runtime write gate",
        "dump_writes_limited_to_declared_patterns",
    ),
    (
        "R2 runtime write gate",
        "dump_grant_refuses_persistent_logging_payload",
    ),
    (
        "R2 runtime write gate",
        "read_device_refuses_zero_length_session_commands",
    ),
    (
        "R2 runtime write gate",
        "dump_grant_refuses_zero_length_session_commands",
    ),
    ("R3 standard info scope", "info_transcript_matches_0_11_2"),
    (
        "R3 standard info scope",
        "backup_flash_recover_send_no_standard_snapshot",
    ),
    ("R4 report rows", "info_cli_stdout_matches_0_11_2"),
    ("R4 report rows", "info_gui_events_match_0_11_2"),
    ("R4 report rows", "pioneer_rows_interleave_at_slots"),
    (
        "R5 lost behaviours",
        "post_flash_identity_check_fails_unconfirmed_flash",
    ),
    (
        "R5 lost behaviours",
        "backup_candidate_infix_and_sha_line_kept",
    ),
    ("R5 lost behaviours", "raw_dump_name_and_line_kept"),
    (
        "R5 lost behaviours",
        "saved_backup_kept_when_authorize_refuses",
    ),
    (
        "R5 lost behaviours",
        "dry_run_keeps_tray_warning_and_mtk_preflight",
    ),
    (
        "R5 lost behaviours",
        "mtk_execute_prints_plan_after_backup_summary",
    ),
    ("R5 lost behaviours", "read_surface_map_is_gone"),
    (
        "R5 lost behaviours",
        "recover_names_only_the_recovery_facet",
    ),
    (
        "R6 recovery reachability",
        "recovery_offered_for_unsupported_identified_drive",
    ),
    (
        "R6 recovery reachability",
        "recovery_identify_needs_no_probe",
    ),
    ("R7 golden coverage", "golden_coverage_is_complete"),
    ("R7 golden coverage", "golden_parity_with_0_11_2"),
    (
        "R8 conformance",
        "conformance_probe_rejects_unknown_mmc_drive",
    ),
    (
        "R8 conformance",
        "details_reuse_probe_data_without_repeat_reads",
    ),
    ("R9 drop-in", "core_modules_name_no_backend"),
    ("R9 drop-in", "cli_and_gui_text_name_no_vendor"),
    ("R10 native GUI", "ui_model_is_toolkit_free"),
    ("R10 native GUI", "every_shell_renders_only_the_ui_model"),
    ("R11 dependency pins", "pioneer_optical_stays_pinned"),
    ("R12 sanitizing", "every_drive_string_is_clean"),
    ("R12 sanitizing", "paths_and_hex_render_unmangled"),
    (
        "R13 consistency",
        "one_recognizer_serves_flash_check_and_inspect",
    ),
    ("R13 consistency", "ambiguous_file_is_an_error"),
    ("R13 consistency", "settings_are_read_only"),
];

fn test_fns(dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            test_fns(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let src = fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                if let Some(rest) = t.strip_prefix("fn ").or_else(|| t.strip_prefix("pub fn ")) {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    let attrs = lines[i.saturating_sub(3)..i].join("\n");
                    if attrs.contains("#[test]") && !attrs.contains("#[ignore") {
                        out.push(name);
                    }
                }
            }
        }
    }
}

#[test]
fn every_design_finding_has_its_guard_test() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    for dir in ["src", "tests"] {
        test_fns(&root.join(dir), &mut found);
    }
    let gui = root.join("../freemkv-flash-gui/src");
    if gui.exists() {
        test_fns(&gui, &mut found);
    }
    let missing: Vec<String> = REQUIRED
        .iter()
        .filter(|(_, name)| !found.iter().any(|f| f == name))
        .map(|(finding, name)| format!("{finding}: {name}"))
        .collect();
    assert!(
        missing.is_empty(),
        "design findings without an active guard test:\n{}",
        missing.join("\n")
    );
}
