use super::*;
use crate::ui::{App, Pick, Profile};
use freemkv_flash::report::{Group, Row};
use freemkv_flash::workflow::DriveChoice;

fn drive(path: &str, label: &str) -> DriveChoice {
    DriveChoice {
        path: path.into(),
        name: path.into(),
        label: label.into(),
    }
}

/// A shell over a model whose jobs are recorded, its drive offering every task.
fn shell(drives: Vec<DriveChoice>) -> Shell {
    let mut app = App::with_drives(drives);
    app.dry_run = Some(Vec::new());
    let mut shell = Shell::new(app, &egui::Context::default());
    if shell.app.profile_worker.is_some() {
        shell.app.answer_profile(Ok(Profile::every_task()));
    }
    shell
}

/// Every text shape the shell paints, and whether it lies fully inside its clip rect.
fn rendered_text(shell: &mut Shell) -> Vec<(String, bool)> {
    let ctx = egui::Context::default();
    configure_style(&ctx);
    let mut text = Vec::new();
    for _ in 0..4 {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(720.0, 610.0),
                )),
                time: Some(10.0),
                ..Default::default()
            },
            |ui| shell.render(ui),
        );
        text.clear();
        for clipped in output.shapes {
            if let egui::epaint::Shape::Text(shape) = clipped.shape {
                let rect = egui::Rect::from_min_size(shape.pos, shape.galley.size());
                text.push((
                    shape.galley.job.text.clone(),
                    clipped.clip_rect.contains_rect(rect),
                ));
            }
        }
    }
    text
}

fn shows(text: &[(String, bool)], want: &str) -> bool {
    text.iter()
        .any(|(t, visible)| *t == crate::localization::english(want) && *visible)
}

#[test]
fn backup_and_flash_controls_are_visible_and_do_not_show_info_results() {
    let mut s = shell(vec![drive("test", "Optical drive")]);
    s.app.flash_input = Some("firmware.bin".into());
    s.app.rows = vec![Row::gui("test", "Manufacturer", "OLD INFO RESULT".into())];
    s.app.status = "Drive information complete".into();
    for (task, controls) in [
        (Task::Backup, vec!["Save backup…"]),
        (Task::Dump, vec!["Save raw dump…"]),
        (
            Task::Recovery,
            vec![
                "Current firmware",
                "Read from drive",
                "Choose Current…",
                "Firmware to flash",
                "Recover",
            ],
        ),
        (Task::Flash, vec!["Change file…", "Flash now", "Check file"]),
    ] {
        s.app.dispatch(Input::SelectTask(task));
        let text = rendered_text(&mut s);
        for control in controls {
            assert!(
                shows(&text, control),
                "missing or clipped {control}: {text:?}"
            );
        }
        assert!(!text
            .iter()
            .any(|(l, _)| l == "OLD INFO RESULT" || l == "Drive information complete"));
    }
}

#[test]
fn long_results_fit_the_original_window_without_resizing() {
    let mut s = shell(vec![drive("ioreg:123", "PIONEER BDR-UD04")]);
    s.app.rows = (0..40)
        .map(|n| {
            Row::gui(
                "test",
                &format!("Field {n}"),
                "long firmware information ".repeat(20).into(),
            )
        })
        .collect();
    let ctx = egui::Context::default();
    for task in [
        Task::Info,
        Task::Backup,
        Task::Dump,
        Task::Flash,
        Task::Recovery,
    ] {
        s.app.dispatch(Input::SelectTask(task));
        s.app.result_task = task;
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(720.0, 610.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run_ui(input, |ui| {
                s.render(ui);
                assert!(ui.min_rect().right() <= 720.0, "{:?}", ui.min_rect());
                assert!(ui.min_rect().bottom() <= 610.0, "{:?}", ui.min_rect());
            });
        }
    }
}

#[test]
fn failed_operation_offers_log_export_next_to_the_error() {
    let mut s = shell(Vec::new());
    s.app.failure = Some("Backup failed".into());
    let text = rendered_text(&mut s);
    assert!(text.iter().any(|(t, _)| t == "Save Log…"), "{text:?}");
    assert!(text.iter().any(|(t, _)| t == "View Log"));
    assert!(text.iter().any(|(t, _)| t == "Backup failed"));
}

#[test]
fn diagnostic_window_shows_the_full_log() {
    let path = std::env::temp_dir().join(format!(
        "freemkv-egui-diagnostic-{}.log",
        std::process::id()
    ));
    std::fs::write(&path, "SCSI result: status=0x00 transferred=0\n").unwrap();
    let mut s = shell(Vec::new());
    s.app.diagnostic_log = Some(path.clone());
    s.app.dispatch(Input::OpenDiagnostics);
    let text = rendered_text(&mut s);
    assert!(text
        .iter()
        .any(|(t, _)| t.contains("SCSI result: status=0x00 transferred=0")));
    assert!(text
        .iter()
        .any(|(t, _)| t == "Attach this log to your bug report."));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn inspect_and_compare_inputs_fit_without_a_connected_drive() {
    let mut s = shell(Vec::new());
    for task in [Task::Inspect, Task::Compare] {
        s.app.dispatch(Input::SelectTask(task));
        let text = rendered_text(&mut s);
        let expected = if task == Task::Inspect { 1 } else { 2 };
        let files: Vec<_> = text.iter().filter(|(t, _)| t == "Firmware file…").collect();
        assert_eq!(files.len(), expected);
        assert!(files.iter().all(|(_, fits)| *fits));
        assert!(!text
            .iter()
            .any(|(t, _)| t == "Swap" || t == "Filter table records"));
    }
}

#[test]
fn confirmation_window_shows_the_gate_texts() {
    let mut s = shell(vec![drive("a", "Drive A")]);
    s.app.task = Task::Recovery;
    s.app.recovery_input = Some("new.tar".into());
    s.app
        .dispatch(Input::Chosen(Pick::RecoveryCurrent, "old.tar".into()));
    s.app.dispatch(Input::Recover);
    s.app
        .worker
        .take()
        .unwrap()
        .send(crate::ui::Msg::Done(Ok(Some(
            freemkv_flash::workflow::UpdateOutcome::Planned,
        ))))
        .unwrap();
    s.app.poll();
    let text = rendered_text(&mut s);
    for want in [
        "Confirm recovery",
        crate::ui::FLASH_DANGER,
        crate::ui::FORCE_WARNING,
        crate::ui::RISK_ACK,
        "Current: old.tar",
    ] {
        assert!(
            text.iter()
                .any(|(t, _)| *t == crate::localization::english(want)),
            "{want}: {text:?}"
        );
    }
}

/// Mirrors the old info card renderer checks over the model's cards.
fn card_text(fields: &[(&str, &str, Group)], width: f32) -> Vec<String> {
    let rows: Vec<_> = fields
        .iter()
        .map(|(k, v, g)| Row::gui("test", k, (*v).into()).in_group(*g))
        .collect();
    let mut cards = crate::ui::info_cards(&rows);
    for card in &mut cards {
        card.title = crate::localization::english(&card.title);
        card.subtitle = card
            .subtitle
            .as_ref()
            .map(|value| crate::localization::english(value));
    }
    let ctx = egui::Context::default();
    let mut text = Vec::new();
    for _ in 0..3 {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 2000.0),
                )),
                ..Default::default()
            },
            |ui| info_cards(ui, &cards, crate::localization::Language::En),
        );
        text = output
            .shapes
            .iter()
            .filter_map(|s| match &s.shape {
                egui::epaint::Shape::Text(t) => Some(t.galley.text().to_owned()),
                _ => None,
            })
            .collect();
    }
    text
}

#[test]
fn information_cards_render_in_narrow_and_wide_layouts() {
    let fields = [
        ("Model", "BDR-XD08U", Group::General),
        ("Kernel type", "ID69", Group::Additional),
        ("CD-R", "Read: Yes    Write: Yes", Group::Media),
        ("DVD region", "2", Group::Region),
        ("Quiet Drive", "Quiet", Group::Settings),
        ("Saved Quiet Drive", "Performance", Group::Settings),
        ("PureRead", "Master", Group::Settings),
        ("Firmware update", "Supported", Group::Operations),
    ];
    for width in [680.0, 880.0] {
        let text = card_text(&fields, width);
        for want in [
            "Current settings · read only",
            "Master",
            "Kernel type",
            "R/W",
        ] {
            assert!(
                text.iter()
                    .any(|t| *t == crate::localization::english(want)),
                "{want} at {width}: {text:?}"
            );
        }
    }
}

#[test]
fn light_theme_has_an_opaque_light_window_background() {
    use eframe::App as _;
    let s = shell(Vec::new());
    let background = s.clear_color(&egui::Visuals::light());
    assert!(background[..3].iter().all(|channel| *channel > 0.8));
    assert_eq!(background[3], 1.0);
}

#[test]
fn diagnostic_actions_share_one_row_in_view_save_submit_order() {
    let mut s = shell(Vec::new());
    s.app.failure = Some("errors.operation_failed".into());
    let ctx = egui::Context::default();
    configure_style(&ctx);
    let mut found = std::collections::BTreeMap::new();
    for _ in 0..3 {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 760.0),
                )),
                ..Default::default()
            },
            |ui| s.render(ui),
        );
        found.clear();
        for clipped in output.shapes {
            if let egui::epaint::Shape::Text(shape) = clipped.shape {
                let text = shape.galley.text();
                if ["View Log", "Save Log…", "Submit Report"].contains(&text) {
                    found.insert(text.to_owned(), shape.pos);
                }
            }
        }
    }
    let view = found["View Log"];
    let save = found["Save Log…"];
    let submit = found["Submit Report"];
    assert!(view.x < save.x && save.x < submit.x);
    assert!((view.y - save.y).abs() < 1.0 && (save.y - submit.y).abs() < 1.0);
}
