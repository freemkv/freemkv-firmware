use super::*;

#[test]
fn diagnostic_viewer_and_export_show_the_same_full_log() {
    let path =
        std::env::temp_dir().join(format!("freemkv-gui-diagnostic-{}.log", std::process::id()));
    std::fs::write(
        &path,
        "SCSI result: status=0x00 transferred=0\nRESULT: error\n",
    )
    .unwrap();
    let mut app = FlashApp::with_drives(Vec::new());
    app.log = vec!["backup failed".into()];
    app.diagnostic_log = Some(path.clone());
    assert!(app
        .diagnostic_text()
        .unwrap()
        .contains("status=0x00 transferred=0"));
    app.details_open = true;
    let visible = rendered_text(&mut app);
    assert!(
        visible
            .iter()
            .any(|(text, _)| text.contains("SCSI result: status=0x00 transferred=0")),
        "{visible:?}"
    );
    assert!(visible
        .iter()
        .any(|(text, _)| text.contains("Attach this log to your bug report.")));
    assert!(!app
        .diagnostic_lines
        .iter()
        .any(|line| line == "backup failed"));
    std::fs::write(&path, "RESULT: updated log\n").unwrap();
    app.refresh_diagnostic_view();
    assert_eq!(app.diagnostic_lines, ["RESULT: updated log"]);
    std::fs::remove_file(&path).unwrap();
    assert!(
        app.diagnostic_text().is_err(),
        "missing full log must not silently export only the summary"
    );
    app.refresh_diagnostic_view();
    assert!(app.diagnostic_lines[0].contains("Could not read diagnostic log"));
}

#[test]
fn failed_operation_offers_log_export_next_to_the_error() {
    let mut app = FlashApp::with_drives(Vec::new());
    app.failure = Some("Backup failed".into());
    let visible = rendered_text(&mut app);
    assert!(
        visible
            .iter()
            .any(|(text, _)| text == "Save diagnostic log…"),
        "{visible:?}"
    );
    assert!(visible
        .iter()
        .any(|(text, _)| text == "View diagnostic log…"));
}

fn rendered_text(app: &mut FlashApp) -> Vec<(String, bool)> {
    let ctx = egui::Context::default();
    crate::configure_style(&ctx);
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
            |ui| app.render(ui),
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

#[test]
fn backup_and_flash_controls_are_visible_and_do_not_show_info_results() {
    let mut app = FlashApp::with_drives(vec![DriveChoice {
        path: "test".into(),
        label: "Optical drive".into(),
    }]);
    app.input = Some("firmware.bin".into());
    app.fields = vec![("Manufacturer".into(), "OLD INFO RESULT".into())];
    app.status = "Drive information complete".into();
    for (task, controls) in [
        (Task::Backup, vec!["Save backup…"]),
        (Task::Dump, vec!["Save raw dump…"]),
        (
            Task::Flash,
            vec!["Change file…", "Flash now", "Check file", "Force flash"],
        ),
    ] {
        app.task = task;
        let text = rendered_text(&mut app);
        for control in controls {
            assert!(
                text.iter()
                    .any(|(label, visible)| label == control && *visible),
                "missing or clipped control {control}: {text:?}"
            );
        }
        assert!(!text
            .iter()
            .any(|(label, _)| label == "OLD INFO RESULT" || label == "Drive information complete"));
    }
}

#[test]
fn long_results_fit_the_original_window_without_resizing() {
    let mut app = FlashApp::with_drives(vec![DriveChoice {
        path: "ioreg:123".into(),
        label: "PIONEER BDR-UD04".into(),
    }]);
    app.fields = (0..40)
        .map(|n| {
            (
                format!("Field {n}"),
                "long firmware information ".repeat(20),
            )
        })
        .collect();
    let ctx = egui::Context::default();
    for task in [Task::Info, Task::Backup, Task::Dump, Task::Flash] {
        app.task = task;
        app.result_task = task;
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(720.0, 610.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run_ui(input, |ui| {
                app.render(ui);
                assert!(
                    ui.min_rect().right() <= 720.0,
                    "content exceeds window width: {:?}",
                    ui.min_rect()
                );
                assert!(
                    ui.min_rect().bottom() <= 610.0,
                    "content exceeds window height: {:?}",
                    ui.min_rect()
                );
            });
        }
    }
}

#[test]
fn light_theme_has_an_opaque_light_window_background() {
    use eframe::App;
    let app = FlashApp::with_drives(Vec::new());
    let background = app.clear_color(&egui::Visuals::light());
    assert!(background[..3].iter().all(|channel| *channel > 0.8));
    assert_eq!(background[3], 1.0);
}

#[test]
fn progress_and_results_are_structured_without_console_parsing() {
    let mut app = FlashApp::with_drives(Vec::new());
    let (tx, rx) = mpsc::channel();
    app.running = true;
    app.rx = Some(rx);
    tx.send(Msg::Event(freemkv_flash::output::Event::Progress {
        label: "Reading firmware".into(),
        done: 512,
        total: 1024,
    }))
    .unwrap();
    tx.send(Msg::Event(freemkv_flash::output::Event::Field {
        label: "Model".into(),
        value: "BDR-UD04".into(),
    }))
    .unwrap();
    app.pump();
    assert_eq!(app.progress, Some(("Reading firmware".into(), 512, 1024)));
    assert_eq!(app.fields, [("Model".into(), "BDR-UD04".into())]);
    assert!(app.running);
}

#[test]
fn confirmation_freezes_target_and_requires_fresh_consent() {
    let mut app = FlashApp::with_drives(vec![DriveChoice {
        path: "drive-a".into(),
        label: "Drive A".into(),
    }]);
    app.input = Some("firmware.bin".into());
    app.risk_ack = true;
    app.choose_flash(&egui::Context::default(), true);
    app.device = "drive-b".into();
    assert_eq!(app.pending_flash.as_ref().unwrap().device, "drive-a");
    assert!(!app.risk_ack);
    assert!(!app.running);
}

#[test]
fn disconnected_worker_releases_controls_and_reports_failure() {
    let mut app = FlashApp::with_drives(Vec::new());
    let (tx, rx) = mpsc::channel();
    app.running = true;
    app.rx = Some(rx);
    drop(tx);
    app.pump();
    assert!(
        !app.running,
        "a dead worker must not leave the app busy forever"
    );
    assert!(app.log.iter().any(|l| l.contains("worker")));
}

#[test]
fn refresh_removes_disconnected_selection_and_its_consent() {
    let mut app = FlashApp::with_drives(vec![DriveChoice {
        path: "ioreg:old".into(),
        label: "Drive".into(),
    }]);
    app.risk_ack = true;
    app.refresh(vec![DriveChoice {
        path: "ioreg:new".into(),
        label: "Reconnected drive".into(),
    }]);
    assert_eq!(app.device, "ioreg:new");
    assert!(!app.risk_ack);
    app.refresh(Vec::new());
    assert!(app.device.is_empty());
}

#[test]
fn completion_is_not_misreported_as_worker_disconnection() {
    let mut app = FlashApp::with_drives(Vec::new());
    let (tx, rx) = mpsc::channel();
    app.running = true;
    app.rx = Some(rx);
    tx.send(Msg::Done(Ok(()))).unwrap();
    drop(tx);
    app.pump();
    assert!(!app.running);
    assert_eq!(app.log.last().unwrap(), "✓ done.");
}
