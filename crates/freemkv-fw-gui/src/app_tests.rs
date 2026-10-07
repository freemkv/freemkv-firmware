use super::*;
fn rendered_text(app: &mut FwApp) -> Vec<(String, bool)> {
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
fn sibling_actions_and_diagnostic_controls_fit_the_same_window() {
    let mut app = FwApp::new();
    app.input = Some("firmware.bin".into());
    app.device = "test-drive".into();
    app.devices.push(DriveChoice {
        path: "test-drive".into(),
        name: "test-drive".into(),
        label: "Optical drive".into(),
    });
    for (task, action) in [
        (Task::Verify, "Verify firmware"),
        (Task::Create, "Create firmware…"),
        (Task::Sign, "Save signed firmware…"),
        (Task::Probe, "Read drive information"),
    ] {
        app.task = task;
        app.result_task = task;
        let text = rendered_text(&mut app);
        for expected in [
            "freemkv",
            "Firmware Modifier",
            action,
            "View diagnostic log…",
        ] {
            assert!(
                text.iter()
                    .any(|(line, visible)| line == expected && *visible),
                "missing visible {expected}: {text:?}"
            );
        }
    }
}

#[test]
fn failed_worker_releases_controls_and_offers_log_export() {
    let mut app = FwApp::new();
    let (tx, rx) = mpsc::channel();
    app.running = true;
    app.rx = Some(rx);
    tx.send(Msg::Done(Err("Cannot parse firmware".into())))
        .unwrap();
    app.pump();
    assert!(!app.running);
    assert!(app
        .failure
        .as_deref()
        .unwrap()
        .contains("Cannot parse firmware"));
    assert!(rendered_text(&mut app)
        .iter()
        .any(|(line, visible)| line == "Save diagnostic log…" && *visible));
}

#[test]
fn diagnostic_viewer_reads_the_file_not_the_activity_summary() {
    let directory = std::env::temp_dir();
    let path = directory.join(format!("fw-viewer-test-{}.log", std::process::id()));
    std::fs::write(&path, "full metadata header and transfer evidence").unwrap();
    let mut app = FwApp::new();
    app.log.push("short summary only".into());
    app.diagnostic_log = Some(path.clone());
    app.details_open = true;
    let text = rendered_text(&mut app);
    assert!(text
        .iter()
        .any(|(line, _)| line == "full metadata header and transfer evidence"));
    assert_eq!(
        app.diagnostic_text().unwrap(),
        "full metadata header and transfer evidence"
    );
    std::fs::remove_file(path).unwrap();
}
