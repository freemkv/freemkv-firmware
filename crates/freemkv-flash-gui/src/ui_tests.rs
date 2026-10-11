use super::*;

fn drive(path: &str, name: &str, label: &str) -> DriveChoice {
    DriveChoice {
        path: path.into(),
        name: name.into(),
        label: label.into(),
    }
}

/// A model with one drive whose jobs are recorded, not run.
fn dry(drives: Vec<DriveChoice>) -> App {
    let mut app = App::with_drives(drives);
    app.dry_run = Some(Vec::new());
    app
}

fn one_drive() -> App {
    dry(vec![drive("drive-a", "drive-a", "Drive A")])
}

/// Every button in the panel, flattened.
fn buttons(view: &View) -> Vec<Button> {
    let mut out = Vec::new();
    for item in &view.panel {
        match item {
            Item::Path { button, .. } => out.push(button.clone()),
            Item::Buttons { buttons, .. } => out.extend(buttons.iter().cloned()),
            _ => {}
        }
    }
    out
}

fn button(view: &View, text: &str) -> Button {
    buttons(view)
        .into_iter()
        .find(|b| b.text == text)
        .unwrap_or_else(|| panic!("no button {text}: {:?}", view.panel))
}

fn has_text(view: &View, text: &str) -> bool {
    view.panel.iter().any(|item| match item {
        Item::Text(t) | Item::Heading(t) | Item::Note(t) | Item::Warning(t) => t == text,
        Item::Check { text: t, .. } => t == text,
        _ => false,
    }) || buttons(view).iter().any(|b| b.text == text)
}

fn last_job(app: &App) -> &(String, String, Job) {
    app.dry_run
        .as_ref()
        .unwrap()
        .last()
        .expect("a job was started")
}

fn finish(app: &mut App, result: Result<(), String>) -> Vec<Effect> {
    app.worker.take().unwrap().send(Msg::Done(result)).unwrap();
    app.poll()
}

// ── tasks and tabs ────────────────────────────────────────────────────────

#[test]
fn every_task_is_a_tab_and_enabled_when_idle() {
    let view = one_drive().view();
    let titles: Vec<_> = view.tabs.iter().map(|t| t.title).collect();
    assert_eq!(
        titles,
        [
            "Drive info",
            "Inspect",
            "Compare",
            "Backup",
            "Dump",
            "Flash",
            "Recovery"
        ]
    );
    assert!(view.tabs.iter().all(|t| t.enabled));
    assert!(view.controls_enabled);
    assert_eq!(view.task, Task::Info);
}

#[test]
fn tabs_and_drive_bar_lock_while_a_job_runs() {
    let mut app = one_drive();
    assert_eq!(app.dispatch(Input::ReadInfo), [Effect::StartTicking]);
    let view = app.view();
    assert!(!view.controls_enabled);
    assert!(view.tabs.iter().all(|t| !t.enabled));
    assert!(!view.drives.refresh.enabled);
    assert!(!view.can_close, "a running job must block closing");
    app.dispatch(Input::SelectTask(Task::Flash));
    assert_eq!(app.task, Task::Info, "tab switch ignored while running");
}

#[test]
fn capabilities_hook_disables_tasks_outside_the_profile() {
    let mut app = one_drive();
    app.set_capabilities(Capabilities {
        tasks: vec![Task::Info, Task::Backup],
    });
    let view = app.view();
    let enabled: Vec<_> = view
        .tabs
        .iter()
        .filter(|t| t.enabled)
        .map(|t| t.task)
        .collect();
    assert_eq!(enabled, [Task::Info, Task::Backup]);
    app.dispatch(Input::SelectTask(Task::Flash));
    assert_eq!(app.task, Task::Info);
    app.dispatch(Input::SelectTask(Task::Backup));
    assert_eq!(app.task, Task::Backup);
}

#[test]
fn info_without_a_drive_offers_only_check_file() {
    let view = dry(Vec::new()).view();
    assert!(!button(&view, "Read drive information").enabled);
    assert!(button(&view, "Check file…").enabled);
    assert!(has_text(
        &view,
        "Connect an optical drive, then select Refresh."
    ));
    assert_eq!(view.drives.selected, None);
    assert_eq!(view.drives.placeholder, "No optical drive found");
    let view = one_drive().view();
    assert!(button(&view, "Read drive information").enabled);
    assert_eq!(
        button(&view, "Read drive information").style,
        ButtonStyle::Primary
    );
}

#[test]
fn no_drive_cannot_start_drive_jobs() {
    let mut app = dry(Vec::new());
    assert!(app.dispatch(Input::ReadInfo).is_empty());
    assert!(!app.running());
    assert_eq!(app.log.last().unwrap(), "No optical drive selected.");
    app.dispatch(Input::SelectTask(Task::Backup));
    assert!(app.dispatch(Input::Choose(Pick::Backup)).is_empty());
    assert!(!button(&app.view(), "Save backup…").enabled);
}

#[test]
fn backup_and_dump_ask_for_a_destination_then_run() {
    let mut app = dry(vec![drive("p", "disk4", "PIONEER BD-RW BDR-XD08")]);
    app.dispatch(Input::SelectTask(Task::Backup));
    assert!(has_text(
        &app.view(),
        "Save firmware backup files for restoration."
    ));
    assert_eq!(
        app.dispatch(Input::Choose(Pick::Backup)),
        [Effect::SaveFile {
            pick: Pick::Backup,
            file_name: "backup.tar".into()
        }]
    );
    app.dispatch(Input::SelectTask(Task::Dump));
    assert_eq!(
        app.dispatch(Input::Choose(Pick::Dump)),
        [Effect::SaveFile {
            pick: Pick::Dump,
            file_name: "dump.bin".into()
        }]
    );
    let out = std::env::temp_dir().join("freemkv-gui-model-no-such-dump.bin");
    app.dispatch(Input::Chosen(Pick::Dump, out.clone()));
    let (label, device, job) = last_job(&app);
    assert_eq!((label.as_str(), device.as_str()), ("Raw dump", "p"));
    assert!(matches!(job, Job::Dump { out: o, replace: false } if *o == out));

    let mut other = dry(vec![drive("h", "disk5", "HL-DT-ST BD-RE")]);
    other.dispatch(Input::SelectTask(Task::Backup));
    assert!(matches!(
        &other.dispatch(Input::Choose(Pick::Backup))[..],
        [Effect::SaveFile { file_name, .. }] if file_name == "backup.bin"
    ));
}

// ── flash: acknowledgement and confirmation ───────────────────────────────

#[test]
fn flash_starts_with_a_firmware_chooser() {
    let mut app = one_drive();
    app.dispatch(Input::SelectTask(Task::Flash));
    let view = app.view();
    assert_eq!(buttons(&view).len(), 1);
    assert!(button(&view, "Choose firmware…").enabled);
    assert_eq!(
        app.dispatch(Input::Choose(Pick::FlashFirmware)),
        [Effect::OpenFile {
            pick: Pick::FlashFirmware,
            filter: Some(FLASH_FILTER)
        }]
    );
    app.dispatch(Input::Chosen(
        Pick::FlashFirmware,
        "/fw/firmware.bin".into(),
    ));
    let view = app.view();
    for text in ["Change file…", "Flash now", "Check file"] {
        assert!(button(&view, text).enabled, "{text}");
    }
    assert_eq!(button(&view, "Check file").style, ButtonStyle::Link);
    assert!(view.panel.iter().any(|i| matches!(
        i,
        Item::Path { path: Some(p), .. } if p.name == "firmware.bin" && p.full == "/fw/firmware.bin"
    )));
}

#[test]
fn flash_requires_fresh_acknowledgement_and_explicit_confirmation() {
    let mut app = one_drive();
    app.task = Task::Flash;
    app.flash_input = Some("firmware.bin".into());
    app.risk_ack = true;
    assert!(app.dispatch(Input::FlashNow).is_empty());
    assert!(!app.running(), "Flash now only opens the confirmation");
    let confirm = app.view().confirm.expect("confirmation sheet");
    assert_eq!(confirm.title, "Confirm flash");
    assert_eq!(confirm.danger, FLASH_DANGER);
    assert_eq!(confirm.ack_text, RISK_ACK);
    assert_eq!(confirm.note, Some(BACKUP_NOTE));
    assert_eq!(confirm.warning, None);
    assert!(!confirm.ack_checked, "consent never carries over");
    assert!(!confirm.confirm.enabled);
    assert_eq!(confirm.confirm.text, "Flash now");
    assert!(!app.view().controls_enabled);

    assert!(
        app.dispatch(Input::Confirm).is_empty(),
        "no consent, no flash"
    );
    assert!(!app.running() && app.pending.is_some());

    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    assert!(app.view().confirm.unwrap().confirm.enabled);
    assert_eq!(app.dispatch(Input::Confirm), [Effect::StartTicking]);
    assert!(app.pending.is_none() && app.running());
    let (label, device, job) = last_job(&app);
    assert_eq!(
        (label.as_str(), device.as_str()),
        ("Firmware update", "drive-a")
    );
    let Job::Flash(options) = job else {
        panic!("expected a flash job")
    };
    assert!(options.execute && options.acknowledged_risk);
    assert_eq!(options.input, PathBuf::from("firmware.bin"));
}

#[test]
fn cancelled_confirmation_runs_nothing_and_clears_consent() {
    let mut app = one_drive();
    app.flash_input = Some("firmware.bin".into());
    app.dispatch(Input::FlashNow);
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::CancelConfirm);
    assert!(app.view().confirm.is_none() && !app.risk_ack && !app.running());
    assert!(app.dispatch(Input::Confirm).is_empty());
    assert!(app.dry_run.as_ref().unwrap().is_empty());
}

#[test]
fn risk_acknowledgement_is_ignored_without_a_confirmation() {
    let mut app = one_drive();
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    assert!(!app.risk_ack);
}

#[test]
fn flash_needs_a_selected_drive() {
    let mut app = dry(Vec::new());
    app.task = Task::Flash;
    app.flash_input = Some("firmware.bin".into());
    assert!(!button(&app.view(), "Flash now").enabled);
    app.dispatch(Input::FlashNow);
    assert!(app.pending.is_none());
}

#[test]
fn confirmation_freezes_target_and_requires_fresh_consent() {
    let mut app = dry(vec![
        drive("drive-a", "drive-a", "Drive A"),
        drive("drive-b", "drive-b", "Drive B"),
    ]);
    app.flash_input = Some("firmware.bin".into());
    app.risk_ack = true;
    app.dispatch(Input::FlashNow);
    app.dispatch(Input::SelectDrive(1));
    app.dispatch(Input::Refresh);
    assert_eq!(app.device, "drive-a", "drive bar is locked under the sheet");
    assert_eq!(app.pending.as_ref().unwrap().device, "drive-a");
    assert!(!app.risk_ack);
    assert!(!app.running());
}

#[test]
fn drive_choice_and_confirmation_show_the_os_name_of_identical_drives() {
    let label = "HL-DT-ST BD-RE BU40N (rev 1.04)";
    let mut app = dry(vec![
        drive(r"\\.\CdRom0", "D:", label),
        drive(r"\\.\CdRom1", "E:", label),
    ]);
    app.dispatch(Input::SelectDrive(1));
    assert_eq!(app.device_label(), "E:  HL-DT-ST BD-RE BU40N (rev 1.04)");
    let bar = app.view().drives;
    assert_eq!(bar.selected, Some(1));
    assert_eq!(bar.items[1].tooltip, r"\\.\CdRom1");
    app.flash_input = Some("firmware.bin".into());
    app.dispatch(Input::FlashNow);
    let confirm = app.view().confirm.unwrap();
    assert_eq!(
        confirm.details[0],
        "Drive: E:  HL-DT-ST BD-RE BU40N (rev 1.04)"
    );
    assert_eq!(app.pending.as_ref().unwrap().device, r"\\.\CdRom1");
}

// ── recovery ──────────────────────────────────────────────────────────────

#[test]
fn recovery_requires_both_inputs_and_a_drive() {
    let mut app = one_drive();
    app.dispatch(Input::SelectTask(Task::Recovery));
    let view = app.view();
    for text in [
        "Current firmware",
        "Read from drive",
        "Choose Current…",
        "Firmware to flash (Kernel + Normal)",
        "Choose firmware…",
        FORCE_WARNING,
        "Recover",
    ] {
        assert!(has_text(&view, text), "{text}");
    }
    assert!(!button(&view, "Recover").enabled);
    app.dispatch(Input::Recover);
    assert!(app.pending.is_none());

    app.dispatch(Input::Chosen(Pick::RecoveryInput, "new.tar".into()));
    assert!(
        !button(&app.view(), "Recover").enabled,
        "current firmware missing"
    );
    app.dispatch(Input::SetCheck(CheckId::RecoveryReadFromDrive, true));
    let view = app.view();
    assert!(!button(&view, "Choose Current…").enabled);
    assert!(has_text(
        &view,
        "Reads installed firmware for protocol analysis. No backup file is saved."
    ));
    assert!(button(&view, "Recover").enabled);
    app.dispatch(Input::SetCheck(CheckId::RecoveryReadFromDrive, false));
    assert!(!button(&app.view(), "Recover").enabled);
    app.dispatch(Input::Chosen(Pick::RecoveryCurrent, "old.tar".into()));
    assert!(button(&app.view(), "Recover").enabled);
}

#[test]
fn recovery_confirms_with_the_force_warning_then_runs_acknowledged() {
    let mut app = one_drive();
    app.task = Task::Recovery;
    app.recovery_input = Some("new.tar".into());
    app.recovery_read = true;
    app.dispatch(Input::Recover);
    let confirm = app.view().confirm.unwrap();
    assert_eq!(confirm.title, "Confirm recovery");
    assert_eq!(confirm.warning, Some(FORCE_WARNING));
    assert_eq!(confirm.note, None);
    assert_eq!(confirm.confirm.text, "Recover");
    assert!(confirm
        .details
        .contains(&"Current: read from drive".to_string()));
    assert!(app.dispatch(Input::Confirm).is_empty());
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::Confirm);
    let (label, device, job) = last_job(&app);
    assert_eq!((label.as_str(), device.as_str()), ("Recovery", "drive-a"));
    let Job::Recovery(options) = job else {
        panic!("expected a recovery job")
    };
    assert!(options.execute && options.acknowledged_risk);
    assert!(matches!(options.current, CurrentFirmware::ReadFromDrive));
    assert_eq!(options.input, PathBuf::from("new.tar"));
}

// ── job lifecycle and events ──────────────────────────────────────────────

#[test]
fn job_lifecycle_reports_progress_then_completion() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    let status = app.view().status.unwrap();
    assert_eq!(status.text, "Drive information…");
    assert!(status.running);
    assert_eq!(status.note, Some(KEEP_CONNECTED));
    assert_eq!(
        status.progress.unwrap().fraction,
        None,
        "indeterminate first"
    );
    assert!(status.cancel.is_none(), "only analysis can be cancelled");
    let tx = app.worker.clone().unwrap();
    tx.send(Msg::Event(Event::Progress {
        label: "Reading firmware".into(),
        done: 512,
        total: 1024,
    }))
    .unwrap();
    assert!(app.poll().is_empty());
    let progress = app.view().status.unwrap().progress.unwrap();
    assert_eq!(progress.label, "Reading firmware");
    assert_eq!(progress.fraction, Some(0.5));
    assert_eq!(finish(&mut app, Ok(())), [Effect::StopTicking]);
    let view = app.view();
    assert!(!app.running() && view.controls_enabled && view.can_close);
    let status = view.status.unwrap();
    assert_eq!(status.text, "Drive information complete");
    assert!(status.progress.is_none());
    assert_eq!(app.log.last().unwrap(), "✓ done.");
}

#[test]
fn failed_job_offers_log_export_next_to_the_error() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    finish(&mut app, Err("Backup failed".into()));
    let results = app.view().results.unwrap();
    let failure = results.failure.unwrap();
    assert_eq!(failure.text, "Backup failed");
    assert_eq!(failure.save_log.text, "Save diagnostic log…");
    assert_eq!(results.view_log.text, "View diagnostic log…");
    assert_eq!(app.status, "Drive information could not finish");
    assert_eq!(app.log.last().unwrap(), "✗ error: Backup failed");
}

#[test]
fn disconnected_worker_releases_controls_and_reports_failure() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    drop(app.worker.take());
    assert_eq!(app.poll(), [Effect::StopTicking]);
    assert!(!app.running(), "a dead worker must not leave the app busy");
    assert!(app.log.iter().any(|l| l.contains("worker")));
    assert_eq!(app.failure.as_deref(), Some(WORKER_GONE));
}

#[test]
fn completion_is_not_misreported_as_worker_disconnection() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    let tx = app.worker.take().unwrap();
    tx.send(Msg::Done(Ok(()))).unwrap();
    drop(tx);
    app.poll();
    assert!(!app.running());
    assert_eq!(app.log.last().unwrap(), "✓ done.");
}

#[test]
fn events_fill_fields_settings_log_and_diagnostic_path() {
    let mut app = one_drive();
    app.event(Event::Field {
        label: "Model".into(),
        value: "BDR-UD04".into(),
    });
    app.event(Event::Field {
        label: "Diagnostic log".into(),
        value: "/tmp/diagnostic.log".into(),
    });
    app.event(Event::Message("hello".into()));
    assert_eq!(app.fields, [("Model".into(), "BDR-UD04".into())]);
    assert_eq!(
        app.diagnostic_log,
        Some(PathBuf::from("/tmp/diagnostic.log"))
    );
    assert_eq!(app.log.last().unwrap(), "hello");
    use freemkv_flash::output::device_settings::{Codec, VendorF4};
    let mut response = [0u8; 256];
    response[..4].copy_from_slice(&[255, 255, 2, 2]);
    let settings = VendorF4.decode(&response).unwrap();
    app.event(Event::DeviceSettings(settings));
    assert_eq!(app.device_settings, Some(settings));
}

#[test]
fn results_belong_to_the_task_that_produced_them() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    app.worker
        .clone()
        .unwrap()
        .send(Msg::Event(Event::Field {
            label: "Model".into(),
            value: "OLD INFO RESULT".into(),
        }))
        .unwrap();
    finish(&mut app, Ok(()));
    assert!(!app.view().results.unwrap().cards.is_empty());
    for task in [Task::Backup, Task::Dump, Task::Flash, Task::Recovery] {
        app.dispatch(Input::SelectTask(task));
        let view = app.view();
        assert!(view.status.is_none() && view.results.is_none(), "{task:?}");
    }
}

#[test]
fn non_info_results_are_plain_fields() {
    let mut app = one_drive();
    app.task = Task::Backup;
    app.result_task = Task::Backup;
    app.fields = vec![("Backup".into(), "/tmp/b.tar".into())];
    let results = app.view().results.unwrap();
    assert!(results.cards.is_empty());
    assert_eq!(results.fields, app.fields);
}

#[test]
fn refresh_removes_disconnected_selection_and_its_consent() {
    let mut app = dry(vec![drive("ioreg:old", "ioreg:old", "Drive")]);
    app.risk_ack = true;
    app.refresh(vec![drive("ioreg:new", "ioreg:new", "Reconnected drive")]);
    assert_eq!(app.device, "ioreg:new");
    assert!(!app.risk_ack);
    app.refresh(Vec::new());
    assert!(app.device.is_empty());
    assert!(app.view().drives.items.is_empty());
}

#[test]
fn selecting_another_drive_clears_its_results() {
    let mut app = dry(vec![drive("a", "a", "A"), drive("b", "b", "B")]);
    app.fields = vec![("Model".into(), "A".into())];
    app.failure = Some("old".into());
    app.dispatch(Input::SelectDrive(1));
    assert_eq!(app.device, "b");
    assert!(app.fields.is_empty() && app.failure.is_none());
    app.dispatch(Input::SelectDrive(7));
    assert_eq!(app.device, "b", "an out-of-range index is ignored");
}

/// The real worker, the real workflow, no drive: it must fail cleanly, never panic.
#[test]
fn drive_info_on_a_missing_device_fails_gracefully() {
    let mut app = App::with_drives(vec![drive(
        "/dev/freemkv-flash-gui-no-such-device",
        "none",
        "Missing drive",
    )]);
    assert_eq!(app.dispatch(Input::ReadInfo), [Effect::StartTicking]);
    let start = Instant::now();
    while app.running() {
        assert!(start.elapsed() < Duration::from_secs(60), "worker hung");
        std::thread::sleep(Duration::from_millis(20));
        app.poll();
    }
    assert!(app.failure.is_some(), "{:?}", app.log);
    assert_eq!(app.status, "Drive information could not finish");
    assert!(app.view().controls_enabled);
}

// ── diagnostics ───────────────────────────────────────────────────────────

#[test]
fn diagnostic_viewer_and_export_show_the_same_full_log() {
    let path =
        std::env::temp_dir().join(format!("freemkv-gui-diagnostic-{}.log", std::process::id()));
    std::fs::write(
        &path,
        "SCSI result: status=0x00 transferred=0\nRESULT: error\n",
    )
    .unwrap();
    let mut app = one_drive();
    app.log = vec!["backup failed".into()];
    app.diagnostic_log = Some(path.clone());
    app.dispatch(Input::OpenDiagnostics);
    let diag = app.view().diagnostics.unwrap();
    assert_eq!(diag.hint, "Attach this log to your bug report.");
    assert_eq!(diag.path.as_deref(), Some(&*path.display().to_string()));
    assert!(diag
        .lines
        .iter()
        .any(|l| l.contains("status=0x00 transferred=0")));
    assert!(!diag.lines.iter().any(|l| l == "backup failed"));
    let texts: Vec<_> = diag.buttons.iter().map(|b| b.text.as_str()).collect();
    assert_eq!(
        texts,
        ["Copy diagnostic log", "Save diagnostic log…", "Close"]
    );
    assert!(matches!(
        &app.dispatch(Input::CopyDiagnostics)[..],
        [Effect::CopyText(t)] if t.contains("RESULT: error")
    ));

    let out = std::env::temp_dir().join(format!("freemkv-gui-export-{}.log", std::process::id()));
    app.dispatch(Input::Chosen(Pick::DiagnosticLog, out.clone()));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        std::fs::read_to_string(&path).unwrap()
    );
    assert!(app
        .diagnostic_notice
        .as_ref()
        .unwrap()
        .starts_with("Diagnostic log exported"));
    std::fs::remove_file(&out).unwrap();

    std::fs::write(&path, "RESULT: updated log\n").unwrap();
    app.refresh_diagnostic_view();
    assert_eq!(*app.diagnostic_lines, ["RESULT: updated log"]);
    std::fs::remove_file(&path).unwrap();
    assert!(
        app.diagnostic_text().is_err(),
        "a missing log must not export a summary"
    );
    app.refresh_diagnostic_view();
    assert!(app.diagnostic_lines[0].contains("Could not read diagnostic log"));
    app.dispatch(Input::CloseDiagnostics);
    assert!(app.view().diagnostics.is_none());
}

#[test]
fn diagnostics_save_offers_the_default_name_even_while_running() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    assert_eq!(
        app.dispatch(Input::Choose(Pick::DiagnosticLog)),
        [Effect::SaveFile {
            pick: Pick::DiagnosticLog,
            file_name: "freemkv-flash-diagnostic.log".into()
        }]
    );
}

// ── inspect and compare ───────────────────────────────────────────────────

#[test]
fn inspect_and_compare_need_their_sources() {
    let mut app = dry(Vec::new());
    app.dispatch(Input::SelectTask(Task::Inspect));
    let view = app.view();
    let files = buttons(&view)
        .iter()
        .filter(|b| b.text == "Firmware file…")
        .count();
    assert_eq!(files, 1);
    assert!(!button(&view, "Selected drive…").enabled, "no drive");
    assert!(!button(&view, "Inspect").enabled);
    assert!(has_text(&view, "Choose a firmware file or drive."));
    app.dispatch(Input::Chosen(Pick::AnalysisFile(0), "/fw/a.bin".into()));
    let view = app.view();
    assert!(button(&view, "Inspect").enabled);
    assert!(has_text(&view, "/fw/a.bin"));

    app.dispatch(Input::SelectTask(Task::Compare));
    let view = app.view();
    assert!(view
        .panel
        .iter()
        .any(|i| matches!(i, Item::Buttons { label: Some(l), .. } if l == "Source B")));
    assert!(!button(&view, "Compare").enabled);
    app.dispatch(Input::Chosen(Pick::AnalysisFile(1), "/fw/b.bin".into()));
    assert!(button(&app.view(), "Compare").enabled);
    app.dispatch(Input::RunAnalysis);
    let (label, device, job) = last_job(&app);
    assert_eq!((label.as_str(), device.as_str()), ("Compare", ""));
    assert!(matches!(
        job,
        Job::Analysis {
            request: Request::Compare(..),
            ..
        }
    ));
    let status = app.view().status.unwrap();
    assert_eq!(status.cancel.unwrap().text, "Cancel analysis");
    app.dispatch(Input::CancelAnalysis);
    assert!(app.control.cancelled());
}

#[test]
fn only_one_compare_side_may_be_a_live_drive() {
    let mut app = one_drive();
    app.dispatch(Input::SelectTask(Task::Compare));
    assert!(matches!(
        &app.dispatch(Input::Choose(Pick::AnalysisDrive(0)))[..],
        [Effect::SaveFile { file_name, .. }] if file_name == "inspection.backup.tar"
    ));
    app.dispatch(Input::Chosen(Pick::AnalysisDrive(0), "/tmp/cap.tar".into()));
    let view = app.view();
    assert!(has_text(&view, "drive-a → capture /tmp/cap.tar"));
    let drive_buttons: Vec<_> = buttons(&view)
        .into_iter()
        .filter(|b| b.text == "Selected drive…")
        .collect();
    assert!(drive_buttons[0].enabled && !drive_buttons[1].enabled);
    assert!(app
        .dispatch(Input::Choose(Pick::AnalysisDrive(1)))
        .is_empty());
}

#[test]
fn report_actions_need_a_result() {
    let mut app = one_drive();
    assert!(app.dispatch(Input::Choose(Pick::ReportText)).is_empty());
    assert!(app.dispatch(Input::CopyReport).is_empty());
    app.dispatch(Input::OpenResults);
    assert!(app.view().analysis.is_none());
}

// ── drive information cards ───────────────────────────────────────────────

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn region_and_saved_settings_are_not_misclassified_as_media() {
    assert_eq!(section("DVD region"), 3);
    assert_eq!(section("DVD-R DL"), 2);
    assert_eq!(section("Saved Quiet Drive"), 4);
    assert_eq!(section("Firmware version"), 1);
    assert_eq!(section("Firmware type"), 1);
    assert_eq!(section("Model"), 0);
}

#[test]
fn information_cards_group_order_and_columns() {
    let fields = pairs(&[
        ("Model", "BDR-XD08U"),
        ("Firmware version", "1.10"),
        ("Kernel type", "ID69"),
        ("Product code", "XYZ"),
        ("CD-R", "Read: Yes    Write: Yes"),
        ("BD-ROM", "Read: Yes    Write: No"),
        ("DVD region", "2"),
        ("Quiet Drive", "Quiet"),
        ("Firmware update", "Supported"),
    ]);
    let cards = info_cards(&fields, None);
    let titles: Vec<_> = cards.iter().map(|c| (c.title, c.column)).collect();
    assert_eq!(
        titles,
        [
            ("General information", 0),
            ("Additional information", 1),
            ("DVD region", 1),
            ("Device settings", 1),
            ("Media capabilities", 0),
            ("Firmware operations", 1),
        ]
    );
    assert_eq!(cards[3].subtitle, Some("Current settings · read only"));
    let CardBody::Rows(rows) = &cards[1].body else {
        panic!("rows")
    };
    assert_eq!(
        rows,
        &[
            Row::Group("Device"),
            Row::Pair("Product code".into(), "XYZ".into()),
            Row::Group("Kernel"),
            Row::Pair("Kernel type".into(), "ID69".into()),
            Row::Group("Normal"),
            Row::Pair("Firmware version".into(), "1.10".into()),
        ]
    );
    let CardBody::Media { left, right } = &cards[4].body else {
        panic!("media")
    };
    assert_eq!(left[0].label, "CD-R");
    assert_eq!((left[0].read, left[0].write), (Tri::Yes, Some(Tri::Yes)));
    assert_eq!(right[0].label, "BD-ROM");
    assert_eq!(right[0].write, None, "read-only media shows no write tick");
}

#[test]
fn info_results_become_cards_only_with_a_model() {
    let mut app = one_drive();
    app.fields = pairs(&[("Model", "BDR"), ("Firmware update", "Supported")]);
    assert_eq!(app.view().results.unwrap().cards.len(), 2);
    app.fields = pairs(&[("File", "ok")]);
    let results = app.view().results.unwrap();
    assert!(results.cards.is_empty());
    assert_eq!(results.fields.len(), 1);
}

#[test]
fn media_visibility_requires_a_positive_capability() {
    for value in [
        "Unknown",
        "No",
        "Read: Unknown    Write: Unknown",
        "Read: Unknown    Write: No",
        "Read: No    Write: No",
        "Read: No    Write: Unknown",
    ] {
        assert!(!visible_media(value), "{value}");
    }
    for value in [
        "Yes",
        "Read: Yes    Write: No",
        "Read: Yes    Write: Unknown",
        "Read: Unknown    Write: Yes",
    ] {
        assert!(visible_media(value), "{value}");
    }
}

#[test]
fn empty_media_card_is_hidden_and_other_information_survives() {
    let fields = pairs(&[
        ("Model", "PIONEER"),
        ("BD-R XL", "Read: Unknown    Write: Unknown"),
        ("LabelFlash", "Unknown"),
    ]);
    let cards = info_cards(&fields, None);
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].title, "General information");
    assert_eq!(
        cards[0].body,
        CardBody::Rows(vec![Row::Pair("Model".into(), "PIONEER".into())])
    );
}

#[test]
fn settings_render_from_codec_descriptors_without_unsupported_children() {
    use freemkv_flash::output::device_settings::{Codec, VendorF4};
    let mut response = [0u8; 256];
    response[..2].fill(255);
    response[2] = 2;
    response[3] = 2;
    response[43] = 1;
    response[45] = 1;
    response[49] = 4; // Must remain hidden when PureRead support is zero.
    let settings = VendorF4.decode(&response).unwrap();
    let cards = info_cards(&[], Some(&settings));
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].title, "Device settings");
    let CardBody::Settings(views) = &cards[0].body else {
        panic!("settings")
    };
    assert!(views.iter().all(|v| !v.title.contains("PureRead")));
    let SettingValue::Choices(choices) = &views[0].value else {
        panic!("choices: {views:?}")
    };
    let saved: Vec<_> = choices
        .iter()
        .filter(|(t, _)| t == "Quiet · saved")
        .collect();
    assert_eq!(saved.len(), 1);
    assert!(choices.iter().any(|(t, _)| t == "Persistent quiet"));
}

#[test]
fn byte_counts_read_naturally() {
    assert_eq!(byte_count(0), "Unchanged");
    assert_eq!(byte_count(10), "10 bytes");
    assert_eq!(byte_count(2048), "2.0 KiB");
}
