//! Shared-workflow desktop front-end; widgets never select an OS or a drive protocol.

use std::sync::mpsc::{self, Receiver, TryRecvError};

use crate::ops::{self, Job};
use eframe::egui;
use freemkv_flash::workflow::{DriveChoice, FlashOptions};

enum Msg {
    Event(freemkv_flash::output::Event),
    Done(Result<(), String>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Task {
    Info,
    Backup,
    Dump,
    Flash,
}

#[derive(Clone)]
struct PendingFlash {
    device: String,
    label: String,
    options: FlashOptions,
}

/// Platform-independent application state.
pub struct FlashApp {
    task: Task,
    result_task: Task,
    input: Option<std::path::PathBuf>,
    status: String,
    failure: Option<String>,
    action: String,
    devices: Vec<DriveChoice>,
    device: String,
    risk_ack: bool,
    pending_flash: Option<PendingFlash>,
    details_open: bool,
    options: FlashOptions,
    log: Vec<String>,
    progress: Option<(String, usize, usize)>,
    fields: Vec<(String, String)>,
    running: bool,
    rx: Option<Receiver<Msg>>,
}

impl FlashApp {
    pub fn new() -> Self {
        Self::with_drives(ops::enumerate())
    }

    fn with_drives(devices: Vec<DriveChoice>) -> Self {
        let device = devices.first().map(|d| d.path.clone()).unwrap_or_default();
        Self {
            task: Task::Info,
            result_task: Task::Info,
            input: None,
            status: "Ready".into(),
            failure: None,
            action: String::new(),
            devices,
            device,
            risk_ack: false,
            pending_flash: None,
            details_open: false,
            options: FlashOptions::default(),
            log: vec!["Ready. Select an optical drive and choose an action.".into()],
            progress: None,
            fields: Vec::new(),
            running: false,
            rx: None,
        }
    }

    fn refresh(&mut self, devices: Vec<DriveChoice>) {
        if !devices.iter().any(|d| d.path == self.device) {
            self.device = devices.first().map(|d| d.path.clone()).unwrap_or_default();
            self.risk_ack = false;
            self.pending_flash = None;
        }
        self.devices = devices;
    }

    fn device_label(&self) -> String {
        self.devices
            .iter()
            .find(|d| d.path == self.device)
            .map(|d| d.label.clone())
            .unwrap_or_else(|| "No optical drive found".into())
    }

    fn start_job(&mut self, ctx: &egui::Context, label: &str, device: String, job: Job) {
        if self.running {
            return;
        }
        if device.is_empty() && !matches!(job, Job::InfoFile { .. }) {
            self.log.push("No optical drive selected.".into());
            return;
        }
        self.result_task = self.task;
        self.running = true;
        self.action = label.to_string();
        self.status = format!("{label}…");
        self.failure = None;
        self.log.clear();
        self.progress = None;
        self.fields.clear();
        self.log.push(format!("{label}: {device}"));
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let line_tx = tx.clone();
            let line_ctx = ctx.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                freemkv_flash::output::capture_events(
                    move |event| {
                        let _ = line_tx.send(Msg::Event(event));
                        line_ctx.request_repaint();
                    },
                    || ops::execute(&device, &job),
                )
            }));
            let result = match result {
                Ok(result) => result.map_err(|e| format!("{e:#}")),
                Err(_) => Err("Operation worker failed unexpectedly. If flashing was underway, the drive state is uncertain; keep the backup and inspect the drive before retrying.".into()),
            };
            let _ = tx.send(Msg::Done(result));
            ctx.request_repaint();
        });
    }

    fn pump(&mut self) {
        let mut finished = false;
        if let Some(rx) = &self.rx {
            loop {
                match rx.try_recv() {
                    Ok(Msg::Event(event)) => match event {
                        freemkv_flash::output::Event::Message(line) => self.log.push(line),
                        freemkv_flash::output::Event::Progress { label, done, total } => {
                            self.progress = Some((label, done, total))
                        }
                        freemkv_flash::output::Event::Field { label, value } => {
                            self.fields.push((label, value))
                        }
                    },
                    Ok(Msg::Done(result)) => {
                        match &result {
                            Ok(()) => self.status = format!("{} complete", self.action),
                            Err(error) => {
                                self.status = format!("{} could not finish", self.action);
                                self.failure = Some(error.clone());
                            }
                        }
                        self.log.push(match result {
                            Ok(()) => "✓ done.".into(),
                            Err(e) => format!("✗ error: {e}"),
                        });
                        finished = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.status = "Operation interrupted".into();
                        self.failure = Some("The worker stopped before reporting a result. If a flash was underway, inspect the drive before retrying.".into());
                        self.log.push("✗ worker disconnected before reporting completion; operation outcome is unknown.".into());
                        finished = true;
                        break;
                    }
                }
            }
        }
        if finished {
            self.running = false;
            self.rx = None;
        }
    }

    fn choose_flash(&mut self, ctx: &egui::Context, execute: bool) {
        let Some(input) = self.input.clone() else {
            return;
        };
        let mut options = self.options.clone();
        options.input = input;
        options.execute = execute;
        options.acknowledged_risk = false;
        if execute {
            self.risk_ack = false;
            self.pending_flash = Some(PendingFlash {
                device: self.device.clone(),
                label: self.device_label(),
                options,
            });
        } else {
            self.start_job(
                ctx,
                "Preview flash",
                self.device.clone(),
                Job::Flash(options),
            );
        }
    }

    fn flash_confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(pending) = self.pending_flash.clone() else {
            return;
        };
        let mut open = true;
        let mut decision = None;
        egui::Window::new("Confirm flash").default_width(480.0).collapsible(false).resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0)).open(&mut open)
            .show(ctx, |ui| {
                ui.label(format!("Drive: {}", pending.label));
                ui.label(format!("Image: {}", pending.options.input.display()));
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), "Flashing can permanently disable the drive. Keep it connected and powered until completion.");
                if pending.options.force {
                    ui.colored_label(egui::Color32::YELLOW, "A backup will be attempted, but this update can proceed without one.");
                } else {
                    ui.label("A validated pre-flash backup will be saved before writing.");
                }
                if pending.options.force {
                    ui.colored_label(egui::Color32::from_rgb(160, 70, 0), "Force: compatibility checks are overridden; backup failure will not stop the update.");
                }
                ui.add_space(12.0);
                ui.checkbox(&mut self.risk_ack, "I understand and want to update this drive");
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { decision = Some(false); }
                    if ui.add_enabled(self.risk_ack, egui::Button::new("Flash now")).clicked() { decision = Some(true); }
                });
            });
        match decision {
            Some(true) => {
                self.pending_flash = None;
                let mut options = pending.options;
                options.acknowledged_risk = self.risk_ack;
                self.start_job(ctx, "Firmware update", pending.device, Job::Flash(options));
            }
            Some(false) => self.pending_flash = None,
            None if !open => self.pending_flash = None,
            None => {}
        }
    }

    fn protect_running_job(&self, ctx: &egui::Context) {
        if self.running && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }
}

impl FlashApp {
    fn task_content(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let selected = !self.device.is_empty();
        match self.task {
            Task::Info => {
                ui.horizontal(|ui| {
                    if primary(ui, "Read drive information", selected).clicked() {
                        self.start_job(ctx, "Drive information", self.device.clone(), Job::Info);
                    }
                    if ui.button("Check file…").clicked() {
                        if let Some(input) = rfd::FileDialog::new().pick_file() {
                            self.start_job(
                                ctx,
                                "Check file",
                                String::new(),
                                Job::InfoFile { input },
                            );
                        }
                    }
                });
                if !selected {
                    ui.label("Connect an optical drive, then select Refresh.");
                }
            }
            Task::Backup | Task::Dump => {
                let dump = self.task == Task::Dump;
                ui.label(if dump {
                    "Capture all accessible drive memory into a raw file."
                } else {
                    "Save firmware backup files for restoration."
                });
                ui.add_space(8.0);
                if primary(
                    ui,
                    if dump {
                        "Save raw dump…"
                    } else {
                        "Save backup…"
                    },
                    selected,
                )
                .clicked()
                {
                    let filename = if dump { "dump.bin" } else { "backup.tar" };
                    if let Some(out) = rfd::FileDialog::new().set_file_name(filename).save_file() {
                        let job = if dump {
                            Job::Dump { out }
                        } else {
                            Job::Backup { out }
                        };
                        self.start_job(
                            ctx,
                            if dump { "Raw dump" } else { "Backup" },
                            self.device.clone(),
                            job,
                        );
                    }
                }
            }
            Task::Flash => {
                ui.label(if self.options.force {
                    "Choose a firmware file. Force can proceed if the backup fails."
                } else {
                    "Choose a firmware file. A backup is saved automatically before updating."
                });
                ui.add_space(8.0);
                egui::Frame::group(ui.style())
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.set_max_width(420.0);
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(
                                            self.input
                                                .as_ref()
                                                .and_then(|p| p.file_name())
                                                .map(|p| p.to_string_lossy().into_owned())
                                                .unwrap_or_else(|| "No firmware selected".into()),
                                        )
                                        .strong(),
                                    )
                                    .truncate(),
                                );
                                ui.small("Firmware image or backup · .bin, .enc, .tar");
                            });
                            if ui.button("Choose file…").clicked() {
                                if let Some(input) = rfd::FileDialog::new()
                                    .add_filter("Firmware or backup", &["bin", "enc", "tar"])
                                    .pick_file()
                                {
                                    self.input = Some(input);
                                }
                            }
                        });
                    });
                ui.add_space(8.0);
                let ready = selected && self.input.is_some();
                ui.horizontal(|ui| {
                    if primary(ui, "Continue…", ready).clicked() {
                        self.choose_flash(ctx, true);
                    }
                    if ui
                        .add_enabled(self.input.is_some(), egui::Button::new("Check file"))
                        .clicked()
                    {
                        if let Some(input) = self.input.clone() {
                            self.start_job(
                                ctx,
                                "Check file",
                                String::new(),
                                Job::InfoFile { input },
                            );
                        }
                    }
                });
                ui.small("Review the drive and file on the next screen. Nothing is written yet.");
                ui.add_space(8.0);
                ui.checkbox(
                    &mut self.options.force,
                    "Force flash (override compatibility and allow backup failure)",
                );
            }
        }
    }
}

fn primary(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(egui::RichText::new(text).color(egui::Color32::WHITE))
            .fill(egui::Color32::from_rgb(30, 95, 165))
            .min_size(egui::vec2(170.0, 34.0)),
    )
}

impl eframe::App for FlashApp {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

impl FlashApp {
    fn render(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.pump();
        self.protect_running_job(&ctx);
        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        egui::Frame::new().inner_margin(16.0).show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.heading("freemkv");
                ui.label("Firmware Utility");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(env!("CARGO_PKG_VERSION"));
                });
            });
            ui.add_space(18.0);
            ui.add_enabled_ui(
                !self.running && self.pending_flash.is_none() && !self.details_open,
                |ui| {
                    egui::Frame::group(ui.style())
                        .inner_margin(14.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Optical drive").strong());
                            ui.horizontal(|ui| {
                                let previous = self.device.clone();
                                egui::ComboBox::from_id_salt("device_combo")
                                    .selected_text(self.device_label())
                                    .width((ui.available_width() - 88.0).max(180.0))
                                    .show_ui(ui, |ui| {
                                        for drive in &self.devices {
                                            ui.selectable_value(
                                                &mut self.device,
                                                drive.path.clone(),
                                                &drive.label,
                                            )
                                            .on_hover_text(&drive.path);
                                        }
                                    });
                                if previous != self.device {
                                    self.risk_ack = false;
                                    self.fields.clear();
                                    self.status = "Ready".into();
                                    self.failure = None;
                                }
                                if ui.button("Refresh").clicked() {
                                    self.refresh(ops::enumerate());
                                }
                            });
                        });
                    ui.add_space(18.0);
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.task, Task::Info, "Drive info");
                        ui.selectable_value(&mut self.task, Task::Backup, "Backup");
                        ui.selectable_value(&mut self.task, Task::Dump, "Dump");
                        ui.selectable_value(&mut self.task, Task::Flash, "Flash firmware");
                    });
                    ui.separator();
                    ui.add_space(18.0);
                    egui::ScrollArea::vertical()
                        .id_salt(("task_content", self.task as u8))
                        .max_height(match self.task {
                            Task::Info => 60.0,
                            Task::Backup | Task::Dump => 110.0,
                            Task::Flash => 200.0,
                        })
                        .min_scrolled_height(match self.task {
                            Task::Info => 60.0,
                            Task::Backup | Task::Dump => 110.0,
                            Task::Flash => 200.0,
                        })
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            self.task_content(ui, &ctx);
                        });
                },
            );
            if self.result_task != self.task {
                return;
            }
            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                if self.running {
                    ui.spinner();
                }
                ui.label(egui::RichText::new(&self.status).strong());
            });
            if self.running {
                if let Some((label, done, total)) = &self.progress {
                    ui.label(label);
                    ui.add(
                        egui::ProgressBar::new(*done as f32 / (*total).max(1) as f32)
                            .show_percentage(),
                    );
                } else {
                    ui.add(egui::ProgressBar::new(0.0).animate(true).text("Preparing…"));
                }
                ui.small("Keep the drive connected and powered until this finishes.");
            }
            egui::ScrollArea::vertical()
                .id_salt("result_panel")
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .max_height(ui.available_height().max(1.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if !self.fields.is_empty() {
                        egui::Grid::new("operation_results")
                            .num_columns(2)
                            .spacing([24.0, 8.0])
                            .max_col_width((ui.available_width() - 24.0) / 2.0)
                            .show(ui, |ui| {
                                for (label, value) in &self.fields {
                                    ui.label(label);
                                    ui.add(egui::Label::new(value).wrap());
                                    ui.end_row();
                                }
                            });
                    }
                    if let Some(error) = &self.failure {
                        ui.colored_label(egui::Color32::from_rgb(160, 45, 35), error);
                    }
                    ui.add_space(6.0);
                    if ui.button("View details…").clicked() {
                        self.details_open = true;
                    }
                });
        });
        self.flash_confirm_dialog(&ctx);
        if self.details_open {
            let mut open = true;
            let mut close = false;
            egui::Window::new("Operation details")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(egui::vec2(620.0, 400.0))
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(&ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Copy details").clicked() {
                            ctx.copy_text(self.log.join("\n"));
                        }
                        if ui.button("Close").clicked() {
                            close = true;
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("diagnostic_text")
                        .scroll_bar_visibility(
                            egui::scroll_area::ScrollBarVisibility::AlwaysVisible,
                        )
                        .max_height(340.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for line in &self.log {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(line).monospace().size(12.0),
                                    )
                                    .wrap(),
                                );
                            }
                        });
                });
            self.details_open = open && !close;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered_text(app: &mut FlashApp) -> Vec<(String, bool)> {
        let ctx = egui::Context::default();
        ctx.set_theme(egui::Theme::Light);
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
        app.fields = vec![("Manufacturer".into(), "OLD INFO RESULT".into())];
        app.status = "Drive information complete".into();
        for (task, controls) in [
            (Task::Backup, vec!["Save backup…"]),
            (Task::Dump, vec!["Save raw dump…"]),
            (
                Task::Flash,
                vec![
                    "Choose file…",
                    "Continue…",
                    "Check file",
                    "Force flash (override compatibility and allow backup failure)",
                ],
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
                .any(|(label, _)| label == "OLD INFO RESULT"
                    || label == "Drive information complete"));
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
}
