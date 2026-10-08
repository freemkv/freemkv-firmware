//! Shared-workflow desktop front-end; widgets never select an OS or a drive protocol.

use std::sync::mpsc::{self, Receiver, TryRecvError};

use crate::ops::{self, Job};
use eframe::egui;
use freemkv_flash::workflow::{DriveChoice, FlashOptions};

enum Msg {
    Event(freemkv_flash::output::Event),
    Analysis(crate::analysis_ui::ResultView),
    Done(Result<(), String>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Task {
    Info,
    Inspect,
    Compare,
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
    analysis: crate::analysis_ui::Panel,
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
    diagnostic_log: Option<std::path::PathBuf>,
    diagnostic_lines: Vec<String>,
    diagnostic_checked: Option<std::time::Instant>,
    diagnostic_notice: Option<String>,
    progress: Option<(String, usize, usize)>,
    fields: Vec<(String, String)>,
    running: bool,
    rx: Option<Receiver<Msg>>,
}

impl FlashApp {
    fn diagnostic_text(&self) -> std::io::Result<String> {
        match &self.diagnostic_log {
            Some(path) => std::fs::read_to_string(path),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No diagnostic log is available for this operation.",
            )),
        }
    }

    fn refresh_diagnostic_view(&mut self) {
        self.diagnostic_lines = match self.diagnostic_text() {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) => vec![format!("Could not read diagnostic log: {error}")],
        };
        self.diagnostic_checked = Some(std::time::Instant::now());
    }

    fn save_diagnostic_log(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("freemkv-flash-diagnostic.log")
            .save_file()
        {
            let result = self
                .diagnostic_text()
                .and_then(|text| std::fs::write(&path, text));
            self.diagnostic_notice = Some(match result {
                Ok(()) => format!("Diagnostic log exported: {}", path.display()),
                Err(error) => format!("Could not export diagnostic log: {error}"),
            });
        }
    }

    pub fn new() -> Self {
        let mut app = Self::with_drives(Vec::new());
        app.discover();
        app
    }

    fn discover(&mut self) {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = events.clone();
        let drives = freemkv_flash::output::capture_events(
            move |event| received.lock().unwrap().push(event),
            ops::enumerate,
        );
        self.refresh(drives);
        for event in events.lock().unwrap().drain(..) {
            match event {
                freemkv_flash::output::Event::Field { label, value }
                    if label == "Diagnostic log" =>
                {
                    self.diagnostic_log = Some(value.into());
                }
                freemkv_flash::output::Event::Message(line) => self.log.push(line),
                _ => {}
            }
        }
    }

    fn with_drives(devices: Vec<DriveChoice>) -> Self {
        let device = devices.first().map(|d| d.path.clone()).unwrap_or_default();
        Self {
            analysis: crate::analysis_ui::Panel::default(),
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
            diagnostic_log: None,
            diagnostic_lines: Vec::new(),
            diagnostic_checked: None,
            diagnostic_notice: None,
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
            .map(DriveChoice::display)
            .unwrap_or_else(|| "No optical drive found".into())
    }

    fn start_job(&mut self, ctx: &egui::Context, label: &str, device: String, job: Job) {
        if self.running {
            return;
        }
        if device.is_empty() && !matches!(job, Job::InfoFile { .. } | Job::Analysis { .. }) {
            self.log.push("No optical drive selected.".into());
            return;
        }
        self.result_task = self.task;
        self.running = true;
        self.action = label.to_string();
        self.status = format!("{label}…");
        self.failure = None;
        self.log.clear();
        self.diagnostic_log = None;
        self.diagnostic_checked = None;
        self.diagnostic_notice = None;
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
                    || {
                        if let Job::Analysis { request, control } = &job {
                            let result = crate::analysis_ui::execute(request, control)?;
                            let _ = tx.send(Msg::Analysis(result));
                            Ok(())
                        } else {
                            ops::execute(&device, &job)
                        }
                    },
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
                            if label == "Diagnostic log" {
                                self.diagnostic_log = Some(value.clone().into());
                            }
                            self.fields.push((label, value))
                        }
                    },
                    Ok(Msg::Analysis(result)) => {
                        self.analysis.result = Some(result);
                        self.analysis.window_open = true;
                    }
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
            self.diagnostic_checked = None;
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
            Task::Inspect | Task::Compare => {
                if let Some(request) =
                    self.analysis
                        .inputs(ui, self.task == Task::Compare, &self.device)
                {
                    let control = self.analysis.control.clone();
                    self.start_job(
                        ctx,
                        if self.task == Task::Compare {
                            "Compare"
                        } else {
                            "Inspect"
                        },
                        String::new(),
                        Job::Analysis { request, control },
                    );
                }
            }
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
                    let filename = if dump {
                        "dump.bin"
                    } else if self.device_label().to_ascii_uppercase().contains("PIONEER") {
                        "backup.tar"
                    } else {
                        "backup.bin"
                    };
                    if let Some(out) = rfd::FileDialog::new().set_file_name(filename).save_file() {
                        // The native save dialog already confirms replacement.
                        let replace = out.symlink_metadata().is_ok();
                        let job = if dump {
                            Job::Dump { out, replace }
                        } else {
                            Job::Backup { out, replace }
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
                let mut choose_file = false;
                if let Some(input) = self.input.clone() {
                    ui.horizontal(|ui| {
                        if ui.button("Change file…").clicked() {
                            choose_file = true;
                        }
                        ui.add(
                            egui::Label::new(
                                input.file_name().unwrap_or_default().to_string_lossy(),
                            )
                            .truncate(),
                        )
                        .on_hover_text(input.display().to_string());
                    });
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if primary(ui, "Flash now", selected).clicked() {
                            self.choose_flash(ctx, true);
                        }
                        if ui.link("Check file").clicked() {
                            self.start_job(
                                ctx,
                                "Check file",
                                String::new(),
                                Job::InfoFile { input },
                            );
                        }
                    });
                    ui.add_space(8.0);
                    ui.checkbox(&mut self.options.force, "Force flash")
                        .on_hover_text(
                        "Override compatibility checks and proceed if a backup cannot be saved.",
                    );
                } else {
                    choose_file = primary(ui, "Choose firmware…", true).clicked();
                }
                if choose_file {
                    if let Some(input) = rfd::FileDialog::new()
                        .add_filter("Firmware or backup", &["bin", "enc", "tar"])
                        .pick_file()
                    {
                        self.input = Some(input);
                    }
                }
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
                                                drive.display(),
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
                                    self.discover();
                                }
                            });
                        });
                    ui.add_space(18.0);
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.task, Task::Info, "Drive info");
                        ui.selectable_value(&mut self.task, Task::Inspect, "Inspect");
                        ui.selectable_value(&mut self.task, Task::Compare, "Compare");
                        ui.selectable_value(&mut self.task, Task::Backup, "Backup");
                        ui.selectable_value(&mut self.task, Task::Dump, "Dump");
                        ui.selectable_value(&mut self.task, Task::Flash, "Flash firmware");
                    });
                    ui.separator();
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .id_salt(("task_content", self.task as u8))
                        .max_height(match self.task {
                            Task::Info => 60.0,
                            Task::Inspect | Task::Compare => 180.0,
                            Task::Backup | Task::Dump => 110.0,
                            Task::Flash => 200.0,
                        })
                        .min_scrolled_height(match self.task {
                            Task::Info => 60.0,
                            Task::Inspect | Task::Compare => 0.0,
                            Task::Backup | Task::Dump => 110.0,
                            Task::Flash => 200.0,
                        })
                        .auto_shrink([false, matches!(self.task, Task::Inspect | Task::Compare)])
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
                if matches!(self.task, Task::Inspect | Task::Compare)
                    && ui.button("Cancel analysis").clicked()
                {
                    self.analysis.control.cancel();
                    self.status = "Cancelling after the current operation returns…".into();
                }
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
                    if matches!(self.task, Task::Inspect | Task::Compare) {
                        if let Some(inspect) = self.analysis.results(ui) {
                            self.task = if inspect {
                                Task::Inspect
                            } else {
                                Task::Compare
                            };
                            self.result_task = self.task;
                        }
                    }
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
                        if ui.button("Save diagnostic log…").clicked() {
                            self.save_diagnostic_log();
                        }
                    }
                    if let Some(notice) = &self.diagnostic_notice {
                        ui.label(notice);
                    }
                    ui.add_space(6.0);
                    if ui.button("View diagnostic log…").clicked() {
                        self.details_open = true;
                        self.diagnostic_checked = None;
                        self.diagnostic_notice = None;
                    }
                });
        });
        self.flash_confirm_dialog(&ctx);
        if self.details_open {
            let refresh_interval = std::time::Duration::from_millis(500);
            if self
                .diagnostic_checked
                .is_none_or(|checked| self.running && checked.elapsed() >= refresh_interval)
            {
                self.refresh_diagnostic_view();
            }
            if self.running {
                ctx.request_repaint_after(refresh_interval);
            }
            let mut open = true;
            let mut close = false;
            egui::Window::new("Diagnostic log")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(egui::vec2(620.0, 400.0))
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(&ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Copy diagnostic log").clicked() {
                            match self.diagnostic_text() {
                                Ok(text) => ctx.copy_text(text),
                                Err(error) => {
                                    self.diagnostic_notice =
                                        Some(format!("Could not read diagnostic log: {error}"))
                                }
                            }
                        }
                        if ui.button("Save diagnostic log…").clicked() {
                            self.save_diagnostic_log();
                        }
                        if ui.button("Close").clicked() {
                            close = true;
                        }
                    });
                    ui.label("Attach this log to your bug report.");
                    if let Some(notice) = &self.diagnostic_notice {
                        ui.label(notice);
                    }
                    ui.separator();
                    egui::ScrollArea::both()
                        .id_salt("diagnostic_text")
                        .scroll_bar_visibility(
                            egui::scroll_area::ScrollBarVisibility::AlwaysVisible,
                        )
                        .max_height(310.0)
                        .auto_shrink([false, false])
                        .show_rows(ui, 14.0, self.diagnostic_lines.len(), |ui, rows| {
                            for line in &self.diagnostic_lines[rows] {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(line).monospace().size(12.0),
                                    )
                                    .extend(),
                                );
                            }
                        });
                });
            self.details_open = open && !close;
        }
    }
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
