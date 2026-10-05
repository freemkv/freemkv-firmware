//! Firmware authoring sibling of the flasher, sharing its visual and diagnostic conventions.

use crate::ops::{self, Job};
use eframe::egui;
use freemkv_flash::workflow::DriveChoice;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};

enum Msg {
    Event(freemkv_flash::output::Event),
    Done(Result<(), String>),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Task {
    Verify,
    Create,
    Sign,
    Probe,
}

pub struct FwApp {
    task: Task,
    result_task: Task,
    input: Option<PathBuf>,
    status: String,
    failure: Option<String>,
    action: String,
    devices: Vec<DriveChoice>,
    device: String,
    details_open: bool,
    log: Vec<String>,
    diagnostic_log: Option<PathBuf>,
    diagnostic_lines: Vec<String>,
    diagnostic_checked: Option<std::time::Instant>,
    diagnostic_notice: Option<String>,
    progress: Option<(String, usize, usize)>,
    fields: Vec<(String, String)>,
    running: bool,
    rx: Option<Receiver<Msg>>,
}

impl FwApp {
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
            .set_file_name("freemkv-fw-diagnostic.log")
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
        Self {
            task: Task::Verify,
            result_task: Task::Verify,
            input: None,
            status: "Ready".into(),
            failure: None,
            action: String::new(),
            devices: Vec::new(),
            device: String::new(),
            details_open: false,
            log: Vec::new(),
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

    fn discover(&mut self) {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = events.clone();
        self.devices = freemkv_flash::output::capture_events(
            move |event| captured.lock().unwrap().push(event),
            || {
                freemkv_fw::diagnostics::run("GUI discovery", || {
                    Ok(freemkv_flash::workflow::drives())
                })
                .unwrap_or_default()
            },
        );
        if !self.devices.iter().any(|drive| drive.path == self.device) {
            self.device = self
                .devices
                .first()
                .map(|drive| drive.path.clone())
                .unwrap_or_default();
        }
        for event in events.lock().unwrap().drain(..) {
            if let freemkv_flash::output::Event::Field { label, value } = event {
                if label == "Diagnostic log" {
                    self.diagnostic_log = Some(value.into());
                }
            }
        }
    }

    fn choose_image(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Firmware image", &["bin"])
            .pick_file()
        {
            self.input = Some(path);
            self.fields.clear();
            self.failure = None;
            self.status = "Ready".into();
        }
    }

    fn start_job(&mut self, ctx: &egui::Context, label: &str, job: Job) {
        if self.running {
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
        self.log.push(label.to_owned());
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
                    || ops::execute(&job),
                )
            }));
            let result = match result {
                Ok(result) => result.map_err(|e| format!("{e:#}")),
                Err(_) => Err(
                    "Operation worker failed unexpectedly. Inspect the output before using it."
                        .into(),
                ),
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
                        self.failure = Some("The worker stopped before reporting a result. Inspect the output before using it.".into());
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

    fn task_content(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        match self.task {
            Task::Probe => {
                ui.label("Check whether the selected drive runs freemkv firmware.");
                if primary(ui, "Read drive information", !self.device.is_empty()).clicked() {
                    self.start_job(ctx, "Drive information", Job::Probe(self.device.clone()));
                }
            }
            Task::Verify => {
                ui.label("Check the firmware image’s integrity before using it.");
                if primary(ui, "Verify firmware", self.input.is_some()).clicked() {
                    self.start_job(
                        ctx,
                        "Firmware verification",
                        Job::Verify(self.input.clone().unwrap()),
                    );
                }
            }
            Task::Create | Task::Sign => {
                let create = self.task == Task::Create;
                ui.label(if create {
                    "Build freemkv firmware from an OEM image, then sign and verify it."
                } else {
                    "Recompute the firmware image’s integrity signatures."
                });
                ui.add_space(8.0);
                if primary(
                    ui,
                    if create {
                        "Create firmware…"
                    } else {
                        "Save signed firmware…"
                    },
                    self.input.is_some(),
                )
                .clicked()
                {
                    let input = self.input.clone().unwrap();
                    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
                    let suffix = if create { "freemkv" } else { "signed" };
                    if let Some(output) = rfd::FileDialog::new()
                        .set_file_name(format!("{stem}.{suffix}.bin"))
                        .add_filter("Firmware image", &["bin"])
                        .save_file()
                    {
                        let job = if create {
                            Job::Create { input, output }
                        } else {
                            Job::Sign { input, output }
                        };
                        self.start_job(
                            ctx,
                            if create {
                                "Firmware creation"
                            } else {
                                "Firmware signing"
                            },
                            job,
                        );
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

impl eframe::App for FwApp {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

impl FwApp {
    fn render(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.pump();
        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
            if ctx.input(|i| i.viewport().close_requested()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
        }
        egui::Frame::new().inner_margin(16.0).show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.heading("freemkv");
                ui.label("Firmware Modifier");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(env!("CARGO_PKG_VERSION"));
                });
            });
            ui.add_space(18.0);
            ui.add_enabled_ui(!self.running && !self.details_open, |ui| {
                egui::Frame::group(ui.style())
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if self.task == Task::Probe {
                            ui.label(egui::RichText::new("Optical drive").strong());
                            ui.horizontal(|ui| {
                                let label = self
                                    .devices
                                    .iter()
                                    .find(|d| d.path == self.device)
                                    .map(|d| d.label.clone())
                                    .unwrap_or_else(|| {
                                        "Select Refresh to find optical drives".into()
                                    });
                                egui::ComboBox::from_id_salt("device_combo")
                                    .selected_text(label)
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
                                if ui.button("Refresh").clicked() {
                                    self.discover();
                                }
                            });
                        } else {
                            ui.label(egui::RichText::new("Firmware image").strong());
                            ui.horizontal(|ui| {
                                if ui
                                    .button(if self.input.is_some() {
                                        "Change file…"
                                    } else {
                                        "Choose firmware…"
                                    })
                                    .clicked()
                                {
                                    self.choose_image();
                                }
                                if let Some(input) = &self.input {
                                    ui.add(
                                        egui::Label::new(
                                            input.file_name().unwrap_or_default().to_string_lossy(),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(input.display().to_string());
                                } else {
                                    ui.weak("No firmware image selected");
                                }
                            });
                        }
                    });
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.task, Task::Verify, "Verify firmware");
                    ui.selectable_value(&mut self.task, Task::Create, "Create firmware");
                    ui.selectable_value(&mut self.task, Task::Probe, "Drive info");
                    ui.menu_button(if self.task == Task::Sign { "Advanced: Sign" } else { "Advanced" }, |ui| {
                        if ui.selectable_label(self.task == Task::Sign, "Sign firmware").on_hover_text("Re-sign a manually edited image. Create already signs and verifies automatically.").clicked() {
                            self.task = Task::Sign;
                            ui.close();
                        }
                    });
                });
                ui.separator();
                ui.add_space(18.0);
                egui::ScrollArea::vertical()
                    .id_salt(("task_content", self.task as u8))
                    .max_height(110.0)
                    .min_scrolled_height(110.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        self.task_content(ui, &ctx);
                    });
            });
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
                ui.small("The operation is running. Keep this window open until it finishes.");
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
mod tests {
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
}
