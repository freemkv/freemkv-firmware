//! Firmware authoring sibling of the flasher, sharing its visual and diagnostic conventions.

use crate::ops::{self, Job};
use eframe::egui;
use freemkv_flash::localization::{self, Language, Preferences};
use freemkv_flash::workflow::DriveChoice;
use freemkv_fw::boot::{BootFeature, BootSettings, BootSupport};
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

type BootPreview = Result<(BootSettings, BootSupport), String>;

pub struct FwApp {
    language: Language,
    preferences: Preferences,
    boot_settings: BootSettings,
    boot_support: Option<BootSupport>,
    boot_input: Option<PathBuf>,
    boot_rx: Option<Receiver<BootPreview>>,
    boot_error: Option<String>,
    boot_dirty: bool,
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
                Ok(()) => localization::message(
                    "notice.log_saved",
                    &[("path", path.display().to_string())],
                ),
                Err(error) => {
                    self.log
                        .push(format!("Could not export diagnostic log: {error:#}"));
                    "errors.save_report".into()
                }
            });
        }
    }

    pub fn new() -> Self {
        Self::with_preferences(Preferences::user())
    }

    fn with_preferences(preferences: Preferences) -> Self {
        Self {
            language: preferences.load(),
            preferences,
            boot_settings: BootSettings::standard(),
            boot_support: None,
            boot_input: None,
            boot_rx: None,
            boot_error: None,
            boot_dirty: false,
            task: Task::Verify,
            result_task: Task::Verify,
            input: None,
            status: "status.ready".into(),
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
            if let freemkv_flash::output::Event::Report(report) = event {
                for (label, value) in report.gui_fields() {
                    if label == "Diagnostic log" {
                        self.diagnostic_log = Some(value.into());
                    }
                }
            }
        }
    }

    fn choose_image(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter(
                localization::get(self.language, "modify.firmware_image"),
                &["bin", "tar"],
            )
            .pick_file()
        {
            self.select_image(path);
        }
    }

    fn select_image(&mut self, path: PathBuf) {
        self.input = Some(path);
        self.boot_input = None;
        self.boot_rx = None;
        self.boot_support = None;
        self.boot_error = None;
        self.boot_settings = BootSettings::standard();
        self.boot_dirty = false;
        self.fields.clear();
        self.failure = None;
        self.status = "status.ready".into();
    }

    fn start_job(&mut self, ctx: &egui::Context, label: &str, job: Job) {
        if self.running {
            return;
        }
        self.result_task = self.task;
        self.running = true;
        self.action = label.to_string();
        self.status =
            localization::message("status.operation_running", &[("operation", label.into())]);
        self.failure = None;
        self.log.clear();
        self.diagnostic_log = None;
        self.diagnostic_checked = None;
        self.diagnostic_notice = None;
        self.progress = None;
        self.fields.clear();
        self.log.push(localization::english(label));
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
                Ok(result) => result.map_err(|e| freemkv_flash::workflow::user_error(&e).encoded()),
                Err(_) => Err("errors.worker".into()),
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
                        freemkv_flash::output::Event::DeviceSettings(_) => {}
                        freemkv_flash::output::Event::Message(line) => self.log.push(line),
                        freemkv_flash::output::Event::Progress { label, done, total } => {
                            self.progress = Some((label, done, total))
                        }
                        freemkv_flash::output::Event::Report(report) => {
                            for (label, value) in report.gui_fields() {
                                if label == "Diagnostic log" {
                                    self.diagnostic_log = Some(value.clone().into());
                                }
                                self.fields.push((label, value))
                            }
                        }
                    },
                    Ok(Msg::Done(result)) => {
                        match &result {
                            Ok(()) => {
                                self.status = localization::message(
                                    "status.operation_complete",
                                    &[("operation", self.action.clone())],
                                )
                            }
                            Err(error) => {
                                self.status = localization::message(
                                    "status.operation_failed",
                                    &[("operation", self.action.clone())],
                                );
                                self.failure = Some(error.clone());
                            }
                        }
                        self.log.push(match result {
                            Ok(()) => "✓ done.".into(),
                            Err(e) => format!("✗ error: {}", localization::english(&e)),
                        });
                        finished = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.status = "status.interrupted".into();
                        self.failure = Some("errors.worker".into());
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

    fn boot_preview(&mut self, ctx: &egui::Context) {
        if self.boot_input != self.input {
            self.boot_input = self.input.clone();
            self.boot_settings = BootSettings::standard();
            self.boot_dirty = false;
            self.boot_support = None;
            self.boot_error = None;
            self.boot_rx = None;
            if let Some(path) = self.input.clone() {
                let (tx, rx) = mpsc::channel();
                self.boot_rx = Some(rx);
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    let result = std::panic::catch_unwind(|| -> anyhow::Result<_> {
                        let artifact = freemkv_fw::artifact::Artifact::parse(std::fs::read(path)?)?;
                        freemkv_fw::api::boot_options(artifact.image())
                    })
                    .map_err(|_| "errors.analysis".to_string())
                    .and_then(|result| {
                        result.map_err(|e| freemkv_flash::workflow::user_error(&e).encoded())
                    });
                    let _ = tx.send(result);
                    ctx.request_repaint();
                });
            }
        }
        if let Some(rx) = &self.boot_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.boot_rx = None;
                    match result {
                        Ok((settings, support)) => {
                            if !self.boot_dirty {
                                self.boot_settings = settings;
                            }
                            self.boot_support = Some(support);
                        }
                        Err(error) => self.boot_error = Some(error),
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    self.boot_rx = None;
                    self.boot_error = Some("errors.analysis".into());
                }
                Err(TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(100));
                }
            }
        }
    }

    fn reset_boot_settings(&mut self) {
        self.boot_settings = BootSettings::standard();
        self.boot_dirty = true;
    }

    fn boot_form(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new(localization::get(self.language, "modify.boot_settings")).strong(),
        );
        ui.small(localization::get(
            self.language,
            "modify.applied_each_time_the_drive_starts",
        ));
        egui::Grid::new("boot_settings")
            .num_columns(2)
            .spacing([16.0, 5.0])
            .show(ui, |ui| {
                for feature in BootFeature::ALL {
                    ui.label(localization::render(self.language, feature.label()));
                    let supported = self
                        .boot_support
                        .as_ref()
                        .is_some_and(|s| s.supports(feature));
                    let value = self.boot_settings.value(feature);
                    let mut selected = value;
                    ui.add_enabled_ui(supported, |ui| {
                        egui::ComboBox::from_id_salt(("boot", feature.key()))
                            .width(220.0)
                            .selected_text(localization::render(self.language, if self.boot_support.is_some() && !supported {
                                "modify.not_supported"
                            } else {
                                self.boot_settings.label(feature)
                            }))
                            .show_ui(ui, |ui| {
                                for &(key, label, _) in feature.choices() {
                                    ui.selectable_value(&mut selected, key, localization::render(self.language, label));
                                }
                            })
                            .response
                            .on_hover_text(if supported {
                                localization::get(self.language, "modify.firmware_startup_setting")
                            } else {
                                localization::get(self.language, "modify.not_supported_by_the_selected_firmware_or_analysis_is_p")
                            });
                    });
                    if selected != value {
                        self.boot_settings
                            .set(feature, selected)
                            .expect("validated form choice");
                        self.boot_dirty = true;
                    }
                    ui.end_row();
                }
            });
        if ui
            .button(localization::get(self.language, "modify.reset_to_defaults"))
            .clicked()
        {
            self.reset_boot_settings();
        }
        if self.boot_rx.is_some() {
            ui.small(localization::get(
                self.language,
                "modify.checking_firmware_support",
            ));
        }
        if let Some(error) = &self.boot_error {
            ui.colored_label(
                egui::Color32::DARK_RED,
                localization::render(self.language, error),
            );
        }
        if let Some(support) = &self.boot_support {
            if !support.has_boot() {
                ui.colored_label(
                    egui::Color32::DARK_RED,
                    localization::get(
                        self.language,
                        "modify.this_firmware_cannot_apply_boot_settings",
                    ),
                );
            }
            if let Err(_error) = self.boot_settings.validate(support) {
                ui.colored_label(
                    egui::Color32::DARK_RED,
                    localization::get(self.language, "errors.boot_settings"),
                );
            }
        }
    }

    fn task_content(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        match self.task {
            Task::Probe => {
                ui.label(localization::get(
                    self.language,
                    "modify.check_whether_the_selected_drive_runs_freemkv_firmware",
                ));
                if primary(
                    ui,
                    localization::get(self.language, "action.read_info"),
                    !self.device.is_empty(),
                )
                .clicked()
                {
                    self.start_job(
                        ctx,
                        "modify.drive_information",
                        Job::Probe(self.device.clone()),
                    );
                }
            }
            Task::Verify => {
                ui.label(localization::get(
                    self.language,
                    "modify.check_the_firmware_image_s_integrity_before_using_it",
                ));
                if primary(
                    ui,
                    localization::get(self.language, "modify.verify_firmware"),
                    self.input.is_some(),
                )
                .clicked()
                {
                    self.start_job(
                        ctx,
                        "modify.firmware_verification",
                        Job::Verify(self.input.clone().unwrap()),
                    );
                }
            }
            Task::Create | Task::Sign => {
                let create = self.task == Task::Create;
                ui.label(if create {
                    localization::get(
                        self.language,
                        "modify.build_freemkv_firmware_from_an_oem_image_then_sign_and_",
                    )
                } else {
                    localization::get(
                        self.language,
                        "modify.recompute_the_firmware_image_s_integrity_signatures",
                    )
                });
                if create {
                    self.boot_preview(ctx);
                    self.boot_form(ui);
                }
                ui.add_space(8.0);
                if primary(
                    ui,
                    if create {
                        localization::get(self.language, "modify.create_firmware")
                    } else {
                        localization::get(self.language, "modify.save_signed_firmware")
                    },
                    self.input.is_some()
                        && (!create
                            || self.boot_support.as_ref().is_some_and(|s| {
                                s.has_boot() && self.boot_settings.validate(s).is_ok()
                            })),
                )
                .clicked()
                {
                    let input = self.input.clone().unwrap();
                    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
                    let suffix = if create { "freemkv" } else { "signed" };
                    if let Some(output) = rfd::FileDialog::new()
                        .set_file_name(format!(
                            "{stem}.{suffix}.{}",
                            input.extension().and_then(|e| e.to_str()).unwrap_or("bin")
                        ))
                        .add_filter(
                            localization::get(self.language, "modify.firmware_image"),
                            &["bin", "tar"],
                        )
                        .save_file()
                    {
                        let job = if create {
                            Job::Create {
                                input,
                                output,
                                defaults: self.boot_settings.clone(),
                            }
                        } else {
                            Job::Sign { input, output }
                        };
                        self.start_job(
                            ctx,
                            if create {
                                "modify.firmware_creation"
                            } else {
                                "modify.firmware_signing"
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
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(localization::text(
            self.language,
            "modify.window_title",
        )));
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
                ui.label(localization::get(self.language, "modify.firmware_modifier"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(env!("CARGO_PKG_VERSION"));
                    let previous = self.language;
                    egui::ComboBox::from_id_salt("firmware_language")
                        .selected_text(self.language.native_name())
                        .show_ui(ui, |ui| {
                            for language in Language::ALL {
                                ui.selectable_value(&mut self.language, language, language.native_name());
                            }
                        });
                    if self.language != previous {
                        if let Err(error) = self.preferences.save(self.language) {
                            self.log.push(format!("Could not save language preference: {error}"));
                            self.diagnostic_notice = Some("errors.language_save".into());
                        }
                    }
                });
            });
            ui.add_space(18.0);
            ui.add_enabled_ui(!self.running && !self.details_open, |ui| {
                egui::Frame::group(ui.style())
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if self.task == Task::Probe {
                            ui.label(egui::RichText::new(localization::get(self.language, "drive.label")).strong());
                            ui.horizontal(|ui| {
                                let label = self
                                    .devices
                                    .iter()
                                    .find(|d| d.path == self.device)
                                    .map(|d| d.display())
                                    .unwrap_or_else(|| {
                                        localization::get(self.language, "modify.select_refresh_to_find_optical_drives").into()
                                    });
                                egui::ComboBox::from_id_salt("device_combo")
                                    .selected_text(label)
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
                                if ui.button(localization::get(self.language, "action.refresh")).clicked() {
                                    self.discover();
                                }
                            });
                        } else {
                            ui.label(egui::RichText::new(localization::get(self.language, "modify.firmware_image")).strong());
                            ui.horizontal(|ui| {
                                if ui
                                    .button(if self.input.is_some() {
                                        localization::get(self.language, "action.change_file")
                                    } else {
                                        localization::get(self.language, "action.choose_firmware")
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
                                    ui.weak(localization::get(self.language, "modify.no_firmware_image_selected"));
                                }
                            });
                        }
                    });
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.task, Task::Verify, localization::get(self.language, "modify.verify_firmware"));
                    ui.selectable_value(&mut self.task, Task::Create, localization::get(self.language, "modify.create_firmware_e1bf99"));
                    ui.selectable_value(&mut self.task, Task::Probe, localization::get(self.language, "task.info"));
                    ui.menu_button(if self.task == Task::Sign { localization::get(self.language, "modify.advanced_sign") } else { localization::get(self.language, "modify.advanced") }, |ui| {
                        if ui.selectable_label(self.task == Task::Sign, localization::get(self.language, "modify.sign_firmware")).on_hover_text(localization::get(self.language, "modify.re_sign_a_manually_edited_image_create_already_signs_an")).clicked() {
                            self.task = Task::Sign;
                            ui.close();
                        }
                    });
                });
                ui.separator();
                ui.add_space(18.0);
                egui::ScrollArea::vertical()
                    .id_salt(("task_content", self.task as u8))
                    .max_height(if self.task == Task::Create { 370.0 } else { 110.0 })
                    .min_scrolled_height(if self.task == Task::Create { 370.0 } else { 110.0 })
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
                ui.label(egui::RichText::new(localization::render(self.language, &self.status)).strong());
            });
            if self.running {
                if let Some((label, done, total)) = &self.progress {
                    ui.label(localization::render(self.language, label));
                    ui.add(
                        egui::ProgressBar::new(*done as f32 / (*total).max(1) as f32)
                            .show_percentage(),
                    );
                } else {
                    ui.add(egui::ProgressBar::new(0.0).animate(true).text(localization::get(self.language, "modify.preparing")));
                }
                ui.small(localization::get(self.language, "modify.the_operation_is_running_keep_this_window_open_until_it"));
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
                                    ui.label(localization::render(self.language, label));
                                    ui.add(egui::Label::new(localization::render(self.language, value)).wrap());
                                    ui.end_row();
                                }
                            });
                    }
                    if let Some(error) = &self.failure {
                        ui.colored_label(egui::Color32::from_rgb(160, 45, 35), localization::render(self.language, error));
                        if ui.button(localization::get(self.language, "ui.save_diagnostic_log")).clicked() {
                            self.save_diagnostic_log();
                        }
                    }
                    if let Some(notice) = &self.diagnostic_notice {
                        ui.label(localization::render(self.language, notice));
                    }
                    ui.add_space(6.0);
                    if ui.button(localization::get(self.language, "modify.view_diagnostic_log")).clicked() {
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
            egui::Window::new(localization::get(self.language, "ui.diagnostic_log"))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(egui::vec2(620.0, 400.0))
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(&ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui
                            .button(localization::get(
                                self.language,
                                "modify.copy_diagnostic_log",
                            ))
                            .clicked()
                        {
                            match self.diagnostic_text() {
                                Ok(text) => ctx.copy_text(text),
                                Err(error) => {
                                    self.diagnostic_notice = Some({
                                        self.log.push(format!(
                                            "Could not read diagnostic log: {error:#}"
                                        ));
                                        "errors.read_log".into()
                                    })
                                }
                            }
                        }
                        if ui
                            .button(localization::get(self.language, "ui.save_diagnostic_log"))
                            .clicked()
                        {
                            self.save_diagnostic_log();
                        }
                        if ui
                            .button(localization::get(self.language, "menu.close"))
                            .clicked()
                        {
                            close = true;
                        }
                    });
                    ui.label(localization::get(
                        self.language,
                        "ui.attach_this_log_to_your_bug_report",
                    ));
                    if let Some(notice) = &self.diagnostic_notice {
                        ui.label(localization::render(self.language, notice));
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
