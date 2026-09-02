//! The egui front-end: widgets + the worker-thread plumbing.
//!
//! All drive access goes through [`crate::ops`]; this module never touches SCSI
//! directly. A job runs on a background thread so the UI stays responsive; the
//! engine's `println!` progress is streamed back line-by-line (on Unix) through
//! an [`std::sync::mpsc`] channel and appended to the log pane.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};

use eframe::egui;

use crate::ops::{self, Job};

/// Messages sent from the worker thread to the UI thread.
enum Msg {
    /// One line of engine output.
    Line(String),
    /// The job finished; `Ok(())` or a formatted error string.
    Done(Result<(), String>),
}

/// Application state.
pub struct FlashApp {
    /// Auto-discovered candidate device paths.
    devices: Vec<String>,
    /// The device the operations act on (editable; the picker fills it in).
    device: String,
    /// Whether the user acknowledged the bricking risk (mirrors the CLI's
    /// `--i-understand-risk`).
    risk_ack: bool,
    /// A flash has been requested and is awaiting the explicit confirm dialog
    /// (mirrors the CLI's `--execute`). Holds the chosen input image.
    pending_flash: Option<PathBuf>,
    /// Rolling log pane contents.
    log: Vec<String>,
    /// A job is in flight — buttons are disabled while true.
    running: bool,
    /// Receiver for the in-flight job's messages, if any.
    rx: Option<Receiver<Msg>>,
}

impl FlashApp {
    /// Build the app, seeding the device list from a first enumeration.
    pub fn new() -> Self {
        let devices = ops::enumerate();
        let device = devices.first().cloned().unwrap_or_default();
        Self {
            devices,
            device,
            risk_ack: false,
            pending_flash: None,
            log: vec!["Ready. Pick a drive and choose an action.".to_string()],
            running: false,
            rx: None,
        }
    }

    /// Append a line to the log pane.
    fn log_line(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
    }

    /// Spawn a worker thread to run `job` against the selected device, streaming
    /// its output back to the UI. `label` names the job in the log header.
    fn start_job(&mut self, ctx: &egui::Context, label: &str, job: Job) {
        if self.running {
            return;
        }
        if self.device.trim().is_empty() {
            self.log_line("No device selected.");
            return;
        }
        self.running = true;
        self.log_line(format!("── {label}: {} ──", self.device));

        let (tx, rx) = mpsc::channel::<Msg>();
        self.rx = Some(rx);
        let device = self.device.clone();
        let ctx = ctx.clone();

        std::thread::spawn(move || {
            let line_tx = tx.clone();
            let line_ctx = ctx.clone();
            let result = ops::capture_lines(
                || ops::execute(&device, &job),
                move |line| {
                    let _ = line_tx.send(Msg::Line(line));
                    line_ctx.request_repaint();
                },
            );
            let _ = tx.send(Msg::Done(result.map_err(|e| format!("{e:#}"))));
            ctx.request_repaint();
        });
    }

    /// Drain any pending worker messages into the log / running state.
    fn pump(&mut self) {
        let mut finished = false;
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Msg::Line(l) => self.log.push(l),
                    Msg::Done(res) => {
                        match res {
                            Ok(()) => self.log.push("✓ done.".to_string()),
                            Err(e) => self.log.push(format!("✗ error: {e}")),
                        }
                        finished = true;
                    }
                }
            }
        }
        if finished {
            self.running = false;
            self.rx = None;
        }
    }

    /// The confirmation dialog for a flash (the explicit "do it for real" gate).
    fn flash_confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(input) = self.pending_flash.clone() else {
            return;
        };
        let mut open = true;
        let mut decision: Option<bool> = None;
        egui::Window::new("Confirm flash")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(format!("Device: {}", self.device));
                ui.label(format!("Image:  {}", input.display()));
                ui.add_space(6.0);
                ui.colored_label(
                    egui::Color32::from_rgb(220, 80, 80),
                    "This writes firmware to the drive and can permanently brick it.\n\
                     A pre-flash backup is saved next to the image first.",
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                    if ui
                        .add(
                            egui::Button::new("Flash now")
                                .fill(egui::Color32::from_rgb(150, 40, 40)),
                        )
                        .clicked()
                    {
                        decision = Some(true);
                    }
                });
            });

        match decision {
            Some(true) => {
                self.pending_flash = None;
                self.start_job(ctx, "flash", Job::Flash { input });
            }
            Some(false) => self.pending_flash = None,
            None => {
                if !open {
                    self.pending_flash = None;
                }
            }
        }
    }
}

impl eframe::App for FlashApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.pump();
        if self.running {
            // Keep polling the channel even if no repaint was requested.
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        ui.add_space(4.0);
        ui.heading("freemkv-flash");
        ui.label("Optical-drive firmware: info · dump · flash");
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Drive:");
            egui::ComboBox::from_id_salt("device_combo")
                .selected_text(if self.device.is_empty() {
                    "<none>".to_string()
                } else {
                    self.device.clone()
                })
                .show_ui(ui, |ui| {
                    for d in &self.devices.clone() {
                        ui.selectable_value(&mut self.device, d.clone(), d);
                    }
                });
            ui.add(egui::TextEdit::singleline(&mut self.device).desired_width(240.0));
            if ui.button("Refresh").clicked() {
                self.devices = ops::enumerate();
                if self.device.is_empty() {
                    self.device = self.devices.first().cloned().unwrap_or_default();
                }
            }
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let enabled = !self.running && !self.device.trim().is_empty();
            if ui
                .add_enabled(enabled, egui::Button::new("Info"))
                .on_hover_text("Identify + classify the drive (read-only)")
                .clicked()
            {
                self.start_job(&ctx, "info", Job::Info);
            }
            if ui
                .add_enabled(enabled, egui::Button::new("Dump…"))
                .on_hover_text("Back up the full image + regions to a .tar")
                .clicked()
            {
                if let Some(out) = rfd::FileDialog::new()
                    .set_file_name("dump.tar")
                    .add_filter("tar archive", &["tar"])
                    .save_file()
                {
                    self.start_job(&ctx, "dump", Job::Dump { out });
                }
            }
            let flash_enabled = enabled && self.risk_ack;
            if ui
                .add_enabled(flash_enabled, egui::Button::new("Flash…"))
                .on_hover_text(if self.risk_ack {
                    "Choose a firmware image to flash"
                } else {
                    "Acknowledge the risk below to enable flashing"
                })
                .clicked()
            {
                if let Some(input) = rfd::FileDialog::new()
                    .add_filter("firmware image", &["bin", "tar"])
                    .pick_file()
                {
                    self.pending_flash = Some(input);
                }
            }
        });

        ui.add_space(4.0);
        ui.checkbox(
            &mut self.risk_ack,
            "I understand flashing can permanently brick the drive",
        );

        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Log");
            if self.running {
                ui.spinner();
                ui.label("working…");
            }
            if ui.button("Clear").clicked() && !self.running {
                self.log.clear();
            }
        });
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.log {
                    ui.label(egui::RichText::new(line).monospace());
                }
            });

        self.flash_confirm_dialog(&ctx);
    }
}
