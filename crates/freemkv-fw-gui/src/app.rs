//! The egui front-end for freemkv-fw: create / verify / sign / probe.
//!
//! Every action calls a `freemkv_fw::api` wrapper and renders the typed outcome
//! into the log pane. The file operations are fast (CMAC over a ~2 MiB image),
//! so they run inline on the UI thread; the device probe opens read-only.

use std::path::{Path, PathBuf};

use eframe::egui;
use freemkv_fw::api;

/// Application state.
pub struct FwApp {
    /// The firmware image the file operations act on.
    image_path: Option<PathBuf>,
    /// The device path the probe acts on.
    device: String,
    /// Rolling log pane contents.
    log: Vec<String>,
}

/// Short hex preview of a digest (first 4 bytes) for compact tables.
fn short_hex(d: &[u8; 16]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

/// `<stem>.<suffix>.bin` next to `input`.
fn default_out(input: &Path, suffix: &str) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".to_string());
    input.with_file_name(format!("{stem}.{suffix}.bin"))
}

impl FwApp {
    /// Build the app with an empty log.
    pub fn new() -> Self {
        Self {
            image_path: None,
            device: default_device(),
            log: vec!["Ready. Open a firmware image to create / verify / sign.".to_string()],
        }
    }

    /// Append a line to the log pane.
    fn push(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
    }

    fn do_verify(&mut self) {
        let Some(path) = self.image_path.clone() else {
            return;
        };
        self.push(format!("── verify: {} ──", path.display()));
        let image = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                self.push(format!("✗ error: reading {}: {e}", path.display()));
                return;
            }
        };
        match api::verify(&image, None) {
            Ok(out) => {
                self.push(format!("scheme: {}", out.scheme));
                self.push(format!(
                    "{:>3}  {:<21}  {:>9}  {:<8}  {:<8}  {:<8}",
                    "idx", "range", "size", "status", "stored", "computed"
                ));
                for v in &out.verdicts {
                    let size = (v.end as u64).saturating_sub(v.start as u64) + 1;
                    self.log.push(format!(
                        "{:>3}  {:<21}  {:>9}  {:<8}  {:<8}  {:<8}",
                        v.index,
                        format!("0x{:x}-0x{:x}", v.start, v.end),
                        format!("0x{size:x}"),
                        if v.ok { "MATCH" } else { "MISMATCH" },
                        short_hex(&v.stored),
                        short_hex(&v.computed),
                    ));
                }
                if out.verdicts.is_empty() {
                    self.push("summary: no active regions");
                } else if out.ok {
                    self.push(format!("✓ summary: {} region(s) OK", out.verdicts.len()));
                } else {
                    let bad = out.verdicts.iter().filter(|v| !v.ok).count();
                    self.push(format!(
                        "✗ summary: {bad} of {} region(s) MISMATCH",
                        out.verdicts.len()
                    ));
                }
            }
            Err(e) => self.push(format!("✗ error: {e:#}")),
        }
    }

    fn do_sign(&mut self) {
        let Some(path) = self.image_path.clone() else {
            return;
        };
        let Some(out_path) = rfd::FileDialog::new()
            .set_file_name(
                default_out(&path, "signed")
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("image.signed.bin"),
            )
            .add_filter("firmware image", &["bin"])
            .save_file()
        else {
            return;
        };
        self.push(format!("── sign: {} ──", path.display()));
        let image = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                self.push(format!("✗ error: reading {}: {e}", path.display()));
                return;
            }
        };
        match api::sign(&image, None) {
            Ok(out) => {
                self.push(format!("scheme: {}", out.scheme));
                if out.changes.is_empty() {
                    self.push("image already valid — 0 regions re-signed");
                } else {
                    self.push(format!("re-signed {} region(s):", out.changes.len()));
                    for c in &out.changes {
                        self.log.push(format!(
                            "  [{:>2}] 0x{:x}-0x{:x}  {} -> {}",
                            c.index,
                            c.start,
                            c.end,
                            short_hex(&c.before),
                            short_hex(&c.after),
                        ));
                    }
                }
                match std::fs::write(&out_path, &out.image) {
                    Ok(()) => self.push(format!(
                        "✓ wrote {} ({} bytes)",
                        out_path.display(),
                        out.image.len()
                    )),
                    Err(e) => self.push(format!("✗ error: writing {}: {e}", out_path.display())),
                }
            }
            Err(e) => self.push(format!("✗ error: {e:#}")),
        }
    }

    fn do_create(&mut self) {
        let Some(path) = self.image_path.clone() else {
            return;
        };
        let Some(out_path) = rfd::FileDialog::new()
            .set_file_name(
                default_out(&path, "freemkv")
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("image.freemkv.bin"),
            )
            .add_filter("firmware image", &["bin"])
            .save_file()
        else {
            return;
        };
        self.push(format!("── create: {} ──", path.display()));
        let image = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                self.push(format!("✗ error: reading {}: {e}", path.display()));
                return;
            }
        };
        match api::create(&image) {
            Ok(out) => {
                self.push(format!("engine: {}", out.engine));
                if let Some(c) = &out.chip {
                    self.push(format!("chip: {} {} · rev {}", c.vendor, c.model, c.rev));
                }
                self.push(format!(
                    "re-signed {} CMAC region(s) OK",
                    out.verdicts.len()
                ));
                match std::fs::write(&out_path, out.image()) {
                    Ok(()) => self.push(format!(
                        "✓ wrote {} ({} bytes)",
                        out_path.display(),
                        out.image().len()
                    )),
                    Err(e) => self.push(format!("✗ error: writing {}: {e}", out_path.display())),
                }
            }
            Err(e) => self.push(format!("✗ error: {e:#}")),
        }
    }

    fn do_probe(&mut self) {
        if self.device.trim().is_empty() {
            self.push("No device specified.");
            return;
        }
        let device = self.device.clone();
        self.push(format!("── probe: {device} ──"));
        match api::probe_device(&device) {
            Ok(out) => {
                let mark = if out.detected { "✓" } else { "•" };
                self.push(format!("{mark} freemkv firmware: {}", out.detail));
            }
            Err(e) => self.push(format!("✗ error: {e:#}")),
        }
    }
}

/// A conventional default device path per OS (the user can edit it).
fn default_device() -> String {
    #[cfg(target_os = "linux")]
    {
        "/dev/sg1".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "/dev/rdisk0".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "\\\\.\\CdRom0".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        String::new()
    }
}

impl eframe::App for FwApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.add_space(4.0);
        ui.heading("freemkv-fw");
        ui.label("Firmware authoring: create · verify · sign · probe");
        ui.add_space(8.0);

        // ── file operations ────────────────────────────────────────────────
        ui.horizontal(|ui| {
            if ui.button("Open image…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("firmware image", &["bin"])
                    .pick_file()
                {
                    self.image_path = Some(p);
                }
            }
            match &self.image_path {
                Some(p) => ui.label(egui::RichText::new(p.display().to_string()).monospace()),
                None => ui.label(egui::RichText::new("<no image>").italics()),
            };
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let has = self.image_path.is_some();
            if ui
                .add_enabled(has, egui::Button::new("Create"))
                .on_hover_text("Build freemkv firmware from this OEM image")
                .clicked()
            {
                self.do_create();
            }
            if ui
                .add_enabled(has, egui::Button::new("Verify"))
                .on_hover_text("Check the integrity table(s) (read-only)")
                .clicked()
            {
                self.do_verify();
            }
            if ui
                .add_enabled(has, egui::Button::new("Sign"))
                .on_hover_text("Recompute and write back every region's digest")
                .clicked()
            {
                self.do_sign();
            }
        });

        ui.add_space(12.0);
        ui.separator();

        // ── device probe ───────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label("Drive:");
            ui.add(egui::TextEdit::singleline(&mut self.device).desired_width(240.0));
            if ui
                .button("Probe")
                .on_hover_text("Ask a live drive whether it runs freemkv firmware (read-only)")
                .clicked()
            {
                self.do_probe();
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Log");
            if ui.button("Clear").clicked() {
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
    }
}
