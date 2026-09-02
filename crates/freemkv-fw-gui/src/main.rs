//! `freemkv-fw-gui` — a minimal desktop UI for `freemkv-fw`.
//!
//! One window over the firmware-authoring engine: create freemkv firmware from
//! an OEM image, verify an image's integrity tables, re-sign an image, and probe
//! a live drive for freemkv firmware. All of it calls the `freemkv_fw`
//! *library* (`freemkv_fw::api`) directly — nothing shells out to the CLI.
//!
//! Drawn with **eframe/egui** (pure-Rust, cross-platform, no system webview);
//! one code path draws on macOS, Windows and Linux alike.

// On Windows, don't spawn a console window alongside the GUI in release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;

use eframe::egui;

/// Decode the bundled freemkv PNG into an egui window icon.
fn load_icon() -> Option<egui::IconData> {
    let bytes = include_bytes!("../assets/freemkv.png");
    let img = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("freemkv-fw")
        .with_inner_size([760.0, 600.0])
        .with_min_inner_size([560.0, 420.0]);
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "freemkv-fw",
        native_options,
        Box::new(|_cc| Ok(Box::new(app::FwApp::new()))),
    )
}
