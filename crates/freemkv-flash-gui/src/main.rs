//! `freemkv-flash-gui` — a genuinely minimal desktop UI for `freemkv-flash`.
//!
//! One window: a drive picker (with Refresh), a read-only Info action, a safe
//! Dump action, and a guarded Flash action, plus a scrolling log pane that
//! streams the operation's output. The heavy lifting is the `freemkv_flash`
//! *library* (`engine::{info, dump_everything, flash}`, called through
//! [`ops`]); this crate only draws widgets and marshals a background worker's
//! output onto the UI thread.
//!
//! The UI is drawn with **eframe/egui** — a pure-Rust, immediate-mode toolkit
//! that is trivially cross-platform (macOS + Windows + Linux) with no system
//! webview. There is no per-OS shell code: one code path draws everywhere.

// On Windows, don't spawn a console window alongside the GUI in release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod ops;

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
        .with_title("freemkv-flash")
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
        "freemkv-flash",
        native_options,
        Box::new(|_cc| Ok(Box::new(app::FlashApp::new()))),
    )
}
