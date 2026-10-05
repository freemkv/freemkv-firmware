//! Cross-platform desktop interface to the shared freemkv-flash workflows.
//! Drive discovery, operations, safety policy and progress match the CLI.

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
        .with_title("freemkv Firmware Utility")
        .with_inner_size([720.0, 610.0])
        .with_resizable(false);
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
        Box::new(|cc| {
            cc.egui_ctx.set_theme(egui::Theme::Light);
            cc.egui_ctx.style_mut_of(egui::Theme::Light, |style| {
                style.spacing.item_spacing = egui::vec2(10.0, 8.0);
                style.spacing.button_padding = egui::vec2(12.0, 7.0);
                style
                    .text_styles
                    .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
                style
                    .text_styles
                    .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
            });
            Ok(Box::new(app::FlashApp::new()))
        }),
    )
}
