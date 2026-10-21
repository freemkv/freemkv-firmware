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
        .with_title(freemkv_flash::localization::get(
            freemkv_flash::localization::Preferences::user().load(),
            "modify.window_title",
        ))
        .with_inner_size([720.0, 800.0])
        .with_min_inner_size([720.0, 800.0])
        .with_resizable(true);
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
        Box::new(|cc| {
            configure_style(&cc.egui_ctx);
            Ok(Box::new(app::FwApp::new()))
        }),
    )
}

fn configure_style(ctx: &egui::Context) {
    static FONTS: std::sync::OnceLock<egui::FontDefinitions> = std::sync::OnceLock::new();
    ctx.set_fonts(
        FONTS
            .get_or_init(|| {
                let mut fonts = egui::FontDefinitions::default();
                #[cfg(target_os = "macos")]
                let candidates: Vec<std::path::PathBuf> = [
                    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
                    "/System/Library/Fonts/AppleSDGothicNeo.ttc",
                    "/System/Library/Fonts/Hiragino Sans GB.ttc",
                ]
                .into_iter()
                .map(Into::into)
                .collect();
                #[cfg(target_os = "windows")]
                let candidates: Vec<std::path::PathBuf> = {
                    let directory = std::env::var_os("WINDIR")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
                        .join("Fonts");
                    ["msyh.ttc", "malgun.ttf", "YuGothR.ttc"]
                        .into_iter()
                        .map(|name| directory.join(name))
                        .collect()
                };
                #[cfg(not(any(target_os = "macos", target_os = "windows")))]
                let candidates: Vec<std::path::PathBuf> = [
                    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                    "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
                    "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
                ]
                .into_iter()
                .map(Into::into)
                .collect();
                for (index, path) in candidates.into_iter().enumerate() {
                    if let Ok(data) = std::fs::read(path) {
                        let name = format!("system-unicode-{index}");
                        fonts.font_data.insert(
                            name.clone(),
                            std::sync::Arc::new(egui::FontData::from_owned(data)),
                        );
                        for family in fonts.families.values_mut() {
                            family.push(name.clone());
                        }
                    }
                }
                fonts
            })
            .clone(),
    );

    ctx.set_theme(egui::Theme::Light);
    ctx.style_mut_of(egui::Theme::Light, |style| {
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    });
}
