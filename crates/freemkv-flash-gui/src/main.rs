//! Desktop interface to the shared freemkv-flash workflows.
//!
//! `ui` is the platform-neutral model; each shell only draws its view and forwards input.
//! macOS runs the native AppKit shell (`mac`); every other OS, and `--egui` on macOS, runs
//! the egui shell over the same model.

// On Windows, don't spawn a console window alongside the GUI in release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod egui_shell;
#[cfg(all(feature = "native", target_os = "macos"))]
mod mac;
mod ops;
mod ui;

fn main() -> eframe::Result<()> {
    #[cfg(all(feature = "native", target_os = "macos"))]
    if !std::env::args().any(|a| a == "--egui") {
        mac::run();
        return Ok(());
    }
    egui_shell::run()
}
