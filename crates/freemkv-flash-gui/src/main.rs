//! Desktop interface to the shared freemkv-flash workflows.
//!
//! `ui` is the platform-neutral model; each shell only draws its view and forwards input.
//! macOS runs the native AppKit shell (`mac`), Windows the Win32 shell (`windows`) and glibc
//! Linux the GTK4 shell (`linux`); any other target, and `--egui` anywhere, runs the egui
//! shell over the same model.

// On Windows, don't spawn a console window alongside the GUI in release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod egui_shell;
#[cfg(all(feature = "native", target_os = "linux", target_env = "gnu"))]
mod linux;
#[cfg(all(feature = "native", target_os = "macos"))]
mod mac;
mod ops;
mod ui;
// Toolkit-free and built everywhere so its tests run on every host; only Windows uses it.
#[cfg_attr(not(all(feature = "native", target_os = "windows")), allow(dead_code))]
mod win_layout;
#[cfg(all(feature = "native", target_os = "windows"))]
mod windows;

fn main() -> eframe::Result<()> {
    #[cfg(all(feature = "native", target_os = "macos"))]
    if !std::env::args().any(|a| a == "--egui") {
        mac::run();
        return Ok(());
    }
    #[cfg(all(feature = "native", target_os = "windows"))]
    if !std::env::args().any(|a| a == "--egui") {
        windows::run();
        return Ok(());
    }
    // GTK's status is the process's: a failed GTK/libadwaita start must not exit 0.
    #[cfg(all(feature = "native", target_os = "linux", target_env = "gnu"))]
    if !std::env::args().any(|a| a == "--egui") {
        let code = linux::run();
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    egui_shell::run()
}
