//! Build script: embed the freemkv icon and the application manifest into the Windows
//! executable.
//!
//! This runs only when the *host* toolchain is Windows (CI or a native Windows
//! build), which is where `winresource` can invoke the resource compiler. On
//! macOS/Linux the block is `cfg`-compiled out and the script is a no-op, so the
//! workspace still builds cleanly everywhere. The macOS `.app` icon is wired via
//! the bundle's `Info.plist` + `freemkv.icns` at packaging time (see README).
//!
//! The manifest is what makes the Win32 shell look native, as in freemkv: Common
//! Controls v6 (themed controls, not Windows 95 grey) and PerMonitorV2 DPI awareness
//! (sharp text on HiDPI). The icon is resource id 1, which `windows.rs` loads.
fn main() {
    println!("cargo:rerun-if-changed=assets/freemkv.ico");
    println!("cargo:rerun-if-changed=assets/freemkv-flash-gui.manifest");
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/freemkv.ico");
        res.set_manifest_file("assets/freemkv-flash-gui.manifest");
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed Windows resources: {e}");
        }
    }
}
