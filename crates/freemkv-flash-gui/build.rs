//! Build script: embed the freemkv icon into the Windows executable.
//!
//! This runs only when the *host* toolchain is Windows (CI or a native Windows
//! build), which is where `winresource` can invoke the resource compiler. On
//! macOS/Linux the block is `cfg`-compiled out and the script is a no-op, so the
//! workspace still builds cleanly everywhere. The macOS `.app` icon is wired via
//! the bundle's `Info.plist` + `freemkv.icns` at packaging time (see README).
fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/freemkv.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed Windows icon: {e}");
        }
    }
}
