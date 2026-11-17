//! `freemkv-crossflash <dir>`: print admitted and known future crossflashes between
//! the firmware packages in `<dir>`, as JSON.
//!
//! Input is a content-addressed package tree (`pioneer/<sha256>.tar`,
//! `mediatek/<sha256>.tar`). Each package stands in
//! for a drive running it; a link `installed -> target` means `flash` would
//! admit `target` on that drive (see `freemkv_flash::crossflash`).
//!
//! `freemkv-crossflash --why <installed> <target>` prints the flasher's verdict
//! for one pair (refusal reason, or "admitted").

use anyhow::Result;

// The catalogue scan allocates and frees image-sized buffers on every worker;
// the macOS system allocator serializes on them, and musl maps and unmaps
// every one (a page fault per page: a third of the scan was kernel time).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
    match freemkv_flash::user_error::read_only(freemkv_flash::diagnostics::run(
        "crossflash analysis",
        run,
    )) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            freemkv_flash::cli::print_error(&error);
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    println!("{}", freemkv_flash::crossflash::cli(&args)?);
    Ok(())
}
