//! Platform-independent glue between the egui front-end and the
//! `freemkv_flash` library.
//!
//! The UI (`app.rs`) owns only the widgets and the event loop. Everything that
//! actually talks to a drive lives here: drive enumeration, the three jobs
//! (info / dump / flash), and — on Unix — the stdout capture that streams the
//! engine's `println!` progress into the log pane.

use std::path::{Path, PathBuf};

use freemkv_flash::drive::{self, Family, FlashRequest};
use freemkv_flash::{engine, manifest, platform};

/// Enumerate candidate optical-drive device paths for this OS.
///
/// The `freemkv_flash` library exposes no enumeration API (its `platform::open`
/// takes an explicit path), so this is a best-effort scan of the conventional
/// device nodes. The user picks one; a bad guess simply fails at `open` time.
pub fn enumerate() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        // Generic SCSI pass-through nodes: /dev/sg0, /dev/sg1, …
        collect_dev("sg")
    }
    #[cfg(target_os = "macos")]
    {
        // Optical units surface as raw disk nodes: /dev/rdisk0, /dev/rdisk1, …
        collect_dev("rdisk")
    }
    #[cfg(target_os = "windows")]
    {
        // No cheap enumeration without extra Win32; offer the conventional
        // CD-ROM device namespace as candidates.
        (0..4).map(|n| format!("\\\\.\\CdRom{n}")).collect()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn collect_dev(prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/dev") {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix(prefix) {
                // Keep only the plain "<prefix><n>" nodes (skip partitions like
                // rdisk0s1), so the list stays short and meaningful.
                if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                    out.push(format!("/dev/{name}"));
                }
            }
        }
    }
    out.sort();
    out
}

/// The three operations the GUI can run against a drive.
pub enum Job {
    /// Identify + classify + firmware fingerprint (read-only).
    Info,
    /// Full image + per-unit regions + read-surface map → one `.tar`.
    Dump { out: PathBuf },
    /// Flash a firmware image, backup-first (the dangerous one).
    Flash { input: PathBuf },
}

/// Run one job against `device`, letting the engine `println!` to stdout (which
/// a caller may be capturing). Returns the engine's own `Result`.
pub fn execute(device: &str, job: &Job) -> anyhow::Result<()> {
    match job {
        Job::Info => {
            let mut dev = platform::open(device, false)?;
            let family = drive::classify(dev.as_mut());
            let handler = drive::for_family(family);
            engine::info(dev.as_mut(), handler.as_ref())
        }
        Job::Dump { out } => {
            let mut dev = platform::open(device, false)?;
            let handler = classify_gated(dev.as_mut())?;
            engine::dump_everything(dev.as_mut(), handler.as_ref(), out)
        }
        Job::Flash { input } => {
            let bytes = std::fs::read(input)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", input.display()))?;
            let input_kind = drive::sniff_input(input);
            let mut dev = platform::open(device, true)?;
            let handler = classify_gated(dev.as_mut())?;
            let drive_model = handler.identity(dev.as_mut()).product;
            let req = FlashRequest {
                input: bytes,
                input_kind,
                mode: manifest::FlashMode::Full,
                // The GUI's flash button IS the "do it for real" action; the
                // dry-run lives in the CLI. The confirm checkbox is the gate.
                execute: true,
                rescue_no_dump: false,
                acknowledged_risk: true,
                enc_override: None,
                drive_model,
                verbose: false,
                // Crossflash is an experimental CLI-only opt-in; the GUI never
                // waives the model gate.
                allow_crossflash: false,
                // Always keep a backup next to the input image.
                predump_out: default_backup_path(input),
            };
            engine::flash(dev.as_mut(), handler.as_ref(), &req)
        }
    }
}

/// Classify and enforce the MTK gate: only MediaTek drives may dump/flash.
fn classify_gated(
    dev: &mut dyn platform::ScsiDevice,
) -> anyhow::Result<Box<dyn drive::DriveFamily>> {
    let family = drive::classify(dev);
    if family != Family::Mtk {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(drive::for_family(family))
}

/// Default pre-flash backup path: `<input>.predump.tar` next to the input.
fn default_backup_path(input: &Path) -> Option<PathBuf> {
    let name = input.file_name()?.to_string_lossy().into_owned();
    Some(input.with_file_name(format!("{name}.predump.tar")))
}

/// Run `f`, redirecting the process's stdout to a pipe so the engine's
/// `println!` progress is delivered line-by-line to `on_line` from a reader
/// thread while `f` is still running (live streaming into the log pane).
///
/// Only one capture may be active at a time (fd 1 is a process-global), so a
/// lock serialises them; the GUI also disables its buttons during a job.
#[cfg(unix)]
pub fn capture_lines<R>(f: impl FnOnce() -> R, on_line: impl FnMut(String) + Send + 'static) -> R {
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::FromRawFd;
    use std::sync::Mutex;

    static SERIALISE: Mutex<()> = Mutex::new(());
    let _guard = SERIALISE.lock().unwrap_or_else(|e| e.into_inner());

    // A pipe; fd 1 is pointed at its write end for the duration of `f`.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is a valid 2-element array for pipe(2) to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return f(); // capture unavailable: run without redirect.
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let _ = std::io::stdout().flush();
    // SAFETY: dup/dup2 on fd 1 and the pipe fds; all are open here.
    let saved = unsafe { libc::dup(1) };
    unsafe {
        libc::dup2(write_fd, 1);
        libc::close(write_fd);
    }

    let reader = std::thread::spawn(move || {
        // SAFETY: read_fd is a valid, owned read end of the pipe.
        let file = unsafe { std::fs::File::from_raw_fd(read_fd) };
        let mut on_line = on_line;
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            on_line(line);
        }
    });

    let out = f();

    let _ = std::io::stdout().flush();
    // Restore stdout; dup2 closes the pipe write end (old fd 1), so the reader
    // sees EOF and its thread ends.
    // SAFETY: `saved` is the dup of the original fd 1, still open.
    unsafe {
        libc::dup2(saved, 1);
        libc::close(saved);
    }
    let _ = reader.join();
    out
}

/// Non-Unix fallback: the process-global stdout redirect used above relies on
/// `dup2` on fd 1, which is a Unix facility. On other platforms (Windows) the
/// job still runs to completion and its `Result` is reported; live line-by-line
/// streaming of the engine's `println!` progress is simply unavailable.
#[cfg(not(unix))]
pub fn capture_lines<R>(f: impl FnOnce() -> R, _on_line: impl FnMut(String) + Send + 'static) -> R {
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The best-effort device scan must never panic, even on a host with no
    /// optical drive attached (it may return internal disks or an empty list).
    #[test]
    fn enumerate_does_not_panic() {
        let list = enumerate();
        // Every entry a shell would show must be a plausible device path.
        for d in &list {
            assert!(!d.is_empty());
        }
    }

    /// Job dispatch must surface a clean `Err` — never a panic — when the
    /// selected device cannot be opened. This exercises the same `execute`
    /// path the GUI's worker thread runs, minus the stdout capture.
    #[test]
    fn info_job_on_missing_device_errs_without_panic() {
        let res = execute("/dev/freemkv-flash-gui-no-such-device", &Job::Info);
        assert!(res.is_err(), "expected an open error, got {res:?}");
    }
}
