//! Automatic operation logs shared by the CLI and GUI; never record data buffers.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;

const MAX_LOG: usize = 8 * 1024 * 1024;
const KEEP_START: usize = 64 * 1024;
const MAX_EVENT: usize = 32 * 1024;

struct Log {
    file: File,
    start: Instant,
    bytes: usize,
    prefix: Vec<u8>,
    rolled: bool,
}

impl Log {
    fn write(&mut self, text: &str) -> io::Result<()> {
        let mut clean = String::with_capacity(text.len().min(MAX_EVENT));
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if clean.len() + ch.len_utf8() > MAX_EVENT {
                clean.push_str(" [event truncated]");
                break;
            }
            if ch == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for code in chars.by_ref() {
                    if ('@'..='~').contains(&code) {
                        break;
                    }
                }
            } else if ch != '\r' {
                clean.push(ch);
            }
        }
        let line = format!("[{:>10.3}s] {clean}\n", self.start.elapsed().as_secs_f64());
        if self.bytes + line.len() > MAX_LOG {
            self.file.set_len(0)?;
            self.file.rewind()?;
            self.file.write_all(&self.prefix)?;
            let marker =
                b"\n[log rolled: initial context retained; older intervening events omitted]\n";
            self.file.write_all(marker)?;
            self.bytes = self.prefix.len() + marker.len();
            self.rolled = true;
        }
        self.file.write_all(line.as_bytes())?;
        self.bytes += line.len();
        if !self.rolled && self.prefix.len() + line.len() <= KEEP_START {
            self.prefix.extend_from_slice(line.as_bytes());
        }
        Ok(())
    }
}

thread_local! {
    static LOG: RefCell<Option<Log>> = const { RefCell::new(None) };
}

/// Append a diagnostic without cluttering the UI. A failed log never interrupts a burn.
pub(crate) fn record(text: impl AsRef<str>) {
    let error = LOG.with(|slot| {
        let mut slot = slot.borrow_mut();
        let error = slot.as_mut().and_then(|log| log.write(text.as_ref()).err());
        if error.is_some() {
            *slot = None;
        }
        error
    });
    if let Some(error) = error {
        eprintln!("warning: diagnostic log write failed: {error}; file logging disabled for this operation");
    }
}

fn log_directory() -> PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(base) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(base).join("freemkv").join("logs");
    }
    #[cfg(target_os = "macos")]
    if let Some(base) = std::env::var_os("HOME") {
        return PathBuf::from(base).join("Library/Logs/freemkv");
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(base) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(base).join("freemkv/logs");
        }
        if let Some(base) = std::env::var_os("HOME") {
            return PathBuf::from(base).join(".local/state/freemkv/logs");
        }
    }
    std::env::temp_dir().join("freemkv-logs")
}

fn system_details() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        return match std::process::Command::new(PathBuf::from(root).join("System32/cmd.exe"))
            .args(["/d", "/c", "ver"])
            .creation_flags(0x08000000)
            .output()
        {
            Ok(output) => format!(
                "Windows version: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            ),
            Err(error) => format!("Windows version unavailable: {error}"),
        };
    }
    #[cfg(target_os = "macos")]
    return std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
        .unwrap_or_else(|error| format!("system version unavailable: {error}"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    return std::fs::read_to_string("/etc/os-release")
        .unwrap_or_else(|error| format!("system version unavailable: {error}"));
}

fn create_log(directory: &Path) -> io::Result<(PathBuf, Log)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(directory)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = directory.join(format!(
        "freemkv-flash-{stamp}-{}-{}.log",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path)?;
    Ok((
        path,
        Log {
            file,
            start: Instant::now(),
            bytes: 0,
            prefix: Vec::new(),
            rolled: false,
        },
    ))
}

/// Run an application operation with an automatic, timestamped diagnostic file.
/// Nested workflows reuse the current log. Native transport warnings are forwarded
/// into the same output stream, including Windows DeviceIoControl error codes.
pub fn run<T>(operation: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    run_at(&log_directory(), operation, work)
}

fn run_at<T>(directory: &Path, operation: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    if LOG.with(|slot| slot.borrow().is_some()) {
        return work();
    }
    let created =
        create_log(directory).or_else(|_| create_log(&std::env::temp_dir().join("freemkv-logs")));
    let path = match created {
        Ok((path, log)) => {
            LOG.with(|slot| *slot.borrow_mut() = Some(log));
            Some(path)
        }
        Err(error) => {
            eprintln!("warning: cannot create diagnostic log: {error}");
            None
        }
    };
    struct Finish;
    impl Drop for Finish {
        fn drop(&mut self) {
            if std::thread::panicking() {
                record("PANIC: operation unwound; outcome unknown");
            }
            LOG.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    let _finish = Finish;
    record(format!(
        "freemkv-flash={} os={} arch={} operation={operation:?} unix_time={:?}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        SystemTime::now().duration_since(UNIX_EPOCH).ok()
    ));
    record(system_details());
    if let Some(path) = &path {
        crate::output::field("Diagnostic log", path.display().to_string());
        eprintln!("Diagnostic log: {}", path.display());
    }
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(NativeWriter::default)
        .finish();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tracing::subscriber::with_default(subscriber, work)
    }));
    let result = match outcome {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            record(format!("PANIC: {message}; operation outcome unknown"));
            std::panic::resume_unwind(payload);
        }
    };
    match &result {
        Ok(_) => record("RESULT: success"),
        Err(error) => record(format!("RESULT: error: {error:#}")),
    }
    if let Some(path) = &path.filter(|_| LOG.with(|slot| slot.borrow().is_some())) {
        eprintln!("Diagnostic log saved: {}", path.display());
    }
    result
}

#[derive(Default)]
struct NativeWriter(Vec<u8>);

impl Write for NativeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for NativeWriter {
    fn drop(&mut self) {
        eprintln!("[native] {}", String::from_utf8_lossy(&self.0).trim_end());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn operation_log_includes_output_native_warning_and_full_error_chain() {
        let path = Arc::new(Mutex::new(None));
        let captured = path.clone();
        let directory =
            std::env::temp_dir().join(format!("freemkv-diagnostics-test-{}", std::process::id()));
        let result: Result<()> = crate::output::capture_events(
            move |event| {
                if let crate::output::Event::Field { label, value } = event {
                    if label == "Diagnostic log" {
                        *captured.lock().unwrap() = Some(PathBuf::from(value));
                    }
                }
            },
            || {
                run_at(&directory, "test", || {
                    println!("capturing drive firmware");
                    tracing::warn!(target: "freemkv::scsi", last_error = 87, "DeviceIoControl failed");
                    run("nested", || {
                        record("SCSI result: status=0x00 transferred=0");
                        Err(anyhow::anyhow!("short firmware read")
                            .context("probing Pioneer firmware read access"))
                    })
                })
            },
        );
        assert!(result.is_err());
        let path = path.lock().unwrap().clone().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        for expected in [
            "freemkv-flash=",
            "os=",
            "capturing drive firmware",
            "last_error=87",
            "DeviceIoControl failed",
            "status=0x00 transferred=0",
            "RESULT: error: probing Pioneer firmware read access: short firmware read",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert_eq!(text.matches("freemkv-flash=").count(), 1);
        assert!(LOG.with(|slot| slot.borrow().is_none()));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rollover_keeps_initial_context_and_final_result_bounded() {
        let directory = std::env::temp_dir().join("freemkv-diagnostics-rollover-test");
        let (path, mut log) = create_log(&directory).unwrap();
        log.write("\x1b[32minitial drive identity\x1b[0m").unwrap();
        let row = "command ".repeat(128);
        for _ in 0..(MAX_LOG / row.len() + 20) {
            log.write(&row).unwrap();
        }
        log.write("RESULT: terminal failure").unwrap();
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.len() <= MAX_LOG);
        assert!(text.contains("initial drive identity"));
        assert!(!text.contains('\x1b'));
        assert!(text.contains("older intervening events omitted"));
        assert!(text.ends_with("RESULT: terminal failure\n"));
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn logging_failure_disables_logging_without_failing_the_operation() {
        let directory = std::env::temp_dir().join("freemkv-diagnostics-failure-test");
        let (path, mut log) = create_log(&directory).unwrap();
        log.file = File::open(&path).unwrap(); // read-only handle makes the write fail
        LOG.with(|slot| *slot.borrow_mut() = Some(log));
        crate::output::capture(|_| {}, || record("cannot write this"));
        assert!(LOG.with(|slot| slot.borrow().is_none()));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn panic_closes_the_log_and_records_unknown_outcome() {
        let path = Arc::new(Mutex::new(None));
        let captured = path.clone();
        let directory = std::env::temp_dir().join("freemkv-diagnostics-panic-test");
        crate::output::capture_events(
            move |event| {
                if let crate::output::Event::Field { label, value } = event {
                    if label == "Diagnostic log" {
                        *captured.lock().unwrap() = Some(PathBuf::from(value));
                    }
                }
            },
            || {
                assert!(std::panic::catch_unwind(|| run_at::<()>(
                    &directory,
                    "panic-test",
                    || panic!("test panic")
                ))
                .is_err());
            },
        );
        assert!(LOG.with(|slot| slot.borrow().is_none()));
        let path = path.lock().unwrap().clone().unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("PANIC: operation unwound; outcome unknown"));
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("PANIC: test panic; operation outcome unknown"));
        std::fs::remove_file(path).unwrap();
    }
}
