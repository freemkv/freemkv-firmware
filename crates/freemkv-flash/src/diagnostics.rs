//! Automatic CLI/GUI operation logs; bounded identity metadata, no firmware payloads.

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
pub fn record(text: impl AsRef<str>) {
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
        if let Some(base) = std::env::var_os("XDG_CACHE_HOME") {
            return PathBuf::from(base).join("freemkv/logs");
        }
        if let Some(base) = std::env::var_os("HOME") {
            return PathBuf::from(base).join(".cache/freemkv/logs");
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

fn create_log(directory: &Path, application: &str) -> io::Result<(PathBuf, Log)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(directory)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = directory.join(format!(
        "{application}-{stamp}-{}-{}.log",
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
    run_named("freemkv-flash", operation, work)
}

/// Run a sibling application's operation with the same automatic diagnostic policy.
/// The application name is a filename component and must contain only ASCII letters,
/// digits or hyphens. Nested operations share the existing file.
pub fn run_named<T>(
    application: &str,
    operation: &str,
    work: impl FnOnce() -> Result<T>,
) -> Result<T> {
    anyhow::ensure!(
        !application.is_empty()
            && application
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-'),
        "invalid diagnostic application name"
    );
    run_at_named(&log_directory(), application, operation, work)
}

#[cfg(test)]
fn run_at<T>(directory: &Path, operation: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    run_at_named(directory, "freemkv-flash", operation, work)
}

fn run_at_named<T>(
    directory: &Path,
    application: &str,
    operation: &str,
    work: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if LOG.with(|slot| slot.borrow().is_some()) {
        return work();
    }
    let created = create_log(directory, application)
        .or_else(|_| create_log(&std::env::temp_dir().join("freemkv-logs"), application));
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
        "{application}={} os={} arch={} operation={operation:?} unix_time={:?}",
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
        .with_max_level(tracing::Level::TRACE)
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
#[path = "diagnostics_tests.rs"]
mod tests;

/// Capture Apple's underlying plug-in errors after a failed macOS transport open.
#[cfg(target_os = "macos")]
pub(crate) fn macos_open_failure() {
    use std::process::{Command, Stdio};
    let predicate = format!(
        "(subsystem == \"com.apple.iokit.cfplugin\" AND processID == {0}) OR (process == \"authd\" AND (eventMessage CONTAINS \"[{0}]\" OR eventMessage CONTAINS \"PID {0} \" OR eventMessage CONTAINS \"pid {0} \"))",
        std::process::id()
    );
    let mut command = Command::new("/usr/bin/log");
    command.args([
        "show",
        "--last",
        "1m",
        "--style",
        "compact",
        "--info",
        "--debug",
        "--predicate",
        &predicate,
    ]);
    command.stdin(Stdio::null());
    match bounded_output(&mut command, std::time::Duration::from_secs(3)) {
        Ok((status, output)) => record(format!("macOS plug-in context: {status}\n{output}")),
        Err(error) => record(format!("macOS plug-in context unavailable: {error}")),
    }
    let mut policy = Command::new("/usr/bin/security");
    policy
        .args(["authorizationdb", "read", "system.burn"])
        .stdin(Stdio::null());
    match bounded_output(&mut policy, std::time::Duration::from_secs(2)) {
        Ok((status, output)) => record(format!(
            "system.burn policy (read-only): {status}\n{output}"
        )),
        Err(error) => record(format!("system.burn policy unavailable: {error}")),
    }
}

#[cfg(any(target_os = "macos", test))]
fn bounded_output(
    command: &mut std::process::Command,
    budget: std::time::Duration,
) -> io::Result<(String, String)> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let read = |stream: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.take(16 * 1024).read_to_end(&mut bytes);
            bytes
        })
    };
    let stdout = read(Box::new(child.stdout.take().unwrap()));
    let stderr = read(Box::new(child.stderr.take().unwrap()));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.to_string(),
            Ok(None) if start.elapsed() < budget => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                break match result {
                    Err(error) => format!("wait failed: {error}"),
                    _ => "timed out; collector terminated".into(),
                };
            }
        }
    };
    let mut bytes = stdout.join().unwrap_or_default();
    bytes.extend_from_slice(&stderr.join().unwrap_or_default());
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}
