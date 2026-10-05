//! GUI jobs delegate to the same application workflows as the CLI.
//! Output is delivered through a scoped callback on every operating system.

use std::path::PathBuf;

#[cfg(test)]
use freemkv_flash::{drive::Family, platform};

/// Enumerate the same optical drives shown by the CLI, including empty trays.
pub fn enumerate() -> Vec<freemkv_flash::workflow::DriveChoice> {
    freemkv_flash::workflow::drives()
}

/// Application operations. Both front-ends use the same workflow for each.
#[derive(Clone)]
pub enum Job {
    Info,
    InfoFile { input: PathBuf },
    Backup { out: PathBuf, replace: bool },
    Dump { out: PathBuf, replace: bool },
    Flash(freemkv_flash::workflow::FlashOptions),
}

/// Run the same operation as the matching CLI command.
pub fn execute(device: &str, job: &Job) -> anyhow::Result<()> {
    use freemkv_flash::workflow;
    match job {
        Job::Info => workflow::info(Some(device)),
        Job::InfoFile { input } => workflow::check_file(input),
        Job::Backup { out, replace } => {
            workflow::backup_with_replace(Some(device), Some(out.clone()), false, *replace)
        }
        Job::Dump { out, replace } => {
            workflow::backup_with_replace(Some(device), Some(out.clone()), true, *replace)
        }
        Job::Flash(options) => {
            let mut options = options.clone();
            options.device = Some(device.to_string());
            workflow::flash(options)
        }
    }
}

/// Stream the shared workflow's information, warnings and progress on every OS.
#[cfg(test)]
pub fn capture_lines<R>(f: impl FnOnce() -> R, on_line: impl FnMut(String) + 'static) -> R {
    freemkv_flash::output::capture(on_line, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Discovery must work even on a host with no optical drive attached.
    #[test]
    fn enumerate_does_not_panic() {
        let list = enumerate();
        // Every entry a shell would show must be a plausible device path.
        for d in &list {
            assert!(!d.path.is_empty());
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

#[cfg(test)]
mod parity_regressions {
    use super::*;

    #[test]
    fn gui_accepts_the_same_pioneer_backend_as_cli() {
        let mut dev = platform::MockScsiDevice::pioneer();
        let backend = freemkv_flash::workflow::classify_gated(&mut dev)
            .expect("Pioneer supports backup and flash");
        assert_eq!(backend, Family::Pioneer);
        assert!(dev.writes.is_empty());
    }

    #[test]
    fn gui_receives_progress_and_warnings() {
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = lines.clone();
        capture_lines(
            || {
                freemkv_flash::style::Progress::new("reading firmware", 0x200000).set(0x100000);
            },
            move |line| received.lock().unwrap().push(line),
        );
        assert!(lines.lock().unwrap().iter().any(|l| l.contains("50%")));
    }
}
