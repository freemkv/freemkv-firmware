//! GUI jobs delegate to the same application workflows as the CLI.
//! Output is delivered through a scoped callback on every operating system.

use std::path::PathBuf;

#[cfg(test)]
use freemkv_flash::{drive::Family, platform};

/// Enumerate the same optical drives shown by the CLI, including empty trays.
pub fn enumerate() -> Vec<freemkv_flash::workflow::DriveChoice> {
    freemkv_flash::diagnostics::run("GUI discovery", || Ok(freemkv_flash::workflow::drives()))
        .unwrap_or_default()
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
#[path = "ops_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ops_parity_regressions_tests.rs"]
mod parity_regressions;
