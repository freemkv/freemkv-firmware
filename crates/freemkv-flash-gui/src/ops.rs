//! GUI jobs delegate to the same application workflows as the CLI.
//! Output is delivered through a scoped callback on every operating system.

use std::path::PathBuf;
use std::sync::Arc;

use freemkv_flash::inspection::{self, ComparisonReport, Control, Inspection, Source};

#[cfg(test)]
use freemkv_flash::platform;

/// Enumerate the same optical drives shown by the CLI, including empty trays.
pub fn enumerate() -> Vec<freemkv_flash::workflow::DriveChoice> {
    freemkv_flash::diagnostics::run("GUI discovery", || Ok(freemkv_flash::workflow::drives()))
        .unwrap_or_default()
}

/// An Inspect or Compare request.
#[derive(Clone)]
pub enum Request {
    Inspect(Source),
    Compare(Source, Source),
}

/// A finished Inspect or Compare.
#[derive(Debug)]
pub enum ResultView {
    Inspect(Arc<Inspection>),
    Compare(ComparisonReport),
}

/// Run an analysis through the shared inspection workflow.
pub fn analyze(request: &Request, control: &Control) -> anyhow::Result<ResultView> {
    match request {
        Request::Inspect(source) => inspection::inspect(source, control).map(ResultView::Inspect),
        Request::Compare(a, b) => inspection::compare(a, b, control).map(ResultView::Compare),
    }
}

/// Application operations. Both front-ends use the same workflow for each.
#[derive(Clone)]
pub enum Job {
    Info,
    Analysis { request: Request, control: Control },
    InfoFile { input: PathBuf },
    Backup { out: PathBuf, replace: bool },
    Dump { out: PathBuf, replace: bool },
    Flash(freemkv_flash::workflow::FlashOptions),
    Recovery(freemkv_flash::workflow::RecoveryOptions),
}

/// Run the same operation as the matching CLI command.
pub fn execute(device: &str, job: &Job) -> anyhow::Result<()> {
    use freemkv_flash::workflow;
    match job {
        Job::Analysis { request, control } => {
            let text = match analyze(request, control)? {
                ResultView::Inspect(r) => r.text(),
                ResultView::Compare(r) => r.text(),
            };
            freemkv_flash::output::field("Analysis", text);
            Ok(())
        }
        Job::Info => workflow::info(Some(device)),
        Job::InfoFile { input } => workflow::check_file(input),
        Job::Backup { out, replace } => {
            workflow::backup_with_replace(Some(device), Some(out.clone()), false, *replace)
        }
        Job::Dump { out, replace } => {
            workflow::backup_with_replace(Some(device), Some(out.clone()), true, *replace)
        }
        Job::Recovery(options) => {
            let mut options = options.clone();
            options.device = Some(device.to_string());
            workflow::recover(options)
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
