//! GUI jobs delegate to the same application workflows as the CLI.
//! Output is delivered through a scoped callback on every operating system.

use std::path::PathBuf;
use std::sync::Arc;

use freemkv_flash::workflow::{
    self, ComparisonReport, Confirm, Control, DriveChoice, DriveProfile, FlashOptions, Inspection,
    RecoveryOptions, Source,
};

use crate::ui::{Profile, Task};

/// Enumerate the same optical drives shown by the CLI, including empty trays.
pub fn enumerate() -> Vec<DriveChoice> {
    workflow::discover()
}

/// Read `device`'s profile: what it is and what the tool can do with it.
pub fn profile(device: &str) -> anyhow::Result<Profile> {
    workflow::profile(device).map(|p| profile_view(&p))
}

/// The GUI's view of a profile. The family name comes from the backend's
/// descriptor; Recovery is offered whenever a backend identified the receiver.
pub(crate) fn profile_view(p: &DriveProfile) -> Profile {
    let caps = &p.capabilities;
    let family = p.backend.as_ref().map(|(d, _)| d);
    let mut chips = vec![family.map_or("Unsupported", |d| d.display_name).to_string()];
    let mut tasks = Vec::new();
    for (offered, task) in [
        (caps.backup, Task::Backup),
        (caps.dump, Task::Dump),
        (caps.flash, Task::Flash),
    ] {
        if offered {
            chips.push(task.title().into());
            tasks.push(task);
        }
    }
    if let Some(recovery) = p.recovery {
        chips.push(match family {
            Some(d) if d.id == recovery.id => Task::Recovery.title().into(),
            _ => format!("{} ({})", Task::Recovery.title(), recovery.display_name),
        });
        tasks.push(Task::Recovery);
    }
    let name = |dump: bool| {
        workflow::default_backup_name(&p.identity, p.backup_format, dump)
            .ok()
            .map(|path| path.display().to_string())
    };
    Profile {
        chips,
        tasks,
        inspect: caps.inspect,
        backup_name: caps.backup.then(|| name(false)).flatten(),
        dump_name: caps.dump.then(|| name(true)).flatten(),
    }
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
        Request::Inspect(source) => workflow::inspect(source, control).map(ResultView::Inspect),
        Request::Compare(a, b) => workflow::compare(a, b, control).map(ResultView::Compare),
    }
}

/// Application operations. Both front-ends use the same workflow for each.
#[derive(Clone)]
pub enum Job {
    Info,
    Analysis {
        request: Request,
        control: Control,
    },
    InfoFile {
        input: PathBuf,
    },
    Backup {
        out: PathBuf,
        replace: bool,
    },
    Dump {
        out: PathBuf,
        replace: bool,
    },
    /// The read-only flash plan shown before consent; no backup, no writes.
    PlanFlash(FlashOptions),
    Flash(FlashOptions),
    Recovery(RecoveryOptions),
}

/// Run the same operation as the matching CLI command; an analysis returns
/// its result. `confirm` answers an authorized flash before it writes.
pub fn execute(
    device: &str,
    job: &Job,
    confirm: &mut dyn Confirm,
) -> anyhow::Result<Option<ResultView>> {
    match job {
        Job::Analysis { request, control } => return analyze(request, control).map(Some),
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
        Job::PlanFlash(options) => {
            let mut options = options.clone();
            options.device = Some(device.to_string());
            workflow::plan_flash(&options).map(drop)
        }
        Job::Flash(options) => {
            let mut options = options.clone();
            options.device = Some(device.to_string());
            workflow::flash(options, confirm)
        }
    }?;
    Ok(None)
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ops_parity_regressions_tests.rs"]
mod parity_regressions;
