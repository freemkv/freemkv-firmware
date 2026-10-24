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

/// The same profile with an explicitly selected Current reference.
pub fn profile_with_current(
    device: &str,
    current: &std::path::Path,
    member: Option<&str>,
) -> anyhow::Result<Profile> {
    workflow::profile_with_current(device, current, member).map(|p| profile_view(&p))
}

/// The GUI's view of a profile. The family name comes from the backend's
/// descriptor; Recovery is offered whenever a backend identified the receiver.
pub(crate) fn profile_view(p: &DriveProfile) -> Profile {
    let caps = &p.capabilities;
    let family = p.backend.as_ref().map(|(d, _)| d);
    let mut chips = vec![family
        .map_or("modify.not_supported", |d| d.display_name)
        .to_string()];
    let mut tasks = Vec::new();
    for (offered, task) in [
        (caps.backup, Task::Backup),
        (caps.dump, Task::Dump),
        (caps.flash, Task::Flash),
    ] {
        if offered {
            tasks.push(task);
        }
    }
    if let Some(recovery) = p.recovery {
        if family.is_none() {
            chips = vec![recovery.display_name.into()];
        }
        tasks.push(Task::Recovery);
    }
    let name = |dump: bool| {
        workflow::default_backup_name(&p.identity, p.backup_format, dump)
            .ok()
            .map(|path| path.display().to_string())
    };
    Profile {
        can_read: p.can_read(),
        flash_current: caps.flash_current,
        recovery_family_override: workflow::recovery_supports_family_override(p),
        recovery_without_live_protocol: !caps.recovery && p.recovery.is_some(),
        chips,
        tasks,
        inspect: caps.inspect,
        backup_name: caps.backup.then(|| name(false)).flatten(),
        dump_name: caps.dump.then(|| name(true)).flatten(),
        flash_extensions: workflow::update_extensions(
            p.recovery.map_or(p.flash_formats, |d| d.formats),
        ),
        notes: p
            .recovery_errors
            .iter()
            .map(|e| format!("Recovery not offered: could not identify the receiver ({e})"))
            .collect(),
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
    /// Execute the envelopes retained by recovery preparation.
    ExecuteRecovery(workflow::PreparedRecovery),
}

/// A job result preserves update evidence separately from analysis views.
pub enum JobResult {
    Complete,
    Preview(workflow::FlashPreview),
    Analysis(ResultView),
    Update(workflow::UpdateOutcome),
    /// An immutable prepared session waiting for consent.
    PreparedRecovery(workflow::PreparedRecovery),
}

/// Run the same operation as the matching CLI command; an analysis returns
/// its result. `confirm` answers an authorized flash before it writes.
pub fn execute(device: &str, job: &Job, confirm: &mut dyn Confirm) -> anyhow::Result<JobResult> {
    match job {
        Job::Analysis { request, control } => {
            return analyze(request, control).map(JobResult::Analysis)
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
            if !options.execute {
                return workflow::prepare_recovery(options).map(JobResult::PreparedRecovery);
            }
            return workflow::recover(options).map(JobResult::Update);
        }
        Job::ExecuteRecovery(prepared) => {
            return workflow::execute_recovery(prepared.clone(), true).map(JobResult::Update);
        }
        Job::PlanFlash(options) => {
            let mut options = options.clone();
            options.device = Some(device.to_string());
            return workflow::preview_flash(&options).map(JobResult::Preview);
        }
        Job::Flash(options) => {
            let mut options = options.clone();
            options.device = Some(device.to_string());
            return workflow::flash(options, confirm).map(JobResult::Update);
        }
    }?;
    Ok(JobResult::Complete)
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ops_parity_regressions_tests.rs"]
mod parity_regressions;
