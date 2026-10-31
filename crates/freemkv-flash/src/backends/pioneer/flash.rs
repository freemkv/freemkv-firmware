//! App adapter for the library's OEM update sequence.
//!
//! Owns tray policy, user progress and error guidance. The library owns command
//! ordering, revision gating, transfer chunks, settle timing and readiness.

#[cfg(test)]
use crate::backends::pioneer::FLASH_CHUNK;

use crate::backend::{ComponentVerification, UpdateVerification, WriteDevice};
use crate::style;
use crate::transport::{ScsiTransport, SharedDevice};
#[cfg(test)]
use anyhow::anyhow;
use anyhow::Result;

impl From<pioneer_optical::operation::IssueKind> for crate::user_error::IssueCode {
    fn from(kind: pioneer_optical::operation::IssueKind) -> Self {
        use pioneer_optical::operation::IssueKind;
        match kind {
            IssueKind::InvalidFirmware => Self::FirmwareInvalid,
            IssueKind::UnsupportedFirmware => Self::UnsupportedFirmware,
            IssueKind::ReceiverMismatch => Self::CurrentMismatch,
            IssueKind::HardwareMismatch => Self::IncompatibleFirmware,
            IssueKind::Connection => Self::Connection,
            IssueKind::Verification | IssueKind::Update => Self::UpdateUncertain,
            IssueKind::Unexpected => Self::Unexpected,
        }
    }
}
use pioneer_optical::drive::UpdateRuntime;
#[cfg(test)]
use pioneer_optical::drive::{UpdateError, UpdateOptions};
use pioneer_optical::receiver::{
    ExecutionMode, ExecutionRuntime, FlashPass, FlashTransport, PreparedNormal, PreparedUpdate,
};
#[cfg(test)]
use pioneer_optical::{receiver::FlashError, DriveClass};
use pioneer_optical::{CodedError, Role};
use std::time::Duration;

/// A validated library plan selected by the app's input routing.
pub(crate) enum PreparedFlash<'a> {
    Complete(&'a PreparedUpdate),
    Normal(&'a PreparedNormal),
}

pub(crate) fn execute_prepared(
    dev: &mut WriteDevice<'_>,
    plan: PreparedFlash<'_>,
    mode: ExecutionMode,
) -> Result<crate::backend::UpdateOutcome> {
    execute_with_sleep(dev, plan, mode, &mut crate::runtime_clock::sleep)
}

pub(super) fn execute_with_sleep(
    dev: &mut WriteDevice<'_>,
    plan: PreparedFlash<'_>,
    mode: ExecutionMode,
    sleep: &mut dyn FnMut(Duration),
) -> Result<crate::backend::UpdateOutcome> {
    if let PreparedFlash::Complete(plan) = &plan {
        retain_handoff_bridges(plan)?;
    }
    let shared = SharedDevice::new(dev);
    let mut reads = ScsiTransport::reads(&shared);
    let mut writes = ScsiTransport::flash(&shared);
    let io = FlashTransport {
        reads: &mut reads,
        writes: &mut writes,
    };
    let info = match &plan {
        PreparedFlash::Complete(plan) => plan.target_info(),
        PreparedFlash::Normal(plan) => plan.target_info(),
    };
    let selected_identity = format!("{} {}", info.model, info.revision);
    let mut runtime = Runtime {
        mode,
        start: crate::runtime_clock::Clock::new(),
        waited: Duration::ZERO,
        completed_passes: 0,
        stage_messages: match plan {
            PreparedFlash::Complete(plan) => plan
                .stages()
                .iter()
                .enumerate()
                .skip(1)
                .map(|(index, _)| {
                    if plan.stages()[index - 1].bridge()
                        == Some(pioneer_optical::receiver::BridgeKind::ReceiverMarker)
                    {
                        "restoring the unmodified target Kernel".to_string()
                    } else {
                        format!("continuing firmware update: stage {}", index + 1)
                    }
                })
                .collect(),
            PreparedFlash::Normal(_) => Vec::new(),
        },
        verification: UpdateVerification {
            kernel: if matches!(&plan, PreparedFlash::Complete(_)) {
                ComponentVerification::NotChecked
            } else {
                ComponentVerification::NotRequested
            },
            normal: ComponentVerification::NotChecked,
            startup_confirmed: false,
            observed_identity: None,
            selected_identity,
        },
        kernel: style::Progress::new("flashing kernel", 0),
        normal: style::Progress::new("flashing normal", 0),
        device: &shared,
        sleep,
    };
    let restoration_required =
        matches!(plan, PreparedFlash::Complete(p) if p.restoration_kernel_transfer().is_some());
    match plan {
        PreparedFlash::Complete(plan) => {
            let mut previous = None;
            for stage in plan.stages() {
                if previous != Some(stage.normal_image()) {
                    report_settings(stage.settings());
                }
                previous = Some(stage.normal_image());
            }
        }
        PreparedFlash::Normal(plan) => report_settings(plan.settings()),
    }
    let outcome = match plan {
        PreparedFlash::Complete(plan) => plan.execute(io, &mut runtime, mode),
        PreparedFlash::Normal(plan) => plan.execute(io, &mut runtime),
    }
    .map_err(|error| {
        crate::diagnostics::record(format!("UPDATE VERIFICATION: {}", runtime.verification));
        execution_error(error, restoration_required, runtime.completed_passes)
            .context(runtime.verification.clone())
    })?;
    println!("{}", super::post_flash_line(&outcome.identity));
    let mut verified_regions = Vec::new();
    if outcome.kernel_verified {
        verified_regions.push("Kernel".to_string());
    }
    let mut unverified_regions = Vec::new();
    if outcome.normal_verified {
        verified_regions.push("Normal".to_string());
    } else {
        unverified_regions.push("Normal".to_string());
    }
    Ok(crate::backend::UpdateOutcome::Completed(
        crate::backend::UpdateEvidence {
            target_started: true,
            target_identity: format!(
                "{} {} ({}, Kernel {}, Normal {})",
                style::printable(outcome.identity.product()),
                style::printable(outcome.identity.revision()),
                style::printable(outcome.identity.platform()),
                style::printable(outcome.identity.kernel_tag()),
                style::printable(outcome.identity.normal_tag())
            ),
            verified_regions,
            unverified_regions,
            completed_stages: (1..=outcome.completed_passes)
                .map(|pass| format!("Pioneer update pass {pass}"))
                .collect(),
            temporary_firmware: false,
        },
    ))
}

fn report_settings(plan: &pioneer_optical::settings::update::Plan) {
    use pioneer_optical::settings::update::Effect;
    if let Some(id) = plan.adaptation_id() {
        crate::diagnostics::record(format!("Pioneer settings adaptation: {id}; original factory mechanism and live prerequisites must match before writing"));
    }
    for setting in plan.entries() {
        match setting.effect() {
            Effect::ParameterWord {
                parameter,
                value,
                explicit,
            } => {
                report_startup_setting(pioneer_optical::startup::Setting {
                    parameter,
                    value,
                    explicit,
                });
            }
            Effect::TemporaryKernelMarker => {
                let text = "temporary receiver setting; pristine OEM Kernel restored and verified in the final pass";
                crate::diagnostics::record(format!(
                    "Pioneer setting {}: {text}",
                    setting.key().id()
                ));
            }
        }
    }
}

pub(super) fn report_startup_setting(setting: pioneer_optical::startup::Setting) {
    let source = if setting.explicit {
        "required by target firmware"
    } else {
        "neutral default for target firmware"
    };
    let text = format!(
        "target word {:#04x} = {:04X} ({source})",
        setting.parameter, setting.value
    );
    crate::diagnostics::record(format!("Pioneer startup setting: {text}"));
    crate::output::field("Startup setting", crate::report::Value::text(&text));
}

pub(crate) fn preparation_error<E>(error: E) -> anyhow::Error
where
    E: std::error::Error + Send + Sync + CodedError + 'static,
{
    let code = error.code();
    let issue = if matches!(
        code,
        "pioneer.settings.compatibility_unresolved" | "pioneer.settings.conversion_unavailable"
    ) {
        crate::user_error::IssueCode::SettingsUnresolved
    } else {
        crate::user_error::IssueCode::from(error.kind())
    };
    let status = crate::crossflash::refusal_status(&error);
    let guidance = if status == crate::crossflash::CompatibilityStatus::Conditional {
        "This supported conversion requires verification of the drive’s original hardware and settings. No firmware was written."
    } else if code.starts_with("pioneer.settings.") {
        "A validated settings mapping is required for this firmware and is unavailable. No firmware was written."
    } else if status == crate::crossflash::CompatibilityStatus::SoftNo {
        "No validated bridge could be prepared for this transition. No firmware was written."
    } else {
        "No firmware was written. Check that the firmware package is complete and compatible with this drive"
    };
    anyhow::Error::new(error)
        .context(format!(
            "Cannot prepare this firmware update [{code}]. {guidance}"
        ))
        .context(issue)
}

// Keep the exact handoff bridge in the existing report collector. After a
// partial update it is the correct Current reference; the original backup has
// the same displayed identity but a different programmer. No desktop files.
pub(super) fn retain_handoff_bridges(plan: &PreparedUpdate) -> Result<()> {
    use pioneer_optical::{envelope::Update, receiver::BridgeKind};
    for (index, stage) in plan.stages().iter().enumerate() {
        if stage.bridge() != Some(BridgeKind::KernelHandoff) {
            continue;
        }
        let kernel = stage
            .kernel_transfer()
            .expect("handoff bridge includes Kernel");
        let normal = stage.normal_transfer();
        let package = Update::load(kernel, normal)?;
        anyhow::ensure!(
            Some(package.kernel().image.as_slice()) == stage.kernel_image()
                && package.normal().image == stage.normal_image(),
            "bridge report package differs from the prepared firmware"
        );
        let mut archive = tar::Builder::new(Vec::new());
        for (name, bytes) in [("kernel.enc", kernel), ("normal.enc", normal)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, name, bytes)?;
        }
        let bytes = archive.into_inner()?;
        let name = format!("pioneer-bridge-stage-{}.tar", index + 1);
        crate::firmware_capture::retain("intermediate", std::path::Path::new(&name), None, &bytes);
        crate::diagnostics::record(format!(
            "Prepared bridge: stage={} package_sha256={}",
            index + 1,
            crate::mediatek_package::digest(&bytes)
        ));
    }
    Ok(())
}

fn execution_error(
    error: pioneer_optical::receiver::ExecutionError<anyhow::Error>,
    restoration_required: bool,
    completed_passes: usize,
) -> anyhow::Error {
    let code = error.code();
    let completed_passes = completed_passes.max(error.completed_stages());
    // Startup parameter writes are device mutations, but do not enter UPDATE.
    // Only expose rollback guidance before any update command or completed pass.
    let startup_issue = if completed_passes == 0 && !error.firmware_write_started() {
        use pioneer_optical::startup::migration::{Error, Rollback};
        match &error {
            pioneer_optical::receiver::ExecutionError::Startup(migration) => {
                match migration.as_ref() {
                    Error::Change { rollback, .. } | Error::Flash { rollback, .. } => {
                        fn guidance<E>(
                            rollback: &Rollback<E>,
                        ) -> Option<crate::user_error::IssueCode> {
                            use crate::user_error::IssueCode;
                            match rollback {
                                Rollback::Restored => Some(IssueCode::StartupSettingRestored),
                                Rollback::Failed(_) => Some(IssueCode::StartupSettingUncertain),
                                Rollback::Settings(results) => {
                                    let outcomes: Vec<_> =
                                        results.iter().filter_map(|(_, r)| guidance(r)).collect();
                                    if outcomes.contains(&IssueCode::StartupSettingUncertain) {
                                        Some(IssueCode::StartupSettingUncertain)
                                    } else if !outcomes.is_empty() {
                                        Some(IssueCode::StartupSettingRestored)
                                    } else {
                                        None
                                    }
                                }
                                Rollback::Unchanged | Rollback::UnsafeAfterFirmwareWrite => None,
                            }
                        }
                        guidance(rollback)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    } else {
        None
    };
    let failure = crate::backend::UpdateFailure {
        phase: error.phase().to_string(),
        write_started: error.write_started(),
        progress: if completed_passes > 0 {
            crate::backend::UpdateProgress::UploadComplete
        } else if error.firmware_write_started() {
            crate::backend::UpdateProgress::PayloadAttempted
        } else {
            crate::backend::UpdateProgress::Preflight
        },
        payload_bytes_accepted: None,
        temporary_firmware: restoration_required && error.firmware_write_started(),
        completed_stages: (1..=completed_passes)
            .map(|pass| format!("Pioneer update pass {pass}"))
            .collect(),
    };
    let error = anyhow::Error::new(error).context(format!("Pioneer update [{code}]; completion was not verified. Keep the pre-flash backup and diagnostic log"));
    let error = match startup_issue {
        Some(issue) => error.context(issue),
        None => error,
    };
    if failure.temporary_firmware {
        error
            .context(
                "the firmware sequence did not complete; the temporary Kernel may remain installed",
            )
            .context(failure)
    } else {
        error.context(failure)
    }
}

struct Runtime<'a, 'd> {
    stage_messages: Vec<String>,
    mode: ExecutionMode,
    device: &'a SharedDevice<'d>,
    sleep: &'a mut dyn FnMut(Duration),
    start: crate::runtime_clock::Clock,
    waited: Duration,
    completed_passes: usize,
    verification: UpdateVerification,
    kernel: style::Progress,
    normal: style::Progress,
}
impl UpdateRuntime for Runtime<'_, '_> {
    fn operation_progress(&mut self, progress: pioneer_optical::operation::Progress) {
        use pioneer_optical::operation::{Component, Phase};
        crate::output::publish(crate::output::Event::Phase {
            phase: match progress.phase {
                Phase::Reading => "reading",
                Phase::Preparing => "preparing",
                Phase::Writing => "writing",
                Phase::Restarting => "restarting",
                Phase::Verifying => "verifying",
            },
            component: match progress.component {
                Component::Firmware => "filter.firmware",
                Component::Kernel => "domain.kernel",
                Component::Normal => "domain.normal",
            },
            done: progress.done,
            total: progress.total,
        });
    }
    fn starting(&mut self, kernel: usize, normal: usize) {
        self.verification.kernel = if kernel == 0 {
            ComponentVerification::NotRequested
        } else {
            ComponentVerification::NotChecked
        };
        self.verification.normal = ComponentVerification::NotChecked;
        self.verification.startup_confirmed = false;
        self.verification.observed_identity = None;
        println!(
            "\n{}",
            style::bold("EXECUTING flash — do not power off or disconnect the drive...")
        );
        self.kernel = style::Progress::new("flashing kernel", kernel);
        self.normal = style::Progress::new("flashing normal", normal);
    }
    fn elapsed(&self) -> Duration {
        self.start.elapsed().max(self.waited)
    }
    fn sleep(&mut self, duration: Duration) {
        self.waited += duration;
        (self.sleep)(duration);
    }
    fn progress(&mut self, role: Role, written: usize, _: usize) {
        match role {
            Role::Kernel => self.kernel.set(written),
            Role::Normal => self.normal.set(written),
        }
    }
    fn entered(&mut self, _: bool) {
        println!("{}", style::dim("  update mode entered"));
    }
    fn poll_failed(&mut self, elapsed: Duration, error: &dyn std::fmt::Debug) {
        crate::diagnostics::record(format!(
            "Pioneer post-flash readiness: elapsed_ms={} error={error:?}",
            elapsed.as_millis()
        ));
    }
}

impl ExecutionRuntime<anyhow::Error> for Runtime<'_, '_> {
    fn verified(&mut self, pass: FlashPass, role: Role, matched: bool) {
        let state = if matched {
            ComponentVerification::Matched
        } else {
            ComponentVerification::Mismatched
        };
        match role {
            Role::Kernel => self.verification.kernel = state,
            Role::Normal => self.verification.normal = state,
        }
        crate::diagnostics::record(format!(
            "Pioneer verification: pass={pass:?} role={role:?} result={state:?}"
        ));
    }
    fn observed_identity(&mut self, pass: FlashPass, id: &pioneer_optical::Identity) {
        self.verification.observed_identity = Some(format!(
            "{} {} {}",
            style::printable(id.vendor()),
            style::printable(id.product()),
            style::printable(id.revision())
        ));
        crate::diagnostics::record(format!(
            "Pioneer identity observed: pass={pass:?} {}",
            self.verification.observed_identity.as_deref().unwrap()
        ));
    }
    fn startup_confirmed(&mut self, pass: FlashPass) {
        self.verification.startup_confirmed = true;
        crate::diagnostics::record(format!("Pioneer Normal startup confirmed: pass={pass:?}"));
    }

    fn verification_unavailable(
        &mut self,
        pass: FlashPass,
        role: Role,
        address: Option<u32>,
        reason: &dyn std::fmt::Debug,
    ) {
        match role {
            Role::Kernel => self.verification.kernel = ComponentVerification::Unavailable,
            Role::Normal => self.verification.normal = ComponentVerification::Unavailable,
        }
        crate::diagnostics::record(format!("Pioneer verification unavailable: pass={pass:?} region={role:?} address={address:?} reason={reason:?}"));
    }

    fn check_pass(&mut self, pass: FlashPass) -> Result<()> {
        self.completed_passes = self.completed_passes.max(pass.completed_stages());
        if self.mode == ExecutionMode::Flash {
            self.device
                .with(|dev| crate::engine::guard_no_medium(dev, true))?;
        }
        if let Some(message) = pass
            .completed_stages()
            .checked_sub(1)
            .and_then(|index| self.stage_messages.get(index))
        {
            println!("{}", style::dim(message));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "flash_tests.rs"]
mod tests;
