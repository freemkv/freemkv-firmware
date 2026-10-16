//! App adapter for the library's OEM update sequence.
//!
//! Owns tray policy, user progress and error guidance. The library owns command
//! ordering, revision gating, transfer chunks, settle timing and readiness.

#[cfg(test)]
use crate::backends::pioneer::FLASH_CHUNK;

use crate::backend::WriteDevice;
use crate::style;
use crate::transport::{self as transport, flash_err, ScsiTransport, SharedDevice};
use anyhow::{anyhow, bail, Context, Result};
use pioneer_optical::drive::{UpdateError, UpdateOptions, UpdateRuntime};
use pioneer_optical::receiver::{
    FlashError, FlashPass, FlashRuntime, FlashTransport, PreparedNormal, PreparedUpdate,
};
use pioneer_optical::{CodedError, DriveClass, Identity, Role};
use std::time::{Duration, Instant};

const PARTIAL_HINT: &str = " — the drive may now hold a partial firmware; re-flash the captured pre-flash backup to restore it";

/// The drive dialect an update session must speak, taken from the drive's own
/// identity (`drive::identify` -> `Identity::class`): a `BD-*` product, or a
/// `DVD-R*` product on a `DVR*` platform. An unreadable or ambiguous identity
/// is refused before any write; the dialect is never guessed.
fn resolve_class(identity: Result<Identity>) -> Result<DriveClass> {
    if let Some(class) = identity.as_ref().ok().and_then(Identity::class) {
        return Ok(class);
    }
    match identity {
        Err(error) => Err(error).context(
            "could not read the drive identity to choose the update dialect; refusing before \
             any write",
        ),
        Ok(_) => bail!(
            "the drive does not identify as a BD or DVR generation; refusing before any write"
        ),
    }
}

/// A validated library plan selected by the app's input routing.
pub(crate) enum PreparedFlash<'a> {
    Complete(&'a PreparedUpdate),
    Normal(&'a PreparedNormal),
}

pub(crate) fn execute_prepared(dev: &mut WriteDevice<'_>, plan: PreparedFlash<'_>) -> Result<()> {
    let shared = SharedDevice::new(dev);
    let mut reads = ScsiTransport::reads(&shared);
    let mut writes = ScsiTransport::flash(&shared);
    let io = FlashTransport {
        reads: &mut reads,
        writes: &mut writes,
    };
    let mut runtime = Runtime {
        start: Instant::now(),
        kernel: style::Progress::new("flashing kernel", 0),
        normal: style::Progress::new("flashing normal", 0),
        device: &shared,
    };
    match plan {
        PreparedFlash::Complete(plan) => plan.flash(io, &mut runtime),
        PreparedFlash::Normal(plan) => plan.flash(io, &mut runtime),
    }
    .map_err(prepared_error)
}

pub(crate) fn preparation_error<E>(error: E) -> anyhow::Error
where
    E: std::error::Error + Send + Sync + CodedError + 'static,
{
    let code = error.code();
    let status = crate::crossflash::refusal_status(&error);
    let guidance = if status == crate::crossflash::CompatibilityStatus::SoftNo {
        "Intermediate transfer is required but not implemented. No firmware was written."
    } else {
        "No firmware was written. Check that the firmware package is complete and compatible with this drive"
    };
    anyhow::Error::new(error).context(format!(
        "Cannot prepare this firmware update [{code}]. {guidance}"
    ))
}

fn prepared_error(error: FlashError<anyhow::Error>) -> anyhow::Error {
    let code = error.code();
    let restoration = matches!(
        &error,
        FlashError::Preflight {
            pass: FlashPass::Restoration,
            ..
        } | FlashError::DescriptorRead {
            pass: FlashPass::Restoration,
            ..
        } | FlashError::DescriptorChanged {
            pass: FlashPass::Restoration
        } | FlashError::DescriptorMismatch {
            pass: FlashPass::Restoration
        } | FlashError::Update {
            pass: FlashPass::Restoration,
            ..
        } | FlashError::Readback {
            pass: FlashPass::Restoration,
            ..
        } | FlashError::ReadbackMismatch {
            pass: FlashPass::Restoration,
            ..
        }
    );
    let error = match error {
        FlashError::Preflight { pass, source } => {
            source.context(format!("{pass:?} flash preflight refused"))
        }
        FlashError::DescriptorRead { pass, source } => flash_err(source).context(format!(
            "{pass:?} receiver descriptor read failed; update entry was not attempted"
        )),
        FlashError::Update { pass, source } => {
            update_error(source).context(format!("{pass:?} flash pass failed"))
        }
        FlashError::Readback { pass, source } => flash_err(source).context(format!(
            "{pass:?} Kernel readback failed; drive state is not verified{PARTIAL_HINT}"
        )),
        error @ FlashError::ReadbackMismatch { .. } => anyhow::Error::new(error)
            .context(format!("Kernel readback did not verify{PARTIAL_HINT}")),
        error @ (FlashError::DescriptorChanged { .. } | FlashError::DescriptorMismatch { .. }) => anyhow::Error::new(error)
            .context("the live drive no longer matches the captured firmware; this update pass was not started. Capture a fresh backup and retry"),
        error => anyhow::Error::new(error),
    };
    let error = error.context(format!("[{code}]"));
    if restoration {
        error.context("pristine Kernel restoration did not complete; the temporary Kernel may remain installed. Re-flash the captured pre-flash backup to restore the drive")
    } else {
        error
    }
}

struct Runtime<'a, 'd> {
    device: &'a SharedDevice<'d>,
    start: Instant,
    kernel: style::Progress,
    normal: style::Progress,
}
impl UpdateRuntime for Runtime<'_, '_> {
    fn starting(&mut self, kernel: usize, normal: usize) {
        println!(
            "\n{}",
            style::bold("EXECUTING flash — do not power off or disconnect the drive...")
        );
        self.kernel = style::Progress::new("flashing kernel", kernel);
        self.normal = style::Progress::new("flashing normal", normal);
    }
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
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

impl FlashRuntime<anyhow::Error> for Runtime<'_, '_> {
    fn prepare_pass(&mut self, pass: FlashPass) -> Result<UpdateOptions> {
        self.device
            .with(|dev| crate::engine::guard_no_medium(dev, true))?;
        let class = resolve_class(transport::identify_on(self.device))?;
        if pass == FlashPass::Restoration {
            println!("{}", style::dim("restoring the unmodified target Kernel"));
        }
        // The library's degraded-receiver mode is never requested.
        Ok(UpdateOptions {
            class,
            recover: false,
        })
    }
}

fn update_error(error: UpdateError<anyhow::Error>) -> anyhow::Error {
    let code = error.code();
    let result = match error {
        UpdateError::Entry(source) => flash_err(source).context("could not enter firmware update mode; no firmware data was transferred. Check the connection and save the diagnostic log before retrying"),
        UpdateError::EntryStateRead(source) => flash_err(source).context("could not confirm firmware update mode; no firmware data was transferred. Check the connection and save the diagnostic log before retrying"),
        UpdateError::EntryState { revision } => anyhow!("drive did not report the expected post-entry update state (revision bytes {revision:02x?}); aborting before any transfer"),
        UpdateError::Transfer { role, offset, length, source } => flash_err(source).context(format!("OEM {role:?} write failed at offset {offset:#x}, length {length}{PARTIAL_HINT}")),
        UpdateError::Finish(source) => flash_err(source).context(format!("OEM Finish write failed{PARTIAL_HINT}")),
        UpdateError::ReadyTimeout(source) => flash_err(source).context("firmware data was transferred, but the drive did not return ready within the post-flash poll timeout; completion could not be verified. Keep the captured pre-flash backup and diagnostic log for recovery"),
        other => anyhow::Error::new(other),
    };
    result.context(format!("[{code}]"))
}

#[cfg(test)]
#[path = "flash_tests.rs"]
mod tests;
