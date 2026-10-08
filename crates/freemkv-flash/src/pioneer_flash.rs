//! App adapter for the library's OEM update sequence.
//!
//! Owns tray policy, user progress and error guidance. The library owns command
//! ordering, revision gating, transfer chunks, settle timing and readiness.

#[cfg(test)]
use crate::drive::pioneer::FLASH_CHUNK;
use crate::drive::pioneer::{transfer, CONTROL_LEN};
use crate::drive::pioneer_transport::{self as transport, flash_err, ScsiTransport, SharedDevice};
use crate::platform::ScsiDevice;
use crate::style;
use anyhow::{anyhow, bail, Context, Result};
use pioneer_optical::drive::{
    execute_update, UpdateError, UpdateOptions, UpdateRuntime, UpdateTransfer,
};
use pioneer_optical::{DriveClass, Identity, Role};
use std::time::{Duration, Instant};

const PARTIAL_HINT: &str = " — the drive may now hold a partial firmware; re-flash the captured pre-flash backup to restore it";

/// The drive dialect an update session must speak. Taken from the drive's own
/// identity (`drive::identify` -> `Identity::class`) when that identity is
/// unambiguous: a `BD-*` product, or a `DVD-R*` product on a `DVR*` platform.
///
/// FALLBACK (`--recover` ONLY): an identity that cannot be read (a degraded
/// drive) or that is neither of those is ambiguous. If the target Normal
/// profiles as a known family (`target_family_known`, from
/// `pioneer_optical::image::family` on its decoded body) the flash is a
/// BD-generation image, so assume [`DriveClass::Bd`] — the `04/FF`-only entry,
/// which is the only flash route validated on hardware. A normal (non-recover)
/// flash never guesses: an unreadable/ambiguous identity is refused before any
/// write, as is a recover flash with no family to lean on.
fn resolve_class(
    identity: Result<Identity>,
    target_family_known: bool,
    recover: bool,
) -> Result<DriveClass> {
    if let Some(class) = identity.as_ref().ok().and_then(Identity::class) {
        return Ok(class);
    }
    if recover && target_family_known {
        println!(
            "{}",
            style::dim("  drive class not reported; target is a known BD family, assuming Bd")
        );
        return Ok(DriveClass::Bd);
    }
    match identity {
        Err(error) => Err(error).context(
            "could not read the drive identity to choose the update dialect (a guess is only \
             made under --recover, for a recognised BD family); refusing before any write",
        ),
        Ok(_) => bail!(
            "the drive does not identify as a BD or DVR generation (a guess is only made under \
             --recover, for a recognised BD family); refusing before any write"
        ),
    }
}

/// Execute one prepared update pass after the final tray guard.
/// The caller owns captured receiver evidence and any required restoration.
pub(crate) fn execute_flash(
    dev: &mut dyn ScsiDevice,
    control: &[u8; CONTROL_LEN],
    kernel: Option<&[u8]>,
    normal: &[u8],
    recover: bool,
    force: bool,
) -> Result<()> {
    let kernel_transfer = kernel.map(transfer::select_kernel).transpose()?;
    let kernel = match kernel_transfer.as_ref() {
        Some(transfer::KernelTransfer::LinearFe(bytes)) => Some(*bytes),
        Some(transfer::KernelTransfer::PreparedFe(bytes)) => Some(bytes.as_slice()),
        None => None,
    };
    crate::engine::guard_no_medium(dev, true, force || recover)?;
    let shared = SharedDevice::new(dev);
    let class = resolve_class(
        transport::identify_on(&shared),
        crate::pioneer_flash_plan::normal_family(normal).is_some(),
        recover,
    )?;
    let mut port = ScsiTransport::flash(&shared);
    let mut runtime = Runtime {
        start: Instant::now(),
        kernel: style::Progress::new("flashing kernel", kernel.map_or(0, <[u8]>::len)),
        normal: style::Progress::new("flashing normal", normal.len()),
    };
    execute_update(
        &mut port,
        &mut runtime,
        control,
        UpdateTransfer { kernel, normal },
        UpdateOptions { class, recover },
    )
    .map_err(update_error)
}

struct Runtime {
    start: Instant,
    kernel: style::Progress,
    normal: style::Progress,
}
impl UpdateRuntime for Runtime {
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
    fn entered(&mut self, recover: bool) {
        println!(
            "{}",
            style::dim(if recover {
                "  update mode entered (recover: identity gate skipped)"
            } else {
                "  update mode entered"
            })
        );
    }
    fn poll_failed(&mut self, elapsed: Duration, error: &dyn std::fmt::Debug) {
        crate::diagnostics::record(format!(
            "Pioneer post-flash readiness: elapsed_ms={} error={error:?}",
            elapsed.as_millis()
        ));
    }
}

fn update_error(error: UpdateError<anyhow::Error>) -> anyhow::Error {
    match error {
        UpdateError::Entry(source) => flash_err(source).context("OEM Entry write failed"),
        UpdateError::EntryStateRead(source) => flash_err(source).context("post-entry INQUIRY"),
        UpdateError::EntryState { revision } => anyhow!("drive did not report the expected post-entry update state (revision bytes {revision:02x?}); aborting before any transfer"),
        UpdateError::Transfer { role, offset, length, source } => flash_err(source).context(format!("OEM {role:?} write failed at offset {offset:#x}, length {length}{PARTIAL_HINT}")),
        UpdateError::Finish(source) => flash_err(source).context(format!("OEM Finish write failed{PARTIAL_HINT}")),
        UpdateError::ReadyTimeout(source) => flash_err(source).context("drive did not return ready within the post-flash poll timeout"),
        other => anyhow!("{other}"),
    }
}

#[cfg(test)]
#[path = "pioneer_flash_tests.rs"]
mod tests;
