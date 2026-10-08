//! Vendor-neutral inspection workflows and report views. Firmware semantics
//! belong to provider libraries; no update session is entered here.
mod capture;
mod compare_report;
mod comparison;
mod pioneer;
mod report;
pub use report::*;

use crate::{drive, engine, platform, workflow};
use anyhow::{Context, Result};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// One immutable source selection. A live source has an explicit capture path.
#[derive(Clone, Debug)]
pub enum Source {
    /// An existing firmware file.
    File(PathBuf),
    /// An existing immutable analysis, reused without I/O.
    Analyzed(Arc<Inspection>),
    /// A live drive, captured once before offline analysis.
    Drive {
        /// Device selector accepted by the regular backup workflow.
        device: String,
        /// New backup path; existing files are never overwritten.
        capture: PathBuf,
    },
}
/// Cooperative cancellation shared with a GUI worker.
#[derive(Clone, Default)]
pub struct Control(Arc<AtomicBool>);
impl Control {
    /// Request cancellation. In-flight transport calls must return first.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    /// Whether cancellation has been requested.
    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    fn check(&self) -> Result<()> {
        if self.cancelled() {
            Err(InspectionError::Cancelled.into())
        } else {
            Ok(())
        }
    }
}
/// Stable application-level inspection errors, suitable for later translation.
#[derive(Debug)]
pub enum InspectionError {
    /// The format is recognized but no analyzer is available.
    UnsupportedFormat(String),
    /// The source cannot be recognized.
    UnrecognizedFormat,
    /// Different provider formats cannot currently be compared.
    UnsupportedPair,
    /// A Pioneer envelope must be supplied in its package.
    PackageRequired,
    /// The caller cancelled.
    Cancelled,
    /// Two live sources were selected.
    TwoDrives,
}
impl InspectionError {
    /// Stable diagnostic code, independent of English wording.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedFormat(_) => "inspect.unsupported_format",
            Self::UnrecognizedFormat => "inspect.unrecognized_format",
            Self::UnsupportedPair => "compare.unsupported_pair",
            Self::PackageRequired => "inspect.package_required",
            Self::Cancelled => "inspect.cancelled",
            Self::TwoDrives => "compare.two_drives",
        }
    }
}
impl std::fmt::Display for InspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormat(format) => write!(
                f,
                "Detailed firmware inspection and comparison are not yet supported for {format}."
            ),
            Self::UnrecognizedFormat => f.write_str("This firmware format was not recognized."),
            Self::UnsupportedPair => {
                f.write_str("These firmware formats cannot currently be compared.")
            }
            Self::PackageRequired => f.write_str(
                "For Pioneer inspection, select the TAR package containing the firmware.",
            ),
            Self::Cancelled => f.write_str("Firmware analysis cancelled."),
            Self::TwoDrives => {
                f.write_str("Select two firmware files, or one firmware file and one drive.")
            }
        }
    }
}
impl std::error::Error for InspectionError {}

/// Inspect one file or capture. File inspection performs no drive discovery.
pub fn inspect(source: &Source, control: &Control) -> Result<Arc<Inspection>> {
    crate::diagnostics::run("inspect", || load_source(source, control))
}
fn load_source(source: &Source, control: &Control) -> Result<Arc<Inspection>> {
    control.check()?;
    if let Source::Analyzed(analysis) = source {
        return Ok(analysis.clone());
    }
    inspect_inner(source, control).map(Arc::new)
}
fn inspect_inner(source: &Source, control: &Control) -> Result<Inspection> {
    control.check()?;
    match source {
        Source::Analyzed(_) => unreachable!("retained analyses are handled by load_source"),
        Source::File(path) => {
            let bytes = workflow::read_capped(path)?;
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            pioneer::inspect_file(name, &bytes, control)
        }
        Source::Drive { device, capture } => {
            let selector = workflow::resolve_device(Some(device))?;
            let mut opened = platform::open(&selector, false)?;
            let mut dev = capture::CancellableDevice {
                device: opened.as_mut(),
                control,
            };
            let resolved = drive::resolve_backend(&mut dev)?
                .context("Drive protocol could not be identified")?;
            let family = resolved.evidence.family;
            if family != drive::Family::Pioneer {
                return Err(InspectionError::UnsupportedFormat(family.to_string()).into());
            }
            control.check()?;
            let state = pioneer::live_state(&mut dev);
            let handler = drive::for_family(family);
            engine::backup_with_replace(&mut dev, handler.as_ref(), capture, false, false, false)?;
            drop(opened);
            control.check()?;
            let mut inspection = inspect_inner(&Source::File(capture.clone()), control)?;
            inspection.live = Some(state);
            Ok(inspection)
        }
    }
}
/// Compare two sources, with files validated before any live capture.
pub fn compare(a: &Source, b: &Source, control: &Control) -> Result<ComparisonReport> {
    crate::diagnostics::run("compare", || {
        if matches!((a, b), (Source::Drive { .. }, Source::Drive { .. })) {
            return Err(InspectionError::TwoDrives.into());
        }
        let (left, right) = if matches!(a, Source::Drive { .. }) {
            let right = load_source(b, control).context("Source B")?;
            (load_source(a, control).context("Source A")?, right)
        } else {
            let left = load_source(a, control).context("Source A")?;
            (left, load_source(b, control).context("Source B")?)
        };
        compare_inspections(left, right, control)
    })
}
/// Compare retained analyses without recapturing or rereading either source.
pub fn compare_inspections(
    left: Arc<Inspection>,
    right: Arc<Inspection>,
    control: &Control,
) -> Result<ComparisonReport> {
    control.check()?;
    compare_report::compare(left, right, control)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
