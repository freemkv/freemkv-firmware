//! Shared application workflows for the CLI and desktop front-end.

use crate::backend::{
    registry, unsupported_family_error, Backend, BackendId, Capabilities, Descriptor, FlashRequest,
    Match, ReadDevice, UNKNOWN_FAMILY,
};
pub use crate::backend::{AuthorizedPlan, Confirm};
/// Inspection inputs and results, so a front-end needs only this module and
/// [`crate::report`] to run Inspect and Compare.
pub use crate::inspection::{
    ComparisonReport, ComponentView, Control, Field, HardwareFamily, Inspection, Source,
};
use crate::manifest::FlashMode;
/// The event stream every workflow writes to, which a front-end subscribes to.
pub use crate::output::{capture_events, Event};
use crate::{engine, platform, style};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One optical drive, discovered even when its tray is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveChoice {
    /// Transport selector accepted by the platform backend: the drive's id.
    pub path: String,
    /// The name the OS shows users (`E:`, `/dev/sr1`, `disk4`); the id when it has none.
    pub name: String,
    /// Human-readable model and revision.
    pub label: String,
}

impl DriveChoice {
    /// The name and model, which tell identical drives apart.
    pub fn display(&self) -> String {
        format!("{}  {}", self.name, self.label)
    }

    /// One `list` line: the display, plus the id when it differs from the name.
    fn list_line(&self) -> String {
        if self.name == self.path {
            self.display()
        } else {
            format!("{}  {}", self.display(), self.path)
        }
    }
}

/// Enumerate actual optical drives through the same platform API on every front-end.
pub fn drives() -> Vec<DriveChoice> {
    platform::list_drives()
        .into_iter()
        .map(|d| DriveChoice {
            label: format!(
                "{} {} (rev {})",
                style::printable(&d.vendor),
                style::printable(&d.model),
                style::printable(&d.firmware)
            ),
            name: d.display_name,
            path: d.path,
        })
        .collect()
}

/// [`drives`] with a diagnostic log, as a front-end's discovery.
pub fn discover() -> Vec<DriveChoice> {
    crate::diagnostics::run("drive discovery", || Ok(drives())).unwrap_or_default()
}

/// Inspect a firmware file, a retained analysis or a live drive capture.
pub fn inspect(source: &Source, control: &Control) -> Result<Arc<Inspection>> {
    crate::inspection::inspect(source, control)
}

/// Compare two sources region by region.
pub fn compare(a: &Source, b: &Source, control: &Control) -> Result<ComparisonReport> {
    crate::inspection::compare(a, b, control)
}

/// Flash options shared by both front-ends. Defaults are a backed-up dry run.
#[derive(Clone, Debug, Default)]
pub struct FlashOptions {
    /// Optional device selector; omission selects the sole attached drive.
    pub device: Option<String>,
    /// Firmware or backup input.
    pub input: PathBuf,
    /// Explicit backup destination; otherwise derive one next to the input.
    pub backup: Option<PathBuf>,
    /// Issue firmware writes instead of previewing the plan.
    pub execute: bool,
    /// Explicit acknowledgement of the flash risk.
    pub acknowledged_risk: bool,
}

/// Inspect a local firmware file without drive discovery or transport access.
pub fn check_file(path: &Path) -> Result<()> {
    crate::diagnostics::run("check-file", || check_file_inner(path))
}

fn check_file_inner(path: &Path) -> Result<()> {
    engine::info_file(path)
}

/// Inspect a drive or a local firmware image.
pub fn info(target: Option<&str>) -> Result<()> {
    crate::diagnostics::run("info", || info_inner(target))
}

fn info_inner(target: Option<&str>) -> Result<()> {
    // A regular file is a firmware image → classify the FILE (no drive needed);
    // anything else (a selector, a /dev node, or nothing) → probe the DRIVE.
    if let Some(t) = target {
        if is_firmware_file(t) {
            return engine::info_file(Path::new(t));
        }
    }
    let selector = resolve_device(target)?;
    let mut dev = platform::open(&selector, false)?;
    let backend = resolved_backend(dev.as_mut())?;
    engine::info(dev.as_mut(), backend)
}

/// Turn an optional user selector into a concrete device selector.
/// - a drive's name from `list` (`E:`, `/dev/sr1`, `disk4`) → that drive's id
/// - any other string → used verbatim as the id (`\\.\CdRomN`, a `/dev` path or an `ioreg:` id)
/// - `None` → the only connected drive, or an error listing the choices
pub fn resolve_device(arg: Option<&str>) -> Result<String> {
    resolve_from(arg, &drives())
}

fn resolve_from(arg: Option<&str>, drives: &[DriveChoice]) -> Result<String> {
    if let Some(a) = arg {
        return Ok(drives
            .iter()
            .find(|d| d.name == a)
            .map_or_else(|| a.to_string(), |d| d.path.clone()));
    }
    match drives {
        [] => bail!("no optical drive found (is one connected and powered on?)"),
        [only] => Ok(only.path.clone()),
        many => {
            let choices = many
                .iter()
                .map(|d| format!("  {}", d.list_line()))
                .collect::<Vec<_>>()
                .join("\n");
            bail!("multiple drives found — pass a drive name or id:\n{choices}")
        }
    }
}

/// Route the `info` argument: a path that exists as a **regular file** is a
/// firmware image (file info); a SCSI **device node** (`/dev/sg*`, a char/block
/// device) or a nonexistent path is a live drive to probe. Firmware images are
/// regular files and device nodes are not, so the two split cleanly with no flag.
fn is_firmware_file(target: &str) -> bool {
    std::fs::metadata(target)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Resolve the backend registry while preserving probe and ambiguity errors.
fn resolved_backend(dev: &mut dyn platform::ScsiDevice) -> Result<Option<&'static dyn Backend>> {
    Ok(registry::resolve(dev)?.map(|resolved| resolved.backend))
}

/// Resolve a backend that offers `capability`, else the unsupported error.
fn resolve_capable(
    dev: &mut dyn platform::ScsiDevice,
    capability: fn(&Capabilities) -> bool,
) -> Result<&'static dyn Backend> {
    match resolved_backend(dev)? {
        Some(backend) if capability(&Capabilities::of(backend)) => Ok(backend),
        Some(backend) => Err(unsupported_family_error(backend.descriptor().display_name)),
        None => Err(unsupported_family_error(UNKNOWN_FAMILY)),
    }
}

/// Resolve a backend with a supported flash operation.
pub fn classify_gated(dev: &mut dyn platform::ScsiDevice) -> Result<BackendId> {
    Ok(resolve_capable(dev, |c| c.flash)?.descriptor().id)
}

/// What a drive is and what the tool can do with it.
#[derive(Debug)]
pub struct DriveProfile {
    /// Device-reported identity.
    pub identity: crate::backend::Identity,
    /// The backend whose probe matched, and its evidence.
    pub backend: Option<(&'static Descriptor, Match)>,
    /// The backend that identified the receiver for recovery; offered even
    /// when no probe matched.
    pub recovery: Option<&'static Descriptor>,
    /// What the matched backend offers.
    pub capabilities: Capabilities,
    /// How a backup is named, when one can be captured.
    pub backup_format: Option<crate::backend::BackupFormat>,
    /// The file formats a flash accepts.
    pub flash_formats: &'static [crate::backend::FileFormat],
}

/// Probe `device` read-only and ask every recovery backend whether it knows
/// the receiver. An unsupported drive is a profile, not an error.
pub fn profile(device: &str) -> Result<DriveProfile> {
    crate::diagnostics::run("profile", || {
        let selector = resolve_device(Some(device))?;
        let mut dev = platform::open(&selector, false)?;
        profile_on(dev.as_mut())
    })
}

/// [`profile`] on an open device.
pub fn profile_on(dev: &mut dyn platform::ScsiDevice) -> Result<DriveProfile> {
    let resolved = registry::resolve(dev)?;
    let identity = match &resolved {
        Some(r) => r.identity.clone(),
        None => crate::backend::read_identity(&mut ReadDevice::new(dev, &[])),
    };
    // Identification errors only mean "not offered": a profile never fails
    // merely because a drive is unsupported.
    let recovery = registry::backends().find_map(|b| {
        let facet = b.recovery()?;
        let found = facet.identify(&mut ReadDevice::new(dev, b.allowed_data_out()));
        matches!(found, Ok(Some(_))).then(|| b.descriptor())
    });
    let backend = resolved.as_ref().map(|r| r.backend);
    Ok(DriveProfile {
        identity,
        capabilities: backend.map_or(Capabilities::NONE, Capabilities::of),
        backup_format: backend.and_then(|b| b.backup()).map(|b| b.format()),
        flash_formats: match backend {
            Some(b) if b.flash().is_some() => b.descriptor().formats,
            _ => &[],
        },
        backend: resolved.map(|r| (r.backend.descriptor(), r.matched)),
        recovery,
    })
}

/// The drive's `info` rows, without showing them.
pub fn details(device: &str) -> Result<crate::report::Report> {
    crate::diagnostics::run("details", || {
        let selector = resolve_device(Some(device))?;
        let mut dev = platform::open(&selector, false)?;
        let backend = resolved_backend(dev.as_mut())?;
        Ok(engine::info_report(dev.as_mut(), backend).report)
    })
}

/// Print the optical drives, by the name or id every operation accepts.
pub fn list() -> Result<()> {
    crate::diagnostics::run("list", list_inner)
}

fn list_inner() -> Result<()> {
    let drives = drives();
    if drives.is_empty() {
        println!("drives: none found");
    }
    for drive in &drives {
        println!("{}", drive.list_line());
    }
    Ok(())
}

/// Capture a backend backup or a salvage dump.
pub fn backup(device: Option<&str>, out: Option<PathBuf>, dump: bool) -> Result<()> {
    backup_with_replace(device, out, dump, false)
}

/// Capture to a save-dialog destination; replacement requires explicit caller consent.
pub fn backup_with_replace(
    device: Option<&str>,
    out: Option<PathBuf>,
    dump: bool,
    replace: bool,
) -> Result<()> {
    crate::diagnostics::run("backup/dump", || {
        backup_with_replace_inner(device, out, dump, replace)
    })
}

fn backup_with_replace_inner(
    device: Option<&str>,
    out: Option<PathBuf>,
    dump: bool,
    replace: bool,
) -> Result<()> {
    crate::diagnostics::record(format!(
        "backup options: device={device:?} output={out:?} dump={dump} replace={replace}"
    ));
    // Dump may enable RAM-only logging after capture; backup needs only reads.
    let selector = resolve_device(device)?;
    let mut dev = if dump {
        platform::open(&selector, true).or_else(|_| platform::open(&selector, false))?
    } else {
        platform::open(&selector, false)?
    };
    let handler = if dump {
        resolve_capable(dev.as_mut(), |c| c.dump)?
    } else {
        resolve_capable(dev.as_mut(), |c| c.backup)?
    };
    let out = match out {
        Some(o) => o,
        None => {
            let id = handler.identity(&mut ReadDevice::new(
                dev.as_mut(),
                handler.allowed_data_out(),
            ));
            default_backup_name(&id, handler.backup().map(|b| b.format()), dump)?
        }
    };
    engine::backup_with_replace(dev.as_mut(), handler, &out, dump, replace)
}

/// The default backup or dump file name: `<model>_<rev>.<infix>.<extension>`
/// from the backend's format, or `<model>_<rev>.dump.bin` for a raw dump (a
/// flat memory image, not a backup archive). The name carries no chipset.
pub fn default_backup_name(
    id: &crate::backend::Identity,
    format: Option<crate::backend::BackupFormat>,
    dump: bool,
) -> Result<PathBuf> {
    let stem: String = format!("{}_{}", id.product, id.revision)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    match format {
        _ if dump => Ok(PathBuf::from(format!("{stem}.dump.bin"))),
        Some(format) => Ok(PathBuf::from(format!(
            "{stem}.{}.{}",
            format.infix, format.extension
        ))),
        None => bail!("backend has no backup format"),
    }
}

/// Validate and execute the shared flash workflow. `confirm` answers the
/// backend's confirmation once the backup is saved and every installed-firmware
/// gate has passed.
pub fn flash(args: FlashOptions, confirm: &mut dyn Confirm) -> Result<()> {
    crate::diagnostics::run("flash", || flash_inner(args, confirm))
}

fn flash_inner(args: FlashOptions, confirm: &mut dyn Confirm) -> Result<()> {
    crate::diagnostics::record(format!(
        "flash options: input={:?} backup={:?} execute={} acknowledged_risk={}",
        args.input, args.backup, args.execute, args.acknowledged_risk
    ));
    if args.execute && !args.acknowledged_risk {
        bail!("refusing to flash without acknowledging the risk");
    }
    let (mut dev, handler, req) = open_flash(&args)?;
    engine::flash(dev.as_mut(), handler, &req, confirm)
}

/// The read-only first stage for a front-end to show before asking for
/// consent: the dry run's checks and plan as text. Needs no backup.
pub fn plan_flash(args: &FlashOptions) -> Result<Vec<String>> {
    crate::diagnostics::run("flash plan", || {
        let args = FlashOptions {
            execute: false,
            ..args.clone()
        };
        let (mut dev, handler, req) = open_flash(&args)?;
        engine::preview_flash(dev.as_mut(), handler, &req)
    })
}

/// Open the drive, resolve its flash backend and build the request.
fn open_flash(
    args: &FlashOptions,
) -> Result<(
    Box<dyn platform::ScsiDevice>,
    &'static dyn Backend,
    FlashRequest,
)> {
    let input = read_capped(&args.input)
        .with_context(|| format!("reading input {}", args.input.display()))?;
    let selector = resolve_device(args.device.as_deref())?;
    let mut dev = platform::open(&selector, args.execute)?;
    let handler = resolve_capable(dev.as_mut(), |c| c.flash)?;
    let input_format = registry::flash_input_format(handler, &args.input, &input)?
        .context("backend reads no firmware files")?;
    let unlocks = handler.allowed_data_out();
    let drive_model = handler
        .identity(&mut ReadDevice::new(dev.as_mut(), unlocks))
        .product;
    let predump_out = args.backup.clone().or_else(|| {
        handler
            .backup()
            .and_then(|b| default_backup_path(&args.input, b.format().extension))
    });
    let req = FlashRequest {
        input,
        input_format,
        mode: FlashMode::Full,
        execute: args.execute,
        acknowledged_risk: args.acknowledged_risk,
        enc_override: None,
        drive_model,
        verbose: false,
        predump_out,
    };
    Ok((dev, handler, req))
}

/// Consent a front-end collected before the job started (the GUI's sheet).
pub struct Preconfirmed;

impl Confirm for Preconfirmed {
    fn confirm(&mut self, _plan: &AuthorizedPlan) -> Result<bool> {
        Ok(true)
    }
}

/// Read a firmware input file with a hard size cap, so a huge file or an endless
/// source (e.g. `/dev/zero`, a FIFO) cannot exhaust memory before the per-family
/// size validation runs. The cap is far above any real firmware/backup artifact
/// (largest Pioneer envelope is ~4.5 MiB; an MTK image 2 MiB).
pub fn read_capped(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    const MAX_INPUT: u64 = 64 * 1024 * 1024;
    crate::diagnostics::record(format!(
        "input file: opening path={path:?} maximum_bytes={MAX_INPUT}"
    ));
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(MAX_INPUT + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_INPUT {
        bail!(
            "input {} exceeds the {} MiB cap for a firmware file; refusing to load",
            path.display(),
            MAX_INPUT / (1024 * 1024)
        );
    }
    use sha2::{Digest, Sha256};
    crate::diagnostics::record(format!(
        "input file: path={path:?} bytes={} sha256={:x}",
        buf.len(),
        Sha256::digest(&buf)
    ));
    Ok(buf)
}

/// Default pre-flash backup path: `<input>.preflash.backup.<backend-extension>`.
fn default_backup_path(input: &Path, extension: &str) -> Option<PathBuf> {
    let name = input.file_name()?;
    for number in 0u64.. {
        let mut filename = name.to_os_string();
        let suffix = if number == 0 {
            String::new()
        } else {
            format!(".{number}")
        };
        filename.push(format!(".preflash.backup{suffix}.{extension}"));
        let candidate = input.with_file_name(filename);
        match candidate.symlink_metadata() {
            Ok(_) => continue,
            Err(_) => return Some(candidate),
        }
    }
    None
}

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;

/// Receiver reference used by Recovery. Reading the drive is always explicit.
#[derive(Clone, Debug)]
pub enum CurrentFirmware {
    /// User-supplied copy of the receiver's firmware; no firmware reads.
    File(PathBuf),
    /// Read firmware into memory for protocol analysis; do not save a backup.
    ReadFromDrive,
}

/// Recovery inputs shared by CLI and GUI.
#[derive(Clone, Debug)]
pub struct RecoveryOptions {
    /// Device selector.
    pub device: Option<String>,
    /// Firmware to write, including Kernel and Normal.
    pub input: PathBuf,
    /// Where to obtain the current receiver's firmware.
    pub current: CurrentFirmware,
    /// Issue writes; otherwise prepare without writing.
    pub execute: bool,
    /// Explicit acknowledgement of firmware-update risk.
    pub acknowledged_risk: bool,
}

/// Recover without automatic backups or installed-versus-target policy gates.
pub fn recover(args: RecoveryOptions) -> Result<()> {
    crate::diagnostics::run("recovery", || {
        if args.execute && !args.acknowledged_risk {
            bail!("refusing recovery without acknowledging the risk");
        }
        crate::diagnostics::record(format!("recovery options: {args:?}"));
        let target = read_capped(&args.input)?;
        let supplied = match &args.current {
            CurrentFirmware::File(path) => Some(read_capped(path)?),
            CurrentFirmware::ReadFromDrive => None,
        };
        let selector = resolve_device(args.device.as_deref())?;
        let mut dev = platform::open(&selector, args.execute)?;
        // Recovery serves drives too damaged to classify: no protocol probe,
        // each recovery backend identifies the receiver itself.
        let mut refusal = None;
        for backend in registry::backends() {
            let Some(facet) = backend.recovery() else {
                continue;
            };
            let unlocks = backend.allowed_data_out();
            if let Some(receiver) = facet.identify(&mut ReadDevice::new(dev.as_mut(), unlocks))? {
                return engine::recover_identified(
                    dev.as_mut(),
                    backend,
                    Some(receiver),
                    supplied.as_deref(),
                    &target,
                    args.execute,
                    args.acknowledged_risk,
                );
            }
            refusal.get_or_insert(facet.unidentified());
        }
        bail!(refusal.unwrap_or("no protocol backend offers recovery for this drive"))
    })
}
