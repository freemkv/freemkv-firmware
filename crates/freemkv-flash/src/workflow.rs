//! Shared application workflows for the CLI and desktop front-end.

use crate::backend::{
    registry, unsupported_family_error, Backend, BackendId, Capabilities, FlashRequest, ReadDevice,
    UNKNOWN_FAMILY,
};
use crate::manifest::FlashMode;
use crate::{engine, platform, style};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

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
            let s: String = format!("{}_{}", id.product, id.revision)
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            match handler.backup().map(|b| b.format()) {
                // A dump is a single flat memory image, not a backup archive.
                _ if dump => PathBuf::from(format!("{s}.dump.bin")),
                // Filename infix (`backup` / `candidate`) comes from the backend,
                // so the CLI names no chipset.
                Some(format) => PathBuf::from(format!("{s}.{}.{}", format.infix, format.extension)),
                None => bail!("backend has no backup format"),
            }
        }
    };
    engine::backup_with_replace(dev.as_mut(), handler, &out, dump, replace)
}

/// Validate and execute the shared flash workflow.
pub fn flash(args: FlashOptions) -> Result<()> {
    crate::diagnostics::run("flash", || flash_inner(args))
}

fn flash_inner(args: FlashOptions) -> Result<()> {
    crate::diagnostics::record(format!(
        "flash options: input={:?} backup={:?} execute={} acknowledged_risk={}",
        args.input, args.backup, args.execute, args.acknowledged_risk
    ));
    if args.execute && !args.acknowledged_risk {
        bail!("refusing to flash without acknowledging the risk");
    }

    let input = read_capped(&args.input)
        .with_context(|| format!("reading input {}", args.input.display()))?;
    let selector = resolve_device(args.device.as_deref())?;
    let mut dev = platform::open(&selector, args.execute)?;
    let handler = resolve_capable(dev.as_mut(), |c| c.flash)?;
    let input_format = registry::flash_input_format(handler, &args.input, &input)
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
        allow_crossflash: false,
    };
    engine::flash(dev.as_mut(), handler, &req)
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
        // Recovery serves drives too damaged to classify, so it does not run the
        // protocol probe: each backend with a recovery path checks the receiver
        // itself.
        let Some(backend) = registry::backends().find(|b| b.recovery().is_some()) else {
            bail!("no protocol backend offers recovery for this drive")
        };
        engine::recover(
            dev.as_mut(),
            backend,
            supplied.as_deref(),
            &target,
            args.execute,
            args.acknowledged_risk,
        )
    })
}
