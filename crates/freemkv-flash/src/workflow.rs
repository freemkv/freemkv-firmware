//! Shared application workflows for the CLI and desktop front-end.

use crate::backend::{
    registry, unsupported_family_error, Backend, BackendId, Capabilities, Descriptor, FlashRequest,
    Match, ReadDevice, UNKNOWN_FAMILY,
};
pub use crate::backend::{
    AuthorizedPlan, Confirm, CurrentFirmwareRequired, FlashPreview, HardwareMismatch,
    UpdateEvidence, UpdateFailure, UpdateImpact, UpdateOutcome, UpdateProgress,
};
/// Correlation helpers keep a front-end's session events linked to operation logs.
pub use crate::diagnostics::{new_operation_id, with_operation_id};
/// Inspection inputs and results, so a front-end needs only this module and
/// [`crate::report`] to run Inspect and Compare.
pub use crate::inspection::{
    ComparisonReport, ComponentView, Control, Field, HardwareFamily, Inspection, InspectionError,
    Source,
};
use crate::manifest::FlashMode;
/// The event stream every workflow writes to, which a front-end subscribes to.
pub use crate::output::{capture_events, Event};
/// Structured localizable issues exposed through the frontend workflow boundary.
pub use crate::user_error::UserError;
use crate::{engine, platform, style};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Evidence about a selected file's origin, separate from flash compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOrigin {
    /// Known OEM firmware bodies and the stored OEM Normal signature match.
    OemLikely,
    /// A reconstructed capture has no original Normal signature.
    UserBackupLikely,
    /// The available evidence cannot establish an origin.
    Unknown,
}

impl FileOrigin {
    /// Catalog ID for a GUI badge, distinct from the English CLI label.
    pub fn label_id(self) -> &'static str {
        match self {
            Self::OemLikely => "domain.oem_likely",
            Self::UserBackupLikely => "domain.user_provided",
            Self::Unknown => "domain.origin_unknown",
        }
    }

    /// Catalog ID for the origin caveat shown before an update.
    pub fn explanation_id(self) -> &'static str {
        match self {
            Self::OemLikely => {
                "domain.firmware_bodies_and_the_original_normal_signature_match_known_oem_refe"
            }
            Self::UserBackupLikely => {
                "domain.firmware_supplied_by_a_user_or_captured_from_a_drive_rather_than_ident"
            }
            Self::Unknown => {
                "domain.the_file_s_origin_could_not_be_established_a_valid_transfer_signature_"
            }
        }
    }

    /// Short user-facing badge text; this is deliberately not a certification.
    pub fn label(self) -> &'static str {
        match self {
            Self::OemLikely => "OEM likely",
            Self::UserBackupLikely => "User provided",
            Self::Unknown => "Origin unknown",
        }
    }

    /// Explain the evidence and its practical limits before flashing.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::OemLikely => "Firmware bodies and the original Normal signature match known OEM references. A backup can also preserve OEM bytes. Origin does not establish drive compatibility.",
            Self::UserBackupLikely => "Firmware supplied by a user or captured from a drive, rather than identified as an original OEM release. Update metadata may have been reconstructed. Origin is separate from drive compatibility.",
            Self::Unknown => "The file's origin could not be established. A valid transfer signature alone does not prove an original OEM release. This label does not establish drive compatibility.",
        }
    }
}

/// Inspect the original selected bytes; never classify a transfer-signed copy.
/// This reads only a local file and does not contact a drive.
pub fn selected_file_origin(path: &Path) -> Result<FileOrigin> {
    let bytes = read_capped(path).with_context(|| format!("Cannot read {}", path.display()))?;
    Ok(registry::file_origin(&bytes))
}

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
    /// Installed firmware reference; omission reads receiver evidence from the drive.
    pub current: Option<PathBuf>,
    /// Explicit installed member of a paired Current MediaTek TAR.
    pub current_member: Option<String>,
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

/// English guidance for diagnostics and compatibility tests. User interfaces must
/// retain [`user_error`]'s stable IDs until rendering in the selected language.
pub fn error_message(error: &anyhow::Error) -> String {
    crate::user_error::UserError::of(error).render(crate::localization::Language::En)
}

/// Localizable customer guidance for desktop front-ends.
pub fn user_error(error: &anyhow::Error) -> crate::user_error::UserError {
    crate::user_error::UserError::of(error)
}

/// Retain desktop/runtime faults in diagnostics and expose only localized guidance.
/// `read_only` is true only when this entry point cannot have written firmware.
pub fn application_failure(detail: &str, read_only: bool) -> UserError {
    let result: Result<()> = crate::diagnostics::run("application runtime", || {
        let error = anyhow::anyhow!("{detail}").context(crate::user_error::IssueCode::Unexpected);
        Err(if read_only {
            error.context(crate::user_error::NoFirmwareWrite)
        } else {
            error
        })
    });
    user_error(&result.expect_err("application failure returns its diagnostic cause"))
}

/// Inspect a local firmware file without drive discovery or transport access.
pub fn check_file(path: &Path) -> Result<()> {
    crate::user_error::read_only(crate::diagnostics::run("check-file", || {
        check_file_inner(path)
    }))
}

fn check_file_inner(path: &Path) -> Result<()> {
    engine::info_file(path)
        .map_err(|e| crate::user_error::explain(e, crate::user_error::IssueCode::FirmwareInvalid))
}

/// Inspect a drive or a local firmware image.
pub fn info(target: Option<&str>) -> Result<()> {
    crate::user_error::read_only(crate::diagnostics::run("info", || info_inner(target)))
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
        [] => Err(
            anyhow::anyhow!("no optical drive found (is one connected and powered on?)")
                .context(crate::user_error::IssueCode::NoDrive),
        ),
        [only] => Ok(only.path.clone()),
        many => {
            let choices = many
                .iter()
                .map(|d| format!("  {}", d.list_line()))
                .collect::<Vec<_>>()
                .join("\n");
            Err(
                anyhow::anyhow!("multiple drives found — pass a drive name or id:\n{choices}")
                    .context(crate::user_error::IssueCode::ChooseDrive),
            )
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
    /// Why a recovery backend could not identify the receiver, when one tried
    /// and failed (not offered is not an error; the reason is still shown).
    pub recovery_errors: Vec<String>,
}

impl DriveProfile {
    /// The update/recovery backend's installed-firmware read capability.
    /// A dump-only match must not replace an identified recovery reader.
    pub fn can_read(&self) -> Option<bool> {
        let id = self
            .backend
            .as_ref()
            .filter(|_| self.capabilities.flash || self.capabilities.recovery)
            .map(|(descriptor, _)| descriptor.id)
            .or_else(|| self.recovery.map(|descriptor| descriptor.id))?;
        registry::backends()
            .find(|backend| backend.descriptor().id == id)
            .map(|backend| backend.can_read())
    }
}

/// Every file-name ending a registered backend reads, for open-file pickers.
pub fn file_extensions() -> Vec<&'static str> {
    extensions(registry::backends().flat_map(|b| b.descriptor().formats))
}

/// Update pickers use the same per-format permission as Flash and Recovery.
pub fn update_extensions(formats: &[crate::backend::FileFormat]) -> Vec<&'static str> {
    extensions(formats.iter().filter(|format| format.update_input))
}

/// All update formats when a drive has not yet been identified.
pub fn update_file_extensions() -> Vec<&'static str> {
    extensions(
        registry::backends()
            .flat_map(|b| b.descriptor().formats)
            .filter(|f| f.update_input),
    )
}

/// The distinct endings of `formats`, in first-seen order.
pub fn extensions<'a>(
    formats: impl IntoIterator<Item = &'a crate::backend::FileFormat>,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    for e in formats.into_iter().flat_map(|f| f.extensions) {
        if !out.contains(e) {
            out.push(*e);
        }
    }
    out
}

/// Probe `device` read-only and ask every recovery backend whether it knows
/// the receiver. An unsupported drive is a profile, not an error.
pub fn profile(device: &str) -> Result<DriveProfile> {
    crate::user_error::read_only(crate::diagnostics::run("profile", || {
        let selector = resolve_device(Some(device))?;
        let mut dev = platform::open(&selector, false)?;
        profile_on(dev.as_mut())
    }))
}

/// Profile with an explicitly selected installed-firmware reference. The file
/// chooses the protocol implementation; that implementation must validate its
/// receiver against the live drive before Recovery can be offered.
pub fn profile_with_current(
    device: &str,
    current: &Path,
    member: Option<&str>,
) -> Result<DriveProfile> {
    crate::user_error::read_only(crate::diagnostics::run("profile", || {
        let current = current_firmware_image(&read_capped(current)?, member)?;
        let selector = resolve_device(Some(device))?;
        let mut dev = platform::open(&selector, false)?;
        profile_on_with_current(dev.as_mut(), &current)
    }))
}

/// Current-assisted profile on an open device. It never grants normal Flash,
/// Backup or Dump capabilities merely because a file was recognized.
pub fn profile_on_with_current(
    dev: &mut dyn platform::ScsiDevice,
    current: &[u8],
) -> Result<DriveProfile> {
    let backend = current_recovery_backend(current)?;
    let identity = crate::backend::read_identity(&mut ReadDevice::without_unlocks(dev));
    let facet = backend
        .recovery()
        .expect("Current recovery capability checked");
    let mut recovery_errors = Vec::new();
    let recovery = match facet
        .identify_with_current(&mut ReadDevice::for_backend(dev, backend), Some(current))
    {
        Ok(Some(_)) => Some(backend.descriptor()),
        Ok(None) => {
            recovery_errors.push(facet.unidentified().into());
            None
        }
        Err(error) => {
            recovery_errors.push(format!("{error:#}"));
            None
        }
    };
    // An explicit Current file narrows all protocol I/O to its implementation.
    // A stale or mismatched Current must not inherit a previous profile's offer.
    let matched = if recovery.is_some() {
        backend.probe(&mut ReadDevice::for_backend(dev, backend), &identity)?
    } else {
        None
    };
    if let Some(ref matched) = matched {
        anyhow::ensure!(
            matched.backend == backend.descriptor().id,
            "backend probe returned an inconsistent backend id"
        );
    }
    let offered = matched.as_ref().map(|_| backend);
    Ok(DriveProfile {
        identity,
        backend: matched.map(|matched| (backend.descriptor(), matched)),
        recovery,
        capabilities: offered.map_or(Capabilities::NONE, Capabilities::of),
        backup_format: offered.and_then(|b| b.backup()).map(|b| b.format()),
        flash_formats: match offered {
            Some(b) if b.flash().is_some() => b.descriptor().formats,
            _ => &[],
        },
        recovery_errors,
    })
}

/// Recognition selects an implementation, never proves drive compatibility.
/// `identify_with_current` owns parsing and the live protocol binding checks.
fn current_recovery_backend(current: &[u8]) -> Result<&'static dyn Backend> {
    let (backend, _) = registry::recognize(current)?
        .context("Current firmware has no recognized protocol format")?;
    anyhow::ensure!(
        backend
            .recovery()
            .is_some_and(|facet| facet.accepts_current_for_identification()),
        "this firmware format cannot identify a recovery receiver"
    );
    Ok(backend)
}

/// [`profile`] on an open device.
pub fn profile_on(dev: &mut dyn platform::ScsiDevice) -> Result<DriveProfile> {
    let resolved = registry::resolve(dev)?;
    let identity = match &resolved {
        Some(r) => r.identity.clone(),
        None => crate::backend::read_identity(&mut ReadDevice::without_unlocks(dev)),
    };
    // Identification errors only mean "not offered": a profile never fails
    // merely because a drive is unsupported.
    let mut recovery_errors = Vec::new();
    let recovery = registry::backends()
        .find_map(|b| {
            let facet = b.recovery()?;
            match facet.identify(&mut ReadDevice::for_backend(dev, b)) {
                Ok(Some(_)) => Some(b.descriptor()),
                Ok(None) => None,
                Err(e) => {
                    recovery_errors.push(format!("{}: {e:#}", b.descriptor().display_name));
                    None
                }
            }
        })
        .or_else(|| {
            let backend = resolved.as_ref()?.backend;
            backend
                .recovery()?
                .accepts_current_for_identification()
                .then(|| backend.descriptor())
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
        recovery_errors: if recovery.is_some() {
            Vec::new()
        } else {
            recovery_errors
        },
        recovery,
    })
}

/// The drive's `info` rows, without showing them.
pub fn details(device: &str) -> Result<crate::report::Report> {
    crate::user_error::read_only(crate::diagnostics::run("details", || {
        let selector = resolve_device(Some(device))?;
        let mut dev = platform::open(&selector, false)?;
        let backend = resolved_backend(dev.as_mut())?;
        Ok(engine::info_report(dev.as_mut(), backend).report)
    }))
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
    crate::user_error::read_only(crate::diagnostics::run("backup/dump", || {
        backup_with_replace_inner(device, out, dump, replace)
    }))
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
            let id = handler.identity(&mut ReadDevice::for_backend(dev.as_mut(), handler));
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
pub fn flash(args: FlashOptions, confirm: &mut dyn Confirm) -> Result<UpdateOutcome> {
    crate::diagnostics::run("flash", || flash_inner(args, confirm))
}

fn flash_inner(args: FlashOptions, confirm: &mut dyn Confirm) -> Result<UpdateOutcome> {
    crate::diagnostics::record(format!(
        "flash options: input={:?} backup={:?} execute={} acknowledged_risk={}",
        args.input, args.backup, args.execute, args.acknowledged_risk
    ));
    if args.execute && !args.acknowledged_risk {
        return Err(UpdateFailure::before_write(
            "risk acknowledgement",
            anyhow::anyhow!("refusing to flash without acknowledging the risk")
                .context(crate::user_error::IssueCode::Acknowledgement),
        ));
    }
    let (mut dev, handler, req) = open_flash(&args)
        .map_err(|error| UpdateFailure::before_write("input and drive checks", error))?;
    engine::flash(dev.as_mut(), handler, &req, confirm).inspect(|outcome| {
        crate::diagnostics::record(format!("UPDATE OUTCOME: {outcome:?}"));
    })
}

/// The read-only first stage for a front-end to show before asking for
/// consent: the dry run's checks and plan as text. Needs no backup.
pub fn plan_flash(args: &FlashOptions) -> Result<Vec<String>> {
    preview_flash(args).map(|preview| preview.lines)
}

/// A preview reports separately whether installed compatibility is still pending.
pub fn preview_flash(args: &FlashOptions) -> Result<FlashPreview> {
    crate::diagnostics::run("flash plan", || {
        let args = FlashOptions {
            execute: false,
            ..args.clone()
        };
        let (mut dev, handler, req) = open_flash(&args)
            .map_err(|error| UpdateFailure::before_write("input and drive checks", error))?;
        engine::preview_flash_details(dev.as_mut(), handler, &req)
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
    anyhow::ensure!(
        args.current.is_some() || args.current_member.is_none(),
        "--current-member requires --current"
    );
    let current = args
        .current
        .as_ref()
        .map(|path| current_firmware_image(&read_capped(path)?, args.current_member.as_deref()))
        .transpose()?;
    if let Some(current) = &current {
        check_supplied_family(current, &input)?;
    }
    let selector = resolve_device(args.device.as_deref())?;
    let mut dev = platform::open(&selector, args.execute)?;
    let handler = resolve_capable(dev.as_mut(), |c| c.flash)?;
    anyhow::ensure!(
        current.is_none() || handler.flash().is_some_and(|f| f.accepts_current()),
        "this flash backend does not accept a Current firmware reference"
    );
    let input_format = registry::update_input_format(handler, &args.input, &input)?
        .context("backend reads no firmware files")?;
    let drive_model = handler
        .identity(&mut ReadDevice::for_backend(dev.as_mut(), handler))
        .product;
    let predump_out = args.backup.clone().or_else(|| {
        handler
            .backup()
            .and_then(|b| default_backup_path(&args.input, b.format().extension))
    });
    let req = FlashRequest {
        current,
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

/// Consent given before the flash started: every confirmation is answered yes.
pub struct Preconfirmed;

impl Confirm for Preconfirmed {
    fn confirm(&mut self, _plan: &AuthorizedPlan) -> Result<bool> {
        Ok(true)
    }
}

/// What a front-end shows when it asks to confirm an authorized flash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlashSheet {
    /// The authorized plan as text, with the saved backup's `backup:` line.
    pub plan: Vec<String>,
    /// Cautions from authorization (e.g. a generation barrier).
    pub warnings: Vec<String>,
    /// What the user confirms, when the backend words it.
    pub confirmation: Option<String>,
}

impl FlashSheet {
    /// The sheet for `plan`, rendered as the CLI shows it before its prompt.
    pub fn of(plan: &AuthorizedPlan) -> Self {
        let text: Vec<String> = plan
            .plan
            .after_backup
            .iter()
            .map(|line| engine::render_plan_line(line, plan.backup()))
            .collect();
        Self {
            plan: text
                .iter()
                .flat_map(|t| t.lines())
                .filter(|l| !l.trim().is_empty())
                .map(str::to_owned)
                .collect(),
            warnings: plan.warnings.clone(),
            confirmation: plan.confirmation.clone(),
        }
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

/// Reject proven file-to-file family mismatches before contacting any drive.
fn check_supplied_family(current: &[u8], target: &[u8]) -> Result<()> {
    let Some((backend, _)) = registry::recognize(current)? else {
        return Ok(());
    };
    if let Some((selected, _)) = registry::recognize(target)? {
        if selected.descriptor().id != backend.descriptor().id {
            return Err(crate::user_error::IssueCode::IncompatibleFirmware.into());
        }
    }
    let Some(files) = backend.files() else {
        return Ok(());
    };
    if let Some(((installed, installed_model), (selected, target_model))) = files
        .family_evidence(current)
        .zip(files.family_evidence(target))
    {
        if installed != selected {
            return Err(crate::backend::HardwareMismatch {
                installed_model,
                target_model,
                source: anyhow::anyhow!(
                    "provided Current family {installed} differs from selected family {selected}"
                ),
            }
            .into());
        }
    }
    Ok(())
}

/// Receiver reference used by Recovery. Reading the drive is always explicit.
#[derive(Clone, Debug)]
pub enum CurrentFirmware {
    /// No installed firmware reference. Supported by receivers that identify live.
    NotRequired,
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
    /// Firmware to write: MediaTek image or Pioneer Kernel and Normal.
    pub input: PathBuf,
    /// Exact MediaTek TAR member to recover; required for paired packages.
    pub member: Option<String>,
    /// Where to obtain the current receiver's firmware.
    pub current: CurrentFirmware,
    /// Exact member of a Current MediaTek TAR, separate from the target member.
    pub current_member: Option<String>,
    /// Issue writes; otherwise prepare without writing.
    pub execute: bool,
    /// Explicit acknowledgement of firmware-update risk.
    pub acknowledged_risk: bool,
    /// Explicitly permit a known hardware-family mismatch during Recovery only.
    pub bypass_family_check: bool,
}

/// Prepare once and recover without automatic backups. Backend recovery admission
/// checks and the declared family-override capability remain in force.
pub fn recover(args: RecoveryOptions) -> Result<UpdateOutcome> {
    crate::diagnostics::run("recovery", || {
        let execute = args.execute;
        let acknowledged_risk = args.acknowledged_risk;
        let prepared = prepare_recovery(args)?;
        if execute {
            execute_recovery(prepared, acknowledged_risk)
        } else {
            Ok(UpdateOutcome::Planned)
        }
    })
}

/// A single-use recovery session; clones share the same consumption guard.
#[derive(Clone, Default)]
pub struct PreparedRecovery(Arc<std::sync::Mutex<Option<RecoverySession>>>);

struct RecoverySession {
    selector: String,
    backend: &'static dyn Backend,
    identity: crate::backend::Identity,
    update: Box<dyn crate::backend::PreparedRecoveryUpdate>,
}

impl std::fmt::Debug for PreparedRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRecovery").finish_non_exhaustive()
    }
}

impl PreparedRecovery {
    fn take(&self) -> Result<RecoverySession> {
        (|| {
            self.0
                .lock()
                .map_err(|_| anyhow::Error::new(crate::user_error::IssueCode::PreparationExpired))?
                .take()
                .context(crate::user_error::IssueCode::PreparationExpired)
        })()
        .map_err(|e| UpdateFailure::before_write("prepared recovery", e))
    }
}

/// Load recovery inputs once, keeping the executable envelopes alive through consent.
pub fn prepare_recovery(args: RecoveryOptions) -> Result<PreparedRecovery> {
    crate::diagnostics::run("recovery preparation", || {
        let mut input = open_recovery(&args).map_err(|e| {
            UpdateFailure::before_write(
                "recovery precheck",
                crate::user_error::explain(e, crate::user_error::IssueCode::FirmwareInvalid),
            )
        })?;
        let facet = input
            .backend
            .recovery()
            .context(crate::user_error::IssueCode::UnsupportedDrive)
            .map_err(|e| UpdateFailure::before_write("recovery capability checks", e))?;
        if args.bypass_family_check && !facet.supports_family_override() {
            return Err(UpdateFailure::before_write(
                "recovery capability checks",
                crate::backend::UnsupportedFamilyOverride.into(),
            ));
        }
        let update = facet
            .prepare(
                &mut ReadDevice::for_backend(input.dev.as_mut(), input.backend),
                &input.receiver,
                input.current.as_deref(),
                &input.target,
                args.bypass_family_check,
            )
            .map_err(|e| {
                UpdateFailure::before_write(
                    "recovery preparation",
                    crate::user_error::explain(e, crate::user_error::IssueCode::FirmwareInvalid),
                )
            })?;
        let identity = input.backend.identity(&mut ReadDevice::for_backend(
            input.dev.as_mut(),
            input.backend,
        ));
        Ok(PreparedRecovery(Arc::new(std::sync::Mutex::new(Some(
            RecoverySession {
                selector: input.selector,
                backend: input.backend,
                identity,
                update,
            },
        )))))
    })
}

/// Consume a prepared session after consent, using only lightweight identity reads.
pub fn execute_recovery(
    prepared: PreparedRecovery,
    acknowledged_risk: bool,
) -> Result<UpdateOutcome> {
    crate::diagnostics::run("recovery execution", || {
        if !acknowledged_risk {
            return Err(UpdateFailure::before_write(
                "risk acknowledgement",
                crate::user_error::IssueCode::Acknowledgement.into(),
            ));
        }
        let session = prepared.take()?;
        let mut dev = platform::open(&session.selector, true).map_err(|e| {
            UpdateFailure::before_write(
                "receiver revalidation",
                e.context(crate::user_error::IssueCode::Connection),
            )
        })?;
        execute_recovery_on(dev.as_mut(), session)
    })
}

fn execute_recovery_on(
    dev: &mut dyn platform::ScsiDevice,
    session: RecoverySession,
) -> Result<UpdateOutcome> {
    let observed = session
        .backend
        .identity(&mut ReadDevice::for_backend(dev, session.backend));
    if observed.vendor.is_empty()
        || observed.product.is_empty()
        || observed.vendor != session.identity.vendor
        || observed.product != session.identity.product
        || observed.revision != session.identity.revision
        || observed.banner != session.identity.banner
    {
        return Err(UpdateFailure::before_write(
            "receiver revalidation",
            crate::user_error::IssueCode::DriveChanged.into(),
        ));
    }
    engine::execute_prepared_recovery(dev, session.update.as_ref()).inspect(|outcome| {
        crate::diagnostics::record(format!("UPDATE OUTCOME: {outcome:?}"));
    })
}

struct RecoveryInput {
    selector: String,
    dev: Box<dyn platform::ScsiDevice>,
    backend: &'static dyn Backend,
    receiver: crate::backend::RecoveryTarget,
    current: Option<Vec<u8>>,
    target: Vec<u8>,
}

fn open_recovery(args: &RecoveryOptions) -> Result<RecoveryInput> {
    if args.execute && !args.acknowledged_risk {
        return Err(crate::user_error::IssueCode::Acknowledgement.into());
    }
    crate::diagnostics::record(format!("recovery options: {args:?}"));
    let input = read_capped(&args.input)?;
    let target = recovery_target(&input, args.member.as_deref())?;
    let supplied = match &args.current {
        CurrentFirmware::File(path) => {
            let bytes = read_capped(path)?;
            Some(current_firmware_image(
                &bytes,
                args.current_member.as_deref(),
            )?)
        }
        CurrentFirmware::ReadFromDrive | CurrentFirmware::NotRequired => None,
    };
    if !args.bypass_family_check {
        if let Some(current) = &supplied {
            check_supplied_family(current, &target)?;
        }
    }
    let candidates: Vec<_> = match supplied.as_deref() {
        Some(current) => vec![current_recovery_backend(current)?],
        None => registry::backends().collect(),
    };
    let selector = resolve_device(args.device.as_deref())?;
    let mut dev = platform::open(&selector, args.execute)?;
    // Recovery serves drives too damaged to classify: no protocol probe,
    // the file-selected backend, or each backend without a Current file,
    // identifies the receiver itself. File selection never grants writes.
    let mut refusal = None;
    for backend in candidates {
        let Some(facet) = backend.recovery() else {
            continue;
        };
        if let Some(receiver) = facet.identify_with_current(
            &mut ReadDevice::for_backend(dev.as_mut(), backend),
            supplied.as_deref(),
        )? {
            if facet.requires_current() && matches!(args.current, CurrentFirmware::NotRequired) {
                bail!("this recovery backend requires --current or --read-from-drive");
            }
            registry::update_input_format(backend, &args.input, &input)?;
            return Ok(RecoveryInput {
                selector,
                dev,
                backend,
                receiver,
                current: supplied,
                target,
            });
        }
        refusal.get_or_insert(facet.unidentified());
    }
    Err(
        anyhow::anyhow!(refusal.unwrap_or("no protocol backend offers recovery for this drive"))
            .context(crate::user_error::IssueCode::UnsupportedDrive),
    )
}

/// Select exactly one member from a package with independent recovery images.
pub fn recovery_target(input: &[u8], member: Option<&str>) -> Result<Vec<u8>> {
    crate::package::recovery_target(input, member)
}

/// Resolve a Current reference without ever treating the target as installed.
pub fn current_firmware_image(input: &[u8], member: Option<&str>) -> Result<Vec<u8>> {
    if input.get(257..262) == Some(b"ustar") {
        recovery_target(input, member)
            .context("selecting Current firmware: use --current-member for a paired TAR")
    } else {
        anyhow::ensure!(
            member.is_none(),
            "--current-member requires a Current TAR package"
        );
        recovery_target(input, None)
    }
}

/// Recovery choices for a bounded input file.
pub fn recovery_members(path: &Path) -> Result<Vec<String>> {
    crate::package::recovery_members(&read_capped(path)?)
}

/// Whether the identified recovery backend requires an installed reference.
pub fn recovery_requires_current(profile: &DriveProfile) -> bool {
    profile
        .recovery
        .and_then(|d| registry::backends().find(|b| b.descriptor().id == d.id))
        .and_then(|b| b.recovery())
        .is_none_or(|r| r.requires_current())
}

/// Whether preparation established two known, different hardware families.
/// Unknown families, parse failures and transport errors are not mismatches.
pub fn is_hardware_mismatch(error: &anyhow::Error) -> bool {
    error.is::<crate::backend::HardwareMismatch>()
}

/// Whether the identified recovery backend supports an explicit family override.
pub fn recovery_supports_family_override(profile: &DriveProfile) -> bool {
    profile
        .recovery
        .and_then(|d| registry::backends().find(|b| b.descriptor().id == d.id))
        .and_then(|b| b.recovery())
        .is_some_and(|r| r.supports_family_override())
}

/// Package a standalone firmware image without opening a drive or overwriting output.
pub fn package_image(input: &Path, output: &Path) -> Result<()> {
    crate::user_error::read_only(crate::diagnostics::run("package", || {
        package_image_inner(input, output)
    }))
}

fn package_image_inner(input: &Path, output: &Path) -> Result<()> {
    use std::io::Write;
    let bytes = crate::package::wrap_image(read_capped(input)?)
        .map_err(|e| e.context(crate::user_error::IssueCode::FirmwareInvalid))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
