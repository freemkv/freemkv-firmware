//! The backend contract: identity, file formats, optional facets, devices and
//! the explicit registry.
//!
//! A drive family is a module under [`crate::backends`] plus one line in
//! [`registry`]. Core code reaches a backend only through the [`Backend`]
//! trait: its [`Descriptor`] and whichever facets it offers. What a drive can
//! do ([`Capabilities`]) is derived from facet presence.
//!
//! Every read-only operation receives a [`ReadDevice`], which refuses data-out
//! except the backend's declared read-unlock commands. Writes receive a
//! [`WriteDevice`], which only the engine's gates can create.

use std::any::Any;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};

use crate::inspection::{Control, Inspection, LiveState};
use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;
use crate::report::{Row, Slot};

pub mod device;
pub mod registry;

pub use crate::engine::gates::{SavedBackup, WriteDevice};
pub use device::{CdbPattern, DeviceAccess, ReadDevice};

// ---- Identity and formats ---------------------------------------------------

/// Stable protocol name of a backend (`"mtk19xx"`, `"pioneer-oem"`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BackendId(pub &'static str);

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// What a backend declares about itself.
#[derive(Debug)]
pub struct Descriptor {
    /// Stable protocol name.
    pub id: BackendId,
    /// User-facing family name (`"MediaTek MT19xx"`, `"Pioneer"`).
    pub display_name: &'static str,
    /// The `flash:` line `info` prints for a live drive, when one applies.
    pub flash_summary: Option<&'static str>,
    /// Every file format this backend reads, in recognition order.
    pub formats: &'static [FileFormat],
}

impl Descriptor {
    /// Whether `format` is one of this backend's own formats.
    pub fn owns(&self, format: &FileFormat) -> bool {
        self.formats.contains(format)
    }
}

/// How the engine treats a flash input of a given format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatRole {
    /// A firmware image written as is.
    Image,
    /// A backup archive, decoded back to an image before writing.
    Backup,
    /// A multi-component update package.
    Package,
}

/// One file format a backend owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileFormat {
    /// Stable id (`"mtk-image"`, `"pioneer-package"`).
    pub id: &'static str,
    /// User-facing wording (`"Pioneer firmware bundle"`).
    pub label: &'static str,
    /// Usual file-name endings, for pickers and help text.
    pub extensions: &'static [&'static str],
    /// How a flash treats this format.
    pub role: FormatRole,
}

/// Family name shown for a drive no backend recognizes.
pub const UNKNOWN_FAMILY: &str = "Unknown";

/// Standard INQUIRY identity fields plus the boot banner, for `info`.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// T10 vendor id (INQUIRY bytes 8..16), trimmed.
    pub vendor: String,
    /// Product id (INQUIRY bytes 16..32), trimmed.
    pub product: String,
    /// Product revision (INQUIRY bytes 32..36), trimmed.
    pub revision: String,
    /// "MT19xx Boot" banner (READ BUFFER mode 6 @ 0x3000), if any.
    pub banner: Option<String>,
}

pub(crate) fn trim_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string()
}

/// Sanitize a drive-supplied ASCII string for safe display: keeps printable
/// bytes (0x20..=0x7e) and replaces everything else (including terminal
/// control/escape sequences a malicious or malfunctioning drive could return)
/// with `.`.
pub(crate) fn sanitize_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            if ('\u{20}'..='\u{7e}').contains(&c) {
                c
            } else {
                '.'
            }
        })
        .collect()
}

/// Standard SPC INQUIRY CDB for `alloc` bytes.
fn inquiry_cdb(alloc: u8) -> [u8; 6] {
    [0x12, 0x00, 0x00, 0x00, alloc, 0x00]
}

/// Read standard INQUIRY identity, surfacing a failed INQUIRY (permission or
/// transport fault) as an error instead of an empty identity.
pub fn try_read_identity(dev: &mut dyn ScsiDevice) -> Result<Identity> {
    let mut id = Identity::default();
    let data = dev
        .command_in(&inquiry_cdb(96), 96)
        .context("INQUIRY failed")?;
    if data.len() < 36 {
        anyhow::bail!(
            "short INQUIRY identity: {} bytes returned, at least 36 required",
            data.len()
        );
    }
    id.vendor = sanitize_ascii(&trim_ascii(&data[8..16]));
    id.product = sanitize_ascii(&trim_ascii(&data[16..32]));
    id.revision = sanitize_ascii(&trim_ascii(&data[32..36]));
    crate::diagnostics::record(format!(
        "drive identity: vendor={:?} product={:?} revision={:?}",
        id.vendor, id.product, id.revision
    ));
    Ok(id)
}

/// Read standard INQUIRY identity. Vendor ROM reads belong to a matched
/// protocol backend, never to the common identity path. A failed INQUIRY still
/// yields an empty identity (callers keep classifying), but is reported loudly
/// so a permission/transport fault is not mistaken for an unsupported drive.
pub fn read_identity(dev: &mut dyn ScsiDevice) -> Identity {
    match try_read_identity(dev) {
        Ok(id) => id,
        Err(error) => {
            eprintln!(
                "{}",
                crate::style::amber(&format!(
                    "warning: could not read the drive identity ({error:#}); check device \
                     permissions/connection — the drive may be reported as unsupported"
                ))
            );
            Identity::default()
        }
    }
}

/// A positive read-only probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The backend that matched.
    pub backend: BackendId,
    /// Read-only signature that justified the match.
    pub evidence: &'static str,
}

// ---- Shared request and report types ----------------------------------------

/// A fully-resolved flash request handed to [`crate::engine`].
#[derive(Debug, Clone)]
pub struct FlashRequest {
    /// The raw input file bytes.
    pub input: Vec<u8>,
    /// The input's format, owned by the drive's backend unless misdirected.
    pub input_format: &'static FileFormat,
    /// Streaming mode (`main` vs `full`). On MediaTek this is informational:
    /// the full image is always streamed and the commit always sent.
    pub mode: FlashMode,
    /// Actually issue writes (otherwise dry-run).
    pub execute: bool,
    /// User acknowledged the bricking risk.
    pub acknowledged_risk: bool,
    /// Hidden expert override for the enc envelope (`Some(true/false)` forces).
    pub enc_override: Option<bool>,
    /// Drive model (INQUIRY product), shown in the flash plan.
    pub drive_model: String,
    /// Show the raw SCSI CDB sequence in the plan (default: clean summary only).
    pub verbose: bool,
    /// Where to save the required pre-flash backup.
    pub predump_out: Option<std::path::PathBuf>,
}

/// What a drive offers, derived from the facets its backend provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// A complete or candidate firmware backup can be captured (`backup`).
    pub backup: bool,
    /// A raw memory dump can be captured (`dump`).
    pub dump: bool,
    /// The WRITE path (`flash`) is implemented and may execute.
    pub flash: bool,
    /// A receiver can be recovered (`recover`).
    pub recovery: bool,
    /// Firmware from this backend can be inspected.
    pub inspect: bool,
    /// The dump is a deeper salvage read (slower, retrying, tolerant of an
    /// unstable drive).
    pub deep_salvage: bool,
}

impl Capabilities {
    /// A drive no backend recognizes: identify only.
    pub const NONE: Self = Self {
        backup: false,
        dump: false,
        flash: false,
        recovery: false,
        inspect: false,
        deep_salvage: false,
    };

    /// What `backend` offers.
    pub fn of(backend: &dyn Backend) -> Self {
        Self {
            backup: backend.backup().is_some(),
            dump: backend.dump().is_some(),
            flash: backend.flash().is_some(),
            recovery: backend.recovery().is_some(),
            inspect: backend.inspect().is_some(),
            deep_salvage: backend.dump().is_some_and(|d| d.deep_salvage()),
        }
    }
}

/// How a backup file is named and labelled: `<model>_<rev>.<infix>.<extension>`
/// and a `<infix> sha256` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupFormat {
    /// File extension.
    pub extension: &'static str,
    /// Filename infix: `backup` for a proven rollback, `candidate` otherwise.
    pub infix: &'static str,
}

/// Provenance of a just-written backup, decided from the artifact's own bytes.
pub enum BackupNotice {
    /// Every component is byte-exact OEM; the capture is a faithful original.
    VerifiedOem(String),
    /// At least one component is a reconstruction (made-up seed/signature), so
    /// physical restore and drive acceptance are untested.
    Unverified(String),
    /// Nothing to say about provenance.
    None,
}

/// The installed firmware's identity, as `info` and the post-flash check show it.
pub struct FirmwareReport {
    /// ASCII descriptor read from the drive, when it has one.
    pub descriptor: Option<String>,
    /// Fingerprint of the firmware's readable code windows.
    pub fingerprint: String,
    /// The matching catalog entry: `(description, where to obtain the image)`.
    pub matched: Option<(&'static str, &'static str)>,
}

/// Unsupported-protocol error shared by backup and flash dispatch. `family`
/// is the matched backend's display name, or [`UNKNOWN_FAMILY`].
pub fn unsupported_family_error(family: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "No executable flash path or confirmed restorable backup is available for {family}. \
         Identification probes may have been sent; no firmware write or backup file was produced. \
         Run `freemkv-flash info DEVICE` to record the identity before adding a backend."
    )
}

// ---- The trait and its facets -----------------------------------------------

/// A firmware command-protocol backend. Everything beyond identity is an
/// optional facet; core code offers exactly what the facets provide.
pub trait Backend: Sync + 'static {
    /// What this backend declares about itself: id, names and file formats.
    fn descriptor(&self) -> &'static Descriptor;

    /// Recognize this protocol from read-only evidence. `None` means it does not
    /// match; an error means the probe could not safely decide.
    fn probe(&self, dev: &mut ReadDevice<'_>, identity: &Identity) -> Result<Option<Match>>;

    /// INQUIRY identity plus any backend banner, for `info` and backup naming.
    fn identity(&self, dev: &mut ReadDevice<'_>) -> Identity {
        read_identity(dev)
    }

    /// The data-out commands this backend's read-only operations may send
    /// (e.g. a read-unlock knock). Everything else is refused.
    fn allowed_data_out(&self) -> &'static [CdbPattern] {
        &[]
    }

    /// File recognition and description (`check`, `info <file>`, flash input).
    fn files(&self) -> Option<&dyn FileFacet> {
        None
    }
    /// Vendor details for `info` and the post-flash identity check.
    fn details(&self) -> Option<&dyn DetailsFacet> {
        None
    }
    /// Backup capture and restore decoding.
    fn backup(&self) -> Option<&dyn BackupFacet> {
        None
    }
    /// Raw memory dump.
    fn dump(&self) -> Option<&dyn DumpFacet> {
        None
    }
    /// Firmware update.
    fn flash(&self) -> Option<&dyn FlashFacet> {
        None
    }
    /// Recovery of a receiver whose normal update path is unusable.
    fn recovery(&self) -> Option<&dyn RecoveryFacet> {
        None
    }
    /// Firmware inspection.
    fn inspect(&self) -> Option<&dyn InspectFacet> {
        None
    }
    /// Read-only drive settings.
    fn settings(&self) -> Option<&dyn SettingsFacet> {
        None
    }
}

/// How a file was recognized. A structural match (a parsed container or exact
/// layout) beats a heuristic one (a pattern search).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    /// The bytes parse as this format.
    Structural,
    /// A signature was found in the bytes.
    Heuristic,
}

/// A backend's claim on a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recognized {
    /// The format the bytes are.
    pub format: &'static FileFormat,
    /// How sure the backend is.
    pub confidence: Confidence,
}

/// File recognition and description.
pub trait FileFacet {
    /// This backend's claim on `bytes`, if any. The registry resolves claims
    /// once for flash input, `check`, `info <file>` and inspection.
    fn recognize(&self, bytes: &[u8]) -> Option<Recognized>;
    /// Print the `info <file>` / `check` report for a file this backend
    /// recognized, or `None` to leave it to the generic report. Read-only.
    fn describe(&self, bytes: &[u8], recognized: &Recognized) -> Option<Result<()>>;
    /// The format of a flash input no backend recognizes, by its name, so the
    /// drive's flash path reports the specific parse error.
    fn classify_input(&self, path: &Path, bytes: &[u8]) -> &'static FileFormat;
    /// A format of this backend that the file name alone identifies, whichever
    /// drive the file is meant for.
    fn claims_by_name(&self, _path: &Path) -> Option<&'static FileFormat> {
        None
    }
}

/// What `info` has already read when it asks a backend for its rows.
pub struct InfoSoFar<'a> {
    /// The standard snapshot.
    pub standard: &'a crate::standard::StandardInfo,
    /// The backend's settings read, once the region rows are done.
    pub settings: Option<&'a Result<crate::output::device_settings::Settings>>,
}

/// Vendor details for `info`.
pub trait DetailsFacet {
    /// The backend's rows at `slot`. Anything already in `read` is reused,
    /// never read again.
    fn rows(&self, _dev: &mut ReadDevice<'_>, _read: &InfoSoFar<'_>, _slot: Slot) -> Vec<Row> {
        Vec::new()
    }
    /// The installed firmware's identity (also the post-flash check).
    fn post_flash_identity(&self, _dev: &mut ReadDevice<'_>) -> Result<Option<FirmwareReport>> {
        Ok(None)
    }
}

/// Drive settings, read-only.
pub trait SettingsFacet {
    /// Read the drive's settings.
    fn read(&self, dev: &mut ReadDevice<'_>) -> Result<crate::output::device_settings::Settings>;
}

/// Backup capture.
pub trait BackupFacet {
    /// File naming and labelling.
    fn format(&self) -> BackupFormat;
    /// Capture one complete serialized backup. Read-only.
    fn capture(&self, dev: &mut ReadDevice<'_>) -> Result<Vec<u8>>;
    /// Provenance advisory for a just-written backup.
    fn notice(&self, bytes: &[u8]) -> BackupNotice;
    /// Validate a backup for `target_model` and return the image it restores.
    fn validate(&self, bytes: &[u8], target_model: &str) -> Result<Vec<u8>>;
}

/// Raw memory dump (saved verbatim as one `.dump.bin`, not a backup).
pub trait DumpFacet {
    /// Whether the dump is a deeper salvage read.
    fn deep_salvage(&self) -> bool {
        false
    }
    /// Data-out commands the dump sends (unlocks, RAM logging); empty means a
    /// read-only dump.
    fn writes(&self) -> &'static [CdbPattern] {
        &[]
    }
    /// Capture the dump. A dump with declared writes gets a write grant limited
    /// to those commands.
    fn capture(&self, dev: DeviceAccess<'_, '_>) -> Result<Vec<u8>>;
}

/// One line of a flash plan, styled by the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanLine {
    /// A bold section header.
    Header(String),
    /// A `label: value` fact.
    Field(&'static str, String),
    /// The `backup:` fact: the saved backup, or that a dry run captures none.
    Backup,
    /// Plain text.
    Text(String),
    /// A caution.
    Warning(String),
    /// A dotted-leader status row that passed.
    Ok(&'static str, String),
    /// Multi-line text shown as one block (it carries its own newlines).
    Block(String),
    /// A line set off from the previous one by a blank line.
    Spaced(Box<PlanLine>),
}

/// A pre-backup flash plan: what to show, plus backend-private state that only
/// the same backend's `authorize` reads.
pub struct FlashPlan {
    /// Shown as soon as the plan is made, on a dry run and on execute.
    pub notes: Vec<PlanLine>,
    /// The plan a dry run shows.
    pub dry_run: Vec<PlanLine>,
    /// What execute shows once the backup is saved and covers the update.
    pub after_backup: Vec<PlanLine>,
    state: Box<dyn Any + Send>,
}

impl FlashPlan {
    /// A plan carrying `state` for the backend's own `authorize`.
    pub fn new(state: impl Any + Send) -> Self {
        Self {
            notes: Vec::new(),
            dry_run: Vec::new(),
            after_backup: Vec::new(),
            state: Box::new(state),
        }
    }

    /// The backend state, when this plan was made by that backend.
    pub fn state<T: 'static>(&self) -> Result<&T> {
        self.state
            .downcast_ref()
            .context("flash plan was made by another backend")
    }
}

/// A plan every installed-firmware gate has passed. Front-ends show
/// `warnings`, then ask for `confirmation` when it is set.
pub struct AuthorizedPlan {
    /// The plan this authorizes.
    pub plan: FlashPlan,
    /// Cautions shown before the confirmation (e.g. a generation barrier).
    pub warnings: Vec<String>,
    /// What the user confirms; `None` needs no further confirmation.
    pub confirmation: Option<String>,
    backup: String,
    state: Box<dyn Any + Send>,
}

impl AuthorizedPlan {
    /// An authorization of `plan` carrying `state` for the backend's `execute`.
    pub fn new(plan: FlashPlan, state: impl Any + Send) -> Self {
        Self {
            plan,
            warnings: Vec::new(),
            confirmation: None,
            backup: String::new(),
            state: Box::new(state),
        }
    }

    /// The `backup:` summary of the saved pre-flash backup, which the engine
    /// fills in once the backend has authorized the plan.
    pub fn backup(&self) -> &str {
        &self.backup
    }

    pub(crate) fn set_backup(&mut self, summary: &str) {
        self.backup = summary.to_string();
    }

    /// The backend state, when this authorization was made by that backend.
    pub fn state<T: 'static>(&self) -> Result<&T> {
        self.state
            .downcast_ref()
            .context("authorized plan was made by another backend")
    }
}

/// A front-end's answer to an authorized flash's confirmation text.
pub trait Confirm {
    /// Whether to write. The engine has already shown the warnings and text.
    fn confirm(&mut self, plan: &AuthorizedPlan) -> Result<bool>;
    /// Whether to be asked about every authorized flash, including one whose
    /// backend words no confirmation (a GUI's sheet). The CLI asks only when
    /// there is text.
    fn asks_every_flash(&self) -> bool {
        false
    }
}

/// Firmware update in two read-only stages, then the write.
pub trait FlashFacet {
    /// Read-only and pre-backup: validate the input against the drive and
    /// describe the plan. Must not need the backup.
    fn plan(&self, dev: &mut ReadDevice<'_>, req: &FlashRequest) -> Result<FlashPlan>;
    /// Whether a dry run touches the drive (tray warning, preflight).
    fn dry_run_uses_device(&self) -> bool {
        true
    }
    /// Read-only readiness check that ends a dry run, and its lines.
    fn preflight(&self, _dev: &mut ReadDevice<'_>, _plan: &FlashPlan) -> Result<Vec<PlanLine>> {
        Ok(Vec::new())
    }
    /// Whether the saved backup holds a rollback for every region the plan
    /// overwrites. The backup stays saved when this refuses.
    fn verify_backup(&self, _plan: &FlashPlan, _backup: &[u8]) -> Result<()> {
        Ok(())
    }
    /// Read-only, after the backup: every gate that needs the installed
    /// firmware. May refuse; the saved backup is kept.
    fn authorize(
        &self,
        dev: &mut ReadDevice<'_>,
        plan: FlashPlan,
        backup: &SavedBackup,
    ) -> Result<AuthorizedPlan>;
    /// Write, then verify the result.
    fn execute(&self, dev: &mut WriteDevice<'_>, plan: &AuthorizedPlan) -> Result<()>;
}

/// A receiver a recovery backend identified, with what it read.
pub struct RecoveryTarget {
    /// The receiver as identified, for front-ends and diagnostics.
    pub label: String,
    state: Box<dyn Any + Send>,
}

impl RecoveryTarget {
    /// A target carrying `state` for the backend's own `recover`.
    pub fn new(label: String, state: impl Any + Send) -> Self {
        Self {
            label,
            state: Box::new(state),
        }
    }

    /// The backend state, when this target was identified by that backend.
    pub fn state<T: 'static>(&self) -> Result<&T> {
        self.state
            .downcast_ref()
            .context("recovery target was identified by another backend")
    }
}

/// Recovery without automatic backups or installed-versus-target policy.
pub trait RecoveryFacet {
    /// Read-only, with no protocol probe (the drive may be too damaged to
    /// classify): `Some` when this is a receiver this backend recovers.
    fn identify(&self, dev: &mut ReadDevice<'_>) -> Result<Option<RecoveryTarget>>;
    /// The refusal when [`RecoveryFacet::identify`] finds no receiver.
    fn unidentified(&self) -> &'static str;
    /// Prepare the transfer from `current` (read from the drive when `None`)
    /// and `target`, and write it when given a write grant.
    fn recover(
        &self,
        dev: DeviceAccess<'_, '_>,
        receiver: &RecoveryTarget,
        current: Option<&[u8]>,
        target: &[u8],
    ) -> Result<()>;
}

/// Firmware inspection.
pub trait InspectFacet {
    /// Inspect a firmware file, or `None` when it is not this backend's format.
    fn inspect(
        &self,
        source: String,
        bytes: &[u8],
        control: &Control,
    ) -> Option<Result<Inspection>>;
    /// The live drive state shown beside a captured inspection.
    fn live_state(&self, dev: &mut ReadDevice<'_>) -> LiveState;
    /// Whether a live capture saves the raw drive read (the dump) rather than
    /// a backup. A raw read keeps the per-unit data a backup resets.
    fn raw_capture(&self) -> bool {
        false
    }
}
