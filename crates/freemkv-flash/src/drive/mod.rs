//! The backend trait and read-only drive identity.
//!
//! Device identity (INQUIRY vendor/product/revision), controller architecture,
//! and update command protocol are distinct. [`crate::backend::registry`] asks
//! each registered [`FirmwareBackend`] for read-only probe evidence and rejects
//! overlap.
//!
//! A [`FirmwareBackend`] exposes protocol capabilities — identity, backup
//! capture, input validation, and `flash_stream` (which owns the whole update
//! session) with optional read-back. It does no file I/O; only `describe_file`,
//! `print_device_info` and `print_flash_notes` may print. The generic
//! orchestration (reading the input file, the pre-flash backup, the dry-run
//! plan, verification, and the safety gate) lives once in [`crate::engine`].

use anyhow::{bail, Context, Result};

use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;

use crate::backend::{BackendId, Descriptor, FileFormat};

/// A full firmware read: `(image, readable byte count, not-exposed `(start,end)`
/// gaps)`. The image is the whole [`DriveFamily::image_size`] span; every offset
/// a drive doesn't map to a read is filled (e.g. `0xFF`) and recorded as a gap.
/// (Aliased so the trait signature stays under clippy's complex-type lint.)
pub type FullImage = (Vec<u8>, usize, Vec<(usize, usize)>);

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

/// Evidence returned by a protocol backend's read-only probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeEvidence {
    /// The backend that matched.
    pub backend: BackendId,
    /// Read-only signature that justified the match.
    pub discriminator: &'static str,
}

/// A fully-resolved flash request handed to [`crate::engine`].
#[derive(Debug, Clone)]
pub struct FlashRequest {
    /// The raw input file bytes.
    pub input: Vec<u8>,
    /// The input's format, owned by the drive's backend unless misdirected.
    pub input_format: &'static FileFormat,
    /// Streaming mode (`main` vs `full`). NOTE: on MTK (the only implemented
    /// family) this is currently informational only — the full 2 MiB image is
    /// always streamed and the commit handshake is always sent regardless of
    /// which mode is selected.
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
    /// Where to save the required pre-flash backup, if supported.
    pub predump_out: Option<std::path::PathBuf>,
    /// EXPERIMENTAL crossflash: allow flashing a DIFFERENT same-chipset model's
    /// firmware (waives the model match; never the chipset-family gate).
    pub allow_crossflash: bool,
}

/// A firmware command protocol's primitives.
///
/// Every method is a protocol operation — no file I/O. Only `describe_file`,
/// `print_device_info` and `print_flash_notes` print. The generic
/// [`crate::engine`] composes these into the `info` / `backup` / `flash`
/// commands. A new family only has to supply its own CDBs; the engine loop is
/// unchanged.
/// The three user-facing capabilities a backend may offer, as one declarative
/// record. The CLI derives the `info` capability line and the `backup`/`flash`
/// gates from this single source of truth rather than a scatter of booleans.
///
/// `info` (read-only identify/classify) is safe for every classified family;
/// `backup` is a complete or candidate backup capture; `flash` is the WRITE
/// path; `deep_salvage` marks a dump that is a deeper salvage read. Today: MTK
/// info+backup+flash, Pioneer info+backup+flash+deep salvage, Unknown info only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Read-only identify/classify (`info`) is available. Safe for any
    /// classified family; effectively always `true`.
    pub info: bool,
    /// A complete or candidate firmware backup can be captured (`backup`).
    pub backup: bool,
    /// The WRITE path (`flash`) is implemented and may execute.
    pub flash: bool,
    /// The `dump` is a deeper salvage read (slower, retrying, tolerant of an
    /// unstable drive) rather than an ordinary backup.
    pub deep_salvage: bool,
}

impl Capabilities {
    /// Identify only: a drive no backend recognizes.
    pub const NONE: Self = Self {
        info: true,
        backup: false,
        flash: false,
        deep_salvage: false,
    };

    /// Every standard capability on (MTK's proven live backup-and-flash path).
    /// MTK has no deep salvage: its backup is already a complete, verified image.
    pub const fn all() -> Self {
        Self {
            info: true,
            backup: true,
            flash: true,
            deep_salvage: false,
        }
    }
}

/// How a captured backup is presented to the user, so the engine labels every
/// family's artifact without naming any chipset. `infix` is the filename part
/// in `<model>_<rev>.<infix>.<ext>`; `notice`, when set, is an advisory line
/// printed after the file is written (for artifacts that are not a proven
/// rollback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupKind {
    /// Filename infix: `backup` for a proven rollback, `candidate` otherwise.
    pub infix: &'static str,
    /// Advisory printed after writing, when the artifact is not proven.
    pub notice: Option<&'static str>,
}

impl BackupKind {
    /// A complete, proven rollback archive.
    pub const PROVEN: Self = Self {
        infix: "backup",
        notice: None,
    };
}

/// Provenance of a just-written backup, decided from the artifact's own bytes.
/// The engine prints it without naming any chipset: a family reports whether
/// what it captured is byte-exact OEM or a reconstruction, and the engine colors
/// the line accordingly.
pub enum BackupNotice {
    /// Every component is byte-exact OEM; the capture is a faithful original.
    VerifiedOem(String),
    /// At least one component is a reconstruction (made-up seed/signature), so
    /// physical restore and drive acceptance are untested.
    Unverified(String),
    /// Nothing to say about provenance.
    None,
}

/// A firmware command-protocol backend for one chipset family. The engine
/// drives every family through this trait and names no specific chipset: all
/// per-family behavior (capabilities, capture, validation, labeling, offline
/// planning) is expressed here, so adding a family touches no orchestration.
pub trait FirmwareBackend: Sync {
    /// What this backend declares about itself: id, names and file formats.
    fn descriptor(&self) -> &'static Descriptor;

    /// The user-facing capabilities this backend offers. Single source of truth
    /// for the `info` label and the `backup`/`flash` gates (see [`Capabilities`]).
    fn capabilities(&self) -> Capabilities;

    /// Recognize this command protocol using read-only evidence. `None` means
    /// the protocol does not match; an error means the probe could not safely
    /// decide. The registry rejects multiple positive matches.
    fn probe(&self, dev: &mut dyn ScsiDevice, identity: &Identity)
        -> Result<Option<ProbeEvidence>>;

    /// Whether the shared `info` snapshot shows its vendor identity and
    /// settings sections for this backend's drives.
    fn vendor_snapshot(&self) -> bool {
        false
    }

    /// Extension of a complete, immediately reflashable backup file. `None`
    /// means this protocol has no proven backup path and cannot execute flash.
    fn backup_extension(&self) -> Option<&'static str> {
        None
    }

    /// How this backend's captured backup is labeled (filename infix + optional
    /// advisory). Defaults to a proven rollback; a backend whose backup is an
    /// unverified candidate overrides this. Lets the engine present any family's
    /// artifact without naming a chipset.
    fn backup_kind(&self) -> BackupKind {
        BackupKind::PROVEN
    }

    /// Provenance advisory for a just-written backup, decided from its bytes.
    /// The default maps `backup_kind().notice` statically; a family that can
    /// tell byte-exact OEM from a reconstruction overrides this to inspect the
    /// artifact and only warn when a component is not OEM.
    fn backup_notice(&self, _bytes: &[u8]) -> BackupNotice {
        match self.backup_kind().notice {
            Some(msg) => BackupNotice::Unverified(msg.to_string()),
            None => BackupNotice::None,
        }
    }

    /// Capture one complete serialized backup file. The engine saves and
    /// verifies these bytes before issuing any update command.
    fn capture_backup(&self, _dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "no proven restorable firmware backup for {}",
            self.descriptor().id
        ))
    }

    /// The `dump` command: a best-effort salvage capture of the drive's firmware.
    /// Never uses vendor kernel mode. The default is an ordinary backup, so a
    /// family without a distinct dump treats `dump` as `backup`.
    fn capture_dump(&self, dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
        self.capture_backup(dev)
    }

    /// Whether [`Self::capture_dump`] yields a single raw memory image (saved
    /// as-is to one `.bin`, not validated as a backup archive) rather than a
    /// backup archive.
    fn dump_is_raw(&self) -> bool {
        false
    }

    /// Validate a backup file for this device and return the update image it
    /// contains. Backends must check completeness, integrity and model.
    fn validate_backup(&self, _bytes: &[u8], _target_model: &str) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "no proven backup restore path for {}",
            self.descriptor().id
        ))
    }

    /// Validate a direct image against this device before any write. A backend
    /// may use read-only commands to verify its exact controller variant.
    fn validate_image(
        &self,
        _dev: &mut dyn ScsiDevice,
        _image: &[u8],
        _drive_product: &str,
        _allow_crossflash: bool,
    ) -> Result<()> {
        Err(anyhow::anyhow!(
            "live flashing is not implemented for {}",
            self.descriptor().id
        ))
    }

    /// The format of a flash input for this backend's drive.
    fn classify_input(&self, path: &std::path::Path, bytes: &[u8]) -> &'static FileFormat;

    /// A format of this backend that the file name alone identifies, whichever
    /// drive the file is meant for.
    fn claims_by_name(&self, _path: &std::path::Path) -> Option<&'static FileFormat> {
        None
    }

    /// Recover a drive whose normal update path is unusable, without automatic
    /// backups or installed-versus-target policy gates. `current` is the
    /// installed firmware when the caller supplies it; otherwise the backend
    /// reads it. Returns `None` when this backend has no recovery path, and an
    /// error when it has one but the drive is not a receiver it recognizes.
    fn recover(
        &self,
        _dev: &mut dyn ScsiDevice,
        _current: Option<&[u8]>,
        _target: &[u8],
        _execute: bool,
    ) -> Option<Result<()>> {
        None
    }

    /// Inclusive byte ranges suitable for post-write read-back comparison.
    /// These are protocol-defined; no generic CMAC or boot-map assumptions
    /// belong in the engine.
    fn verification_ranges(&self, _image: &[u8]) -> Result<Vec<(usize, usize)>> {
        Err(anyhow::anyhow!(
            "read-back verification map unavailable for {}",
            self.descriptor().id
        ))
    }

    /// Backend-specific, file-only plan for a protocol whose live backup and
    /// write path is still unproven. `None` uses the normal connected-device
    /// workflow; `Some` is the complete plan result and must issue no I/O.
    fn offline_plan(&self, _req: &FlashRequest) -> Option<Result<()>> {
        None
    }

    /// Whether this family's live flash is a whole-package OEM update session
    /// ([`Self::flash_bundle`]) rather than the standard image-chunk loop. The
    /// engine uses this to apply the shared safety gate + pre-flash backup and
    /// then hand the execute flow to the bundle executor. Default `false`.
    fn flash_is_bundle(&self) -> bool {
        false
    }

    /// Whole-package (bundle) WRITE executor for families whose live flash is a
    /// single OEM update session rather than the MTK image-chunk loop. Returns
    /// `Some(result)` to own the execute flow (the engine has already run the
    /// safety gate, tray guard, and pre-flash backup); `None` (default) lets the
    /// engine use its standard image/restore flash path. `installed_backup` is the
    /// pre-flash backup bytes (the installed firmware), when one was captured, so
    /// the backend can route the flash (e.g. detect a downgrade/crossflash).
    fn flash_bundle(
        &self,
        _dev: &mut dyn ScsiDevice,
        _req: &FlashRequest,
        _installed_backup: Option<&[u8]>,
    ) -> Option<Result<()>> {
        None
    }

    /// Verify a just-captured pre-flash backup actually covers the region(s) the
    /// flash will overwrite, so it is a usable rollback. `input` is the flash
    /// input (so the check can see which components will be written). The default
    /// accepts any successful capture; a family whose capture can be PARTIAL
    /// (e.g. Pioneer, which can return a Kernel-only archive when the Normal read
    /// fails) must override this to reject a backup missing a to-be-written
    /// component.
    fn verify_preflash_backup(&self, _backup: &[u8], _input: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Whether the WRITE (flash) path is implemented. Derived from
    /// [`Self::capabilities`]; a convenience for existing call sites.
    fn is_supported(&self) -> bool {
        self.capabilities().flash
    }

    /// Read INQUIRY + boot banner (the `info` primitive). Standard for all
    /// families, so provided by default.
    fn identity(&self, dev: &mut dyn ScsiDevice) -> Identity {
        read_identity(dev)
    }

    /// Read the entire firmware image (the `dump --everything` primitive):
    /// `(image, readable_bytes, gaps)`, graceful — any offset the drive doesn't
    /// expose is filled and recorded as a gap. Read-only.
    ///
    /// Default: an "unsupported" error, so a family with no full-image read path
    /// makes the engine omit `firmware.bin` from the dump rather than panic.
    fn read_full_image(&self, _dev: &mut dyn ScsiDevice) -> Result<FullImage> {
        Err(anyhow::anyhow!(
            "full-image dump not supported for the {} family",
            self.descriptor().display_name
        ))
    }

    /// Full firmware image size in bytes (e.g. 2 MiB).
    fn image_size(&self) -> usize;

    /// Streaming chunk size in bytes (e.g. 16 KiB).
    fn chunk_size(&self) -> usize;

    /// Envelope the whole image before streaming. Returns the payload bytes and
    /// whether the enc wrap was applied.
    fn envelope(
        &self,
        dev: &mut dyn ScsiDevice,
        image: &[u8],
        enc_override: Option<bool>,
    ) -> Result<(Vec<u8>, bool)>;

    /// Human-readable dry-run plan for an `image_len`-byte flash. `verbose` adds
    /// the raw SCSI CDB sequence; the default is a clean plain-language summary.
    fn flash_plan(&self, image_len: usize, verbose: bool) -> Result<String>;

    /// Wait (read-only, bounded) for the drive to finish programming after the
    /// last chunk, before read-back verify. Default: no wait.
    fn wait_ready(&self, _dev: &mut dyn ScsiDevice) -> Result<()> {
        Ok(())
    }

    /// Read-only readiness handshake (PROBE + TEST UNIT READY) — issues NO write.
    /// The engine runs this during a dry-run so a not-ready drive is surfaced
    /// before the operator commits to `--execute`. Default: no-op.
    fn preflight(&self, _dev: &mut dyn ScsiDevice) -> Result<()> {
        Ok(())
    }

    /// Identify the installed firmware (read-only) by reading the two readable
    /// firmware-code windows and matching the built-in catalog. Default: none.
    fn firmware_report(
        &self,
        _dev: &mut dyn ScsiDevice,
    ) -> Result<Option<crate::backends::mtk::fw_ident::FwReport>> {
        Ok(None)
    }

    /// Print this backend's report for a firmware FILE (`info <file>`), or
    /// return `None` when the bytes are not this backend's format. Read-only.
    fn describe_file(&self, _image: &[u8]) -> Option<Result<()>> {
        None
    }

    /// Print this backend's vendor fields for `info`, after the standard MMC
    /// fields. Read-only. Default: none.
    fn print_device_info(&self, _dev: &mut dyn ScsiDevice) {}

    /// Print backend-specific notes for a flash plan (e.g. an authorized
    /// crossflash and its risks). Informational only; gates run separately.
    fn print_flash_notes(&self, _image: &[u8], _drive_model: &str, _allow_crossflash: bool) {}

    /// Stream a complete flash payload in one backend-owned update session,
    /// calling `progress` with the bytes sent so far after each chunk. The
    /// engine runs the shared gates (validation, backup, tray, safety) first.
    /// Default: this backend has no image-stream flash.
    fn flash_stream(
        &self,
        _dev: &mut dyn ScsiDevice,
        _payload: &[u8],
        _mode: FlashMode,
        _progress: &mut dyn FnMut(usize),
    ) -> Result<()> {
        bail!("{} has no image-stream flash", self.descriptor().id)
    }

    /// Read back `len` bytes at `offset` (the engine uses this for verify).
    /// Default: this backend has no image read-back.
    fn readback(&self, _dev: &mut dyn ScsiDevice, _offset: usize, _len: usize) -> Result<Vec<u8>> {
        bail!("{} has no image read-back", self.descriptor().id)
    }
}

/// Compatibility name while the remaining command workflow migrates to
/// protocol-based terminology.
pub use FirmwareBackend as DriveFamily;

/// Unsupported-protocol error shared by backup and flash dispatch. `family`
/// is the matched backend's display name, or [`crate::backend::UNKNOWN_FAMILY`].
pub fn unsupported_family_error(family: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "No executable flash path or confirmed restorable backup is available for {family}. \
         Identification probes may have been sent; no firmware write or backup file was produced. \
         Run `freemkv-flash info DEVICE` to record the identity before adding a backend."
    )
}
