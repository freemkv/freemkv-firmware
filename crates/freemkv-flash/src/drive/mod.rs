//! Firmware command-protocol backends and read-only device classification.
//!
//! Device identity (INQUIRY vendor/product/revision), controller architecture,
//! and update command protocol are distinct. [`resolve_backend`] asks each
//! explicitly registered [`FirmwareBackend`] for read-only probe evidence and
//! rejects overlap; [`for_family`] keeps the older workflow API operational.
//!
//! A [`FirmwareBackend`] exposes protocol capabilities — identity, backup
//! capture, input validation, and flash open/chunk/close/read-back steps. It does no file
//! I/O and prints nothing. The generic orchestration (reading the input file,
//! the pre-flash backup, the dry-run plan, the streaming loop, verification, and
//! the safety gate) lives once in [`crate::engine`] and drives any family
//! through this trait. Only [`mtk`] has a proven live backup-and-flash path;
//! other candidates can classify but fail closed on writes.

use anyhow::{bail, Result};

use crate::manifest::FlashMode;
use crate::platform::ScsiDevice;

pub mod fw_ident;
pub mod mtk;
pub mod pioneer;

pub use mtk::UserDump;

/// A full firmware read: `(image, readable byte count, not-exposed `(start,end)`
/// gaps)`. The image is the whole [`DriveFamily::image_size`] span; every offset
/// a drive doesn't map to a read is filled (e.g. `0xFF`) and recorded as a gap.
/// (Aliased so the trait signature stays under clippy's complex-type lint.)
pub type FullImage = (Vec<u8>, usize, Vec<(usize, usize)>);

/// Compatibility identifier for a firmware command-protocol backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// MediaTek MT19xx (MT1959 / MT1939). Supported.
    Mtk,
    /// Pioneer OEM update protocol. Classified, not live-flash supported.
    Pioneer,
    /// Could not be classified. Fail-safe: never flashed.
    Unknown,
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Family::Mtk => "MediaTek MT19xx",
            Family::Pioneer => "Pioneer",
            Family::Unknown => "Unknown",
        })
    }
}

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

/// Read standard INQUIRY identity. Vendor ROM reads belong to a matched
/// protocol backend, never to the common identity path.
pub fn read_identity(dev: &mut dyn ScsiDevice) -> Identity {
    let mut id = Identity::default();
    if let Ok(data) = dev.command_in(&mtk::cdb_inquiry(96), 96) {
        if data.len() >= 36 {
            id.vendor = sanitize_ascii(&trim_ascii(&data[8..16]));
            id.product = sanitize_ascii(&trim_ascii(&data[16..32]));
            id.revision = sanitize_ascii(&trim_ascii(&data[32..36]));
        }
    }
    id
}

/// Read an MT19xx boot banner only from the MTK protocol probe/info path.
pub(crate) fn read_mt19_banner(dev: &mut dyn ScsiDevice) -> Option<String> {
    // The 0x3000 ROM buffer is exactly ROM_003000_LEN (32 B); asking for more
    // makes the drive reject the read with ILLEGAL REQUEST (invalid field in
    // CDB), which is why the banner previously always came back empty.
    let cdb = mtk::cdb_read_buffer(
        mtk::MODE_6,
        mtk::ROM_BUFFER_ID,
        mtk::ROM_003000_OFFSET,
        mtk::ROM_003000_LEN,
    );
    let data = dev.command_in(&cdb, mtk::ROM_003000_LEN as usize).ok()?;
    let end = data
        .iter()
        .position(|&b| b == 0 || !(0x20..0x7f).contains(&b))
        .unwrap_or(data.len());
    let banner = trim_ascii(&data[..end]);
    (!banner.is_empty()).then_some(banner)
}

/// Evidence returned by a protocol backend's read-only probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeEvidence {
    /// Backend family used by the existing engine API.
    pub family: Family,
    /// Stable protocol name independent of device branding.
    pub backend_name: &'static str,
    /// Read-only signature that justified the match.
    pub discriminator: &'static str,
}

/// A unique backend match, with device identity kept separate from the
/// controller protocol. Neither the vendor string nor the chip architecture
/// alone proves that a device accepts a backend's update commands.
#[derive(Debug, Clone)]
pub struct BackendMatch {
    /// Device-reported vendor, product, revision and optional banner.
    pub identity: Identity,
    /// Protocol signature independent of the device identity.
    pub evidence: ProbeEvidence,
}

/// Classify a drive using only proven discriminators.
///
/// * GET_CONFIG 0x46 feature 0x010C echoing `01 0C` **AND** the drive's
///   boot-ROM region at `0x003000` containing the ASCII `MT19` substring
///   (the MediaTek MT19-family boot-banner short-form; `has_mt19_banner`
///   scans the 32-byte region for it) ⇒ [`Family::Mtk`]. Both gates
///   required: feature 0x010C is the standard MMC "Firmware Information"
///   descriptor and any compliant non-MTK drive that implements it would
///   otherwise be misclassified as MTK; the MT19-family boot banner
///   ("MT1959 Boot ..." / "MT1939 Boot ...") is a hardware signature no
///   unrelated drive would happen to echo. (The longer `MTEKMT19xx`
///   identity tag lives in a different flash region at `0x1EC000 + 0x34`
///   and is NOT what this gate checks — see `has_mt19_banner` for why.)
/// * READ BUFFER mode 2, buffer-id 0xF1 (48-byte hardware identity) plus
///   positive `PIONEER` / BDR, BDC or DVR INQUIRY identity ⇒ Pioneer OEM
///   candidate. Older ATA/SCSI hardware is classified but backup refuses it.
/// * Multiple positive backend matches ⇒ ambiguous, mapped to Unknown here;
///   use [`resolve_backend`] to receive the explicit error.
/// * neither ⇒ [`Family::Unknown`].
pub fn classify(dev: &mut dyn ScsiDevice) -> Family {
    resolve_backend(dev)
        .ok()
        .flatten()
        .map_or(Family::Unknown, |m| m.evidence.family)
}

/// Explicit backend registry. Adding a controller protocol requires one entry
/// here and an implementation of [`DriveFamily::probe`]. No source-file scan or
/// vendor-name shortcut can make a new protocol flashable.
static MTK_BACKEND: mtk::Mtk = mtk::Mtk;
static PIONEER_BACKEND: pioneer::Pioneer = pioneer::Pioneer::new();
struct BackendRegistration {
    prototype: &'static dyn FirmwareBackend,
    create: fn() -> Box<dyn FirmwareBackend>,
}

static BACKENDS: [BackendRegistration; 2] = [
    BackendRegistration {
        prototype: &MTK_BACKEND,
        create: || Box::new(mtk::Mtk),
    },
    BackendRegistration {
        prototype: &PIONEER_BACKEND,
        create: || Box::new(pioneer::Pioneer::new()),
    },
];

/// Run every registered, read-only protocol probe. Ambiguous matches fail
/// closed rather than allowing registry order to select a writer.
pub fn resolve_backend(dev: &mut dyn ScsiDevice) -> Result<Option<BackendMatch>> {
    let identity = read_identity(dev);
    let mut found: Option<ProbeEvidence> = None;
    for registered in &BACKENDS {
        let backend = registered.prototype;
        if let Some(evidence) = backend.probe(dev, &identity)? {
            if evidence.family != backend.family() {
                bail!("backend probe returned an inconsistent family");
            }
            if let Some(prior) = &found {
                bail!(
                    "ambiguous firmware protocol: {} ({}) and {} ({}) both matched",
                    prior.backend_name,
                    prior.discriminator,
                    evidence.backend_name,
                    evidence.discriminator
                );
            }
            found = Some(evidence);
        }
    }
    Ok(found.map(|evidence| BackendMatch { identity, evidence }))
}

fn get_config_is_mtk(dev: &mut dyn ScsiDevice) -> bool {
    let cdb = mtk::cdb_get_config(mtk::FEATURE_FWDATE, 32);
    matches!(dev.command_in(&cdb, 32), Ok(d) if d.len() >= 10 && d[8] == 0x01 && d[9] == 0x0C)
}

/// True iff the drive's boot-ROM region at `0x003000` carries the ASCII
/// **`MT19`** boot-banner substring — the MediaTek MT19-family vendor
/// signature ("MT1959 Boot ..." / "MT1939 Boot ..." across every MT19xx
/// part). Backstops the standard MMC feature check so a compliant non-MTK
/// drive that also implements feature 0x010C cannot be misclassified as MTK
/// (which would then let a `flash --allow-crossflash` write MTK CDBs at a
/// Pioneer/Renesas controller).
///
/// The banner is a stable per-part on-flash string that the OEM ships in
/// every MT19xx image; we look for `MT19` rather than the more specific
/// `MTEKMT19` because the 32-byte boot-banner region carries the short
/// form (e.g. `"MT1959 Boot BU5"`), while the longer `MTEKMT19xx` tag lives
/// in a different region (`0x1EC000 + 0x34`, the identity descriptor).
fn has_mt19_banner(dev: &mut dyn ScsiDevice) -> bool {
    let cdb = mtk::cdb_read_buffer(
        mtk::MODE_6,
        mtk::ROM_BUFFER_ID,
        mtk::ROM_003000_OFFSET,
        mtk::ROM_003000_LEN,
    );
    let Ok(rom) = dev.command_in(&cdb, mtk::ROM_003000_LEN as usize) else {
        return false;
    };
    rom.windows(4).any(|w| w == b"MT19")
}

fn read_buffer_f1_ok(dev: &mut dyn ScsiDevice) -> bool {
    // This is the firmware receiver's 48-byte identity response, not the
    // unrelated READ BUFFER mode-0/F1 8-byte probe once used here.
    let cdb = mtk::cdb_read_buffer(0x02, 0xF1, 0x0000, 48);
    matches!(dev.command_in(&cdb, 48), Ok(d)
        if d.len() == 48
            && d[16..24].iter().all(|b| (0x20..=0x7e).contains(b))
            && [b"SAT ".as_slice(), b"ATA ".as_slice(), b"SCSI".as_slice()]
                .iter()
                .any(|prefix| d[16..24].starts_with(prefix)))
}

/// How the flash input file was sniffed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// A full 2 MB firmware image.
    Bin,
    /// A per-unit dump tar (restore those regions).
    Tar,
    /// Extractor-produced multi-component Pioneer firmware bundle.
    PioneerBundle,
}

/// Sniff the flash input kind from a path's extension (`.tar` => tar, else bin).
pub fn sniff_input(path: &std::path::Path) -> InputKind {
    if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        let n = n.to_ascii_lowercase();
        n.ends_with(".firmware.tar") || n.ends_with(".installer.tar")
    }) {
        return InputKind::PioneerBundle;
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("tar") => InputKind::Tar,
        _ => InputKind::Bin,
    }
}

/// A fully-resolved flash request handed to [`crate::engine`].
#[derive(Debug, Clone)]
pub struct FlashRequest {
    /// The raw input file bytes.
    pub input: Vec<u8>,
    /// Whether the input is a full image, rollback archive, or Pioneer bundle.
    pub input_kind: InputKind,
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
    /// Skip the mandatory pre-flash backup (dangerous: no rollback if the write
    /// fails). Default `false`: a failed backup aborts the flash.
    pub skip_backup: bool,
}

/// A per-unit region to restore from a `.tar` dump (targeted write).
#[derive(Debug, Clone, Copy)]
pub struct RestoreRegion<'a> {
    /// Human label (the tar member name).
    pub label: &'static str,
    /// Absolute ROM offset the region is written to.
    pub offset: u32,
    /// The region bytes.
    pub bytes: &'a [u8],
}

/// A firmware command protocol's primitives.
///
/// Every method is a protocol operation — no file I/O, no printing. The
/// generic [`crate::engine`] composes these into the `info` / `backup` / `flash`
/// commands. A new family only has to supply its own CDBs; the engine loop is
/// unchanged.
/// The three user-facing capabilities a backend may offer, as one declarative
/// record. The CLI derives the `info` capability line and the `backup`/`flash`
/// gates from this single source of truth rather than a scatter of booleans.
///
/// `info` (read-only identify/classify) is safe for every classified family;
/// `backup` is a complete or candidate backup capture; `flash` is the WRITE
/// path; `recover` is a deeper salvage backup. Today: MTK info+backup+flash,
/// Pioneer info+backup+flash+recover, Unknown info only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Read-only identify/classify (`info`) is available. Safe for any
    /// classified family; effectively always `true`.
    pub info: bool,
    /// A complete or candidate firmware backup can be captured (`backup`).
    pub backup: bool,
    /// The WRITE path (`flash`) is implemented and may execute.
    pub flash: bool,
    /// A distinct deeper-read `recover` capture exists (a slower, retrying,
    /// instability-tolerant salvage read). Families without it treat `recover`
    /// as an ordinary backup.
    pub recover: bool,
}

impl Capabilities {
    /// Every standard capability on (MTK's proven live backup-and-flash path).
    /// MTK has no distinct deeper recover: its backup is already a complete,
    /// verified image, so `recover` falls back to a normal backup.
    pub const fn all() -> Self {
        Self {
            info: true,
            backup: true,
            flash: true,
            recover: false,
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
    /// The family this implementation handles.
    fn family(&self) -> Family;

    /// The user-facing capabilities this backend offers. Single source of truth
    /// for the `info` label and the `backup`/`flash` gates (see [`Capabilities`]).
    fn capabilities(&self) -> Capabilities;

    /// Stable command-protocol label, distinct from device vendor and chip ISA.
    fn backend_name(&self) -> &'static str;

    /// Recognize this command protocol using read-only evidence. `None` means
    /// the protocol does not match; an error means the probe could not safely
    /// decide. The registry rejects multiple positive matches.
    fn probe(&self, dev: &mut dyn ScsiDevice, identity: &Identity)
        -> Result<Option<ProbeEvidence>>;

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
            self.backend_name()
        ))
    }

    /// Capture a backup using a deeper, retrying, instability-tolerant read to
    /// salvage a component that an ordinary [`Self::capture_backup`] could not
    /// read off a struggling drive. The default is an ordinary backup, so a
    /// family without a distinct recover (e.g. MTK) treats `recover` as
    /// `backup`.
    fn capture_recover(&self, dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
        self.capture_backup(dev)
    }

    /// Validate a backup file for this device and return the update image it
    /// contains. Backends must check completeness, integrity and model.
    fn validate_backup(&self, _bytes: &[u8], _target_model: &str) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "no proven backup restore path for {}",
            self.backend_name()
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
            self.backend_name()
        ))
    }

    /// Interpret an input path for this protocol. The default is a direct
    /// firmware image; only backends that implement a backup codec recognize
    /// their backup extension as a restorable input.
    fn classify_input(&self, _path: &std::path::Path) -> InputKind {
        InputKind::Bin
    }

    /// Inclusive byte ranges suitable for post-write read-back comparison.
    /// These are protocol-defined; no generic CMAC or boot-map assumptions
    /// belong in the engine.
    fn verification_ranges(&self, _image: &[u8]) -> Result<Vec<(usize, usize)>> {
        Err(anyhow::anyhow!(
            "read-back verification map unavailable for {}",
            self.backend_name()
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

    /// Legacy diagnostic per-unit read capability. This is distinct from a
    /// complete rollback [`Self::capture_backup`] and never permits flash.
    fn dump_supported(&self) -> bool {
        self.is_supported()
    }

    /// Read INQUIRY + boot banner (the `info` primitive). Standard for all
    /// families, so provided by default.
    fn identity(&self, dev: &mut dyn ScsiDevice) -> Identity {
        read_identity(dev)
    }

    /// Legacy diagnostic per-unit read, retained for existing MTK callers.
    fn read_dump(&self, dev: &mut dyn ScsiDevice) -> Result<UserDump>;

    /// Read the entire firmware image (the `dump --everything` primitive):
    /// `(image, readable_bytes, gaps)`, graceful — any offset the drive doesn't
    /// expose is filled and recorded as a gap. Read-only.
    ///
    /// Default: an "unsupported" error, so a family with no full-image read path
    /// makes the engine omit `firmware.bin` from the dump rather than panic.
    fn read_full_image(&self, _dev: &mut dyn ScsiDevice) -> Result<FullImage> {
        Err(anyhow::anyhow!(
            "full-image dump not supported for the {} family",
            self.family()
        ))
    }

    /// Build the read-surface map (`map.json` + `map.md`) for the `dump`
    /// everything-tar, from an ALREADY-READ `image` and its `gaps` (from
    /// [`Self::read_full_image`]) plus the `ident` header. Read-only.
    ///
    /// Default: `Ok(None)` — a family with no surface map simply omits it from
    /// the dump tar.
    fn read_surface_map(
        &self,
        _dev: &mut dyn ScsiDevice,
        _ident: &Identity,
        _image: &[u8],
        _gaps: &[(usize, usize)],
    ) -> Result<Option<(String, String)>> {
        Ok(None)
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
    fn firmware_report(&self, _dev: &mut dyn ScsiDevice) -> Result<Option<fw_ident::FwReport>> {
        Ok(None)
    }

    /// Open a flash session (preflight + prepare). One data-out command.
    fn flash_open(&self, dev: &mut dyn ScsiDevice, mode: FlashMode) -> Result<()>;

    /// Stream one chunk at absolute `offset`.
    fn flash_chunk(&self, dev: &mut dyn ScsiDevice, offset: usize, bytes: &[u8]) -> Result<()>;

    /// Close a flash session (commit + ready + status).
    fn flash_close(&self, dev: &mut dyn ScsiDevice, mode: FlashMode) -> Result<()>;

    /// Read back `len` bytes at `offset` (the engine uses this for verify).
    fn readback(&self, dev: &mut dyn ScsiDevice, offset: usize, len: usize) -> Result<Vec<u8>>;

    /// Map a per-unit dump onto the targeted regions a `.tar` restore writes.
    fn restore_regions<'a>(&self, dump: &'a UserDump) -> Vec<RestoreRegion<'a>>;

    /// Write one targeted region verbatim (the `.tar` restore primitive).
    fn write_region(&self, dev: &mut dyn ScsiDevice, offset: u32, bytes: &[u8]) -> Result<()>;
}

/// Compatibility name while the remaining command workflow migrates to
/// protocol-based terminology.
pub use FirmwareBackend as DriveFamily;

/// Return the [`DriveFamily`] implementation for a classified [`Family`].
pub fn for_family(family: Family) -> Box<dyn DriveFamily> {
    BACKENDS
        .iter()
        .find(|registered| registered.prototype.family() == family)
        .map_or_else(
            || Box::new(UnknownFamily) as Box<dyn FirmwareBackend>,
            |registered| (registered.create)(),
        )
}

/// Unsupported-protocol error shared by backup and flash dispatch.
pub fn unsupported_family_error(family: Family) -> anyhow::Error {
    anyhow::anyhow!(
        "No executable flash path or confirmed restorable backup is available for {family}. \
         Identification probes may have been sent; no firmware write or backup file was produced. \
         Run `freemkv-flash info DEVICE` to record the identity before adding a backend."
    )
}

/// Implement [`DriveFamily`] for a classified-but-unsupported family: every
/// command that would touch the drive returns the MTK-gate error, so no dump or
/// flash CDB is ever issued. Used by the Pioneer / Unknown stubs.
#[macro_export]
macro_rules! unsupported_drive_family {
    ($ty:ty, $family:expr) => {
        impl $crate::drive::DriveFamily for $ty {
            fn family(&self) -> $crate::drive::Family {
                $family
            }
            fn backend_name(&self) -> &'static str {
                "unsupported"
            }
            fn probe(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _identity: &$crate::drive::Identity,
            ) -> ::anyhow::Result<::core::option::Option<$crate::drive::ProbeEvidence>> {
                Ok(None)
            }
            fn capabilities(&self) -> $crate::drive::Capabilities {
                // Classified-but-unsupported: identify only, never back up or write.
                $crate::drive::Capabilities {
                    info: true,
                    backup: false,
                    flash: false,
                    recover: false,
                }
            }
            fn read_dump(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
            ) -> ::anyhow::Result<$crate::drive::UserDump> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn image_size(&self) -> usize {
                0
            }
            fn chunk_size(&self) -> usize {
                0
            }
            fn envelope(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _image: &[u8],
                _enc_override: ::core::option::Option<bool>,
            ) -> ::anyhow::Result<(::std::vec::Vec<u8>, bool)> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_plan(
                &self,
                _image_len: usize,
                _verbose: bool,
            ) -> ::anyhow::Result<::std::string::String> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_open(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _mode: $crate::manifest::FlashMode,
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_chunk(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: usize,
                _bytes: &[u8],
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn flash_close(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _mode: $crate::manifest::FlashMode,
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn readback(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: usize,
                _len: usize,
            ) -> ::anyhow::Result<::std::vec::Vec<u8>> {
                Err($crate::drive::unsupported_family_error($family))
            }
            fn restore_regions<'a>(
                &self,
                _dump: &'a $crate::drive::UserDump,
            ) -> ::std::vec::Vec<$crate::drive::RestoreRegion<'a>> {
                ::std::vec::Vec::new()
            }
            fn write_region(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: u32,
                _bytes: &[u8],
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::unsupported_family_error($family))
            }
        }
    };
}

/// Fallback family for [`Family::Unknown`]: refuses everything.
struct UnknownFamily;
unsupported_drive_family!(UnknownFamily, Family::Unknown);

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
