//! OS transport layer: SCSI pass-through abstraction.
//!
//! This is one of the two independent plug-in layers (the other is [`crate::drive`]).
//! Every backend implements [`ScsiDevice`]; [`open`] performs compile-time OS
//! selection:
//!
//! * Linux — real `SG_IO` ioctl.
//! * Windows — real SPTI `IOCTL_SCSI_PASS_THROUGH_DIRECT`.
//! * macOS — real IOKit `SCSITaskDeviceInterface` via a C shim.
//!
//! A programmable [`MockScsiDevice`] is always available so unit and
//! integration tests can exercise the drive/flash logic on any host (including
//! macOS CI) without touching real hardware.

use anyhow::Result;

/// A command failure with structured sense data, independent of its display text.
#[derive(Debug)]
pub struct ScsiSenseError {
    /// SCSI sense key identifying the error category.
    pub sense_key: u8,
    /// Additional sense code supplied by the device.
    pub asc: u8,
    /// Additional sense code qualifier supplied by the device.
    pub ascq: u8,
    detail: String,
}

impl ScsiSenseError {
    /// Attach structured sense to the command's existing diagnostic text.
    pub fn new(sense_key: u8, asc: u8, ascq: u8, detail: impl Into<String>) -> Self {
        Self {
            sense_key,
            asc,
            ascq,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ScsiSenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ScsiSenseError {}

/// Recover sense through anyhow contexts without interpreting human-readable errors.
/// Transport failures without sense and malformed sense buffers return `None`.
pub fn sense_triplet(error: &anyhow::Error) -> Option<(u8, u8, u8)> {
    error
        .downcast_ref::<ScsiSenseError>()
        .map(|s| (s.sense_key, s.asc, s.ascq))
}

/// Direction of the data phase for a SCSI command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// No data phase.
    None,
    /// Data flows device -> host (e.g. INQUIRY, READ_BUFFER).
    FromDevice,
    /// Data flows host -> device (e.g. WRITE_BUFFER).
    ToDevice,
}

/// Drive medium/tray state relevant to a firmware flash. Flashing is safe ONLY
/// when the tray is closed AND empty; an open tray or a loaded disc are both
/// refused (with distinct guidance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MediumStatus {
    /// Tray closed, no disc — the only flash-safe state.
    #[default]
    ClosedEmpty,
    /// Tray is open (empty). Refuse: the tray must be closed to flash.
    TrayOpen,
    /// A disc is loaded. Refuse: reprogramming while servicing a medium can wedge.
    DiscPresent,
}

/// A raw SCSI device capable of issuing CDBs.
pub trait ScsiDevice {
    /// Issue a data-in command; returns up to `alloc_len` bytes.
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>>;

    /// Issue a data-out command, sending `data` to the device.
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()>;

    /// Issue a data-out command that tolerates NO nonzero SCSI status — any
    /// CHECK CONDITION is fatal (no RECOVERED / UNIT-ATTENTION leniency). Used by
    /// the OEM firmware-write path, which must abort on any nonzero result. The
    /// default delegates to [`Self::command_out`]; the real transport overrides
    /// it with the strict policy.
    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.command_out(cdb, data)
    }

    /// Human-readable identity of the underlying transport/device path.
    fn describe(&self) -> String;

    /// Tray/medium state, probed via TEST UNIT READY. Firmware must be flashed
    /// with a CLOSED, EMPTY tray — reprogramming while the drive services a medium
    /// can wedge it mid-program, and an open tray is not a settled flash state.
    /// The flash engine calls this to refuse a disc-loaded OR tray-open flash.
    ///
    /// The default is [`MediumStatus::ClosedEmpty`] for backends/mocks that do not
    /// model tray state, so it never blocks host-independent tests; the real
    /// transport overrides it.
    fn medium_status(&mut self) -> Result<MediumStatus> {
        Ok(MediumStatus::ClosedEmpty)
    }
}

// ---- SCSI sense decoding (shared by the transport and the flash logic) ------

/// Human-readable SCSI sense-key name (SPC-4 table 48).
pub fn sense_key_name(key: u8) -> &'static str {
    match key {
        0x0 => "NO SENSE",
        0x1 => "RECOVERED ERROR",
        0x2 => "NOT READY",
        0x3 => "MEDIUM ERROR",
        0x4 => "HARDWARE ERROR",
        0x5 => "ILLEGAL REQUEST",
        0x6 => "UNIT ATTENTION",
        0x7 => "DATA PROTECT",
        0x8 => "BLANK CHECK",
        0xA => "COPY ABORTED",
        0xB => "ABORTED COMMAND",
        0xD => "VOLUME OVERFLOW",
        0xE => "MISCOMPARE",
        _ => "UNKNOWN SENSE KEY",
    }
}

/// Plain-language meaning for the ASC/ASCQ pairs an optical drive realistically
/// returns during firmware work (readiness + write/program faults); falls back
/// to a generic note otherwise.
pub fn asc_meaning(asc: u8, ascq: u8) -> &'static str {
    match (asc, ascq) {
        (0x00, 0x00) => "no additional sense information",
        (0x03, 0x00) => "peripheral device write fault",
        (0x04, 0x00) => "logical unit not ready, cause not reportable",
        (0x04, 0x01) => "logical unit not ready, becoming ready",
        (0x04, 0x02) => "logical unit not ready, initializing command required",
        (0x08, _) => "logical unit communication failure",
        (0x0C, _) => "write error",
        (0x11, _) => "unrecovered read error",
        (0x20, 0x00) => "invalid command operation code",
        (0x21, 0x00) => "logical block address out of range",
        (0x24, 0x00) => "invalid field in CDB",
        (0x26, _) => "invalid field in parameter list",
        (0x28, 0x00) => "not-ready to ready change (medium may have changed)",
        (0x29, _) => "power-on / reset / bus-device-reset occurred",
        (0x30, _) => "incompatible medium installed",
        (0x31, 0x00) => "medium format corrupted",
        (0x3A, 0x00) => "medium not present (no disc)",
        (0x3A, 0x01) => "medium not present — tray closed (no disc)",
        (0x3A, 0x02) => "medium not present — tray open",
        (0x40, _) => "diagnostic / hardware component failure",
        (0x44, 0x00) => "internal target failure",
        (0x51, 0x00) => "erase failure",
        _ => "(see ASC/ASCQ)",
    }
}

/// Is this sense a benign "no medium present" state — NOT READY (key 0x2) with
/// ASC 0x3A (medium not present, any ASCQ: tray closed / open / no medium)?
///
/// Firmware operations need no disc loaded, so this is the *normal* state for a
/// flash and the transport must not fail the command on it. A data-in read that
/// genuinely needed medium returns no data in this state and is caught by the
/// caller's length check, so tolerating it here cannot smuggle garbage upward.
pub fn is_no_medium(key: u8, asc: u8) -> bool {
    key == 0x2 && asc == 0x3A
}

/// Classify a TEST UNIT READY `(key, ASC, ASCQ)` into a no-medium [`MediumStatus`]:
/// key 0x2 / ASC 0x3A with ASCQ 0x02 = tray open, any other ASCQ = closed empty.
/// `None` for anything that is not a positive no-medium state (the caller then
/// treats it conservatively as a loaded/unsettled drive).
pub fn medium_status_from_sense(key: u8, asc: u8, ascq: u8) -> Option<MediumStatus> {
    if !is_no_medium(key, asc) {
        return None;
    }
    Some(if ascq == 0x02 {
        MediumStatus::TrayOpen
    } else {
        MediumStatus::ClosedEmpty
    })
}

/// One-line human-readable description of a `(key, ASC, ASCQ)` sense triple,
/// e.g. `NOT READY: medium not present — tray closed (no disc) [key 0x2 ASC 3Ah/01h]`.
pub fn describe_sense(key: u8, asc: u8, ascq: u8) -> String {
    format!(
        "{}: {} [key 0x{:X} ASC {:02X}h/{:02X}h]",
        sense_key_name(key),
        asc_meaning(asc, ascq),
        key,
        asc,
        ascq
    )
}

mod adapter;
pub(crate) use adapter::trace_commands;

mod mock;
pub use mock::MockScsiDevice;

/// Open the platform's real SCSI backend for `path`.
///
/// The per-OS transports (SG_IO / IOKit / SPTI) live in libfreemkv's `scsi`
/// feature; `adapter::TransportDevice` bridges one to this crate's
/// [`ScsiDevice`] contract. `writable` is retained for source compatibility but
/// is now moot — libfreemkv opens the device O_RDWR, and the read-only
/// `info`/`dump` paths simply never issue a write.
pub fn open(path: &str, writable: bool) -> Result<Box<dyn ScsiDevice>> {
    let _ = writable;
    Ok(Box::new(adapter::TransportDevice::open(path)?))
}

/// Enumerate optical drives via the platform (IOKit / sysfs / setupapi). This is
/// media-independent: an empty macOS drive has no `/dev/diskN` node, so its
/// selector comes back as an opaque `ioreg:<id>` that `open` still accepts.
pub fn list_drives() -> Vec<libfreemkv::DriveInfo> {
    let drives = libfreemkv::list_drives();
    crate::diagnostics::record(format!("discovery: {} drive(s)", drives.len()));
    for drive in &drives {
        crate::diagnostics::record(format!(
            "discovery: path={:?} vendor={:?} model={:?} firmware={:?}",
            drive.path, drive.vendor, drive.model, drive.firmware
        ));
    }
    drives
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
