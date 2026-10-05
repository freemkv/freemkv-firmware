//! The ONE bridge between freemkv-flash's [`ScsiDevice`] and the
//! [`pioneer_optical::transport::Transport`] the high-level
//! [`pioneer_optical::flash`] API drives.
//!
//! Everything Pioneer-vendor (identity, read-unlock knock, memory reads, OEM
//! update entry / transfer / finish, the DVR handshake) is issued by
//! `pioneer_optical::flash::*`; the rest of the flasher never builds a vendor
//! CDB. This adapter passes the crate's CDBs straight through to the SCSI layer
//! and adds the policy the flasher owns:
//!
//! * **strictness** — a flash transport sends every data-out through
//!   [`ScsiDevice::command_out_strict`] (abort on any nonzero status, no retry),
//!   exactly as the OEM host loop does; a read transport uses the lenient path;
//! * **OEM control buffer** — see [`ScsiTransport::with_control`];
//! * **abort latch** — see [`Latch`].
//!
//! Invariant (checked by `tests/no_cdbs.rs`): no Pioneer source file, this one
//! included, contains a WRITE BUFFER / READ BUFFER opcode literal.

use std::cell::{Cell, RefCell};

use anyhow::{anyhow, Result};
use pioneer_optical::flash::FlashError;
use pioneer_optical::transport::{TransferDir, Transport};

use crate::platform::{sense_triplet, ScsiDevice, ScsiSenseError};

/// A [`ScsiDevice`] that can be lent to a [`ScsiTransport`] while the caller
/// keeps issuing its own commands between session calls (the flash session
/// borrows the transport for its whole lifetime).
pub struct SharedDevice<'a>(RefCell<&'a mut dyn ScsiDevice>);

impl<'a> SharedDevice<'a> {
    /// Wrap `dev`.
    pub fn new(dev: &'a mut dyn ScsiDevice) -> Self {
        Self(RefCell::new(dev))
    }

    /// Run `f` with exclusive access to the device.
    pub fn with<R>(&self, f: impl FnOnce(&mut dyn ScsiDevice) -> R) -> R {
        f(&mut **self.0.borrow_mut())
    }

    /// Standard INQUIRY (not a Pioneer vendor command): `alloc` bytes.
    pub fn inquiry(&self, alloc: u8) -> Result<Vec<u8>> {
        self.with(|d| d.command_in(&pioneer_optical::inquiry(alloc), alloc as usize))
    }

    /// One post-flash readiness poll step: a supplementary GET EVENT STATUS drain
    /// (result ignored, as the OEM host does) then TEST UNIT READY. `Ok` means
    /// the drive is ready.
    pub fn poll_ready_once(&self) -> Result<()> {
        self.with(|d| {
            let _ = d.command_in(&pioneer_optical::get_event_status(), 0x08);
            d.command_in(&pioneer_optical::test_unit_ready(), 0)
                .map(|_| ())
        })
    }
}

/// Abort latch shared between the caller and a [`ScsiTransport`]. Once tripped
/// (by the transport on any failed command, or by the caller on a failed gate)
/// the transport refuses every further data-out locally.
///
/// Why: `pioneer_optical::flash::KernelSession` best-effort-commits (`05/FF`) on
/// drop. The OEM host never commits after a failure — a failed transfer leaves
/// the drive mid-flash and a stray commit could bless a partial image — so the
/// flasher trips the latch and the drop-time commit never reaches the wire.
#[derive(Default)]
pub struct Latch(Cell<bool>);

impl Latch {
    /// A fresh, untripped latch.
    pub fn new() -> Self {
        Self::default()
    }
    /// Refuse all further data-out commands.
    pub fn trip(&self) {
        self.0.set(true);
    }
    /// Whether the latch has been tripped.
    pub fn tripped(&self) -> bool {
        self.0.get()
    }
}

/// Adapter implementing [`Transport`] over a [`SharedDevice`].
pub struct ScsiTransport<'a, 'd> {
    dev: &'a SharedDevice<'d>,
    strict: bool,
    latch: Option<&'a Latch>,
    control: Option<&'a [u8; pioneer_optical::CONTROL_LEN as usize]>,
    sense: Option<(u8, u8, u8)>,
}

impl<'a, 'd> ScsiTransport<'a, 'd> {
    /// Read-path transport: lenient data-out (the read-unlock knock tolerates a
    /// self-clearing UNIT ATTENTION), no latch, no control buffer.
    pub fn reads(dev: &'a SharedDevice<'d>) -> Self {
        Self {
            dev,
            strict: false,
            latch: None,
            control: None,
            sense: None,
        }
    }

    /// Flash-path transport: strict data-out, guarded by `latch`.
    pub fn flash(dev: &'a SharedDevice<'d>, latch: &'a Latch) -> Self {
        Self {
            dev,
            strict: true,
            latch: Some(latch),
            control: None,
            sense: None,
        }
    }

    /// Supply the 256-byte OEM control buffer (descriptor + key).
    ///
    /// API GAP WORKAROUND: `pioneer_optical::flash::enter_kernel_mode` /
    /// `KernelSession::finish` send an all-zero control buffer for the entry and
    /// commit, but the OEM update requires the keyed control buffer in both. This
    /// transport substitutes `control` for the data-out of exactly those two crate
    /// commands (recognised by comparing against the crate's own
    /// `enter_update()` / `finish()` builders — no opcode bytes here). Delete once
    /// the crate takes the control buffer as a parameter.
    pub fn with_control(
        mut self,
        control: &'a [u8; pioneer_optical::CONTROL_LEN as usize],
    ) -> Self {
        self.control = Some(control);
        self
    }
}

impl Transport for ScsiTransport<'_, '_> {
    type Error = anyhow::Error;

    fn exec(&mut self, cdb: &[u8], dir: TransferDir, buf: &mut [u8]) -> Result<usize> {
        let result = match dir {
            TransferDir::DataIn => self.dev.with(|d| {
                let data = d.command_in(cdb, buf.len())?;
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }),
            TransferDir::None | TransferDir::DataOut => {
                if self.latch.is_some_and(Latch::tripped) {
                    return Err(anyhow!(
                        "data-out suppressed: an earlier flash step failed or was aborted"
                    ));
                }
                let payload: &[u8] = match dir {
                    TransferDir::None => &[],
                    _ => match self.control {
                        Some(control)
                            if cdb == pioneer_optical::enter_update()
                                || cdb == pioneer_optical::finish() =>
                        {
                            control
                        }
                        _ => buf,
                    },
                };
                let strict = self.strict;
                self.dev
                    .with(|d| {
                        if strict {
                            d.command_out_strict(cdb, payload)
                        } else {
                            d.command_out(cdb, payload)
                        }
                    })
                    .map(|()| payload.len())
            }
        };
        match &result {
            Ok(_) => self.sense = None,
            Err(error) => {
                self.sense = sense_triplet(error);
                if self.strict {
                    if let Some(latch) = self.latch {
                        latch.trip();
                    }
                }
            }
        }
        result
    }

    fn sense(&self) -> Option<(u8, u8, u8)> {
        self.sense
    }
}

/// Fold a high-level flash error back into `anyhow`, keeping the structured
/// sense (so `sense_triplet` still works on a `Locked` refusal).
pub fn flash_err(error: FlashError<anyhow::Error>) -> anyhow::Error {
    match error {
        FlashError::Transport(e) => e,
        FlashError::Locked => anyhow::Error::new(ScsiSenseError::new(
            5,
            0x24,
            0,
            "drive refused the command (sense 05/24/00: locked / invalid field)",
        )),
        other => anyhow!("{other}"),
    }
}

/// One vendor firmware read: exactly `len` bytes at `off`. The crate issues the
/// read-unlock knock itself before every read.
pub fn read_memory_exact(dev: &mut dyn ScsiDevice, off: u32, len: u32) -> Result<Vec<u8>> {
    let shared = SharedDevice::new(dev);
    let mut transport = ScsiTransport::reads(&shared);
    let mut buf = vec![0u8; len as usize];
    let n = pioneer_optical::flash::read_memory(&mut transport, off, len, &mut buf)
        .map_err(flash_err)?;
    buf.truncate(n);
    Ok(buf)
}

/// INQUIRY + vendor identity via `Drive::identify`, on an already-shared device.
/// Makes no state-changing call.
pub fn identify_on(shared: &SharedDevice<'_>) -> Result<pioneer_optical::flash::Identity> {
    let mut transport = ScsiTransport::reads(shared);
    pioneer_optical::flash::Drive::identify(&mut transport).map_err(flash_err)
}

/// [`identify_on`] for a bare device.
pub fn identify(dev: &mut dyn ScsiDevice) -> Result<pioneer_optical::flash::Identity> {
    identify_on(&SharedDevice::new(dev))
}
