//! The ONE bridge between freemkv-flash's [`ScsiDevice`] and the
//! [`pioneer_optical::drive::Transport`] the [`pioneer_optical::drive`]
//! sequences run over.
//!
//! Everything Pioneer-vendor (identity, read-unlock knock, memory reads, OEM
//! update entry / transfer / finish, the DVR handshake) is issued by
//! `pioneer_optical::drive::*`; the rest of the flasher never builds a vendor
//! CDB. This adapter passes the crate's CDBs straight through to the SCSI layer
//! and adds the one policy the flasher owns: **strictness** — a flash transport
//! sends every data-out through [`ScsiDevice::command_out_strict`] (abort on any
//! nonzero status, no retry), exactly as the OEM host loop does; a read
//! transport uses the lenient path.
//!
//! Invariant (checked by `tests/no_cdbs.rs`): no Pioneer source file, this one
//! included, contains a WRITE BUFFER / READ BUFFER opcode literal.

use std::cell::RefCell;

use anyhow::{anyhow, Result};
use pioneer_optical::drive::{Data, Error, Transport};
use pioneer_optical::Identity;

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
        self.with(|d| d.command_in(&pioneer_optical::cdb::inquiry(alloc), alloc as usize))
    }

    /// One post-flash readiness poll step: a supplementary GET EVENT STATUS drain
    /// (result ignored, as the OEM host does) then TEST UNIT READY. `Ok` means
    /// the drive is ready.
    pub fn poll_ready_once(&self) -> Result<()> {
        self.with(|d| {
            let _ = d.command_in(&pioneer_optical::cdb::get_event_status(), 0x08);
            d.command_in(&pioneer_optical::cdb::test_unit_ready(), 0)
                .map(|_| ())
        })
    }
}

/// Adapter implementing [`Transport`] over a [`SharedDevice`].
pub struct ScsiTransport<'a, 'd> {
    dev: &'a SharedDevice<'d>,
    strict: bool,
    sense: Option<(u8, u8, u8)>,
}

impl<'a, 'd> ScsiTransport<'a, 'd> {
    /// Read-path transport: lenient data-out (the read-unlock knock tolerates a
    /// self-clearing UNIT ATTENTION).
    pub fn reads(dev: &'a SharedDevice<'d>) -> Self {
        Self {
            dev,
            strict: false,
            sense: None,
        }
    }

    /// Flash-path transport: strict data-out.
    pub fn flash(dev: &'a SharedDevice<'d>) -> Self {
        Self {
            dev,
            strict: true,
            sense: None,
        }
    }
}

impl Transport for ScsiTransport<'_, '_> {
    type Error = anyhow::Error;

    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize> {
        let strict = self.strict;
        let result = self.dev.with(|d| match data {
            Data::In(buf) => {
                let got = d.command_in(cdb, buf.len())?;
                let n = got.len();
                anyhow::ensure!(
                    n <= buf.len(),
                    "Pioneer transport returned {n} bytes for a {}-byte buffer",
                    buf.len()
                );
                buf[..n].copy_from_slice(&got[..n]);
                Ok(n)
            }
            Data::None | Data::Out(_) => {
                let payload: &[u8] = match data {
                    Data::Out(bytes) => bytes,
                    _ => &[],
                };
                if strict {
                    d.command_out_strict(cdb, payload)?;
                } else {
                    d.command_out(cdb, payload)?;
                }
                Ok(payload.len())
            }
        });
        self.sense = result.as_ref().err().and_then(sense_triplet);
        result
    }

    fn sense(&self) -> Option<(u8, u8, u8)> {
        self.sense
    }
}

/// Fold a high-level flash error back into `anyhow`, keeping the structured
/// sense (so `sense_triplet` still works on a `Locked` refusal).
pub fn flash_err(error: Error<anyhow::Error>) -> anyhow::Error {
    match error {
        Error::Transport(e) => e,
        Error::Locked => anyhow::Error::new(ScsiSenseError::new(
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
    let n =
        pioneer_optical::drive::read_memory(&mut transport, off, &mut buf).map_err(flash_err)?;
    buf.truncate(n);
    Ok(buf)
}

/// INQUIRY + vendor identity via `drive::identify`, on an already-shared device.
/// Makes no state-changing call.
pub fn identify_on(shared: &SharedDevice<'_>) -> Result<Identity> {
    let mut transport = ScsiTransport::reads(shared);
    pioneer_optical::drive::identify(&mut transport).map_err(flash_err)
}

/// [`identify_on`] for a bare device.
pub fn identify(dev: &mut dyn ScsiDevice) -> Result<Identity> {
    identify_on(&SharedDevice::new(dev))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_read_is_rejected_without_truncating_it() {
        let mut dev = crate::platform::MockScsiDevice::new().on(|_| true, vec![0; 5]);
        let shared = SharedDevice::new(&mut dev);
        let mut transport = ScsiTransport::reads(&shared);
        let mut buffer = [0u8; 4];
        let error = transport.exec(&[0x3c], Data::In(&mut buffer)).unwrap_err();
        assert!(error
            .to_string()
            .contains("returned 5 bytes for a 4-byte buffer"));
    }
}
