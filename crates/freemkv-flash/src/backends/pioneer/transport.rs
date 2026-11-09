//! Pioneer read and identity command sequences over the shared SCSI adapter.
use crate::platform::ScsiDevice;
use crate::transport::{flash_err, ScsiTransport, SharedDevice};
use anyhow::Result;
use pioneer_optical::Identity;

/// One vendor firmware read: at most `len` bytes at `off`, with no retry.
/// The crate issues the read-unlock knock itself before the read.
pub fn read_memory_partial(dev: &mut dyn ScsiDevice, off: u32, len: u32) -> Result<Vec<u8>> {
    let shared = SharedDevice::new(dev);
    let mut transport = ScsiTransport::reads(&shared);
    let mut buf = vec![0u8; len as usize];
    let n =
        pioneer_optical::drive::read_memory(&mut transport, off, &mut buf).map_err(flash_err)?;
    buf.truncate(n);
    Ok(buf)
}

/// One vendor firmware read: exactly `len` bytes at `off`, with no retry.
/// The crate issues the read-unlock knock itself before the read.
pub fn read_memory_exact(dev: &mut dyn ScsiDevice, off: u32, len: u32) -> Result<Vec<u8>> {
    let data = read_memory_partial(dev, off, len)?;
    anyhow::ensure!(
        data.len() == len as usize,
        "firmware read at {off:#x} returned {} bytes; requested {len}",
        data.len()
    );
    Ok(data)
}

/// Capture uses the same validated CDB response contract as discovery.
pub fn identify_protocol(dev: &mut dyn ScsiDevice) -> Result<Identity> {
    let shared = SharedDevice::new(dev);
    let mut transport = ScsiTransport::reads(&shared);
    pioneer_optical::drive::identify_protocol(&mut transport).map_err(flash_err)
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
