//! Pioneer / Renesas drive family — read-only DUMP support.
//!
//! Pioneer (INQUIRY vendor `PIONEER`) and Renesas / HL-DT-ST (`RENESAS`) are the
//! same silicon and speak the same protocol here, so a single implementation
//! backs both ([`Pioneer`] and [`super::renesas::Renesas`] via the
//! [`renesas_pioneer_drive_family!`] macro).
//!
//! ## DUMP is supported; FLASH is NOT
//! The full drive-memory image can be read out (read-only). Every WRITE (flash)
//! primitive returns [`flash_unsupported`]; freemkv-flash never programs a
//! Pioneer/Renesas drive.
//!
//! ## The one allowed write: the vendor "enable" knock
//! The SOLE write this family ever issues is the universal Pioneer "enable"
//! knock — `WRITE_BUFFER` mode 0x02 / buffer id 0x41 @ 0xA5AAAA, no payload
//! (`3B 02 41 A5 AA AA 00 00 00 00`) — which flips the drive into raw-read mode.
//! It is idempotent and gated to the dump path in [`read_full_image`]; it is
//! never sent during classify / identity / info.
//!
//! ## RAW READ
//! After the knock, the drive memory is read with `READ_BUFFER` mode 0x02 /
//! buffer id 0xB0 at a 3-byte big-endian offset (`3C 02 B0 <off[3 BE]>
//! <len[3 BE]> 00`).

use anyhow::{Context, Result};

use super::mtk::{cdb_read_buffer, cdb_write_buffer};
use super::{Family, FullImage};
use crate::platform::ScsiDevice;

// ---- Protocol constants -----------------------------------------------------

/// Enable-knock WRITE_BUFFER mode (0x02).
pub(crate) const ENABLE_MODE: u8 = 0x02;
/// Enable-knock WRITE_BUFFER buffer id (0x41).
pub(crate) const ENABLE_BUFFER_ID: u8 = 0x41;
/// Enable-knock WRITE_BUFFER offset (0xA5AAAA), no payload.
pub(crate) const ENABLE_OFFSET: u32 = 0xA5_AAAA;

/// Raw-read READ_BUFFER mode (0x02).
pub(crate) const RAW_MODE: u8 = 0x02;
/// Raw-read READ_BUFFER buffer id (0xB0). The full-image sweep uses
/// [`DUMP_CHUNK`]-sized reads (see the byte-exact CDB-layout test).
pub(crate) const RAW_BUFFER_ID: u8 = 0xB0;

/// Full drive-memory image span captured by a dump (6 MiB).
///
/// The 3-byte CDB offset addresses up to 16 MiB; the two known probe windows
/// are 0x04 and 0x500000, so 6 MiB comfortably covers the readable region with
/// margin. Offsets the drive doesn't map to a read are filled with
/// `0xFF` and recorded as gaps (exactly like the MTK full-image read).
pub(crate) const IMAGE_SIZE: usize = 0x60_0000;
/// Full-image sweep chunk (4 KiB), matching the MTK read granularity. Used as
/// the fast-path read size; on refusal the sweep falls back to [`RELIABLE_READ`].
pub(crate) const DUMP_CHUNK: usize = 0x1000;
/// The only READ_BUFFER length proven to be accepted (164 B, `0xA4`). When a
/// larger [`DUMP_CHUNK`] read is refused — some drives cap READ_BUFFER below the
/// chunk size — the sweep retries the same window in these units so the dump
/// still succeeds. Correctness over speed.
pub(crate) const RELIABLE_READ: usize = 0xA4;

// ---- Primitives -------------------------------------------------------------

/// Issue the vendor "enable" knock — the ONLY write this family ever sends.
///
/// Idempotent; flips the drive into raw-read mode. Called once at the start of
/// [`read_full_image`] and nowhere else.
pub(crate) fn enable(dev: &mut dyn ScsiDevice) -> Result<()> {
    let cdb = cdb_write_buffer(ENABLE_MODE, ENABLE_BUFFER_ID, ENABLE_OFFSET, 0);
    dev.command_out(&cdb, &[])
        .context("Pioneer enable knock (WRITE BUFFER 3B 02 41 A5 AA AA) failed")
}

/// One raw READ_BUFFER (mode 0x02 / buffer 0xB0) at `off` for `len` bytes.
fn raw_read(dev: &mut dyn ScsiDevice, off: u32, len: u32) -> Result<Vec<u8>> {
    let cdb = cdb_read_buffer(RAW_MODE, RAW_BUFFER_ID, off, len);
    dev.command_in(&cdb, len as usize)
}

/// Read the full drive-memory image (the dump primitive), GRACEFUL: issue the
/// enable knock ONCE, then sweep `READ_BUFFER 0xB0` across `0..IMAGE_SIZE` in
/// [`DUMP_CHUNK`] steps; any offset the drive doesn't expose is filled with
/// `0xFF` and recorded as a gap. Returns `(image, readable_bytes, gaps)`.
/// Read-only apart from the single enable knock.
///
/// The emitted bytes are the RAW ROM.
// NOTE: the raw ROM bytes are emitted as-read. Any post-processing/transform is
// UNVALIDATED without hardware, so freemkv-flash deliberately does not apply one.
pub(crate) fn read_full_image(dev: &mut dyn ScsiDevice) -> Result<FullImage> {
    // The one and only write: the vendor enable knock. Idempotent; gated to the
    // dump path so it never fires during classify / identity / info.
    enable(dev)?;

    let mut image = Vec::with_capacity(IMAGE_SIZE);
    let mut readable = 0usize;
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut off = 0usize;
    while off < IMAGE_SIZE {
        let l = DUMP_CHUNK.min(IMAGE_SIZE - off);
        // Fast path: one big read for the whole chunk.
        if let Some(v) = raw_read(dev, off as u32, l as u32)
            .ok()
            .filter(|v| v.len() == l)
        {
            image.extend_from_slice(&v);
            readable += l;
            off += l;
            continue;
        }
        // Fallback: the big read was refused or short. The drive may cap
        // READ_BUFFER below DUMP_CHUNK, so retry the SAME window in RELIABLE_READ
        // (164 B — the only proven length) units. Only a sub-read that ALSO fails
        // becomes a gap; the 0xFF gap fills coalesce back into one contiguous
        // range, so the dump shape is identical to a single-read sweep.
        let end = off + l;
        while off < end {
            let sl = RELIABLE_READ.min(end - off);
            match raw_read(dev, off as u32, sl as u32) {
                Ok(v) if v.len() == sl => {
                    image.extend_from_slice(&v);
                    readable += sl;
                }
                _ => {
                    image.extend(std::iter::repeat_n(0xFFu8, sl));
                    match gaps.last_mut() {
                        Some((_, gend)) if *gend == off => *gend = off + sl,
                        _ => gaps.push((off, off + sl)),
                    }
                }
            }
            off += sl;
        }
    }
    Ok((image, readable, gaps))
}

/// The error returned by every FLASH primitive: this family is read-only.
pub(crate) fn flash_unsupported(family: Family) -> anyhow::Error {
    anyhow::anyhow!(
        "FLASH is not supported for the {family} family — freemkv-flash is read-only \
         (dump) for Pioneer/Renesas silicon. The only write it ever issues is the \
         vendor enable knock, and only on the dump path."
    )
}

/// Implement [`crate::drive::DriveFamily`] for a Pioneer/Renesas struct: DUMP
/// (read-only) is supported; every WRITE (flash) primitive returns
/// [`flash_unsupported`]. Shared by [`Pioneer`] and
/// [`super::renesas::Renesas`], which differ only in [`Family`].
#[macro_export]
macro_rules! renesas_pioneer_drive_family {
    ($ty:ty, $family:expr) => {
        impl $crate::drive::DriveFamily for $ty {
            fn family(&self) -> $crate::drive::Family {
                $family
            }
            fn is_supported(&self) -> bool {
                // FLASH (write) is unsupported.
                false
            }
            fn dump_supported(&self) -> bool {
                // DUMP (read-only) is supported.
                true
            }
            fn read_dump(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
            ) -> ::anyhow::Result<$crate::drive::UserDump> {
                // The six per-unit regions are an MTK-specific layout and do not
                // map onto this silicon. The dump is the full-image read instead
                // (the engine degrades gracefully when this is absent).
                ::anyhow::bail!(
                    "per-unit region dump is not defined for the {} family; \
                     the full-image dump (read-only) is used instead",
                    $family
                )
            }
            fn read_full_image(
                &self,
                dev: &mut dyn $crate::platform::ScsiDevice,
            ) -> ::anyhow::Result<$crate::drive::FullImage> {
                $crate::drive::pioneer::read_full_image(dev)
            }
            fn image_size(&self) -> usize {
                $crate::drive::pioneer::IMAGE_SIZE
            }
            fn chunk_size(&self) -> usize {
                $crate::drive::pioneer::DUMP_CHUNK
            }
            fn envelope(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _image: &[u8],
                _enc_override: ::core::option::Option<bool>,
            ) -> ::anyhow::Result<(::std::vec::Vec<u8>, bool)> {
                Err($crate::drive::pioneer::flash_unsupported($family))
            }
            fn flash_plan(
                &self,
                _image_len: usize,
                _verbose: bool,
            ) -> ::anyhow::Result<::std::string::String> {
                Err($crate::drive::pioneer::flash_unsupported($family))
            }
            fn flash_open(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _mode: $crate::manifest::FlashMode,
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::pioneer::flash_unsupported($family))
            }
            fn flash_chunk(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: usize,
                _bytes: &[u8],
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::pioneer::flash_unsupported($family))
            }
            fn flash_close(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _mode: $crate::manifest::FlashMode,
            ) -> ::anyhow::Result<()> {
                Err($crate::drive::pioneer::flash_unsupported($family))
            }
            fn readback(
                &self,
                _dev: &mut dyn $crate::platform::ScsiDevice,
                _offset: usize,
                _len: usize,
            ) -> ::anyhow::Result<::std::vec::Vec<u8>> {
                Err($crate::drive::pioneer::flash_unsupported($family))
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
                Err($crate::drive::pioneer::flash_unsupported($family))
            }
        }
    };
}

/// The Pioneer drive family (read-only dump).
pub struct Pioneer;

renesas_pioneer_drive_family!(Pioneer, Family::Pioneer);

#[cfg(test)]
#[path = "pioneer_tests.rs"]
mod tests;
