//! Linux SG_IO SCSI backend.
//!
//! Talks to `/dev/sr*` / `/dev/sg*` via the `SG_IO` ioctl. Pure Rust over
//! `libc` (no hand-written C).

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

use anyhow::{anyhow, bail, Context, Result};

use super::{Direction, ScsiDevice};

const SG_IO: libc::c_ulong = 0x2285;
const SG_DXFER_NONE: libc::c_int = -1;
const SG_DXFER_TO_DEV: libc::c_int = -2;
const SG_DXFER_FROM_DEV: libc::c_int = -3;
const SG_INTERFACE_ID_ORIG: libc::c_int = b'S' as libc::c_int;
const DEFAULT_TIMEOUT_MS: libc::c_uint = 30_000;
/// SCSI status byte for CHECK CONDITION (sense data available).
const CHECK_CONDITION: libc::c_uchar = 0x02;
/// SG driver-status bit meaning "sense data present" (a CHECK CONDITION), not a
/// transport-level driver error.
const DRIVER_SENSE: libc::c_ushort = 0x08;

/// Extract the SCSI sense key from a fixed- (0x70/0x71) or descriptor-format
/// (0x72/0x73) sense buffer; `None` if it is too short or an unknown format.
fn sense_key(sense: &[u8]) -> Option<u8> {
    match *sense.first()? {
        0x70 | 0x71 => sense.get(2).map(|&b| b & 0x0F),
        0x72 | 0x73 => sense.get(1).map(|&b| b & 0x0F),
        _ => None,
    }
}

#[repr(C)]
struct SgIoHdr {
    interface_id: libc::c_int,
    dxfer_direction: libc::c_int,
    cmd_len: libc::c_uchar,
    mx_sb_len: libc::c_uchar,
    iovec_count: libc::c_ushort,
    dxfer_len: libc::c_uint,
    dxferp: *mut libc::c_void,
    cmdp: *const libc::c_uchar,
    sbp: *mut libc::c_uchar,
    timeout: libc::c_uint,
    flags: libc::c_uint,
    pack_id: libc::c_int,
    usr_ptr: *mut libc::c_void,
    status: libc::c_uchar,
    masked_status: libc::c_uchar,
    msg_status: libc::c_uchar,
    sb_len_wr: libc::c_uchar,
    host_status: libc::c_ushort,
    driver_status: libc::c_ushort,
    resid: libc::c_int,
    duration: libc::c_uint,
    info: libc::c_uint,
}

/// A SCSI device reached through the Linux SG_IO interface.
pub struct SgioDevice {
    file: File,
    path: String,
}

impl SgioDevice {
    /// Open a SCSI generic / block device for SG_IO access. `writable` requests
    /// O_RDWR (needed for WRITE BUFFER on the `flash` path); the read-only
    /// `info`/`dump` commands pass `false` so they never require write
    /// permission on the device.
    pub fn open(path: &str, writable: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(writable)
            .open(path)
            .with_context(|| format!("opening SCSI device {path}"))?;
        Ok(Self {
            file,
            path: path.to_string(),
        })
    }

    fn ioctl(&mut self, cdb: &[u8], dir: Direction, buf: &mut [u8]) -> Result<usize> {
        if cdb.is_empty() || cdb.len() > 255 {
            bail!("invalid CDB length {}", cdb.len());
        }
        let mut sense = [0u8; 32];
        let dxfer_direction = match dir {
            Direction::None => SG_DXFER_NONE,
            Direction::FromDevice => SG_DXFER_FROM_DEV,
            Direction::ToDevice => SG_DXFER_TO_DEV,
        };

        let mut hdr = SgIoHdr {
            interface_id: SG_INTERFACE_ID_ORIG,
            dxfer_direction,
            cmd_len: cdb.len() as libc::c_uchar,
            mx_sb_len: sense.len() as libc::c_uchar,
            iovec_count: 0,
            dxfer_len: buf.len() as libc::c_uint,
            dxferp: if buf.is_empty() {
                std::ptr::null_mut()
            } else {
                buf.as_mut_ptr() as *mut libc::c_void
            },
            cmdp: cdb.as_ptr(),
            sbp: sense.as_mut_ptr(),
            timeout: DEFAULT_TIMEOUT_MS,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };

        // SAFETY: hdr is a correctly-initialised sg_io_hdr_t; buffers referenced
        // by its pointers outlive the ioctl call.
        let rc = unsafe { libc::ioctl(self.file.as_raw_fd(), SG_IO, &mut hdr as *mut SgIoHdr) };
        if rc < 0 {
            return Err(anyhow!(std::io::Error::last_os_error()))
                .with_context(|| format!("SG_IO ioctl on {}", self.path));
        }
        // Transport-layer failures always fail. DRIVER_SENSE (0x08) only means
        // "sense data is present" (i.e. a CHECK CONDITION) — mask it off so a
        // benign CHECK CONDITION is not misread as a driver/transport error.
        if hdr.host_status != 0 || (hdr.driver_status & !DRIVER_SENSE) != 0 {
            bail!(
                "SCSI transport failure on {}: host=0x{:04x} driver=0x{:04x}",
                self.path,
                hdr.host_status,
                hdr.driver_status
            );
        }
        if hdr.status != 0 {
            let sense = &sense[..(hdr.sb_len_wr as usize).min(sense.len())];
            // A CHECK CONDITION carrying a benign sense key is informational,
            // not a failure: a firmware program raises UNIT ATTENTION (0x6), and
            // a drive mid-transition raises NOT READY (0x2). Tolerate those (and
            // NO SENSE 0x0 / RECOVERED 0x1, or an unparseable/empty sense) so the
            // flash framing polls (PROBE / TEST UNIT READY / COMMIT) do not abort
            // on the near-certain post-program UNIT ATTENTION. Any other status
            // or sense key is a real command failure.
            let benign = hdr.status == CHECK_CONDITION
                && matches!(sense_key(sense), None | Some(0x0 | 0x1 | 0x2 | 0x6));
            if !benign {
                bail!(
                    "SCSI command failed on {}: status=0x{:02x} sense={:02x?}",
                    self.path,
                    hdr.status,
                    sense
                );
            }
        }
        let transferred = buf.len().saturating_sub(hdr.resid.max(0) as usize);
        Ok(transferred)
    }
}

impl ScsiDevice for SgioDevice {
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; alloc_len];
        let n = self.ioctl(cdb, Direction::FromDevice, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        let mut buf = data.to_vec();
        let dir = if buf.is_empty() {
            Direction::None
        } else {
            Direction::ToDevice
        };
        let n = self.ioctl(cdb, dir, &mut buf)?;
        if n != data.len() {
            bail!(
                "short WRITE_BUFFER: drive accepted {} of {} bytes",
                n,
                data.len()
            );
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("sgio://{}", self.path)
    }
}
