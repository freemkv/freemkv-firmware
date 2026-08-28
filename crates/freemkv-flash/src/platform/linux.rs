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
    /// Open a SCSI generic / block device for read-write SG_IO access.
    pub fn open(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening SCSI device {path}"))?;
        Ok(Self {
            file,
            path: path.to_string(),
        })
    }

    fn ioctl(&mut self, cdb: &[u8], dir: Direction, buf: &mut [u8]) -> Result<()> {
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
        if hdr.status != 0 || hdr.host_status != 0 || hdr.driver_status != 0 {
            bail!(
                "SCSI command failed: status=0x{:02x} host=0x{:04x} driver=0x{:04x} sense={:02x?}",
                hdr.status,
                hdr.host_status,
                hdr.driver_status,
                &sense[..hdr.sb_len_wr as usize]
            );
        }
        Ok(())
    }
}

impl ScsiDevice for SgioDevice {
    fn command_in(&mut self, cdb: &[u8], alloc_len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; alloc_len];
        self.ioctl(cdb, Direction::FromDevice, &mut buf)?;
        Ok(buf)
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        let mut buf = data.to_vec();
        let dir = if buf.is_empty() {
            Direction::None
        } else {
            Direction::ToDevice
        };
        self.ioctl(cdb, dir, &mut buf)
    }

    fn describe(&self) -> String {
        format!("sgio://{}", self.path)
    }
}
