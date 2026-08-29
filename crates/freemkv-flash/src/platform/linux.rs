//! Linux SG_IO SCSI backend.
//!
//! Talks to `/dev/sr*` / `/dev/sg*` via the `SG_IO` ioctl. Pure Rust over
//! `libc` (no hand-written C).

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

use anyhow::{anyhow, bail, Context, Result};

use super::{Direction, ScsiDevice};

// `libc::ioctl`'s request argument is typed differently per libc: `c_ulong` on
// glibc, `c_int` on musl. Match each so the same source builds for a glibc CI
// target and a static-musl release binary without a cast (which would truncate
// or trip `clippy::unnecessary_cast` on one of the two).
#[cfg(target_env = "musl")]
const SG_IO: libc::c_int = 0x2285;
#[cfg(not(target_env = "musl"))]
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

/// Extract (key, ASC, ASCQ) from a fixed- or descriptor-format sense buffer.
fn sense_kaa(sense: &[u8]) -> Option<(u8, u8, u8)> {
    match *sense.first()? {
        0x70 | 0x71 if sense.len() >= 14 => Some((sense[2] & 0x0F, sense[12], sense[13])),
        0x72 | 0x73 if sense.len() >= 4 => Some((sense[1] & 0x0F, sense[2], sense[3])),
        _ => None,
    }
}

/// Human-readable name for a SCSI sense key (SPC).
fn sense_key_name(key: u8) -> &'static str {
    match key {
        0x0 => "NO SENSE",
        0x1 => "RECOVERED ERROR",
        0x2 => "NOT READY",
        0x3 => "MEDIUM ERROR",
        0x4 => "HARDWARE ERROR",
        0x5 => "ILLEGAL REQUEST",
        0x6 => "UNIT ATTENTION",
        0x7 => "DATA PROTECT",
        0xB => "ABORTED COMMAND",
        _ => "UNKNOWN SENSE KEY",
    }
}

/// Plain-language meaning for the ASC/ASCQ pairs we actually expect from an
/// optical drive during firmware work; falls back to a generic note otherwise.
fn asc_meaning(asc: u8, ascq: u8) -> &'static str {
    match (asc, ascq) {
        (0x00, 0x00) => "no additional sense information",
        (0x04, 0x00) => "logical unit not ready, cause not reportable",
        (0x04, 0x01) => "logical unit not ready, becoming ready",
        (0x04, 0x02) => "logical unit not ready, initializing command required",
        (0x28, 0x00) => "not-ready to ready change (medium may have changed)",
        (0x29, _) => "power-on / reset / bus-device-reset occurred",
        (0x3A, 0x00) => "medium not present (no disc)",
        (0x3A, 0x01) => "medium not present — tray closed (no disc)",
        (0x3A, 0x02) => "medium not present — tray open",
        (0x20, 0x00) => "invalid command operation code",
        (0x24, 0x00) => "invalid field in CDB",
        (0x21, 0x00) => "logical block address out of range",
        (0x30, _) => "incompatible medium installed",
        _ => "(see ASC/ASCQ)",
    }
}

/// Decode a sense buffer into a one-line human-readable description, e.g.
/// `NOT READY: medium not present — tray closed (no disc) [key 0x2 ASC 3Ah/01h]`.
fn describe_sense(sense: &[u8]) -> String {
    match sense_kaa(sense) {
        Some((key, asc, ascq)) => format!(
            "{}: {} [key 0x{:X} ASC {:02X}h/{:02X}h]",
            sense_key_name(key),
            asc_meaning(asc, ascq),
            key,
            asc,
            ascq
        ),
        None => format!("unparsable sense {sense:02x?}"),
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

        // A firmware program — and any bus reset — raises UNIT ATTENTION (0x6) on
        // the *next* command, which SCSI terminates with CHECK CONDITION *without*
        // performing it. The UA self-clears once reported, so re-issuing returns
        // the real result. We therefore retry a UNIT ATTENTION exactly once, but
        // never for a data-OUT WRITE_BUFFER: re-sending the burn-triggering final
        // chunk could re-arm the program. For reads the retry is mandatory — the
        // first attempt's data phase is untrustworthy, so we must re-read rather
        // than hand back a possibly-stale/garbage buffer.
        let mut transferred = 0usize;
        for attempt in 0..2 {
            // Clear the fields the kernel writes back before each attempt (sbp
            // still points at this same, non-moved `sense` array).
            hdr.status = 0;
            hdr.host_status = 0;
            hdr.driver_status = 0;
            hdr.sb_len_wr = 0;
            hdr.resid = 0;
            sense.fill(0);

            // SAFETY: hdr is a correctly-initialised sg_io_hdr_t; buffers referenced
            // by its pointers outlive the ioctl call.
            let rc = unsafe { libc::ioctl(self.file.as_raw_fd(), SG_IO, &mut hdr as *mut SgIoHdr) };
            if rc < 0 {
                return Err(anyhow!(std::io::Error::last_os_error()))
                    .with_context(|| format!("SG_IO ioctl on {}", self.path));
            }
            // Transport-layer failures always fail. DRIVER_SENSE (0x08) only means
            // "sense data is present" (a CHECK CONDITION) — mask it off so a benign
            // CHECK CONDITION is not misread as a driver/transport error.
            if hdr.host_status != 0 || (hdr.driver_status & !DRIVER_SENSE) != 0 {
                bail!(
                    "SCSI transport failure on {}: host=0x{:04x} driver=0x{:04x}",
                    self.path,
                    hdr.host_status,
                    hdr.driver_status
                );
            }
            transferred = buf.len().saturating_sub(hdr.resid.max(0) as usize);
            if hdr.status == 0 {
                break;
            }
            let sense = &sense[..(hdr.sb_len_wr as usize).min(sense.len())];
            let key = sense_key(sense);
            // A self-clearing UNIT ATTENTION: retry once (but never a data-OUT
            // write). On a read this is the ONLY safe path — see above.
            if hdr.status == CHECK_CONDITION
                && key == Some(0x6)
                && attempt == 0
                && dir != Direction::ToDevice
            {
                continue;
            }
            // Otherwise tolerate only RECOVERED (0x1, the command DID complete)
            // and — for a NON-read command (the no-data COMMIT handshake, dir
            // None, and data-OUT WRITE BUFFER) — an un-retried UNIT ATTENTION: the
            // drive raises the post-program UA here and the trailer is a status
            // no-op, while a data-OUT write that did not actually land is still
            // caught by the transferred-length check in `command_out`. A data-IN
            // read (PROBE / TEST UNIT READY / dump / read-back) that still
            // CHECK-CONDITIONs after its one retry is NEVER tolerated: its data is
            // not valid, and silently accepting a zero-filled/garbage region would
            // corrupt a backup. NOT READY (0x2) and every hard sense key are real
            // failures.
            let tolerable = hdr.status == CHECK_CONDITION
                && (key == Some(0x1) || (dir != Direction::FromDevice && key == Some(0x6)));
            if !tolerable {
                bail!(
                    "SCSI command failed on {}: {} (status 0x{:02x}, raw sense {:02x?})",
                    self.path,
                    describe_sense(sense),
                    hdr.status,
                    sense
                );
            }
            break;
        }
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
