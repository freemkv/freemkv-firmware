//! Backup read path for a drive already running **freemkv-modified** firmware.
//!
//! Stock MediaTek firmware exposes no command to read arbitrary flash (OEM
//! `READ BUFFER` mode6/buf0 is a CPU-memory copy, and on JB-class drives the
//! flash is not CPU-mapped, so only the calibration aperture answers — a full
//! backup-by-read is impossible on stock firmware). But firmware built by the
//! `freemkv-fw` modify engine injects a diagnostic memory-read command
//! (`Verb::DumpAll`) that peeks the drive's 32-bit address space, where flash is
//! mapped at 0. That lets us read a drive we previously modified.
//!
//! The wire format here MIRRORS `freemkv_fw::abi` (the canonical definition).
//! `freemkv-fw` depends on `freemkv-flash` (not the reverse), so it cannot be
//! imported here; a guard test on the `freemkv-fw` side asserts these bytes
//! match `abi::build_identity_cdb` / `abi::build_memread_cdb` so the two can
//! never drift. This is freemkv's own injected command, not an OEM protocol, so
//! it deliberately lives here and not in `mediatek-optical`.

use anyhow::Result;

use crate::platform::ScsiDevice;
use crate::probe::FullImage;
use mediatek_optical::layout::IMAGE_SIZE;

/// `READ BUFFER` opcode the injected handler hijacks (`abi::READ_BUFFER_OPCODE`).
const OPCODE: u8 = 0x3C;
/// The OEM-unused mode that selects the freemkv handler (`abi::KNOCK_MODE`).
const KNOCK_MODE: u8 = 0x0E;
/// The safe knock at `cdb[2..4]` (`abi::KNOCK`).
const KNOCK: [u8; 2] = [0xC0, 0xDE];
/// `Verb::Identity` (`abi.rs`): status/ping, returns the magic + version.
const VERB_IDENTITY: u8 = 0x01;
/// `Verb::DumpAll` (`abi.rs`): 64-byte memory peek at the BE address in cdb[5..9].
const VERB_DUMPALL: u8 = 0x09;
/// Bytes returned by one `DumpAll` read (`abi::MEMREAD_LEN`).
const MEMREAD_LEN: usize = 64;
/// Identity reply prefix (`abi::RESP_MAGIC`).
const RESP_MAGIC: &[u8] = b"freemkv";
/// Identity data-in allocation (matches `freemkv-fw info`'s `ALLOC_LEN`).
const IDENTITY_ALLOC: u16 = 96;

/// `IDENTITY` CDB: `3C 0E C0 DE 01 00 00 <alloc BE> 00`. Public so a guard test
/// on the `freemkv-fw` side can assert it matches `abi::build_identity_cdb`.
pub fn identity_cdb(alloc_len: u16) -> [u8; 10] {
    [
        OPCODE,
        KNOCK_MODE,
        KNOCK[0],
        KNOCK[1],
        VERB_IDENTITY,
        0,
        0,
        (alloc_len >> 8) as u8,
        alloc_len as u8,
        0,
    ]
}

/// `DUMPALL` CDB: `3C 0E C0 DE 09 <addr[31:24..7:0] BE> 00`. Public so a guard
/// test on the `freemkv-fw` side can assert it matches `abi::build_memread_cdb`.
pub fn memread_cdb(addr: u32) -> [u8; 10] {
    [
        OPCODE,
        KNOCK_MODE,
        KNOCK[0],
        KNOCK[1],
        VERB_DUMPALL,
        (addr >> 24) as u8,
        (addr >> 16) as u8,
        (addr >> 8) as u8,
        addr as u8,
        0,
    ]
}

/// Whether the drive answers the freemkv `IDENTITY` ping, i.e. it is running
/// freemkv-modified firmware. Read-only: a stock drive errors or returns
/// non-matching bytes to this OEM-unused mode, which both read as "not freemkv".
pub(crate) fn is_freemkv(dev: &mut dyn ScsiDevice) -> bool {
    match dev.command_in(&identity_cdb(IDENTITY_ALLOC), IDENTITY_ALLOC as usize) {
        Ok(data) => data.starts_with(RESP_MAGIC),
        Err(_) => false,
    }
}

/// Read the full 2 MiB firmware image through the injected `DumpAll` command
/// (flash is mapped at address 0). Returns the same `(image, readable, gaps)`
/// shape as [`crate::probe::FullImage`] so the caller validates it
/// identically. Any 64-byte window the drive will not return is `0xFF`-filled
/// and recorded as a gap. Read-only.
pub(crate) fn capture_full_image(dev: &mut dyn ScsiDevice) -> Result<FullImage> {
    let mut image = Vec::with_capacity(IMAGE_SIZE);
    let mut readable = 0usize;
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut progress = crate::style::Progress::new("reading drive memory (freemkv)", IMAGE_SIZE);
    let mut off = 0usize;
    while off < IMAGE_SIZE {
        let len = MEMREAD_LEN.min(IMAGE_SIZE - off);
        match dev.command_in(&memread_cdb(off as u32), MEMREAD_LEN) {
            Ok(data) if data.len() >= len => {
                image.extend_from_slice(&data[..len]);
                readable += len;
            }
            _ => {
                image.extend(std::iter::repeat_n(0xFFu8, len));
                match gaps.last_mut() {
                    Some((_, end)) if *end == off => *end = off + len,
                    _ => gaps.push((off, off + len)),
                }
            }
        }
        off += len;
        progress.set(off);
        crate::output::publish(crate::output::Event::Phase {
            phase: "reading",
            component: "filter.firmware",
            done: Some(off),
            total: Some(IMAGE_SIZE),
        });
    }
    Ok((image, readable, gaps))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;

    /// A drive that answers the freemkv injected commands from a backing image.
    struct FwMock {
        image: Vec<u8>,
        is_freemkv: bool,
    }

    impl ScsiDevice for FwMock {
        fn command_in(&mut self, cdb: &[u8], _alloc: usize) -> anyhow::Result<Vec<u8>> {
            // Only the freemkv knock is understood; anything else errors, like a
            // stock drive would.
            if cdb.get(..4) != Some(&[OPCODE, KNOCK_MODE, KNOCK[0], KNOCK[1]][..]) {
                bail!("not a freemkv command");
            }
            match cdb[4] {
                VERB_IDENTITY if self.is_freemkv => Ok(b"freemkv 9.9.9\0\0\0".to_vec()),
                VERB_IDENTITY => bail!("stock firmware: unknown mode"),
                VERB_DUMPALL => {
                    let addr = u32::from_be_bytes([cdb[5], cdb[6], cdb[7], cdb[8]]) as usize;
                    let end = (addr + MEMREAD_LEN).min(self.image.len());
                    Ok(self.image[addr.min(self.image.len())..end].to_vec())
                }
                other => bail!("unknown verb {other:#x}"),
            }
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> anyhow::Result<()> {
            bail!("the backup read path issues no writes")
        }
        fn describe(&self) -> String {
            "fw-mock".into()
        }
    }

    #[test]
    fn identity_cdb_layout() {
        assert_eq!(
            identity_cdb(96),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x01, 0x00, 0x00, 0x00, 0x60, 0x00]
        );
    }

    #[test]
    fn memread_cdb_packs_the_address_big_endian() {
        assert_eq!(
            memread_cdb(0x1E_D000),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x09, 0x00, 0x1E, 0xD0, 0x00, 0x00]
        );
    }

    #[test]
    fn detects_freemkv_firmware_by_the_identity_magic() {
        let mut fw = FwMock {
            image: vec![0; IMAGE_SIZE],
            is_freemkv: true,
        };
        assert!(is_freemkv(&mut fw));
        let mut stock = FwMock {
            image: vec![0; IMAGE_SIZE],
            is_freemkv: false,
        };
        assert!(!is_freemkv(&mut stock));
    }

    #[test]
    fn dumpall_reads_the_whole_image_with_no_gaps() {
        let image: Vec<u8> = (0..IMAGE_SIZE).map(|i| (i % 253) as u8).collect();
        let mut fw = FwMock {
            image: image.clone(),
            is_freemkv: true,
        };
        let (read, readable, gaps) = capture_full_image(&mut fw).unwrap();
        assert_eq!(read, image, "DumpAll must return the flash byte-for-byte");
        assert_eq!(readable, IMAGE_SIZE);
        assert!(gaps.is_empty(), "{gaps:#x?}");
    }
}

#[cfg(test)]
mod raw_dump_regression_tests {
    use super::*;
    use crate::backend::{DeviceAccess, DumpFacet, ReadDevice};

    struct Drive {
        freemkv: bool,
        short_at: Option<usize>,
        identity_reads: usize,
        dump_reads: usize,
        oem_reads: usize,
    }
    impl ScsiDevice for Drive {
        fn command_in(&mut self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>> {
            if cdb == identity_cdb(IDENTITY_ALLOC) {
                self.identity_reads += 1;
                return Ok(if self.freemkv {
                    b"freemkv 0.15.0".to_vec()
                } else {
                    vec![]
                });
            }
            if cdb.get(..5) == Some(&[OPCODE, KNOCK_MODE, KNOCK[0], KNOCK[1], VERB_DUMPALL]) {
                self.dump_reads += 1;
                let off = u32::from_be_bytes(cdb[5..9].try_into().unwrap()) as usize;
                return Ok(vec![
                    0x29;
                    if self.short_at == Some(off) {
                        alloc - 1
                    } else {
                        alloc
                    }
                ]);
            }
            if cdb.get(..3) == Some(&[0x3c, 6, 0]) {
                self.oem_reads += 1;
                return Ok(vec![0x73; alloc]);
            }
            anyhow::bail!("unexpected read {cdb:x?}")
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
            panic!("raw dump must never write")
        }
        fn describe(&self) -> String {
            "raw-dump-regression".into()
        }
    }
    fn drive(freemkv: bool) -> Drive {
        Drive {
            freemkv,
            short_at: None,
            identity_reads: 0,
            dump_reads: 0,
            oem_reads: 0,
        }
    }
    #[test]
    fn known_mtk_raw_dump_uses_injected_full_image_reader() {
        let mut dev = drive(true);
        let image = crate::backends::mtk::Mtk
            .capture(DeviceAccess::Read(&mut ReadDevice::without_unlocks(
                &mut dev,
            )))
            .unwrap();
        assert!(
            image == vec![0x29; IMAGE_SIZE],
            "raw dump must use injected bytes"
        );
        assert_eq!(dev.identity_reads, 1);
        assert_eq!(dev.dump_reads, IMAGE_SIZE / MEMREAD_LEN);
        assert_eq!(dev.oem_reads, 0);
    }
    #[test]
    fn known_mtk_raw_dump_keeps_partial_injected_capture() {
        let mut dev = drive(true);
        dev.short_at = Some(0x3000);
        let image = crate::backends::mtk::Mtk
            .capture(DeviceAccess::Read(&mut ReadDevice::without_unlocks(
                &mut dev,
            )))
            .unwrap();
        let mut expected = vec![0x29; IMAGE_SIZE];
        expected[0x3000..0x3000 + MEMREAD_LEN].fill(0xff);
        assert!(
            image == expected,
            "partial injected bytes and FF gap must be retained"
        );
        assert_eq!(dev.dump_reads, IMAGE_SIZE / MEMREAD_LEN);
        assert_eq!(dev.oem_reads, 0);
    }
    #[test]
    fn known_mtk_raw_dump_preserves_stock_reader() {
        let mut dev = drive(false);
        let image = crate::backends::mtk::Mtk
            .capture(DeviceAccess::Read(&mut ReadDevice::without_unlocks(
                &mut dev,
            )))
            .unwrap();
        assert!(
            image == vec![0x73; IMAGE_SIZE],
            "stock raw bytes must be retained"
        );
        assert_eq!(dev.identity_reads, 1);
        assert_eq!(dev.dump_reads, 0);
        assert_eq!(dev.oem_reads, IMAGE_SIZE / 0x1000);
    }
}
