use super::*;

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "probe-test-{}",
            crate::diagnostics::new_operation_id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Reader {
    no_flash: bool,
    blocked_zero: bool,
    short_sweep: bool,
    hole: bool,
    calls: usize,
}
impl ScsiDevice for Reader {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        assert_eq!(cdb[0], 0x3c, "probe must issue only READ BUFFER");
        self.calls += 1;
        let off = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]);
        if cdb[1] != 6 || cdb[2] != 0 || self.no_flash {
            return if cdb[1] == 2 {
                Ok(vec![0; len])
            } else {
                anyhow::bail!("unsupported channel")
            };
        }
        if (self.blocked_zero && off == 0) || (self.hole && (0x1000..0x3000).contains(&off)) {
            anyhow::bail!("unreadable region");
        }
        if len > 4096 {
            anyhow::bail!("chunk too large");
        }
        if self.short_sweep && off == 0x1000 && len == 4096 {
            return Ok(vec![1; len - 1]);
        }
        let mut bytes = vec![(off / 4096) as u8 ^ 0x5a; len];
        if off == BANNER_OFF && len >= 4 {
            bytes[..4].copy_from_slice(FLASH_SIG);
        }
        Ok(bytes)
    }
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        panic!("read probe attempted a write")
    }
    fn describe(&self) -> String {
        "synthetic read-only drive".into()
    }
}

#[test]
fn raw_dump_preserves_readable_bytes_and_fills_only_reported_gaps() {
    let directory = Scratch::new();
    let path = directory.path().join("dump.bin");
    let mut drive = Reader {
        hole: true,
        ..Reader::default()
    };
    read_raw(&mut drive, 6, 0, 0, 4096, Some(&path)).unwrap();
    let image = std::fs::read(&path).unwrap();
    assert_eq!(image.len(), IMAGE_SIZE);
    assert!(image[..4096].iter().all(|b| *b == 0x5a));
    assert!(image[0x1000..0x3000].iter().all(|b| *b == 0xff));
    assert_eq!(&image[0x3000..0x3004], FLASH_SIG);
    read_raw(&mut drive, 6, 0, 0, 16, None).unwrap();
    assert!(read_raw(&mut drive, 1, 0x44, 0, 16, None).is_err());
    read_raw(&mut Reader::default(), 6, 0, 0, 4096, Some(&path)).unwrap();
    assert_ne!(std::fs::read(path).unwrap()[0x1000], 0xff);
}

#[test]
fn probe_requires_a_flash_signature_and_stops_at_blocked_or_short_reads() {
    let directory = Scratch::new();
    let path = directory.path().join("probe.bin");
    read_probe(
        &mut Reader {
            no_flash: true,
            ..Reader::default()
        },
        Some(&path),
    )
    .unwrap();
    assert!(!path.exists());
    read_probe(
        &mut Reader {
            blocked_zero: true,
            ..Reader::default()
        },
        Some(&path),
    )
    .unwrap();
    assert!(!path.exists());
    assert!(read_probe(
        &mut Reader {
            short_sweep: true,
            ..Reader::default()
        },
        Some(&path)
    )
    .is_err());
    assert!(!path.exists());
    read_probe(&mut Reader::default(), Some(&path)).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), IMAGE_SIZE as u64);
}

#[test]
fn channel_map_distinguishes_data_errors_and_zeros_without_writes() {
    let directory = Scratch::new();
    let path = directory.path().join("map.txt");
    let mut drive = Reader {
        hole: true,
        ..Reader::default()
    };
    read_map(&mut drive, Some(&path)).unwrap();
    let map = std::fs::read_to_string(&path).unwrap();
    assert!(map.contains("mode=06 buf=00"));
    assert!(map.contains("0x001000..0x003000  ERR"));
    assert!(map.contains("FLASH"));
    assert!(drive.calls >= 16 * 256);
    read_map(
        &mut Reader {
            no_flash: true,
            ..Reader::default()
        },
        Some(&path),
    )
    .unwrap();
    assert!(std::fs::read_to_string(path)
        .unwrap()
        .contains("no (mode,buf) returned real data"));
}
