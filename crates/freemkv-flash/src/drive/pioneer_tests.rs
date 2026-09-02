//! Unit tests for the Pioneer/Renesas family (proven CDBs, read-only dump,
//! flash gated off).

use super::*;
use crate::drive::mtk::{cdb_read_buffer, cdb_write_buffer};
use crate::drive::{for_family, Family, UserDump};
use crate::manifest::FlashMode;
use crate::platform::MockScsiDevice;

// ---- Proven CDB layouts (byte-for-byte) -------------------------------------

#[test]
fn enable_knock_cdb_is_the_proven_bytes() {
    // WRITE_BUFFER mode 0x02 / buffer 0x41 @ 0xA5AAAA, no payload.
    assert_eq!(
        cdb_write_buffer(ENABLE_MODE, ENABLE_BUFFER_ID, ENABLE_OFFSET, 0),
        [0x3B, 0x02, 0x41, 0xA5, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00]
    );
}

#[test]
fn raw_read_probe_cdb_is_the_proven_bytes() {
    // READ_BUFFER mode 0x02 / buffer 0xB0 @ 0x04, len 0xA4 (the proven probe form).
    assert_eq!(
        cdb_read_buffer(RAW_MODE, RAW_BUFFER_ID, 0x04, 0xA4),
        [0x3C, 0x02, 0xB0, 0x00, 0x00, 0x04, 0x00, 0x00, 0xA4, 0x00]
    );
}

// ---- classify → dump --------------------------------------------------------

#[test]
fn pioneer_classifies_and_dumps_full_image() {
    let mut dev = MockScsiDevice::pioneer();
    assert_eq!(crate::drive::classify(&mut dev), Family::Pioneer);

    let drive = for_family(Family::Pioneer);
    assert!(drive.dump_supported(), "dump must be supported");
    assert!(!drive.is_supported(), "flash must stay unsupported");

    let (image, readable, gaps) = drive.read_full_image(&mut dev).unwrap();
    assert_eq!(image.len(), IMAGE_SIZE);
    assert_eq!(readable, IMAGE_SIZE, "the mock exposes every offset");
    assert!(gaps.is_empty());

    // Deterministic offset-derived content (mock): byte at offset N == N as u8.
    assert_eq!(image[0], 0x00);
    assert_eq!(image[0x1234], 0x34);

    // The ONE and only write is the enable knock — exactly once.
    assert_eq!(
        dev.writes.len(),
        1,
        "dump must issue a single write (the knock)"
    );
    assert_eq!(
        dev.writes[0].0,
        cdb_write_buffer(ENABLE_MODE, ENABLE_BUFFER_ID, ENABLE_OFFSET, 0).to_vec()
    );
    assert!(dev.writes[0].1.is_empty(), "the knock carries no payload");
}

#[test]
fn dump_fills_unreadable_regions_as_gaps() {
    // Make a window in the middle unreadable; it must be 0xFF-filled and recorded.
    let gap_start = 0x2000u32;
    let gap_end = 0x4000u32;
    let mut dev = MockScsiDevice::pioneer().with_pioneer_gap(gap_start, gap_end);
    let drive = for_family(Family::Pioneer);

    let (image, readable, gaps) = drive.read_full_image(&mut dev).unwrap();
    assert_eq!(image.len(), IMAGE_SIZE);
    let gap_len = (gap_end - gap_start) as usize;
    assert_eq!(readable, IMAGE_SIZE - gap_len);
    assert_eq!(gaps, vec![(gap_start as usize, gap_end as usize)]);
    // The gap is 0xFF-filled; bytes on either side are the deterministic content.
    assert!(image[gap_start as usize..gap_end as usize]
        .iter()
        .all(|&b| b == 0xFF));
    assert_eq!(
        image[gap_start as usize - 1],
        (gap_start as usize - 1) as u8
    );
    assert_eq!(image[gap_end as usize], gap_end as u8);
}

#[test]
fn renesas_classifies_and_dumps() {
    let mut dev = MockScsiDevice::renesas();
    assert_eq!(crate::drive::classify(&mut dev), Family::Renesas);

    let drive = for_family(Family::Renesas);
    assert!(drive.dump_supported());
    assert!(!drive.is_supported());
    let (image, _readable, _gaps) = drive.read_full_image(&mut dev).unwrap();
    assert_eq!(image.len(), IMAGE_SIZE);
    assert_eq!(dev.writes.len(), 1, "only the enable knock is written");
}

// ---- flash stays blocked ----------------------------------------------------

#[test]
fn flash_primitives_are_unsupported_and_write_nothing() {
    for fam in [Family::Pioneer, Family::Renesas] {
        let drive = for_family(fam);
        let mut dev = MockScsiDevice::pioneer();

        assert!(drive.read_dump(&mut dev).is_err(), "no per-unit dump");
        assert!(drive.envelope(&mut dev, &[0u8; 16], None).is_err());
        assert!(drive.flash_plan(IMAGE_SIZE, false).is_err());
        assert!(drive.flash_open(&mut dev, FlashMode::Full).is_err());
        assert!(drive.flash_chunk(&mut dev, 0, &[0u8; 4]).is_err());
        assert!(drive.flash_close(&mut dev, FlashMode::Full).is_err());
        assert!(drive.readback(&mut dev, 0, 4).is_err());
        assert!(drive.write_region(&mut dev, 0x1000, &[0u8; 4]).is_err());
        assert!(drive.restore_regions(&sample_dump()).is_empty());

        // None of the flash primitives touched the drive.
        assert!(
            dev.writes.is_empty(),
            "a read-only family must never issue a flash write"
        );
    }
}

fn sample_dump() -> UserDump {
    UserDump {
        rom_003000: vec![0; 0x20],
        rom_1ec000: vec![0; 0x100],
        rom_1f0000: vec![0; 0x10000],
        inq: vec![0; 96],
        fd_fwdate: vec![0; 28],
        fd_sn: vec![0; 28],
    }
}
