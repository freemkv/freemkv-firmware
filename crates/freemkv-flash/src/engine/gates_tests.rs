use super::*;
use crate::backend::{
    Backend, BackendId, CdbPattern, Descriptor, DeviceAccess, DumpFacet, Identity, Match,
    ReadDevice,
};
use crate::backends::pioneer::{Pioneer, DESCRIPTOR as PIONEER};
use crate::platform::MockScsiDevice;
use pioneer_optical::cdb;

fn request(execute: bool, acknowledged_risk: bool) -> FlashRequest {
    FlashRequest {
        current: None,
        input: Vec::new(),
        input_format: &PIONEER.formats[0],
        mode: crate::manifest::FlashMode::Full,
        execute,
        acknowledged_risk,
        enc_override: None,
        drive_model: String::new(),
        verbose: false,
        predump_out: None,
    }
}

fn saved() -> SavedBackup {
    saved_for_tests(Vec::new())
}

#[test]
fn flash_grant_requires_execute_and_acknowledgement() {
    let mut mock = MockScsiDevice::new();
    assert!(flash(&mut mock, &request(false, true), Some(&saved())).is_err());
    let error = flash(&mut mock, &request(true, false), Some(&saved()))
        .err()
        .unwrap();
    assert!(error.to_string().contains("SAFETY GATE"), "{error}");
    let mut writer = flash(&mut mock, &request(true, true), Some(&saved())).unwrap();
    writer.command_out(&cdb::enter_update(), &[0; 256]).unwrap();
    assert_eq!(mock.writes.len(), 1);
}

#[test]
fn recovery_write_requires_execute_and_ack() {
    // The grant itself: both --execute and the acknowledgement.
    let mut mock = MockScsiDevice::new();
    assert!(recovery(&mut mock, false, true).is_err());
    assert!(recovery(&mut mock, true, false).is_err());
    assert!(recovery(&mut mock, true, true).is_ok());
    assert!(mock.writes.is_empty() && mock.reads.is_empty());

    // Through the engine: an unacknowledged execute is refused before any I/O,
    // and a dry run never sends a write.
    let mut mock = MockScsiDevice::pioneer();
    let error = crate::engine::recover(&mut mock, &Pioneer::new(), Some(b"x"), b"y", true, false)
        .unwrap_err();
    assert!(
        error.to_string().contains("acknowledging the risk"),
        "{error}"
    );
    assert!(mock.reads.is_empty() && mock.writes.is_empty());
    let mut mock = MockScsiDevice::pioneer();
    let _ = crate::engine::recover(&mut mock, &Pioneer::new(), None, b"y", false, false);
    assert!(!mock.reads.is_empty());
    assert!(
        mock.writes.iter().all(|(c, _)| *c == cdb::knock()),
        "a recovery dry run sent a write"
    );
}

/// A dump that declares only the knock but tries to enter update mode.
struct RogueDump;

static ROGUE: Descriptor = Descriptor {
    id: BackendId("rogue-dump"),
    display_name: "Rogue",
    flash_summary: None,
    formats: &[],
};

static KNOCK_ONLY: &[CdbPattern] = &[CdbPattern {
    label: "read-unlock knock",
    matches: |c, d| c == cdb::knock() && d.is_empty(),
}];

impl Backend for RogueDump {
    fn descriptor(&self) -> &'static Descriptor {
        &ROGUE
    }
    fn probe(&self, _: &mut ReadDevice<'_>, _: &Identity) -> anyhow::Result<Option<Match>> {
        Ok(None)
    }
    fn dump(&self) -> Option<&dyn DumpFacet> {
        Some(self)
    }
}

impl DumpFacet for RogueDump {
    fn writes(&self) -> &'static [CdbPattern] {
        KNOCK_ONLY
    }
    fn capture(&self, mut dev: DeviceAccess<'_, '_>) -> anyhow::Result<Vec<u8>> {
        dev.scsi().command_out(&cdb::knock(), &[])?;
        dev.scsi().command_out(&cdb::enter_update(), &[0; 256])?;
        Ok(vec![1])
    }
}

#[test]
fn dump_writes_limited_to_declared_patterns() {
    // The grant passes declared commands and refuses everything else.
    let mut mock = MockScsiDevice::new();
    {
        let mut writer = dump(&mut mock, KNOCK_ONLY);
        writer.command_out(&cdb::knock(), &[]).unwrap();
        assert!(writer.command_out(&cdb::enter_update(), &[0; 256]).is_err());
        assert!(writer
            .command_out_strict(&cdb::finish(), &[0; 256])
            .is_err());
    }
    assert_eq!(mock.writes.len(), 1);

    // Through the engine: an undeclared dump write never reaches the drive.
    let mut mock = MockScsiDevice::new();
    let out = std::env::temp_dir().join(format!("rogue-dump-{}.bin", std::process::id()));
    let error = crate::engine::backup(&mut mock, &RogueDump, &out, true).unwrap_err();
    assert!(
        format!("{error:#}").contains("refused data-out"),
        "{error:#}"
    );
    assert_eq!(mock.writes.len(), 1, "only the declared knock was sent");
    assert!(!out.exists());

    // Pioneer's real dump sends only what it declares.
    let mut mock = MockScsiDevice::pioneer();
    let out = std::env::temp_dir().join(format!("pioneer-dump-{}.bin", std::process::id()));
    let _ = crate::engine::backup(&mut mock, &Pioneer::new(), &out, true);
    let _ = std::fs::remove_file(&out);
    let declared = Pioneer::new().dump().unwrap().writes();
    assert!(!mock.writes.is_empty());
    assert!(mock
        .writes
        .iter()
        .all(|(c, d)| crate::backend::device::declared(declared, c, d)));
}

/// A diagnostic control envelope for `pioneer_optical::logging` in group
/// `0x93`: `command` `0x12` sets the RAM mask, `0x10` the persistent one.
fn logging_payload(command: u8) -> Vec<u8> {
    let mut data = vec![0u8; cdb::DIAGNOSTIC_CONTROL_LEN as usize];
    data[..7].copy_from_slice(&[0x93, command, 1, 0, 0x04, 0, 0]);
    data
}

#[test]
fn dump_grant_refuses_logging_switch_outside_dispatch_groups_or_without_arrival_bit() {
    let writes = Pioneer::new().dump().unwrap().writes();
    let control = cdb::write_diagnostic_control();
    let mut low_group = logging_payload(0x12);
    low_group[0] = 0x7f;
    let mut cleared = logging_payload(0x12);
    cleared[4] = 0;
    let mut other_bits = logging_payload(0x12);
    other_bits[3..7].copy_from_slice(&0x924d_2490u32.to_be_bytes());
    let mut mock = MockScsiDevice::new();
    {
        let mut writer = dump(&mut mock, writes);
        for refused in [&low_group, &cleared] {
            let error = writer.command_out(&control, refused).unwrap_err();
            assert!(
                format!("{error:#}").contains("refused data-out"),
                "{error:#}"
            );
        }
        writer.command_out(&control, &other_bits).unwrap();
    }
    assert_eq!(mock.writes, [(control.to_vec(), other_bits)]);
}

#[test]
fn dump_grant_refuses_persistent_logging_payload() {
    // Same CDB, different payload: only the RAM-only switch may pass.
    let writes = Pioneer::new().dump().unwrap().writes();
    let control = cdb::write_diagnostic_control();
    let mut mock = MockScsiDevice::new();
    {
        let mut writer = dump(&mut mock, writes);
        let error = writer
            .command_out(&control, &logging_payload(0x10))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("refused data-out"),
            "{error:#}"
        );
        assert!(writer.command_out(&control, &[]).is_err());
        assert!(writer.command_out(&cdb::knock(), &[0; 4]).is_err());
        writer
            .command_out(&control, &logging_payload(0x12))
            .unwrap();
        writer.command_out(&cdb::knock(), &[]).unwrap();
    }
    assert_eq!(
        mock.writes,
        [
            (control.to_vec(), logging_payload(0x12)),
            (cdb::knock().to_vec(), Vec::new())
        ]
    );
}

#[test]
fn dump_grant_refuses_zero_length_session_commands() {
    // A limited grant applies the read handle's no-data allowlist too.
    use crate::backends::mtk::cdb as mtk;
    let mut mock = MockScsiDevice::mtk();
    {
        let mut writer = dump(&mut mock, KNOCK_ONLY);
        assert!(writer.command_in(&mtk::enter_update(), 0).is_err());
        assert!(writer.command_in(&mtk::finish(), 0).is_err());
        writer.command_in(&mtk::test_unit_ready(), 0).unwrap();
    }
    assert_eq!(mock.reads, [mtk::test_unit_ready().to_vec()]);
    // A full grant is the flash path's business, not this check's.
    let mut mock = MockScsiDevice::mtk();
    ungated_for_tests(&mut mock)
        .command_in(&mtk::enter_update(), 0)
        .unwrap();
}

/// A Pioneer drive whose low memory holds a discoverable RAM logging handler
/// (dispatcher group `0x93`, mask at `0x337c`), shaped as on a real UD04.
struct LoggingDrive {
    memory: Vec<u8>,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
}

const LOGGING_MASK_AT: usize = 0x337c;

impl LoggingDrive {
    fn new() -> Self {
        let mut b = vec![0; 0x4000];
        let p = 0x108;
        b[0x100..p].copy_from_slice(&[1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 8]);
        for (n, target) in [(0usize, 0x192usize), (1, 0x17e), (2, 0x16e)] {
            let at = p + 6 * n;
            b[at..at + 4].copy_from_slice(&[0xa9, 0x10 + n as u8, 0x58, 0x70]);
            b[at + 4..at + 6].copy_from_slice(&((target - at - 6) as i16).to_be_bytes());
        }
        b[0x16e..0x176].copy_from_slice(&[0x0c, 0x11, 0x47, 4, 0x18, 0x99, 0x40, 0x1e]);
        b[0x17e..0x186].copy_from_slice(&[1, 0, 0x6b, 0x20, 0, 0, 0x33, 0x7c]);
        b[0x192..0x19a].copy_from_slice(&[0xf9, 1, 0x0f, 0xa0, 0x5e, 0, 3, 0]);
        b[0x300..0x312].copy_from_slice(&[
            1, 0, 0x6d, 0xf3, 0x0f, 0x83, 1, 0, 0x6b, 0xa0, 0, 0, 0x33, 0x7c, 0x0c, 0x99, 0x47,
            0x1e,
        ]);
        b[0x330..0x336].copy_from_slice(&[1, 0, 0x6d, 0x73, 0x54, 0x70]);
        b[0x400..0x40c].copy_from_slice(&[0x93, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0]);
        b[0x500..0x514].copy_from_slice(&[
            1, 0, 0x6b, 0x20, 0, 0, 0x33, 0x7c, 0x7a, 0x60, 0, 4, 0, 0, 0x19, 0x99, 0x0f, 0x80,
            0x47, 4,
        ]);
        b[LOGGING_MASK_AT..LOGGING_MASK_AT + 4].copy_from_slice(&0x9249_2490u32.to_be_bytes());
        Self {
            memory: b,
            writes: Vec::new(),
        }
    }

    fn mask(&self) -> u32 {
        u32::from_be_bytes(
            self.memory[LOGGING_MASK_AT..LOGGING_MASK_AT + 4]
                .try_into()
                .unwrap(),
        )
    }
}

impl ScsiDevice for LoggingDrive {
    fn describe(&self) -> String {
        "logging drive".into()
    }
    fn command_in(&mut self, c: &[u8], n: usize) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0; n];
        if c.len() == 10 && c[2] == cdb::MEMORY_ID {
            let off = u32::from_be_bytes([0, c[3], c[4], c[5]]) as usize;
            for (i, v) in out.iter_mut().enumerate() {
                *v = self.memory.get(off + i).copied().unwrap_or(0);
            }
        }
        Ok(out)
    }
    fn command_out(&mut self, c: &[u8], d: &[u8]) -> anyhow::Result<()> {
        if c == cdb::write_diagnostic_control() {
            self.memory[LOGGING_MASK_AT..LOGGING_MASK_AT + 4].copy_from_slice(&d[3..7]);
        }
        self.writes.push((c.to_vec(), d.to_vec()));
        Ok(())
    }
}

#[test]
fn real_dump_enables_logging_through_its_limited_grant() {
    // The engine's dump grant, the backend's declared writes and the real
    // capture: pioneer-optical builds the logging payload, the grant judges it.
    let pioneer = Pioneer::new();
    let facet = pioneer.dump().unwrap();
    let mut drive = LoggingDrive::new();
    let bytes = facet
        .capture(DeviceAccess::Write(&mut dump(&mut drive, facet.writes())))
        .unwrap();
    let directory = crate::backends::pioneer::dump::directory(&bytes)
        .unwrap()
        .unwrap();
    assert_eq!(
        directory["logging"],
        "enabled in RAM; mask address 0x337c, group 0x93, bit 0x40000"
    );
    let control = cdb::write_diagnostic_control();
    assert_eq!(
        drive.writes.iter().filter(|(c, _)| *c == control).count(),
        1,
        "the RAM logging switch never reached the drive: {:02x?}",
        drive.writes
    );
    assert_eq!(drive.mask(), 0x9249_2490 | 0x0004_0000);
}
