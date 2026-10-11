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
    assert!(flash(&mut mock, &request(false, true), &saved()).is_err());
    let error = flash(&mut mock, &request(true, false), &saved())
        .err()
        .unwrap();
    assert!(error.to_string().contains("SAFETY GATE"), "{error}");
    let mut writer = flash(&mut mock, &request(true, true), &saved()).unwrap();
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

/// A diagnostic control envelope for `pioneer_optical::logging`: `command`
/// `0x12` sets the RAM mask, `0x10` the persistent one.
fn logging_payload(command: u8) -> Vec<u8> {
    let mut data = vec![0u8; cdb::DIAGNOSTIC_CONTROL_LEN as usize];
    data[..7].copy_from_slice(&[0x31, command, 1, 0, 0x04, 0, 0]);
    data
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
