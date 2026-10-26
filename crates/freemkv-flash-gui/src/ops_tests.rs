use super::*;
use freemkv_flash::platform::MockScsiDevice;

/// Discovery must work even on a host with no optical drive attached.
#[test]
fn enumerate_does_not_panic() {
    let list = enumerate();
    // Every entry a shell would show must be a plausible device path.
    for d in &list {
        assert!(!d.path.is_empty());
    }
}

/// Job dispatch must surface a clean `Err` — never a panic — when the
/// selected device cannot be opened. This exercises the same `execute`
/// path the GUI's worker thread runs, minus the stdout capture.
#[test]
fn info_job_on_missing_device_errs_without_panic() {
    let res = execute(
        "/dev/freemkv-flash-gui-no-such-device",
        &Job::Info,
        &mut freemkv_flash::workflow::Preconfirmed,
    );
    assert!(res.is_err(), "expected an open error");
}

/// A Pioneer-style receiver that no protocol probe matches but whose recovery
/// backend identifies it (vendor, product, serial and platform as given).
fn receiver(platform: &[u8]) -> MockScsiDevice {
    let mut inq = vec![b' '; 96];
    inq[0] = 5;
    inq[4] = 91;
    inq[8..16].copy_from_slice(b"PIONEER ");
    inq[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
    inq[32..36].copy_from_slice(b"1.14");
    let mut f1 = vec![b' '; 48];
    f1[..3].copy_from_slice(b"SN1");
    f1[16..16 + platform.len()].copy_from_slice(platform);
    f1[24..28].copy_from_slice(b"ID58");
    f1[32..36].copy_from_slice(b"ID58");
    f1[40..44].copy_from_slice(b"0000");
    MockScsiDevice::new()
        .on(|cdb| cdb.first() == Some(&0x12), inq)
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            f1,
        )
}

fn profile_of(mut dev: MockScsiDevice) -> Profile {
    profile_view(&freemkv_flash::workflow::profile_on(&mut dev).unwrap())
}

#[test]
fn recovery_is_offered_for_an_unsupported_identified_drive() {
    let profile = profile_of(receiver(b"BDR 8A10"));
    assert_eq!(profile.tasks, [Task::Backup, Task::Dump, Task::Recovery]);
    assert_eq!(profile.chips, ["Pioneer"]);
    assert_eq!(
        profile.backup_name.as_deref(),
        Some("BD-RW___BDR-UD04_1.14.candidate.tar")
    );
    assert_eq!(
        profile.dump_name.as_deref(),
        Some("BD-RW___BDR-UD04_1.14.dump.bin")
    );
    assert!(profile.recovery_without_live_protocol);
    assert_eq!(profile.can_read, Some(true));

    let profile = profile_of(MockScsiDevice::new());
    assert!(profile.tasks.is_empty() && !profile.inspect);
    assert_eq!(profile.chips, ["modify.not_supported"]);
}

#[test]
fn rec_profile_offers_backup_and_dump_without_flash() {
    for hardware in [b"REC 8301", b"REC 8800", b"REC 8C00"] {
        let profile = profile_of(receiver(hardware));
        assert!(profile.tasks.contains(&Task::Dump));
        assert!(profile.tasks.contains(&Task::Backup));
        assert!(!profile.tasks.contains(&Task::Flash));
        assert!(profile.dump_name.is_some());
        assert!(profile.backup_name.is_some());
        assert!(!profile.flash_current);
    }
}

#[test]
fn a_supported_drive_offers_its_facets_with_names_from_the_backup_format() {
    let profile = profile_of(receiver(b"SAT 8A10"));
    assert_eq!(
        profile.tasks,
        [Task::Backup, Task::Dump, Task::Flash, Task::Recovery]
    );
    assert_eq!(profile.chips, ["Pioneer"]);
    assert_eq!(
        profile.backup_name.as_deref(),
        Some("BD-RW___BDR-UD04_1.14.candidate.tar")
    );
    assert_eq!(
        profile.dump_name.as_deref(),
        Some("BD-RW___BDR-UD04_1.14.dump.bin")
    );
}
