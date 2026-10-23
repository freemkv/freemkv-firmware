use super::*;

#[test]
fn oversized_read_is_rejected_without_truncating_it() {
    let mut dev = crate::platform::MockScsiDevice::new().on(|_| true, vec![0; 5]);
    let shared = SharedDevice::new(&mut dev);
    let mut transport = ScsiTransport::reads(&shared);
    let mut buffer = [0u8; 4];
    let error = transport.exec(&[0x3c], Data::In(&mut buffer)).unwrap_err();
    assert!(error
        .to_string()
        .contains("returned 5 bytes for a 4-byte buffer"));
}

#[test]
fn empty_update_command_is_distinct_from_a_read_probe() {
    use mediatek_optical::drive::Data as MtkData;
    let mut dev =
        crate::platform::MockScsiDevice::echoing().on_fail(|cdb| cdb == [0x3b], "PREPARE rejected");
    let shared = SharedDevice::new(&mut dev);
    let mut transport = ScsiTransport::flash(&shared);
    let mut probe = [0u8; 4];
    let _ =
        mediatek_optical::drive::Transport::exec(&mut transport, &[0x3c], MtkData::In(&mut probe));
    assert!(!transport.empty_write_attempted());
    assert!(
        mediatek_optical::drive::Transport::exec(&mut transport, &[0x3b], MtkData::Out(&[]))
            .is_err()
    );
    assert!(transport.empty_write_attempted());
}
