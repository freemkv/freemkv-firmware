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
