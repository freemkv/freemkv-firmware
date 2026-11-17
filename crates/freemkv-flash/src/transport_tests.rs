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
    assert!(!transport.payload_write_attempted());
    assert!(
        mediatek_optical::drive::Transport::exec(&mut transport, &[0x3b], MtkData::Out(&[]))
            .is_err()
    );
    assert!(transport.empty_write_attempted());
    assert!(!transport.payload_write_attempted());
    assert!(
        mediatek_optical::drive::Transport::exec(&mut transport, &[0x3b], MtkData::Out(&[1]))
            .is_err()
    );
    assert!(transport.payload_write_attempted());
}

struct MemoryRead {
    len: usize,
    response: Option<Result<Vec<u8>>>,
    order: Vec<&'static str>,
}

impl MemoryRead {
    fn new(len: usize, response: Result<Vec<u8>>) -> Self {
        Self {
            len,
            response: Some(response),
            order: Vec::new(),
        }
    }

    fn assert_one_read(&self) {
        assert_eq!(self.order, ["knock", "read"]);
        assert!(self.response.is_none());
    }
}

impl ScsiDevice for MemoryRead {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        assert_eq!(
            cdb,
            [0x3c, 2, 0xb0, 0x12, 0x34, 0x56, 0, 0, self.len as u8, 0]
        );
        assert_eq!(len, self.len);
        self.order.push("read");
        self.response.take().expect("unexpected memory read retry")
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        assert_eq!(cdb, [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]);
        assert!(data.is_empty());
        self.order.push("knock");
        Ok(())
    }

    fn describe(&self) -> String {
        "memory read test".into()
    }
}

#[test]
fn exact_memory_read_returns_the_response_after_one_knock_and_read() {
    let bytes = vec![0x91, 0, 0xff, 0x42];
    let mut dev = MemoryRead::new(4, Ok(bytes.clone()));
    assert_eq!(read_memory_exact(&mut dev, 0x123456, 4).unwrap(), bytes);
    dev.assert_one_read();
}

#[test]
fn exact_memory_read_rejects_short_and_empty_responses_without_retry() {
    for bytes in [vec![0x91, 0x42], vec![]] {
        let actual = bytes.len();
        let mut dev = MemoryRead::new(4, Ok(bytes));
        let error = read_memory_exact(&mut dev, 0x123456, 4).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("firmware read at 0x123456 returned {actual} bytes; requested 4")
        );
        dev.assert_one_read();
    }
}

#[test]
fn partial_memory_read_preserves_short_and_empty_responses_without_retry() {
    for bytes in [vec![0x91, 0x42], vec![]] {
        let mut dev = MemoryRead::new(4, Ok(bytes.clone()));
        assert_eq!(read_memory_partial(&mut dev, 0x123456, 4).unwrap(), bytes);
        dev.assert_one_read();
    }
}

#[test]
fn memory_reads_preserve_explicit_errors_without_retry() {
    for read in [read_memory_exact, read_memory_partial] {
        let error = ScsiSenseError::new(4, 0x44, 0, "memory read failed");
        let mut dev = MemoryRead::new(4, Err(error.into()));
        let error = read(&mut dev, 0x123456, 4).unwrap_err();
        assert_eq!(sense_triplet(&error), Some((4, 0x44, 0)));
        assert!(error.to_string().contains("memory read failed"));
        dev.assert_one_read();
    }
}

#[test]
fn memory_reads_reject_oversized_responses_without_retry() {
    for read in [read_memory_exact, read_memory_partial] {
        let mut dev = MemoryRead::new(4, Ok(vec![0x91; 5]));
        let error = read(&mut dev, 0x123456, 4).unwrap_err();
        assert!(error
            .to_string()
            .contains("returned 5 bytes for a 4-byte buffer"));
        dev.assert_one_read();
    }
}

#[test]
fn zero_length_memory_reads_preserve_the_protocol_sequence() {
    for read in [read_memory_exact, read_memory_partial] {
        let mut dev = MemoryRead::new(0, Ok(vec![]));
        assert!(read(&mut dev, 0x123456, 0).unwrap().is_empty());
        dev.assert_one_read();
    }
}

#[test]
fn only_strict_transports_record_write_attempts() {
    use crate::platform::MockScsiDevice;
    use mediatek_optical::drive::{Data as MtkData, Transport as MtkTransport};
    let mut dev = MockScsiDevice::echoing();
    let shared = SharedDevice::new(&mut dev);

    let mut lenient = ScsiTransport::reads(&shared);
    lenient.exec(&[0x3b], Data::Out(&[])).unwrap();
    lenient.exec(&[0x3b], Data::Out(&[1])).unwrap();
    MtkTransport::exec(&mut lenient, &[0x3b], MtkData::Out(&[])).unwrap();
    MtkTransport::exec(&mut lenient, &[0x3b], MtkData::Out(&[1])).unwrap();
    assert!(!lenient.empty_write_attempted());
    assert!(!lenient.payload_write_attempted());

    for mtk in [false, true] {
        let mut payload = ScsiTransport::flash(&shared);
        let mut empty = ScsiTransport::flash(&shared);
        if mtk {
            MtkTransport::exec(&mut payload, &[0x3b], MtkData::Out(&[1])).unwrap();
            MtkTransport::exec(&mut empty, &[0x3b], MtkData::Out(&[])).unwrap();
        } else {
            payload.exec(&[0x3b], Data::Out(&[1])).unwrap();
            empty.exec(&[0x3b], Data::Out(&[])).unwrap();
        }
        assert!(payload.payload_write_attempted(), "mtk={mtk}");
        assert!(!payload.empty_write_attempted(), "mtk={mtk}");
        assert!(empty.empty_write_attempted(), "mtk={mtk}");
        assert!(!empty.payload_write_attempted(), "mtk={mtk}");
    }
}

#[test]
fn transports_keep_the_sense_of_the_last_failed_command() {
    use crate::platform::MockScsiDevice;
    use mediatek_optical::drive::{Data as MtkData, Transport as MtkTransport};
    let mut dev = MockScsiDevice::echoing()
        .on_sense(|c| c[0] == 0x3c, 5, 0x24, 0)
        .on(|c| c[0] == 0x12, vec![0; 4]);
    let shared = SharedDevice::new(&mut dev);
    let mut transport = ScsiTransport::reads(&shared);
    let mut buffer = [0u8; 4];
    assert!(transport.exec(&[0x3c], Data::In(&mut buffer)).is_err());
    assert_eq!(Transport::sense(&transport), Some((5, 0x24, 0)));
    transport.exec(&[0x12], Data::In(&mut buffer)).unwrap();
    assert_eq!(Transport::sense(&transport), None);
    assert!(MtkTransport::exec(&mut transport, &[0x3c], MtkData::In(&mut buffer)).is_err());
    assert_eq!(MtkTransport::sense(&transport), Some((5, 0x24, 0)));
    MtkTransport::exec(&mut transport, &[0x12], MtkData::In(&mut buffer)).unwrap();
    assert_eq!(MtkTransport::sense(&transport), None);
}

#[test]
fn mediatek_reads_are_summarized_as_complete_short_or_failed() {
    use crate::platform::MockScsiDevice;
    use mediatek_optical::drive::{Data as MtkData, Transport as MtkTransport};
    let mut dev = MockScsiDevice::echoing()
        .on(|c| c[0] == 0x3c, vec![0; 4])
        .on(|c| c[0] == 0x3d, vec![0; 2])
        .on_fail(|c| c[0] == 0x3e, "read rejected");
    let shared = SharedDevice::new(&mut dev);
    let mut transport = ScsiTransport::reads(&shared);
    assert_eq!(
        transport.read_summary(),
        "Receiver probe reads: 0 complete, 0 short, 0 failed"
    );
    let mut buffer = [0u8; 4];
    MtkTransport::exec(&mut transport, &[0x3c], MtkData::In(&mut buffer)).unwrap();
    MtkTransport::exec(&mut transport, &[0x3d], MtkData::In(&mut buffer)).unwrap();
    assert!(MtkTransport::exec(&mut transport, &[0x3e], MtkData::In(&mut buffer)).is_err());
    let summary = transport.read_summary();
    assert!(
        summary
            .starts_with("Receiver probe reads: 1 complete, 1 short, 1 failed; last read problem:"),
        "{summary}"
    );
    assert!(summary.contains("read rejected"), "{summary}");
}
