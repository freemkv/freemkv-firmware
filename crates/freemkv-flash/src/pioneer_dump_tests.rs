use super::*;
use crate::platform::ScsiSenseError;

struct Device {
    reads: Vec<Vec<u8>>,
    disconnect: bool,
}
impl ScsiDevice for Device {
    fn describe(&self) -> String {
        "test drive".into()
    }
    fn command_out(&mut self, c: &[u8], b: &[u8]) -> Result<()> {
        assert_eq!(c, pioneer_optical::cdb::knock());
        assert!(b.is_empty());
        Ok(())
    }
    fn command_in(&mut self, c: &[u8], n: usize) -> Result<Vec<u8>> {
        self.reads.push(c.to_vec());
        if c[0] == 0x12 {
            return Ok(vec![0; n]);
        }
        if self.disconnect && c[2] == 0x92 {
            anyhow::bail!("disconnected");
        }
        if c[2] == 0xe7 || c[2] == 0xfc {
            return Err(ScsiSenseError::new(5, 0x24, 0, "unavailable").into());
        }
        let off = u32::from_be_bytes([0, c[3], c[4], c[5]]);
        if c[2] == 0xe5 {
            return Ok(vec![0x55]);
        }
        Ok((0..n).map(|i| ((off as usize + i) % 251) as u8).collect())
    }
}
#[test]
fn capture_preserves_addresses_records_gaps_and_captures_log_first() {
    let mut d = Device {
        reads: vec![],
        disconnect: false,
    };
    let b = capture(&mut d).unwrap();
    assert_eq!(d.reads[0], pioneer_optical::cdb::read_diagnostic_log());
    assert_eq!(b[0x410321], (0x410321 % 251) as u8);
    assert_eq!(b[0xc00d20], (0xd20 % 251) as u8);
    assert_eq!(b[0xe10000], (0x200000 % 251) as u8);
    assert!(b[0x880000..0xc00000].iter().all(|v| *v == 0));
    let dir = directory(&b).unwrap().unwrap();
    assert_eq!(dir["reads"][0]["status"], "unavailable");
    assert_eq!(dir["reads"][0]["sense"], serde_json::json!([5, 36, 0]));
    assert_eq!(dir["complete"], false); // short E5 read
    assert!(dir["logging"].as_str().unwrap().starts_with("skipped:"));
    let mut corrupt = b.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(directory(&corrupt).is_err());
    assert!(directory(&b[..100]).unwrap().is_none());
}
#[test]
fn disconnect_preserves_partial_capture_and_stops_commands() {
    let mut d = Device {
        reads: vec![],
        disconnect: true,
    };
    let b = capture(&mut d).unwrap();
    let dir = directory(&b).unwrap().unwrap();
    assert_eq!(dir["complete"], false);
    assert_eq!(d.reads.len(), 3);
    assert_eq!(dir["reads"][2]["status"], "failed");
    assert!(b[0..0x880000].iter().all(|v| *v == 0));
}
