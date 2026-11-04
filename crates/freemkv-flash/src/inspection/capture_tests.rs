use super::*;
struct CancelAfterRead(Control);
impl ScsiDevice for CancelAfterRead {
    fn command_in(&mut self, _: &[u8], len: usize) -> Result<Vec<u8>> {
        self.0.cancel();
        Ok(vec![42; len])
    }
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        panic!("no command may reach the drive after cancellation")
    }
    fn describe(&self) -> String {
        "test".into()
    }
    fn medium_status(&mut self) -> Result<MediumStatus> {
        panic!("no probe may reach the drive after cancellation")
    }
}
#[test]
fn cancellation_stops_commands_after_the_in_flight_read() {
    let control = Control::default();
    let mut underlying = CancelAfterRead(control.clone());
    let mut device = CancellableDevice {
        device: &mut underlying,
        control: &control,
    };
    assert_eq!(device.command_in(&[0x3c], 4).unwrap(), [42; 4]);
    assert!(device.command_in(&[0x3c], 4).is_err());
    assert!(device.command_out(&[0x3b], &[]).is_err());
    assert!(device.command_out_strict(&[0x3b], &[]).is_err());
    assert!(device.medium_status().is_err());
}

#[derive(Default)]
struct Recorder {
    calls: Vec<String>,
}
impl ScsiDevice for Recorder {
    fn command_in(&mut self, _: &[u8], len: usize) -> Result<Vec<u8>> {
        self.calls.push("command_in".into());
        Ok(vec![0; len])
    }
    fn diagnostic_in(&mut self, _: &[u8], len: usize, timeout_ms: u32) -> Result<Vec<u8>> {
        self.calls.push(format!("diagnostic_in:{timeout_ms}"));
        Ok(vec![0; len])
    }
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        self.calls.push("command_out".into());
        Ok(())
    }
    fn command_out_strict(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        self.calls.push("command_out_strict".into());
        Ok(())
    }
    fn command_out_directed(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        self.calls.push("command_out_directed".into());
        Ok(())
    }
    fn describe(&self) -> String {
        "test".into()
    }
}
#[test]
fn diagnostic_and_directed_commands_reach_the_inner_methods() {
    let control = Control::default();
    let mut inner = Recorder::default();
    let mut device = CancellableDevice {
        device: &mut inner,
        control: &control,
    };
    device.diagnostic_in(&[0x12], 36, 5000).unwrap();
    device.command_out_directed(&[0x3b], &[]).unwrap();
    assert_eq!(inner.calls, ["diagnostic_in:5000", "command_out_directed"]);
}
#[test]
fn cancelled_control_blocks_diagnostic_and_directed_commands() {
    let control = Control::default();
    control.cancel();
    let mut inner = Recorder::default();
    let mut device = CancellableDevice {
        device: &mut inner,
        control: &control,
    };
    assert!(device.diagnostic_in(&[0x12], 36, 5000).is_err());
    assert!(device.command_out_directed(&[0x3b], &[]).is_err());
    assert!(inner.calls.is_empty());
}
