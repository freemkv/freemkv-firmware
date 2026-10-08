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
