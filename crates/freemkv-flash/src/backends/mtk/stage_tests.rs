//! Exercise automatic stages with a simulated receiver that boots each write.
use super::super::fixture;
use super::*;
use crate::platform::MockScsiDevice;

struct Drive {
    inner: MockScsiDevice,
    written: Vec<u8>,
    stages: Vec<Vec<u8>>,
    boot_intermediate: bool,
    encrypted_after: bool,
    wire_stages: Vec<Vec<u8>>,
}
impl ScsiDevice for Drive {
    fn command_in(&mut self, cdb: &[u8], n: usize) -> Result<Vec<u8>> {
        self.inner.command_in(cdb, n)
    }
    fn command_out(&mut self, command: &[u8], data: &[u8]) -> Result<()> {
        self.inner.command_out(command, data)?;
        if command.first() == Some(&0x3b) && command.get(1) == Some(&6) && !data.is_empty() {
            let offset =
                ((command[3] as usize) << 16) | ((command[4] as usize) << 8) | command[5] as usize;
            self.written[offset..offset + data.len()].copy_from_slice(data);
        }
        if command == cdb::finish() {
            self.wire_stages.push(self.written.clone());
            if self.encrypted_after && !self.stages.is_empty() {
                mediatek_optical::enc::decrypt(&mut self.written).unwrap();
            }
            self.stages.push(self.written.clone());
            if self.boot_intermediate || self.stages.len() > 1 {
                let mut inquiry = vec![0; 36];
                inquiry[0] = 5;
                inquiry[4] = 31;
                inquiry[8..36].copy_from_slice(&self.written[0x1ec000..0x1ec01c]);
                self.inner = MockScsiDevice::echoing()
                    .with_firmware_image(self.written.clone())
                    .on(|c| c.first() == Some(&0x12), inquiry);
            }
        }
        Ok(())
    }
    fn describe(&self) -> String {
        "staged fixture".into()
    }
}
fn image(revision: &[u8; 4], code: u8) -> Vec<u8> {
    let mut bytes = fixture::image(&fixture::BU3, "BD-RE BU40N", code);
    bytes[0x1ec000..0x1ec008].copy_from_slice(b"HL-DT-ST");
    bytes[0x1ec018..0x1ec01c].copy_from_slice(revision);
    mediatek_optical::image::cmac::resign(&bytes).unwrap()
}
fn run(boot: bool, encrypted_after: bool) -> (Result<()>, Drive, Vec<u8>, Vec<u8>) {
    let initial = image(b"1.00", 1);
    let mut intermediate = image(b"INTM", 2);
    if encrypted_after {
        encrypted_receiver(&mut intermediate);
    }
    let final_image = image(b"1.05", 3);
    let mut dev = Drive {
        inner: MockScsiDevice::echoing().with_firmware_image(initial.clone()),
        written: vec![0; IMAGE_SIZE],
        stages: vec![],
        boot_intermediate: boot,
        encrypted_after,
        wire_stages: Vec::new(),
    };
    let receiver = detect_receiver(&mut ReadDevice::without_unlocks(&mut dev)).unwrap();
    let live = fixture::identity(&initial);
    let prepared = authorize_bytes(
        &live,
        "BD-RE BU40N",
        Verdict::SameModel,
        &intermediate,
        Some(&initial),
    )
    .unwrap();
    let plan = FlashPlan::new(Plan {
        image: intermediate.clone(),
        final_image: Some(final_image.clone()),
        live,
        receiver,
        drive_product: "BD-RE BU40N".into(),
        verdict: Verdict::SameModel,
    });
    let authorized = AuthorizedPlan::new(plan, prepared);
    let result = Mtk.execute(
        &mut crate::engine::gates::ungated_for_tests(&mut dev),
        &authorized,
    );
    (result, dev, intermediate, final_image)
}
#[test]
fn stages_write_intermediate_then_final() {
    let (result, dev, intermediate, final_image) = run(true, false);
    result.unwrap();
    assert_eq!(dev.stages, vec![intermediate, final_image]);
}
#[test]
fn failed_intermediate_startup_prevents_final_write() {
    let (result, dev, intermediate, _) = run(false, false);
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("startup was not confirmed"));
    assert_eq!(dev.stages, vec![intermediate]);
}

fn encrypted_receiver(image: &mut [u8]) {
    image[0x9a300..0x9a340].fill(0);
    let call = 0x9a320;
    let target = 0x9b000;
    image[call - 12..call]
        .copy_from_slice(&[0xeb, 0x69, 0x10, 0x22, 1, 0xa9, 3, 0x20, 0, 3, 0x18, 0x18]);
    let delta = target - call - 4;
    image[call..call + 2].copy_from_slice(&(0xf000u16 | ((delta >> 12) as u16)).to_le_bytes());
    image[call + 2..call + 4]
        .copy_from_slice(&(0xf800u16 | ((delta >> 1) as u16 & 2047)).to_le_bytes());
    let aes = [
        0xf7, 0xb5, 6, 0, 0x14, 0, 0, 0x48, 0x11, 0, 0x84, 0xb0, 0, 0, 0, 0, 0, 0x2c, 1, 0xd0,
        0x20, 7, 2, 0xd0, 0, 0x20, 7, 0xb0, 0xf0, 0xbd, 0xa0, 8, 1, 0x22, 0x92, 6, 2, 0x90, 0x10,
        0x68, 0x10, 0x21, 0x88, 0x43, 0x10, 0x60,
    ];
    image[target..target + aes.len()].copy_from_slice(&aes);
}
#[test]
fn final_stage_redetects_and_encrypts_for_the_new_receiver() {
    let (result, dev, intermediate, final_image) = run(true, true);
    result.unwrap();
    assert_eq!(dev.stages, vec![intermediate.clone(), final_image.clone()]);
    assert_eq!(dev.wire_stages[0], intermediate);
    let mut expected = final_image;
    mediatek_optical::enc::encrypt(&mut expected).unwrap();
    assert_eq!(dev.wire_stages[1], expected);
}

#[test]
fn standalone_bin_plans_only_the_requested_image() {
    let initial = image(b"1.00", 1);
    for revision in [b"INTM", b"1.05"] {
        let target = image(revision, 2);
        let mut dev = MockScsiDevice::new().with_firmware_image(initial.clone());
        let request = FlashRequest {
            input: target.clone(),
            input_format: &super::super::IMAGE,
            mode: crate::manifest::FlashMode::Full,
            execute: false,
            acknowledged_risk: false,
            enc_override: None,
            drive_model: "BD-RE BU40N".into(),
            verbose: false,
            predump_out: None,
        };
        let plan = Mtk
            .plan(&mut ReadDevice::without_unlocks(&mut dev), &request)
            .unwrap();
        let state: &Plan = plan.state().unwrap();
        assert_eq!(state.image, target);
        assert!(
            state.final_image.is_none(),
            "a standalone BIN must not infer another stage"
        );
        assert!(dev.writes.is_empty());
    }
}
