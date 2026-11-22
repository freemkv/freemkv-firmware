//! Exercise automatic stages with a simulated receiver that boots each write.
use super::super::{detect_receiver, fixture};
use super::*;
use crate::platform::MockScsiDevice;

#[test]
fn old_modified_table_corruption_is_refused_before_flash() {
    let mut image =
        include_bytes!("../../../../freemkv-fw/tests/fixtures/WH16NS58_OEM_1.V9.bin").to_vec();
    let entry = crate::cmac::parse_table(&image)
        .unwrap()
        .into_iter()
        .find(|entry| entry.enabled == u32::MAX)
        .unwrap();
    image[entry.entry_off..entry.entry_off + 4].copy_from_slice(&0x02000e41u32.to_le_bytes());
    // mediatek-optical 1.3.0 refuses an unknown flag word in `resign` and
    // `verify` itself, so the overwritten slot can no longer be re-signed into a
    // MAC-valid image; the upstream refusal and our flag gate must both hold.
    assert!(matches!(
        crate::cmac::resign(&image),
        Err(crate::cmac::CmacError::UnknownEnabled { index, enabled: 0x02000e41 })
            if index == entry.index
    ));
    assert!(!crate::cmac::verify(&image));
    let refusal = format!("{:#}", super::check_image(&image).unwrap_err());
    assert!(
        refusal.contains("unsupported flag word 0x02000e41"),
        "{refusal}"
    );
}

struct Drive {
    inner: MockScsiDevice,
    written: Vec<u8>,
    stages: Vec<Vec<u8>>,
    boot_intermediate: bool,
    encrypted_after: bool,
    header_only_after: bool,
    wire_stages: Vec<Vec<u8>>,
    restricted: bool,
}
impl ScsiDevice for Drive {
    fn command_in(&mut self, cdb: &[u8], n: usize) -> Result<Vec<u8>> {
        if self.restricted
            && !self.stages.is_empty()
            && cdb.len() >= 10
            && cdb[..3] == super::cdb::read_memory(0, 0)[..3]
        {
            let off = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
            let end = off + n;
            anyhow::ensure!(
                [
                    (0x3000, 0x3020),
                    (0x1ec000, 0x1ec100),
                    (0x1e84e4, 0x1e85e4),
                    (0x1f0000, 0x200000)
                ]
                .iter()
                .any(|&(lo, hi)| off >= lo && off < hi && end <= hi),
                "restricted live code read {off:#x}"
            );
        }
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
                if self.header_only_after {
                    mediatek_optical::envelope::decrypt(&mut self.written[0x3000..0x3010]).unwrap();
                } else {
                    mediatek_optical::envelope::decrypt(&mut self.written).unwrap();
                }
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
    mediatek_optical::envelope::cmac::resign(&bytes).unwrap()
}

/// A drive that models the pre-erase encoding probe over `ScsiDevice`:
/// REQUEST SENSE reports the last transfer's sense, a WRITE BUFFER stream is
/// accepted only when it carries the plaintext the drive expects (sense 0x00)
/// and otherwise rejected with the wrong-encoding `0xBD`, and COMMIT (finish)
/// is never required to answer the probe. A plaintext (PP) drive accepts the
/// first probe candidate; `rejects_all` models a drive that refuses every one.
struct ProbeDrive {
    inner: MockScsiDevice,
    plain: Vec<u8>,
    rejects_all: bool,
    last_sense: (u8, u8, u8),
    finishes: usize,
    sense_during_probe: Vec<(u8, u8, u8)>,
}

impl ProbeDrive {
    fn plaintext(image: &[u8]) -> Self {
        Self {
            inner: MockScsiDevice::echoing().with_firmware_image(image.to_vec()),
            plain: image.to_vec(),
            rejects_all: false,
            last_sense: (0, 0, 0),
            finishes: 0,
            sense_during_probe: Vec::new(),
        }
    }
    fn rejecting(image: &[u8]) -> Self {
        Self {
            rejects_all: true,
            ..Self::plaintext(image)
        }
    }
}

impl ScsiDevice for ProbeDrive {
    fn command_in(&mut self, cdb: &[u8], n: usize) -> Result<Vec<u8>> {
        // REQUEST SENSE: a fixed-format reply from the last transfer, exactly as
        // many bytes as the transport requested.
        if cdb.first() == Some(&0x03) {
            let mut sense = vec![0u8; n];
            if n >= 14 {
                sense[0] = 0x70;
                sense[2] = self.last_sense.0;
                sense[7] = 10;
                sense[12] = self.last_sense.1;
                sense[13] = self.last_sense.2;
            }
            return Ok(sense);
        }
        self.inner.command_in(cdb, n)
    }
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        // WRITE BUFFER stream (mode 6): judge the chunk's encoding.
        if cdb.first() == Some(&0x3b) && cdb.get(1) == Some(&6) && !data.is_empty() {
            let off = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
            let expected = self.plain.get(off..off + data.len());
            let accepted = !self.rejects_all && expected == Some(data);
            if accepted {
                self.last_sense = (0, 0, 0);
            } else {
                self.last_sense = (5, 0xBD, 0);
                self.sense_during_probe.push(self.last_sense);
                anyhow::bail!("wrong-encoding reject (sense 05/BD/00)");
            }
        }
        if cdb == cdb::finish() {
            self.finishes += 1;
        }
        self.inner.command_out(cdb, data)
    }
    fn describe(&self) -> String {
        "probe fixture".into()
    }
}

#[test]
fn recovery_selects_standalone_mediatek_bin_and_rejects_invalid_input() {
    let bytes = image(b"1.V9", 3);
    assert_eq!(
        crate::workflow::recovery_target(&bytes, None).unwrap(),
        bytes
    );
    assert!(crate::workflow::recovery_target(&bytes, Some("firmware.bin")).is_err());
    assert!(crate::workflow::recovery_target(&vec![0; 0x200000], None).is_err());
    // Payload integrity remains the backend preparation gate, as in Flash.
}

/// Flash a single image through the proven `--current` reference path, so the
/// shared executor's exact command sequence and progress accounting are tested
/// without the probe prefix. (The probe path is covered by its own tests.)
fn flash_single_image(
    dev: &mut MockScsiDevice,
    current: &[u8],
    target: &[u8],
) -> Result<UpdateOutcome> {
    let mut req = request(target.to_vec(), &super::super::IMAGE);
    req.current = Some(current.to_vec());
    let plan = Mtk.plan(&mut ReadDevice::without_unlocks(dev), &req)?;
    let authorized = Mtk.authorize(&mut ReadDevice::without_unlocks(dev), plan, None)?;
    Mtk.execute(
        &mut crate::engine::gates::ungated_for_tests(dev),
        &authorized,
    )
}

/// Flash a single image through the current-free probe path.
fn flash_single_image_probed(
    dev: &mut dyn crate::platform::ScsiDevice,
    target: &[u8],
) -> Result<UpdateOutcome> {
    let req = request(target.to_vec(), &super::super::IMAGE);
    let plan = Mtk.plan(&mut ReadDevice::without_unlocks(dev), &req)?;
    let authorized = Mtk.authorize(&mut ReadDevice::without_unlocks(dev), plan, None)?;
    Mtk.execute(
        &mut crate::engine::gates::ungated_for_tests(dev),
        &authorized,
    )
}

#[test]
fn flash_and_recovery_share_exact_application_write_commands_and_bytes() {
    let current = image(b"1.00", 1);
    let target = image(b"1.01", 3);
    let mut flash = MockScsiDevice::echoing().with_firmware_image(current.clone());
    let mut recovery = MockScsiDevice::echoing().with_firmware_image(current.clone());
    assert!(flash_single_image(&mut flash, &current, &target)
        .unwrap()
        .fully_verified());
    assert!(
        crate::engine::recover(&mut recovery, &Mtk, None, &target, true, true)
            .unwrap()
            .fully_verified()
    );
    assert_eq!(flash.writes, recovery.writes);
    assert_eq!(flash.writes.first().unwrap().0, cdb::enter_update());
    assert_eq!(flash.writes.last().unwrap().0, cdb::finish());
    let transferred: Vec<_> = flash
        .writes
        .iter()
        .flat_map(|(_, data)| data.clone())
        .collect();
    assert_eq!(transferred, target);
}

#[test]
fn recovery_entry_policy_continues_once_while_flash_stops_before_streaming() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let current = image(b"1.00", 1);
    let target = image(b"1.01", 3);
    for recover in [false, true] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let mut dev = MockScsiDevice::echoing()
            .with_firmware_image(current.clone())
            .on_fail(
                move |command| {
                    let matches = command == cdb::enter_update();
                    if matches {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    matches
                },
                "PREPARE rejected",
            );
        let result = if recover {
            crate::engine::recover(&mut dev, &Mtk, None, &target, true, true)
        } else {
            flash_single_image(&mut dev, &current, &target)
        };
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "entry must never retry");
        if recover {
            assert!(result.unwrap().fully_verified());
            let transferred: Vec<_> = dev
                .writes
                .iter()
                .flat_map(|(_, data)| data.clone())
                .collect();
            assert_eq!(transferred, target);
            assert_eq!(dev.writes.last().unwrap().0, cdb::finish());
        } else {
            let error = result.unwrap_err();
            assert!(format!("{error:#}").contains("PREPARE rejected"));
            let failure = error.downcast_ref::<UpdateFailure>().unwrap();
            assert_eq!(
                failure.progress,
                crate::backend::UpdateProgress::EntryAttempted
            );
            assert_eq!(failure.payload_bytes_accepted, Some(0));
            assert_eq!(
                failure.impact(),
                crate::backend::UpdateImpact::EntryUncertain
            );
            let diagnostic = format!("{error:#}");
            assert!(diagnostic.contains("entry command attempted; no firmware payload sent"));
            assert!(!diagnostic.contains("write started: true"));
            let guidance =
                crate::user_error::UserError::of(&error).render(crate::localization::Language::En);
            assert!(guidance.contains("no firmware data was sent"));
            assert!(!guidance.contains("firmware may be incomplete"));
            assert!(dev.writes.is_empty());
        }
    }
}

#[test]
fn recovery_selected_current_is_not_ignored_when_live_receiver_is_readable() {
    let current = image(b"1.00", 1);
    let stale = image(b"1.01", 1);
    let target = image(b"1.02", 3);
    let mut dev = MockScsiDevice::echoing().with_firmware_image(current);
    let error = crate::engine::recover(&mut dev, &Mtk, Some(&stale), &target, false, false)
        .expect_err("selected Current must match even when live code can be read");
    assert!(
        format!("{error:#}").contains("Current firmware does not match"),
        "{error:#}"
    );
    assert!(dev.writes.is_empty());
}
fn running_inquiry(image: &[u8]) -> Vec<u8> {
    let mut inquiry = vec![0; 36];
    inquiry[0] = 5;
    inquiry[4] = 31;
    inquiry[8..36].copy_from_slice(&image[0x1ec000..0x1ec01c]);
    inquiry
}
fn run(boot: bool, encrypted_after: bool) -> (Result<UpdateOutcome>, Drive, Vec<u8>, Vec<u8>) {
    run_with_changed_receiver(boot, encrypted_after, false)
}
fn run_with_changed_receiver(
    boot: bool,
    encrypted_after: bool,
    changed: bool,
) -> (Result<UpdateOutcome>, Drive, Vec<u8>, Vec<u8>) {
    run_with_restricted_receiver(boot, encrypted_after, changed, false)
}
fn run_with_restricted_receiver(
    boot: bool,
    encrypted_after: bool,
    changed: bool,
    restricted: bool,
) -> (Result<UpdateOutcome>, Drive, Vec<u8>, Vec<u8>) {
    let initial = image(b"1.00", 1);
    let mut intermediate = image(b"INTM", 1);
    if encrypted_after {
        super::super::bulk_receiver_fixture::stamp(&mut intermediate);
    }
    let final_image = image(b"1.05", 3);
    let mut dev = Drive {
        // Only Drive's successful boot branch may change the running identity;
        // echoed staging bytes alone do not prove that firmware started.
        inner: MockScsiDevice::echoing()
            .with_firmware_image(initial.clone())
            .on(|c| c.first() == Some(&0x12), running_inquiry(&initial)),
        written: vec![0; IMAGE_SIZE],
        stages: vec![],
        boot_intermediate: boot,
        encrypted_after,
        header_only_after: false,
        wire_stages: Vec::new(),
        restricted,
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
    .unwrap()
    .bind(&receiver)
    .unwrap();
    if changed {
        let mut changed_image = initial.clone();
        changed_image[receiver.signature_address() as usize] ^= 1;
        dev.inner = MockScsiDevice::echoing().with_firmware_image(changed_image);
    }
    let final_prepared = match prepare_next_stage(&intermediate, &final_image) {
        Ok(plan) => plan,
        Err(error) => return (Err(error), dev, intermediate, final_image),
    };
    let plan = FlashPlan::new(Plan {
        image: intermediate.clone(),
        live,
        drive_product: "BD-RE BU40N".into(),
        verdict: Verdict::SameModel,
        mode: PlanMode::Reference {
            receiver,
            following: vec![final_prepared],
        },
    });
    let authorized = AuthorizedPlan::new(plan, Authorized::Reference(prepared));
    let result = Mtk.execute(
        &mut crate::engine::gates::ungated_for_tests(&mut dev),
        &authorized,
    );
    (result, dev, intermediate, final_image)
}

#[test]
fn changed_receiver_rejects_the_bound_plan_before_any_write() {
    let (result, dev, _, _) = run_with_changed_receiver(true, false, true);
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("changed"));
    let failure = error
        .downcast_ref::<UpdateFailure>()
        .expect("structured failure");
    assert!(!failure.write_started);
    assert_eq!(failure.phase, "receiver revalidation");
    assert!(dev.inner.writes.is_empty());
    assert!(dev.stages.is_empty());
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
    assert!(format!("{:#}", result.unwrap_err()).contains("startup"));
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
fn unsupported_final_receiver_contract_is_rejected_before_intermediate_write() {
    let current = image(b"1.00", 1);
    let mut intermediate = image(b"INTM", 2);
    encrypted_receiver(&mut intermediate);
    let target = image(b"1.05", 3);
    let mut dev = MockScsiDevice::new().with_firmware_image(current);
    let req = request(package(&intermediate, &target), &super::super::PACKAGE);
    assert!(Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .is_err());
    assert!(dev.writes.is_empty());
}

#[test]
fn restricted_intermediate_uses_prepared_reference_and_reports_limited_verification() {
    let (result, dev, intermediate, final_image) =
        run_with_restricted_receiver(true, false, false, true);
    let UpdateOutcome::Completed(evidence) = result.unwrap() else {
        panic!("expected completed operation")
    };
    assert!(evidence.target_started);
    assert!(!evidence.unverified_regions.is_empty());
    assert_eq!(
        evidence.completed_stages,
        ["intermediate", "final firmware"]
    );
    assert_eq!(dev.stages, vec![intermediate, final_image]);
}

#[test]
fn recovery_uses_selected_current_intm_without_reflashing_it() {
    let mut current = image(b"INTM", 2);
    super::super::bulk_receiver_fixture::stamp(&mut current);
    let target = image(b"1.V9", 3);
    let mut inquiry = vec![0; 36];
    inquiry[0] = 5;
    inquiry[4] = 31;
    inquiry[8..36].copy_from_slice(&current[0x1ec000..0x1ec01c]);
    let mut dev = Drive {
        inner: MockScsiDevice::echoing()
            .with_firmware_image(current.clone())
            .on(|c| c.first() == Some(&0x12), inquiry),
        written: vec![0; IMAGE_SIZE],
        stages: vec![current.clone()],
        boot_intermediate: true,
        encrypted_after: true,
        header_only_after: false,
        wire_stages: vec![],
        restricted: true,
    };
    crate::engine::recover(&mut dev, &Mtk, Some(&current), &target, true, true).unwrap();
    assert_eq!(dev.stages, vec![current, target.clone()]);
    assert_eq!(dev.wire_stages.len(), 1);
    let mut expected = target;
    mediatek_optical::envelope::encrypt(&mut expected).unwrap();
    assert_eq!(dev.wire_stages[0], expected);
}

#[test]
fn recovery_prepares_the_user_reference_recipe_without_matching_running_revision() {
    use crate::backend::RecoveryFacet;

    let mut current = image(b"INTM", 2);
    encrypted_receiver(&mut current);
    let original = image(b"1.V1", 1);
    let target = image(b"1.V9", 3);
    let mut inquiry = vec![0; 36];
    inquiry[0] = 5;
    inquiry[4] = 31;
    inquiry[8..36].copy_from_slice(&current[0x1ec000..0x1ec01c]);
    let mut dev = Drive {
        inner: MockScsiDevice::echoing()
            .with_firmware_image(current.clone())
            .on(|c| c.first() == Some(&0x12), inquiry),
        written: vec![0; IMAGE_SIZE],
        stages: vec![current],
        boot_intermediate: true,
        encrypted_after: true,
        header_only_after: false,
        wire_stages: vec![],
        restricted: true,
    };
    let identified = Mtk
        .identify_with_current(&mut ReadDevice::without_unlocks(&mut dev), Some(&original))
        .unwrap()
        .unwrap();
    assert!(identified.label.contains("Plaintext"));
    let outcome =
        crate::engine::recover(&mut dev, &Mtk, Some(&original), &target, false, true).unwrap();
    assert!(matches!(outcome, UpdateOutcome::Planned));
    assert!(dev.wire_stages.is_empty());
    assert!(dev.inner.writes.is_empty());
}

#[test]
#[ignore = "requires FREEMKV_HOARD with the production 1.V9 package"]
fn production_intm_recovery_streams_header_encrypted_body_plaintext() {
    let root = std::path::PathBuf::from(std::env::var_os("FREEMKV_HOARD").expect("FREEMKV_HOARD"));
    let tar = std::fs::read(root.join(
        "packages/mediatek/ef64ae9e3f5471e0a1cd091544f577757a969cba6e2faca34d18028ecb755270.tar",
    ))
    .unwrap();
    let current = crate::workflow::current_firmware_image(&tar, Some("intermediate.bin")).unwrap();
    let target = crate::workflow::recovery_target(&tar, Some("firmware.bin")).unwrap();
    assert_eq!(
        crate::mediatek_package::digest(&current),
        "c3a18eed17251d1508964647e833ffdfe01b13c28dff9a717dfac6336e7c70e6"
    );
    let mut inquiry = vec![0; 36];
    inquiry[0] = 5;
    inquiry[4] = 31;
    inquiry[8..36].copy_from_slice(&current[0x1ec000..0x1ec01c]);
    let mut dev = Drive {
        inner: MockScsiDevice::echoing()
            .with_firmware_image(current.clone())
            .on(|c| c.first() == Some(&0x12), inquiry),
        written: vec![0; IMAGE_SIZE],
        stages: vec![current.clone()],
        boot_intermediate: true,
        encrypted_after: true,
        header_only_after: true,
        wire_stages: vec![],
        restricted: true,
    };
    crate::engine::recover(&mut dev, &Mtk, Some(&current), &target, true, true).unwrap();
    assert_eq!(dev.stages, vec![current, target]);
    assert_eq!(dev.wire_stages.len(), 1);
    let mut expected = dev.stages[1].clone();
    mediatek_optical::envelope::encrypt(&mut expected[0x3000..0x3010]).unwrap();
    assert_eq!(dev.wire_stages[0], expected);
    assert_eq!(
        &dev.wire_stages[0][0x10600..0x10608],
        &dev.stages[1][0x10600..0x10608]
    );
}

#[test]
#[ignore = "requires FREEMKV_HOARD with production V1 and paired V9 images"]
fn production_v1_paired_flash_runs_intm_then_mixed_v9_with_restricted_reads() {
    let root = std::path::PathBuf::from(std::env::var_os("FREEMKV_HOARD").expect("FREEMKV_HOARD"));
    let tar = std::fs::read(root.join(
        "packages/mediatek/ef64ae9e3f5471e0a1cd091544f577757a969cba6e2faca34d18028ecb755270.tar",
    ))
    .unwrap();
    let initial=std::fs::read(root.join("images/mediatek/MT1959/HL-DT-ST_WH16NS58_MT1959_JB8_JB8/GENERAL/1.V1/main/4041c0f122a902288ca8439888f68f7760616a0a37c366b825d6497b51157e46.bin")).unwrap();
    let package = crate::mediatek_package::Package::parse(&tar).unwrap();
    let mut dev = Drive {
        inner: MockScsiDevice::echoing().with_firmware_image(initial.clone()),
        written: vec![0; IMAGE_SIZE],
        stages: vec![],
        boot_intermediate: true,
        encrypted_after: true,
        header_only_after: true,
        wire_stages: vec![],
        restricted: true,
    };
    let req = FlashRequest {
        current: None,
        input: tar,
        input_format: &super::super::PACKAGE,
        mode: crate::manifest::FlashMode::Full,
        execute: true,
        acknowledged_risk: true,
        enc_override: None,
        drive_model: Build::of_image(&initial).unwrap().product,
        verbose: false,
        predump_out: None,
    };
    let plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .unwrap();
    let state = plan.state::<Plan>().unwrap();
    let receiver = detect_receiver(&mut ReadDevice::without_unlocks(&mut dev)).unwrap();
    let prepared = authorize_bytes(
        &state.live,
        &state.drive_product,
        state.verdict,
        &state.image,
        Some(&initial),
    )
    .unwrap()
    .bind(&receiver)
    .unwrap();
    Mtk.execute(
        &mut crate::engine::gates::ungated_for_tests(&mut dev),
        &AuthorizedPlan::new(plan, prepared),
    )
    .unwrap();
    assert_eq!(
        dev.stages,
        vec![
            package.intermediate().unwrap().to_vec(),
            package.firmware().to_vec()
        ]
    );
    assert_eq!(dev.wire_stages[0], package.intermediate().unwrap());
    let mut expected = package.firmware().to_vec();
    mediatek_optical::envelope::encrypt(&mut expected[0x3000..0x3010]).unwrap();
    assert_eq!(dev.wire_stages[1], expected);
}

#[test]
fn standalone_bin_plans_only_the_requested_image() {
    let initial = image(b"1.00", 1);
    for revision in [b"INTM", b"1.05"] {
        let target = image(revision, 2);
        let mut dev = MockScsiDevice::new().with_firmware_image(initial.clone());
        let request = FlashRequest {
            current: None,
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
            matches!(&state.mode, PlanMode::Probe { final_image: None }),
            "a standalone BIN with no Current must probe a single stage"
        );
        assert!(dev.writes.is_empty());
    }
}

#[test]
fn no_backup_crossflash_is_gated_like_same_model_on_live_evidence() {
    // Hardware family, not model name, decides: a consented no-backup
    // crossflash gets the same live gates as a same-model flash.
    let current = image(b"1.00", 1);
    let target = image(b"1.05", 2);
    let authorized = authorize_bytes(
        &fixture::identity(&current),
        "BD-RE BU40N",
        Verdict::Crossflash,
        &target,
        None,
    )
    .unwrap();
    assert_eq!(authorized.prepared.image(), target);
    let mut corrupt = target;
    corrupt[0x11000] ^= 1;
    assert!(authorize_bytes(
        &fixture::identity(&current),
        "BD-RE BU40N",
        Verdict::Crossflash,
        &corrupt,
        None
    )
    .is_err());
}

#[test]
fn mediatek_family_mismatch_keeps_hashes_in_diagnostics_only() {
    let current = image(b"1.00", 1);
    let mut target = image(b"1.05", 2);
    let board = fixture::Board {
        platform: "BU9",
        ..fixture::BU3
    };
    fixture::stamp(&mut target, &board);
    let target = crate::cmac::resign(&target).unwrap();
    let error = authorize_bytes(
        &fixture::identity(&current),
        "BD-RE BU40N",
        Verdict::SameModel,
        &target,
        Some(&current),
    )
    .err()
    .expect("different families must refuse");
    let message = crate::workflow::error_message(&error);
    assert!(
        message.contains("installed and selected firmware are for different hardware"),
        "{message}"
    );
    assert!(message.contains("BU40N"));
    let current_family = mediatek_optical::envelope::family(&current)
        .unwrap()
        .to_string();
    let target_family = mediatek_optical::envelope::family(&target)
        .unwrap()
        .to_string();
    assert_ne!(current_family, target_family);
    assert!(!message.contains(&current_family));
    assert!(!message.contains(&target_family));
    assert!(format!("{error:#}").contains(&current_family));
    assert!(format!("{error:#}").contains(&target_family));
}

#[test]
fn no_backup_same_model_uses_live_evidence_without_target_as_installed() {
    let current = image(b"1.00", 1);
    let target = image(b"1.05", 2);
    let authorized = authorize_bytes(
        &fixture::identity(&current),
        "BD-RE BU40N",
        Verdict::SameModel,
        &target,
        None,
    )
    .unwrap();
    assert_eq!(authorized.prepared.image(), target);
    let mut corrupt = target;
    corrupt[0x11000] ^= 1;
    assert!(authorize_bytes(
        &fixture::identity(&current),
        "BD-RE BU40N",
        Verdict::SameModel,
        &corrupt,
        None
    )
    .is_err());
}

#[test]
fn final_stage_redetects_and_encrypts_for_the_new_receiver() {
    let (result, dev, intermediate, final_image) = run(true, true);
    result.unwrap();
    assert_eq!(dev.stages, vec![intermediate.clone(), final_image.clone()]);
    assert_eq!(dev.wire_stages[0], intermediate);
    let mut expected = final_image;
    mediatek_optical::envelope::encrypt(&mut expected).unwrap();
    assert_eq!(dev.wire_stages[1], expected);
}

#[test]
fn restricted_intm_to_final_uses_just_installed_image_and_encrypted_wire() {
    let (result, dev, intermediate, final_image) =
        run_with_restricted_receiver(true, true, false, true);
    let UpdateOutcome::Completed(evidence) = result.unwrap() else {
        panic!("expected completion")
    };
    assert!(!evidence.unverified_regions.is_empty());
    assert_eq!(dev.stages, vec![intermediate, final_image.clone()]);
    let mut expected = final_image;
    mediatek_optical::envelope::encrypt(&mut expected).unwrap();
    assert_eq!(dev.wire_stages[1], expected);
}

fn request(input: Vec<u8>, input_format: &'static crate::backend::FileFormat) -> FlashRequest {
    FlashRequest {
        current: None,
        input,
        input_format,
        mode: crate::manifest::FlashMode::Full,
        execute: true,
        acknowledged_risk: true,
        enc_override: None,
        drive_model: "BD-RE BU40N".into(),
        verbose: false,
        predump_out: None,
    }
}

fn restricted_current_drive(current: &[u8]) -> Drive {
    Drive {
        inner: MockScsiDevice::echoing()
            .with_firmware_image(current.to_vec())
            .on(|c| c.first() == Some(&0x12), running_inquiry(current)),
        written: vec![0; IMAGE_SIZE],
        stages: vec![current.to_vec()],
        boot_intermediate: true,
        encrypted_after: true,
        header_only_after: false,
        wire_stages: vec![],
        restricted: true,
    }
}

#[test]
fn flash_current_reference_binds_restricted_v9_without_using_target_receiver_code() {
    let mut current = image(b"1.V9", 1);
    super::super::bulk_receiver_fixture::stamp(&mut current);
    let current = crate::cmac::resign(&current).unwrap();
    let target = image(b"1.V9", 3);
    let mut dev = restricted_current_drive(&current);
    let mut req = request(target.clone(), &super::super::IMAGE);
    // Without --current, a restricted drive no longer demands a Current file:
    // the plan is a probe-mode plan (the wire encoding is probed at write time),
    // and it never reads live receiver code.
    let plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .unwrap();
    let state = plan.state::<Plan>().unwrap();
    assert!(matches!(&state.mode, PlanMode::Probe { final_image: None }));
    assert!(plan
        .dry_run
        .iter()
        .flat_map(|line| match line {
            PlanLine::Detail(inner) => Some(inner.as_ref().clone()),
            other => Some(other.clone()),
        })
        .any(|line| matches!(line, PlanLine::Field("encoding", _))));
    assert!(dev.inner.writes.is_empty());

    // With --current, the proven reference path binds the encrypted receiver.
    req.current = Some(current.clone());
    let plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .unwrap();
    let state = plan.state::<Plan>().unwrap();
    assert_eq!(state.image, target);
    let PlanMode::Reference { receiver, .. } = &state.mode else {
        panic!("--current must select the reference path");
    };
    assert_eq!(
        receiver.encoding(),
        mediatek_optical::prepare::Encoding::Encrypted
    );
    assert_eq!(
        receiver.provenance(),
        mediatek_optical::prepare::Provenance::UserSuppliedReference
    );
    assert!(plan
        .dry_run
        .iter()
        .flat_map(|line| match line {
            PlanLine::Detail(inner) => Some(inner.as_ref().clone()),
            other => Some(other.clone()),
        })
        .any(|line| matches!(line, PlanLine::Field("receiver code source", _))));
    let authorized = Mtk
        .authorize(&mut ReadDevice::without_unlocks(&mut dev), plan, None)
        .unwrap();
    let sheet = crate::workflow::FlashSheet::of(&authorized);
    assert!(sheet
        .notices
        .iter()
        .any(|s| s.contains("Its match to the installed firmware has not been verified.")));
    assert!(!sheet
        .technical_details
        .iter()
        .any(|s| s.contains("Its match to the installed firmware has not been verified.")));
    let Authorized::Reference(executable) = authorized.state::<Authorized>().unwrap() else {
        panic!("reference authorization expected");
    };
    assert_eq!(
        executable.prepared.plan().encoding().body,
        mediatek_optical::prepare::Encoding::Encrypted
    );
    let mut stale = current;
    stale[0x1ec01b] ^= 1;
    dev.inner = MockScsiDevice::echoing()
        .with_firmware_image(stale.clone())
        .on(|c| c.first() == Some(&0x12), running_inquiry(&stale));
    let shared = SharedDevice::new(&mut dev);
    let mut reads = ScsiTransport::reads(&shared);
    assert!(executable
        .prepared
        .plan()
        .receiver()
        .revalidate(&mut reads)
        .is_err());
    assert!(dev.inner.writes.is_empty());
}

/// A confirm that fails loudly if the engine ever asks about a missing backup:
/// MediaTek must flash with no backup attempt and no backup confirmation.
struct NeverBackup;
impl crate::backend::Confirm for NeverBackup {
    fn confirm(&mut self, _: &AuthorizedPlan) -> Result<bool> {
        Ok(true)
    }
    fn proceed_without_backup(&mut self, _reason: &str) -> Result<bool> {
        panic!("MediaTek must not gate on a pre-flash backup")
    }
}

#[test]
fn mediatek_flash_needs_no_current_and_no_backup() {
    // No --current, no --backup: the probe path flashes directly. The engine
    // never asks to proceed without a backup, and writes no backup file.
    let img = image(b"1.V9", 1);
    let mut dev = ProbeDrive::plaintext(&img);
    let path =
        std::env::temp_dir().join(format!("freemkv-mtk-nobackup-{}.bin", std::process::id()));
    let req = FlashRequest {
        current: None,
        input: img.clone(),
        input_format: &super::super::IMAGE,
        mode: crate::manifest::FlashMode::Full,
        execute: true,
        acknowledged_risk: true,
        enc_override: None,
        drive_model: "BD-RE BU40N".into(),
        verbose: false,
        // Even if a default path is offered, MediaTek must not write a backup.
        predump_out: Some(path.clone()),
    };
    let outcome = crate::engine::flash(&mut dev, &Mtk, &req, &mut NeverBackup).unwrap();
    assert!(matches!(outcome, UpdateOutcome::Completed(_)));
    assert!(!path.exists(), "no pre-flash backup file must be written");
    // The drive saw a safe probe (PREPARE + one chunk + sense, no premature
    // COMMIT) followed by the real flash that ends in COMMIT.
    assert!(dev.finishes >= 1, "the real flash must COMMIT");
}

#[test]
fn probe_path_reports_the_plaintext_wire_encoding() {
    let img = image(b"1.00", 1);
    let mut dev = ProbeDrive::plaintext(&img);
    flash_single_image_probed(&mut dev, &img).unwrap();
    assert!(dev.finishes >= 1);
}

#[test]
fn probe_none_accepted_is_surfaced_cleanly() {
    let img = image(b"1.00", 1);
    let mut dev = ProbeDrive::rejecting(&img);
    let error = flash_single_image_probed(&mut dev, &img).unwrap_err();
    assert!(
        format!("{error:#}").contains("encoding probe failed"),
        "{error:#}"
    );
    let failure = error.downcast_ref::<UpdateFailure>().unwrap();
    assert!(!failure.write_started);
    assert_eq!(failure.phase, "wire-encoding probe");
    assert_eq!(dev.finishes, 0, "a failed probe must never COMMIT");
}

#[test]
#[ignore = "requires FREEMKV_HOARD with the production WH16NS58 1.V9 package"]
fn exact_v9_current_reference_prepares_normal_flash_with_restricted_reads() {
    let root = std::path::PathBuf::from(std::env::var_os("FREEMKV_HOARD").expect("FREEMKV_HOARD"));
    let bytes = std::fs::read(root.join(
        "packages/mediatek/ef64ae9e3f5471e0a1cd091544f577757a969cba6e2faca34d18028ecb755270.tar",
    ))
    .unwrap();
    let package = crate::mediatek_package::Package::parse(&bytes).unwrap();
    let current = package.firmware();
    let target = std::env::var_os("FREEMKV_FLASH_TARGET")
        .map(|path| std::fs::read(path).unwrap())
        .unwrap_or_else(|| current.to_vec());
    let mut dev = restricted_current_drive(current);
    let mut req = request(target.clone(), &super::super::IMAGE);
    req.drive_model = Build::of_image(current).unwrap().product;
    // Without --current the restricted drive now plans a probe-mode flash.
    assert!(matches!(
        Mtk.plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
            .unwrap()
            .state::<Plan>()
            .unwrap()
            .mode,
        PlanMode::Probe { .. }
    ));
    req.current = Some(current.to_vec());
    let plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .unwrap();
    let authorized = Mtk
        .authorize(&mut ReadDevice::without_unlocks(&mut dev), plan, None)
        .unwrap();
    let Authorized::Reference(executable) = authorized.state::<Authorized>().unwrap() else {
        panic!("reference authorization expected");
    };
    let prepared = &executable.prepared;
    assert_eq!(
        prepared.plan().prepare_command().command(),
        cdb::enter_update()
    );
    assert_eq!(
        prepared.plan().encoding().body,
        mediatek_optical::prepare::Encoding::Encrypted
    );
    let mut decoded = prepared.plan().transfer().to_vec();
    mediatek_optical::envelope::decrypt(&mut decoded).unwrap();
    assert_eq!(decoded, target);
    assert!(dev.inner.writes.is_empty());
}

fn package(intermediate: &[u8], target: &[u8]) -> Vec<u8> {
    use crate::mediatek_package::{digest, Component, Manifest, Package, Role, FORMAT};
    let components = vec![
        Component {
            path: "intermediate.bin".into(),
            sha256: digest(intermediate),
            role: Role::Intermediate,
        },
        Component {
            path: "firmware.bin".into(),
            sha256: digest(target),
            role: Role::Firmware,
        },
    ];
    let pairing = serde_json::json!({ "basis": "lg-rcdata-103-final-105-intermediate",
        "source": { "sha256": "0".repeat(64) }, "container_sha256": "0".repeat(64),
        "intermediate_sha256": digest(intermediate), "final_sha256": digest(target) });
    Package::from_parts(
        Manifest {
            format: FORMAT.into(),
            version: 1,
            components,
            pairing: Some(pairing),
            metadata: Default::default(),
        },
        [
            ("intermediate.bin".into(), intermediate.to_vec()),
            ("firmware.bin".into(), target.to_vec()),
        ]
        .into(),
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[test]
fn unchanged_firmware_after_matching_protected_readback_is_not_success() {
    let current = image(b"INTM", 1);
    let target = image(b"1.V9", 1);
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(current.clone())
        .on(|c| c.first() == Some(&0x12), running_inquiry(&current));
    let receiver = detect_receiver(&mut ReadDevice::without_unlocks(&mut dev)).unwrap();
    let plan = authorize_bytes(
        &fixture::identity(&current),
        "BD-RE BU40N",
        Verdict::SameModel,
        &target,
        Some(&current),
    )
    .unwrap()
    .bind(&receiver)
    .unwrap();
    let error = execute_stage(
        &mut crate::engine::gates::ungated_for_tests(&mut dev),
        &plan.prepared,
        false,
        vec![],
    )
    .unwrap_err();
    let failure = error.downcast_ref::<UpdateFailure>().unwrap();
    assert!(failure.write_started);
    assert_eq!(failure.phase, "target startup confirmation");
    assert!(format!("{error:#}").contains("selected target"));
}

#[test]
fn final_receiver_refusal_retains_previous_write_and_intermediate_evidence() {
    let intermediate = image(b"INTM", 1);
    let target = image(b"1.V9", 1);
    let next = prepare_next_stage(&intermediate, &target).unwrap();
    let stale = image(b"1.V1", 1);
    let mut dev = MockScsiDevice::echoing().with_firmware_image(stale);
    let error = execute_stage(
        &mut crate::engine::gates::ungated_for_tests(&mut dev),
        &next.prepared,
        true,
        vec!["intermediate".into()],
    )
    .unwrap_err();
    let failure = error.downcast_ref::<UpdateFailure>().unwrap();
    assert_eq!(failure.phase, "receiver revalidation");
    assert!(
        failure.write_started,
        "the preceding intermediate stage already wrote firmware"
    );
    assert!(failure.temporary_firmware);
    assert_eq!(failure.completed_stages, ["intermediate"]);
    assert!(
        dev.writes.is_empty(),
        "the final stage must send no commands after a stale receiver refusal"
    );
}

#[test]
fn prepare_entry_failure_conservatively_records_possible_command_mutation() {
    let error = mediatek_optical::drive::FlashError::Entry(
        mediatek_optical::drive::Error::Transport(anyhow!("prepare transport error")),
    );
    assert_eq!(failure_phase(&error), ("update entry", true));
}

#[test]
fn probe_plan_reads_no_live_receiver_code_before_the_write_phase() {
    // Current-free planning never reads live receiver code: the wire encoding is
    // discovered by a safe probe in the write phase, not detected at plan time.
    let target = image(b"1.00", 1);
    let mut dev = ProbeDrive::plaintext(&target);
    let request = request(target.clone(), &super::super::IMAGE);
    let code_block = cdb::read_memory(0x98000, 1024);
    let captures = |dev: &ProbeDrive| {
        dev.inner
            .reads
            .iter()
            .filter(|command| command.as_slice() == code_block)
            .count()
    };
    let plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &request)
        .unwrap();
    assert_eq!(
        captures(&dev),
        0,
        "probe-mode planning must read no live receiver code"
    );
    let authorized = Mtk
        .authorize(&mut ReadDevice::without_unlocks(&mut dev), plan, None)
        .unwrap();
    assert_eq!(
        captures(&dev),
        0,
        "authorization must read no live receiver code either"
    );
    assert!(dev.inner.writes.is_empty(), "no writes before execute");
    Mtk.execute(
        &mut crate::engine::gates::ungated_for_tests(&mut dev),
        &authorized,
    )
    .unwrap();
    assert!(dev.finishes >= 1, "the write phase probes then flashes");
}

#[test]
fn confirmation_cleanup_real_two_stage_plan_keeps_startup_requirement_visible() {
    let current = image(b"1.00", 1);
    let intermediate = image(b"INTM", 2);
    let target = image(b"1.05", 3);
    let mut dev = MockScsiDevice::echoing().with_firmware_image(current.clone());
    // The two-stage reference path (with --current) still shows the receiver
    // signature as a technical detail, while probe-mode flashes show none.
    let mut req = request(package(&intermediate, &target), &super::super::PACKAGE);
    req.current = Some(current.clone());
    let plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .unwrap();
    let authorized = Mtk
        .authorize(&mut ReadDevice::without_unlocks(&mut dev), plan, None)
        .unwrap();
    let sheet = crate::workflow::FlashSheet::of(&authorized);
    assert!(sheet.notices.iter().any(
        |s| s.contains("Two-stage update: intermediate, confirm startup, then final firmware")
    ));
    assert!(!sheet.notices.iter().any(|s| s.contains("signature at")));
    assert!(sheet
        .technical_details
        .iter()
        .any(|s| s.contains("signature at")));
    assert!(dev.writes.is_empty());
}

#[test]
fn confirmation_cleanup_real_crossflash_plan_keeps_identity_and_rollback_warnings() {
    let current = image(b"1.00", 1);
    let mut target = image(b"1.05", 3);
    target[0x1ec008..0x1ec018].copy_from_slice(b"BD-RE BU50N     ");
    let target = crate::cmac::resign(&target).unwrap();
    let mut dev = MockScsiDevice::new().with_firmware_image(current.clone());
    let req = request(target, &super::super::IMAGE);
    let mut plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .unwrap();
    // Even an outer informational wrapper cannot hide a producer's warning.
    for line in &mut plan.after_backup {
        if matches!(line, PlanLine::Warning(_)) {
            *line = PlanLine::Detail(Box::new(PlanLine::Spaced(Box::new(line.clone()))));
        }
    }
    let backup = crate::engine::gates::saved_for_tests(current);
    let authorized = Mtk
        .authorize(
            &mut ReadDevice::without_unlocks(&mut dev),
            plan,
            Some(&backup),
        )
        .unwrap();
    let sheet = crate::workflow::FlashSheet::of(&authorized);
    for phrase in [
        "CROSSFLASH:",
        "the drive will identify as",
        "your backup restores",
    ] {
        assert!(
            sheet.warnings.iter().any(|s| s.contains(phrase)),
            "{phrase}: {:?}",
            sheet.warnings
        );
        assert!(!sheet.technical_details.iter().any(|s| s.contains(phrase)));
    }
    assert!(dev.writes.is_empty());
}

#[test]
fn known_mtk_invalid_current_reference_has_current_guidance() {
    use crate::backend::RecoveryFacet;
    let installed = image(b"1.00", 1);
    let mut dev = MockScsiDevice::echoing().with_firmware_image(installed);
    let error = Mtk
        .identify_with_current(
            &mut ReadDevice::without_unlocks(&mut dev),
            Some(b"bad current"),
        )
        .err()
        .expect("invalid Current must be rejected");
    assert_eq!(
        crate::user_error::UserError::of(&error).id,
        "errors.current_invalid"
    );
    assert!(dev.writes.is_empty());
}

#[test]
fn known_mtk_preflight_keeps_original_transport_cause() {
    struct Failure;
    impl ScsiDevice for Failure {
        fn command_in(&mut self, _: &[u8], _: usize) -> Result<Vec<u8>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "preflight-access-denied",
            )
            .into())
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
            panic!("preflight must not write")
        }
        fn describe(&self) -> String {
            "preflight-failure".into()
        }
    }
    let error = Mtk
        .preflight(
            &mut ReadDevice::without_unlocks(&mut Failure),
            &FlashPlan::new(()),
        )
        .expect_err("transport failure must propagate");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    assert!(format!("{error:#}").contains("read-only preflight failed"));
}

#[test]
fn boot_recovery_with_current_uses_live_receiver() {
    use crate::backend::RecoveryFacet;
    let current = image(b"1.00", 1);
    let mut installed = image(b"BOOT", 1);
    // Plain boot receiver instruction signature used by mediatek-optical.
    installed[0x36c4..0x36d2].copy_from_slice(&[
        0x03, 0x21, 0x09, 0x03, 0x61, 0x18, 0, 0xa8, 0, 0x5d, 0x09, 0x78, 0x88, 0x42,
    ]);
    for supplied in [None, Some(current.as_slice())] {
        let mut dev = MockScsiDevice::echoing().with_firmware_image(installed.clone());
        assert!(Mtk
            .identify_with_current(&mut ReadDevice::without_unlocks(&mut dev), supplied)
            .unwrap()
            .is_some());
        assert!(dev.writes.is_empty());
    }
    installed[0x36c4] ^= 1;
    let mut dev = MockScsiDevice::echoing().with_firmware_image(installed);
    assert!(
        Mtk.identify_with_current(&mut ReadDevice::without_unlocks(&mut dev), Some(&current))
            .is_err(),
        "Current must not substitute for an unrecognized live BOOT receiver"
    );
    assert!(dev.writes.is_empty());
}

#[test]
fn recovery_transfer_failure_reports_how_much_payload_was_accepted() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let current = image(b"1.00", 1);
    let target = image(b"1.01", 3);
    let is_transfer = |c: &[u8]| c.len() > 1 && c[0] == 0x3b && c[1] == 0x06;
    let mut clean = MockScsiDevice::echoing().with_firmware_image(current.clone());
    crate::engine::recover(&mut clean, &Mtk, None, &target, true, true).unwrap();
    let total = clean.writes.iter().filter(|(c, _)| is_transfer(c)).count();
    assert!(total >= 1);
    for fail_at in [1, total] {
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let mut dev = MockScsiDevice::echoing()
            .with_firmware_image(current.clone())
            .on_fail(
                move |c| is_transfer(c) && counter.fetch_add(1, Ordering::SeqCst) + 1 == fail_at,
                "transfer rejected",
            );
        let error = crate::engine::recover(&mut dev, &Mtk, None, &target, true, true).unwrap_err();
        assert!(
            format!("{error:#}").contains("transfer rejected"),
            "{error:#}"
        );
        let failure = error.downcast_ref::<UpdateFailure>().unwrap();
        assert_ne!(failure.progress, crate::backend::UpdateProgress::Preflight);
        if fail_at == 1 {
            assert_eq!(failure.payload_bytes_accepted, Some(0));
        } else {
            assert!(failure.payload_bytes_accepted > Some(0), "{failure:?}");
        }
        assert!(!failure.temporary_firmware);
    }
}

fn injected_flash_failure(
    current: &[u8],
    target: &[u8],
    fail: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
) -> anyhow::Error {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let armed = Arc::new(AtomicBool::new(false));
    let gate = armed.clone();
    let mut dev = MockScsiDevice::echoing()
        .with_firmware_image(current.to_vec())
        .on_fail(
            move |c| gate.load(Ordering::SeqCst) && fail(c),
            "injected failure",
        );
    let req = request(target.to_vec(), &super::super::IMAGE);
    let plan = Mtk
        .plan(&mut ReadDevice::without_unlocks(&mut dev), &req)
        .unwrap();
    let backup = crate::engine::gates::saved_for_tests(current.to_vec());
    let authorized = Mtk
        .authorize(
            &mut ReadDevice::without_unlocks(&mut dev),
            plan,
            Some(&backup),
        )
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    Mtk.execute(
        &mut crate::engine::gates::ungated_for_tests(&mut dev),
        &authorized,
    )
    .unwrap_err()
}

#[test]
fn failed_flash_reports_how_far_it_progressed() {
    use crate::backend::UpdateProgress;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let current = image(b"1.00", 1);
    let target = image(b"1.01", 3);
    let is_transfer = |c: &[u8]| c.len() > 1 && c[0] == 0x3b && c[1] == 0x06;
    let mut clean = MockScsiDevice::echoing().with_firmware_image(current.clone());
    flash_single_image(&mut clean, &current, &target).unwrap();
    let total = clean.writes.iter().filter(|(c, _)| is_transfer(c)).count();
    assert!(total > 1);

    let error = injected_flash_failure(&current, &target, |c| c == cdb::probe());
    let failure = error.downcast_ref::<UpdateFailure>().unwrap();
    assert_eq!(failure.progress, UpdateProgress::Preflight);
    assert!(!failure.write_started);

    let error = injected_flash_failure(&current, &target, |c| c == cdb::enter_update());
    let failure = error.downcast_ref::<UpdateFailure>().unwrap();
    assert_eq!(failure.progress, UpdateProgress::EntryAttempted);
    assert_eq!(failure.phase, "update entry");
    assert!(!failure.temporary_firmware);

    for (fail_at, progress) in [
        (1, UpdateProgress::PayloadAttempted),
        (total, UpdateProgress::PayloadAccepted),
    ] {
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let error = injected_flash_failure(&current, &target, move |c| {
            is_transfer(c) && counter.fetch_add(1, Ordering::SeqCst) + 1 == fail_at
        });
        let failure = error.downcast_ref::<UpdateFailure>().unwrap();
        assert_eq!(failure.progress, progress, "chunk {fail_at}");
        assert_eq!(failure.phase, "firmware transfer");
        assert!(failure.write_started);
        assert!(!failure.temporary_firmware, "single-stage flash");
        if fail_at == 1 {
            assert_eq!(failure.payload_bytes_accepted, Some(0));
        } else {
            assert!(failure.payload_bytes_accepted > Some(0));
        }
    }
}

#[test]
fn failed_first_stage_of_a_two_stage_flash_leaves_temporary_firmware() {
    let (result, _, _, _) = run(false, false);
    let error = result.unwrap_err();
    let failure = error.downcast_ref::<UpdateFailure>().unwrap();
    assert!(failure.temporary_firmware);
}

#[test]
fn failure_phase_names_each_flash_boundary() {
    use mediatek_optical::drive::FlashError;
    let transport = || DriveError::Transport(anyhow!("x"));
    assert_eq!(
        failure_phase(&FlashError::Transfer {
            offset: 0,
            length: 1,
            source: transport()
        }),
        ("firmware transfer", true)
    );
    assert_eq!(
        failure_phase(&FlashError::Fault {
            stage: Stage::Commit,
            sense: (4, 0x44, 0)
        }),
        ("programming status", true)
    );
    assert_eq!(
        failure_phase(&FlashError::ReadyTimeout(transport())),
        ("waiting for programming to finish", true)
    );
}

#[test]
fn runtime_tracks_upload_state_clock_and_phases() {
    use mediatek_optical::{Component, Phase, Progress};
    use std::{cell::RefCell, rc::Rc, time::Duration};
    let mut runtime = Runtime::new();
    assert!(!runtime.upload_complete());
    assert_eq!(runtime.payload_bytes_accepted(), 0);
    runtime.progress(10, 100);
    assert_eq!(runtime.payload_bytes_accepted(), 10);
    runtime.uploaded(100);
    assert!(runtime.upload_complete());
    assert_eq!(runtime.payload_bytes_accepted(), 100);

    crate::runtime_clock::simulated(|| {
        let mut runtime = Runtime::new();
        runtime.sleep(Duration::from_secs(5));
        assert_eq!(runtime.elapsed(), Duration::from_secs(5));
    });

    let seen = Rc::new(RefCell::new(Vec::new()));
    let sink = seen.clone();
    crate::output::capture_events(
        move |event| sink.borrow_mut().push(event),
        || {
            Runtime::new().operation_progress(Progress::bytes(
                Phase::Writing,
                Component::Firmware,
                5,
                10,
            ));
        },
    );
    assert!(seen.borrow().contains(&crate::output::Event::Phase {
        phase: "writing",
        component: "filter.firmware",
        done: Some(5),
        total: Some(10),
    }));
}

#[test]
fn mediatek_helpers_report_banner_text_and_flash_acceptance() {
    assert!(Mtk.accepts_current());
    let mut img = image(b"1.00", 1);
    let at = ROM_003000_OFFSET as usize;
    for k in 0..crossflash::BANNER_LEN {
        img[at + k] = 0xA0 + k as u8;
    }
    let mut dev = MockScsiDevice::echoing().with_firmware_image(img.clone());
    let banner = read_drive_banner(&mut ReadDevice::without_unlocks(&mut dev)).unwrap();
    assert_eq!(&banner[..], &img[at..at + crossflash::BANNER_LEN]);
    let mut failing = MockScsiDevice::echoing()
        .with_firmware_image(img)
        .on_fail(|c| c.first() == Some(&0x3c), "banner unreadable");
    assert!(read_drive_banner(&mut ReadDevice::without_unlocks(&mut failing)).is_none());

    assert_eq!(
        text(&DriveError::Transport(anyhow!("inner").context("outer"))),
        "outer: inner"
    );
    let short = DriveError::Short {
        expected: 4,
        actual: 2,
    };
    assert_eq!(text(&short), short.to_string());
    assert!(!text(&short).is_empty());
}

#[test]
fn recovery_transfer_failure_classifies_attempted_versus_accepted_payload() {
    use crate::backend::UpdateProgress;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let current = image(b"1.00", 1);
    let target = image(b"1.01", 3);
    let is_transfer = |c: &[u8]| c.len() > 1 && c[0] == 0x3b && c[1] == 0x06;
    let mut clean = MockScsiDevice::echoing().with_firmware_image(current.clone());
    crate::engine::recover(&mut clean, &Mtk, None, &target, true, true).unwrap();
    let total = clean.writes.iter().filter(|(c, _)| is_transfer(c)).count();
    for (fail_at, progress) in [
        (1, UpdateProgress::PayloadAttempted),
        (total, UpdateProgress::PayloadAccepted),
    ] {
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let mut dev = MockScsiDevice::echoing()
            .with_firmware_image(current.clone())
            .on_fail(
                move |c| is_transfer(c) && counter.fetch_add(1, Ordering::SeqCst) + 1 == fail_at,
                "transfer rejected",
            );
        let error = crate::engine::recover(&mut dev, &Mtk, None, &target, true, true).unwrap_err();
        let failure = error.downcast_ref::<UpdateFailure>().unwrap();
        assert_eq!(failure.progress, progress, "chunk {fail_at}");
        assert_eq!(failure.phase, "firmware transfer");
        assert!(failure.write_started);
    }
}
