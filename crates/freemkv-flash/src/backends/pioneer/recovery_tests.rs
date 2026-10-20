use super::*;
use crate::engine::gates::ungated_for_tests;
use pioneer_optical::envelope::{
    builder::{encode_encrypted_pair, BuildInputs, KernelBuild, NormalSignature},
    signature::SigningKey,
    Update,
};

// Synthetic instruction fixtures, not extracted firmware images.
const UNGATED_FINALIZER: &[u8] = &[
    0x7a, 0x00, 0x00, 0x01, 0x12, 0x00, 0x1f, 0x81, 0x58, 0x60, 0x00, 0x94, 0x1a, 0x91, 0x01, 0x00,
    0x69, 0xc1, 0x01, 0x00, 0x6f, 0x41, 0x00, 0x08, 0x1a, 0xb3, 0xf3, 0x12, 0x0a, 0x93, 0x7a, 0x11,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x69, 0xf1, 0x1a, 0xd5, 0xf5, 0x10, 0x01, 0x00, 0x6f, 0xf5,
    0x00, 0x04, 0x0f, 0xf0, 0x79, 0x10, 0x00, 0x0c, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x08, 0x0f, 0xc0,
    0x7a, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xb1, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x46, 0x0e,
    0x18, 0x99, 0x0f, 0xc0, 0x5e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x0c, 0x01, 0x00,
    0x6f, 0x70, 0x00, 0x0c,
];

const GATED_FINALIZER: &[u8] = &[
    0x7a, 0x00, 0x00, 0x01, 0x12, 0x00, 0x1f, 0x81, 0x58, 0x60, 0x00, 0xa6, 0x1a, 0x91, 0x01, 0x00,
    0x69, 0xd1, 0x01, 0x00, 0x6f, 0x51, 0x00, 0x08, 0x1a, 0xb3, 0xf3, 0x12, 0x0a, 0x93, 0x7a, 0x11,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x69, 0xf1, 0x1a, 0xc4, 0xf4, 0x10, 0x01, 0x00, 0x6f, 0xf4,
    0x00, 0x04, 0x0f, 0xf0, 0x79, 0x10, 0x00, 0x0c, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x08, 0x0f, 0xd0,
    0x7a, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xb1, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x46, 0x0e,
    0x18, 0x99, 0x0f, 0xd0, 0x5e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x0c, 0x18, 0x99,
    0x0f, 0xd0, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x47, 0x44, 0x01, 0x00, 0x6f, 0x70, 0x00, 0x0c,
];

const MARKER_CHECK: &[u8] = &[
    0x01, 0x00, 0x6d, 0xf4, 0x1b, 0x87, 0x0f, 0x82, 0x01, 0x00, 0x6b, 0x24, 0x00, 0x41, 0x00, 0x14,
    0x01, 0x00, 0x6f, 0x00, 0x00, 0x08, 0x0c, 0x99, 0x46, 0x0a, 0x7a, 0x10, 0x00, 0x00, 0x12, 0xfe,
    0x0f, 0x81, 0x40, 0x0e, 0x01, 0x00, 0x6f, 0x21, 0x00, 0x0e, 0x0a, 0x81, 0x7a, 0x11, 0x00, 0x01,
    0x00, 0x28, 0x0f, 0xf0, 0x1a, 0xa2, 0xfa, 0x01, 0x5e, 0x00, 0x01, 0x90, 0x68, 0x78, 0xa8, 0xff,
    0x47, 0x08, 0x0c, 0x88, 0x47, 0x04, 0x18, 0x00, 0x40, 0x02, 0xf0, 0x01, 0x6a, 0x30, 0x00, 0x00,
    0x06, 0x7e, 0x77, 0x00, 0x44, 0x0a, 0x7a, 0x24, 0xff, 0xff, 0xff, 0xff, 0x46, 0x02, 0x18, 0x00,
    0x0c, 0x08, 0x0b, 0xf7, 0x01, 0x00, 0x6d, 0x74, 0x54, 0x70,
];

fn balance(bytes: &mut [u8]) {
    let at = bytes.len() - 4;
    bytes[at..].fill(0);
    let sum = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |sum, w| sum.wrapping_add(u32::from_be_bytes(*w)));
    bytes[at..].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
fn fixture_pair(gated: bool, marker: u8) -> Update {
    fixture_pair_sat(gated, marker, b"SAT FFFEGENERAL 0000")
}

fn fixture_pair_sat(gated: bool, marker: u8, sat: &[u8; 20]) -> Update {
    // Default receiver class: XOR-skip offsets [0x100, 0x200].
    fixture_pair_class(gated, marker, sat, [0x100, 0x200])
}

/// Like `fixture_pair_sat` but with explicit XOR-skip offsets, so a test can
/// build a second receiver class (the offsets ARE the class; see
/// `kernel_xor_branches`). Both must be distinct and 4-aligned.
fn fixture_pair_class(gated: bool, marker: u8, sat: &[u8; 20], xor_offsets: [u32; 2]) -> Update {
    fixture_pair_class_with(gated, marker, sat, xor_offsets, |_| {})
}

/// As `fixture_pair_class`, but `tweak` may edit the decoded Kernel body (before
/// its checksum is balanced) — used to plant a loader's receive-transport
/// fingerprint so the detector picks the two-region 10xx transport.
fn fixture_pair_class_with(
    gated: bool,
    marker: u8,
    sat: &[u8; 20],
    xor_offsets: [u32; 2],
    tweak: impl FnOnce(&mut [u8]),
) -> Update {
    let mut kernel = vec![0; 0x10000];
    crate::kernel_handoff_fixture(&mut kernel);
    kernel[0x1000..0x1014].copy_from_slice(sat);
    kernel[0x40..0x42].copy_from_slice(&[0xae, 0xfe]);
    kernel[0x46..0x48].copy_from_slice(&[0xae, 0xf0]);
    let (o1, o2) = (xor_offsets[0].to_be_bytes(), xor_offsets[1].to_be_bytes());
    #[rustfmt::skip]
    let branch = [
        0x7a, 0x20, o1[0], o1[1], o1[2], o1[3], 0x47, 12,
        0x7a, 0x20, o2[0], o2[1], o2[2], o2[3], 0x47, 4,
        1, 0xf0, 0x65, 5,
    ];
    kernel[0x100..0x114].copy_from_slice(&branch);
    // The XOR-skip branch above is followed by the Forward-rotation decode loop
    // the receiver reads: AND.W #0x1F,R3; MOV.W R3,R1; JSR shift-helper (at
    // KERNEL_BASE+0x114+14 = 0x400122); OR.L; SHLR.L (right) + RTS. Without this
    // `normal_rotation_from_kernel` returns None and `Update::load` fails
    // `UnknownRotation`.
    kernel[0x114..0x126].copy_from_slice(&[
        0x79, 0x63, 0, 0x1f, 0x0d, 0x31, 0x5e, 0x40, 0x01, 0x22, 1, 0xf0, 0x64, 0x40, 0x11, 0x70,
        0x54, 0x70,
    ]);
    let finalizer = if gated {
        GATED_FINALIZER
    } else {
        UNGATED_FINALIZER
    };
    kernel[0x300..0x300 + finalizer.len()].copy_from_slice(finalizer);
    for (offset, address) in [(0x349, [0x40, 0x20, 0]), (0x355, [0x40, 0x22, 0])] {
        kernel[offset..offset + 3].copy_from_slice(&address);
    }
    if gated {
        kernel[0x363..0x366].copy_from_slice(&[0x40, 0x30, 0]);
        kernel[0x3000..0x3000 + MARKER_CHECK.len()].copy_from_slice(MARKER_CHECK);
    }
    kernel[pioneer_optical::envelope::KERNEL_MARKER_OFFSET] = marker;
    tweak(&mut kernel);
    balance(&mut kernel);
    let mut normal = vec![0; 0x2000];
    normal[..16].copy_from_slice(b"PIONEER TEST-NEW");
    normal[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    normal[0x400..0x408].copy_from_slice(&[0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36, 0, 0]);
    normal[0x500..0x510].copy_from_slice(&[
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, marker, 0x46, 0x4e,
    ]);
    balance(&mut normal);
    let mut scalar = [0; 20];
    scalar[19] = 5;
    let signer = SigningKey::from_bytes(scalar).unwrap();
    let encoded = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "26/10/07",
            kernel: KernelBuild::from_seed(7),
            normal_key_seed: 11,
        },
        NormalSignature::Sign(&signer),
    )
    .unwrap();
    Update::load(&encoded.kernel, &encoded.normal).unwrap()
}

#[test]
fn unsigned_targets_are_signed_only_for_transfer_and_invalid_signatures_still_fail() {
    let pair = fixture_pair(false, 1);
    let kernel = pair.kernel_transfer();
    let signed = pair.normal_transfer();
    assert!(super::super::normal_prepare::load_pair(kernel, signed).is_ok());
    for zeroed in [true, false] {
        let mut normal = signed.to_vec();
        if zeroed {
            normal[0x170..0x1c0].fill(0);
        } else {
            normal[0x170] ^= 1;
        }
        if zeroed {
            let prepared = super::super::normal_prepare::load_pair(kernel, &normal).unwrap();
            assert_eq!(prepared.normal().image, pair.normal().image);
            assert_eq!(prepared.kernel().image, pair.kernel().image);
            let transfer = prepared.normal_transfer();
            assert_eq!(&transfer[..0x170], &normal[..0x170]);
            assert_eq!(&transfer[0x1c0..], &normal[0x1c0..]);
            assert!(normal[0x170..0x1c0].iter().all(|b| *b == 0));
            assert!(Update::load(kernel, transfer).is_ok());
            assert!(super::super::offline_pair_data_out(kernel, &normal).is_ok());
            let installed = archive(&pair, false);
            let plan = crate::backend::FlashPlan::new(super::super::execute_plan(&normal).unwrap());
            let authorized = super::super::authorize_installed(plan, Some(&installed)).unwrap();
            let prepared = authorized.state::<super::super::Prepared>().unwrap();
            assert!(
                prepared.normal.is_some(),
                "Normal-only backup must be prepared"
            );
            let unsigned_pair = archive(&pair, true);
            let plan =
                crate::backend::FlashPlan::new(super::super::execute_plan(&unsigned_pair).unwrap());
            let authorized = super::super::authorize_installed(plan, Some(&installed)).unwrap();
            let prepared = authorized.state::<super::super::Prepared>().unwrap();
            assert!(
                prepared.complete.is_some(),
                "Paired backup must be prepared"
            );
            // A missing signature does not excuse a corrupt body/key table.
            let mut corrupt = normal.clone();
            let last = corrupt.len() - 4;
            corrupt[last] ^= 1;
            assert!(super::super::normal_prepare::load_pair(kernel, &corrupt).is_err());
            continue;
        }
        for error in [
            super::super::normal_prepare::load_pair(kernel, &normal).unwrap_err(),
            super::super::offline_pair_data_out(kernel, &normal).unwrap_err(),
        ] {
            let message = error.to_string();
            assert!(message.contains("No firmware was written"), "{error:#}");
            assert!(message.contains("signed"), "{error:#}");
            assert!(matches!(
                error.downcast_ref::<pioneer_optical::envelope::UpdateError>(),
                Some(pioneer_optical::envelope::UpdateError::Authentication)
            ));
            assert!(message.contains("could not be verified"));
            assert!(message.contains("nonzero invalid signature"));
        }
    }
}

struct Drive {
    updating: bool,
    finished: bool,
    stuck: bool,
    fail_write: Option<usize>,
    attempts: usize,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
    require_sense_restart: bool,
    restart_pending: bool,
    sense_polls: usize,
    reject_sense: bool,
    parameter: Option<u16>,
    parameter_reads: usize,
    reject_parameter_write: bool,
    readback_images: Vec<Vec<u8>>,
    finished_passes: usize,
    post_flash_hardware: Option<String>,
    post_flash_kernel_tag: Option<String>,
}
impl Default for Drive {
    fn default() -> Self {
        Self {
            updating: false,
            finished: false,
            stuck: false,
            fail_write: None,
            attempts: 0,
            writes: Vec::new(),
            require_sense_restart: false,
            restart_pending: false,
            sense_polls: 0,
            reject_sense: false,
            parameter: Some(0xffff),
            parameter_reads: 0,
            reject_parameter_write: false,
            readback_images: Vec::new(),
            finished_passes: 0,
            post_flash_hardware: None,
            post_flash_kernel_tag: None,
        }
    }
}
impl ScsiDevice for Drive {
    fn describe(&self) -> String {
        "Recovery test".into()
    }
    fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; len];
        if command.len() == 10 && command[2] == 0xb0 && !self.readback_images.is_empty() {
            let address = u32::from_be_bytes([0, command[3], command[4], command[5]]) as usize;
            let image = self
                .readback_images
                .get(self.finished_passes.saturating_sub(1))
                .context("unexpected Kernel readback pass")?;
            let start = address
                .checked_sub(pioneer_optical::image::KERNEL_BASE as usize)
                .context("unexpected readback address")?;
            return Ok(image[start..start + len].to_vec());
        }
        if command == cdb::read_parameter_word(0x9f).unwrap() {
            assert!(!self.updating, "Normal parameter command in update mode");
            self.parameter_reads += 1;
            return Ok(self
                .parameter
                .expect("parameter not configured")
                .to_be_bytes()
                .to_vec());
        }
        if command == cdb::request_sense(18) {
            self.sense_polls += 1;
            if self.reject_sense {
                bail!("REQUEST SENSE unavailable");
            }
            self.restart_pending = false;
            return Ok(bytes);
        }
        if self.restart_pending {
            return Err(crate::platform::ScsiSenseError::new(
                2,
                4,
                2,
                "initializing command required",
            )
            .into());
        }
        let kernel = (self.updating && !self.finished) || self.stuck;
        if command == cdb::inquiry(len as u8) {
            bytes[0] = 5;
            bytes[8..16].copy_from_slice(b"PIONEER ");
            bytes[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
            bytes[32..36].copy_from_slice(if kernel { b"0000" } else { b"1.00" });
        } else if command == cdb::vendor_identity() {
            let hardware = if self.finished_passes > 0 {
                self.post_flash_hardware.as_deref().unwrap_or("SAT FFFE")
            } else {
                "SAT FFFE"
            };
            let kernel_tag = if self.finished_passes > 0 {
                self.post_flash_kernel_tag.as_deref().unwrap_or("GENERAL ")
            } else {
                "GENERAL "
            };
            bytes[16..24].copy_from_slice(format!("{hardware:<8}").as_bytes());
            bytes[24..32].copy_from_slice(format!("{kernel_tag:<8}").as_bytes());
            if !kernel {
                bytes[32..40].copy_from_slice(b"GENERAL ");
            }
        } else if command == cdb::test_unit_ready() {
            return Err(crate::platform::ScsiSenseError::new(2, 0x3a, 0, "no medium").into());
        } else if command != cdb::get_event_status() {
            panic!("unexpected read (firmware reads forbidden): {command:02x?}");
        }
        Ok(bytes)
    }
    fn command_out(&mut self, command: &[u8], _: &[u8]) -> Result<()> {
        if !self.readback_images.is_empty() && command == cdb::knock() {
            return Ok(());
        }
        panic!("lenient write forbidden")
    }
    fn command_out_strict(&mut self, command: &[u8], bytes: &[u8]) -> Result<()> {
        self.attempts += 1;
        if command == cdb::write_parameter_word(0x9f).unwrap() {
            assert!(!self.updating, "Normal parameter command in update mode");
            if self.reject_parameter_write {
                bail!("injected parameter write failure");
            }
            self.parameter = Some(u16::from_be_bytes(bytes.try_into().unwrap()));
            self.writes.push((command.to_vec(), bytes.to_vec()));
            return Ok(());
        }
        if self.fail_write == Some(self.attempts) {
            bail!("injected write failure");
        }
        self.writes.push((command.to_vec(), bytes.to_vec()));
        if command == cdb::enter_update() {
            self.finished = false;
        }
        if command == cdb::finish() && self.writes.iter().any(|(c, _)| c[2] == 0xf0) {
            self.finished = true;
            self.restart_pending = self.require_sense_restart;
            self.finished_passes += 1;
        }
        Ok(())
    }
}
fn recovery_plan() -> Plan {
    Plan::from_updates(fixture_pair(false, 1), fixture_pair(false, 0)).unwrap()
}

#[test]
fn normal_recovery_changes_startup_word_before_update_entry() {
    let mut plan = recovery_plan();
    plan.startup_setting = pioneer_optical::startup::Setting {
        parameter: 0x9f,
        value: 0xff01,
        explicit: true,
    };
    let mut drive = Drive {
        parameter: Some(0xffff),
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(drive.parameter, Some(0xff01));
    assert_eq!(drive.parameter_reads, 2);
    assert_eq!(drive.writes[0].0, cdb::write_parameter_word(0x9f).unwrap());
    assert_eq!(drive.writes[1].0, cdb::enter_update());
}

#[test]
fn recovery_parameter_write_failure_stops_before_update_entry() {
    let mut plan = recovery_plan();
    plan.startup_setting = pioneer_optical::startup::Setting {
        parameter: 0x9f,
        value: 0xff01,
        explicit: true,
    };
    let mut drive = Drive {
        parameter: Some(0xffff),
        reject_parameter_write: true,
        ..Default::default()
    };
    assert!(plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .is_err());
    assert!(drive.writes.is_empty());
    assert!(!drive.updating);
}

#[test]
fn recovery_in_update_mode_does_not_issue_normal_parameter_command() {
    let mut plan = recovery_plan();
    plan.startup_setting = pioneer_optical::startup::Setting {
        parameter: 0x9f,
        value: 0xff01,
        explicit: true,
    };
    let mut drive = Drive {
        updating: true,
        parameter: Some(0xffff),
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(drive.parameter, Some(0xffff));
    assert_eq!(drive.parameter_reads, 0);
    assert!(!drive.writes.iter().any(|(c, _)| c.get(2) == Some(&0xa0)));
}

#[test]
#[ignore = "requires the supplied BDR-207M 1.60 backup and BDR-PR1ML 1.30 package"]
fn real_207m_to_pr1ml_recovery_selects_ff01() {
    let current = std::fs::read(std::env::var("PIONEER_RECOVERY_CURRENT").unwrap()).unwrap();
    let target = std::fs::read(std::env::var("PIONEER_RECOVERY_TARGET").unwrap()).unwrap();
    let plan = Plan::prepare(&current, &target).unwrap();
    assert_eq!(plan.startup_setting.parameter, 0x9f);
    assert_eq!(plan.startup_setting.value, 0xff01);
    assert!(plan.startup_setting.explicit);
}

#[test]
fn completed_programming_needs_sense_poll_before_normal_can_start() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        require_sense_restart: true,
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert!(drive.finished);
    assert!(!drive.restart_pending);
    assert_eq!(drive.sense_polls, 1);
}

#[test]
fn failed_sense_poll_cannot_turn_a_stuck_loader_into_success() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        require_sense_restart: true,
        reject_sense: true,
        ..Default::default()
    };
    let error = plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(error.to_string().contains("return to normal mode"));
    assert!(drive.finished && drive.restart_pending);
    assert_eq!(drive.sense_polls, READINESS_POLLS + 1);
    assert_eq!(
        drive
            .writes
            .iter()
            .filter(|(c, _)| *c == cdb::finish())
            .count(),
        1
    );
}

#[test]
fn handoff_mismatch_refuses_flash_offline_and_recovery_preparation() {
    let current = fixture_pair(false, 1);
    let target = fixture_pair_class_with(
        false,
        1,
        b"SAT FFFEGENERAL 0000",
        [0x100, 0x200],
        |kernel| {
            kernel.copy_within(0x20..0x30, 0x2a);
            kernel[0x20..0x2a].fill(0);
        },
    );
    let current = archive(&current, false);
    let target = archive(&target, false);
    let error = Plan::prepare(&current, &target)
        .err()
        .expect("Recovery must refuse during preparation");
    let text = format!("{error:#}");
    assert!(
        text.contains("handoff mismatch") && text.contains("0x400020") && text.contains("0x40002a"),
        "{text}"
    );
    let decision =
        crate::crossflash::decide(crate::crossflash::Platform::Pioneer, &current, &target);
    assert_eq!(
        decision.status,
        crate::crossflash::CompatibilityStatus::SoftNo
    );
    let error = super::super::decide_offline(&current, &target).unwrap_err();
    assert!(format!("{error:#}").contains("handoff mismatch"));
}

#[test]
fn unknown_programmer_is_not_bypassed_by_recovery() {
    let current = fixture_pair_class_with(
        false,
        1,
        b"SAT FFFEGENERAL 0000",
        [0x100, 0x200],
        |kernel| {
            kernel[0xe000..0xe016].fill(0);
        },
    );
    let error = Plan::from_updates(current, fixture_pair(false, 1))
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("installed Kernel programming handoff is unsupported"));
}

#[test]
fn compatibility_status_preserves_hard_refusals_over_handoff_candidates() {
    use crate::crossflash::{decide, CompatibilityStatus::*, Platform};
    let installed = archive(&fixture_pair(false, 1), false);
    let same = archive(&fixture_pair(false, 1), false);
    assert_eq!(decide(Platform::Pioneer, &installed, &same).status, Yes);
    let unknown = archive(
        &fixture_pair_class_with(false, 1, b"SAT FFFEGENERAL 0000", [0x100, 0x200], |k| {
            k[0xe000..0xe016].fill(0)
        }),
        false,
    );
    assert_eq!(decide(Platform::Pioneer, &unknown, &same).status, HardNo);
    assert!(Plan::prepare(&unknown, &same).is_err());
    // A receiver-class change does not add a hard refusal to a paired update:
    // the incoming Kernel receives its own Normal after the handoff.
    let incompatible = archive(
        &fixture_pair_class_with(false, 1, b"SAT FFFEGENERAL 0000", [0x104, 0x204], |k| {
            k.copy_within(0x20..0x30, 0x2a);
            k[0x20..0x2a].fill(0);
        }),
        false,
    );
    assert_eq!(
        decide(Platform::Pioneer, &installed, &incompatible).status,
        SoftNo
    );
    assert!(Plan::prepare(&installed, &incompatible).is_err());
    assert_eq!(decide(Platform::Pioneer, b"invalid", &same).status, HardNo);
}

#[test]
fn kernel_recovery_writes_both_components_without_entry_or_firmware_reads() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(drive.writes.first().unwrap().0[2], 0xfe);
    assert_eq!(
        drive
            .writes
            .iter()
            .filter(|(c, _)| *c == cdb::finish())
            .count(),
        1
    );
    for (buffer, expected) in [
        (0xfe, plan.kernel_transfer.as_slice()),
        (0xf0, plan.normal_transfer.as_slice()),
    ] {
        let actual: Vec<_> = drive
            .writes
            .iter()
            .filter(|(c, _)| c[2] == buffer)
            .flat_map(|(_, b)| b.iter().copied())
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn gated_loader_recovers_erased_marker_with_verified_temporary_then_pristine_kernel() {
    let plan = Plan::from_updates(fixture_pair(true, 1), fixture_pair(false, 0xff)).unwrap();
    assert_eq!(plan.first_kernel_image[0xfe], 1);
    assert_eq!(plan.final_kernel_image[0xfe], 0xff);
    let pristine = plan.restoration_kernel_transfer.as_ref().unwrap();
    assert_ne!(&plan.kernel_transfer, pristine);
    let mut drive = Drive {
        updating: true,
        readback_images: vec![
            plan.first_kernel_image.clone(),
            plan.final_kernel_image.clone(),
        ],
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(drive.finished_passes, 2);
    let finish_positions: Vec<_> = drive
        .writes
        .iter()
        .enumerate()
        .filter_map(|(i, (cdb, _))| (cdb == &cdb::finish()).then_some(i))
        .collect();
    assert_eq!(finish_positions.len(), 2);
    assert!(!drive.writes[..finish_positions[0]]
        .iter()
        .any(|(cdb, _)| cdb == &cdb::enter_update()));
    assert!(drive.writes[finish_positions[0] + 1..finish_positions[1]]
        .iter()
        .any(|(cdb, _)| cdb == &cdb::enter_update()));
    for (writes, expected) in [
        (&drive.writes[..finish_positions[0]], &plan.kernel_transfer),
        (
            &drive.writes[finish_positions[0] + 1..finish_positions[1]],
            pristine,
        ),
    ] {
        let actual: Vec<_> = writes
            .iter()
            .filter(|(cdb, _)| cdb[2] == 0xfe)
            .flat_map(|(_, data)| data.iter().copied())
            .collect();
        assert_eq!(&actual, expected);
    }
}

#[test]
fn temporary_kernel_readback_mismatch_stops_before_pristine_restoration() {
    let plan = Plan::from_updates(fixture_pair(true, 1), fixture_pair(false, 0xff)).unwrap();
    let mut wrong = plan.first_kernel_image.clone();
    wrong[0x400] ^= 1;
    let mut drive = Drive {
        updating: true,
        readback_images: vec![wrong, plan.final_kernel_image.clone()],
        ..Default::default()
    };
    let error = plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(format!("{error:#}").contains("readback differs"));
    assert_eq!(drive.finished_passes, 1);
    assert_eq!(
        drive
            .writes
            .iter()
            .filter(|(cdb, _)| cdb == &cdb::finish())
            .count(),
        1
    );
}

#[test]
fn pristine_kernel_readback_mismatch_reports_failed_restoration() {
    let plan = Plan::from_updates(fixture_pair(true, 1), fixture_pair(false, 0xff)).unwrap();
    let mut wrong_final = plan.final_kernel_image.clone();
    wrong_final[0x400] ^= 1;
    let mut drive = Drive {
        updating: true,
        readback_images: vec![plan.first_kernel_image.clone(), wrong_final],
        ..Default::default()
    };
    let error = plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(format!("{error:#}")
        .contains("pristine Kernel restoration finished but readback did not verify"));
    assert_eq!(drive.finished_passes, 2);
}

/// Plant the BD 10xx kernel-loader fingerprint into a free region of a decoded
/// Kernel body so the transport detector selects the two-region transport.
fn plant_two_region_signature(kernel: &mut [u8]) {
    kernel[0x5000..0x5006].copy_from_slice(&[0x7a, 0x10, 0x00, 0x01, 0x02, 0x00]);
    kernel[0x5010..0x5014].copy_from_slice(&0x0001_1200u32.to_be_bytes());
    kernel[0x5020..0x5024].copy_from_slice(&0x0002_0400u32.to_be_bytes());
    kernel[0x5030..0x5034].copy_from_slice(&0x0041_0000u32.to_be_bytes());
}

#[test]
fn two_region_kernel_recovery_preserves_oem_header_key_body_placement() {
    // OEM receivers add their staging base to CDB offsets and consume the key
    // at base+0x200 and body at base+0x1200. See pioneer-optical OEM_PLACEMENT.md.
    let installed = fixture_pair_class_with(
        false,
        1,
        b"SAT FFFEGENERAL 0000",
        [0x100, 0x200],
        plant_two_region_signature,
    );
    let target = fixture_pair_class(false, 0, b"SAT FFFEGENERAL 0000", [0x400, 0x800]);
    let plan = Plan::from_updates(installed, target).unwrap();
    let mut drive = Drive {
        updating: true,
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();

    let kernel_writes: Vec<_> = drive.writes.iter().filter(|(c, _)| c[2] == 0xfe).collect();
    assert_eq!(kernel_writes.len(), 3);
    for ((cdb, bytes), (offset, range)) in kernel_writes.iter().zip([
        ([0x00, 0x00, 0x00], 0..0x1200),
        ([0x00, 0x12, 0x00], 0x1200..0x9200),
        ([0x00, 0x92, 0x00], 0x9200..0x11200),
    ]) {
        assert_eq!(&cdb[3..6], &offset);
        assert_eq!(bytes.as_slice(), &plan.kernel_transfer[range]);
    }
    let received: Vec<u8> = kernel_writes
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    assert_eq!(received, plan.kernel_transfer);
}

#[test]
fn normal_recovery_enters_first_and_uses_supplied_receiver_control() {
    let plan = recovery_plan();
    let mut drive = Drive::default();
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(
        drive.writes[0],
        (cdb::enter_update().to_vec(), plan.control.to_vec())
    );
    assert_eq!(drive.writes.last().unwrap().1, plan.control);
}

#[test]
#[ignore = "requires supplied S12JX and WX1DM packages"]
fn real_wx_kernel_mode_recovery_prepares_temporary_and_pristine_passes() {
    let wx = std::fs::read(std::env::var("PIONEER_STARTUP_WX_PACKAGE").unwrap()).unwrap();
    let sj = std::fs::read(std::env::var("PIONEER_STARTUP_ORIGINAL_PACKAGE").unwrap()).unwrap();
    let plan = Plan::prepare(&wx, &sj).unwrap();
    assert_eq!(plan.first_kernel_image[0xfe], 1);
    assert_eq!(plan.final_kernel_image[0xfe], 0xff);
    assert!(plan.restoration_kernel_transfer.is_some());
    let temporary = Envelope::load(&plan.kernel_transfer).unwrap();
    let pristine = Envelope::load(plan.restoration_kernel_transfer.as_ref().unwrap()).unwrap();
    assert_eq!(temporary.image, plan.first_kernel_image);
    assert_eq!(pristine.image, plan.final_kernel_image);
    assert!(Update::load(&plan.kernel_transfer, &plan.normal_transfer).is_ok());
    let mut drive = Drive {
        updating: true,
        require_sense_restart: true,
        post_flash_hardware: Some(plan.restoration_hardware.clone()),
        post_flash_kernel_tag: Some(plan.restoration_kernel_tag.clone()),
        readback_images: vec![
            plan.first_kernel_image.clone(),
            plan.final_kernel_image.clone(),
        ],
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(drive.finished_passes, 2);
    assert!(drive.sense_polls > 0);
    let finish_positions: Vec<_> = drive
        .writes
        .iter()
        .enumerate()
        .filter_map(|(i, (cdb, _))| (cdb == &cdb::finish()).then_some(i))
        .collect();
    assert_eq!(finish_positions.len(), 2);
    for (writes, expected) in [
        (&drive.writes[..finish_positions[0]], &plan.kernel_transfer),
        (
            &drive.writes[finish_positions[0] + 1..finish_positions[1]],
            plan.restoration_kernel_transfer.as_ref().unwrap(),
        ),
    ] {
        let actual: Vec<_> = writes
            .iter()
            .filter(|(cdb, _)| cdb[2] == 0xfe)
            .flat_map(|(_, data)| data.iter().copied())
            .collect();
        assert_eq!(&actual, expected);
    }
    assert!(!drive
        .writes
        .iter()
        .any(|(cdb, _)| cdb.get(2) == Some(&0xa0)));
}
#[test]
fn failed_write_stops_without_retry_or_finish() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        fail_write: Some(2),
        ..Default::default()
    };
    assert!(plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .is_err());
    assert_eq!(drive.attempts, 2);
    assert!(!drive.finished);
}
#[test]
fn remaining_in_kernel_is_not_reported_as_success() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        stuck: true,
        ..Default::default()
    };
    let error = plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(error.to_string().contains("return to normal mode"));
}
#[test]
fn supplied_real_recovery_packages_prepare_and_transfer_without_reads() {
    let (Ok(current), Ok(target)) = (
        std::env::var("PIONEER_RECOVERY_CURRENT"),
        std::env::var("PIONEER_RECOVERY_TARGET"),
    ) else {
        return;
    };
    let current = std::fs::read(current).unwrap();
    let target = std::fs::read(target).unwrap();
    let plan = Plan::prepare(&current, &target).unwrap();
    let (update, original_normal) = load_target(&target).unwrap();
    let transferred = Update::load(update.kernel_transfer(), &plan.normal_transfer)
        .expect("prepared Normal must satisfy its receiving Kernel's integrity and authentication");
    assert_eq!(transferred.normal().image, update.normal().image);
    if original_normal[0x170..0x1c0].iter().all(|byte| *byte == 0) {
        assert!(
            plan.was_reencoded(),
            "unsigned target needs transfer authentication"
        );
        assert_eq!(
            &plan.normal_transfer[0x1c0..],
            &original_normal[0x1c0..],
            "signing must preserve the firmware ciphertext"
        );
    } else {
        assert!(
            !plan.was_reencoded(),
            "paired Normal must retain its OEM encoding"
        );
        assert_eq!(plan.normal_transfer, update.normal_transfer());
    }
    crate::crossflash::admits(crate::crossflash::Platform::Pioneer, &current, &target)
        .expect("Flash must prepare the same paired Normal as Recovery");
    let mut drive = Drive {
        updating: true,
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
}

#[test]
fn credentials_come_from_current_not_target() {
    let current = fixture_pair(false, 1);
    let target = fixture_pair(false, 0);
    let ReceiverControl::Key(expected) =
        pioneer_optical::image::receiver_control(&current.normal().image).unwrap()
    else {
        panic!("expected keyed fixture")
    };
    assert_ne!(
        pioneer_optical::image::receiver_control(&current.normal().image),
        pioneer_optical::image::receiver_control(&target.normal().image)
    );
    let plan = Plan::from_updates(current, target).unwrap();
    assert_eq!(&plan.control[16..20], expected);
}

#[test]
fn entry_failure_never_sends_components() {
    let mut drive = Drive {
        fail_write: Some(1),
        ..Default::default()
    };
    let error = recovery_plan()
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(error.to_string().contains("update entry failed"));
    assert_eq!(drive.attempts, 1);
    assert!(drive.writes.is_empty());
}

fn archive(update: &Update, unsigned: bool) -> Vec<u8> {
    let kernel = update.kernel().repack(&update.kernel().image).unwrap();
    let mut normal = update.normal().repack(&update.normal().image).unwrap();
    if unsigned {
        normal[0x170..0x1c0].fill(0);
    }
    let mut tar = tar::Builder::new(Vec::new());
    for (name, data) in [("kernel.enc", kernel), ("normal.enc", normal)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, data.as_slice()).unwrap();
    }
    tar.into_inner().unwrap()
}

#[test]
fn unsigned_backup_is_valid_current_evidence_and_restorable_target() {
    let update = fixture_pair(false, 1);
    let unsigned = archive(&update, true);
    let signed = archive(&update, false);
    assert!(Plan::prepare(&unsigned, &signed).is_ok());
    let restored = Plan::prepare(&signed, &unsigned).unwrap();
    assert!(Update::load(update.kernel_transfer(), &restored.normal_transfer).is_ok());
    assert_eq!(
        &restored.normal_transfer[0x1c0..],
        &update.normal_transfer()[0x1c0..]
    );
}

struct UnsupportedDrive {
    inquiry: Vec<u8>,
    vendor_reads: usize,
    writes: usize,
}
impl ScsiDevice for UnsupportedDrive {
    fn describe(&self) -> String {
        "unsupported test drive".into()
    }
    fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
        if command == cdb::inquiry(pioneer_optical::INQUIRY_LEN as u8) {
            return Ok(self.inquiry.clone());
        }
        assert_eq!(command, cdb::vendor_identity());
        self.vendor_reads += 1;
        Ok(vec![0; len])
    }
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        self.writes += 1;
        bail!("unexpected write")
    }
    fn command_out_strict(&mut self, c: &[u8], b: &[u8]) -> Result<()> {
        self.command_out(c, b)
    }
}

#[test]
fn wrong_drive_and_short_identity_fail_before_vendor_commands_or_writes() {
    let mut mtk = vec![0; pioneer_optical::INQUIRY_LEN];
    mtk[0] = 5;
    mtk[8..16].copy_from_slice(b"HL-DT-ST");
    let mut disk = mtk.clone();
    disk[0] = 0;
    disk[8..16].copy_from_slice(b"PIONEER ");
    let plan = recovery_plan();
    for inquiry in [mtk, disk, vec![0; 8]] {
        let mut drive = UnsupportedDrive {
            inquiry,
            vendor_reads: 0,
            writes: 0,
        };
        // This same eligibility check is used by the workflow before reads/dry-run.
        assert!(identify_receiver(&mut drive).is_err());
        let error = plan
            .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
            .unwrap_err();
        assert!(
            error.to_string().contains("No firmware written")
                || error.to_string().contains("no firmware written")
        );
        assert_eq!(drive.vendor_reads, 0);
        assert_eq!(drive.writes, 0);
    }
}

#[test]
fn mismatched_live_receiver_fails_before_update_entry() {
    let mut inquiry = vec![0; pioneer_optical::INQUIRY_LEN];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"UNKNOWN RECEIVER");
    let mut drive = UnsupportedDrive {
        inquiry,
        vendor_reads: 0,
        writes: 0,
    };
    let error = recovery_plan()
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("differs from the captured installed firmware"));
    assert_eq!(drive.vendor_reads, 1);
    assert_eq!(drive.writes, 0);
}

#[test]
fn recover_hook_dry_run_writes_nothing_and_execute_writes() {
    let current = archive(&fixture_pair(false, 1), false);
    let target = archive(&fixture_pair(false, 0), false);

    let mut dry = Drive {
        updating: true,
        ..Default::default()
    };
    let pioneer = crate::backends::pioneer::Pioneer::new();
    crate::engine::recover(&mut dry, &pioneer, Some(&current), &target, false, false).unwrap();
    assert_eq!(dry.attempts, 0, "dry run wrote to the drive");
    assert!(dry.writes.is_empty());

    let mut live = Drive {
        updating: true,
        ..Default::default()
    };
    crate::engine::recover(&mut live, &pioneer, Some(&current), &target, true, true).unwrap();
    assert!(live.finished && !live.writes.is_empty());
}

// ---- Hoard-wide recover re-encode KAT ---------------------------------------
//
// Env-gated (`FREEMKV_PIONEER_HOARD`, the directory holding
// `index/packages.json`); unset is a no-op. Across every same-family
// Kernel+Normal package pair, the recover plan must admit exactly the
// offline-provable target Normals. Two cases:
//
//  * same receiver class (identical XOR-skip offsets + rotation): the installed
//    Kernel decodes the shipped Normal to the identical body by construction, so
//    the pair is provable without a re-encode;
//  * different receiver class: the target Normal must re-encode for the installed
//    Kernel and the result must decode, under that Kernel, to the identical body
//    with a zero BE32 checksum. Every such cross-receiver pair is proven here.
//
// The real same-SAT cross-receiver case BDR-207M <- BDR-PR1ML is additionally
// driven end-to-end through `Plan::prepare`; paired Normal keeps the incoming
// Kernel's OEM encoding, while Normal-only preparation may need re-encoding.
#[test]
fn hoard_207m_160_to_pr1ml_175_preserves_normal_for_incoming_kernel() {
    use sha2::{Digest, Sha256};
    let Ok(root) = std::env::var("FREEMKV_PIONEER_HOARD") else {
        return;
    };
    let root = std::path::Path::new(&root);
    let current_hash = "a82b29011251ae3e15fd4f891a29239d974f34e83e1e155725ae3627145d1c7f";
    let target_hash = "a1fea2b6390c668cb3c499e46c77ec4dcae0e9522b08a6c19928feb0b1ccdd00";
    let current = std::fs::read(root.join(format!(
        "packages/pioneer/8000/ID43/1.60/{current_hash}.installer.tar"
    )))
    .unwrap();
    let target = std::fs::read(root.join(format!(
        "packages/pioneer/8000/ID88/1.75/{target_hash}.installer.tar"
    )))
    .unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&current)), current_hash);
    assert_eq!(format!("{:x}", Sha256::digest(&target)), target_hash);
    let (expected, _) = load_target(&target).unwrap();
    let plan = Plan::prepare(&current, &target).unwrap();
    assert!(!plan.was_reencoded());
    assert_eq!(plan.normal_transfer, expected.normal_transfer());
    // The user's log sent this exact target Kernel, then a Normal explicitly
    // re-encoded for installed ID43. The incoming ID88 Kernel receives Normal.
    assert_eq!(
        format!("{:x}", Sha256::digest(&plan.kernel_transfer[..32768])),
        "12bfbcbe3f35c89fe1ecc53854a13ed00bbc5baa97279d78adb83cb9f04937b7"
    );
    let normal_chunk = format!("{:x}", Sha256::digest(&plan.normal_transfer[..32768]));
    assert_ne!(
        normal_chunk,
        "0b2a978c54a16e8585c3d68a418161111abadae7a35e01983acb177149e6a22e"
    );
    eprintln!("PR1ML 1.75 OEM Normal first chunk: {normal_chunk}");
}

#[test]
fn hoard_recover_admits_offline_provable_same_family_pairs() {
    use crate::backends::pioneer::classify_flash_input;
    use crate::backends::pioneer::flash_plan::{
        normal_family_with_kernel, receiver_class, ReceiverClass,
    };
    use pioneer_optical::envelope::builder::{
        encode_normal_for_kernel, NormalKeySource, NormalSignature,
    };
    use pioneer_optical::envelope::signature::SigningKey;
    use pioneer_optical::envelope::{decode_envelope_with_kernel, Envelope};
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    let Ok(root) = std::env::var("FREEMKV_PIONEER_HOARD") else {
        eprintln!("FREEMKV_PIONEER_HOARD not set; recover re-encode KAT skipped");
        return;
    };
    let root = PathBuf::from(root);
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("index/packages.json")).expect("index"))
            .expect("index JSON");
    let field = |p: &serde_json::Value, k: &str| p[k].as_str().unwrap_or_default().to_string();

    struct Meta {
        name: String,
        path: PathBuf,
        family: String,
        class: ReceiverClass,
    }
    let mut metas: Vec<Meta> = Vec::new();
    let mut seen = HashSet::new();
    for p in index["packages"].as_array().expect("packages array") {
        if !p["kernel_sha256"].is_string() || !p["normal_sha256"].is_string() {
            continue;
        }
        if !seen.insert((field(p, "kernel_sha256"), field(p, "normal_sha256"))) {
            continue;
        }
        let path = root.join(field(p, "path"));
        let Ok(tar) = std::fs::read(&path) else {
            continue;
        };
        let Ok((Some(k), Some(n))) = classify_flash_input(&tar) else {
            continue;
        };
        let (Some(family), Some(class)) =
            (normal_family_with_kernel(&n, &k), receiver_class(&k, &n))
        else {
            continue;
        };
        metas.push(Meta {
            name: format!(
                "{} {} {}",
                field(p, "embedded_model"),
                field(p, "destination"),
                field(p, "revision")
            ),
            path,
            family: family.to_string(),
            class,
        });
    }
    assert!(metas.len() >= 2, "hoard must hold multiple K+N packages");

    let mut by_family: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, m) in metas.iter().enumerate() {
        by_family.entry(m.family.as_str()).or_default().push(i);
    }

    // A fixed caller-owned signer; its on-drive acceptance is hardware-unproven.
    let signer = SigningKey::from_bytes([7; 20]).unwrap();
    let decode_body = |kernel: &[u8], normal: &[u8]| -> Option<Vec<u8>> {
        let k = Envelope::load(kernel).ok()?;
        Some(decode_envelope_with_kernel(normal, &k)?.image)
    };

    // `cross_abi` = cross-receiver pairs refused because the target Normal needs
    // Kernel entry points the installed Kernel does not provide (AbiMismatch):
    // a structural incompatibility (different Kernel ABI generation inside one
    // family hash) that re-encode cannot bridge and that `flash` also refuses.
    // These are legitimately not crossflashable, so they are excluded from the
    // re-encode provable-ratio rather than counted as re-encode failures.
    let (mut same_class, mut cross_proven, mut cross_total, mut cross_abi, mut cross_no_seed) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    // Full per-pair matrix (family, installed X, target Y, verdict), emitted to
    // FREEMKV_PIONEER_HOARD_REPORT when set. AS-IS = installed Kernel decodes the
    // shipped Normal unchanged; REENCODE = X->Y needs cross-receiver re-encode;
    // REFUSED = not offline-provable (with cause).
    let mut rows: Vec<String> = Vec::new();
    for group in by_family.values() {
        let mut cross: Vec<(usize, usize)> = Vec::new();
        let mut same_pair: Option<(usize, usize)> = None;
        for &i in group {
            for &j in group {
                if i == j {
                    continue;
                }
                if metas[i].class == metas[j].class {
                    same_class += 1;
                    same_pair.get_or_insert((i, j));
                    rows.push(format!(
                        "{}\t{}\t{}\tAS-IS",
                        metas[i].family, metas[i].name, metas[j].name
                    ));
                } else {
                    cross.push((i, j));
                }
            }
        }
        if cross.is_empty() {
            continue;
        }
        // Load only this family's bytes, proving each cross-receiver pair.
        let bytes: HashMap<usize, (Vec<u8>, Vec<u8>)> = group
            .iter()
            .filter_map(|&i| {
                let (Some(k), Some(n)) =
                    classify_flash_input(&std::fs::read(&metas[i].path).ok()?).ok()?
                else {
                    return None;
                };
                Some((i, (k, n)))
            })
            .collect();
        // Sanity-check the by-construction claim on one same-class pair when one
        // exists in this (multi-class) family.
        if let Some((i, j)) = same_pair {
            let (ki, _) = &bytes[&i];
            let (kj, nj) = &bytes[&j];
            assert_eq!(
                decode_body(ki, nj),
                decode_body(kj, nj),
                "{} and {} share a receiver class but decode a Normal differently",
                metas[i].name,
                metas[j].name
            );
        }
        for (i, j) in cross {
            cross_total += 1;
            let (ki, _) = &bytes[&i];
            let (kj, nj) = &bytes[&j];
            let installed = Envelope::load(ki).expect("installed kernel");
            let want = decode_body(kj, nj).expect("target body");
            let seed = Envelope::load(kj)
                .ok()
                .and_then(|k| decode_envelope_with_kernel(nj, &k))
                .and_then(|n| n.encoding_seed());
            let Some(seed) = seed else {
                cross_no_seed += 1;
                rows.push(format!(
                    "{}\t{}\t{}\tREFUSED: no recoverable encoding seed",
                    metas[i].family, metas[i].name, metas[j].name
                ));
                continue;
            };
            let reencoded = match encode_normal_for_kernel(
                &installed.image,
                &want,
                &nj[..0x200],
                NormalKeySource::Seed(seed),
                NormalSignature::Sign(&signer),
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // AbiMismatch is a legitimate structural refusal (the Normal
                    // requires Kernel entry points this Kernel does not provide),
                    // not a re-encode failure: record it but do not count it
                    // against the provable-ratio.
                    if matches!(e, pioneer_optical::envelope::Error::AbiMismatch) {
                        cross_abi += 1;
                        rows.push(format!(
                            "{}\t{}\t{}\tREFUSED: AbiMismatch",
                            metas[i].family, metas[i].name, metas[j].name
                        ));
                        continue;
                    }
                    failures.push(format!("{} <- {}: {e:?}", metas[j].name, metas[i].name));
                    rows.push(format!(
                        "{}\t{}\t{}\tREFUSED: {e:?}",
                        metas[i].family, metas[i].name, metas[j].name
                    ));
                    continue;
                }
            };
            let proven = decode_envelope_with_kernel(&reencoded, &installed)
                .is_some_and(|d| d.image == want && be32_sum_zero(&d.image));
            if proven {
                cross_proven += 1;
                rows.push(format!(
                    "{}\t{}\t{}\tREENCODE",
                    metas[i].family, metas[i].name, metas[j].name
                ));
            } else {
                failures.push(format!(
                    "{} <- {}: re-encode does not prove",
                    metas[j].name, metas[i].name
                ));
                rows.push(format!(
                    "{}\t{}\t{}\tREFUSED: re-encode does not prove",
                    metas[i].family, metas[i].name, metas[j].name
                ));
            }
        }
    }

    // The real same-SAT cross-receiver case through the full recover plan.
    let find = |n: &str| {
        metas
            .iter()
            .position(|m| m.name.starts_with(n))
            .unwrap_or_else(|| panic!("hoard is missing {n}"))
    };
    let a = find("BDR-207M ID43 1.60");
    let b = find("BDR-PR1ML ID88 1.30");
    assert_eq!(
        metas[a].family, metas[b].family,
        "named case shares a family"
    );
    assert_ne!(
        metas[a].class, metas[b].class,
        "207M and PR1ML must straddle a receiver class"
    );
    let plan = Plan::prepare(
        &std::fs::read(&metas[a].path).unwrap(),
        &std::fs::read(&metas[b].path).unwrap(),
    )
    .expect("installed 207M must admit the paired PR1ML update");
    assert!(
        !plan.was_reencoded(),
        "207M -> PR1ML must preserve Normal for the incoming PR1ML Kernel"
    );

    if let Ok(report) = std::env::var("FREEMKV_PIONEER_HOARD_REPORT") {
        rows.sort();
        let body = format!(
            "# Pioneer recover re-encode matrix: every same-family ordered pair\n\
             # columns: family<TAB>installed(X)<TAB>target(Y)<TAB>verdict\n\
             # AS-IS = installed Kernel decodes shipped Normal unchanged; \
             REENCODE = X->Y needs re-encode; REFUSED = not offline-provable (cause)\n\
             # totals: same-class(AS-IS) {same_class}; cross-receiver proven \
             {cross_proven}/{} seed-available ABI-compatible candidates; \
             {cross_abi} AbiMismatch (structural refusal); {cross_no_seed} \
             no recoverable seed (refused); {} unexpected encode/proof failures\n{}\n",
            cross_total - cross_abi - cross_no_seed,
            failures.len(),
            rows.join("\n"),
        );
        std::fs::write(&report, body).expect("write hoard report");
        eprintln!(
            "wrote recover re-encode matrix ({} rows) to {report}",
            rows.len()
        );
    }
    let seeded_candidates = cross_total - cross_abi - cross_no_seed;
    eprintln!(
        "recover KAT: same-class(AS-IS) {same_class}; cross-receiver re-encode proven \
         {cross_proven}/{seeded_candidates} seed-available ABI-compatible candidates; \
         {cross_abi} AbiMismatch (structural refusal); {cross_no_seed} no recoverable \
         seed (refused); {} unexpected encode/proof failures",
        failures.len()
    );
    assert!(
        seeded_candidates >= 700,
        "far fewer cross-receiver pairs have a recoverable seed and compatible ABI than expected \
         ({seeded_candidates}; {cross_abi} AbiMismatch, {cross_no_seed} seed-unavailable)"
    );
    assert_eq!(
        cross_proven, seeded_candidates,
        "every seed-available ABI-compatible cross-receiver re-encode must prove; \
         {cross_abi} AbiMismatch and {cross_no_seed} seed-unavailable pairs were refused: \
         {failures:#?}"
    );
    assert!(
        failures.is_empty(),
        "unexpected encode/proof failures: {failures:#?}"
    );
    // Both arms of the receiver-class split must actually be exercised, or the
    // ratio above is vacuous.
    assert!(
        same_class > 0 && cross_total > 0,
        "receiver-class split exercised neither arm (same_class={same_class}, \
         cross_total={cross_total})"
    );
}

// ---- Receiver gate: family + encoding, never SAT (0.11.x rule + re-encode) ----

use crate::backends::pioneer::flash_plan::check_receiver;

#[test]
fn check_receiver_fails_closed_when_the_installed_kernel_is_unknown() {
    // A Kernel+Normal flash with no readable installed Kernel must refuse, never
    // assume the drive can receive it. Covered in CI without a hoard.
    let target = fixture_pair(false, 0);
    let tk = target.kernel().repack(&target.kernel().image).unwrap();
    let tn = target.normal().repack(&target.normal().image).unwrap();
    let err = check_receiver(None, Some(&tk), &tn).unwrap_err();
    assert!(
        err.contains("currently-installed Kernel"),
        "unknown installed Kernel must fail closed, got: {err}"
    );
    // A Normal-only flash (no target Kernel) is always admitted: the installed
    // Kernel is the receiver.
    assert!(check_receiver(None, None, &tn).is_ok());
    // An identical installed and target Kernel is trivially its own receiver.
    assert!(check_receiver(Some(&tk), Some(&tk), &tn).is_ok());
}

#[test]
fn check_receiver_admits_a_different_sat_same_receiver_class() {
    // A hardware family spans several SATs and crossflashing across them is the
    // 0.11.x behaviour (e.g. BDR-UD03 SAT 8510 -> BDR-UD04 SAT 8A10). Only the
    // receiver encoding is gated, so a different SAT with the same receiver
    // class must be admitted. Regression guard against re-adding a SAT gate.
    let installed = fixture_pair_sat(false, 1, b"SAT FFFEGENERAL 0000");
    let target = fixture_pair_sat(false, 0, b"SAT FFFDGENERAL 0000");
    let ik = installed
        .kernel()
        .repack(&installed.kernel().image)
        .unwrap();
    let tk = target.kernel().repack(&target.kernel().image).unwrap();
    let tn = target.normal().repack(&target.normal().image).unwrap();
    // Setup sanity: the two kernels really do report different SATs.
    assert_ne!(
        pioneer_optical::envelope::header_info(&ik).map(|h| h.hardware_version),
        pioneer_optical::envelope::header_info(&tk).map(|h| h.hardware_version),
        "fixtures must differ in SAT for this test to mean anything"
    );
    assert_eq!(check_receiver(Some(&ik), Some(&tk), &tn), Ok(()));
}

#[test]
fn paired_normal_uses_incoming_receiver_class() {
    use crate::backends::pioneer::flash_plan::receiver_class;
    // Different XOR-skip rules prove that the old Kernel is not Normal's receiver.
    let installed = fixture_pair_class(false, 1, b"SAT FFFEGENERAL 0000", [0x100, 0x200]);
    let target = fixture_pair_class(false, 0, b"SAT FFFEGENERAL 0000", [0x400, 0x800]);
    let ik = installed
        .kernel()
        .repack(&installed.kernel().image)
        .unwrap();
    let in_ = installed
        .normal()
        .repack(&installed.normal().image)
        .unwrap();
    let tk = target.kernel().repack(&target.kernel().image).unwrap();
    let tn = target.normal().repack(&target.normal().image).unwrap();
    // Setup sanity: the two fixtures really are different receiver classes.
    assert_ne!(
        receiver_class(&ik, &in_),
        receiver_class(&tk, &tn),
        "fixtures must be different receiver classes for this test"
    );
    assert_eq!(
        check_receiver(Some(&ik), Some(&tk), &tn),
        Ok(()),
        "the incoming Kernel receives its paired Normal"
    );
}

#[test]
fn flash_and_recovery_preserve_normal_for_incoming_kernel() {
    use crate::backend::FlashPlan;
    use crate::backends::pioneer::{authorize_installed, execute_plan};
    let target = fixture_pair_class(false, 0, b"SAT FFFEGENERAL 0000", [0x400, 0x800]);
    let installed = fixture_pair_class(false, 1, b"SAT FFFEGENERAL 0000", [0x100, 0x200]);
    let plan = FlashPlan::new(execute_plan(&archive(&target, false)).unwrap());
    let authorized = authorize_installed(plan, Some(&archive(&installed, false))).unwrap();
    let prepared = authorized.state::<super::super::Prepared>().unwrap();
    assert_eq!(
        prepared.complete.as_ref().unwrap().normal_transfer(),
        target.normal_transfer()
    );
    let recovery = Plan::prepare(&archive(&installed, false), &archive(&target, false)).unwrap();
    assert!(!recovery.was_reencoded());
    assert_eq!(recovery.normal_transfer, target.normal_transfer());
    let bytes = target.normal().repack(&target.normal().image).unwrap();
    let converted =
        super::super::normal_prepare::prepare(installed.kernel(), target.normal(), &bytes).unwrap();
    assert_ne!(
        converted, bytes,
        "a Normal-only conversion really changes encoding"
    );
    let proof =
        pioneer_optical::envelope::Envelope::load_with_kernel(&converted, installed.kernel())
            .unwrap();
    assert_eq!(proof.image, target.normal().image);
    assert!(be32_sum_zero(&proof.image));

    let target = fixture_pair_sat(false, 0, b"SAT FFFEGENERAL 0000");
    let installed = fixture_pair_sat(false, 1, b"SAT FFFDGENERAL 0000");
    let plan = FlashPlan::new(execute_plan(&archive(&target, false)).unwrap());
    if let Err(e) = authorize_installed(plan, Some(&archive(&installed, false))) {
        panic!("a different-SAT, same-class installed Kernel must be admitted: {e:#}");
    }
}

#[test]
fn recover_admits_a_different_sat_target_in_the_same_family() {
    // `image::family` does not hash the SAT, and a hardware family spans several
    // SATs. recover gates on family + re-encode, never SAT, so a same-family,
    // different-SAT target must prepare. Regression guard against a SAT gate.
    let current = archive(&fixture_pair_sat(false, 1, b"SAT FFFEGENERAL 0000"), false);
    let other_sat = archive(&fixture_pair_sat(false, 0, b"SAT FFFDGENERAL 0000"), false);
    if let Err(e) = Plan::prepare(&current, &other_sat) {
        panic!("a same-family, different-SAT target must prepare: {e:#}");
    }
}

#[test]
fn be32_sum_zero_fails_closed_on_degenerate_bodies() {
    // Fail-closed guards: a degenerate decode (empty or non-4-aligned body) must
    // NOT read as a zero checksum, or the receiver gate would admit it.
    assert!(
        !be32_sum_zero(&[]),
        "empty body must not be a zero checksum"
    );
    assert!(
        !be32_sum_zero(&[0, 0, 0]),
        "a trailing partial word must fail"
    );
    assert!(
        !be32_sum_zero(&[0, 0, 0, 0, 1]),
        "a non-4-aligned body must fail"
    );
    // Positive control: a well-formed all-zero body is a valid zero checksum.
    assert!(be32_sum_zero(&[0, 0, 0, 0]));
}

#[test]
fn crossflash_links_follow_the_flash_gates() {
    // Crossflash links come from the flasher's own offline
    // decision: a different SAT with the same receiver class links both ways; a
    // different receiver class also links when the incoming Kernel receives Normal.
    use crate::crossflash::{links, Platform};
    let sat_a = archive(&fixture_pair_sat(false, 0, b"SAT FFFEGENERAL 0000"), false);
    let sat_b = archive(&fixture_pair_sat(false, 1, b"SAT FFFDGENERAL 0000"), false);
    let class_y = archive(
        &fixture_pair_class(false, 0, b"SAT FFFEGENERAL 0000", [0x400, 0x800]),
        false,
    );
    let found = links(Platform::Pioneer, &[&sat_a, &sat_b, &class_y]);
    assert!(
        found.contains(&(0, 1)) && found.contains(&(1, 0)),
        "{found:?}"
    );
    assert!(
        found.contains(&(0, 2)) && found.contains(&(2, 0)),
        "{found:?}"
    );
}
