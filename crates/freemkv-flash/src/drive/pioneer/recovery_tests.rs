use super::*;
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
    let mut kernel = vec![0; 0x10000];
    kernel[0x1000..0x1014].copy_from_slice(b"SAT FFFEGENERAL 0000");
    kernel[0x40..0x42].copy_from_slice(&[0xae, 0xfe]);
    kernel[0x46..0x48].copy_from_slice(&[0xae, 0xf0]);
    kernel[0x100..0x114].copy_from_slice(&[
        0x7a, 0x20, 0, 0, 1, 0, 0x47, 12, 0x7a, 0x20, 0, 0, 2, 0, 0x47, 4, 1, 0xf0, 0x65, 5,
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

#[derive(Default)]
struct Drive {
    updating: bool,
    finished: bool,
    stuck: bool,
    fail_write: Option<usize>,
    attempts: usize,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
}
impl ScsiDevice for Drive {
    fn describe(&self) -> String {
        "Recovery test".into()
    }
    fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; len];
        let kernel = (self.updating && !self.finished) || self.stuck;
        if command == cdb::inquiry(len as u8) {
            bytes[0] = 5;
            bytes[8..16].copy_from_slice(b"PIONEER ");
            bytes[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
            bytes[32..36].copy_from_slice(if kernel { b"0000" } else { b"1.00" });
        } else if command == cdb::vendor_identity() {
            bytes[16..24].copy_from_slice(b"SAT FFFE");
            bytes[24..32].copy_from_slice(b"GENERAL ");
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
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        panic!("lenient write forbidden")
    }
    fn command_out_strict(&mut self, command: &[u8], bytes: &[u8]) -> Result<()> {
        self.attempts += 1;
        if self.fail_write == Some(self.attempts) {
            bail!("injected write failure");
        }
        self.writes.push((command.to_vec(), bytes.to_vec()));
        if command == cdb::finish() && self.writes.iter().any(|(c, _)| c[2] == 0xf0) {
            self.finished = true;
        }
        Ok(())
    }
}
fn recovery_plan() -> Plan {
    Plan::from_updates(fixture_pair(false, 1), fixture_pair(false, 0)).unwrap()
}

#[test]
fn kernel_recovery_writes_both_components_without_entry_or_firmware_reads() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        ..Default::default()
    };
    plan.run(&mut drive, &mut |_| {}).unwrap();
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
        (0xfe, plan.target.kernel_transfer()),
        (0xf0, plan.target.normal_transfer()),
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
fn normal_recovery_enters_first_and_uses_supplied_receiver_control() {
    let plan = recovery_plan();
    let mut drive = Drive::default();
    plan.run(&mut drive, &mut |_| {}).unwrap();
    assert_eq!(
        drive.writes[0],
        (cdb::enter_update().to_vec(), plan.control.to_vec())
    );
    assert_eq!(drive.writes.last().unwrap().1, plan.control);
}
#[test]
fn failed_write_stops_without_retry_or_finish() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        fail_write: Some(2),
        ..Default::default()
    };
    assert!(plan.run(&mut drive, &mut |_| {}).is_err());
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
    let error = plan.run(&mut drive, &mut |_| {}).unwrap_err();
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
    let plan = Plan::prepare(
        &std::fs::read(current).unwrap(),
        &std::fs::read(target).unwrap(),
    )
    .unwrap();
    let mut drive = Drive {
        updating: true,
        ..Default::default()
    };
    plan.run(&mut drive, &mut |_| {}).unwrap();
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
    let error = recovery_plan().run(&mut drive, &mut |_| {}).unwrap_err();
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
fn unsigned_backup_is_valid_current_evidence_but_not_a_signed_target() {
    let update = fixture_pair(false, 1);
    let unsigned = archive(&update, true);
    let signed = archive(&update, false);
    assert!(Plan::prepare(&unsigned, &signed).is_ok());
    assert!(Plan::prepare(&signed, &unsigned).is_err());
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
        let error = plan.run(&mut drive, &mut |_| {}).unwrap_err();
        assert!(
            error.to_string().contains("No firmware written")
                || error.to_string().contains("no firmware written")
        );
        assert_eq!(drive.vendor_reads, 0);
        assert_eq!(drive.writes, 0);
    }
}

#[test]
fn unsupported_pioneer_dialect_fails_before_update_entry() {
    let mut inquiry = vec![0; pioneer_optical::INQUIRY_LEN];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"UNKNOWN RECEIVER");
    let mut drive = UnsupportedDrive {
        inquiry,
        vendor_reads: 0,
        writes: 0,
    };
    let error = recovery_plan().run(&mut drive, &mut |_| {}).unwrap_err();
    assert!(error.to_string().contains("update dialect"));
    assert_eq!(drive.vendor_reads, 1);
    assert_eq!(drive.writes, 0);
}
