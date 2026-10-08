use super::*;
use pioneer_optical::envelope::{
    builder::{encode_encrypted_pair, BuildInputs, KernelBuild, NormalSignature},
    signature::SigningKey,
    Envelope, Update,
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
pub(super) fn pair(gated: bool, marker: u8) -> Update {
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
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, 4, 0x46, 0x4e,
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
fn plan(restore: bool) -> PreparedUpdate {
    let installed = pair(restore, 1);
    Receiver::from_installed(&installed)
        .unwrap()
        .prepare(pair(false, 0))
        .unwrap()
}

struct Drive {
    memory: Vec<u8>,
    descriptor: Vec<u8>,
    kernel: Vec<u8>,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
    fail_at: Option<usize>,
    corrupt_after_finish: bool,
}
impl Drive {
    fn new(plan: &PreparedUpdate) -> Self {
        Self {
            memory: plan.first_kernel_image().to_vec(),
            descriptor: b"PIONEER TEST-NEW".to_vec(),
            kernel: Vec::new(),
            writes: Vec::new(),
            fail_at: None,
            corrupt_after_finish: false,
        }
    }
}
impl ScsiDevice for Drive {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb == pioneer_optical::cdb::read_memory(CONTROL_DESCRIPTOR_ADDRESS, 16) {
            return Ok(self.descriptor.clone());
        }
        if cdb.len() == 10 && cdb[..3] == pioneer_optical::cdb::read_memory(0, 0)[..3] {
            let addr = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]);
            let offset = (addr - pioneer_optical::image::KERNEL_BASE) as usize;
            return Ok(self.memory[offset..offset + len].to_vec());
        }
        let mut out = vec![0; len];
        if cdb[0] == 0x12 {
            out[8..16].copy_from_slice(b"PIONEER ");
            out[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
            out[32..36].copy_from_slice(b"000 ");
        }
        Ok(out)
    }
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        if cdb == pioneer_optical::cdb::knock() && data.is_empty() {
            return Ok(());
        }
        bail!("unexpected lenient write")
    }
    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        if self.fail_at == Some(self.writes.len()) {
            bail!("injected restoration write failure");
        }
        self.writes.push((cdb.to_vec(), data.to_vec()));
        if cdb[..3] == [0x3b, 0x07, 0xfe] {
            self.kernel.extend_from_slice(data);
        }
        if cdb == pioneer_optical::cdb::finish() {
            self.memory = Envelope::load(&self.kernel).unwrap().image;
            if self.corrupt_after_finish {
                self.memory[0] ^= 1;
            }
        }
        Ok(())
    }
    fn describe(&self) -> String {
        "synthetic receiver".into()
    }
}

#[test]
fn first_pass_readback_failure_prevents_any_restore_write() {
    let plan = plan(true);
    let mut drive = Drive::new(&plan);
    drive.memory[0] ^= 1;
    let error = finish_prepared_update(&mut drive, &plan, false, false).unwrap_err();
    assert!(format!("{error:#}").contains("first-pass Kernel readback"));
    assert!(format!("{error:#}").contains("resident Kernel readback differs"));
    assert!(drive.writes.is_empty());
}
#[test]
fn restore_requires_matching_live_receiver_before_entry() {
    let plan = plan(true);
    let mut drive = Drive::new(&plan);
    drive.descriptor[9] ^= 1;
    let error = finish_prepared_update(&mut drive, &plan, false, false).unwrap_err();
    assert_eq!(
        error.downcast_ref::<pioneer_optical::receiver::Error>(),
        Some(&pioneer_optical::receiver::Error::DescriptorMismatch)
    );
    assert!(drive.writes.is_empty());
}
#[test]
fn restoration_write_failure_propagates_without_finish() {
    let plan = plan(true);
    let mut drive = Drive::new(&plan);
    drive.fail_at = Some(1);
    let error = finish_prepared_update(&mut drive, &plan, false, false).unwrap_err();
    assert!(format!("{error:#}").contains("injected restoration write failure"));
    assert_eq!(drive.writes.len(), 1);
    assert_eq!(drive.writes[0].0, pioneer_optical::cdb::enter_update());
}
#[test]
fn restoration_success_requires_pristine_readback_and_preserves_normal() {
    let plan = plan(true);
    for corrupt in [false, true] {
        let mut drive = Drive::new(&plan);
        drive.corrupt_after_finish = corrupt;
        let result = finish_prepared_update(&mut drive, &plan, false, false);
        if corrupt {
            assert!(format!("{:#}", result.unwrap_err()).contains("readback did not verify"));
        } else {
            result.unwrap();
            assert_eq!(drive.memory, plan.final_kernel_image());
        }
        assert_eq!(drive.kernel, plan.restoration_kernel_transfer().unwrap());
        let normal: Vec<_> = drive
            .writes
            .iter()
            .filter(|(c, _)| c[..3] == [0x3b, 0x07, 0xf0])
            .flat_map(|(_, d)| d.iter().copied())
            .collect();
        assert_eq!(normal, plan.normal_transfer());
    }
}
#[test]
fn unpatched_update_only_verifies_without_an_extra_session() {
    let plan = plan(false);
    let mut drive = Drive::new(&plan);
    finish_prepared_update(&mut drive, &plan, false, false).unwrap();
    assert!(drive.writes.is_empty());
}
