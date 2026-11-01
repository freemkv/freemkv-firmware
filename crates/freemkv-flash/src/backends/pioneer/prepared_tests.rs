use super::*;
use pioneer_optical::receiver::PreparedUpdate;

const CONTROL_DESCRIPTOR_ADDRESS: u32 = 0x0041_0000;

#[test]
fn held_ud02_ud04_settings_are_prepared_by_the_normal_live_authorization_path() {
    let Ok(root) = std::env::var("PIONEER_SETTINGS_HOARD") else {
        return;
    };
    let root = std::path::Path::new(&root);
    let component = |kind: &str, sha: &str, directory: &str| {
        std::fs::read(root.join(directory).join(kind).join(format!("{sha}.enc"))).unwrap()
    };
    let source_dir = "dump/pioneer/sat/8410/ID84/1.00";
    let kernel = component(
        "kernel",
        "7e1104a2843825aea6d03bde6359d94254f3cea192e576450f3f94c4afcee824",
        source_dir,
    );
    let normal = component(
        "normal",
        "a37a4f222e2fa7e225f6451b30eb2e459f1933ab38c81a4d7967c10d77bc1373",
        source_dir,
    );
    let mut archive = tar::Builder::new(Vec::new());
    for (name, data) in [("kernel.enc", kernel), ("normal.enc", normal)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, data.as_slice())
            .unwrap();
    }
    let installed = archive.into_inner().unwrap();
    let target_kernel = component(
        "kernel",
        "36996326ae5eaa369ef34a8434514ca137b31a3f144af0955c2d12f4a8b2ea83",
        "oem/pioneer/sat/8A10/GENERAL/1.00",
    );
    let target_normal = component(
        "normal",
        "8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141",
        "oem/pioneer/sat/8A10/GENERAL/1.14",
    );
    let mut target_archive = tar::Builder::new(Vec::new());
    for (name, data) in [
        ("kernel.enc", &target_kernel),
        ("normal.enc", &target_normal),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        target_archive
            .append_data(&mut header, name, data.as_slice())
            .unwrap();
    }
    let native_ud04 = target_archive.into_inner().unwrap();
    assert_eq!(
        crate::crossflash::decide(
            crate::crossflash::Platform::Pioneer,
            &installed,
            &native_ud04
        )
        .status,
        crate::crossflash::CompatibilityStatus::Yes
    );
    assert_eq!(
        crate::crossflash::decide(
            crate::crossflash::Platform::Pioneer,
            &native_ud04,
            &installed
        )
        .status,
        crate::crossflash::CompatibilityStatus::HardNo
    );
    // Both paths prepare the same certified pair without any factory-SKU read.
    let current = recovery::Current::load(&installed).unwrap();
    recovery::Target::load(&native_ud04)
        .unwrap()
        .bind(&current, false)
        .unwrap();
    let authorized = authorize_installed(
        FlashPlan::new(ExecutePlan {
            kernel: Some(target_kernel.clone()),
            normal: target_normal.clone(),
            selection: FlashSelection::KernelAndNormal,
        }),
        Some(&installed),
    )
    .unwrap();
    let prepared: &Prepared = authorized.state().unwrap();
    let complete = prepared.complete.as_ref().unwrap();
    assert_eq!(
        complete.settings().adaptation_id(),
        Some("pioneer.ud02-to-ud04-1.14")
    );
    assert_eq!(
        complete.settings().requirements(),
        &[pioneer_optical::settings::adaptation::Requirement {
            parameter: 0x28f,
            value: 1
        }]
    );
    let kernel = Envelope::load(&target_kernel).unwrap();
    let normal = Envelope::load_with_kernel(complete.normal_transfer(), &kernel).unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(
        format!("{:x}", Sha256::digest(normal.image.as_slice())),
        "ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815"
    );
}

#[test]
fn reported_ud02_capture_prepares_flash_and_recovery_without_factory_identity() {
    let Ok(root) = std::env::var("PIONEER_UD02_REPORT_FIXTURES") else {
        return;
    };
    let root = std::path::Path::new(&root);
    let installed =
        std::fs::read(root.join("BDR-UD04_1.14_8A10_349da8b4.tar.preflash.backup.tar")).unwrap();
    let target = std::fs::read(root.join("BDR-UD04_1.14_8A10_349da8b4.tar")).unwrap();
    assert_eq!(
        crate::crossflash::decide(crate::crossflash::Platform::Pioneer, &installed, &target).status,
        crate::crossflash::CompatibilityStatus::Yes
    );
    let current = recovery::Current::load(&installed).unwrap();
    recovery::Target::load(&target)
        .unwrap()
        .bind(&current, false)
        .unwrap();
    let plan = FlashPlan::new(execute_plan(&target).unwrap());
    let authorized = authorize_installed(plan, Some(&installed)).unwrap();
    let prepared: &Prepared = authorized.state().unwrap();
    let complete = prepared.complete.as_ref().unwrap();
    assert_eq!(
        complete.settings().adaptation_id(),
        Some("pioneer.ud02-to-ud04-1.14")
    );
    assert_eq!(
        complete.settings().requirements(),
        &[pioneer_optical::settings::adaptation::Requirement {
            parameter: 0x28f,
            value: 1
        }]
    );
}

fn execute(dev: &mut dyn ScsiDevice, plan: &PreparedUpdate) -> Result<()> {
    crate::backends::pioneer::flash::execute_with_sleep(
        &mut crate::engine::gates::ungated_for_tests(dev),
        crate::backends::pioneer::flash::PreparedFlash::Complete(plan),
        pioneer_optical::receiver::ExecutionMode::Flash,
        &mut |_| {},
    )
    .map(|_| ())
}
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
    crate::kernel_handoff_fixture(&mut kernel);
    kernel[0x1000..0x1014].copy_from_slice(b"SAT FFFEGENERAL 0000");
    kernel[0x40..0x42].copy_from_slice(&[0xae, 0xfe]);
    kernel[0x46..0x48].copy_from_slice(&[0xae, 0xf0]);
    kernel[0x100..0x114].copy_from_slice(&[
        0x7a, 0x20, 0, 0, 1, 0, 0x47, 12, 0x7a, 0x20, 0, 0, 2, 0, 0x47, 4, 1, 0xf0, 0x65, 5,
    ]);
    // Forward-rotation decode loop the receiver reads after the XOR-skip branch;
    // without it pioneer-optical 0.15.0 returns UnknownRotation from Update::load.
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
    parameter: Option<u16>,
    parameter_reads: usize,
    bad_parameter_verification: bool,
    reject_parameter_read: bool,
    reject_parameter_write: bool,
    memory: Vec<u8>,
    normal_memory: Vec<u8>,
    normal_readback_reads: usize,
    corrupt_normal_after_finish: bool,
    initial_identity: (
        [u8; pioneer_optical::INQUIRY_LEN],
        [u8; pioneer_optical::IDENTITY_LEN],
    ),
    target_identity: (
        [u8; pioneer_optical::INQUIRY_LEN],
        [u8; pioneer_optical::IDENTITY_LEN],
    ),
    descriptor: Vec<u8>,
    kernel: Vec<u8>,
    normal_wire: Vec<u8>,
    updating: bool,
    wrong_target_revision: bool,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
    fail_at: Option<usize>,
    corrupt_after_finish: Option<usize>,
    finishes: usize,
    medium_checks: usize,
    insert_disc_after_first_pass: bool,
}
impl Drive {
    fn new(plan: &PreparedUpdate) -> Self {
        let mut inquiry = [0; pioneer_optical::INQUIRY_LEN];
        inquiry[0] = 5;
        inquiry[8..16].copy_from_slice(b"PIONEER ");
        inquiry[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
        inquiry[32..36].copy_from_slice(b"1.00");
        let mut vendor = [0; pioneer_optical::IDENTITY_LEN];
        vendor[16..24].copy_from_slice(b"SAT FFFE");
        vendor[24..32].copy_from_slice(b"GENERAL ");
        vendor[32..40].copy_from_slice(b"GENERAL ");
        Self {
            parameter: Some(0xffff),
            parameter_reads: 0,
            bad_parameter_verification: false,
            reject_parameter_read: false,
            reject_parameter_write: false,
            memory: plan.first_kernel_image().to_vec(),
            normal_memory: Vec::new(),
            normal_readback_reads: 0,
            corrupt_normal_after_finish: false,
            initial_identity: (inquiry, vendor),
            target_identity: (inquiry, vendor),
            descriptor: b"PIONEER TEST-NEW".to_vec(),
            kernel: Vec::new(),
            normal_wire: Vec::new(),
            updating: false,
            wrong_target_revision: false,
            writes: Vec::new(),
            fail_at: None,
            corrupt_after_finish: None,
            finishes: 0,
            medium_checks: 0,
            insert_disc_after_first_pass: false,
        }
    }
    fn with_firmware(mut self, current: &Update, target: &Update) -> Self {
        fn identity(
            update: &Update,
        ) -> (
            [u8; pioneer_optical::INQUIRY_LEN],
            [u8; pioneer_optical::IDENTITY_LEN],
        ) {
            let mut inquiry = [b' '; pioneer_optical::INQUIRY_LEN];
            inquiry[0] = 5;
            inquiry[8..16].copy_from_slice(b"PIONEER ");
            let info = update.normal().info();
            let product = info
                .model
                .strip_prefix("PIONEER ")
                .unwrap_or(&info.model)
                .as_bytes();
            assert!(product.len() <= 16);
            inquiry[16..16 + product.len()].copy_from_slice(product);
            inquiry[32..36].copy_from_slice(info.revision.as_bytes());
            let mut vendor = [b' '; pioneer_optical::IDENTITY_LEN];
            for (offset, field) in [
                (16, &info.hardware_version),
                (24, &update.kernel().info().kernel_version),
                (32, &info.kernel_version),
            ] {
                assert!(field.len() <= 8);
                vendor[offset..offset + field.len()].copy_from_slice(field.as_bytes());
            }
            (inquiry, vendor)
        }
        self.initial_identity = identity(current);
        self.target_identity = identity(target);
        self.memory = current.kernel().image.clone();
        self.descriptor = current.normal().image[..16].to_vec();
        self
    }
}
impl ScsiDevice for Drive {
    fn medium_status(&mut self) -> Result<crate::platform::MediumStatus> {
        self.medium_checks += 1;
        Ok(if self.insert_disc_after_first_pass && self.finishes > 0 {
            crate::platform::MediumStatus::DiscPresent
        } else {
            crate::platform::MediumStatus::ClosedEmpty
        })
    }

    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb == pioneer_optical::cdb::read_parameter_word(0x9f).unwrap() {
            self.parameter_reads += 1;
            if self.reject_parameter_read {
                bail!("A0 unsupported by mock drive");
            }
            let value = if self.bad_parameter_verification && self.parameter_reads == 2 {
                0xaaaa
            } else {
                self.parameter.expect("unexpected parameter read")
            };
            return Ok(value.to_be_bytes().to_vec());
        }
        if cdb == pioneer_optical::cdb::read_memory(CONTROL_DESCRIPTOR_ADDRESS, 16) {
            return Ok(self.descriptor.clone());
        }
        if cdb.len() == 10 && cdb[..3] == pioneer_optical::cdb::read_memory(0, 0)[..3] {
            let addr = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]);
            if addr >= 0x0041_0000 {
                self.normal_readback_reads += 1;
                let offset = (addr - 0x0041_0000) as usize;
                return Ok(self.normal_memory[offset..offset + len].to_vec());
            }
            let offset = (addr - pioneer_optical::image::KERNEL_BASE) as usize;
            return Ok(self.memory[offset..offset + len].to_vec());
        }
        let mut out = vec![0; len];
        let (inquiry, vendor) = if self.finishes == 0 {
            &self.initial_identity
        } else {
            &self.target_identity
        };
        if cdb[0] == 0x12 {
            let count = out.len().min(inquiry.len());
            out[..count].copy_from_slice(&inquiry[..count]);
            if self.updating {
                out[32..36].copy_from_slice(b"0000");
            } else if self.finishes > 0 && self.wrong_target_revision {
                out[32..36].copy_from_slice(b"9.99");
            }
        } else if cdb == pioneer_optical::cdb::vendor_identity() {
            let count = out.len().min(vendor.len());
            out[..count].copy_from_slice(&vendor[..count]);
            if self.updating {
                out[32..40].fill(b' ');
            }
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
        if cdb == pioneer_optical::cdb::write_parameter_word(0x9f).unwrap()
            && self.reject_parameter_write
        {
            bail!("A0 write unsupported by mock drive");
        }
        if self.fail_at == Some(self.writes.len()) {
            bail!("injected firmware write failure");
        }
        self.writes.push((cdb.to_vec(), data.to_vec()));
        if cdb == pioneer_optical::cdb::write_parameter_word(0x9f).unwrap() {
            assert!(self.parameter.is_some());
            self.parameter = Some(u16::from_be_bytes(data.try_into().unwrap()));
            return Ok(());
        }
        if cdb == pioneer_optical::cdb::enter_update() {
            self.kernel.clear();
            self.normal_wire.clear();
            self.updating = true;
        }
        if cdb[..3] == [0x3b, 0x07, 0xfe] {
            self.kernel.extend_from_slice(data);
        }
        if cdb[..3] == [0x3b, 0x07, 0xf0] {
            self.normal_wire.extend_from_slice(data);
        }
        if cdb == pioneer_optical::cdb::finish() {
            self.updating = false;
            let kernel = Envelope::load(&self.kernel)?;
            self.normal_memory = Envelope::load_with_kernel(&self.normal_wire, &kernel)?.image;
            if self.corrupt_normal_after_finish {
                self.normal_memory[0x100] ^= 1;
            }
            self.descriptor = self.normal_memory[..16].to_vec();
            self.memory = kernel.image;
            self.finishes += 1;
            if self.corrupt_after_finish == Some(self.finishes) {
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
    drive.corrupt_after_finish = Some(1);
    let error = execute(&mut drive, &plan).unwrap_err();
    assert!(format!("{error:#}").contains("Initial Kernel readback differs"));
    assert!(format!("{error:#}").contains("Initial Kernel readback differs"));
    assert_eq!(drive.finishes, 1);
}
#[test]
fn prepared_flash_requires_matching_live_receiver_before_entry() {
    let plan = plan(true);
    let mut drive = Drive::new(&plan);
    drive.descriptor[9] ^= 1;
    let messages = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = messages.clone();
    let error = crate::output::capture(
        move |line| sink.borrow_mut().push(line),
        || execute(&mut drive, &plan),
    )
    .unwrap_err();
    assert!(!messages
        .borrow()
        .iter()
        .any(|line| line.contains("EXECUTING")));
    assert!(format!("{error:#}").contains("live receiver descriptor does not match"));
    assert!(drive.writes.is_empty());
}
#[test]
fn prepared_write_failure_propagates_without_finish() {
    let plan = plan(true);
    let mut drive = Drive::new(&plan);
    drive.fail_at = Some(1);
    let error = execute(&mut drive, &plan).unwrap_err();
    assert!(format!("{error:#}").contains("injected firmware write failure"));
    assert_eq!(drive.writes.len(), 1);
    assert_eq!(drive.writes[0].0, pioneer_optical::cdb::enter_update());
}

#[test]
fn flash_stops_before_firmware_when_a0_read_is_unsupported() {
    let plan = plan(false);
    let mut drive = Drive::new(&plan);
    drive.reject_parameter_read = true;
    let error = execute(&mut drive, &plan).unwrap_err();
    assert!(format!("{error:#}").contains("A0 startup parameter read failed"));
    assert!(format!("{error:#}").contains("no firmware was written"));
    assert!(drive.writes.is_empty());
    assert_eq!(drive.finishes, 0);
}

#[test]
fn flash_stops_before_firmware_when_a0_write_is_unsupported() {
    let plan = plan(false);
    let mut drive = Drive::new(&plan);
    drive.parameter = Some(0xff01);
    drive.reject_parameter_write = true;
    let error = execute(&mut drive, &plan).unwrap_err();
    assert!(format!("{error:#}").contains("A0 startup parameter write or verification failed"));
    assert!(format!("{error:#}").contains("no firmware was written"));
    assert!(drive.writes.is_empty());
    assert_eq!(drive.finishes, 0);
}
#[test]
fn restoration_success_requires_pristine_readback_and_preserves_normal() {
    let plan = plan(true);
    for corrupt in [false, true] {
        let mut drive = Drive::new(&plan);
        drive.corrupt_after_finish = corrupt.then_some(2);
        let result = execute(&mut drive, &plan);
        if corrupt {
            assert!(format!("{:#}", result.unwrap_err()).contains("Kernel readback differs"));
        } else {
            result.unwrap();
            assert_eq!(drive.memory, plan.final_kernel_image());
        }
        assert_eq!(drive.kernel, plan.final_stage_kernel_transfer().unwrap());
        let normal: Vec<_> = drive
            .writes
            .iter()
            .filter(|(c, _)| c[..3] == [0x3b, 0x07, 0xf0])
            .flat_map(|(_, d)| d.iter().copied())
            .collect();
        assert_eq!(normal, plan.normal_transfer().repeat(2));
    }
}
#[test]
fn unpatched_update_reports_target_startup_and_readback_limits() {
    let plan = plan(false);
    let mut drive = Drive::new(&plan);
    let outcome = crate::backends::pioneer::flash::execute_with_sleep(
        &mut crate::engine::gates::ungated_for_tests(&mut drive),
        crate::backends::pioneer::flash::PreparedFlash::Complete(&plan),
        pioneer_optical::receiver::ExecutionMode::Flash,
        &mut |_| {},
    )
    .unwrap();
    let crate::backend::UpdateOutcome::Completed(evidence) = outcome else {
        panic!("execution only planned")
    };
    assert!(evidence.target_started);
    assert_eq!(evidence.verified_regions, ["Kernel"]);
    assert_eq!(evidence.unverified_regions, ["Normal"]);
    assert!(!evidence.temporary_firmware);
    assert_eq!(drive.finishes, 1);
}

fn pair_with_normal_readback(marker: u8) -> Update {
    let original = pair(false, marker);
    let mut kernel = original.kernel().image.clone();
    // H8 descriptor and extent instructions establish the Normal readback surface.
    for (at, hex) in [
        (0x6000, "18 bb 1a 91 0c b9 78 10 6a 2a 00 41 00 00 78 10 6a 28 00 40 62 00 1c 8a 47 04 5e 40 10 20 0a 0b ab 10 45 de"),
        (0x6100, "1a a2 7a 01 00 40 00 00 01 00 6b 23 00 41 00 14 7a 13 00 41 00 00 40 06 01 00 6d 10 0a 82 1f b1 46 f6"),
    ] {
        let bytes: Vec<u8> = hex.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap()).collect();
        kernel[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    kernel[0x6200..0x6210].copy_from_slice(&original.normal().image[..16]);
    balance(&mut kernel);
    let update = Update::load(
        &original.kernel().repack(&kernel).unwrap(),
        original.normal_transfer(),
    )
    .unwrap();
    assert!(update.kernel().normal_layout().is_ok());
    update
}

#[test]
fn different_running_revision_does_not_skip_normal_readback() {
    let installed = pair_with_normal_readback(1);
    let plan = Receiver::from_installed(&installed)
        .unwrap()
        .prepare(pair_with_normal_readback(0))
        .unwrap();
    for corrupt in [false, true] {
        let mut drive = Drive::new(&plan);
        drive.wrong_target_revision = true;
        drive.corrupt_normal_after_finish = corrupt;
        let result = crate::backends::pioneer::flash::execute_with_sleep(
            &mut crate::engine::gates::ungated_for_tests(&mut drive),
            crate::backends::pioneer::flash::PreparedFlash::Complete(&plan),
            pioneer_optical::receiver::ExecutionMode::Flash,
            &mut |_| {},
        );
        assert!(
            drive.normal_readback_reads > 0,
            "different revision must still read Normal"
        );
        if corrupt {
            let error = result.unwrap_err();
            assert!(
                format!("{error:#}").contains("Normal readback differs"),
                "{error:#}"
            );
        } else {
            assert!(result.unwrap().fully_verified());
        }
        assert_eq!(drive.finishes, 1);
    }
}

#[test]
fn newly_inserted_disc_blocks_restoration_and_explains_temporary_kernel() {
    let plan = plan(true);
    let mut drive = Drive::new(&plan);
    drive.insert_disc_after_first_pass = true;
    let error = execute(&mut drive, &plan).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("a disc is loaded"));
    assert!(message.contains("temporary Kernel may remain installed"));
    // Before migration, immediately before entry, and before restoration.
    assert_eq!(drive.medium_checks, 3);
    assert_eq!(drive.finishes, 1);
    assert_eq!(
        drive
            .writes
            .iter()
            .filter(|(cdb, _)| cdb == &pioneer_optical::cdb::enter_update())
            .count(),
        1
    );
}

#[test]
fn missing_descriptor_is_reported_before_update_entry() {
    let plan = plan(false);
    let mut drive = Drive::new(&plan);
    drive.descriptor.clear();
    let error = execute(&mut drive, &plan).unwrap_err();
    assert!(format!("{error:#}").contains("receiver descriptor read"));
    assert!(drive.writes.is_empty());
}

#[test]
#[ignore = "requires supplied S12JX and WX1DM packages; mock device only"]
fn real_package_flash_migrates_startup_word_in_both_directions() {
    let load = |key: &str| {
        let bytes = std::fs::read(std::env::var(key).unwrap()).unwrap();
        let (kernel, normal) = classify_flash_input(&bytes).unwrap();
        super::normal_prepare::load_pair(&kernel.unwrap(), &normal.unwrap()).unwrap()
    };
    let sj = load("PIONEER_STARTUP_ORIGINAL_PACKAGE");
    let wx = load("PIONEER_STARTUP_WX_PACKAGE");
    for (source, target, original, required) in
        [(&sj, &wx, 0xffff, 0xfe24), (&wx, &sj, 0xfe24, 0xffff)]
    {
        let plan = Receiver::from_installed(source)
            .unwrap()
            .prepare(target.clone())
            .unwrap();
        assert_eq!(plan.startup_setting().unwrap().value, required);
        for scenario in 0..4 {
            let mut drive = Drive::new(&plan).with_firmware(source, target);
            drive.parameter = Some(original);
            drive.bad_parameter_verification = scenario == 1;
            drive.fail_at = (scenario == 2).then_some(1);
            if scenario == 3 {
                drive.descriptor[0] ^= 1;
            }
            let result = execute(&mut drive, &plan);
            let firmware_writes = drive.writes.iter().filter(|(c, _)| c[2] != 0xa0).count();
            match scenario {
                0 => {
                    result.unwrap();
                    assert_eq!(drive.parameter, Some(required));
                    assert_eq!(
                        drive.writes[0],
                        (
                            pioneer_optical::cdb::write_parameter_word(0x9f)
                                .unwrap()
                                .to_vec(),
                            required.to_be_bytes().to_vec()
                        )
                    );
                    assert_eq!(drive.finishes, 1);
                    assert_eq!(drive.memory, plan.final_kernel_image());
                }
                1 => {
                    assert!(result.is_err());
                    assert_eq!(drive.parameter, Some(original));
                    assert_eq!(drive.writes.len(), 2);
                    assert_eq!(firmware_writes, 0);
                }
                2 => {
                    assert!(result.is_err());
                    assert_eq!(drive.parameter, Some(required));
                    assert_eq!(drive.writes.len(), 1);
                    assert_eq!(firmware_writes, 0);
                }
                3 => {
                    assert!(result.is_err());
                    assert_eq!(drive.parameter, Some(original));
                    assert!(drive.writes.is_empty());
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
#[ignore = "requires supplied BDR-207M 1.60 backup and BDR-PR1ML 1.30 package"]
fn real_207m_to_pr1ml_flash_uses_a0_without_code_surface_match() {
    let load = |key: &str| {
        let bytes = std::fs::read(std::env::var(key).unwrap()).unwrap();
        let (kernel, normal) = classify_flash_input(&bytes).unwrap();
        super::normal_prepare::load_pair(&kernel.unwrap(), &normal.unwrap()).unwrap()
    };
    let current = load("PIONEER_RECOVERY_CURRENT");
    let target = load("PIONEER_RECOVERY_TARGET");
    assert!(pioneer_optical::startup::surface::discover(&current.normal().image).is_none());
    let plan = Receiver::from_installed(&current)
        .unwrap()
        .prepare(target.clone())
        .unwrap();
    let setting = plan.startup_setting().unwrap();
    assert_eq!((setting.parameter, setting.value), (0x9f, 0xff01));

    let mut drive = Drive::new(&plan).with_firmware(&current, &target);
    drive.parameter = Some(0xffff);
    execute(&mut drive, &plan).unwrap();
    assert_eq!(drive.parameter, Some(0xff01));
    assert_eq!(
        drive.writes[0],
        (
            pioneer_optical::cdb::write_parameter_word(0x9f)
                .unwrap()
                .to_vec(),
            0xff01u16.to_be_bytes().to_vec()
        )
    );
    assert_eq!(drive.memory, plan.final_kernel_image());
}
