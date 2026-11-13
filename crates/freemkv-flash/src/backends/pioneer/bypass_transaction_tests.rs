//! Startup word lifecycle through Flash/Recovery, including Recovery's explicit
//! family override. The live word is never a prerequisite: an installed fixed
//! gate with the target's value proves it (nothing read or written); otherwise
//! Flash sets the target's word, which Recovery never does.
use super::*;

const ORIGINAL: u16 = 0xff01;
const TARGET: u16 = 0xfe24;

fn startup_pair(value: u16) -> Update {
    let original = pair(false, 1);
    let mut normal = original.normal().image.clone();
    // Native 009F comparison and complete loader-rejection wrapper. The call
    // binds to the matrix fixture's Normal-resident parameter reader.
    normal[0x600..0x614].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
        0x41, 7, 0x80,
    ]);
    normal[0x60a..0x60c].copy_from_slice(&value.to_be_bytes());
    normal[0x780..0x786].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    balance(&mut normal);
    let mut transfer = original.normal().repack(&normal).unwrap();
    let mut scalar = [0; 20];
    scalar[19] = 5;
    SigningKey::from_bytes(scalar)
        .unwrap()
        .sign_normal(&mut transfer)
        .unwrap();
    Update::load(original.kernel_transfer(), &transfer).unwrap()
}

fn archive(update: &Update, normal_only: bool) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("kernel.enc", update.kernel_transfer()),
        ("normal.enc", update.normal_transfer()),
    ] {
        if normal_only && name == "kernel.enc" {
            continue;
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes).unwrap();
    }
    tar.into_inner().unwrap()
}

fn unchanged_comparison_plan(bypass: bool, installed: Update) -> PreparedUpdate {
    let target = startup_pair(ORIGINAL);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let plan = if bypass {
        receiver.prepare_without_family_check(target.clone())
    } else {
        receiver.prepare(target.clone())
    }
    .unwrap();
    assert!(plan.settings().required_words().is_empty());
    // No comparison operand or checksum is rewritten.
    assert_eq!(
        plan.stages().last().unwrap().normal_image(),
        target.normal().image
    );
    assert_eq!(
        Envelope::load_with_kernel(plan.normal_transfer(), target.kernel())
            .unwrap()
            .image,
        target.normal().image
    );
    plan
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Read,
    ShortRead,
    Mismatch,
    Entry,
    KernelTransfer,
    NormalTransfer,
    Finish,
    KernelReadback,
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    ReadParameter,
    FirmwareCommand(Vec<u8>),
}

struct ObservedDrive {
    inner: Drive,
    fault: Fault,
    events: Vec<Event>,
}

impl ObservedDrive {
    fn new(plan: &PreparedUpdate, fault: Fault) -> Self {
        let mut inner = Drive::new(plan);
        inner.parameter = Some(if fault == Fault::Mismatch {
            TARGET
        } else {
            ORIGINAL
        });
        inner.corrupt_after_finish = (fault == Fault::KernelReadback).then_some(1);
        Self {
            inner,
            fault,
            events: Vec::new(),
        }
    }
    fn firmware_attempts(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event, Event::FirmwareCommand(_)))
            .count()
    }
}

impl ScsiDevice for ObservedDrive {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn medium_status(&mut self) -> Result<crate::platform::MediumStatus> {
        self.inner.medium_status()
    }
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb.get(2) == Some(&0xa0) {
            assert_eq!(cdb, [0x3c, 0x02, 0xa0, 0, 0x01, 0x3e, 0, 0, 2, 0]);
            self.events.push(Event::ReadParameter);
            if self.fault == Fault::Read {
                bail!("injected parameter read failure");
            }
            if self.fault == Fault::ShortRead {
                return Ok(vec![0xff]);
            }
        }
        self.inner.command_in(cdb, len)
    }
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        assert_eq!(cdb, [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]);
        self.inner.command_out(cdb, data)
    }
    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        assert_ne!(
            cdb.get(2),
            Some(&0xa0),
            "persistent parameter write is forbidden"
        );
        self.events.push(Event::FirmwareCommand(cdb.to_vec()));
        let reject = match self.fault {
            Fault::Entry => cdb == pioneer_optical::cdb::enter_update(),
            Fault::KernelTransfer => cdb[..3] == [0x3b, 0x07, 0xfe],
            Fault::NormalTransfer => cdb[..3] == [0x3b, 0x07, 0xf0],
            Fault::Finish => cdb == pioneer_optical::cdb::finish(),
            _ => false,
        };
        if reject {
            bail!("injected firmware command failure");
        }
        self.inner.command_out_strict(cdb, data)
    }
}

fn execute_mode(
    drive: &mut ObservedDrive,
    plan: &PreparedUpdate,
    mode: pioneer_optical::drive::ExecutionMode,
) -> Result<()> {
    super::super::flash::execute_with_sleep(
        &mut crate::engine::gates::ungated_for_tests(drive),
        super::super::flash::PreparedFlash::Complete(plan),
        mode,
        &mut |_| {},
    )
    .map(|_| ())
}

#[test]
fn differing_startup_words_are_set_by_the_flash_transaction() {
    use crate::backend::{FlashFacet, ReadDevice, RecoveryFacet, RecoveryTarget};
    use crate::crossflash::{CompatibilityStatus, RouteStatus};
    use crate::platform::MockScsiDevice;
    use pioneer_optical::prepare::SettingEffect as Effect;
    for (source_value, target_value) in [(ORIGINAL, TARGET), (TARGET, ORIGINAL)] {
        let installed = archive(&startup_pair(source_value), false);
        let target_update = startup_pair(target_value);
        let target = archive(&target_update, false);

        // Preparation performs no device I/O and plans the target's own word.
        let mut flash = MockScsiDevice::new();
        let plan = FlashPlan::new(execute_plan(&target).unwrap());
        let saved = crate::engine::gates::saved_for_tests(installed.clone());
        Pioneer::new()
            .authorize(
                &mut ReadDevice::without_unlocks(&mut flash),
                plan,
                Some(&saved),
            )
            .expect("a differing fixed startup word is corrected on the drive");
        assert!(flash.reads.is_empty() && flash.writes.is_empty());
        let authorized = authorize_installed(
            FlashPlan::new(execute_plan(&target).unwrap()),
            Some(&installed),
        )
        .unwrap();
        let prepared: &Prepared = authorized.state().unwrap();
        let settings = match (&prepared.complete, &prepared.normal) {
            (Some(complete), None) => complete.stages()[0].settings(),
            (None, Some(normal)) => normal.settings(),
            _ => panic!("incomplete plan"),
        };
        assert!(settings.entries().iter().any(|entry| entry.effect()
            == Effect::ParameterWord {
                parameter: 0x9f,
                value: target_value,
                explicit: true,
            }));

        for bypass in [false, true] {
            let mut recovery = MockScsiDevice::new();
            let current = RecoveryTarget::new(
                "test".into(),
                Some(recovery::Current::load(&installed).unwrap()),
            );
            Pioneer::new()
                .prepare(
                    &mut ReadDevice::without_unlocks(&mut recovery),
                    &current,
                    None,
                    &target,
                    bypass,
                )
                .expect("Recovery plans the same word write");
            assert!(recovery.reads.is_empty() && recovery.writes.is_empty());
        }

        for normal_only in [false, true] {
            let target = archive(&target_update, normal_only);
            let decision = crate::crossflash::decide(
                crate::backend::registry::PIONEER_PLATFORM,
                &installed,
                &target,
            );
            assert_eq!(decision.status, CompatibilityStatus::Yes, "{decision:?}");
            assert!(decision
                .routes
                .iter()
                .all(|route| route.status == RouteStatus::Allowed));
            crate::crossflash::admits(
                crate::backend::registry::PIONEER_PLATFORM,
                &installed,
                &target,
            )
            .unwrap();
        }
    }
}

/// The installed fixed gate requires the target's word, so the drive holds it:
/// nothing is read or written, whatever a probe would have returned.
fn proven_plan(bypass: bool) -> PreparedUpdate {
    let plan = unchanged_comparison_plan(bypass, startup_pair(ORIGINAL));
    assert!(plan.startup_setting().is_none());
    assert!(plan.settings().entries().is_empty());
    assert!(plan.settings().word_writes().is_empty());
    plan
}

#[test]
fn proven_startup_word_is_neither_read_nor_written_in_flash_and_recovery() {
    use pioneer_optical::drive::ExecutionMode::{Flash, Recovery};
    for (bypass, mode) in [(false, Flash), (false, Recovery), (true, Recovery)] {
        let plan = proven_plan(bypass);
        for fault in [Fault::None, Fault::Read, Fault::ShortRead, Fault::Mismatch] {
            let mut drive = ObservedDrive::new(&plan, fault);
            let original = drive.inner.parameter;
            execute_mode(&mut drive, &plan, mode).unwrap();
            assert!(!drive.events.contains(&Event::ReadParameter), "{fault:?}");
            assert_eq!(
                drive.events[0],
                Event::FirmwareCommand(pioneer_optical::cdb::enter_update().to_vec())
            );
            assert_eq!(drive.inner.parameter_reads, 0);
            assert_eq!(drive.inner.parameter, original);
            assert_eq!(drive.inner.finishes, 1);
            assert_eq!(drive.inner.memory, plan.final_kernel_image());
            assert_eq!(
                drive.inner.normal_memory,
                plan.stages().last().unwrap().normal_image()
            );
        }
    }
}

#[test]
fn firmware_failures_never_write_persistent_startup_parameters() {
    let plan = proven_plan(true);
    for fault in [
        Fault::Entry,
        Fault::KernelTransfer,
        Fault::NormalTransfer,
        Fault::Finish,
        Fault::KernelReadback,
    ] {
        let mut drive = ObservedDrive::new(&plan, fault);
        execute_mode(
            &mut drive,
            &plan,
            pioneer_optical::drive::ExecutionMode::Recovery,
        )
        .unwrap_err();
        assert!(drive.firmware_attempts() > 0, "{fault:?}");
        assert_eq!(drive.inner.parameter, Some(ORIGINAL), "{fault:?}");
        assert_eq!(drive.inner.parameter_reads, 0);
    }
}

#[test]
fn unresolved_source_sets_the_target_word_and_recovery_refuses_before_firmware() {
    use pioneer_optical::drive::ExecutionMode::Recovery;
    for bypass in [false, true] {
        let installed = pair(false, 1);
        assert!(matches!(
            pioneer_optical::startup::bound_selection(&installed.normal().image),
            pioneer_optical::image::layout::Observation::Unresolved(_)
        ));
        let plan = unchanged_comparison_plan(bypass, installed);
        let writes = plan.settings().word_writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].filter, "startup-prerequisite");
        assert_eq!(
            (writes[0].word.parameter, writes[0].word.value),
            (0x9f, ORIGINAL)
        );
        // Recovery never writes the word; it refuses before any device command.
        let mut drive = ObservedDrive::new(&plan, Fault::None);
        let error = execute_mode(&mut drive, &plan, Recovery).unwrap_err();
        assert!(format!("{error:#}").contains("Recovery"), "{error:#}");
        assert!(drive.events.is_empty());
        assert_eq!(drive.inner.parameter, Some(ORIGINAL));
    }
}

#[test]
fn offline_routes_admit_a_proven_startup_word_without_requirements() {
    use crate::crossflash::{decide, CompatibilityStatus, RouteStatus};
    let installed = archive(&startup_pair(ORIGINAL), false);
    for normal_only in [false, true] {
        let target = archive(&startup_pair(ORIGINAL), normal_only);
        let decision = decide(
            crate::backend::registry::PIONEER_PLATFORM,
            &installed,
            &target,
        );
        assert_eq!(decision.status, CompatibilityStatus::Yes, "{decision:?}");
        assert_eq!(decision.routes.len(), 1);
        assert_eq!(decision.routes[0].status, RouteStatus::Allowed);
        assert!(decision.routes[0].requirements.is_empty());
        crate::crossflash::admits(
            crate::backend::registry::PIONEER_PLATFORM,
            &installed,
            &target,
        )
        .unwrap();
    }
}
