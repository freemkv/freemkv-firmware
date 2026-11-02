//! Fault coverage for Recovery's explicit compatibility override. These use the
//! existing wire-level drive fixture, with compatible bank contracts and a
//! separately recognized target startup-word requirement.
use super::*;

const ORIGINAL: u16 = 0xff01;
const REQUIRED: u16 = 0xfe24;

fn override_plan() -> PreparedUpdate {
    let installed = pair(false, 1);
    let mut normal = installed.normal().image.clone();
    // Native 009F comparison, with a recognized loader-rejection wrapper.
    normal[0x600..0x614].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 1, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e, 0x41,
        7, 0x80,
    ]);
    normal[0x780..0x786].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    balance(&mut normal);
    let mut transfer = installed.normal().repack(&normal).unwrap();
    let mut scalar = [0; 20];
    scalar[19] = 5;
    SigningKey::from_bytes(scalar)
        .unwrap()
        .sign_normal(&mut transfer)
        .unwrap();
    let target = Update::load(installed.kernel_transfer(), &transfer).unwrap();
    let receiver = Receiver::from_installed(&installed).unwrap();
    assert!(receiver.prepare(target.clone()).is_ok());
    let plan = receiver.prepare_without_family_check(target).unwrap();
    let setting = plan.startup_setting().unwrap();
    assert_eq!(
        (setting.parameter, setting.value, setting.explicit),
        (0x9f, REQUIRED, true)
    );
    assert!(plan.settings().adaptation_id().is_none());
    assert!(plan.settings().requirements().is_empty());
    plan
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    InitialRead,
    InitialShortRead,
    ChangeWriteRejected,
    ChangeWriteAcceptedThenError,
    VerifyRead,
    VerifyShortRead,
    VerifyMismatch,
    Entry,
    KernelTransfer,
    NormalTransfer,
    Finish,
    KernelReadback,
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    ReadParameter,
    WriteParameter(u16),
    FirmwareCommand(Vec<u8>),
}

struct ObservedDrive {
    inner: Drive,
    fault: Fault,
    events: Vec<Event>,
    reads: usize,
    parameter_writes: usize,
}

impl ObservedDrive {
    fn new(plan: &PreparedUpdate, fault: Fault) -> Self {
        let mut inner = Drive::new(plan);
        inner.parameter = Some(ORIGINAL);
        inner.corrupt_after_finish = (fault == Fault::KernelReadback).then_some(1);
        Self {
            inner,
            fault,
            events: Vec::new(),
            reads: 0,
            parameter_writes: 0,
        }
    }

    fn parameter_values(&self) -> Vec<u16> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::WriteParameter(value) => Some(*value),
                _ => None,
            })
            .collect()
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
            assert_eq!(
                cdb,
                [0x3c, 0x02, 0xa0, 0, 0x01, 0x3e, 0, 0, 2, 0],
                "unrelated mechanism/settings read"
            );
            self.events.push(Event::ReadParameter);
            self.reads += 1;
            if matches!(
                (self.fault, self.reads),
                (Fault::InitialRead, 1) | (Fault::VerifyRead, 2)
            ) {
                bail!("injected parameter read failure");
            }
            if matches!(
                (self.fault, self.reads),
                (Fault::InitialShortRead, 1) | (Fault::VerifyShortRead, 2)
            ) {
                return Ok(vec![0xff]);
            }
            if self.fault == Fault::VerifyMismatch && self.reads == 2 {
                return Ok(0xaaaau16.to_be_bytes().to_vec());
            }
        }
        self.inner.command_in(cdb, len)
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        assert_eq!(
            cdb,
            [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0],
            "only read unlock may use lenient transport"
        );
        self.inner.command_out(cdb, data)
    }

    fn command_out_strict(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        if cdb.get(2) == Some(&0xa0) {
            assert_eq!(
                cdb,
                [0x3b, 0x02, 0xa0, 0, 0x01, 0x3e, 0, 0, 2, 0],
                "unrelated mechanism/settings write"
            );
            let value = u16::from_be_bytes(data.try_into().unwrap());
            self.events.push(Event::WriteParameter(value));
            self.parameter_writes += 1;
            if self.parameter_writes == 1 {
                if self.fault == Fault::ChangeWriteRejected {
                    bail!("injected parameter write rejection");
                }
                if self.fault == Fault::ChangeWriteAcceptedThenError {
                    self.inner.command_out_strict(cdb, data)?;
                    bail!("injected lost parameter write acknowledgement");
                }
            }
        } else {
            self.events.push(Event::FirmwareCommand(cdb.to_vec()));
            let reject = match self.fault {
                Fault::Entry => cdb == [0x3b, 4, 0xff, 0, 0, 0, 0, 1, 0, 0],
                Fault::KernelTransfer => cdb[..3] == [0x3b, 0x07, 0xfe],
                Fault::NormalTransfer => cdb[..3] == [0x3b, 0x07, 0xf0],
                Fault::Finish => cdb == [0x3b, 5, 0xff, 0, 0, 0, 0, 1, 0, 0],
                _ => false,
            };
            if reject {
                bail!("injected firmware command failure");
            }
        }
        self.inner.command_out_strict(cdb, data)
    }
}

fn recover(drive: &mut ObservedDrive, plan: &PreparedUpdate) -> Result<()> {
    super::super::flash::execute_with_sleep(
        &mut crate::engine::gates::ungated_for_tests(drive),
        super::super::flash::PreparedFlash::Complete(plan),
        pioneer_optical::receiver::ExecutionMode::Recovery,
        &mut |_| {},
    )
    .map(|_| ())
}

#[test]
fn bypass_preserves_verified_startup_transaction() {
    let plan = override_plan();
    let mut drive = ObservedDrive::new(&plan, Fault::None);
    recover(&mut drive, &plan).unwrap();
    assert_eq!(
        &drive.events[..3],
        &[
            Event::ReadParameter,
            Event::WriteParameter(REQUIRED),
            Event::ReadParameter,
        ]
    );
    assert_eq!(
        drive.events[3],
        Event::FirmwareCommand(vec![0x3b, 4, 0xff, 0, 0, 0, 0, 1, 0, 0])
    );
    assert_eq!(drive.parameter_values(), [REQUIRED]);
    assert_eq!(drive.inner.parameter, Some(REQUIRED));
    assert_eq!(drive.inner.finishes, 1);
    assert_eq!(drive.inner.memory, plan.final_kernel_image());
}

#[test]
fn bypass_startup_failures_stop_before_firmware_and_restore_original() {
    let plan = override_plan();
    for fault in [
        Fault::InitialRead,
        Fault::InitialShortRead,
        Fault::ChangeWriteRejected,
        Fault::ChangeWriteAcceptedThenError,
        Fault::VerifyRead,
        Fault::VerifyShortRead,
        Fault::VerifyMismatch,
    ] {
        let mut drive = ObservedDrive::new(&plan, fault);
        let result = recover(&mut drive, &plan);
        assert!(result.is_err(), "{fault:?}");
        assert_eq!(drive.firmware_attempts(), 0, "{fault:?}");
        assert_eq!(drive.inner.finishes, 0, "{fault:?}");
        assert_eq!(drive.inner.parameter, Some(ORIGINAL), "{fault:?}");
        if matches!(fault, Fault::InitialRead | Fault::InitialShortRead) {
            assert_eq!(drive.events, [Event::ReadParameter], "{fault:?}");
        } else {
            let mut expected = vec![Event::ReadParameter, Event::WriteParameter(0xfe24)];
            if !matches!(
                fault,
                Fault::ChangeWriteRejected | Fault::ChangeWriteAcceptedThenError
            ) {
                expected.push(Event::ReadParameter);
            }
            expected.extend([Event::WriteParameter(0xff01), Event::ReadParameter]);
            assert_eq!(drive.events, expected, "{fault:?}");
            assert_eq!(drive.parameter_values(), [REQUIRED, ORIGINAL], "{fault:?}");
            assert_eq!(
                drive.events.last(),
                Some(&Event::ReadParameter),
                "rollback must be verified: {fault:?}"
            );
        }
    }
}

#[test]
fn bypass_firmware_attempt_failure_never_restores_old_startup_word() {
    let plan = override_plan();
    for fault in [
        Fault::Entry,
        Fault::KernelTransfer,
        Fault::NormalTransfer,
        Fault::Finish,
        Fault::KernelReadback,
    ] {
        let mut drive = ObservedDrive::new(&plan, fault);
        let error = recover(&mut drive, &plan).unwrap_err();
        assert!(drive.firmware_attempts() > 0, "{fault:?}");
        assert_eq!(drive.parameter_values(), [REQUIRED], "{fault:?}: {error:#}");
        assert_eq!(drive.inner.parameter, Some(REQUIRED), "{fault:?}");
        assert!(
            format!("{error:#}").contains("retained"),
            "{fault:?}: {error:#}"
        );
    }
}

#[test]
fn bypass_matching_startup_word_never_writes_settings() {
    let plan = override_plan();
    let mut drive = ObservedDrive::new(&plan, Fault::None);
    drive.inner.parameter = Some(0xfe24);
    recover(&mut drive, &plan).unwrap();
    assert_eq!(drive.events[0], Event::ReadParameter);
    assert_eq!(
        drive.events[1],
        Event::FirmwareCommand(vec![0x3b, 4, 0xff, 0, 0, 0, 0, 1, 0, 0])
    );
    assert!(drive.parameter_values().is_empty());
    assert_eq!(drive.inner.parameter, Some(0xfe24));
    assert_eq!(drive.inner.finishes, 1);
}
