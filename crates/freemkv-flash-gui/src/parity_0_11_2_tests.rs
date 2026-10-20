//! Parity with the 0.11.2 GUI for every Pioneer action it offered.
//!
//! `v0_11_2` transcribes, with line references, the job each 0.11.2 control
//! started (`crates/freemkv-flash-gui/src/{app,analysis_ui,ops}.rs` at the
//! v0.11.2 tag). Each test drives the 0.12 model with `Input`s, records the job
//! through the `dry_run` seam, and compares the workflow call it makes with the
//! 0.11.2 one. Where they differ by design, the test asserts both sides and
//! names the commit that made the change.

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use freemkv_flash::platform::MockScsiDevice;
use freemkv_flash::report::{self, Group};
use freemkv_flash::workflow::{
    self, Control, CurrentFirmware, DriveChoice, Event, FlashSheet, Source,
};

use crate::ops::{self, Job, Request, ResultView};
use crate::ui::{
    App, Button, CardBody, CheckId, Effect, FileFilter, Input, Item, Msg, Pick, Side, Task,
};

/// A recovery's current-firmware source, as the workflow receives it.
#[derive(Clone, Debug, PartialEq)]
enum Current {
    NotRequired,
    File(PathBuf),
    ReadFromDrive,
}

/// An analysis source. `as_backup` has no 0.11.2 field; Pioneer captures a
/// backup either way (`pioneer_capture_is_a_backup_either_way`).
#[derive(Clone, Debug, PartialEq)]
enum Src {
    File(PathBuf),
    Drive {
        device: String,
        capture: PathBuf,
        as_backup: bool,
    },
    Analyzed(String),
}

/// The workflow call a job makes, with the options the workflow receives.
/// `FlashOptions::force` is absent: every 0.11.2 Flash job set it false and
/// 954f51d removed the field.
#[derive(Clone, Debug, PartialEq)]
enum Call {
    Info,
    CheckFile(PathBuf),
    Backup {
        out: PathBuf,
        dump: bool,
        replace: bool,
    },
    /// `workflow::flash`.
    Flash {
        device: Option<String>,
        input: PathBuf,
        backup: Option<PathBuf>,
        execute: bool,
        acknowledged_risk: bool,
    },
    /// A read-only preview: 0.11.2 `flash` with `execute: false`, or 0.12
    /// `plan_flash`, which clears `execute` itself.
    Preview {
        device: Option<String>,
        input: PathBuf,
        backup: Option<PathBuf>,
        acknowledged_risk: bool,
    },
    Recover {
        device: Option<String>,
        input: PathBuf,
        current: Current,
        execute: bool,
        acknowledged_risk: bool,
    },
    Inspect(Src),
    Compare(Src, Src),
}

/// One started job: its status label, the device handed to `ops::execute`, and the call.
#[derive(Clone, Debug, PartialEq)]
struct Sent {
    label: String,
    device: String,
    call: Call,
}

fn src(source: &Source) -> Src {
    match source {
        Source::File(path) => Src::File(path.clone()),
        Source::Drive {
            device,
            capture,
            as_backup,
        } => Src::Drive {
            device: device.clone(),
            capture: capture.clone(),
            as_backup: *as_backup,
        },
        Source::Analyzed(a) => Src::Analyzed(a.source.clone()),
    }
}

/// The call `ops::execute` makes for `job` (its arms match 0.11.2 `ops.rs:879-896`).
fn call(job: &Job) -> Call {
    match job {
        Job::Info => Call::Info,
        Job::InfoFile { input } => Call::CheckFile(input.clone()),
        Job::Backup { out, replace } => Call::Backup {
            out: out.clone(),
            dump: false,
            replace: *replace,
        },
        Job::Dump { out, replace } => Call::Backup {
            out: out.clone(),
            dump: true,
            replace: *replace,
        },
        Job::Flash(o) => Call::Flash {
            device: o.device.clone(),
            input: o.input.clone(),
            backup: o.backup.clone(),
            execute: o.execute,
            acknowledged_risk: o.acknowledged_risk,
        },
        Job::PlanFlash(o) => Call::Preview {
            device: o.device.clone(),
            input: o.input.clone(),
            backup: o.backup.clone(),
            acknowledged_risk: o.acknowledged_risk,
        },
        Job::Recovery(o) => Call::Recover {
            device: o.device.clone(),
            input: o.input.clone(),
            current: match &o.current {
                CurrentFirmware::NotRequired => Current::NotRequired,
                CurrentFirmware::File(path) => Current::File(path.clone()),
                CurrentFirmware::ReadFromDrive => Current::ReadFromDrive,
            },
            execute: o.execute,
            acknowledged_risk: o.acknowledged_risk,
        },
        Job::Analysis { request, .. } => match request {
            Request::Inspect(a) => Call::Inspect(src(a)),
            Request::Compare(a, b) => Call::Compare(src(a), src(b)),
        },
    }
}

/// What 0.11.2 started, transcribed from its sources at the v0.11.2 tag.
mod v0_11_2 {
    use super::{Call, Current, Sent, Src};
    use std::path::{Path, PathBuf};

    fn sent(label: &str, device: &str, call: Call) -> Sent {
        Sent {
            label: label.into(),
            device: device.into(),
            call,
        }
    }

    /// `app.rs:401-402`, "Read drive information".
    pub fn read_info(device: &str) -> Sent {
        sent("Drive information", device, Call::Info)
    }

    /// `app.rs:404-411` ("Check file…" on Info) and `app.rs:524-530` (Flash's link).
    pub fn check_file(input: &Path) -> Sent {
        sent("Check file", "", Call::CheckFile(input.into()))
    }

    /// `app.rs:438-444`: the save panel's suggested name, guessed from the drive label.
    pub fn save_name(label: &str, dump: bool) -> &'static str {
        if dump {
            "dump.bin"
        } else if label.to_ascii_uppercase().contains("PIONEER") {
            "backup.tar"
        } else {
            "backup.bin"
        }
    }

    /// `app.rs:445-458` and `ops.rs:881-886`.
    pub fn backup(device: &str, out: &Path, dump: bool) -> Sent {
        let replace = out.symlink_metadata().is_ok();
        let call = Call::Backup {
            out: out.into(),
            dump,
            replace,
        };
        sent(if dump { "Raw dump" } else { "Backup" }, device, call)
    }

    /// "Flash now": `app.rs:287-303` freezes `FlashOptions::default()` with
    /// `force = false`, `execute = true`; the dialog's "Flash now" (`app.rs:342-361`),
    /// enabled only once the box is ticked, sets `acknowledged_risk`.
    pub fn flash_now(device: &str, input: &Path) -> Sent {
        let call = Call::Flash {
            device: None,
            input: input.into(),
            backup: None,
            execute: true,
            acknowledged_risk: true,
        };
        sent("Firmware update", device, call)
    }

    /// `app.rs:304-310`, `choose_flash(ctx, false)`. No 0.11.2 control called it.
    pub fn preview(device: &str, input: &Path) -> Sent {
        let call = Call::Preview {
            device: None,
            input: input.into(),
            backup: None,
            acknowledged_risk: false,
        };
        sent("Preview flash", device, call)
    }

    /// "Recover" (`app.rs:482-501`), then the dialog's "Recover" (`app.rs:347-359`).
    /// "Read from drive" wins over a chosen Current file.
    pub fn recover(device: &str, input: &Path, read: bool, current: Option<&Path>) -> Sent {
        let current = if read {
            Current::ReadFromDrive
        } else {
            Current::File(current.expect("Recover needs Current").into())
        };
        let call = Call::Recover {
            device: None,
            input: input.into(),
            current,
            execute: true,
            acknowledged_risk: true,
        };
        sent("Recovery", device, call)
    }

    /// `app.rs:381-397`: analyses run with no device; sources from `analysis_ui.rs:44-72`.
    pub fn inspect(a: Src) -> Sent {
        sent("Inspect", "", Call::Inspect(a))
    }

    pub fn compare(a: Src, b: Src) -> Sent {
        sent("Compare", "", Call::Compare(a, b))
    }

    /// A live analysis source (`analysis_ui.rs:63-71`); 0.11.2 had no `as_backup`.
    pub fn drive_source(device: &str, capture: PathBuf) -> Src {
        Src::Drive {
            device: device.into(),
            capture,
            as_backup: false,
        }
    }

    /// File-picker filters: Flash (`app.rs:538`), Recovery (`app.rs:553`) and
    /// analysis (`analysis_ui.rs:49`).
    // Flash offers TAR packages and standalone BIN images.
    pub const FIRMWARE_FILTER: (&str, &[&str]) = ("Firmware", &["tar", "enc", "bin"]);
    /// Save-panel names: `analysis_ui.rs:66`, `:172`, `:175` and `app.rs:87`.
    pub const DRIVE_CAPTURE: &str = "inspection.backup.tar";
    pub const REPORT_TEXT: &str = "firmware-report.txt";
    pub const REPORT_JSON: &str = "firmware-report.json";
    pub const DIAGNOSTIC_LOG: &str = "freemkv-flash-diagnostic.log";
    pub const DANGER: &str = "Flashing can permanently disable the drive. Keep it connected and powered until completion.";
    pub const RISK_ACK: &str = "I understand and want to update this drive";
    /// Analysis window actions (`analysis_ui.rs:168-176`).
    pub const REPORT_ACTIONS: [&str; 3] = ["Copy report", "Save text…", "Save JSON…"];
}

// ── the Pioneer model ─────────────────────────────────────────────────────

const PIONEER: &str = "disk4";
const OTHER: &str = "disk5";

/// The profile the real Pioneer backend reports for a mock BDR-UD04 (SAT
/// platform): every task, Recovery included.
fn pioneer_profile() -> workflow::DriveProfile {
    let mut inquiry = vec![b' '; 96];
    inquiry[0] = 5;
    inquiry[4] = 91;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
    inquiry[32..36].copy_from_slice(b"1.14");
    let mut identity = vec![b' '; 48];
    identity[..3].copy_from_slice(b"SN1");
    identity[16..24].copy_from_slice(b"SAT 8A10");
    identity[24..28].copy_from_slice(b"ID58");
    identity[32..36].copy_from_slice(b"ID58");
    identity[40..44].copy_from_slice(b"0000");
    let mut dev = MockScsiDevice::new()
        .on(|cdb| cdb.first() == Some(&0x12), inquiry)
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            identity,
        );
    workflow::profile_on(&mut dev).expect("a Pioneer profile")
}

/// A model with a Pioneer drive selected and profiled, whose jobs are recorded.
fn pioneer_app() -> App {
    let drive = |path: &str, label: &str| DriveChoice {
        path: path.into(),
        name: path.into(),
        label: label.into(),
    };
    let mut app = App::with_drives(vec![
        drive(PIONEER, "PIONEER BD-RW BDR-UD04"),
        drive(OTHER, "HL-DT-ST BD-RE BU40N"),
    ]);
    app.dry_run = Some(Vec::new());
    app.start();
    let profile = ops::profile_view(&pioneer_profile());
    app.profile_worker
        .take()
        .unwrap()
        .send(Ok(profile))
        .unwrap();
    app.poll();
    app
}

fn jobs(app: &App) -> usize {
    app.dry_run.as_ref().unwrap().len()
}

fn sent(app: &App) -> Sent {
    let (label, device, job) = app.dry_run.as_ref().unwrap().last().expect("a job");
    Sent {
        label: label.clone(),
        device: device.clone(),
        call: call(job),
    }
}

fn finish(app: &mut App, result: Result<(), String>) {
    app.worker
        .take()
        .unwrap()
        .send(Msg::Done(result.map(|_| None)))
        .unwrap();
    app.poll();
}

fn panel_buttons(app: &App) -> Vec<Button> {
    let mut out = Vec::new();
    for item in app.view().panel {
        match item {
            Item::Path { button, .. } => out.push(button),
            Item::Buttons { buttons, .. } => out.extend(buttons),
            _ => {}
        }
    }
    out
}

/// Press the panel button labelled `text`, as a shell would.
fn press(app: &mut App, text: &str) -> Vec<Effect> {
    let button = panel_buttons(app)
        .into_iter()
        .find(|b| b.text == text)
        .unwrap_or_else(|| panic!("no button {text}: {:?}", app.view().panel));
    assert!(button.enabled, "{text} is disabled");
    app.dispatch(button.input)
}

fn open_filter(effects: &[Effect]) -> Option<FileFilter> {
    match effects {
        [Effect::OpenFile { filter, .. }] => filter.clone(),
        other => panic!("expected an open panel: {other:?}"),
    }
}

fn save_name(effects: &[Effect]) -> String {
    match effects {
        [Effect::SaveFile { file_name, .. }] => file_name.clone(),
        other => panic!("expected a save panel: {other:?}"),
    }
}

/// Every 0.11.2 ending is still offered under the same filter name.
fn covers(filter: Option<FileFilter>, old: (&str, &[&str])) {
    let filter = filter.expect("a filter");
    assert_eq!(filter.name, old.0);
    for e in old.1 {
        assert!(filter.extensions.contains(e), "{e} missing: {filter:?}");
    }
}

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("freemkv-gui-parity-{}-{name}", std::process::id()))
}

fn mtk_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../freemkv-flash/tests/fixtures/HL-DT-ST_BU40N_N1.02_2017-12-08.bin")
}

// ── drive selection, information and file checks ─────────────────────────

#[test]
fn selecting_and_refreshing_drives_retarget_jobs_as_in_0_11_2() {
    let mut app = pioneer_app();
    app.failure = Some("old".into());
    app.status = "Backup could not finish".into();
    app.dispatch(Input::SelectDrive(1));
    assert_eq!((app.status.as_str(), app.failure.as_ref()), ("Ready", None));
    app.profile_worker
        .take()
        .unwrap()
        .send(Ok(ops::profile_view(&pioneer_profile())))
        .unwrap();
    app.poll();
    app.dispatch(Input::ReadInfo);
    assert_eq!(sent(&app), v0_11_2::read_info(OTHER));
    finish(&mut app, Ok(()));

    // Refresh (0.11.2 `app.rs:159-166`): a vanished drive falls back to the first.
    let first = app.drives[0].clone();
    app.refresh(vec![first]);
    app.dispatch(Input::ReadInfo);
    assert_eq!(sent(&app), v0_11_2::read_info(PIONEER));
    assert_eq!(app.view().drives.refresh.input, Input::Refresh);
}

#[test]
fn read_drive_information_matches_0_11_2() {
    let mut app = pioneer_app();
    press(&mut app, "Read drive information");
    assert_eq!(sent(&app), v0_11_2::read_info(PIONEER));
}

#[test]
fn check_file_from_info_and_flash_matches_0_11_2() {
    let mut app = pioneer_app();
    let effects = press(&mut app, "Check file…");
    assert_eq!(
        open_filter(&effects),
        None,
        "0.11.2 opened an unfiltered panel"
    );
    let file = PathBuf::from("/fw/BDR-UD04_1.14.firmware.tar");
    app.dispatch(Input::Chosen(Pick::CheckFile, file.clone()));
    assert_eq!(sent(&app), v0_11_2::check_file(&file));
    finish(&mut app, Ok(()));

    app.dispatch(Input::SelectTask(Task::Flash));
    app.dispatch(Input::Chosen(Pick::FlashFirmware, file.clone()));
    press(&mut app, "Check file");
    assert_eq!(sent(&app), v0_11_2::check_file(&file));
}

// ── backup and dump ───────────────────────────────────────────────────────

/// Intended change (8b0fcb4): the suggested name is the CLI's
/// `<model>_<rev>.<infix>.<ext>` from the backup format, not 0.11.2's label guess.
#[test]
fn pioneer_backup_runs_the_0_11_2_job_under_the_cli_name() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Backup));
    let name = save_name(&press(&mut app, "Save backup…"));
    let p = pioneer_profile();
    let cli = workflow::default_backup_name(&p.identity, p.backup_format, false).unwrap();
    assert_eq!(name, cli.display().to_string());
    assert_eq!(name, "BD-RW___BDR-UD04_1.14.candidate.tar");
    assert_eq!(v0_11_2::save_name(&app.device_label(), false), "backup.tar");

    let out = temp("backup.tar");
    app.dispatch(Input::Chosen(Pick::Backup, out.clone()));
    assert_eq!(sent(&app), v0_11_2::backup(PIONEER, &out, false));
    finish(&mut app, Ok(()));

    // An existing file was confirmed by the save panel: both replace it.
    std::fs::write(&out, b"old").unwrap();
    app.dispatch(Input::Chosen(Pick::Backup, out.clone()));
    let replaced = sent(&app);
    assert_eq!(replaced, v0_11_2::backup(PIONEER, &out, false));
    assert!(matches!(replaced.call, Call::Backup { replace: true, .. }));
    std::fs::remove_file(&out).unwrap();
}

/// Intended change (8b0fcb4): `<model>_<rev>.dump.bin`, the CLI's dump name.
#[test]
fn pioneer_dump_runs_the_0_11_2_job_under_the_cli_name() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Dump));
    let name = save_name(&press(&mut app, "Save raw dump…"));
    let p = pioneer_profile();
    let cli = workflow::default_backup_name(&p.identity, p.backup_format, true).unwrap();
    assert_eq!(name, cli.display().to_string());
    assert_eq!(name, "BD-RW___BDR-UD04_1.14.dump.bin");
    assert_eq!(v0_11_2::save_name(&app.device_label(), true), "dump.bin");

    let out = temp("dump.bin");
    app.dispatch(Input::Chosen(Pick::Dump, out.clone()));
    assert_eq!(sent(&app), v0_11_2::backup(PIONEER, &out, true));
}

// ── flash ─────────────────────────────────────────────────────────────────

#[test]
fn flash_picker_accepts_tar_packages_and_bin_images() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Flash));
    covers(
        open_filter(&press(&mut app, "Choose firmware…")),
        ("Firmware or backup", &["tar", "bin"]),
    );
    app.dispatch(Input::Chosen(Pick::FlashFirmware, "/fw/a.tar".into()));
    covers(
        open_filter(&press(&mut app, "Change file…")),
        ("Firmware or backup", &["tar", "bin"]),
    );
}

/// Intended change (b287273): the risk box is ticked on a sheet opened after
/// the backup and authorization, not before the job; the write call is 0.11.2's.
#[test]
fn flash_now_sends_the_0_11_2_options_after_an_unticked_confirmation() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Flash));
    let input = PathBuf::from("/fw/BDR-UD04_1.14.firmware.tar");
    app.dispatch(Input::Chosen(Pick::FlashFirmware, input.clone()));
    press(&mut app, "Flash now");
    finish(&mut app, Ok(()));
    assert_eq!(sent(&app), v0_11_2::flash_now(PIONEER, &input));

    let (reply, answer) = mpsc::channel();
    let worker = app.worker.clone().unwrap();
    worker
        .send(Msg::Authorized(FlashSheet::default(), reply))
        .unwrap();
    app.poll();
    let sheet = app.view().confirm.expect("the flash sheet");
    assert_eq!(
        (sheet.title, sheet.danger),
        ("Confirm flash", v0_11_2::DANGER)
    );
    assert_eq!(
        (sheet.ack_text, sheet.ack_checked),
        (v0_11_2::RISK_ACK, false)
    );
    assert!(!sheet.confirm.enabled);
    app.dispatch(Input::Confirm);
    assert!(answer.try_recv().is_err(), "no tick, no write");
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::Confirm);
    assert_eq!(answer.try_recv(), Ok(true));
}

/// 0.11.2 had no reachable dry run; 0.12 always runs the read-only plan first
/// (afd0893), with the options 0.11.2's unreached preview would have sent.
#[test]
fn flash_dry_run_is_the_read_only_plan_with_0_11_2_preview_options() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Flash));
    let input = PathBuf::from("/fw/BDR-UD04_1.14.firmware.tar");
    app.dispatch(Input::Chosen(Pick::FlashFirmware, input.clone()));
    press(&mut app, "Flash now");
    let plan = sent(&app);
    let old = v0_11_2::preview(PIONEER, &input);
    assert_eq!((plan.device, plan.call), (old.device, old.call));
    assert_eq!(plan.label, "Flash plan");
    finish(&mut app, Err("plan refused".into()));
    assert_eq!(jobs(&app), 1, "a failed plan starts no backup or write");
    assert!(app.view().confirm.is_none());
}

// ── recovery ──────────────────────────────────────────────────────────────

/// Choose the Recovery firmware, press Recover, tick and confirm.
fn recover(app: &mut App, input: &Path) {
    app.dispatch(Input::SelectTask(Task::Recovery));
    covers(
        open_filter(&press(app, "Choose firmware…")),
        v0_11_2::FIRMWARE_FILTER,
    );
    app.dispatch(Input::Chosen(Pick::RecoveryInput, input.into()));
    let before = jobs(app);
    press(app, "Recover");
    assert_eq!(jobs(app), before, "nothing runs before the confirmation");
    let sheet = app.view().confirm.expect("the recovery sheet");
    assert_eq!(sheet.title, "Confirm recovery");
    assert_eq!(sheet.warnings, ["Recovery skips backups and compatibility checks. Incompatible firmware can make the drive unusable."]);
    assert_eq!(
        (sheet.ack_text, sheet.ack_checked),
        (v0_11_2::RISK_ACK, false)
    );
    app.dispatch(Input::Confirm);
    assert_eq!(jobs(app), before, "no tick, no recovery");
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::Confirm);
}

#[test]
fn recovery_reading_current_from_the_drive_matches_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Recovery));
    app.dispatch(Input::SetCheck(CheckId::RecoveryReadFromDrive, true));
    let input = PathBuf::from("/fw/target.firmware.tar");
    recover(&mut app, &input);
    assert_eq!(sent(&app), v0_11_2::recover(PIONEER, &input, true, None));
}

#[test]
fn recovery_from_a_current_file_matches_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Recovery));
    covers(
        open_filter(&press(&mut app, "Choose Current…")),
        v0_11_2::FIRMWARE_FILTER,
    );
    let current = PathBuf::from("/fw/current.backup.tar");
    app.dispatch(Input::Chosen(Pick::RecoveryCurrent, current.clone()));
    let input = PathBuf::from("/fw/target.firmware.tar");
    recover(&mut app, &input);
    assert_eq!(
        sent(&app),
        v0_11_2::recover(PIONEER, &input, false, Some(&current))
    );
}

#[test]
fn recovery_read_from_drive_wins_over_a_current_file_as_in_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Recovery));
    let current = PathBuf::from("/fw/current.backup.tar");
    app.dispatch(Input::Chosen(Pick::RecoveryCurrent, current.clone()));
    app.dispatch(Input::SetCheck(CheckId::RecoveryReadFromDrive, true));
    let input = PathBuf::from("/fw/target.firmware.tar");
    recover(&mut app, &input);
    assert_eq!(
        sent(&app),
        v0_11_2::recover(PIONEER, &input, true, Some(&current))
    );
}

// ── inspect and compare ───────────────────────────────────────────────────

#[test]
fn pioneer_capture_is_a_backup_either_way() {
    let pioneer = freemkv_flash::backend::registry::backends()
        .find(|b| b.descriptor().display_name == "Pioneer")
        .expect("the Pioneer backend");
    let inspect = pioneer.inspect().expect("Pioneer inspects");
    assert!(!inspect.raw_capture(), "as_backup would change the capture");
}

#[test]
fn inspect_a_live_pioneer_drive_matches_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Inspect));
    let name = save_name(&press(&mut app, "Selected drive…"));
    assert_eq!(name, v0_11_2::DRIVE_CAPTURE);
    let capture = temp("inspection.backup.tar");
    app.dispatch(Input::Chosen(Pick::AnalysisDrive(0), capture.clone()));
    press(&mut app, "Inspect");
    let source = v0_11_2::drive_source(PIONEER, capture);
    assert_eq!(sent(&app), v0_11_2::inspect(source));
}

#[test]
fn compare_a_file_with_a_live_pioneer_drive_matches_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Compare));
    covers(
        open_filter(&app.dispatch(Input::Choose(Pick::AnalysisFile(0)))),
        v0_11_2::FIRMWARE_FILTER,
    );
    let file = PathBuf::from("/fw/BDR-UD04_1.14.firmware.tar");
    app.dispatch(Input::Chosen(Pick::AnalysisFile(0), file.clone()));
    let capture = temp("compare.backup.tar");
    app.dispatch(Input::Chosen(Pick::AnalysisDrive(1), capture.clone()));
    // 0.11.2 `analysis_ui.rs:56-60`: one side at most is a live drive.
    assert!(app
        .dispatch(Input::Choose(Pick::AnalysisDrive(0)))
        .is_empty());
    press(&mut app, "Compare");
    let b = v0_11_2::drive_source(PIONEER, capture);
    assert_eq!(sent(&app), v0_11_2::compare(Src::File(file), b));
}

/// Run an analysis whose worker returns `result`.
fn analysed(app: &mut App, result: ResultView) {
    app.dispatch(Input::Chosen(Pick::AnalysisFile(0), mtk_fixture()));
    app.dispatch(Input::Chosen(Pick::AnalysisFile(1), mtk_fixture()));
    app.dispatch(Input::RunAnalysis);
    let worker = app.worker.clone().unwrap();
    worker.send(Msg::Analysis(result)).unwrap();
    finish(app, Ok(()));
}

#[test]
fn inspect_a_or_b_from_a_comparison_matches_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Compare));
    let copy = temp("side-b.bin");
    std::fs::copy(mtk_fixture(), &copy).unwrap();
    let (a, b) = (Source::File(mtk_fixture()), Source::File(copy.clone()));
    let report = workflow::compare(&a, &b, &Control::default()).unwrap();
    std::fs::remove_file(&copy).unwrap();
    let right = report.right.source.clone();
    assert_ne!(right, report.left.source);
    analysed(&mut app, ResultView::Compare(report));
    // 0.11.2 `analysis_ui.rs:300-304`: the side becomes the Inspect source and result.
    app.dispatch(Input::InspectSide(Side::B));
    assert_eq!(app.task, Task::Inspect);
    assert_eq!(
        app.sources[0].as_ref().map(src),
        Some(Src::Analyzed(right.clone()))
    );
    assert!(matches!(&app.analysis, Some(ResultView::Inspect(r)) if r.source == right));
}

#[test]
fn cancel_analysis_cancels_the_running_job_as_in_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Inspect));
    app.dispatch(Input::Chosen(Pick::AnalysisFile(0), mtk_fixture()));
    press(&mut app, "Inspect");
    let status = app.view().status.unwrap();
    let cancel = status.cancel.expect("Cancel analysis while running");
    assert_eq!(cancel.text, "Cancel analysis");
    assert!(!app.view().can_close, "0.11.2 refused to close mid-job");
    app.dispatch(cancel.input);
    let (_, _, job) = app.dry_run.as_ref().unwrap().last().unwrap();
    let Job::Analysis { control, .. } = job else {
        panic!("an analysis job")
    };
    assert!(control.cancelled());
}

// ── exports ───────────────────────────────────────────────────────────────

/// Exports are backend-neutral (`text()` / `json()`); the committed MediaTek
/// fixture stands in for Pioneer firmware, which the repository does not ship.
#[test]
fn report_exports_match_0_11_2() {
    let mut app = pioneer_app();
    app.dispatch(Input::SelectTask(Task::Inspect));
    let inspection = workflow::inspect(&Source::File(mtk_fixture()), &Control::default()).unwrap();
    analysed(&mut app, ResultView::Inspect(inspection.clone()));
    let window = app.view().analysis.expect("the results window");
    let actions: Vec<_> = window
        .tree
        .actions
        .iter()
        .map(|b| b.text.as_str())
        .collect();
    assert_eq!(actions, v0_11_2::REPORT_ACTIONS);

    assert_eq!(
        app.dispatch(Input::CopyReport),
        [Effect::CopyText(inspection.text())]
    );
    for (pick, name, want) in [
        (Pick::ReportText, v0_11_2::REPORT_TEXT, inspection.text()),
        (
            Pick::ReportJson,
            v0_11_2::REPORT_JSON,
            inspection.json().unwrap(),
        ),
    ] {
        assert_eq!(save_name(&app.dispatch(Input::Choose(pick))), name);
        let out = temp(name);
        app.dispatch(Input::Chosen(pick, out.clone()));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), want, "{name}");
        std::fs::remove_file(&out).unwrap();
    }
}

#[test]
fn diagnostic_log_exports_match_0_11_2() {
    let log = temp("diagnostic.log");
    std::fs::write(&log, "SCSI result: status=0x02\nRESULT: error\n").unwrap();
    let mut app = pioneer_app();
    press(&mut app, "Read drive information");
    let row = report::Row::gui(
        "field",
        "Diagnostic log",
        log.display().to_string().as_str().into(),
    );
    let worker = app.worker.clone().unwrap();
    worker.send(Msg::Event(Event::Report(row.into()))).unwrap();
    finish(&mut app, Err("drive refused".into()));

    let results = app.view().results.unwrap();
    let failure = results.failure.expect("a failure offers the log");
    assert_eq!(failure.save_log.text, "Save diagnostic log…");
    assert_eq!(
        app.dispatch(results.view_log.input),
        [Effect::OpenPath(log.clone())]
    );

    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        app.dispatch(Input::CopyDiagnostics),
        [Effect::CopyText(text.clone())]
    );
    let saved = app.dispatch(failure.save_log.input);
    assert_eq!(save_name(&saved), v0_11_2::DIAGNOSTIC_LOG);
    let out = temp("exported.log");
    app.dispatch(Input::Chosen(Pick::DiagnosticLog, out.clone()));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), text);
    std::fs::remove_file(&out).unwrap();
    std::fs::remove_file(&log).unwrap();
}

// ── settings ──────────────────────────────────────────────────────────────

/// 0.11.2 drew the settings as disabled controls (`info_ui.rs:8`, `:166`);
/// 0.12 draws them as read-only rows (8b0fcb4). Neither can change a setting.
#[test]
fn settings_are_read_only_as_in_0_11_2() {
    let mut app = pioneer_app();
    press(&mut app, "Read drive information");
    let worker = app.worker.clone().unwrap();
    for (label, value, group) in [
        ("Model", "BDR-UD04", Group::General),
        ("Quiet Drive", "Quiet (active and saved)", Group::Settings),
        ("PureRead", "Standard", Group::Settings),
    ] {
        let row = report::Row::gui("field", label, value.into()).in_group(group);
        worker.send(Msg::Event(Event::Report(row.into()))).unwrap();
    }
    finish(&mut app, Ok(()));
    let cards = app.view().results.unwrap().cards;
    let settings = cards
        .iter()
        .find(|c| c.title == "Device settings")
        .expect("a settings card");
    assert_eq!(settings.subtitle, Some("Current settings · read only"));
    let rows = |pairs: &[(&str, &str)]| {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    assert_eq!(
        settings.body,
        CardBody::Rows(rows(&[
            ("Quiet Drive", "Quiet (active and saved)"),
            ("PureRead", "Standard")
        ]))
    );
}

// ── every native shell ────────────────────────────────────────────────────

const SHELLS: [(&str, &str); 4] = [
    ("mac.rs", include_str!("mac.rs")),
    ("windows.rs", include_str!("windows.rs")),
    ("linux.rs", include_str!("linux.rs")),
    ("egui_shell.rs", include_str!("egui_shell.rs")),
];

/// Each control the parity tests press, and the code that renders it from the
/// `View` and sends its `Input`: one of the alternatives must appear in every shell.
const CONTROLS: &[(&str, &[&str])] = &[
    (
        "button sends its own input",
        &[
            "out.push(b.input.clone())",
            "let input = b.input.clone()",
            "tag_for(&b.input)",
        ],
    ),
    ("drive choice", &["Input::SelectDrive"]),
    ("Refresh", &["drives.refresh", "bar.refresh"]),
    ("task tabs", &["Input::SelectTask"]),
    ("panel buttons", &["Item::Buttons"]),
    ("file choosers", &["Item::Path"]),
    ("checkboxes", &["Item::Check"]),
    ("checkbox input", &["Input::SetCheck"]),
    ("risk box", &["CheckId::RiskAck"]),
    ("Confirm", &["Input::Confirm", "c.confirm.clone()"]),
    ("Cancel", &["Input::CancelConfirm"]),
    (
        "Cancel analysis",
        &["s.cancel", "status.cancel", "st.cancel"],
    ),
    ("Open results…", &["open_results"]),
    ("Save diagnostic log… (failure)", &["save_log"]),
    ("View diagnostic log…", &["view_log"]),
    ("diagnostic window buttons", &["d.buttons"]),
    ("report actions", &["tree.actions"]),
    ("Inspect A / B", &["NodeKind::Buttons"]),
    ("open panel", &["Effect::OpenFile"]),
    ("save panel", &["Effect::SaveFile"]),
    ("chosen file", &["Input::Chosen"]),
    ("copy", &["Effect::CopyText"]),
    ("close guard", &["can_close"]),
];

#[test]
fn every_native_shell_renders_every_parity_control() {
    let mut missing = Vec::new();
    for (file, source) in SHELLS {
        for (control, needles) in CONTROLS {
            if !needles.iter().any(|n| source.contains(n)) {
                missing.push(format!("{file}: {control}"));
            }
        }
    }
    assert!(missing.is_empty(), "unreachable controls: {missing:#?}");
}

/// Every task tab 0.11.2 had is offered for a Pioneer drive.
#[test]
fn every_0_11_2_tab_is_offered_for_a_pioneer_drive() {
    let app = pioneer_app();
    let tabs: Vec<_> = app
        .view()
        .tabs
        .iter()
        .filter(|t| t.enabled)
        .map(|t| t.title)
        .collect();
    assert_eq!(
        tabs,
        [
            "Drive info",
            "Inspect",
            "Compare",
            "Backup",
            "Dump",
            "Flash",
            "Recovery"
        ]
    );
    assert_eq!(app.view().drives.chips[0], "Pioneer");
}

/// 0.11.2 showed why Recovery could not start when pressed; 0.12 hides the tab
/// instead, so the reason must reach the activity log.
#[test]
fn a_failed_recovery_identify_is_logged() {
    let mut profile = pioneer_profile();
    profile.recovery = None;
    profile.recovery_errors = vec!["Pioneer: vendor identity read failed".into()];
    let view = crate::ops::profile_view(&profile);
    assert!(!view.tasks.contains(&Task::Recovery));
    assert_eq!(
        view.notes,
        ["Recovery not offered: could not identify the receiver (Pioneer: vendor identity read failed)"]
    );
}
