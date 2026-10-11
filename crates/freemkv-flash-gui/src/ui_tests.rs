use super::*;
use freemkv_flash::backend::{
    Backend, BackendId, BackupFacet, BackupFormat, BackupNotice, Descriptor, FileFormat,
    FlashFacet, FlashPlan, FlashRequest, FormatRole, Identity, Match, PlanLine, ReadDevice,
    SavedBackup, WriteDevice,
};
use freemkv_flash::manifest::FlashMode;
use freemkv_flash::platform::MockScsiDevice;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn drive(path: &str, name: &str, label: &str) -> DriveChoice {
    DriveChoice {
        path: path.into(),
        name: name.into(),
        label: label.into(),
    }
}

impl Profile {
    /// A drive that offers every task.
    pub(crate) fn every_task() -> Self {
        Self {
            chips: ["Test family", "Backup", "Dump", "Flash", "Recovery"]
                .map(String::from)
                .to_vec(),
            tasks: vec![Task::Backup, Task::Dump, Task::Flash, Task::Recovery],
            inspect: true,
            backup_name: Some("DRIVE_1.00.backup.bin".into()),
            dump_name: Some("DRIVE_1.00.dump.bin".into()),
        }
    }
}

impl App {
    /// Answer the pending profile read, as its worker would.
    pub(crate) fn answer_profile(&mut self, profile: Result<Profile, String>) {
        let worker = self.profile_worker.take().expect("a profile read");
        worker.send(profile).unwrap();
        self.poll();
    }
}

/// A model whose jobs and profile reads are recorded, not run.
fn dry(drives: Vec<DriveChoice>) -> App {
    let mut app = App::with_drives(drives);
    app.dry_run = Some(Vec::new());
    app
}

/// `dry`, with the selected drive's profile read and offering every task.
fn ready(drives: Vec<DriveChoice>) -> App {
    let mut app = dry(drives);
    app.start();
    app.answer_profile(Ok(Profile::every_task()));
    app
}

fn one_drive() -> App {
    ready(vec![drive("drive-a", "drive-a", "Drive A")])
}

/// One GUI report row in `group`.
fn row(label: &str, value: &str, group: Group) -> report::Row {
    report::Row::gui("test", label, value.into()).in_group(group)
}

/// Every button in the panel, flattened.
fn buttons(view: &View) -> Vec<Button> {
    let mut out = Vec::new();
    for item in &view.panel {
        match item {
            Item::Path { button, .. } => out.push(button.clone()),
            Item::Buttons { buttons, .. } => out.extend(buttons.iter().cloned()),
            _ => {}
        }
    }
    out
}

fn button(view: &View, text: &str) -> Button {
    buttons(view)
        .into_iter()
        .find(|b| b.text == text)
        .unwrap_or_else(|| panic!("no button {text}: {:?}", view.panel))
}

fn has_text(view: &View, text: &str) -> bool {
    view.panel.iter().any(|item| match item {
        Item::Text(t) | Item::Heading(t) | Item::Note(t) | Item::Warning(t) => t == text,
        Item::Check { text: t, .. } => t == text,
        _ => false,
    }) || buttons(view).iter().any(|b| b.text == text)
}

fn last_job(app: &App) -> &(String, String, Job) {
    app.dry_run
        .as_ref()
        .unwrap()
        .last()
        .expect("a job was started")
}

/// Flash now runs the read-only plan first; let it pass, which starts the
/// backup-and-authorize job.
fn plan_passes(app: &mut App) {
    let (label, _, job) = last_job(app);
    assert_eq!(label, "Flash plan");
    assert!(matches!(job, Job::PlanFlash(o) if !o.acknowledged_risk));
    finish(app, Ok(()));
    let (label, _, job) = last_job(app);
    assert_eq!(label, "Firmware update");
    assert!(matches!(job, Job::Flash(o) if o.execute));
}

/// One GUI result row, as the workflows publish it.
fn field_event(label: &str, value: &str) -> Event {
    freemkv_flash::output::Event::Report(
        freemkv_flash::report::Row::gui("field", label, value.into()).into(),
    )
}

fn finish(app: &mut App, result: Result<(), String>) -> Vec<Effect> {
    app.worker.take().unwrap().send(Msg::Done(result)).unwrap();
    app.poll()
}

// ── tasks and tabs ────────────────────────────────────────────────────────

#[test]
fn every_task_is_a_tab_and_enabled_when_idle() {
    let view = one_drive().view();
    let titles: Vec<_> = view.tabs.iter().map(|t| t.title).collect();
    assert_eq!(
        titles,
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
    assert!(view.tabs.iter().all(|t| t.enabled));
    assert!(view.controls_enabled);
    assert_eq!(view.task, Task::Info);
}

#[test]
fn tabs_and_drive_bar_lock_while_a_job_runs() {
    let mut app = one_drive();
    assert_eq!(app.dispatch(Input::ReadInfo), [Effect::StartTicking]);
    let view = app.view();
    assert!(!view.controls_enabled);
    assert!(view.tabs.iter().all(|t| !t.enabled));
    assert!(!view.drives.refresh.enabled);
    assert!(!view.can_close, "a running job must block closing");
    app.dispatch(Input::SelectTask(Task::Flash));
    assert_eq!(app.task, Task::Info, "tab switch ignored while running");
}

fn enabled_tabs(app: &App) -> Vec<Task> {
    let view = app.view();
    view.tabs
        .iter()
        .filter(|t| t.enabled)
        .map(|t| t.task)
        .collect()
}

#[test]
fn tabs_come_from_the_drive_profile() {
    let mut app = dry(vec![drive("drive-a", "drive-a", "Drive A")]);
    assert_eq!(app.start(), [Effect::StartTicking]);
    assert_eq!(app.view().drives.chips, [PROBING]);
    assert!(enabled_tabs(&app).is_empty(), "controls lock while probing");
    app.dispatch(Input::SelectTask(Task::Inspect));
    assert_eq!(app.task, Task::Info, "no tab switch while probing");

    let backup_only = Profile {
        chips: vec!["Family".into(), "Backup".into()],
        tasks: vec![Task::Backup],
        ..Profile::default()
    };
    app.answer_profile(Ok(backup_only));
    assert_eq!(app.view().drives.chips, ["Family", "Backup"]);
    assert_eq!(
        enabled_tabs(&app),
        [Task::Info, Task::Inspect, Task::Compare, Task::Backup]
    );
    app.dispatch(Input::SelectTask(Task::Flash));
    assert_eq!(app.task, Task::Info);
    app.dispatch(Input::SelectTask(Task::Backup));
    assert_eq!(app.task, Task::Backup);
}

#[test]
fn recovery_is_offered_for_an_unsupported_identified_drive() {
    let mut app = dry(vec![drive("drive-a", "drive-a", "Drive A")]);
    app.start();
    app.answer_profile(Ok(Profile {
        chips: vec!["Unsupported".into(), "Recovery (Family)".into()],
        tasks: vec![Task::Recovery],
        ..Profile::default()
    }));
    assert_eq!(
        enabled_tabs(&app),
        [Task::Info, Task::Inspect, Task::Compare, Task::Recovery]
    );
    app.dispatch(Input::SelectTask(Task::Recovery));
    assert_eq!(app.task, Task::Recovery);
}

#[test]
fn a_new_profile_without_the_current_task_falls_back_to_info() {
    let mut app = ready(vec![drive("a", "a", "A"), drive("b", "b", "B")]);
    app.dispatch(Input::SelectTask(Task::Flash));
    assert_eq!(app.dispatch(Input::SelectDrive(1)), [Effect::StartTicking]);
    app.answer_profile(Ok(Profile::default()));
    assert_eq!(app.task, Task::Info);
    assert_eq!(
        enabled_tabs(&app),
        [Task::Info, Task::Inspect, Task::Compare]
    );
}

#[test]
fn a_failed_profile_is_shown_and_logged() {
    let mut app = dry(vec![drive("drive-a", "drive-a", "Drive A")]);
    app.start();
    assert_eq!(
        {
            let worker = app.profile_worker.take().unwrap();
            worker.send(Err("permission denied".into())).unwrap();
            app.poll()
        },
        [Effect::StopTicking]
    );
    assert_eq!(app.view().drives.chips, ["Profile unavailable"]);
    assert!(app.log.iter().any(|l| l.ends_with("permission denied")));
    assert_eq!(
        enabled_tabs(&app),
        [Task::Info, Task::Inspect, Task::Compare]
    );
}

#[test]
fn refresh_reads_the_profile_again() {
    let mut app = one_drive();
    app.dispatch(Input::Refresh);
    assert!(app.profile_worker.is_some(), "refresh re-reads the profile");
}

#[test]
fn info_without_a_drive_offers_only_check_file() {
    let view = dry(Vec::new()).view();
    assert!(!button(&view, "Read drive information").enabled);
    assert!(button(&view, "Check file…").enabled);
    assert!(has_text(
        &view,
        "Connect an optical drive, then select Refresh."
    ));
    assert_eq!(view.drives.selected, None);
    assert_eq!(view.drives.placeholder, "No optical drive found");
    let view = one_drive().view();
    assert!(button(&view, "Read drive information").enabled);
    assert_eq!(
        button(&view, "Read drive information").style,
        ButtonStyle::Primary
    );
}

#[test]
fn no_drive_cannot_start_drive_jobs() {
    let mut app = dry(Vec::new());
    assert!(app.dispatch(Input::ReadInfo).is_empty());
    assert!(!app.running());
    assert_eq!(app.log.last().unwrap(), "No optical drive selected.");
    assert_eq!(app.view().drives.chips, Vec::<String>::new());
    app.dispatch(Input::SelectTask(Task::Backup));
    assert_eq!(app.task, Task::Info, "no drive, no backup tab");
    assert!(app.dispatch(Input::Choose(Pick::Backup)).is_empty());
}

#[test]
fn backup_and_dump_names_come_from_the_profile() {
    let mut app = ready(vec![drive("p", "disk4", "Drive")]);
    app.dispatch(Input::SelectTask(Task::Backup));
    assert!(has_text(
        &app.view(),
        "Save firmware backup files for restoration."
    ));
    assert_eq!(
        app.dispatch(Input::Choose(Pick::Backup)),
        [Effect::SaveFile {
            pick: Pick::Backup,
            file_name: "DRIVE_1.00.backup.bin".into()
        }]
    );
    app.dispatch(Input::SelectTask(Task::Dump));
    assert_eq!(
        app.dispatch(Input::Choose(Pick::Dump)),
        [Effect::SaveFile {
            pick: Pick::Dump,
            file_name: "DRIVE_1.00.dump.bin".into()
        }]
    );
    let out = std::env::temp_dir().join("freemkv-gui-model-no-such-dump.bin");
    app.dispatch(Input::Chosen(Pick::Dump, out.clone()));
    let (label, device, job) = last_job(&app);
    assert_eq!((label.as_str(), device.as_str()), ("Raw dump", "p"));
    assert!(matches!(job, Job::Dump { out: o, replace: false } if *o == out));

    let mut other = dry(vec![drive("h", "disk5", "Other drive")]);
    other.start();
    other.answer_profile(Ok(Profile {
        tasks: vec![Task::Backup],
        backup_name: Some("Other_2.00.candidate.tar".into()),
        ..Profile::default()
    }));
    assert!(matches!(
        &other.dispatch(Input::Choose(Pick::Backup))[..],
        [Effect::SaveFile { file_name, .. }] if file_name == "Other_2.00.candidate.tar"
    ));
    assert!(other.dispatch(Input::Choose(Pick::Dump)).is_empty());
}

// ── flash: acknowledgement and confirmation ───────────────────────────────

#[test]
fn flash_starts_with_a_firmware_chooser() {
    let mut app = one_drive();
    app.dispatch(Input::SelectTask(Task::Flash));
    let view = app.view();
    assert_eq!(buttons(&view).len(), 1);
    assert!(button(&view, "Choose firmware…").enabled);
    assert_eq!(
        app.dispatch(Input::Choose(Pick::FlashFirmware)),
        [Effect::OpenFile {
            pick: Pick::FlashFirmware,
            filter: Some(FLASH_FILTER)
        }]
    );
    app.dispatch(Input::Chosen(
        Pick::FlashFirmware,
        "/fw/firmware.bin".into(),
    ));
    let view = app.view();
    for text in ["Change file…", "Flash now", "Check file"] {
        assert!(button(&view, text).enabled, "{text}");
    }
    assert_eq!(button(&view, "Check file").style, ButtonStyle::Link);
    assert!(view.panel.iter().any(|i| matches!(
        i,
        Item::Path { path: Some(p), .. } if p.name == "firmware.bin" && p.full == "/fw/firmware.bin"
    )));
}

/// A flash backend that authorizes with a generation-barrier warning and
/// records whether it wrote.
struct SheetBackend {
    confirmation: Option<&'static str>,
    executed: AtomicBool,
}

static SHEET_FORMAT: FileFormat = FileFormat {
    id: "sheet-image",
    label: "Sheet test image",
    extensions: &["bin"],
    role: FormatRole::Image,
};

static SHEET_DESCRIPTOR: Descriptor = Descriptor {
    id: BackendId("sheet-test"),
    display_name: "Sheet test",
    flash_summary: None,
    formats: &[],
};

const BARRIER: &str = "downgrade crosses the generation barrier";

impl Backend for SheetBackend {
    fn descriptor(&self) -> &'static Descriptor {
        &SHEET_DESCRIPTOR
    }
    fn probe(&self, _: &mut ReadDevice<'_>, _: &Identity) -> anyhow::Result<Option<Match>> {
        Ok(None)
    }
    fn backup(&self) -> Option<&dyn BackupFacet> {
        Some(self)
    }
    fn flash(&self) -> Option<&dyn FlashFacet> {
        Some(self)
    }
}

impl BackupFacet for SheetBackend {
    fn format(&self) -> BackupFormat {
        BackupFormat {
            extension: "bin",
            infix: "backup",
        }
    }
    fn capture(&self, _: &mut ReadDevice<'_>) -> anyhow::Result<Vec<u8>> {
        Ok(vec![1, 2, 3])
    }
    fn notice(&self, _: &[u8]) -> BackupNotice {
        BackupNotice::None
    }
    fn validate(&self, bytes: &[u8], _: &str) -> anyhow::Result<Vec<u8>> {
        Ok(bytes.to_vec())
    }
}

impl FlashFacet for SheetBackend {
    fn plan(&self, _: &mut ReadDevice<'_>, _: &FlashRequest) -> anyhow::Result<FlashPlan> {
        let mut plan = FlashPlan::new(());
        plan.after_backup = vec![
            PlanLine::Header("== flash plan ==".into()),
            PlanLine::Backup,
        ];
        Ok(plan)
    }
    fn authorize(
        &self,
        _: &mut ReadDevice<'_>,
        plan: FlashPlan,
        _: &SavedBackup,
    ) -> anyhow::Result<AuthorizedPlan> {
        let mut authorized = AuthorizedPlan::new(plan, ());
        authorized.warnings = vec![BARRIER.into()];
        authorized.confirmation = self.confirmation.map(str::to_owned);
        Ok(authorized)
    }
    fn execute(&self, _: &mut WriteDevice<'_>, _: &AuthorizedPlan) -> anyhow::Result<()> {
        self.executed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// A flash job played by the real engine over a mock drive, answering
/// through the GUI's sheet.
struct Flashing {
    backend: Arc<SheetBackend>,
    backup: PathBuf,
    done: Receiver<Result<(), String>>,
}

impl Flashing {
    fn executed(&self) -> bool {
        self.backend.executed.load(Ordering::SeqCst)
    }

    /// The engine's result, once the worker has finished.
    fn result(&self) -> Result<(), String> {
        self.done
            .recv_timeout(Duration::from_secs(20))
            .expect("the flash worker finished")
    }

    /// The worker is still waiting on the sheet.
    fn waiting(&self) -> bool {
        self.done.recv_timeout(Duration::from_millis(200)).is_err()
    }
}

/// Press Flash now on `app`, let the plan pass, and run the backup-and-
/// authorize job until its sheet opens.
fn flash_until_sheet(app: &mut App, confirmation: Option<&'static str>) -> Flashing {
    app.flash_input = Some("firmware.bin".into());
    app.dispatch(Input::FlashNow);
    plan_passes(app);
    let worker = app.worker.take().expect("the flash job's worker");
    let backend = Arc::new(SheetBackend {
        confirmation,
        executed: AtomicBool::new(false),
    });
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let backup = std::env::temp_dir().join(format!(
        "freemkv-gui-sheet-{}-{}.bin",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let (done_tx, done) = mpsc::channel();
    let (engine_backend, out) = (backend.clone(), backup.clone());
    std::thread::spawn(move || {
        let request = FlashRequest {
            input: Vec::new(),
            input_format: &SHEET_FORMAT,
            mode: FlashMode::Full,
            execute: true,
            acknowledged_risk: true,
            enc_override: None,
            drive_model: "TEST".into(),
            verbose: false,
            predump_out: Some(out),
        };
        let events = worker.clone();
        let mut sheet = SheetConfirm {
            tx: worker.clone(),
            waker: None,
        };
        let result = workflow::capture_events(
            move |event| {
                let _ = events.send(Msg::Event(event));
            },
            || {
                let mut dev = MockScsiDevice::new();
                freemkv_flash::engine::flash(&mut dev, &*engine_backend, &request, &mut sheet)
            },
        )
        .map_err(|e| format!("{e:#}"));
        let _ = worker.send(Msg::Done(result.clone()));
        let _ = done_tx.send(result);
    });
    let start = Instant::now();
    while app.pending.is_none() {
        assert!(start.elapsed() < Duration::from_secs(20), "{:?}", app.log);
        std::thread::sleep(Duration::from_millis(10));
        app.poll();
    }
    Flashing {
        backend,
        backup,
        done,
    }
}

#[test]
fn execute_never_runs_without_confirm_after_authorize() {
    let mut app = one_drive();
    // No confirmation text: the CLI would not ask, the GUI's sheet still does.
    let flashing = flash_until_sheet(&mut app, None);
    assert!(app.running(), "the job waits on the sheet");
    assert!(flashing.waiting() && !flashing.executed());
    assert!(app.dispatch(Input::Confirm).is_empty());
    assert!(
        flashing.waiting() && !flashing.executed(),
        "no tick, no write"
    );
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::Confirm);
    assert!(app.pending.is_none());
    assert_eq!(flashing.result(), Ok(()));
    assert!(flashing.executed());
    let start = Instant::now();
    while app.running() {
        assert!(start.elapsed() < Duration::from_secs(20));
        app.poll();
    }
    assert_eq!(app.status, "Firmware update complete");
    let _ = std::fs::remove_file(&flashing.backup);
}

#[test]
fn cancel_at_the_sheet_writes_nothing_and_keeps_the_backup() {
    let mut app = one_drive();
    let flashing = flash_until_sheet(&mut app, Some("This will flash: TEST"));
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::CancelConfirm);
    assert!(app.view().confirm.is_none() && !app.risk_ack);
    let error = flashing.result().unwrap_err();
    assert!(error.contains("aborted at confirmation"), "{error}");
    assert!(!flashing.executed(), "a cancelled sheet wrote");
    assert_eq!(std::fs::read(&flashing.backup).unwrap(), [1, 2, 3]);
    let start = Instant::now();
    while app.running() {
        assert!(start.elapsed() < Duration::from_secs(20));
        app.poll();
    }
    assert_eq!(app.status, "Firmware update cancelled");
    assert_eq!(app.failure, None);
    assert_eq!(app.log.last().map(String::as_str), Some(CANCELLED));
    assert_eq!(app.dry_run.as_ref().unwrap().len(), 2, "plan, then flash");
    let _ = std::fs::remove_file(&flashing.backup);
}

#[test]
fn the_sheet_shows_the_authorized_plan_and_its_warnings() {
    let mut app = one_drive();
    let flashing = flash_until_sheet(&mut app, Some("This will flash: TEST"));
    let confirm = app.view().confirm.expect("the flash sheet");
    assert_eq!(confirm.title, "Confirm flash");
    assert_eq!(confirm.warnings, [BARRIER]);
    assert_eq!(confirm.prompt.as_deref(), Some("This will flash: TEST"));
    let saved = format!("backup: saved {} (3 bytes)", flashing.backup.display());
    assert_eq!(
        confirm.details,
        [
            "Drive: drive-a  Drive A".to_string(),
            "Image: firmware.bin".into(),
            "== flash plan ==".into(),
            saved,
        ]
    );
    assert_eq!(confirm.danger, FLASH_DANGER);
    assert_eq!(confirm.note, Some(BACKUP_KEPT));
    assert_eq!(confirm.confirm.text, "Flash now");
    assert!(!app.view().controls_enabled && !app.view().can_close);
    app.dispatch(Input::CancelConfirm);
    let _ = flashing.result();
    let _ = std::fs::remove_file(&flashing.backup);
}

#[test]
fn the_confirm_button_is_gated_by_the_tick() {
    let mut app = one_drive();
    app.risk_ack = true;
    let flashing = flash_until_sheet(&mut app, None);
    let confirm = app.view().confirm.unwrap();
    assert!(!confirm.ack_checked, "the tick resets when the sheet opens");
    assert!(!confirm.confirm.enabled);
    assert!(app.dispatch(Input::Confirm).is_empty());
    assert!(app.pending.is_some() && flashing.waiting());
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    let confirm = app.view().confirm.unwrap();
    assert!(confirm.ack_checked && confirm.confirm.enabled);
    app.dispatch(Input::SetCheck(CheckId::RiskAck, false));
    assert!(!app.view().confirm.unwrap().confirm.enabled);
    app.dispatch(Input::CancelConfirm);
    assert!(flashing.result().is_err() && !flashing.executed());
    let _ = std::fs::remove_file(&flashing.backup);
}

#[test]
fn a_failed_plan_shows_no_sheet() {
    let mut app = one_drive();
    app.flash_input = Some("firmware.bin".into());
    app.dispatch(Input::FlashNow);
    assert!(
        app.view().confirm.is_none(),
        "the plan runs before any sheet"
    );
    finish(
        &mut app,
        Err("image fails its AES-CMAC integrity check".into()),
    );
    assert!(app.view().confirm.is_none() && app.pending.is_none());
    assert_eq!(
        app.failure.as_deref(),
        Some("image fails its AES-CMAC integrity check")
    );
    assert!(!app.running());
    assert!(app.dispatch(Input::Confirm).is_empty());
    assert_eq!(
        app.dry_run.as_ref().unwrap().len(),
        1,
        "no backup after a failed plan"
    );
}

#[test]
fn risk_acknowledgement_is_ignored_without_a_confirmation() {
    let mut app = one_drive();
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    assert!(!app.risk_ack);
}

#[test]
fn flash_needs_a_selected_drive() {
    let mut app = dry(Vec::new());
    app.task = Task::Flash;
    app.flash_input = Some("firmware.bin".into());
    assert!(!button(&app.view(), "Flash now").enabled);
    app.dispatch(Input::FlashNow);
    assert!(app.pending.is_none() && !app.running());
}

#[test]
fn flash_target_is_frozen_when_flash_now_is_pressed() {
    let mut app = ready(vec![
        drive("drive-a", "drive-a", "Drive A"),
        drive("drive-b", "drive-b", "Drive B"),
    ]);
    app.flash_input = Some("firmware.bin".into());
    app.dispatch(Input::FlashNow);
    app.dispatch(Input::SelectDrive(1));
    plan_passes(&mut app);
    app.dispatch(Input::SelectDrive(1));
    app.dispatch(Input::Refresh);
    assert_eq!(
        app.device, "drive-a",
        "drive bar is locked during the flash"
    );
    let (_, device, _) = last_job(&app);
    assert_eq!(device, "drive-a");
    let worker = app.worker.clone().unwrap();
    let (reply, _answer) = mpsc::channel();
    worker
        .send(Msg::Authorized(FlashSheet::default(), reply))
        .unwrap();
    app.poll();
    assert_eq!(app.pending.as_ref().unwrap().target.device, "drive-a");
    assert!(!app.risk_ack);
}

#[test]
fn drive_choice_and_confirmation_show_the_os_name_of_identical_drives() {
    let label = "HL-DT-ST BD-RE BU40N (rev 1.04)";
    let mut app = ready(vec![
        drive(r"\\.\CdRom0", "D:", label),
        drive(r"\\.\CdRom1", "E:", label),
    ]);
    app.dispatch(Input::SelectDrive(1));
    app.answer_profile(Ok(Profile::every_task()));
    assert_eq!(app.device_label(), "E:  HL-DT-ST BD-RE BU40N (rev 1.04)");
    let bar = app.view().drives;
    assert_eq!(bar.selected, Some(1));
    assert_eq!(bar.items[1].tooltip, r"\\.\CdRom1");
    app.flash_input = Some("firmware.bin".into());
    app.dispatch(Input::FlashNow);
    plan_passes(&mut app);
    let (reply, _answer) = mpsc::channel();
    let worker = app.worker.clone().unwrap();
    worker
        .send(Msg::Authorized(FlashSheet::default(), reply))
        .unwrap();
    app.poll();
    let confirm = app.view().confirm.unwrap();
    assert_eq!(
        confirm.details[0],
        "Drive: E:  HL-DT-ST BD-RE BU40N (rev 1.04)"
    );
    assert_eq!(app.pending.as_ref().unwrap().target.device, r"\\.\CdRom1");
}

// ── recovery ──────────────────────────────────────────────────────────────

#[test]
fn recovery_requires_both_inputs_and_a_drive() {
    let mut app = one_drive();
    app.dispatch(Input::SelectTask(Task::Recovery));
    let view = app.view();
    for text in [
        "Current firmware",
        "Read from drive",
        "Choose Current…",
        "Firmware to flash (Kernel + Normal)",
        "Choose firmware…",
        FORCE_WARNING,
        "Recover",
    ] {
        assert!(has_text(&view, text), "{text}");
    }
    assert!(!button(&view, "Recover").enabled);
    app.dispatch(Input::Recover);
    assert!(app.pending.is_none());

    app.dispatch(Input::Chosen(Pick::RecoveryInput, "new.tar".into()));
    assert!(
        !button(&app.view(), "Recover").enabled,
        "current firmware missing"
    );
    app.dispatch(Input::SetCheck(CheckId::RecoveryReadFromDrive, true));
    let view = app.view();
    assert!(!button(&view, "Choose Current…").enabled);
    assert!(has_text(
        &view,
        "Reads installed firmware for protocol analysis. No backup file is saved."
    ));
    assert!(button(&view, "Recover").enabled);
    app.dispatch(Input::SetCheck(CheckId::RecoveryReadFromDrive, false));
    assert!(!button(&app.view(), "Recover").enabled);
    app.dispatch(Input::Chosen(Pick::RecoveryCurrent, "old.tar".into()));
    assert!(button(&app.view(), "Recover").enabled);
}

#[test]
fn recovery_confirms_with_the_force_warning_then_runs_acknowledged() {
    let mut app = one_drive();
    app.task = Task::Recovery;
    app.recovery_input = Some("new.tar".into());
    app.recovery_read = true;
    app.dispatch(Input::Recover);
    let confirm = app.view().confirm.unwrap();
    assert_eq!(confirm.title, "Confirm recovery");
    assert_eq!(confirm.warnings, [FORCE_WARNING]);
    assert_eq!((confirm.prompt, confirm.note), (None, None));
    assert_eq!(confirm.confirm.text, "Recover");
    assert!(confirm
        .details
        .contains(&"Current: read from drive".to_string()));
    assert!(app.dispatch(Input::Confirm).is_empty());
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::Confirm);
    let (label, device, job) = last_job(&app);
    assert_eq!((label.as_str(), device.as_str()), ("Recovery", "drive-a"));
    let Job::Recovery(options) = job else {
        panic!("expected a recovery job")
    };
    assert!(options.execute && options.acknowledged_risk);
    assert!(matches!(options.current, CurrentFirmware::ReadFromDrive));
    assert_eq!(options.input, PathBuf::from("new.tar"));
}

// ── job lifecycle and events ──────────────────────────────────────────────

#[test]
fn job_lifecycle_reports_progress_then_completion() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    let status = app.view().status.unwrap();
    assert_eq!(status.text, "Drive information…");
    assert!(status.running);
    assert_eq!(status.note, Some(KEEP_CONNECTED));
    assert_eq!(
        status.progress.unwrap().fraction,
        None,
        "indeterminate first"
    );
    assert!(status.cancel.is_none(), "only analysis can be cancelled");
    let tx = app.worker.clone().unwrap();
    tx.send(Msg::Event(Event::Progress {
        label: "Reading firmware".into(),
        done: 512,
        total: 1024,
    }))
    .unwrap();
    assert!(app.poll().is_empty());
    let progress = app.view().status.unwrap().progress.unwrap();
    assert_eq!(progress.label, "Reading firmware");
    assert_eq!(progress.fraction, Some(0.5));
    assert_eq!(finish(&mut app, Ok(())), [Effect::StopTicking]);
    let view = app.view();
    assert!(!app.running() && view.controls_enabled && view.can_close);
    let status = view.status.unwrap();
    assert_eq!(status.text, "Drive information complete");
    assert!(status.progress.is_none());
    assert_eq!(app.log.last().unwrap(), "✓ done.");
}

#[test]
fn failed_job_offers_log_export_next_to_the_error() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    finish(&mut app, Err("Backup failed".into()));
    let results = app.view().results.unwrap();
    let failure = results.failure.unwrap();
    assert_eq!(failure.text, "Backup failed");
    assert_eq!(failure.save_log.text, "Save diagnostic log…");
    assert_eq!(results.view_log.text, "View diagnostic log…");
    assert_eq!(app.status, "Drive information could not finish");
    assert_eq!(app.log.last().unwrap(), "✗ error: Backup failed");
}

#[test]
fn disconnected_worker_releases_controls_and_reports_failure() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    drop(app.worker.take());
    assert_eq!(app.poll(), [Effect::StopTicking]);
    assert!(!app.running(), "a dead worker must not leave the app busy");
    assert!(app.log.iter().any(|l| l.contains("worker")));
    assert_eq!(app.failure.as_deref(), Some(WORKER_GONE));
}

#[test]
fn completion_is_not_misreported_as_worker_disconnection() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    let tx = app.worker.take().unwrap();
    tx.send(Msg::Done(Ok(()))).unwrap();
    drop(tx);
    app.poll();
    assert!(!app.running());
    assert_eq!(app.log.last().unwrap(), "✓ done.");
}

#[test]
fn events_fill_rows_log_and_diagnostic_path() {
    let mut app = one_drive();
    app.event(field_event("Model", "BDR-UD04"));
    app.event(field_event("Diagnostic log", "/tmp/diagnostic.log"));
    app.event(Event::Message("hello".into()));
    app.event(Event::Report(
        report::Row::cli("cli", "cli only", "x".into()).into(),
    ));
    let labels: Vec<_> = app.rows.iter().map(|r| r.gui_label.clone()).collect();
    assert_eq!(labels, [Some("Model".to_string())]);
    assert_eq!(
        app.diagnostic_log,
        Some(PathBuf::from("/tmp/diagnostic.log"))
    );
    assert_eq!(app.log.last().unwrap(), "hello");
}

#[test]
fn results_belong_to_the_task_that_produced_them() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    app.worker
        .clone()
        .unwrap()
        .send(Msg::Event(field_event("Model", "OLD INFO RESULT")))
        .unwrap();
    finish(&mut app, Ok(()));
    assert!(!app.view().results.unwrap().cards.is_empty());
    for task in [Task::Backup, Task::Dump, Task::Flash, Task::Recovery] {
        app.dispatch(Input::SelectTask(task));
        let view = app.view();
        assert!(view.status.is_none() && view.results.is_none(), "{task:?}");
    }
}

#[test]
fn non_info_results_are_plain_fields() {
    let mut app = one_drive();
    app.task = Task::Backup;
    app.result_task = Task::Backup;
    app.rows = vec![row("Backup", "/tmp/b.tar", Group::General)];
    let results = app.view().results.unwrap();
    assert!(results.cards.is_empty());
    assert_eq!(results.fields, [("Backup".into(), "/tmp/b.tar".into())]);
}

#[test]
fn refresh_removes_disconnected_selection_and_its_consent() {
    let mut app = dry(vec![drive("ioreg:old", "ioreg:old", "Drive")]);
    app.risk_ack = true;
    app.refresh(vec![drive("ioreg:new", "ioreg:new", "Reconnected drive")]);
    assert_eq!(app.device, "ioreg:new");
    assert!(!app.risk_ack);
    app.refresh(Vec::new());
    assert!(app.device.is_empty());
    assert!(app.view().drives.items.is_empty());
}

#[test]
fn selecting_another_drive_clears_its_results() {
    let mut app = ready(vec![drive("a", "a", "A"), drive("b", "b", "B")]);
    app.rows = vec![row("Model", "A", Group::General)];
    app.failure = Some("old".into());
    app.dispatch(Input::SelectDrive(1));
    assert_eq!(app.device, "b");
    assert!(app.rows.is_empty() && app.failure.is_none());
    app.answer_profile(Ok(Profile::every_task()));
    app.dispatch(Input::SelectDrive(7));
    assert_eq!(app.device, "b", "an out-of-range index is ignored");
}

/// The real worker, the real workflow, no drive: it must fail cleanly, never panic.
#[test]
fn drive_info_on_a_missing_device_fails_gracefully() {
    let mut app = App::with_drives(vec![drive(
        "/dev/freemkv-flash-gui-no-such-device",
        "none",
        "Missing drive",
    )]);
    assert_eq!(app.dispatch(Input::ReadInfo), [Effect::StartTicking]);
    let start = Instant::now();
    while app.running() {
        assert!(start.elapsed() < Duration::from_secs(60), "worker hung");
        std::thread::sleep(Duration::from_millis(20));
        app.poll();
    }
    assert!(app.failure.is_some(), "{:?}", app.log);
    assert_eq!(app.status, "Drive information could not finish");
    assert!(app.view().controls_enabled);
}

// ── diagnostics ───────────────────────────────────────────────────────────

#[test]
fn diagnostic_viewer_and_export_show_the_same_full_log() {
    let path =
        std::env::temp_dir().join(format!("freemkv-gui-diagnostic-{}.log", std::process::id()));
    std::fs::write(
        &path,
        "SCSI result: status=0x00 transferred=0\nRESULT: error\n",
    )
    .unwrap();
    let mut app = one_drive();
    app.log = vec!["backup failed".into()];
    app.diagnostic_log = Some(path.clone());
    app.dispatch(Input::OpenDiagnostics);
    let diag = app.view().diagnostics.unwrap();
    assert_eq!(diag.hint, "Attach this log to your bug report.");
    assert_eq!(diag.path.as_deref(), Some(&*path.display().to_string()));
    assert!(diag
        .lines
        .iter()
        .any(|l| l.contains("status=0x00 transferred=0")));
    assert!(!diag.lines.iter().any(|l| l == "backup failed"));
    let texts: Vec<_> = diag.buttons.iter().map(|b| b.text.as_str()).collect();
    assert_eq!(
        texts,
        ["Copy diagnostic log", "Save diagnostic log…", "Close"]
    );
    assert!(matches!(
        &app.dispatch(Input::CopyDiagnostics)[..],
        [Effect::CopyText(t)] if t.contains("RESULT: error")
    ));

    let out = std::env::temp_dir().join(format!("freemkv-gui-export-{}.log", std::process::id()));
    app.dispatch(Input::Chosen(Pick::DiagnosticLog, out.clone()));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        std::fs::read_to_string(&path).unwrap()
    );
    assert!(app
        .diagnostic_notice
        .as_ref()
        .unwrap()
        .starts_with("Diagnostic log exported"));
    std::fs::remove_file(&out).unwrap();

    std::fs::write(&path, "RESULT: updated log\n").unwrap();
    app.refresh_diagnostic_view();
    assert_eq!(*app.diagnostic_lines, ["RESULT: updated log"]);
    std::fs::remove_file(&path).unwrap();
    assert!(
        app.diagnostic_text().is_err(),
        "a missing log must not export a summary"
    );
    app.refresh_diagnostic_view();
    assert!(app.diagnostic_lines[0].contains("Could not read diagnostic log"));
    app.dispatch(Input::CloseDiagnostics);
    assert!(app.view().diagnostics.is_none());
}

#[test]
fn diagnostics_save_offers_the_default_name_even_while_running() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    assert_eq!(
        app.dispatch(Input::Choose(Pick::DiagnosticLog)),
        [Effect::SaveFile {
            pick: Pick::DiagnosticLog,
            file_name: "freemkv-flash-diagnostic.log".into()
        }]
    );
}

// ── inspect and compare ───────────────────────────────────────────────────

#[test]
fn inspect_and_compare_need_their_sources() {
    let mut app = dry(Vec::new());
    app.dispatch(Input::SelectTask(Task::Inspect));
    let view = app.view();
    let files = buttons(&view)
        .iter()
        .filter(|b| b.text == "Firmware file…")
        .count();
    assert_eq!(files, 1);
    assert!(!button(&view, "Selected drive…").enabled, "no drive");
    assert!(!button(&view, "Inspect").enabled);
    assert!(has_text(&view, "Choose a firmware file or drive."));
    app.dispatch(Input::Chosen(Pick::AnalysisFile(0), "/fw/a.bin".into()));
    let view = app.view();
    assert!(button(&view, "Inspect").enabled);
    assert!(has_text(&view, "/fw/a.bin"));

    app.dispatch(Input::SelectTask(Task::Compare));
    let view = app.view();
    assert!(view
        .panel
        .iter()
        .any(|i| matches!(i, Item::Buttons { label: Some(l), .. } if l == "Source B")));
    assert!(!button(&view, "Compare").enabled);
    app.dispatch(Input::Chosen(Pick::AnalysisFile(1), "/fw/b.bin".into()));
    assert!(button(&app.view(), "Compare").enabled);
    app.dispatch(Input::RunAnalysis);
    let (label, device, job) = last_job(&app);
    assert_eq!((label.as_str(), device.as_str()), ("Compare", ""));
    assert!(matches!(
        job,
        Job::Analysis {
            request: Request::Compare(..),
            ..
        }
    ));
    let status = app.view().status.unwrap();
    assert_eq!(status.cancel.unwrap().text, "Cancel analysis");
    app.dispatch(Input::CancelAnalysis);
    assert!(app.control.cancelled());
}

#[test]
fn only_one_compare_side_may_be_a_live_drive() {
    let mut app = one_drive();
    app.dispatch(Input::SelectTask(Task::Compare));
    assert!(matches!(
        &app.dispatch(Input::Choose(Pick::AnalysisDrive(0)))[..],
        [Effect::SaveFile { file_name, .. }] if file_name == "inspection.backup.tar"
    ));
    app.dispatch(Input::Chosen(Pick::AnalysisDrive(0), "/tmp/cap.tar".into()));
    let view = app.view();
    assert!(has_text(&view, "drive-a → capture /tmp/cap.tar"));
    let drive_buttons: Vec<_> = buttons(&view)
        .into_iter()
        .filter(|b| b.text == "Selected drive…")
        .collect();
    assert!(drive_buttons[0].enabled && !drive_buttons[1].enabled);
    assert!(app
        .dispatch(Input::Choose(Pick::AnalysisDrive(1)))
        .is_empty());
}

#[test]
fn capture_as_backup_follows_every_live_source() {
    let mut app = one_drive();
    app.dispatch(Input::SelectTask(Task::Inspect));
    let check = |app: &App| {
        app.view().panel.iter().find_map(|i| match i {
            Item::Check {
                id: CheckId::CaptureAsBackup,
                checked,
                ..
            } => Some(*checked),
            _ => None,
        })
    };
    assert_eq!(check(&app), Some(false));
    app.dispatch(Input::Chosen(Pick::AnalysisDrive(0), "/tmp/cap.bin".into()));
    assert!(matches!(
        &app.sources[0],
        Some(Source::Drive {
            as_backup: false,
            ..
        })
    ));
    app.dispatch(Input::SetCheck(CheckId::CaptureAsBackup, true));
    assert_eq!(check(&app), Some(true));
    assert!(matches!(
        &app.sources[0],
        Some(Source::Drive {
            as_backup: true,
            ..
        })
    ));
    assert!(has_text(
        &app.view(),
        "drive-a → capture /tmp/cap.bin (as a backup)"
    ));
}

/// Inspect the committed MediaTek fixture after `edit`, via a temporary file.
fn mtk_inspection(name: &str, edit: impl FnOnce(&mut [u8])) -> Arc<workflow::Inspection> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../freemkv-flash/tests/fixtures/HL-DT-ST_BU40N_N1.02_2017-12-08.bin");
    let mut bytes = std::fs::read(fixture).unwrap();
    edit(&mut bytes);
    let path = std::env::temp_dir().join(format!("freemkv-gui-{}-{name}", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let result = workflow::inspect(&Source::File(path.clone()), &Control::default());
    let _ = std::fs::remove_file(&path);
    result.unwrap()
}

/// The "Changes by region" rows of a comparison tree, plus its text lines.
fn compare_tree(
    report: workflow::ComparisonReport,
) -> (Vec<String>, Vec<Vec<String>>, Vec<String>) {
    let tree = analysis_tree(&ResultView::Compare(report));
    let texts = tree
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    fn find(nodes: &[Node]) -> Option<(Vec<String>, Vec<Vec<String>>)> {
        nodes.iter().find_map(|n| match &n.kind {
            NodeKind::Table { header, rows } => Some((header.clone(), rows.clone())),
            _ => find(&n.children),
        })
    }
    let (header, rows) = find(&tree.nodes).expect("a region table");
    (header, rows, texts)
}

#[test]
fn compare_tree_marks_expected_and_unexpected_differences() {
    // Two drive reads of one build: boot mirror in the boot page, own calibration.
    let read = |unit: u8, code: bool| {
        move |b: &mut [u8]| {
            b.copy_within(0x1_0000..0x1_0400, 0);
            b[0x1f_0010] = unit;
            if code {
                b[0x1_2345] ^= 1;
            }
        }
    };
    let a = mtk_inspection("a.bin", read(1, false));
    let b = mtk_inspection("b.bin", read(2, false));
    let report =
        freemkv_flash::inspection::compare_inspections(a.clone(), b, &Control::default()).unwrap();
    let (header, rows, texts) = compare_tree(report);
    assert_eq!(header[1], "Role");
    assert_eq!(header.last().unwrap(), "Verdict");
    let calibration = rows.iter().find(|r| r[0] == "Calibration").unwrap();
    assert_eq!(
        (calibration[1].as_str(), calibration[5].as_str()),
        ("Per-unit", "Expected")
    );
    assert!(rows
        .iter()
        .filter(|r| r[0] != "Calibration")
        .all(|r| r[5] == "None"));
    assert!(
        texts.iter().any(|t| t == "No unexpected differences."),
        "{texts:?}"
    );

    let c = mtk_inspection("c.bin", read(2, true));
    let (_, rows, texts) = compare_tree(
        freemkv_flash::inspection::compare_inspections(a, c, &Control::default()).unwrap(),
    );
    let code = rows.iter().find(|r| r[5] == "Unexpected").unwrap();
    assert_eq!(
        (code[0].as_str(), code[1].as_str()),
        ("Integrity-covered code 0", "Code")
    );
    assert!(
        texts
            .iter()
            .any(|t| t == "Unexpected differences in 1 region."),
        "{texts:?}"
    );
}

#[test]
fn inspect_tree_shows_each_region_role() {
    let tree = analysis_tree(&ResultView::Inspect(mtk_inspection("s.bin", |_| {})));
    let firmware = tree
        .nodes
        .iter()
        .find(|n| n.kind == NodeKind::Section("Firmware".into()))
        .unwrap();
    let boot = firmware
        .children
        .iter()
        .find(|n| n.kind == NodeKind::Section("Boot page".into()))
        .unwrap();
    assert_eq!(
        boot.children[0].kind,
        NodeKind::Field {
            label: "Role:".into(),
            value: "Code".into()
        }
    );
}

#[test]
fn report_actions_need_a_result() {
    let mut app = one_drive();
    assert!(app.dispatch(Input::Choose(Pick::ReportText)).is_empty());
    assert!(app.dispatch(Input::CopyReport).is_empty());
    app.dispatch(Input::OpenResults);
    assert!(app.view().analysis.is_none());
}

// ── drive information cards ───────────────────────────────────────────────

#[test]
fn information_cards_follow_report_groups_in_report_order() {
    let rows = [
        row("Model", "BDR-XD08U", Group::General),
        row("Firmware version", "1.10", Group::General),
        row("Kernel type", "ID69", Group::Additional),
        row("Product code", "XYZ", Group::Additional),
        row("CD-R", "Read: Yes    Write: Yes", Group::Media),
        row("BD-ROM", "Read: Yes    Write: No", Group::Media),
        row("DVD region", "2", Group::Region),
        row("Quiet Drive", "Quiet (active and saved)", Group::Settings),
        row("Firmware update", "Supported", Group::Operations),
    ];
    let cards = info_cards(&rows);
    let titles: Vec<_> = cards.iter().map(|c| (c.title, c.column)).collect();
    assert_eq!(
        titles,
        [
            ("General information", 0),
            ("Additional information", 1),
            ("DVD region", 1),
            ("Device settings", 1),
            ("Media capabilities", 0),
            ("Firmware operations", 1),
        ]
    );
    assert_eq!(cards[3].subtitle, Some("Current settings · read only"));
    let pairs = |list: &[(&str, &str)]| {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        cards[0].body,
        CardBody::Rows(pairs(&[
            ("Model", "BDR-XD08U"),
            ("Firmware version", "1.10")
        ]))
    );
    assert_eq!(
        cards[1].body,
        CardBody::Rows(pairs(&[("Kernel type", "ID69"), ("Product code", "XYZ")])),
        "rows keep the producer's order"
    );
    assert_eq!(
        cards[3].body,
        CardBody::Rows(pairs(&[("Quiet Drive", "Quiet (active and saved)")]))
    );
    let CardBody::Media { left, right } = &cards[4].body else {
        panic!("media")
    };
    assert_eq!(left[0].label, "CD-R");
    assert_eq!((left[0].read, left[0].write), (Tri::Yes, Some(Tri::Yes)));
    assert_eq!(right[0].label, "BD-ROM");
    assert_eq!(right[0].write, None, "read-only media shows no write tick");
}

#[test]
fn info_results_become_cards_only_after_reading_drive_information() {
    let mut app = one_drive();
    app.dispatch(Input::ReadInfo);
    let worker = app.worker.clone().unwrap();
    for event in [
        field_event("Model", "BDR"),
        Event::Report(row("Firmware update", "Supported", Group::Operations).into()),
    ] {
        worker.send(Msg::Event(event)).unwrap();
    }
    finish(&mut app, Ok(()));
    assert_eq!(app.view().results.unwrap().cards.len(), 2);

    app.dispatch(Input::Chosen(Pick::CheckFile, "/fw/a.bin".into()));
    app.worker
        .clone()
        .unwrap()
        .send(Msg::Event(field_event("File", "/fw/a.bin")))
        .unwrap();
    finish(&mut app, Ok(()));
    let results = app.view().results.unwrap();
    assert!(results.cards.is_empty());
    assert_eq!(results.fields, [("File".into(), "/fw/a.bin".into())]);
}

#[test]
fn media_visibility_requires_a_positive_capability() {
    for value in [
        "Unknown",
        "No",
        "Read: Unknown    Write: Unknown",
        "Read: Unknown    Write: No",
        "Read: No    Write: No",
        "Read: No    Write: Unknown",
    ] {
        assert!(!visible_media(value), "{value}");
    }
    for value in [
        "Yes",
        "Read: Yes    Write: No",
        "Read: Yes    Write: Unknown",
        "Read: Unknown    Write: Yes",
    ] {
        assert!(visible_media(value), "{value}");
    }
}

#[test]
fn empty_media_card_is_hidden_and_other_information_survives() {
    let rows = [
        row("Model", "Drive", Group::General),
        row("BD-R XL", "Read: Unknown    Write: Unknown", Group::Media),
        row("LabelFlash", "Unknown", Group::Media),
    ];
    let cards = info_cards(&rows);
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].title, "General information");
    assert_eq!(
        cards[0].body,
        CardBody::Rows(vec![("Model".into(), "Drive".into())])
    );
}

#[test]
fn inspect_tree_leaves_out_standing_caveats() {
    let component = workflow::ComponentView {
        name: "Normal".into(),
        fields: Vec::new(),
        regions: Vec::new(),
        diagnostics: vec!["finding".into(), "standing caveat".into()],
        standing: vec![1],
    };
    let node = component_node(&component);
    assert_eq!(node.kind, NodeKind::Section("Normal".into()));
    let texts: Vec<_> = node
        .children
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::Text(t) => Some(t.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["finding"]);
}

#[test]
fn byte_counts_read_naturally() {
    assert_eq!(byte_count(0), "Unchanged");
    assert_eq!(byte_count(10), "10 bytes");
    assert_eq!(byte_count(2048), "2.0 KiB");
}
