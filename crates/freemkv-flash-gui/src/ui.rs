//! Platform-neutral model of the flash GUI.
//!
//! Everything a shell needs to *decide* lives here; a shell only *draws* `App::view()` and
//! forwards user actions to `App::dispatch`. No widget type and no toolkit: this file compiles
//! and is tested on every host.
//!
//! The rule (freemkv's): if a change to this file would need mirroring in `mac.rs` or the egui
//! shell, the split is wrong.
//!
//! Drive work only ever goes through `ops` (the CLI's workflows) on a worker thread.
//! The Flash and Recovery gates — a fresh risk acknowledgement, then an explicit confirmation
//! — are enforced here once, for every shell.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use freemkv_flash::report::{self, Group};
use freemkv_flash::workflow::{
    self, AuthorizedPlan, Control, CurrentFirmware, DriveChoice, Event, FlashOptions, FlashSheet,
    RecoveryOptions, Source,
};

use crate::ops::{self, Job, Request, ResultView};

/// Shown wherever Recovery is offered or confirmed. Wording is part of the safety contract.
pub const FORCE_WARNING: &str = "Recovery mode: no backups, compatibility checks overridden. Attempts to write the selected firmware to the drive. An incompatible image can leave the drive unusable. Required file and drive-protocol checks still apply.";
/// The confirmation sheet's danger line.
pub const FLASH_DANGER: &str =
    "Flashing can permanently disable the drive. Keep it connected and powered until completion.";
/// The acknowledgement that must be ticked, fresh, before Flash or Recover is enabled.
pub const RISK_ACK: &str = "I understand and want to update this drive";
/// Under the progress bar while a job runs.
pub const KEEP_CONNECTED: &str = "Keep the drive connected and powered until this finishes.";
/// On the flash sheet: the backup is already saved, and cancelling is safe.
pub const BACKUP_KEPT: &str =
    "The pre-flash backup is saved. Cancel keeps it and writes nothing to the drive.";
const CANCELLED: &str =
    "Cancelled at the confirmation: nothing was written; the pre-flash backup is kept.";
const WORKER_PANIC: &str = "Operation worker failed unexpectedly. If flashing was underway, the drive state is uncertain; keep the backup and inspect the drive before retrying.";
const WORKER_GONE: &str = "The worker stopped before reporting a result. If a flash was underway, inspect the drive before retrying.";
const DIAGNOSTIC_FIELD: &str = "Diagnostic log";
const DIAGNOSTIC_REFRESH: Duration = Duration::from_millis(500);

/// The application's tasks, in tab order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Task {
    Info,
    Inspect,
    Compare,
    Backup,
    Dump,
    Flash,
    Recovery,
}

impl Task {
    pub const ALL: [Task; 7] = [
        Task::Info,
        Task::Inspect,
        Task::Compare,
        Task::Backup,
        Task::Dump,
        Task::Flash,
        Task::Recovery,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Task::Info => "Drive info",
            Task::Inspect => "Inspect",
            Task::Compare => "Compare",
            Task::Backup => "Backup",
            Task::Dump => "Dump",
            Task::Flash => "Flash",
            Task::Recovery => "Recovery",
        }
    }
}

/// What the selected drive offers, from `workflow::profile`.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Profile {
    /// Shown beside the drive: the family (or "Unsupported"), then what it offers.
    pub(crate) chips: Vec<String>,
    /// The drive tasks offered; Info, Inspect and Compare need no profile.
    pub(crate) tasks: Vec<Task>,
    /// A live capture can feed Inspect and Compare.
    pub(crate) inspect: bool,
    /// The suggested backup and dump file names, from the backup format.
    pub(crate) backup_name: Option<String>,
    pub(crate) dump_name: Option<String>,
    /// File endings a flash to this drive accepts.
    pub(crate) flash_extensions: Vec<&'static str>,
}

/// Where the selected drive's profile stands.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ProfileState {
    NoDrive,
    Probing,
    Ready(Profile),
    Failed,
}

/// Shown beside the drive while its profile is read.
pub const PROBING: &str = "probing…";
const PROFILE_FAILED: &str = "Profile unavailable";

/// What a file chooser is for; returned with the chosen path in `Input::Chosen`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    CheckFile,
    FlashFirmware,
    RecoveryCurrent,
    RecoveryInput,
    Backup,
    Dump,
    AnalysisFile(usize),
    AnalysisDrive(usize),
    DiagnosticLog,
    ReportText,
    ReportJson,
}

/// A file-type filter for an open panel; endings come from the backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFilter {
    pub name: &'static str,
    pub extensions: Vec<&'static str>,
}

/// Work only a shell can do; the shell performs it and reports back through `Input`.
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    /// Run an open panel; dispatch `Input::Chosen(pick, path)` if a file was chosen.
    OpenFile {
        pick: Pick,
        filter: Option<FileFilter>,
    },
    /// Run a save panel (it confirms replacement); dispatch `Input::Chosen` on a choice.
    SaveFile {
        pick: Pick,
        file_name: String,
    },
    CopyText(String),
    /// Call `App::poll` periodically until `StopTicking`.
    StartTicking,
    StopTicking,
}

/// Checkboxes in the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckId {
    RecoveryReadFromDrive,
    RiskAck,
    /// Save a live analysis capture as a backup rather than a raw read.
    CaptureAsBackup,
}

/// One side of a comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

/// Every user action a shell can forward.
#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    SelectDrive(usize),
    Refresh,
    SelectTask(Task),
    Choose(Pick),
    Chosen(Pick, PathBuf),
    SetCheck(CheckId, bool),
    ReadInfo,
    FlashNow,
    CheckFlashFile,
    Recover,
    RunAnalysis,
    CancelAnalysis,
    Confirm,
    CancelConfirm,
    OpenDiagnostics,
    CloseDiagnostics,
    CopyDiagnostics,
    OpenResults,
    CloseResults,
    CopyReport,
    InspectSide(Side),
}

// ── the view ──────────────────────────────────────────────────────────────

/// Everything a shell draws, fully decided.
#[derive(Clone, Debug, PartialEq)]
pub struct View {
    pub title: String,
    pub drives: DriveBar,
    pub tabs: Vec<Tab>,
    pub task: Task,
    /// The selected task's form.
    pub panel: Vec<Item>,
    /// False while a job runs or a confirmation is pending: drive bar, tabs and panel disable.
    pub controls_enabled: bool,
    /// Absent when the last result belongs to another task.
    pub status: Option<Status>,
    pub results: Option<Results>,
    pub confirm: Option<Confirm>,
    pub log: Vec<String>,
    pub diagnostics: Option<Diagnostics>,
    pub analysis: Option<AnalysisWindow>,
    /// Closing the window would orphan a running job.
    pub can_close: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DriveBar {
    pub label: &'static str,
    pub items: Vec<DriveItem>,
    pub selected: Option<usize>,
    /// Shown, disabled, when there is no drive.
    pub placeholder: &'static str,
    pub refresh: Button,
    /// The selected drive's profile chips, or `PROBING` while it is read.
    pub chips: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DriveItem {
    pub text: String,
    pub tooltip: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Tab {
    pub task: Task,
    pub title: &'static str,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonStyle {
    Primary,
    Normal,
    Link,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Button {
    pub text: String,
    pub input: Input,
    pub enabled: bool,
    pub style: ButtonStyle,
}

impl Button {
    fn new(text: &str, input: Input, enabled: bool) -> Self {
        Self {
            text: text.into(),
            input,
            enabled,
            style: ButtonStyle::Normal,
        }
    }
    fn primary(text: &str, input: Input, enabled: bool) -> Self {
        Self {
            style: ButtonStyle::Primary,
            ..Self::new(text, input, enabled)
        }
    }
    fn link(text: &str, input: Input) -> Self {
        Self {
            style: ButtonStyle::Link,
            ..Self::new(text, input, true)
        }
    }
}

/// A chosen file: its name for the label, the full path for a tooltip.
#[derive(Clone, Debug, PartialEq)]
pub struct PathView {
    pub name: String,
    pub full: String,
}

impl PathView {
    fn of(path: &Path) -> Self {
        Self {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            full: path.display().to_string(),
        }
    }
}

/// One line of a task form.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Text(String),
    Heading(String),
    /// Small, secondary text.
    Note(String),
    /// Caution text (the Recovery warning).
    Warning(String),
    Check {
        id: CheckId,
        text: String,
        checked: bool,
        enabled: bool,
    },
    /// A chooser button followed by the chosen file, if any.
    Path {
        button: Button,
        path: Option<PathView>,
    },
    /// A row of buttons, optionally led by a label.
    Buttons {
        label: Option<String>,
        buttons: Vec<Button>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub text: String,
    pub running: bool,
    pub progress: Option<Progress>,
    pub note: Option<&'static str>,
    pub cancel: Option<Button>,
}

/// A running job's progress; `fraction` is `None` until the first update (indeterminate).
#[derive(Clone, Debug, PartialEq)]
pub struct Progress {
    pub label: String,
    pub fraction: Option<f32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Results {
    /// "Open results…" for a finished Inspect or Compare.
    pub open_results: Option<Button>,
    /// Drive information, grouped into cards.
    pub cards: Vec<Card>,
    /// Any other operation's labelled results.
    pub fields: Vec<(String, String)>,
    pub failure: Option<Failure>,
    pub notice: Option<String>,
    pub view_log: Button,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Failure {
    pub text: String,
    pub save_log: Button,
}

/// A drive-information card. `column` places it in a two-column layout; a single column
/// shows the cards in the order given.
#[derive(Clone, Debug, PartialEq)]
pub struct Card {
    pub title: &'static str,
    pub subtitle: Option<&'static str>,
    pub column: usize,
    pub body: CardBody,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CardBody {
    /// `(label, value)` rows, in report order.
    Rows(Vec<(String, String)>),
    /// Read/write capability ticks, split CD/DVD (left) and the rest (right).
    Media {
        left: Vec<MediaRow>,
        right: Vec<MediaRow>,
    },
}

/// A capability state: ticked, unticked, or blank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tri {
    Yes,
    No,
    Unknown,
}

impl Tri {
    fn of(value: &str) -> Self {
        match value {
            "Yes" => Tri::Yes,
            "No" => Tri::No,
            _ => Tri::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MediaRow {
    pub label: String,
    pub read: Tri,
    /// `None` for read-only media and single-valued capabilities.
    pub write: Option<Tri>,
}

/// Header over the media read/write ticks, and its expansion.
pub const MEDIA_HEADER: &str = "R/W";
pub const MEDIA_HINT: &str = "Read / Write";
/// Title of the activity log pane.
pub const LOG_TITLE: &str = "Activity log";
/// Why the window will not close while a job runs.
pub const CLOSE_BLOCKED: &str =
    "An operation is still running. Keep the drive connected and powered until it finishes.";

/// The Flash/Recovery confirmation sheet.
#[derive(Clone, Debug, PartialEq)]
pub struct Confirm {
    pub title: &'static str,
    pub details: Vec<String>,
    pub danger: &'static str,
    /// Cautions: a flash's authorization warnings, or the Recovery warning.
    pub warnings: Vec<String>,
    /// The backend's own confirmation text, when it words one.
    pub prompt: Option<String>,
    pub note: Option<&'static str>,
    pub ack_text: &'static str,
    pub ack_checked: bool,
    pub confirm: Button,
    pub cancel: Button,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Diagnostics {
    pub title: &'static str,
    pub buttons: Vec<Button>,
    pub hint: &'static str,
    pub path: Option<String>,
    pub notice: Option<String>,
    pub lines: Arc<Vec<String>>,
}

/// The analysis results window: a cached tree plus the latest save notice.
#[derive(Clone, Debug, PartialEq)]
pub struct AnalysisWindow {
    pub tree: Arc<AnalysisView>,
    pub notice: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AnalysisView {
    pub title: &'static str,
    pub actions: Vec<Button>,
    pub heading: String,
    pub nodes: Vec<Node>,
}

/// One node of the analysis tree; `open` is a section's initial expansion.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub kind: NodeKind,
    pub open: bool,
    pub children: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum NodeKind {
    Section(String),
    Field {
        label: String,
        value: String,
    },
    Text(String),
    Note(String),
    Mono(String),
    Buttons(Vec<Button>),
    Table {
        header: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

impl Node {
    fn leaf(kind: NodeKind) -> Self {
        Self {
            kind,
            open: false,
            children: Vec::new(),
        }
    }
    fn text(s: impl Into<String>) -> Self {
        Self::leaf(NodeKind::Text(s.into()))
    }
    fn section(name: impl Into<String>, open: bool, children: Vec<Node>) -> Self {
        Self {
            kind: NodeKind::Section(name.into()),
            open,
            children,
        }
    }
}

// ── the model ─────────────────────────────────────────────────────────────

/// Messages from the worker thread.
pub(crate) enum Msg {
    Event(Event),
    Analysis(ResultView),
    /// A flash passed every gate after its backup; the worker waits for the
    /// sheet's answer on the sender before writing.
    Authorized(FlashSheet, Sender<bool>),
    Done(Result<(), String>),
}

/// The drive and input an operation was started for, frozen when the user
/// pressed Flash now or Recover.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) device: String,
    pub(crate) label: String,
    pub(crate) options: FlashOptions,
}

/// What a confirmation sheet asks.
#[derive(Clone, Debug)]
pub(crate) enum Sheet {
    /// Recovery, asked before its job starts.
    Recovery(CurrentFirmware),
    /// An authorized flash; its worker waits on `reply`.
    Flash {
        sheet: FlashSheet,
        reply: Sender<bool>,
    },
}

/// A confirmation in progress.
#[derive(Clone, Debug)]
pub(crate) struct Pending {
    pub(crate) target: Target,
    pub(crate) sheet: Sheet,
}

/// Called from the worker after each event so an event-driven shell repaints.
pub type Waker = Arc<dyn Fn() + Send + Sync>;

/// The whole application state. The shells hold none of their own.
pub struct App {
    pub(crate) profile: ProfileState,
    pub(crate) profile_rx: Option<Receiver<Result<Profile, String>>>,
    pub(crate) drives: Vec<DriveChoice>,
    pub(crate) device: String,
    pub(crate) task: Task,
    pub(crate) result_task: Task,
    pub(crate) flash_input: Option<PathBuf>,
    pub(crate) recovery_input: Option<PathBuf>,
    pub(crate) recovery_current: Option<PathBuf>,
    pub(crate) recovery_read: bool,
    pub(crate) capture_as_backup: bool,
    pub(crate) sources: [Option<Source>; 2],
    pub(crate) analysis: Option<ResultView>,
    pub(crate) analysis_tree: Option<Arc<AnalysisView>>,
    pub(crate) analysis_open: bool,
    pub(crate) analysis_notice: Option<String>,
    pub(crate) control: Control,
    pub(crate) status: String,
    pub(crate) failure: Option<String>,
    pub(crate) action: String,
    pub(crate) risk_ack: bool,
    pub(crate) pending: Option<Pending>,
    /// A flash whose read-only plan is running; its backup starts when it passes.
    pub(crate) planning: Option<Target>,
    /// A flash whose backup and authorization are running; its sheet opens
    /// when the worker reports the authorized plan.
    pub(crate) flashing: Option<Target>,
    /// The user cancelled the flash sheet; the job's refusal is not a failure.
    pub(crate) cancelled: bool,
    pub(crate) log: Vec<String>,
    pub(crate) diagnostic_log: Option<PathBuf>,
    pub(crate) diagnostics_open: bool,
    pub(crate) diagnostic_lines: Arc<Vec<String>>,
    pub(crate) diagnostic_checked: Option<Instant>,
    pub(crate) diagnostic_notice: Option<String>,
    pub(crate) progress: Option<(String, usize, usize)>,
    /// The last job's GUI report rows, in report order.
    pub(crate) rows: Vec<report::Row>,
    /// The last job read drive information, so its rows become cards.
    pub(crate) info_result: bool,
    pub(crate) rx: Option<Receiver<Msg>>,
    waker: Option<Waker>,
    /// qa's GUI gate (`gui_gate`): refuse every job, profile read and drive scan, so the gate's
    /// synthetic drive can never reach a device. Debug builds only.
    #[cfg(debug_assertions)]
    pub(crate) inert: bool,
    /// Test seam: record jobs instead of running them, keeping the worker's sender.
    #[cfg(test)]
    pub(crate) dry_run: Option<Vec<(String, String, Job)>>,
    #[cfg(test)]
    pub(crate) worker: Option<Sender<Msg>>,
    #[cfg(test)]
    pub(crate) profile_worker: Option<Sender<Result<Profile, String>>>,
}

impl App {
    /// The model with the attached drives discovered. Call `start` once shown.
    pub fn new() -> Self {
        let mut app = Self::with_drives(Vec::new());
        app.discover();
        app
    }

    /// Begin reading the selected drive's profile.
    pub fn start(&mut self) -> Vec<Effect> {
        self.start_profile()
    }

    pub(crate) fn with_drives(drives: Vec<DriveChoice>) -> Self {
        let device = drives.first().map(|d| d.path.clone()).unwrap_or_default();
        Self {
            profile: ProfileState::NoDrive,
            profile_rx: None,
            drives,
            device,
            task: Task::Info,
            result_task: Task::Info,
            flash_input: None,
            recovery_input: None,
            recovery_current: None,
            recovery_read: false,
            capture_as_backup: false,
            sources: [None, None],
            analysis: None,
            analysis_tree: None,
            analysis_open: false,
            analysis_notice: None,
            control: Control::default(),
            status: "Ready".into(),
            failure: None,
            action: String::new(),
            risk_ack: false,
            pending: None,
            planning: None,
            flashing: None,
            cancelled: false,
            log: vec!["Ready. Select an optical drive and choose an action.".into()],
            diagnostic_log: None,
            diagnostics_open: false,
            diagnostic_lines: Arc::default(),
            diagnostic_checked: None,
            diagnostic_notice: None,
            progress: None,
            rows: Vec::new(),
            info_result: false,
            rx: None,
            waker: None,
            #[cfg(debug_assertions)]
            inert: false,
            #[cfg(test)]
            dry_run: None,
            #[cfg(test)]
            worker: None,
            #[cfg(test)]
            profile_worker: None,
        }
    }

    /// Let an event-driven shell repaint when the worker has news.
    pub fn set_waker(&mut self, waker: Waker) {
        self.waker = Some(waker);
    }

    /// Read the selected drive's profile on a worker; the drive bar shows
    /// `PROBING` and the controls lock until it arrives.
    fn start_profile(&mut self) -> Vec<Effect> {
        #[cfg(debug_assertions)]
        if self.inert {
            return Vec::new();
        }
        self.profile_rx = None;
        if !self.selected() {
            self.profile = ProfileState::NoDrive;
            return Vec::new();
        }
        self.profile = ProfileState::Probing;
        let (tx, rx) = mpsc::channel();
        self.profile_rx = Some(rx);
        #[cfg(test)]
        if self.dry_run.is_some() {
            self.profile_worker = Some(tx);
            return vec![Effect::StartTicking];
        }
        let device = self.device.clone();
        let waker = self.waker.clone();
        std::thread::spawn(move || {
            let profile = std::panic::catch_unwind(|| {
                workflow::capture_events(|_| {}, || ops::profile(&device))
            });
            let _ = tx.send(match profile {
                Ok(result) => result.map_err(|e| format!("{e:#}")),
                Err(_) => Err(WORKER_PANIC.into()),
            });
            if let Some(wake) = waker {
                wake();
            }
        });
        vec![Effect::StartTicking]
    }

    /// Apply a finished profile; a task the drive no longer offers falls back to Info.
    pub(crate) fn set_profile(&mut self, profile: Result<Profile, String>) {
        self.profile = match profile {
            Ok(profile) => ProfileState::Ready(profile),
            Err(error) => {
                self.log
                    .push(format!("Could not read the drive's profile: {error}"));
                ProfileState::Failed
            }
        };
        if !self.offers(self.task) {
            self.task = Task::Info;
        }
    }

    fn ready_profile(&self) -> Option<&Profile> {
        match &self.profile {
            ProfileState::Ready(profile) => Some(profile),
            _ => None,
        }
    }

    /// Whether `task` is offered: Info, Inspect and Compare always; the rest
    /// only when the drive's profile offers them.
    fn offers(&self, task: Task) -> bool {
        matches!(task, Task::Info | Task::Inspect | Task::Compare)
            || self
                .ready_profile()
                .is_some_and(|p| p.tasks.contains(&task))
    }

    pub fn running(&self) -> bool {
        self.rx.is_some()
    }

    fn busy(&self) -> bool {
        self.running() || self.pending.is_some() || self.profile_rx.is_some()
    }

    fn discover(&mut self) {
        #[cfg(debug_assertions)]
        if self.inert {
            return;
        }
        // Tests must not enumerate the host's real drives.
        #[cfg(test)]
        if self.dry_run.is_some() {
            return;
        }
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = events.clone();
        let drives = workflow::capture_events(
            move |event| received.lock().unwrap().push(event),
            ops::enumerate,
        );
        self.refresh(drives);
        for event in events.lock().unwrap().drain(..) {
            match event {
                Event::Report(report) => {
                    for (label, value) in report.gui_fields() {
                        if label == DIAGNOSTIC_FIELD {
                            self.diagnostic_log = Some(value.into());
                        }
                    }
                }
                Event::Message(line) => self.log.push(line),
                _ => {}
            }
        }
    }

    pub(crate) fn refresh(&mut self, drives: Vec<DriveChoice>) {
        if !drives.iter().any(|d| d.path == self.device) {
            self.device = drives.first().map(|d| d.path.clone()).unwrap_or_default();
            self.risk_ack = false;
            self.pending = None;
        }
        self.drives = drives;
    }

    pub(crate) fn device_label(&self) -> String {
        self.drives
            .iter()
            .find(|d| d.path == self.device)
            .map(DriveChoice::display)
            .unwrap_or_else(|| "No optical drive found".into())
    }

    fn selected(&self) -> bool {
        !self.device.is_empty()
    }

    /// Apply one user action; returns the work only the shell can do.
    pub fn dispatch(&mut self, input: Input) -> Vec<Effect> {
        match input {
            Input::SelectDrive(i) => {
                if let Some(path) = self.drives.get(i).map(|d| d.path.clone()) {
                    if !self.busy() && path != self.device {
                        self.device = path;
                        self.risk_ack = false;
                        self.rows.clear();
                        self.status = "Ready".into();
                        self.failure = None;
                        return self.start_profile();
                    }
                }
            }
            Input::Refresh if !self.busy() => {
                self.discover();
                return self.start_profile();
            }
            Input::SelectTask(task) if !self.busy() && self.offers(task) => {
                self.task = task;
            }
            Input::Choose(pick) => return self.choose(pick),
            Input::Chosen(pick, path) => return self.chosen(pick, path),
            Input::SetCheck(CheckId::RecoveryReadFromDrive, on) if !self.busy() => {
                self.recovery_read = on;
            }
            Input::SetCheck(CheckId::RiskAck, on) if self.pending.is_some() => self.risk_ack = on,
            Input::SetCheck(CheckId::CaptureAsBackup, on) if !self.busy() => {
                self.capture_as_backup = on;
                let mut changed = false;
                for slot in &mut self.sources {
                    if let Some(Source::Drive { as_backup, .. }) = slot {
                        changed |= *as_backup != on;
                        *as_backup = on;
                    }
                }
                if changed {
                    self.set_analysis(None);
                }
            }
            Input::ReadInfo if !self.busy() => {
                return self.start_job("Drive information", self.device.clone(), Job::Info);
            }
            Input::CheckFlashFile if !self.busy() => {
                if let Some(input) = self.flash_input.clone() {
                    return self.start_job("Check file", String::new(), Job::InfoFile { input });
                }
            }
            Input::FlashNow if !self.busy() && self.selected() && self.offers(Task::Flash) => {
                if let Some(input) = self.flash_input.clone() {
                    return self.plan_flash(FlashOptions {
                        input,
                        execute: true,
                        ..Default::default()
                    });
                }
            }
            Input::Recover
                if !self.busy() && self.recovery_ready() && self.offers(Task::Recovery) =>
            {
                let current = if self.recovery_read {
                    CurrentFirmware::ReadFromDrive
                } else {
                    CurrentFirmware::File(self.recovery_current.clone().unwrap_or_default())
                };
                let target = self.target(FlashOptions {
                    input: self.recovery_input.clone().unwrap_or_default(),
                    execute: true,
                    ..Default::default()
                });
                self.ask(target, Sheet::Recovery(current));
            }
            Input::Confirm => return self.confirm(),
            Input::CancelConfirm => {
                if let Some(Pending {
                    sheet: Sheet::Flash { reply, .. },
                    ..
                }) = self.pending.take()
                {
                    self.cancelled = true;
                    let _ = reply.send(false);
                }
                self.risk_ack = false;
            }
            Input::RunAnalysis if !self.busy() => return self.run_analysis(),
            Input::CancelAnalysis if self.running() => {
                self.control.cancel();
                self.status = "Cancelling after the current operation returns…".into();
            }
            Input::OpenDiagnostics => {
                self.diagnostics_open = true;
                self.diagnostic_notice = None;
                self.refresh_diagnostic_view();
            }
            Input::CloseDiagnostics => self.diagnostics_open = false,
            Input::CopyDiagnostics => match self.diagnostic_text() {
                Ok(text) => return vec![Effect::CopyText(text)],
                Err(e) => {
                    self.diagnostic_notice = Some(format!("Could not read diagnostic log: {e}"))
                }
            },
            Input::OpenResults if self.analysis.is_some() => self.analysis_open = true,
            Input::CloseResults => self.analysis_open = false,
            Input::CopyReport => {
                if let Some(result) = &self.analysis {
                    return vec![Effect::CopyText(report_text(result))];
                }
            }
            Input::InspectSide(side) => self.inspect_side(side),
            _ => {}
        }
        Vec::new()
    }

    fn choose(&mut self, pick: Pick) -> Vec<Effect> {
        let open = |filter| vec![Effect::OpenFile { pick, filter }];
        let save = |name: &str| {
            vec![Effect::SaveFile {
                pick,
                file_name: name.into(),
            }]
        };
        let exporting = matches!(
            pick,
            Pick::DiagnosticLog | Pick::ReportText | Pick::ReportJson
        );
        if self.busy() && !exporting {
            return Vec::new();
        }
        match pick {
            Pick::CheckFile => open(None),
            Pick::FlashFirmware => {
                let extensions = self
                    .ready_profile()
                    .map(|p| p.flash_extensions.clone())
                    .filter(|e| !e.is_empty())
                    .unwrap_or_else(workflow::file_extensions);
                open(Some(FileFilter {
                    name: "Firmware or backup",
                    extensions,
                }))
            }
            Pick::RecoveryCurrent | Pick::RecoveryInput | Pick::AnalysisFile(_) => {
                open(Some(FileFilter {
                    name: "Firmware",
                    extensions: workflow::file_extensions(),
                }))
            }
            Pick::Backup | Pick::Dump if self.selected() => {
                let profile = self.ready_profile();
                let name = match pick {
                    Pick::Backup => profile.and_then(|p| p.backup_name.as_deref()),
                    _ => profile.and_then(|p| p.dump_name.as_deref()),
                };
                name.map(save).unwrap_or_default()
            }
            Pick::AnalysisDrive(i) if self.drive_source_allowed(i) => save("inspection.backup.tar"),
            Pick::DiagnosticLog => save("freemkv-flash-diagnostic.log"),
            Pick::ReportText if self.analysis.is_some() => save("firmware-report.txt"),
            Pick::ReportJson if self.analysis.is_some() => save("firmware-report.json"),
            _ => Vec::new(),
        }
    }

    fn chosen(&mut self, pick: Pick, path: PathBuf) -> Vec<Effect> {
        match pick {
            Pick::DiagnosticLog => {
                let result = self
                    .diagnostic_text()
                    .and_then(|text| std::fs::write(&path, text));
                self.diagnostic_notice = Some(match result {
                    Ok(()) => format!("Diagnostic log exported: {}", path.display()),
                    Err(error) => format!("Could not export diagnostic log: {error}"),
                });
            }
            Pick::ReportText | Pick::ReportJson => {
                let Some(result) = &self.analysis else {
                    return Vec::new();
                };
                let data = if pick == Pick::ReportText {
                    Ok(report_text(result))
                } else {
                    report_json(result)
                };
                let written = data.and_then(|d| std::fs::write(&path, d).map_err(Into::into));
                self.analysis_notice = Some(match written {
                    Ok(()) => format!("Saved {}", path.display()),
                    Err(e) => format!("Could not save report: {e}"),
                });
            }
            _ if self.busy() => {}
            Pick::CheckFile => {
                return self.start_job("Check file", String::new(), Job::InfoFile { input: path })
            }
            Pick::FlashFirmware => self.flash_input = Some(path),
            Pick::RecoveryCurrent => self.recovery_current = Some(path),
            Pick::RecoveryInput => self.recovery_input = Some(path),
            Pick::Backup | Pick::Dump => {
                // The native save panel has already confirmed replacing an existing file.
                let replace = path.symlink_metadata().is_ok();
                let (label, job) = if pick == Pick::Dump {
                    ("Raw dump", Job::Dump { out: path, replace })
                } else {
                    ("Backup", Job::Backup { out: path, replace })
                };
                return self.start_job(label, self.device.clone(), job);
            }
            Pick::AnalysisFile(i) => self.set_source(i, Source::File(path)),
            Pick::AnalysisDrive(i) if self.drive_source_allowed(i) => {
                let device = self.device.clone();
                self.set_source(
                    i,
                    Source::Drive {
                        device,
                        capture: path,
                        as_backup: self.capture_as_backup,
                    },
                );
            }
            Pick::AnalysisDrive(_) => {}
        }
        Vec::new()
    }

    fn compare(&self) -> bool {
        self.task == Task::Compare
    }

    /// A live drive may feed one side of an analysis, never both.
    fn drive_source_allowed(&self, i: usize) -> bool {
        let other_live = self.compare()
            && matches!(
                self.sources.get(1 - i.min(1)),
                Some(Some(Source::Drive { .. }))
            );
        let live = self.ready_profile().is_some_and(|p| p.inspect);
        i < 2 && self.selected() && live && !other_live
    }

    fn set_source(&mut self, i: usize, source: Source) {
        if let Some(slot) = self.sources.get_mut(i) {
            *slot = Some(source);
            self.set_analysis(None);
        }
    }

    fn set_analysis(&mut self, result: Option<ResultView>) {
        self.analysis_tree = result.as_ref().map(|r| Arc::new(analysis_tree(r)));
        self.analysis = result;
        self.analysis_notice = None;
    }

    fn recovery_ready(&self) -> bool {
        self.selected()
            && self.recovery_input.is_some()
            && (self.recovery_read || self.recovery_current.is_some())
    }

    /// The selected drive and `options`, frozen; consent always starts unticked.
    fn target(&self, mut options: FlashOptions) -> Target {
        options.acknowledged_risk = false;
        Target {
            device: self.device.clone(),
            label: self.device_label(),
            options,
        }
    }

    /// Open a confirmation sheet; its risk box is always unticked on opening.
    fn ask(&mut self, target: Target, sheet: Sheet) {
        self.risk_ack = false;
        self.pending = Some(Pending { target, sheet });
    }

    /// A flash first runs its read-only plan (no backup, no writes) for the
    /// frozen target; a failed plan ends there.
    fn plan_flash(&mut self, options: FlashOptions) -> Vec<Effect> {
        let target = self.target(options);
        let job = Job::PlanFlash(target.options.clone());
        let effects = self.start_job("Flash plan", target.device.clone(), job);
        if !effects.is_empty() {
            self.planning = Some(target);
        }
        effects
    }

    /// The plan passed: back up and authorize, keeping the plan's log. The
    /// worker writes only after the sheet's Confirm, which needs the risk box,
    /// so the request carries the acknowledgement the sheet collects.
    fn back_up_and_authorize(&mut self, target: Target) -> Vec<Effect> {
        let mut options = target.options.clone();
        options.acknowledged_risk = true;
        let log = std::mem::take(&mut self.log);
        let effects = self.start_job(
            "Firmware update",
            target.device.clone(),
            Job::Flash(options),
        );
        self.log.splice(0..0, log);
        if !effects.is_empty() {
            self.flashing = Some(target);
        }
        effects
    }

    fn confirm(&mut self) -> Vec<Effect> {
        if !self.risk_ack {
            return Vec::new();
        }
        match self.pending.take() {
            Some(Pending {
                sheet: Sheet::Flash { reply, .. },
                ..
            }) => {
                self.risk_ack = false;
                let _ = reply.send(true);
                Vec::new()
            }
            Some(Pending {
                target,
                sheet: Sheet::Recovery(current),
            }) if !self.running() => {
                let job = Job::Recovery(RecoveryOptions {
                    device: None,
                    input: target.options.input,
                    current,
                    execute: true,
                    acknowledged_risk: true,
                });
                self.start_job("Recovery", target.device, job)
            }
            other => {
                self.pending = other;
                Vec::new()
            }
        }
    }

    fn run_analysis(&mut self) -> Vec<Effect> {
        let compare = self.compare();
        let request = match (&self.sources, compare) {
            ([Some(a), Some(b)], true) => Request::Compare(a.clone(), b.clone()),
            ([Some(a), _], false) => Request::Inspect(a.clone()),
            _ => return Vec::new(),
        };
        self.control = Control::default();
        self.set_analysis(None);
        let control = self.control.clone();
        let label = if compare { "Compare" } else { "Inspect" };
        self.start_job(label, String::new(), Job::Analysis { request, control })
    }

    fn inspect_side(&mut self, side: Side) {
        let Some(ResultView::Compare(report)) = &self.analysis else {
            return;
        };
        let source = match side {
            Side::A => report.left.clone(),
            Side::B => report.right.clone(),
        };
        self.sources[0] = Some(Source::Analyzed(source.clone()));
        self.set_analysis(Some(ResultView::Inspect(source)));
        self.task = Task::Inspect;
        self.result_task = Task::Inspect;
    }

    pub(crate) fn start_job(&mut self, label: &str, device: String, job: Job) -> Vec<Effect> {
        #[cfg(debug_assertions)]
        if self.inert {
            self.log.push(format!("{label}: not run by the GUI gate."));
            return Vec::new();
        }
        if self.running() {
            return Vec::new();
        }
        if device.is_empty() && !matches!(job, Job::InfoFile { .. } | Job::Analysis { .. }) {
            self.log.push("No optical drive selected.".into());
            return Vec::new();
        }
        self.result_task = self.task;
        self.action = label.to_string();
        self.status = format!("{label}…");
        self.failure = None;
        self.log.clear();
        self.diagnostic_log = None;
        self.diagnostic_checked = None;
        self.diagnostic_notice = None;
        self.progress = None;
        self.rows.clear();
        self.info_result = matches!(job, Job::Info);
        self.log.push(format!("{label}: {device}"));
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        #[cfg(test)]
        if let Some(jobs) = &mut self.dry_run {
            jobs.push((label.into(), device, job));
            self.worker = Some(tx);
            return vec![Effect::StartTicking];
        }
        let waker = self.waker.clone();
        std::thread::spawn(move || run_job(&device, job, tx, waker));
        vec![Effect::StartTicking]
    }

    /// Drain the worker's events; call on every tick or repaint.
    pub fn poll(&mut self) -> Vec<Effect> {
        let profiled = self.poll_profile();
        let mut finished = false;
        let mut planned = None;
        if let Some(rx) = self.rx.take() {
            loop {
                match rx.try_recv() {
                    Ok(Msg::Event(event)) => self.event(event),
                    Ok(Msg::Analysis(result)) => {
                        self.set_analysis(Some(result));
                        self.analysis_open = true;
                    }
                    Ok(Msg::Authorized(sheet, reply)) => match self.flashing.clone() {
                        Some(target) => self.ask(target, Sheet::Flash { sheet, reply }),
                        None => {
                            let _ = reply.send(false);
                        }
                    },
                    Ok(Msg::Done(result)) => {
                        planned = self.planning.take().filter(|_| result.is_ok());
                        self.end_flash();
                        let cancelled = std::mem::take(&mut self.cancelled);
                        match &result {
                            Ok(()) => self.status = format!("{} complete", self.action),
                            Err(_) if cancelled => {
                                self.status = format!("{} cancelled", self.action)
                            }
                            Err(error) => {
                                self.status = format!("{} could not finish", self.action);
                                self.failure = Some(error.clone());
                            }
                        }
                        self.log.push(match result {
                            Ok(()) => "✓ done.".into(),
                            Err(_) if cancelled => CANCELLED.into(),
                            Err(e) => format!("✗ error: {e}"),
                        });
                        finished = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.planning = None;
                        self.end_flash();
                        self.status = "Operation interrupted".into();
                        self.failure = Some(WORKER_GONE.into());
                        self.log.push("✗ worker disconnected before reporting completion; operation outcome is unknown.".into());
                        finished = true;
                        break;
                    }
                }
            }
            if !finished {
                self.rx = Some(rx);
            }
        }
        if let Some(target) = planned {
            self.back_up_and_authorize(target);
        }
        let due = self.diagnostic_checked.is_none_or(|checked| {
            finished || (self.running() && checked.elapsed() >= DIAGNOSTIC_REFRESH)
        });
        if self.diagnostics_open && due {
            self.refresh_diagnostic_view();
        }
        if (finished || profiled) && !self.running() && self.profile_rx.is_none() {
            vec![Effect::StopTicking]
        } else {
            Vec::new()
        }
    }

    /// A flash job ended: its sheet, if still open, has no one to answer.
    fn end_flash(&mut self) {
        self.flashing = None;
        if matches!(
            self.pending,
            Some(Pending {
                sheet: Sheet::Flash { .. },
                ..
            })
        ) {
            self.pending = None;
            self.risk_ack = false;
        }
    }

    /// Take a finished profile, if one arrived; true when the read ended.
    fn poll_profile(&mut self) -> bool {
        let Some(rx) = &self.profile_rx else {
            return false;
        };
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return false,
            Err(TryRecvError::Disconnected) => Err(WORKER_GONE.into()),
        };
        self.profile_rx = None;
        self.set_profile(result);
        true
    }

    pub(crate) fn event(&mut self, event: Event) {
        match event {
            Event::Message(line) => self.log.push(line),
            Event::Progress { label, done, total } => {
                // Large regions report only through the bar; log each phase once so the
                // activity log names it ("  reading normal...") like the small ones.
                if self.progress.as_ref().is_none_or(|(l, _, _)| *l != label) {
                    self.log.push(format!("  {label}..."));
                }
                self.progress = Some((label, done, total));
            }
            Event::Report(report) => {
                for row in report.rows {
                    match row.gui_label.as_deref() {
                        Some(DIAGNOSTIC_FIELD) => {
                            self.diagnostic_log = Some(row.value.plain().into())
                        }
                        Some(_) => self.rows.push(row),
                        None => {}
                    }
                }
            }
            // The settings arrive as report rows too.
            Event::DeviceSettings(_) => {}
        }
    }

    pub(crate) fn diagnostic_text(&self) -> std::io::Result<String> {
        match &self.diagnostic_log {
            Some(path) => std::fs::read_to_string(path),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No diagnostic log is available for this operation.",
            )),
        }
    }

    pub(crate) fn refresh_diagnostic_view(&mut self) {
        self.diagnostic_lines = Arc::new(match self.diagnostic_text() {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) => vec![format!("Could not read diagnostic log: {error}")],
        });
        self.diagnostic_checked = Some(Instant::now());
    }

    // ── view ──────────────────────────────────────────────────────────────

    /// The complete, fully-decided description of what to show.
    pub fn view(&self) -> View {
        let enabled = !self.busy();
        let shown = self.result_task == self.task;
        View {
            title: format!("freemkv Firmware Utility {}", env!("CARGO_PKG_VERSION")),
            drives: DriveBar {
                label: "Optical drive",
                items: self
                    .drives
                    .iter()
                    .map(|d| DriveItem {
                        text: d.display(),
                        tooltip: d.path.clone(),
                    })
                    .collect(),
                selected: self.drives.iter().position(|d| d.path == self.device),
                placeholder: "No optical drive found",
                refresh: Button::new("Refresh", Input::Refresh, enabled),
                chips: match &self.profile {
                    ProfileState::NoDrive => Vec::new(),
                    ProfileState::Probing => vec![PROBING.into()],
                    ProfileState::Ready(profile) => profile.chips.clone(),
                    ProfileState::Failed => vec![PROFILE_FAILED.into()],
                },
            },
            tabs: Task::ALL
                .iter()
                .map(|&task| Tab {
                    task,
                    title: task.title(),
                    enabled: enabled && self.offers(task),
                })
                .collect(),
            task: self.task,
            panel: self.panel(enabled),
            controls_enabled: enabled,
            status: shown.then(|| self.status_view()),
            results: shown.then(|| self.results_view()),
            confirm: self.pending.as_ref().map(|p| self.confirm_view(p)),
            log: self.log.clone(),
            diagnostics: self.diagnostics_open.then(|| self.diagnostics_view()),
            analysis: self
                .analysis_tree
                .as_ref()
                .filter(|_| self.analysis_open)
                .map(|tree| AnalysisWindow {
                    tree: tree.clone(),
                    notice: self.analysis_notice.clone(),
                }),
            can_close: !self.running(),
        }
    }

    fn panel(&self, enabled: bool) -> Vec<Item> {
        let selected = self.selected();
        let path = |text: &str, pick, on: bool, file: &Option<PathBuf>| Item::Path {
            button: Button::new(text, Input::Choose(pick), enabled && on),
            path: file.as_deref().map(PathView::of),
        };
        match self.task {
            Task::Info => {
                let mut items = vec![Item::Buttons {
                    label: None,
                    buttons: vec![
                        Button::primary(
                            "Read drive information",
                            Input::ReadInfo,
                            enabled && selected,
                        ),
                        Button::new("Check file…", Input::Choose(Pick::CheckFile), enabled),
                    ],
                }];
                if !selected {
                    items.push(Item::Note(
                        "Connect an optical drive, then select Refresh.".into(),
                    ));
                }
                items
            }
            Task::Inspect | Task::Compare => self.analysis_panel(enabled),
            Task::Backup | Task::Dump => {
                let dump = self.task == Task::Dump;
                vec![
                    Item::Text(if dump {
                        "Capture all accessible drive memory into a raw file.".into()
                    } else {
                        "Save firmware backup files for restoration.".into()
                    }),
                    Item::Buttons {
                        label: None,
                        buttons: vec![if dump {
                            Button::primary(
                                "Save raw dump…",
                                Input::Choose(Pick::Dump),
                                enabled && selected,
                            )
                        } else {
                            Button::primary(
                                "Save backup…",
                                Input::Choose(Pick::Backup),
                                enabled && selected,
                            )
                        }],
                    },
                ]
            }
            Task::Flash => match &self.flash_input {
                Some(_) => vec![
                    path("Change file…", Pick::FlashFirmware, true, &self.flash_input),
                    Item::Buttons {
                        label: None,
                        buttons: vec![
                            Button::primary("Flash now", Input::FlashNow, enabled && selected),
                            Button {
                                enabled,
                                ..Button::link("Check file", Input::CheckFlashFile)
                            },
                        ],
                    },
                ],
                None => vec![Item::Buttons {
                    label: None,
                    buttons: vec![Button::primary(
                        "Choose firmware…",
                        Input::Choose(Pick::FlashFirmware),
                        enabled,
                    )],
                }],
            },
            Task::Recovery => {
                let mut items = vec![
                    Item::Heading("Current firmware".into()),
                    Item::Check {
                        id: CheckId::RecoveryReadFromDrive,
                        text: "Read from drive".into(),
                        checked: self.recovery_read,
                        enabled,
                    },
                    path(
                        "Choose Current…",
                        Pick::RecoveryCurrent,
                        !self.recovery_read,
                        &self.recovery_current,
                    ),
                ];
                if self.recovery_read {
                    items.push(Item::Note(
                        "Reads installed firmware for protocol analysis. No backup file is saved."
                            .into(),
                    ));
                }
                items.extend([
                    Item::Heading("Firmware to flash (Kernel + Normal)".into()),
                    path(
                        "Choose firmware…",
                        Pick::RecoveryInput,
                        true,
                        &self.recovery_input,
                    ),
                    Item::Warning(FORCE_WARNING.into()),
                    Item::Buttons {
                        label: None,
                        buttons: vec![Button::primary(
                            "Recover",
                            Input::Recover,
                            enabled && self.recovery_ready(),
                        )],
                    },
                ]);
                items
            }
        }
    }

    fn analysis_panel(&self, enabled: bool) -> Vec<Item> {
        let compare = self.compare();
        let mut items = Vec::new();
        for i in 0..if compare { 2 } else { 1 } {
            let label = match (compare, i) {
                (false, _) => "Source",
                (true, 0) => "Source A",
                _ => "Source B",
            };
            items.push(Item::Buttons {
                label: Some(label.into()),
                buttons: vec![
                    Button::new(
                        "Firmware file…",
                        Input::Choose(Pick::AnalysisFile(i)),
                        enabled,
                    ),
                    Button::new(
                        "Selected drive…",
                        Input::Choose(Pick::AnalysisDrive(i)),
                        enabled && self.drive_source_allowed(i),
                    ),
                ],
            });
            items.push(Item::Note(match &self.sources[i] {
                Some(Source::File(p)) => p.display().to_string(),
                Some(Source::Drive {
                    device,
                    capture,
                    as_backup,
                }) => format!(
                    "{device} → capture {}{}",
                    capture.display(),
                    if *as_backup { " (as a backup)" } else { "" }
                ),
                Some(Source::Analyzed(a)) => format!("Retained analysis: {}", a.source),
                None => "Choose a firmware file or drive.".into(),
            }));
        }
        items.push(Item::Check {
            id: CheckId::CaptureAsBackup,
            text: "Save a drive capture as a backup".into(),
            checked: self.capture_as_backup,
            enabled,
        });
        let ready = self.sources[0].is_some() && (!compare || self.sources[1].is_some());
        items.push(Item::Buttons {
            label: None,
            buttons: vec![Button::new(
                if compare { "Compare" } else { "Inspect" },
                Input::RunAnalysis,
                enabled && ready,
            )],
        });
        items
    }

    fn status_view(&self) -> Status {
        let running = self.running();
        let analysis = matches!(self.task, Task::Inspect | Task::Compare);
        Status {
            text: self.status.clone(),
            running,
            progress: running.then(|| match &self.progress {
                Some((label, done, total)) => Progress {
                    label: label.clone(),
                    fraction: Some(*done as f32 / (*total).max(1) as f32),
                },
                None => Progress {
                    label: "Preparing…".into(),
                    fraction: None,
                },
            }),
            note: running.then_some(KEEP_CONNECTED),
            cancel: (running && analysis)
                .then(|| Button::new("Cancel analysis", Input::CancelAnalysis, true)),
        }
    }

    fn results_view(&self) -> Results {
        let analysis = matches!(self.task, Task::Inspect | Task::Compare);
        let info = self.result_task == Task::Info && self.info_result && !self.rows.is_empty();
        Results {
            open_results: (analysis && self.analysis.is_some())
                .then(|| Button::new("Open results…", Input::OpenResults, true)),
            cards: if info {
                info_cards(&self.rows)
            } else {
                Vec::new()
            },
            fields: if info {
                Vec::new()
            } else {
                self.rows.iter().filter_map(gui_pair).collect()
            },
            failure: self.failure.as_ref().map(|text| Failure {
                text: text.clone(),
                save_log: Button::new(
                    "Save diagnostic log…",
                    Input::Choose(Pick::DiagnosticLog),
                    true,
                ),
            }),
            notice: self.diagnostic_notice.clone(),
            view_log: Button::new("View diagnostic log…", Input::OpenDiagnostics, true),
        }
    }

    fn confirm_view(&self, pending: &Pending) -> Confirm {
        let mut details = vec![
            format!("Drive: {}", pending.target.label),
            format!("Image: {}", pending.target.options.input.display()),
        ];
        let (recovery, warnings, prompt) = match &pending.sheet {
            Sheet::Recovery(current) => {
                details.push(match current {
                    CurrentFirmware::File(path) => format!("Current: {}", path.display()),
                    CurrentFirmware::ReadFromDrive => "Current: read from drive".into(),
                });
                (true, vec![FORCE_WARNING.to_string()], None)
            }
            Sheet::Flash { sheet, .. } => {
                details.extend(sheet.plan.iter().cloned());
                (false, sheet.warnings.clone(), sheet.confirmation.clone())
            }
        };
        Confirm {
            title: if recovery {
                "Confirm recovery"
            } else {
                "Confirm flash"
            },
            details,
            danger: FLASH_DANGER,
            warnings,
            prompt,
            note: (!recovery).then_some(BACKUP_KEPT),
            ack_text: RISK_ACK,
            ack_checked: self.risk_ack,
            confirm: Button::primary(
                if recovery { "Recover" } else { "Flash now" },
                Input::Confirm,
                self.risk_ack,
            ),
            cancel: Button::new("Cancel", Input::CancelConfirm, true),
        }
    }

    fn diagnostics_view(&self) -> Diagnostics {
        Diagnostics {
            title: "Diagnostic log",
            buttons: vec![
                Button::new("Copy diagnostic log", Input::CopyDiagnostics, true),
                Button::new(
                    "Save diagnostic log…",
                    Input::Choose(Pick::DiagnosticLog),
                    true,
                ),
                Button::new("Close", Input::CloseDiagnostics, true),
            ],
            hint: "Attach this log to your bug report.",
            path: self
                .diagnostic_log
                .as_ref()
                .map(|p| p.display().to_string()),
            notice: self.diagnostic_notice.clone(),
            lines: self.diagnostic_lines.clone(),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// The worker: one job, every event forwarded, a panic reported as a failure.
fn run_job(device: &str, job: Job, tx: Sender<Msg>, waker: Option<Waker>) {
    let wake = {
        let waker = waker.clone();
        move || {
            if let Some(w) = &waker {
                w();
            }
        }
    };
    let event_tx = tx.clone();
    let event_wake = wake.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        workflow::capture_events(
            move |event| {
                let _ = event_tx.send(Msg::Event(event));
                event_wake();
            },
            || {
                let mut sheet = SheetConfirm {
                    tx: tx.clone(),
                    waker: waker.clone(),
                };
                if let Some(result) = ops::execute(device, &job, &mut sheet)? {
                    let _ = tx.send(Msg::Analysis(result));
                }
                anyhow::Ok(())
            },
        )
    }));
    let result = match result {
        Ok(result) => result.map_err(|e| format!("{e:#}")),
        Err(_) => Err(WORKER_PANIC.into()),
    };
    let _ = tx.send(Msg::Done(result));
    wake();
}

/// The worker's side of the flash sheet: hand the authorized plan to the
/// model and wait for its answer. A model that is gone answers no.
pub(crate) struct SheetConfirm {
    pub(crate) tx: Sender<Msg>,
    pub(crate) waker: Option<Waker>,
}

impl workflow::Confirm for SheetConfirm {
    fn confirm(&mut self, plan: &AuthorizedPlan) -> anyhow::Result<bool> {
        let (reply, answer) = mpsc::channel();
        if self
            .tx
            .send(Msg::Authorized(FlashSheet::of(plan), reply))
            .is_err()
        {
            return Ok(false);
        }
        if let Some(wake) = &self.waker {
            wake();
        }
        Ok(answer.recv().unwrap_or(false))
    }

    fn asks_every_flash(&self) -> bool {
        true
    }
}

fn report_text(result: &ResultView) -> String {
    match result {
        ResultView::Inspect(r) => r.text(),
        ResultView::Compare(r) => r.text(),
    }
}

fn report_json(result: &ResultView) -> anyhow::Result<String> {
    match result {
        ResultView::Inspect(r) => r.json(),
        ResultView::Compare(r) => r.json(),
    }
}

// ── drive information cards ───────────────────────────────────────────────

/// The cards in single-column order: the report group, its title, and its
/// column in the two-column layout.
const CARDS: [(Group, &str, usize); 6] = [
    (Group::General, "General information", 0),
    (Group::Additional, "Additional information", 1),
    (Group::Region, "DVD region", 1),
    (Group::Settings, "Device settings", 1),
    (Group::Media, "Media capabilities", 0),
    (Group::Operations, "Firmware operations", 1),
];

/// A row's GUI label and value, when the GUI shows it.
fn gui_pair(row: &report::Row) -> Option<(String, String)> {
    Some((row.gui_label.clone()?, row.value.plain()))
}

/// A media row is shown only when it reports a positive capability.
pub(crate) fn visible_media(value: &str) -> bool {
    value
        .strip_prefix("Read: ")
        .and_then(|s| s.split_once("    Write: "))
        .map_or(value == "Yes", |(read, write)| {
            read == "Yes" || write == "Yes"
        })
}

fn media_row(label: &str, value: &str) -> MediaRow {
    match value
        .strip_prefix("Read: ")
        .and_then(|s| s.split_once("    Write: "))
    {
        Some((read, write)) => MediaRow {
            label: label.into(),
            read: Tri::of(read),
            write: (!label.ends_with("-ROM")).then(|| Tri::of(write)),
        },
        None => MediaRow {
            label: label.into(),
            read: Tri::of(value),
            write: None,
        },
    }
}

/// Drive information as one card per report group, rows in report order.
pub(crate) fn info_cards(rows: &[report::Row]) -> Vec<Card> {
    let mut cards = Vec::new();
    for (group, title, column) in CARDS {
        let pairs: Vec<(String, String)> = rows
            .iter()
            .filter(|r| r.group == group)
            .filter_map(gui_pair)
            .collect();
        let body = if group == Group::Media {
            let (left, right): (Vec<_>, Vec<_>) = pairs
                .iter()
                .filter(|(_, v)| visible_media(v))
                .map(|(k, v)| media_row(k, v))
                .partition(|r| {
                    ["CD-", "DVD-", "DVD+"]
                        .iter()
                        .any(|p| r.label.starts_with(p))
                });
            if left.is_empty() && right.is_empty() {
                continue;
            }
            CardBody::Media { left, right }
        } else if pairs.is_empty() {
            continue;
        } else {
            CardBody::Rows(pairs)
        };
        cards.push(Card {
            title,
            subtitle: (group == Group::Settings).then_some("Current settings · read only"),
            column,
            body,
        });
    }
    cards
}

// ── analysis tree ─────────────────────────────────────────────────────────

fn field_nodes(fields: &[workflow::Field]) -> Vec<Node> {
    fields
        .iter()
        .filter(|f| !matches!(f.label.as_str(), "Codec" | "Logical bytes"))
        .map(|f| {
            Node::leaf(NodeKind::Field {
                label: format!("{}:", f.label),
                value: f.value.clone(),
            })
        })
        .collect()
}

fn byte_count(bytes: usize) -> String {
    if bytes == 0 {
        "Unchanged".into()
    } else if bytes < 1024 {
        format!("{bytes} bytes")
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

fn family_id(family: &Option<workflow::HardwareFamily>) -> &str {
    family.as_ref().map_or("Unknown", |f| f.id.as_str())
}

/// One inspected component: its fields, findings and region tree.
pub(crate) fn component_node(c: &workflow::ComponentView) -> Node {
    let mut children = field_nodes(&c.fields);
    children.extend(c.findings().map(Node::text));
    for r in &c.regions {
        let mut region = vec![Node::leaf(NodeKind::Field {
            label: "Role:".into(),
            value: r.role.label().into(),
        })];
        region.extend(field_nodes(&r.fields));
        for t in &r.tables {
            let records = t
                .records
                .iter()
                .map(|record| {
                    let fields: Vec<String> = record
                        .fields
                        .iter()
                        .map(|f| format!("{}: {}", f.label, f.value))
                        .collect();
                    Node::leaf(NodeKind::Mono(format!(
                        "{} @ {:#x}: {}",
                        record.index,
                        record.range.start,
                        fields.join("; ")
                    )))
                })
                .collect();
            let name = format!("{} — {} records", t.format, t.records.len());
            region.push(Node::section(name, false, records));
        }
        children.push(Node::section(&r.name, false, region));
    }
    Node::section(&c.name, true, children)
}

/// The Inspect or Compare result as a tree, built once per result.
pub(crate) fn analysis_tree(result: &ResultView) -> AnalysisView {
    let mut nodes = Vec::new();
    let heading = match result {
        ResultView::Inspect(report) => {
            // A provider that derives no family is headed by its source.
            let family = report.family_line().is_some();
            if family {
                nodes.push(Node::text(&report.source));
            }
            if let Some(live) = &report.live {
                nodes.push(Node::text(format!(
                    "Drive state captured at {} (Unix seconds)",
                    live.captured_at
                )));
                nodes.extend(field_nodes(&live.fields));
                nodes.extend(live.diagnostics.iter().map(Node::text));
            } else {
                nodes.push(Node::leaf(NodeKind::Note(
                    "DVD region and change counters are available only from a live drive capture."
                        .into(),
                )));
            }
            for name in &report.missing_components {
                nodes.push(Node::leaf(NodeKind::Field {
                    label: format!("{name}:"),
                    value: "Not included in this source.".into(),
                }));
            }
            nodes.extend(report.components.iter().map(component_node));
            if family {
                format!("Hardware family: {}", family_id(&report.family))
            } else {
                report.source.clone()
            }
        }
        ResultView::Compare(report) => {
            nodes.push(Node::text(format!(
                "A: {} — {}",
                report.left.source,
                family_id(&report.left_family)
            )));
            nodes.push(Node::text(format!(
                "B: {} — {}",
                report.right.source,
                family_id(&report.right_family)
            )));
            nodes.push(Node::text(match report.unexpected_regions() {
                0 => "No unexpected differences.".to_string(),
                1 => "Unexpected differences in 1 region.".to_string(),
                n => format!("Unexpected differences in {n} regions."),
            }));
            nodes.push(Node::leaf(NodeKind::Buttons(vec![
                Button::new("Inspect A", Input::InspectSide(Side::A), true),
                Button::new("Inspect B", Input::InspectSide(Side::B), true),
            ])));
            for s in &report.sections {
                let mut children: Vec<Node> = s.summary.iter().map(Node::text).collect();
                let rows = s
                    .regions
                    .iter()
                    .map(|region| {
                        vec![
                            region.name.clone(),
                            region.role.label().into(),
                            byte_count(region.left_changed),
                            byte_count(region.right_changed),
                            if region.unresolved {
                                "Partially compared".into()
                            } else {
                                region
                                    .difference_percent
                                    .map_or("Not available".into(), |p| format!("{p:.2}%"))
                            },
                            match (region.differs(), region.expected) {
                                (false, _) => "None",
                                (true, true) => "Expected",
                                (true, false) => "Unexpected",
                            }
                            .into(),
                        ]
                    })
                    .collect();
                let table = Node::leaf(NodeKind::Table {
                    header: [
                        "Region",
                        "Role",
                        "Changed in A",
                        "Changed in B",
                        "Different",
                        "Verdict",
                    ]
                    .map(String::from)
                    .to_vec(),
                    rows,
                });
                children.push(Node::section("Changes by region", true, vec![table]));
                let mut technical = vec![Node::text("Percentages use decoded and expanded bytes across both sources. Metadata and verified address relocations do not count as differences.")];
                technical.extend(field_nodes(&s.fields));
                technical.push(Node::text(format!(
                    "{} address-relocation or metadata changes excluded.",
                    s.relocations.len()
                )));
                technical.push(Node::section(
                    "Excluded changes",
                    false,
                    s.relocations.iter().map(Node::text).collect(),
                ));
                technical.extend(s.details.iter().map(Node::text));
                children.push(Node::section("Technical details", false, technical));
                nodes.push(Node::section(&s.name, true, children));
            }
            format!("Hardware family: {:?}", report.family)
        }
    };
    AnalysisView {
        title: "Firmware analysis",
        actions: vec![
            Button::new("Copy report", Input::CopyReport, true),
            Button::new("Save text…", Input::Choose(Pick::ReportText), true),
            Button::new("Save JSON…", Input::Choose(Pick::ReportJson), true),
        ],
        heading,
        nodes,
    }
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod tests;
