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
pub use freemkv_flash::workflow::FileOrigin;
use freemkv_flash::workflow::{
    self, AuthorizedPlan, Control, CurrentFirmware, DriveChoice, Event, FlashOptions, FlashSheet,
    RecoveryOptions, Source,
};

use crate::ops::{self, Job, Request, ResultView};
use crate::support::Journal;

/// Shown wherever Recovery is offered or confirmed. Wording is part of the safety contract.
pub const FORCE_WARNING: &str = "ui.recovery_skips_automatic_backups_and_some_compatib";
/// The confirmation sheet's danger line.
pub const FLASH_DANGER: &str = "ui.flashing_can_permanently_disable_the_drive_keep_it";
/// The acknowledgement that must be ticked, fresh, before Flash or Recover is enabled.
pub const RISK_ACK: &str = "ui.i_understand_and_want_to_update_this_drive";
/// Under the progress bar while a job runs.
pub const KEEP_CONNECTED: &str = "ui.keep_the_drive_connected_and_powered_until_this_fi";
/// On the flash sheet: the backup is already saved, and cancelling is safe.
pub const BACKUP_KEPT: &str = "ui.the_pre_flash_backup_is_saved_cancel_keeps_it_and_";
const CANCELLED: &str = "ui.cancelled_no_firmware_was_written";
const WORKER_PANIC: &str = "ui.operation_worker_failed_unexpectedly_if_flashing_w";
const WORKER_GONE: &str = "ui.the_worker_stopped_before_reporting_a_result_if_a_";
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

    pub const fn message_id(self) -> &'static str {
        match self {
            Task::Info => "task.info",
            Task::Inspect => "task.inspect",
            Task::Compare => "task.compare",
            Task::Backup => "task.backup",
            Task::Dump => "task.dump",
            Task::Flash => "task.flash",
            Task::Recovery => "task.recovery",
        }
    }

    pub fn title(self) -> &'static str {
        crate::localization::get(crate::localization::Language::En, self.message_id())
    }
}

/// What the selected drive offers, from `workflow::profile`.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Profile {
    pub(crate) can_read: Option<bool>,
    pub(crate) flash_current: bool,
    /// Shown beside the drive: the family (or "Unsupported"), then what it offers.
    pub(crate) chips: Vec<String>,
    /// The drive tasks offered; Info, Inspect and Compare need no profile.
    pub(crate) tasks: Vec<Task>,
    /// Recheck Current choices when Recovery lacks a normal live protocol match.
    pub(crate) recovery_without_live_protocol: bool,
    /// A live capture can feed Inspect and Compare.
    pub(crate) inspect: bool,
    /// The suggested backup and dump file names, from the backup format.
    pub(crate) backup_name: Option<String>,
    pub(crate) dump_name: Option<String>,
    /// File endings a flash to this drive accepts.
    pub(crate) flash_extensions: Vec<&'static str>,
    /// Lines for the activity log, e.g. why Recovery is not offered.
    pub(crate) notes: Vec<String>,
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
pub const PROBING: &str = "status.probing";
const PROFILE_FAILED: &str = "ui.profile_unavailable";

/// What a file chooser is for; returned with the chosen path in `Input::Chosen`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    CheckFile,
    FlashFirmware,
    FlashCurrent,
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
    /// Open an automatically saved diagnostic in the system text viewer.
    OpenPath(PathBuf),
    /// Call `App::poll` periodically until `StopTicking`.
    StartTicking,
    StopTicking,
}

/// Checkboxes in the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckId {
    FlashReadFromDrive,
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
    SetLanguage(crate::localization::Language),
    SelectDrive(usize),
    Refresh,
    SelectTask(Task),
    Choose(Pick),
    Chosen(Pick, PathBuf),
    SetCheck(CheckId, bool),
    ReadInfo,
    FlashNow,
    CheckFlashFile,
    CheckRecoveryFile,
    FlashCurrentMember(String),
    Recover,
    RecoveryMember(String),
    RecoveryCurrentMember(String),
    RunAnalysis,
    CancelAnalysis,
    Confirm,
    CancelConfirm,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    OpenDiagnostics,
    ViewLog,
    SubmitReport,
    CancelReport,
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
    pub language: crate::localization::Language,
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
    pub label: String,
    pub items: Vec<DriveItem>,
    pub selected: Option<usize>,
    /// Shown, disabled, when there is no drive.
    pub placeholder: String,
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
    pub title: String,
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
    /// Origin evidence, colored by all shells without implying compatibility.
    Origin(workflow::FileOrigin),
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
    pub note: Option<String>,
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
    pub submit_report: Button,
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
    pub title: String,
    pub subtitle: Option<String>,
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

/// Title of the activity log pane.
#[cfg(all(feature = "native", target_os = "macos"))]
pub const LOG_TITLE: &str = "ui.activity_log";
/// Why the window will not close while a job runs.
pub const CLOSE_BLOCKED: &str = "ui.an_operation_is_still_running_keep_the_drive_conne";

/// The Flash/Recovery confirmation sheet.
#[derive(Clone, Debug, PartialEq)]
pub struct Confirm {
    pub title: String,
    pub details: Vec<String>,
    pub danger: String,
    /// Cautions: a flash's authorization warnings, or the Recovery warning.
    pub warnings: Vec<String>,
    /// The backend's own confirmation text, when it words one.
    pub prompt: Option<String>,
    pub note: Option<String>,
    pub ack_text: String,
    pub ack_checked: bool,
    pub confirm: Button,
    pub cancel: Button,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Diagnostics {
    pub title: String,
    pub buttons: Vec<Button>,
    pub hint: String,
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
    pub title: String,
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

fn translate(language: crate::localization::Language, value: &mut String) {
    *value = crate::localization::render(language, value);
}

fn translate_button(language: crate::localization::Language, button: &mut Button) {
    translate(language, &mut button.text);
}

fn translate_item(language: crate::localization::Language, item: &mut Item) {
    match item {
        Item::Origin(_) => {}
        Item::Text(text) | Item::Heading(text) | Item::Note(text) | Item::Warning(text) => {
            translate(language, text)
        }
        Item::Check { text, .. } => translate(language, text),
        Item::Path { button, .. } => translate_button(language, button),
        Item::Buttons { label, buttons } => {
            if let Some(label) = label {
                translate(language, label);
            }
            buttons
                .iter_mut()
                .for_each(|button| translate_button(language, button));
        }
    }
}

fn translate_node(language: crate::localization::Language, node: &mut Node) {
    match &mut node.kind {
        NodeKind::Section(text) | NodeKind::Text(text) | NodeKind::Note(text) => {
            translate(language, text)
        }
        NodeKind::Field { label, value } => {
            translate(language, label);
            translate(language, value);
        }
        NodeKind::Mono(_) => {}
        NodeKind::Buttons(buttons) => buttons
            .iter_mut()
            .for_each(|button| translate_button(language, button)),
        NodeKind::Table { header, rows } => {
            header.iter_mut().for_each(|text| translate(language, text));
            rows.iter_mut()
                .flatten()
                .for_each(|text| translate(language, text));
        }
    }
    node.children
        .iter_mut()
        .for_each(|child| translate_node(language, child));
}

/// Resolve catalog messages at the model boundary so every shell receives the same language.
fn translate_view(view: &mut View) {
    let language = view.language;
    translate(language, &mut view.title);
    translate(language, &mut view.drives.label);
    translate(language, &mut view.drives.placeholder);
    translate_button(language, &mut view.drives.refresh);
    view.drives
        .chips
        .iter_mut()
        .for_each(|text| translate(language, text));
    view.tabs
        .iter_mut()
        .for_each(|tab| translate(language, &mut tab.title));
    view.panel
        .iter_mut()
        .for_each(|item| translate_item(language, item));
    view.log
        .iter_mut()
        .for_each(|line| *line = crate::localization::english(line));
    if let Some(status) = &mut view.status {
        translate(language, &mut status.text);
        if let Some(note) = &mut status.note {
            translate(language, note);
        }
        if let Some(progress) = &mut status.progress {
            translate(language, &mut progress.label);
        }
        if let Some(cancel) = &mut status.cancel {
            translate_button(language, cancel);
        }
    }
    if let Some(results) = &mut view.results {
        if let Some(button) = &mut results.open_results {
            translate_button(language, button);
        }
        results.cards.iter_mut().for_each(|card| {
            translate(language, &mut card.title);
            if let Some(subtitle) = &mut card.subtitle {
                translate(language, subtitle);
            }
            match &mut card.body {
                CardBody::Rows(rows) => rows.iter_mut().for_each(|(label, value)| {
                    translate(language, label);
                    translate(language, value);
                }),
                CardBody::Media { left, right } => left
                    .iter_mut()
                    .chain(right)
                    .for_each(|row| translate(language, &mut row.label)),
            }
        });
        results.fields.iter_mut().for_each(|(label, value)| {
            translate(language, label);
            translate(language, value);
        });
        if let Some(failure) = &mut results.failure {
            translate(language, &mut failure.text);
            translate_button(language, &mut failure.save_log);
        }
        if let Some(notice) = &mut results.notice {
            translate(language, notice);
        }
        translate_button(language, &mut results.view_log);
        translate_button(language, &mut results.submit_report);
    }
    if let Some(confirm) = &mut view.confirm {
        translate(language, &mut confirm.title);
        confirm
            .details
            .iter_mut()
            .for_each(|text| translate(language, text));
        translate(language, &mut confirm.danger);
        confirm
            .warnings
            .iter_mut()
            .for_each(|text| translate(language, text));
        if let Some(prompt) = &mut confirm.prompt {
            translate(language, prompt);
        }
        if let Some(note) = &mut confirm.note {
            translate(language, note);
        }
        translate(language, &mut confirm.ack_text);
        translate_button(language, &mut confirm.confirm);
        translate_button(language, &mut confirm.cancel);
    }
    if let Some(diagnostics) = &mut view.diagnostics {
        translate(language, &mut diagnostics.title);
        diagnostics
            .buttons
            .iter_mut()
            .for_each(|button| translate_button(language, button));
        translate(language, &mut diagnostics.hint);
        if let Some(notice) = &mut diagnostics.notice {
            translate(language, notice);
        }
    }
    if let Some(analysis) = &mut view.analysis {
        let mut tree = (*analysis.tree).clone();
        translate(language, &mut tree.title);
        translate(language, &mut tree.heading);
        tree.actions
            .iter_mut()
            .for_each(|button| translate_button(language, button));
        tree.nodes
            .iter_mut()
            .for_each(|node| translate_node(language, node));
        analysis.tree = Arc::new(tree);
        if let Some(notice) = &mut analysis.notice {
            translate(language, notice);
        }
    }
}

// ── the model ─────────────────────────────────────────────────────────────

/// Messages from the worker thread.
pub(crate) enum Msg {
    Event(Event),
    DriveAfter(String),
    FailureEvidence(workflow::UpdateFailure),
    UserGuidance(String),
    PreviewCompatibilityPending(bool),
    Analysis(ResultView),
    /// A flash passed every gate after its backup; the worker waits for the
    /// sheet's answer on the sender before writing.
    Authorized(FlashSheet, Sender<bool>),
    /// Backup capture failed; wait for an explicit human Yes or No.
    BackupUnavailable(String, Sender<bool>),
    Done(Result<Option<workflow::UpdateOutcome>, String>),
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
    WithoutBackup {
        reason: String,
        reply: Sender<bool>,
    },
    /// Recovery, asked after its read-only preparation has passed.
    Recovery {
        options: RecoveryOptions,
        plan: Vec<String>,
    },
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

/// Async file-origin result, tied to the chooser and path that requested it.
type OriginReply = (Pick, PathBuf, Result<workflow::FileOrigin, String>);

/// The whole application state. The shells hold none of their own.
pub struct App {
    pub(crate) language: crate::localization::Language,
    pub(crate) preferences: crate::localization::Preferences,
    journal: Option<Journal>,
    logging_warning: Option<String>,
    operation_id: Option<String>,
    failure_evidence: Option<workflow::UpdateFailure>,
    preview_compatibility_pending: Option<bool>,
    report_rx: Option<Receiver<Result<String, String>>>,
    report_control: Option<crate::support::Submission>,
    recovery_planning: Option<(Target, RecoveryOptions)>,
    origin_rx: Vec<Receiver<OriginReply>>,
    flash_origin: Option<Result<workflow::FileOrigin, String>>,
    recovery_origin: Option<Result<workflow::FileOrigin, String>>,
    pub(crate) profile: ProfileState,
    pub(crate) profile_rx: Option<Receiver<Result<Profile, String>>>,
    pub(crate) drives: Vec<DriveChoice>,
    pub(crate) device: String,
    pub(crate) task: Task,
    pub(crate) result_task: Task,
    pub(crate) flash_input: Option<PathBuf>,
    flash_current: Option<PathBuf>,
    flash_read: bool,
    flash_current_members: Vec<String>,
    flash_current_member: Option<String>,
    pub(crate) recovery_input: Option<PathBuf>,
    pub(crate) recovery_current: Option<PathBuf>,
    pub(crate) recovery_read: bool,
    recovery_member: Option<String>,
    recovery_members: Vec<String>,
    recovery_current_members: Vec<String>,
    recovery_current_member: Option<String>,
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
    backup_waived: bool,
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
        #[cfg(test)]
        let preferences = crate::localization::Preferences::Memory;
        #[cfg(not(test))]
        let preferences = crate::localization::Preferences::user();
        Self::with_preferences(drives, preferences)
    }

    pub(crate) fn with_preferences(
        drives: Vec<DriveChoice>,
        preferences: crate::localization::Preferences,
    ) -> Self {
        let device = drives.first().map(|d| d.path.clone()).unwrap_or_default();
        let mut startup_log = vec![crate::localization::english(
            "ui.ready_select_an_optical_drive_and_choose_an_action",
        )];
        let (journal, logging_warning) = if cfg!(test) {
            (None, None)
        } else {
            match Journal::open() {
                Ok(journal) => (Some(journal), None),
                Err(error) => {
                    startup_log.push(format!("Session history could not be opened: {error:#}"));
                    (Some(Journal::memory()), Some("errors.history".into()))
                }
            }
        };
        Self {
            language: preferences.load(),
            preferences,
            journal,
            logging_warning,
            operation_id: None,
            failure_evidence: None,
            preview_compatibility_pending: None,
            report_rx: None,
            report_control: None,
            recovery_planning: None,
            origin_rx: Vec::new(),
            flash_origin: None,
            recovery_origin: None,
            profile: ProfileState::NoDrive,
            profile_rx: None,
            drives,
            device,
            task: Task::Info,
            result_task: Task::Info,
            flash_input: None,
            flash_current: None,
            flash_read: true,
            flash_current_members: Vec::new(),
            flash_current_member: None,
            recovery_input: None,
            recovery_current: None,
            recovery_read: true,
            recovery_member: None,
            recovery_members: Vec::new(),
            recovery_current_members: Vec::new(),
            recovery_current_member: None,
            capture_as_backup: false,
            sources: [None, None],
            analysis: None,
            analysis_tree: None,
            analysis_open: false,
            analysis_notice: None,
            control: Control::default(),
            status: "status.ready".into(),
            failure: None,
            action: String::new(),
            risk_ack: false,
            pending: None,
            planning: None,
            flashing: None,
            backup_waived: false,
            cancelled: false,
            log: startup_log,
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
        let current = (!self.recovery_read
            && (self.recovery_current_members.len() < 2 || self.recovery_current_member.is_some()))
        .then(|| self.recovery_current.clone())
        .flatten();
        let member = self.recovery_current_member.clone();
        let waker = self.waker.clone();
        std::thread::spawn(move || {
            let profile = std::panic::catch_unwind(|| {
                workflow::capture_events(
                    |_| {},
                    || match current {
                        Some(ref path) => {
                            ops::profile_with_current(&device, path, member.as_deref())
                        }
                        None => ops::profile(&device),
                    },
                )
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
            Ok(profile) => {
                if profile.can_read == Some(false) {
                    self.flash_read = false;
                    self.recovery_read = false;
                }
                self.log.extend(profile.notes.iter().cloned());
                ProfileState::Ready(profile)
            }
            Err(error) => {
                self.log
                    .push(format!("Could not read the drive's profile: {error}"));
                ProfileState::Failed
            }
        };
    }

    fn ready_profile(&self) -> Option<&Profile> {
        match &self.profile {
            ProfileState::Ready(profile) => Some(profile),
            _ => None,
        }
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
        self.record_event(
            "drives_observed",
            serde_json::json!({
                "drives": self.drives.iter().map(DriveChoice::display).collect::<Vec<_>>()
            }),
        );
    }

    fn record_event(&mut self, kind: &str, mut data: serde_json::Value) {
        if let Some(id) = &self.operation_id {
            data["operation_id"] = id.clone().into();
        }
        if let Some(journal) = &mut self.journal {
            if let Err(error) = journal.record(kind, crate::localization::english_json(data)) {
                self.log
                    .push(format!("Could not save session history: {error:#}"));
                self.logging_warning
                    .get_or_insert_with(|| "errors.history".into());
            }
        }
    }

    pub(crate) fn device_label(&self) -> String {
        self.drives
            .iter()
            .find(|d| d.path == self.device)
            .map(DriveChoice::display)
            .unwrap_or_else(|| "drive.none".into())
    }

    fn selected(&self) -> bool {
        !self.device.is_empty()
    }

    /// Apply one user action; returns the work only the shell can do.
    pub fn dispatch(&mut self, input: Input) -> Vec<Effect> {
        match input {
            Input::SetLanguage(language) => {
                if self.language != language {
                    self.language = language;
                    if let Err(error) = self.preferences.save(language) {
                        self.log.push(format!(
                            "Language changed for this session but could not be saved: {error}"
                        ));
                    }
                }
            }
            Input::SelectDrive(i) => {
                if let Some(path) = self.drives.get(i).map(|d| d.path.clone()) {
                    if !self.busy() && path != self.device {
                        self.device = path;
                        self.flash_read = true;
                        self.recovery_read = true;
                        self.risk_ack = false;
                        self.rows.clear();
                        self.status = "status.ready".into();
                        self.failure = None;
                        return self.start_profile();
                    }
                }
            }
            Input::Refresh if !self.busy() => {
                self.discover();
                return self.start_profile();
            }
            Input::SelectTask(task) if !self.busy() => {
                self.task = task;
            }
            Input::Choose(pick) => return self.choose(pick),
            Input::Chosen(pick, path) => return self.chosen(pick, path),
            Input::SetCheck(CheckId::FlashReadFromDrive, on) if !self.busy() && self.can_read() => {
                if self.flash_read != on {
                    self.clear_flash_result();
                    self.flash_read = on;
                }
            }
            Input::SetCheck(CheckId::RecoveryReadFromDrive, on)
                if !self.busy() && self.can_read() =>
            {
                if self.recovery_read != on {
                    self.clear_flash_result();
                }
                self.recovery_read = on;
                return self.refresh_current_profile();
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
                return self.start_job("modify.drive_information", self.device.clone(), Job::Info);
            }
            action @ (Input::CheckFlashFile | Input::CheckRecoveryFile) if !self.busy() => {
                let input = if matches!(action, Input::CheckRecoveryFile) {
                    self.recovery_input.clone()
                } else {
                    self.flash_input.clone()
                };
                if let Some(input) = input {
                    return self.start_job("ui.check_file", String::new(), Job::InfoFile { input });
                }
            }
            Input::FlashNow if !self.busy() && self.flash_ready() => {
                if let Some(input) = self.flash_input.clone() {
                    let use_current = self.flash_current_supported() && !self.flash_read;
                    return self.plan_flash(FlashOptions {
                        current: use_current.then(|| self.flash_current.clone()).flatten(),
                        current_member: use_current
                            .then(|| self.flash_current_member.clone())
                            .flatten(),
                        input,
                        execute: true,
                        ..Default::default()
                    });
                }
            }
            Input::FlashCurrentMember(member) if !self.busy() => {
                if self.flash_current_members.contains(&member)
                    && self.flash_current_member.as_ref() != Some(&member)
                {
                    self.clear_flash_result();
                    self.flash_current_member = Some(member);
                }
            }
            Input::RecoveryMember(member) if !self.busy() => {
                if self.recovery_members.contains(&member) {
                    if self.recovery_member.as_ref() != Some(&member) {
                        self.clear_flash_result();
                    }
                    self.recovery_member = Some(member);
                }
            }
            Input::RecoveryCurrentMember(member) if !self.busy() => {
                if self.recovery_current_members.contains(&member) {
                    if self.recovery_current_member.as_ref() != Some(&member) {
                        self.clear_flash_result();
                    }
                    self.recovery_current_member = Some(member);
                    return self.refresh_current_profile();
                }
            }
            Input::Recover if !self.busy() && self.recovery_ready() => {
                let current = if self.recovery_read {
                    CurrentFirmware::ReadFromDrive
                } else if let Some(current) = self.recovery_current.clone() {
                    CurrentFirmware::File(current)
                } else {
                    CurrentFirmware::NotRequired
                };
                let target = self.target(FlashOptions {
                    input: self.recovery_input.clone().unwrap_or_default(),
                    execute: true,
                    ..Default::default()
                });
                let options = RecoveryOptions {
                    device: None,
                    input: target.options.input.clone(),
                    member: self.recovery_member.clone(),
                    current,
                    current_member: (!self.recovery_read)
                        .then(|| self.recovery_current_member.clone())
                        .flatten(),
                    execute: false,
                    acknowledged_risk: false,
                };
                let effects = self.start_job(
                    "ui.recovery_plan",
                    target.device.clone(),
                    Job::Recovery(options.clone()),
                );
                if !effects.is_empty() {
                    self.recovery_planning = Some((target, options));
                }
                return effects;
            }
            Input::Confirm => return self.confirm(),
            Input::CancelConfirm => {
                if let Some(Pending {
                    sheet: Sheet::Flash { reply, .. } | Sheet::WithoutBackup { reply, .. },
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
                self.status = "ui.cancelling_after_the_current_operation_returns".into();
            }
            Input::OpenDiagnostics => {
                self.diagnostics_open = true;
                self.diagnostic_notice = None;
                self.refresh_diagnostic_view();
            }
            Input::ViewLog => {
                if let Some(path) = self.diagnostic_log.as_ref().filter(|p| p.is_file()) {
                    return vec![Effect::OpenPath(path.clone())];
                }
                self.diagnostics_open = true;
                self.refresh_diagnostic_view();
            }
            Input::SubmitReport if self.report_rx.is_none() => {
                self.record_event("report_requested", serde_json::json!({}));
                let Some(journal) = &self.journal else {
                    self.diagnostic_notice = Some("ui.report_history_is_unavailable".into());
                    return Vec::new();
                };
                let source = journal.source();
                let (tx, rx) = mpsc::channel();
                let control = crate::support::Submission::new();
                self.report_control = Some(control.clone());
                self.report_rx = Some(rx);
                self.diagnostic_notice = Some("ui.opening_report_approval_in_your_browser".into());
                let waker = self.waker.clone();
                std::thread::spawn(move || {
                    let result = crate::support::submit(source, control, |message| {
                        let _ = tx.send(Ok(message));
                        if let Some(wake) = &waker {
                            wake();
                        }
                    });
                    let _ = tx.send(result.map_err(|error| format!("{error:#}")));
                    if let Some(wake) = &waker {
                        wake();
                    }
                });
                return vec![Effect::StartTicking];
            }
            Input::CancelReport => {
                if let Some(control) = &self.report_control {
                    control.cancel();
                    self.diagnostic_notice =
                        Some("ui.stopping_report_submission_after_the_current_reque".into());
                }
            }
            Input::CloseDiagnostics => self.diagnostics_open = false,
            Input::CopyDiagnostics => match self.diagnostic_text() {
                Ok(text) => return vec![Effect::CopyText(text)],
                Err(e) => {
                    self.log
                        .push(format!("Could not read diagnostic log: {e:#}"));
                    self.diagnostic_notice = Some("errors.read_log".into())
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
                let extensions = vec!["tar", "bin"];
                open(Some(FileFilter {
                    name: crate::localization::get(self.language, "filter.firmware_backup"),
                    extensions,
                }))
            }
            Pick::FlashCurrent
            | Pick::RecoveryCurrent
            | Pick::RecoveryInput
            | Pick::AnalysisFile(_) => open(Some(FileFilter {
                name: crate::localization::get(self.language, "filter.firmware"),
                extensions: workflow::file_extensions(),
            })),
            Pick::Backup | Pick::Dump if self.selected() => {
                let profile = self.ready_profile();
                let name = match pick {
                    Pick::Backup => profile.and_then(|p| p.backup_name.as_deref()),
                    _ => profile.and_then(|p| p.dump_name.as_deref()),
                };
                save(name.unwrap_or(if pick == Pick::Dump {
                    "drive-dump.bin"
                } else {
                    "drive-backup.tar"
                }))
            }
            Pick::AnalysisDrive(i) if self.drive_source_allowed(i) => save("inspection.backup.tar"),
            Pick::DiagnosticLog => save("freemkv-flash-diagnostic.log"),
            Pick::ReportText if self.analysis.is_some() => save("firmware-report.txt"),
            Pick::ReportJson if self.analysis.is_some() => save("firmware-report.json"),
            _ => Vec::new(),
        }
    }

    /// A previous flash result describes its original selection, not the new one.
    fn clear_flash_result(&mut self) {
        if self.result_task == self.task && matches!(self.task, Task::Flash | Task::Recovery) {
            self.status = "status.ready".into();
            self.failure = None;
            self.rows.clear();
            self.progress = None;
        }
    }

    fn chosen(&mut self, pick: Pick, path: PathBuf) -> Vec<Effect> {
        match pick {
            Pick::DiagnosticLog => {
                let result = self
                    .diagnostic_text()
                    .and_then(|text| std::fs::write(&path, text));
                self.diagnostic_notice = Some(match result {
                    Ok(()) => crate::localization::message(
                        "notice.log_saved",
                        &[("path", path.display().to_string())],
                    ),
                    Err(error) => {
                        self.log
                            .push(format!("Could not export diagnostic log: {error:#}"));
                        "errors.save_report".into()
                    }
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
                    Ok(()) => crate::localization::message(
                        "notice.report_saved",
                        &[("path", path.display().to_string())],
                    ),
                    Err(e) => {
                        self.log.push(format!("Could not save report: {e:#}"));
                        "errors.save_report".into()
                    }
                });
            }
            _ if self.busy() => {}
            Pick::CheckFile => {
                return self.start_job(
                    "ui.check_file",
                    String::new(),
                    Job::InfoFile { input: path },
                )
            }
            Pick::FlashFirmware => {
                self.clear_flash_result();
                self.flash_input = Some(path.clone());
                return self.read_origin(pick, path);
            }
            Pick::RecoveryCurrent => {
                self.clear_flash_result();
                self.recovery_read = false;
                self.recovery_current_members =
                    workflow::recovery_members(&path).unwrap_or_default();
                self.recovery_current_member = None;
                self.recovery_current = Some(path);
                return self.refresh_current_profile();
            }
            Pick::FlashCurrent => {
                self.clear_flash_result();
                self.flash_read = false;
                self.flash_current_members = workflow::recovery_members(&path).unwrap_or_default();
                self.flash_current_member = None;
                self.flash_current = Some(path);
            }
            Pick::RecoveryInput => {
                self.clear_flash_result();
                self.recovery_member = None;
                self.recovery_members = workflow::recovery_members(&path).unwrap_or_default();
                self.recovery_input = Some(path.clone());
                return self.read_origin(pick, path);
            }
            Pick::Backup | Pick::Dump if self.selected() => {
                // The native save panel has already confirmed replacing an existing file.
                let replace = path.symlink_metadata().is_ok();
                let (label, job) = if pick == Pick::Dump {
                    ("ui.raw_dump", Job::Dump { out: path, replace })
                } else {
                    ("task.backup", Job::Backup { out: path, replace })
                };
                return self.start_job(label, self.device.clone(), job);
            }
            Pick::Backup | Pick::Dump => {}
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

    fn refresh_current_profile(&mut self) -> Vec<Effect> {
        if self.ready_profile().is_none_or(|profile| {
            !profile.tasks.contains(&Task::Recovery) || profile.recovery_without_live_protocol
        }) {
            self.start_profile()
        } else {
            Vec::new()
        }
    }

    fn recovery_ready(&self) -> bool {
        self.selected()
            && self.recovery_input.is_some()
            && (self.recovery_members.len() < 2 || self.recovery_member.is_some())
            && (self.recovery_read
                || (self.recovery_current.is_some()
                    && (self.recovery_current_members.len() < 2
                        || self.recovery_current_member.is_some())))
    }

    fn flash_current_supported(&self) -> bool {
        self.ready_profile()
            .is_some_and(|p| p.flash_current || p.can_read == Some(false))
    }

    fn can_read(&self) -> bool {
        self.ready_profile()
            .and_then(|profile| profile.can_read)
            .unwrap_or(true)
    }

    fn has_origin_error(&self) -> bool {
        match self.task {
            Task::Flash => self.flash_origin.as_ref().is_some_and(Result::is_err),
            Task::Recovery => self.recovery_origin.as_ref().is_some_and(Result::is_err),
            _ => false,
        }
    }

    fn flash_ready(&self) -> bool {
        self.selected()
            && self.flash_input.is_some()
            && (!self.flash_current_supported()
                || self.flash_read
                || (self.flash_current.is_some()
                    && (self.flash_current_members.len() < 2
                        || self.flash_current_member.is_some())))
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
        let effects = self.start_job("ui.flash_plan", target.device.clone(), job);
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
            "ui.firmware_update",
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
        let backup_question = self
            .pending
            .as_ref()
            .is_some_and(|pending| matches!(pending.sheet, Sheet::WithoutBackup { .. }));
        if !self.risk_ack && !backup_question {
            return Vec::new();
        }
        match self.pending.take() {
            Some(Pending {
                sheet: Sheet::WithoutBackup { reply, .. },
                ..
            }) => {
                self.backup_waived = true;
                self.risk_ack = false;
                let _ = reply.send(true);
                Vec::new()
            }
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
                sheet: Sheet::Recovery { mut options, .. },
            }) if !self.running() => {
                options.execute = true;
                options.acknowledged_risk = true;
                let job = Job::Recovery(options);
                self.start_job("task.recovery", target.device, job)
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
            self.log.push(format!(
                "{}: not run by the GUI gate.",
                crate::localization::english(label)
            ));
            return Vec::new();
        }
        if self.running() {
            return Vec::new();
        }
        if device.is_empty() && !matches!(job, Job::InfoFile { .. } | Job::Analysis { .. }) {
            self.log.push("ui.no_optical_drive_selected".into());
            return Vec::new();
        }
        self.result_task = self.task;
        self.action = label.to_string();
        self.status = crate::localization::message(
            "status.operation_running",
            &[("operation", label.into())],
        );
        self.failure = None;
        self.failure_evidence = None;
        self.backup_waived = false;
        self.preview_compatibility_pending = None;
        self.log.clear();
        self.diagnostic_log = None;
        self.diagnostic_checked = None;
        self.diagnostic_notice = None;
        self.progress = None;
        self.rows.clear();
        self.info_result = matches!(job, Job::Info);
        self.log
            .push(format!("{}: {device}", crate::localization::english(label)));
        self.operation_id = Some(workflow::new_operation_id());
        self.record_event(
            "operation_started",
            serde_json::json!({
                "operation": label,
                "drive_before": self.device_label(),
                "device": device,
                "input": match &job {
                    Job::Flash(o) | Job::PlanFlash(o) => Some(o.input.display().to_string()),
                    Job::Recovery(o) => Some(o.input.display().to_string()),
                    Job::InfoFile { input } => Some(input.display().to_string()),
                    _ => None,
                }
            }),
        );
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        #[cfg(test)]
        if let Some(jobs) = &mut self.dry_run {
            jobs.push((crate::localization::english(label), device, job));
            self.worker = Some(tx);
            return vec![Effect::StartTicking];
        }
        let waker = self.waker.clone();
        let operation_id = self
            .operation_id
            .clone()
            .expect("started operation has an id");
        std::thread::spawn(move || run_job(&device, job, tx, waker, operation_id));
        vec![Effect::StartTicking]
    }

    /// Drain the worker's events; call on every tick or repaint.
    pub fn poll(&mut self) -> Vec<Effect> {
        let mut report_done = false;
        if let Some(rx) = self.report_rx.take() {
            loop {
                match rx.try_recv() {
                    Ok(Ok(message)) => self.diagnostic_notice = Some(message),
                    Ok(Err(error)) => {
                        self.log.push(format!("Could not submit report: {error}"));
                        self.diagnostic_notice = Some(
                            if self
                                .report_control
                                .as_ref()
                                .is_some_and(|control| control.cancelled())
                            {
                                "report.cancelled"
                            } else {
                                "errors.submit_report"
                            }
                            .into(),
                        );
                        report_done = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        report_done = true;
                        break;
                    }
                }
            }
            if !report_done {
                self.report_rx = Some(rx);
            } else {
                self.report_control = None;
            }
        }
        let origin_done = self.poll_origin();
        let profiled = self.poll_profile();
        let mut finished = false;
        let mut planned = None;
        let mut recovery_planned = None;
        if let Some(rx) = self.rx.take() {
            loop {
                match rx.try_recv() {
                    Ok(Msg::Event(event)) => self.event(event),
                    Ok(Msg::FailureEvidence(evidence)) => self.failure_evidence = Some(evidence),
                    Ok(Msg::UserGuidance(message)) => self.failure = Some(message),
                    Ok(Msg::PreviewCompatibilityPending(pending)) => {
                        self.preview_compatibility_pending = Some(pending);
                    }
                    Ok(Msg::DriveAfter(label)) => {
                        self.record_event("drive_after", serde_json::json!({"drive": label}))
                    }
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
                    Ok(Msg::BackupUnavailable(reason, reply)) => match self.flashing.clone() {
                        Some(target) => self.ask(target, Sheet::WithoutBackup { reason, reply }),
                        None => {
                            let _ = reply.send(false);
                        }
                    },
                    Ok(Msg::Done(result)) => {
                        recovery_planned = self.recovery_planning.take().filter(|_| {
                            matches!(result, Ok(Some(workflow::UpdateOutcome::Planned)))
                        });
                        planned = self.planning.take().filter(|_| result.is_ok());
                        self.end_flash();
                        let cancelled = std::mem::take(&mut self.cancelled);
                        match &result {
                            Ok(Some(outcome)) => {
                                self.status = crate::localization::message(
                                    "status.operation_result",
                                    &[
                                        ("operation", self.action.clone()),
                                        ("result", outcome.summary().into()),
                                    ],
                                )
                            }
                            Ok(None) if self.preview_compatibility_pending == Some(true) => {
                                self.status = "status.package_checked".into();
                            }
                            Ok(None) => {
                                self.status = crate::localization::message(
                                    "status.operation_complete",
                                    &[("operation", self.action.clone())],
                                )
                            }
                            Err(_) if cancelled => {
                                self.status = crate::localization::message(
                                    "status.operation_cancelled",
                                    &[("operation", self.action.clone())],
                                );
                                self.failure = None
                            }
                            Err(_) => {
                                let consequence = self.failure_evidence.as_ref().map(|evidence| {
                                    if evidence.temporary_firmware {
                                        "errors.temporary_firmware"
                                    } else if evidence.write_started {
                                        "errors.partial_firmware"
                                    } else {
                                        "errors.update_not_started"
                                    }
                                });
                                let blocked = self
                                    .failure_evidence
                                    .as_ref()
                                    .is_some_and(|e| !e.write_started && !e.temporary_firmware);
                                let message = if blocked {
                                    "errors.update_blocked"
                                } else {
                                    "errors.operation_failed"
                                }
                                .to_string();
                                let consequence = if blocked { None } else { consequence };
                                let message = consequence.map_or(message.clone(), |key| {
                                    crate::localization::message(
                                        "ui.join",
                                        &[("first", message.clone()), ("second", key.into())],
                                    )
                                });
                                self.status = message.clone();
                                // Keep the summary localized; precheck guidance names the
                                // stopped stage and actionable reason without technical hashes.
                                self.failure = Some(self.failure.take().unwrap_or(message));
                            }
                        }
                        let update_evidence = result
                            .as_ref()
                            .ok()
                            .and_then(Option::as_ref)
                            .map(outcome_json);
                        let result_kind = match &result {
                            Err(_) if cancelled => "cancelled",
                            Err(_)
                                if self
                                    .failure_evidence
                                    .as_ref()
                                    .is_some_and(|e| !e.write_started && !e.temporary_firmware) =>
                            {
                                "blocked"
                            }
                            Err(_) => "error",
                            Ok(None) if self.preview_compatibility_pending == Some(true) => {
                                "prechecked"
                            }
                            Ok(Some(workflow::UpdateOutcome::Planned)) => "planned",
                            Ok(Some(outcome)) if !outcome.safe_to_probe() => "uncertain",
                            Ok(Some(outcome)) if !outcome.fully_verified() => {
                                "limited_verification"
                            }
                            Ok(_) => "success",
                        };
                        self.log.push(match result {
                            Ok(Some(outcome)) => format!(
                                "{} {}",
                                crate::localization::english(&self.action),
                                outcome.summary()
                            ),
                            Ok(None) if self.preview_compatibility_pending == Some(true) => {
                                self.status.clone()
                            }
                            Ok(None) => "✓ done.".into(),
                            Err(_) if cancelled => CANCELLED.into(),
                            Err(e) => format!(
                                "✗ {}: {}",
                                crate::localization::english(&self.status),
                                crate::localization::english(&e)
                            ),
                        });
                        self.record_event("operation_finished", serde_json::json!({
                            "operation": self.action,
                            "result": result_kind,
                            "summary": self.status,
                            "error": self.failure,
                            "failure": self.failure.as_ref().map(|_| failure_json(self.failure_evidence.as_ref())),
                            "update": update_evidence,
                            "compatibility_pending": self.preview_compatibility_pending,
                        }));
                        self.operation_id = None;
                        finished = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.planning = None;
                        self.recovery_planning = None;
                        self.end_flash();
                        self.status = "ui.operation_interrupted".into();
                        self.failure = Some(WORKER_GONE.into());
                        self.log
                            .push("ui.worker_disconnected_before_reporting_completion_op".into());
                        self.record_event(
                            "operation_finished",
                            serde_json::json!({
                                "operation": self.action, "result": "interrupted",
                                "summary": self.status, "error": self.failure,
                                "failure": failure_json(self.failure_evidence.as_ref()),
                            }),
                        );
                        self.operation_id = None;
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
        if let Some((target, options)) = recovery_planned {
            let plan = self
                .rows
                .iter()
                .filter_map(gui_pair)
                .map(|(label, value)| format!("{label}: {value}"))
                .collect();
            self.ask(target, Sheet::Recovery { options, plan });
        }
        let due = self.diagnostic_checked.is_none_or(|checked| {
            finished || (self.running() && checked.elapsed() >= DIAGNOSTIC_REFRESH)
        });
        if self.diagnostics_open && due {
            self.refresh_diagnostic_view();
        }
        if (finished || profiled || origin_done || report_done)
            && !self.running()
            && self.profile_rx.is_none()
            && self.origin_rx.is_empty()
            && self.report_rx.is_none()
        {
            vec![Effect::StopTicking]
        } else {
            Vec::new()
        }
    }

    fn read_origin(&mut self, pick: Pick, path: PathBuf) -> Vec<Effect> {
        match pick {
            Pick::FlashFirmware => self.flash_origin = None,
            Pick::RecoveryInput => self.recovery_origin = None,
            _ => return Vec::new(),
        }
        let (tx, rx) = mpsc::channel();
        self.origin_rx.push(rx);
        let waker = self.waker.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(|| workflow::selected_file_origin(&path))
                .map_err(|_| "ui.file_origin_inspection_stopped_unexpectedly".to_string())
                .and_then(|r| r.map_err(|e| format!("{e:#}")));
            let _ = tx.send((pick, path, result));
            if let Some(wake) = waker {
                wake();
            }
        });
        vec![Effect::StartTicking]
    }

    fn poll_origin(&mut self) -> bool {
        let mut done = false;
        for rx in std::mem::take(&mut self.origin_rx) {
            match rx.try_recv() {
                Ok((pick, path, result)) => {
                    let selected = (pick == Pick::FlashFirmware
                        && self.flash_input.as_ref() == Some(&path))
                        || (pick == Pick::RecoveryInput
                            && self.recovery_input.as_ref() == Some(&path));
                    if selected {
                        if let Err(error) = &result {
                            let detail = crate::localization::english(error);
                            self.log
                                .push(format!("File origin inspection failed: {detail}"));
                            self.record_event("file_origin_failed", serde_json::json!({"file": path.display().to_string(), "error": detail}));
                            self.diagnostic_log = None;
                            self.diagnostic_checked = None;
                        }
                    }
                    match pick {
                        Pick::FlashFirmware if self.flash_input.as_ref() == Some(&path) => {
                            self.flash_origin = Some(result)
                        }
                        Pick::RecoveryInput if self.recovery_input.as_ref() == Some(&path) => {
                            self.recovery_origin = Some(result)
                        }
                        _ => {}
                    }
                }
                Err(TryRecvError::Empty) => {
                    self.origin_rx.push(rx);
                    continue;
                }
                Err(TryRecvError::Disconnected) => {}
            }
            done = true;
        }
        done
    }

    fn origin_items(&self, recovery: bool) -> Vec<Item> {
        let origin = if recovery {
            &self.recovery_origin
        } else {
            &self.flash_origin
        };
        match origin {
            Some(Ok(origin)) => vec![
                Item::Origin(*origin),
                Item::Note(match origin {
                    workflow::FileOrigin::OemLikely => {
                        "ui.matches_known_oem_firmware_drive_compatibility_is_".into()
                    }
                    _ => origin.explanation().into(),
                }),
            ],
            Some(Err(_error)) => vec![
                Item::Origin(workflow::FileOrigin::Unknown),
                Item::Note("origin.inspect_failed".into()),
            ],
            None => vec![Item::Note("ui.checking_file_origin".into())],
        }
    }

    /// A flash job ended: its sheet, if still open, has no one to answer.
    fn end_flash(&mut self) {
        self.flashing = None;
        if matches!(
            self.pending,
            Some(Pending {
                sheet: Sheet::Flash { .. } | Sheet::WithoutBackup { .. },
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
                    self.record_event("stage", serde_json::json!({"name": label, "total": total}));
                }
                self.progress = Some((label, done, total));
            }
            Event::Report(report) => {
                for row in report.rows {
                    match row.gui_label.as_deref() {
                        Some("Diagnostic warning") => {
                            self.logging_warning = Some(row.value.plain())
                        }
                        Some(DIAGNOSTIC_FIELD) => {
                            let path = row.value.plain();
                            self.record_event("diagnostic", serde_json::json!({"log_file": path}));
                            self.diagnostic_log = Some(path.into())
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
        let saved = self.diagnostic_log.as_ref().map(std::fs::read_to_string);
        if let Some(Ok(text)) = saved.as_ref() {
            return Ok(text.clone());
        }
        if self.failure.is_some() || self.has_origin_error() {
            return Ok(format!(
                "In-memory diagnostics; no diagnostic file was saved.\n{}\n{}",
                self.log
                    .iter()
                    .map(|line| crate::localization::english(line))
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.failure
                    .as_ref()
                    .map(|failure| crate::localization::english(failure))
                    .unwrap_or_default()
            ));
        }
        match saved {
            Some(result) => result,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No diagnostic log is available for this operation.",
            )),
        }
    }

    pub(crate) fn refresh_diagnostic_view(&mut self) {
        self.diagnostic_lines = Arc::new(match self.diagnostic_text() {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) => vec![format!("Could not read diagnostic log: {error:#}")],
        });
        self.diagnostic_checked = Some(Instant::now());
    }

    // ── view ──────────────────────────────────────────────────────────────

    /// The complete, fully-decided description of what to show.
    pub fn view(&self) -> View {
        let enabled = !self.busy();
        let shown = self.result_task == self.task;
        let mut view = View {
            title: format!(
                "{} {}",
                crate::localization::get(self.language, "app.name"),
                env!("CARGO_PKG_VERSION")
            ),
            language: self.language,
            drives: DriveBar {
                label: "drive.label".into(),
                items: self
                    .drives
                    .iter()
                    .map(|d| DriveItem {
                        text: d.display(),
                        tooltip: d.path.clone(),
                    })
                    .collect(),
                selected: self.drives.iter().position(|d| d.path == self.device),
                placeholder: "drive.none".into(),
                refresh: Button::new("action.refresh", Input::Refresh, enabled),
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
                    title: task.message_id().into(),
                    enabled,
                })
                .collect(),
            task: self.task,
            panel: self.panel(enabled),
            controls_enabled: enabled,
            status: shown.then(|| self.status_view()),
            results: (shown || self.has_origin_error()).then(|| {
                let mut results = self.results_view();
                if !shown {
                    results.cards.clear();
                    results.fields.clear();
                    results.failure = None;
                    results.open_results = None;
                }
                results
            }),
            confirm: self.pending.as_ref().map(|p| self.confirm_view(p)),
            log: self
                .log
                .iter()
                .map(|line| crate::localization::english(line))
                .collect(),
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
        };
        translate_view(&mut view);
        view
    }

    fn panel(&self, enabled: bool) -> Vec<Item> {
        // Profile labels are advisory. Each operation performs its own live
        // identification and authorization; a BOOT or failed profile must not
        // prevent reaching Recovery or preparing a Flash operation.
        let selected = self.selected();
        match self.task {
            Task::Info => {
                let mut items = vec![Item::Buttons {
                    label: None,
                    buttons: vec![
                        Button::primary("action.read_info", Input::ReadInfo, enabled && selected),
                        Button::new("action.check_file", Input::Choose(Pick::CheckFile), enabled),
                    ],
                }];
                if !selected {
                    items.push(Item::Note("info.connect_drive".into()));
                }
                items
            }
            Task::Inspect | Task::Compare => self.analysis_panel(enabled),
            Task::Backup | Task::Dump => {
                let dump = self.task == Task::Dump;
                vec![
                    Item::Text(if dump {
                        "ui.capture_all_accessible_drive_memory_into_a_raw_fil".into()
                    } else {
                        "ui.save_firmware_backup_files_for_restoration".into()
                    }),
                    Item::Buttons {
                        label: None,
                        buttons: vec![if dump {
                            Button::primary(
                                "ui.save_raw_dump",
                                Input::Choose(Pick::Dump),
                                enabled && selected,
                            )
                        } else {
                            Button::primary(
                                "ui.save_backup",
                                Input::Choose(Pick::Backup),
                                enabled && selected,
                            )
                        }],
                    },
                ]
            }
            Task::Flash | Task::Recovery => {
                self.firmware_panel(enabled, self.task == Task::Recovery)
            }
        }
    }

    fn firmware_panel(&self, enabled: bool, recovery: bool) -> Vec<Item> {
        let (input, current, read, members, member, current_pick, input_pick, check) = if recovery {
            (
                &self.recovery_input,
                &self.recovery_current,
                self.recovery_read,
                &self.recovery_current_members,
                &self.recovery_current_member,
                Pick::RecoveryCurrent,
                Pick::RecoveryInput,
                CheckId::RecoveryReadFromDrive,
            )
        } else {
            (
                &self.flash_input,
                &self.flash_current,
                self.flash_read,
                &self.flash_current_members,
                &self.flash_current_member,
                Pick::FlashCurrent,
                Pick::FlashFirmware,
                CheckId::FlashReadFromDrive,
            )
        };
        let path = |text: &str, pick, on: bool, file: &Option<PathBuf>| Item::Path {
            button: Button::new(text, Input::Choose(pick), enabled && on),
            path: file.as_deref().map(PathView::of),
        };
        let mut items = Vec::new();
        if recovery {
            items.push(Item::Warning(FORCE_WARNING.into()));
        }
        if recovery || self.flash_current_supported() {
            items.push(Item::Heading("ui.current_firmware".into()));
            if self.can_read() {
                items.push(Item::Check {
                    id: check,
                    text: "ui.read_from_drive".into(),
                    checked: read,
                    enabled,
                });
            } else {
                items.push(Item::Note("current.choose_installed".into()));
            }
            items.push(path("ui.choose_current", current_pick, !read, current));
            if read {
                items.push(Item::Note(
                    "ui.use_the_drive_to_identify_the_installed_firmware_i".into(),
                ));
            } else if members.len() > 1 {
                items.push(Item::Buttons {
                    label: Some("ui.current_firmware_member".into()),
                    buttons: members
                        .iter()
                        .map(|name| {
                            Button::primary(
                                &format!(
                                    "{}{}",
                                    if member.as_ref() == Some(name) {
                                        "Selected: "
                                    } else {
                                        ""
                                    },
                                    name
                                ),
                                if recovery {
                                    Input::RecoveryCurrentMember(name.clone())
                                } else {
                                    Input::FlashCurrentMember(name.clone())
                                },
                                enabled,
                            )
                        })
                        .collect(),
                });
            }
        }
        items.extend([
            Item::Heading("ui.firmware_to_flash".into()),
            path(
                if input.is_some() {
                    "action.change_file"
                } else {
                    "action.choose_firmware"
                },
                input_pick,
                true,
                input,
            ),
        ]);
        if recovery && self.recovery_members.len() > 1 {
            items.push(Item::Note(
                "ui.select_exactly_one_image_to_recover_no_second_stag".into(),
            ));
            items.push(Item::Buttons {
                label: Some("ui.recovery_image".into()),
                buttons: self
                    .recovery_members
                    .iter()
                    .map(|name| {
                        Button::primary(
                            &if self.recovery_member.as_ref() == Some(name) {
                                crate::localization::message(
                                    "notice.selected_member",
                                    &[("member", name.clone())],
                                )
                            } else {
                                name.clone()
                            },
                            Input::RecoveryMember(name.clone()),
                            enabled,
                        )
                    })
                    .collect(),
            });
        }
        if input.is_some() {
            items.extend(self.origin_items(recovery));
        }
        items.push(Item::Buttons {
            label: None,
            buttons: vec![
                Button::primary(
                    if recovery {
                        "ui.recover"
                    } else {
                        "ui.flash_now"
                    },
                    if recovery {
                        Input::Recover
                    } else {
                        Input::FlashNow
                    },
                    enabled
                        && if recovery {
                            self.recovery_ready()
                        } else {
                            self.flash_ready()
                        },
                ),
                Button {
                    enabled: enabled && input.is_some(),
                    ..Button::link(
                        "ui.check_file",
                        if recovery {
                            Input::CheckRecoveryFile
                        } else {
                            Input::CheckFlashFile
                        },
                    )
                },
            ],
        });
        items
    }

    fn analysis_panel(&self, enabled: bool) -> Vec<Item> {
        let compare = self.compare();
        let mut items = Vec::new();
        for i in 0..if compare { 2 } else { 1 } {
            let label = match (compare, i) {
                (false, _) => "ui.source",
                (true, 0) => "ui.source_a",
                _ => "ui.source_b",
            };
            items.push(Item::Buttons {
                label: Some(label.into()),
                buttons: vec![
                    Button::new(
                        "ui.firmware_file",
                        Input::Choose(Pick::AnalysisFile(i)),
                        enabled,
                    ),
                    Button::new(
                        "ui.selected_drive",
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
                }) => crate::localization::message(
                    "ui.device_capture_arg0_arg1",
                    &[
                        ("device", device.to_string()),
                        ("arg0", format!("{}", capture.display())),
                        (
                            "arg1",
                            (if *as_backup {
                                "source.backup_suffix"
                            } else {
                                ""
                            })
                            .to_string(),
                        ),
                    ],
                ),
                Some(Source::Analyzed(a)) => crate::localization::message(
                    "ui.retained_analysis_arg0",
                    &[("arg0", a.source.to_string())],
                ),
                None => "ui.choose_a_firmware_file_or_drive".into(),
            }));
        }
        items.push(Item::Check {
            id: CheckId::CaptureAsBackup,
            text: "ui.save_a_drive_capture_as_a_backup".into(),
            checked: self.capture_as_backup,
            enabled,
        });
        let ready = self.sources[0].is_some() && (!compare || self.sources[1].is_some());
        items.push(Item::Buttons {
            label: None,
            buttons: vec![Button::new(
                if compare {
                    "task.compare"
                } else {
                    "task.inspect"
                },
                Input::RunAnalysis,
                enabled && ready,
            )],
        });
        items
    }

    fn status_view(&self) -> Status {
        let running = self.running();
        let analysis = matches!(self.task, Task::Inspect | Task::Compare);
        let text = if running {
            match &self.progress {
                Some((label, done, total)) if *total > 0 => crate::localization::message(
                    "status.progress",
                    &[
                        ("operation", self.action.clone()),
                        ("stage", label.clone()),
                        ("percent", (done.saturating_mul(100) / total).to_string()),
                    ],
                ),
                Some((label, _, _)) => crate::localization::message(
                    "status.stage",
                    &[("operation", self.action.clone()), ("stage", label.clone())],
                ),
                None => self.status.clone(),
            }
        } else {
            self.status.clone()
        };
        Status {
            text,
            running,
            progress: running.then(|| match &self.progress {
                Some((label, done, total)) => Progress {
                    label: if label.is_empty() {
                        "ui.working".into()
                    } else {
                        String::new()
                    },
                    fraction: Some(*done as f32 / (*total).max(1) as f32),
                },
                None => Progress {
                    label: String::new(),
                    fraction: None,
                },
            }),
            note: running.then(|| KEEP_CONNECTED.to_owned()),
            cancel: (running && analysis)
                .then(|| Button::new("ui.cancel_analysis", Input::CancelAnalysis, true)),
        }
    }

    fn results_view(&self) -> Results {
        let analysis = matches!(self.task, Task::Inspect | Task::Compare);
        let info = self.result_task == Task::Info && self.info_result && !self.rows.is_empty();
        let concise = matches!(self.task, Task::Flash | Task::Recovery);
        Results {
            open_results: (analysis && self.analysis.is_some())
                .then(|| Button::new("ui.open_results", Input::OpenResults, true)),
            cards: if info {
                info_cards(&self.rows)
            } else {
                Vec::new()
            },
            fields: if info || concise {
                Vec::new()
            } else {
                self.rows.iter().filter_map(gui_pair).collect()
            },
            failure: self.failure.as_ref().map(|text| Failure {
                text: text.clone(),
                save_log: Button::new("action.save_log", Input::Choose(Pick::DiagnosticLog), true),
            }),
            notice: match (&self.logging_warning, &self.diagnostic_notice) {
                (Some(warning), Some(notice)) => Some(crate::localization::message(
                    "notice.join",
                    &[("first", warning.clone()), ("second", notice.clone())],
                )),
                (Some(warning), None) => Some(warning.clone()),
                (None, notice) => notice.clone(),
            },
            view_log: Button::new(
                "action.view_log",
                Input::ViewLog,
                self.diagnostic_log.is_some() || self.failure.is_some() || self.has_origin_error(),
            ),
            submit_report: if self.report_rx.is_some() {
                Button::new(
                    "ui.cancel_report",
                    Input::CancelReport,
                    self.report_control.as_ref().is_some_and(|c| !c.cancelled()),
                )
            } else {
                Button::new(
                    "action.submit_report",
                    Input::SubmitReport,
                    self.journal.is_some(),
                )
            },
        }
    }

    fn confirm_view(&self, pending: &Pending) -> Confirm {
        let mut details = vec![
            crate::localization::message(
                "confirm.drive",
                &[("drive", pending.target.label.clone())],
            ),
            crate::localization::message(
                "confirm.image",
                &[("path", pending.target.options.input.display().to_string())],
            ),
        ];
        let (recovery, warnings, prompt) = match &pending.sheet {
            Sheet::WithoutBackup { reason, .. } => {
                return Confirm {
                    title: "backup.unavailable".into(),
                    details,
                    danger: String::new(),
                    warnings: vec![reason.clone()],
                    prompt: Some("backup.proceed".into()),
                    note: None,
                    ack_text: String::new(),
                    ack_checked: false,
                    confirm: Button::primary("action.yes", Input::Confirm, true),
                    cancel: Button::new("action.no", Input::CancelConfirm, true),
                };
            }
            Sheet::Recovery { options, plan } => {
                details.extend(plan.iter().cloned());
                details.push(match &options.current {
                    CurrentFirmware::NotRequired => {
                        "ui.receiver_detected_directly_no_current_firmware_req".into()
                    }
                    CurrentFirmware::File(path) => crate::localization::message(
                        "ui.current_arg0",
                        &[("arg0", format!("{}", path.display()))],
                    ),
                    CurrentFirmware::ReadFromDrive => "ui.current_read_from_drive".into(),
                });
                if let Some(member) = &options.current_member {
                    details.push(crate::localization::message(
                        "ui.current_member_receiver_reference_member",
                        &[("member", member.to_string())],
                    ));
                }
                if let Some(member) = &options.member {
                    details.push(crate::localization::message(
                        "ui.target_member_will_be_flashed_member",
                        &[("member", member.to_string())],
                    ));
                }
                (true, vec![FORCE_WARNING.to_string()], None)
            }
            Sheet::Flash { sheet, .. } => {
                details.extend(sheet.plan.iter().cloned());
                details.push(match &pending.target.options.current {
                    Some(path) => crate::localization::message(
                        "ui.current_arg0",
                        &[("arg0", format!("{}", path.display()))],
                    ),
                    None => "ui.current_read_from_drive".into(),
                });
                if let Some(member) = &pending.target.options.current_member {
                    details.push(crate::localization::message(
                        "ui.current_member_receiver_reference_member",
                        &[("member", member.to_string())],
                    ));
                }
                (false, sheet.warnings.clone(), sheet.confirmation.clone())
            }
        };
        let origin = if recovery {
            &self.recovery_origin
        } else {
            &self.flash_origin
        };
        let origin = origin
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .copied()
            .unwrap_or(workflow::FileOrigin::Unknown);
        details.push(crate::localization::message(
            "ui.file_origin_arg0_arg1",
            &[
                ("arg0", origin.label().to_string()),
                ("arg1", origin.explanation().to_string()),
            ],
        ));
        Confirm {
            title: if recovery {
                "ui.confirm_recovery"
            } else {
                "ui.confirm_flash"
            }
            .into(),
            details,
            danger: FLASH_DANGER.into(),
            warnings,
            prompt,
            note: (!recovery && !self.backup_waived).then(|| BACKUP_KEPT.to_owned()),
            ack_text: RISK_ACK.into(),
            ack_checked: self.risk_ack,
            confirm: Button::primary(
                if recovery {
                    "ui.recover"
                } else {
                    "ui.flash_now"
                },
                Input::Confirm,
                self.risk_ack,
            ),
            cancel: Button::new("ui.cancel", Input::CancelConfirm, true),
        }
    }

    fn diagnostics_view(&self) -> Diagnostics {
        Diagnostics {
            title: "ui.diagnostic_log".into(),
            buttons: vec![
                Button::new("modify.copy_diagnostic_log", Input::CopyDiagnostics, true),
                Button::new("action.save_log", Input::Choose(Pick::DiagnosticLog), true),
                Button::new("menu.close", Input::CloseDiagnostics, true),
            ],
            hint: "ui.attach_this_log_to_your_bug_report".into(),
            path: self
                .diagnostic_log
                .as_ref()
                .map(|p| p.display().to_string()),
            notice: match (&self.logging_warning, &self.diagnostic_notice) {
                (Some(warning), Some(notice)) => Some(crate::localization::message(
                    "notice.join",
                    &[("first", warning.clone()), ("second", notice.clone())],
                )),
                (Some(warning), None) => Some(warning.clone()),
                (None, notice) => notice.clone(),
            },
            lines: self.diagnostic_lines.clone(),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

fn failure_json(evidence: Option<&workflow::UpdateFailure>) -> serde_json::Value {
    match evidence {
        Some(e) => serde_json::json!({
            "phase": e.phase, "write_started": e.write_started,
            "temporary_firmware": e.temporary_firmware, "completed_stages": e.completed_stages,
            "safe_to_probe": false,
        }),
        None => serde_json::json!({
            "phase": "unknown", "write_started": null, "temporary_firmware": null,
            "completed_stages": null, "safe_to_probe": false,
        }),
    }
}

fn outcome_json(outcome: &workflow::UpdateOutcome) -> serde_json::Value {
    match outcome {
        workflow::UpdateOutcome::Planned => serde_json::json!({"state": "planned"}),
        workflow::UpdateOutcome::Completed(e) => serde_json::json!({
            "state": "completed", "target_started": e.target_started,
            "target_identity": e.target_identity,
            "verified_regions": e.verified_regions, "unverified_regions": e.unverified_regions,
            "completed_stages": e.completed_stages, "temporary_firmware": e.temporary_firmware,
            "fully_verified": outcome.fully_verified(), "safe_to_probe": outcome.safe_to_probe(),
        }),
    }
}

fn post_update_snapshot(
    result: &Result<Option<workflow::UpdateOutcome>, String>,
    probe: impl FnOnce() -> String,
) -> Option<String> {
    result
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .filter(|outcome| outcome.safe_to_probe())
        .map(|_| probe())
}

/// The worker: one job, every event forwarded, a panic reported as a failure.
fn run_job(device: &str, job: Job, tx: Sender<Msg>, waker: Option<Waker>, operation_id: String) {
    let check_after = matches!(job, Job::Flash(_) | Job::Recovery(_));
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
                workflow::with_operation_id(&operation_id, || {
                    match ops::execute(device, &job, &mut sheet)? {
                        ops::JobResult::Analysis(result) => {
                            let _ = tx.send(Msg::Analysis(result));
                            Ok(None)
                        }
                        ops::JobResult::Update(outcome) => Ok(Some(outcome)),
                        ops::JobResult::Preview(preview) => {
                            let _ = tx.send(Msg::PreviewCompatibilityPending(
                                preview.compatibility_pending,
                            ));
                            Ok(None)
                        }
                        ops::JobResult::Complete => Ok(None),
                    }
                })
            },
        )
    }));
    let result = match result {
        Ok(result) => result.map_err(|e: anyhow::Error| {
            let _ = tx.send(Msg::Event(Event::Message(format!(
                "Operation failed: {e:#}"
            ))));
            if let Some(evidence) = e.downcast_ref::<workflow::UpdateFailure>() {
                let _ = tx.send(Msg::FailureEvidence(evidence.clone()));
            }
            let message = workflow::user_error(&e).encoded();
            let _ = tx.send(Msg::UserGuidance(message.clone()));
            message
        }),
        Err(_) => Err(WORKER_PANIC.into()),
    };
    if check_after {
        if let Some(after) = post_update_snapshot(&result, || {
            ops::enumerate()
                .into_iter()
                .find(|drive| drive.path == device)
                .map_or_else(
                    || "Drive not detected after operation".to_owned(),
                    |drive| drive.display(),
                )
        }) {
            let _ = tx.send(Msg::DriveAfter(after));
        }
    }
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
    fn proceed_without_backup(&mut self, reason: &str) -> anyhow::Result<bool> {
        let (reply, answer) = mpsc::channel();
        if self
            .tx
            .send(Msg::BackupUnavailable(reason.to_owned(), reply))
            .is_err()
        {
            return Ok(false);
        }
        if let Some(wake) = &self.waker {
            wake();
        }
        Ok(answer.recv().unwrap_or(false))
    }

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
    (Group::General, "ui.general_information", 0),
    (Group::Additional, "ui.additional_information", 1),
    (Group::Region, "ui.dvd_region", 1),
    (Group::Settings, "ui.device_settings", 1),
    (Group::Media, "ui.media_capabilities", 0),
    (Group::Operations, "ui.firmware_operations", 1),
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
            title: title.into(),
            subtitle: (group == Group::Settings)
                .then(|| "ui.current_settings_read_only".to_owned()),
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
                label: crate::localization::message("field.label", &[("label", f.label.clone())]),
                value: f.value.clone(),
            })
        })
        .collect()
}

fn byte_count(bytes: usize) -> String {
    if bytes == 0 {
        "ui.unchanged".into()
    } else if bytes < 1024 {
        crate::localization::message("unit.bytes", &[("count", bytes.to_string())])
    } else {
        crate::localization::message(
            "unit.kib",
            &[("count", format!("{:.1}", bytes as f64 / 1024.0))],
        )
    }
}

fn family_id(family: &Option<workflow::HardwareFamily>) -> &str {
    family.as_ref().map_or("ui.unknown", |f| f.id.as_str())
}

/// One inspected component: its fields, findings and region tree.
pub(crate) fn component_node(c: &workflow::ComponentView) -> Node {
    let mut children = field_nodes(&c.fields);
    children.extend(c.findings().map(Node::text));
    for r in &c.regions {
        let mut region = vec![Node::leaf(NodeKind::Field {
            label: crate::localization::message("field.label", &[("label", "ui.role".into())]),
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
            let name = crate::localization::message(
                "analysis.records",
                &[
                    ("format", t.format.clone()),
                    ("count", t.records.len().to_string()),
                ],
            );
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
                nodes.push(Node::text(crate::localization::message(
                    "ui.drive_state_captured_at_arg0_unix_seconds",
                    &[("arg0", format!("{}", live.captured_at))],
                )));
                nodes.extend(field_nodes(&live.fields));
                nodes.extend(live.diagnostics.iter().map(Node::text));
            } else {
                nodes.push(Node::leaf(NodeKind::Note(
                    "ui.dvd_region_and_change_counters_are_available_only_".into(),
                )));
            }
            for name in &report.missing_components {
                nodes.push(Node::leaf(NodeKind::Field {
                    label: crate::localization::message("field.label", &[("label", name.clone())]),
                    value: "ui.not_included_in_this_source".into(),
                }));
            }
            nodes.extend(report.components.iter().map(component_node));
            if family {
                crate::localization::message(
                    "ui.hardware_family_arg0",
                    &[("arg0", family_id(&report.family).to_string())],
                )
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
                0 => "ui.no_unexpected_differences".to_string(),
                1 => "ui.unexpected_differences_in_1_region".to_string(),
                n => crate::localization::message(
                    "ui.unexpected_differences_in_n_regions",
                    &[("n", format!("{}", n))],
                ),
            }));
            nodes.push(Node::leaf(NodeKind::Buttons(vec![
                Button::new("ui.inspect_a", Input::InspectSide(Side::A), true),
                Button::new("ui.inspect_b", Input::InspectSide(Side::B), true),
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
                                "ui.partially_compared".into()
                            } else {
                                region
                                    .difference_percent
                                    .map_or("ui.not_available".into(), |p| format!("{p:.2}%"))
                            },
                            match (region.differs(), region.expected) {
                                (false, _) => "ui.none",
                                (true, true) => "ui.expected",
                                (true, false) => "ui.unexpected",
                            }
                            .into(),
                        ]
                    })
                    .collect();
                let table = Node::leaf(NodeKind::Table {
                    header: [
                        "ui.region",
                        "ui.role",
                        "ui.changed_in_a",
                        "ui.changed_in_b",
                        "ui.different",
                        "ui.verdict",
                    ]
                    .map(String::from)
                    .to_vec(),
                    rows,
                });
                children.push(Node::section("ui.changes_by_region", true, vec![table]));
                let mut technical = vec![Node::text(
                    "ui.percentages_use_decoded_and_expanded_bytes_across_",
                )];
                technical.extend(field_nodes(&s.fields));
                technical.push(Node::text(crate::localization::message(
                    "ui.arg0_address_relocation_or_metadata_changes_excluded",
                    &[("arg0", format!("{}", s.relocations.len()))],
                )));
                technical.push(Node::section(
                    "ui.excluded_changes",
                    false,
                    s.relocations.iter().map(Node::text).collect(),
                ));
                technical.extend(s.details.iter().map(Node::text));
                children.push(Node::section("ui.technical_details", false, technical));
                nodes.push(Node::section(&s.name, true, children));
            }
            crate::localization::message(
                "ui.hardware_family_arg0",
                &[("arg0", format!("{:?}", report.family))],
            )
        }
    };
    AnalysisView {
        title: "ui.firmware_analysis".into(),
        actions: vec![
            Button::new("ui.copy_report", Input::CopyReport, true),
            Button::new("ui.save_text", Input::Choose(Pick::ReportText), true),
            Button::new("ui.save_json", Input::Choose(Pick::ReportJson), true),
        ],
        heading,
        nodes,
    }
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod tests;
