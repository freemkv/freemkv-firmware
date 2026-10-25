//! Linux desktop shell using GTK4 and libadwaita, after freemkv's `linux.rs`.
//!
//! Renders `App::view()` into widgets, routes input through `App::dispatch` and performs the
//! returned effects; product decisions live in `ui.rs`. One window, laid out like the macOS
//! shell: a drive dropdown and Refresh, a linked row of task buttons, the task form, status
//! and progress, the results (libadwaita property rows in grouped cards) and the activity
//! log. Flash and Recovery confirm in a modal `AdwMessageDialog`; diagnostics and analysis
//! results get their own windows. Files go through `GtkFileDialog` (portal-aware).
//!
//! The model is the only state: `render` compares the view with what it last drew and
//! rebuilds only what changed, and `painting` keeps the signals its writes emit from being
//! mistaken for the user.

// qa's GUI gate (`FREEMKV_FLASH_GATE`), a debug-build hook.
#[cfg(debug_assertions)]
mod gate;
mod widgets;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use gtk4 as gtk;
use gtk4::prelude::*;
use gtk4::{gio, glib};
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::ui::{
    self, AnalysisView, Confirm, Diagnostics, DriveItem, Effect, Input, Item, Results, Status,
    Task, View,
};

/// Matches the `.desktop` file, so the shell finds its icon and launcher entry.
const APP_ID: &str = "org.freemkv.freemkv-flash-gui";
/// Poll period for a running job, as on macOS and Windows.
const TICK_MS: u64 = 200;

/// Entry point. Blocks until the window closes; 0 on a normal exit, non-zero if GTK could
/// not start.
pub fn run() -> i32 {
    if let Err(e) = adw::init() {
        crate::application_failure(&format!("GTK/libadwaita initialization failed: {e}"), true);
        return 1;
    }
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    // Only argv[0]: GApplication would otherwise read `--egui`-style flags as files.
    let argv0 = std::env::args()
        .next()
        .unwrap_or_else(|| "freemkv-flash-gui".into());
    app.run_with_args(&[argv0]).into()
}

/// What the shell last drew, so `render` rebuilds only what changed. Not model state.
#[derive(Default)]
struct Memo {
    language: Option<crate::localization::Language>,
    drives: Option<Vec<DriveItem>>,
    panel: Option<(Task, Vec<Item>)>,
    results: Option<Option<Results>>,
    log: Vec<String>,
    diag_lines: Option<Arc<Vec<String>>>,
    diag_buttons: Option<Vec<ui::Button>>,
    tree: Option<Arc<AnalysisView>>,
}

/// The open confirmation: its dialog, acknowledgement box and whether it still wants an answer.
struct ConfirmDialog {
    dialog: adw::MessageDialog,
    ack: gtk::CheckButton,
}

struct DiagWindow {
    window: adw::Window,
    title: adw::WindowTitle,
    buttons: gtk::Box,
    hint: gtk::Label,
    path: gtk::Label,
    notice: gtk::Label,
    text: gtk::TextView,
}

struct AnalysisWindow {
    window: adw::Window,
    title: adw::WindowTitle,
    actions: gtk::Box,
    notice: gtk::Label,
    heading: gtk::Label,
    body: gtk::Box,
}

pub(crate) struct Shell {
    /// The single source of truth. The shell holds no state of its own.
    app: RefCell<ui::App>,
    window: adw::ApplicationWindow,
    title: adw::WindowTitle,
    language_menu_button: gtk::MenuButton,
    refresh_action: gio::SimpleAction,

    drive_label: gtk::Label,
    drives: gtk::DropDown,
    drive_list: gtk::StringList,
    refresh: gtk::Button,
    drive_chips: gtk::Label,
    tabs: Vec<gtk::ToggleButton>,
    panel: gtk::Box,

    status_box: gtk::Box,
    status: gtk::Label,
    progress_label: gtk::Label,
    progress: gtk::ProgressBar,
    note: gtk::Label,
    cancel: gtk::Button,
    /// The input the Cancel button currently forwards.
    cancel_input: RefCell<Option<Input>>,
    results: gtk::Box,
    log: gtk::TextView,

    diag: RefCell<Option<DiagWindow>>,
    analysis: RefCell<Option<AnalysisWindow>>,
    confirm: RefCell<Option<ConfirmDialog>>,
    report_prompt: RefCell<Option<adw::MessageDialog>>,

    memo: RefCell<Memo>,
    tick: RefCell<Option<glib::SourceId>>,
    painting: Cell<bool>,
}

fn build_ui(gapp: &adw::Application) {
    // A second launch activates this instance: show the window we have.
    if let Some(w) = gapp.active_window() {
        w.present();
        return;
    }
    #[cfg(debug_assertions)]
    let (model, gate) = crate::gui_gate::model_or(ui::App::new);
    #[cfg(not(debug_assertions))]
    let model = ui::App::new();
    let window = adw::ApplicationWindow::builder()
        .application(gapp)
        .title(&model.view().title)
        .default_width(900)
        .default_height(760)
        .build();
    window.set_size_request(760, 640);

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    let title = adw::WindowTitle::new(&model.view().title, "");
    header.set_title_widget(Some(&title));
    let menu_btn = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .primary(true)
        .menu_model(&main_menu(model.language))
        .build();
    let language_menu_button = menu_btn.clone();
    header.pack_end(&menu_btn);
    toolbar.add_top_bar(&header);

    let root = gtk::Box::new(gtk::Orientation::Vertical, 12);
    for m in [
        gtk::Widget::set_margin_top,
        gtk::Widget::set_margin_bottom,
        gtk::Widget::set_margin_start,
        gtk::Widget::set_margin_end,
    ] {
        m(root.upcast_ref(), 18);
    }

    // Drive bar.
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let drive_label = gtk::Label::new(None);
    let drive_list = gtk::StringList::new(&[]);
    let drives = gtk::DropDown::new(Some(drive_list.clone()), gtk::Expression::NONE);
    drives.set_hexpand(true);
    let refresh = gtk::Button::new();
    bar.append(&drive_label);
    bar.append(&drives);
    bar.append(&refresh);
    root.append(&bar);
    let drive_chips = widgets::label("", &["caption", "dim-label"]);
    root.append(&drive_chips);

    // Task switcher: a linked row of toggle buttons, the GNOME segmented control.
    let switcher = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    switcher.add_css_class("linked");
    switcher.set_halign(gtk::Align::Start);
    let mut tabs: Vec<gtk::ToggleButton> = Vec::new();
    for task in Task::ALL {
        let b = gtk::ToggleButton::with_label(task.title());
        if let Some(first) = tabs.first() {
            b.set_group(Some(first));
        }
        switcher.append(&b);
        tabs.push(b);
    }
    root.append(&switcher);

    let panel = gtk::Box::new(gtk::Orientation::Vertical, 10);
    root.append(&panel);
    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // Status and progress.
    let status_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    let status = widgets::label("", &["heading"]);
    let progress_label = widgets::label("", &["caption", "dim-label"]);
    let progress = gtk::ProgressBar::new();
    let note = widgets::label("", &["caption", "dim-label"]);
    let cancel = gtk::Button::new();
    cancel.set_halign(gtk::Align::Start);
    for w in [
        status.upcast_ref::<gtk::Widget>(),
        progress_label.upcast_ref(),
        progress.upcast_ref(),
        note.upcast_ref(),
        cancel.upcast_ref(),
    ] {
        status_box.append(w);
    }
    root.append(&status_box);

    // Results.
    let results = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .min_content_height(120)
        .child(&results)
        .build();
    root.append(&scroll);

    // Activity log.
    // Operation diagnostics are opened from the result action instead of
    // consuming the bottom of every task.
    let (log_scroll, log) = widgets::text_pane();
    log_scroll.set_min_content_height(110);
    log_scroll.set_max_content_height(110);
    log_scroll.set_visible(false);

    toolbar.set_content(Some(&root));
    window.set_content(Some(&toolbar));

    let refresh_action = gio::SimpleAction::new("refresh", None);
    let shell = Rc::new(Shell {
        app: RefCell::new(model),
        window: window.clone(),
        title,
        language_menu_button,
        refresh_action: refresh_action.clone(),
        drive_label,
        drives,
        drive_list,
        refresh,
        drive_chips,
        tabs,
        panel,
        status_box,
        status,
        progress_label,
        progress,
        note,
        cancel,
        cancel_input: RefCell::new(None),
        results,
        log,
        diag: RefCell::new(None),
        analysis: RefCell::new(None),
        confirm: RefCell::new(None),
        report_prompt: RefCell::new(None),
        memo: RefCell::new(Memo::default()),
        tick: RefCell::new(None),
        painting: Cell::new(false),
    });
    shell.install_actions(gapp, refresh_action);
    shell.connect();
    let fx = shell.app.borrow_mut().start();
    shell.perform(fx);
    window.present();
    #[cfg(debug_assertions)]
    if let Some(dir) = gate {
        gate::start(&shell, dir);
    }
}

/// The hamburger menu: the window's commands, Quit last (GNOME convention).
fn main_menu(language: crate::localization::Language) -> gio::Menu {
    let menu = gio::Menu::new();
    let commands = gio::Menu::new();
    commands.append(
        Some(&crate::localization::text(language, "menu.refresh_drives")),
        Some("app.refresh"),
    );
    commands.append(
        Some(&crate::localization::text(language, "menu.diagnostic_log")),
        Some("app.diagnostics"),
    );
    menu.append_section(None, &commands);
    let language_menu = gio::Menu::new();
    for language in crate::localization::Language::ALL {
        let action = format!("app.language-{}", language.code());
        language_menu.append(Some(language.native_name()), Some(&action));
    }
    menu.append_submenu(
        Some(&crate::localization::text(language, "settings.language")),
        &language_menu,
    );
    let app = gio::Menu::new();
    app.append(
        Some(&crate::localization::text(language, "menu.quit")),
        Some("app.quit"),
    );
    menu.append_section(None, &app);
    menu
}

impl Shell {
    fn view(&self) -> View {
        self.app.borrow().view()
    }

    /// The single choke-point: dispatch, perform the effects, repaint.
    fn send(self: &Rc<Self>, input: Input) {
        let fx = self.app.borrow_mut().dispatch(input);
        self.perform(fx);
    }

    fn perform(self: &Rc<Self>, effects: Vec<Effect>) {
        for e in effects {
            match e {
                Effect::OpenFile { pick, filter } => self.choose_file(pick, filter, None),
                Effect::SaveFile { pick, file_name } => {
                    self.choose_file(pick, None, Some(file_name))
                }
                Effect::ReportPrompt {
                    summary,
                    description,
                } => {
                    self.present_report_prompt(&summary, &description);
                }
                Effect::CopyText(text) => self.window.clipboard().set_text(&text),
                Effect::OpenPath(path) => {
                    if let Err(error) = crate::external::open_path(&path) {
                        self.send(Input::ShellFailed(
                            crate::ui::ShellFailure::OpenLog,
                            format!("{error:#}"),
                        ));
                    }
                }
                Effect::StartTicking => self.start_tick(),
                Effect::StopTicking => {
                    if let Some(id) = self.tick.borrow_mut().take() {
                        id.remove();
                    }
                }
            }
        }
        self.render();
    }

    fn present_report_prompt(self: &Rc<Self>, summary: &str, description: &str) {
        let language = self.app.borrow().language;
        let text = |key| crate::localization::text(language, key);
        let dialog = adw::MessageDialog::new(
            Some(&self.window),
            Some(&text("report.prompt_title")),
            Some(&crate::localization::render(language, summary)),
        );
        dialog.set_modal(true);
        dialog.add_response("cancel", &text("ui.cancel"));
        dialog.add_response("send", &text("report.send"));
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let extra = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let label = widgets::label(&text("report.description_label"), &[]);
        let editor = gtk::TextView::new();
        editor.set_wrap_mode(gtk::WrapMode::WordChar);
        editor.set_accepts_tab(false);
        editor.buffer().set_text(description);
        label.set_mnemonic_widget(Some(&editor));
        extra.append(&label);
        let scroll = gtk::ScrolledWindow::builder()
            .min_content_height(140)
            .min_content_width(400)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&editor)
            .build();
        extra.append(&scroll);
        dialog.set_extra_child(Some(&extra));
        let me = self.clone();
        dialog.connect_response(None, move |dialog, response| {
            if me.report_prompt.borrow().as_ref() != Some(dialog) {
                return;
            }
            me.report_prompt.borrow_mut().take();
            let buffer = editor.buffer();
            let description = buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), true)
                .to_string();
            me.send(if response == "send" {
                Input::SendReport(description)
            } else {
                Input::DismissReport(description)
            });
        });
        *self.report_prompt.borrow_mut() = Some(dialog.clone());
        dialog.present();
    }

    fn start_tick(self: &Rc<Self>) {
        if self.tick.borrow().is_some() {
            return;
        }
        let me = self.clone();
        let id = glib::timeout_add_local(Duration::from_millis(TICK_MS), move || {
            let fx = me.app.borrow_mut().poll();
            me.perform(fx);
            glib::ControlFlow::Continue
        });
        *self.tick.borrow_mut() = Some(id);
    }

    /// `GtkFileDialog`, modal to the window; a choice comes back as `Chosen`. A dismissed
    /// dialog sends nothing, and Escape there closes only the dialog. Saving asks before
    /// replacing a file, which the model relies on.
    fn choose_file(
        self: &Rc<Self>,
        pick: ui::Pick,
        filter: Option<ui::FileFilter>,
        save_as: Option<String>,
    ) {
        let dlg = gtk::FileDialog::builder().modal(true).build();
        if let Some(f) = filter.and_then(ui::FileFilter::validated) {
            let ff = gtk::FileFilter::new();
            ff.set_name(Some(f.name));
            for e in &f.extensions {
                ff.add_suffix(e);
            }
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            filters.append(&ff);
            dlg.set_filters(Some(&filters));
            dlg.set_default_filter(Some(&ff));
        }
        let me = self.clone();
        let done = move |r: Result<gio::File, glib::Error>| match r {
            Ok(file) => match file.path() {
                Some(path) => me.send(Input::Chosen(pick, path)),
                None => me.send(Input::DialogFailed(
                    pick,
                    "File dialog returned no local path".into(),
                )),
            },
            Err(error)
                if error.matches(gtk::DialogError::Dismissed)
                    || error.matches(gtk::DialogError::Cancelled)
                    || error.matches(gio::IOErrorEnum::Cancelled) => {}
            Err(error) => me.send(Input::DialogFailed(pick, error.to_string())),
        };
        match save_as {
            Some(name) => {
                dlg.set_initial_name(Some(&name));
                dlg.save(Some(&self.window), gio::Cancellable::NONE, done);
            }
            None => dlg.open(Some(&self.window), gio::Cancellable::NONE, done),
        }
    }

    fn install_actions(self: &Rc<Self>, gapp: &adw::Application, refresh: gio::SimpleAction) {
        let me = self.clone();
        refresh.connect_activate(move |_, _| me.send(Input::Refresh));
        gapp.add_action(&refresh);
        for language in crate::localization::Language::ALL {
            let action_name = format!("language-{}", language.code());
            let action = gio::SimpleAction::new(&action_name, None);
            let me = self.clone();
            action.connect_activate(move |_, _| me.send(Input::SetLanguage(language)));
            gapp.add_action(&action);
        }
        let diagnostics = gio::SimpleAction::new("diagnostics", None);
        let me = self.clone();
        diagnostics.connect_activate(move |_, _| me.send(Input::OpenDiagnostics));
        gapp.add_action(&diagnostics);
        // Quit is the window's close button: one guarded way out.
        let quit = gio::SimpleAction::new("quit", None);
        let me = self.clone();
        quit.connect_activate(move |_, _| me.window.close());
        gapp.add_action(&quit);
        gapp.set_accels_for_action("app.refresh", &["F5", "<Primary>r"]);
        gapp.set_accels_for_action("app.quit", &["<Primary>q"]);
    }

    fn connect(self: &Rc<Self>) {
        let me = self.clone();
        self.refresh
            .connect_clicked(move |_| me.send(Input::Refresh));
        let me = self.clone();
        self.drives.connect_selected_notify(move |dd| {
            let has_drives = me
                .memo
                .borrow()
                .drives
                .as_ref()
                .is_some_and(|d| !d.is_empty());
            let i = dd.selected();
            if !me.painting.get() && has_drives && i != gtk::INVALID_LIST_POSITION {
                me.send(Input::SelectDrive(i as usize));
            }
        });
        for (task, b) in Task::ALL.into_iter().zip(&self.tabs) {
            let me = self.clone();
            b.connect_toggled(move |b| {
                if b.is_active() && !me.painting.get() {
                    me.send(Input::SelectTask(task));
                }
            });
        }
        let me = self.clone();
        self.cancel.connect_clicked(move |_| {
            let input = me.cancel_input.borrow().clone();
            if let Some(i) = input {
                me.send(i);
            }
        });
        // The model decides whether closing would orphan a job; the shell only says so.
        let me = self.clone();
        self.window.connect_close_request(move |_| {
            if me.view().can_close {
                if let Some(id) = me.tick.borrow_mut().take() {
                    id.remove();
                }
                return glib::Propagation::Proceed;
            }
            let dlg = adw::MessageDialog::new(
                Some(&me.window),
                Some(&crate::localization::render(
                    me.view().language,
                    ui::CLOSE_BLOCKED,
                )),
                None,
            );
            dlg.add_response(
                "ok",
                crate::localization::get(me.view().language, "action.ok"),
            );
            dlg.set_default_response(Some("ok"));
            dlg.set_close_response("ok");
            dlg.present();
            glib::Propagation::Stop
        });
    }

    // ── rendering ─────────────────────────────────────────────────────────

    /// Apply a fully-decided `View` to the widgets. The only place widgets are written.
    fn render(self: &Rc<Self>) {
        let v = self.view();
        self.painting.set(true);
        {
            let mut memo = self.memo.borrow_mut();
            if memo.language.replace(v.language) != Some(v.language) {
                memo.drives = None;
                memo.results = None;
            }
        }
        self.window.set_title(Some(&v.title));
        self.title.set_title(&v.title);
        self.language_menu_button
            .set_menu_model(Some(&main_menu(v.language)));
        self.render_drives(&v);
        for (tab, b) in v.tabs.iter().zip(&self.tabs) {
            b.set_label(&tab.title);
            b.set_sensitive(tab.enabled);
            if tab.task == v.task && !b.is_active() {
                b.set_active(true);
            }
        }
        let panel_key = (v.task, v.panel.clone());
        if self.memo.borrow().panel.as_ref() != Some(&panel_key) {
            widgets::clear(&self.panel);
            for item in &v.panel {
                self.panel.append(&self.panel_item(item));
            }
            self.memo.borrow_mut().panel = Some(panel_key);
        }
        self.render_status(v.status.as_ref());
        if self.memo.borrow().results.as_ref() != Some(&v.results) {
            widgets::clear(&self.results);
            if let Some(r) = &v.results {
                self.fill_results(r);
            }
            self.memo.borrow_mut().results = Some(v.results.clone());
        }
        if self.memo.borrow().log != v.log {
            widgets::set_text(&self.log, &v.log.join("\n"));
            self.memo.borrow_mut().log.clone_from(&v.log);
        }
        self.refresh_action.set_enabled(v.drives.refresh.enabled);
        self.render_confirm(v.confirm.as_ref());
        self.render_diagnostics(v.diagnostics.as_ref());
        self.render_analysis(&v);
        self.painting.set(false);
    }

    fn render_drives(self: &Rc<Self>, v: &View) {
        let bar = &v.drives;
        self.drive_label.set_label(&bar.label);
        self.drive_chips.set_label(&bar.chips.join("  \u{b7}  "));
        self.drive_chips.set_visible(!bar.chips.is_empty());
        if self.memo.borrow().drives.as_ref() != Some(&bar.items) {
            let texts: Vec<&str> = if bar.items.is_empty() {
                vec![bar.placeholder.as_str()]
            } else {
                bar.items.iter().map(|d| d.text.as_str()).collect()
            };
            self.drive_list.splice(0, self.drive_list.n_items(), &texts);
            self.memo.borrow_mut().drives = Some(bar.items.clone());
        }
        self.drives.set_selected(bar.selected.unwrap_or(0) as u32);
        let tip = bar
            .selected
            .and_then(|i| bar.items.get(i))
            .map(|d| d.tooltip.as_str());
        self.drives.set_tooltip_text(tip);
        self.drives
            .set_sensitive(v.controls_enabled && !bar.items.is_empty());
        widgets::bind(&self.refresh, &bar.refresh);
    }

    fn render_status(&self, status: Option<&Status>) {
        let Some(s) = status else {
            self.status_box.set_visible(false);
            return;
        };
        self.status_box.set_visible(true);
        self.status.set_label(&s.text);
        match &s.progress {
            Some(p) => {
                self.progress_label.set_visible(true);
                self.progress_label.set_label(&p.label);
                self.progress.set_visible(true);
                match p.fraction {
                    Some(f) => self.progress.set_fraction(f64::from(f)),
                    // Indeterminate: each tick moves the bar along.
                    None => self.progress.pulse(),
                }
            }
            None => {
                self.progress_label.set_visible(false);
                self.progress.set_visible(false);
            }
        }
        self.note.set_visible(s.note.is_some());
        self.note.set_label(s.note.as_deref().unwrap_or(""));
        match &s.cancel {
            Some(b) => {
                self.cancel.set_visible(true);
                widgets::bind(&self.cancel, b);
                *self.cancel_input.borrow_mut() = Some(b.input.clone());
            }
            None => {
                self.cancel.set_visible(false);
                *self.cancel_input.borrow_mut() = None;
            }
        }
    }

    /// A button that forwards its model input when clicked.
    fn button(self: &Rc<Self>, b: &ui::Button) -> gtk::Button {
        let btn = gtk::Button::new();
        widgets::bind(&btn, b);
        let me = self.clone();
        let input = b.input.clone();
        btn.connect_clicked(move |_| me.send(input.clone()));
        btn
    }

    fn button_row(self: &Rc<Self>, buttons: &[ui::Button]) -> gtk::Box {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        for b in buttons {
            row.append(&self.button(b));
        }
        row
    }

    fn panel_item(self: &Rc<Self>, item: &Item) -> gtk::Widget {
        match item {
            Item::Text(t) => widgets::label(t, &[]).upcast(),
            Item::Heading(t) => widgets::label(t, &["heading"]).upcast(),
            Item::Origin(origin) => widgets::label(
                &crate::localization::render(self.app.borrow().language, origin.label_id()),
                &[match origin {
                    crate::ui::FileOrigin::OemLikely => "success",
                    crate::ui::FileOrigin::UserBackupLikely => "warning",
                    crate::ui::FileOrigin::Unknown => "dim-label",
                }],
            )
            .upcast(),
            Item::Note(t) => widgets::label(t, &["caption", "dim-label"]).upcast(),
            Item::Warning(t) => widgets::label(t, &["warning"]).upcast(),
            Item::Check {
                id,
                text,
                checked,
                enabled,
            } => {
                let c = gtk::CheckButton::with_label(text);
                c.set_active(*checked);
                c.set_sensitive(*enabled);
                let (me, id) = (self.clone(), *id);
                c.connect_toggled(move |c| {
                    if !me.painting.get() {
                        me.send(Input::SetCheck(id, c.is_active()));
                    }
                });
                c.upcast()
            }
            Item::Path { button, path } => {
                let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
                row.append(&self.button(button));
                if let Some(p) = path {
                    let l = gtk::Label::new(Some(&p.name));
                    l.set_tooltip_text(Some(&p.full));
                    l.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
                    row.append(&l);
                }
                row.upcast()
            }
            Item::Buttons { label, buttons } => {
                let row = self.button_row(buttons);
                if let Some(l) = label {
                    let l = widgets::label(l, &[]);
                    l.set_width_request(80);
                    row.prepend(&l);
                }
                row.upcast()
            }
        }
    }

    fn fill_results(self: &Rc<Self>, r: &Results) {
        if let Some(b) = &r.open_results {
            let btn = self.button(b);
            btn.set_halign(gtk::Align::Start);
            self.results.append(&btn);
        }
        if !r.cards.is_empty() {
            self.results
                .append(&widgets::cards(&r.cards, self.view().language));
        } else if !r.fields.is_empty() {
            self.results.append(&widgets::fields(&r.fields));
        }
        if let Some(f) = &r.failure {
            let classes: &[&str] = match f.severity {
                ui::IssueSeverity::Notice => &[],
                ui::IssueSeverity::ActionRequired => &["warning"],
                ui::IssueSeverity::Error => &["error"],
            };
            let l = widgets::label(&f.text, classes);
            l.set_selectable(true);
            self.results.append(&l);
        }
        if let Some(n) = &r.notice {
            self.results.append(&widgets::label(n, &["caption"]));
        }
        let mut actions = vec![r.view_log.clone()];
        if let Some(f) = &r.failure {
            actions.push(f.save_log.clone());
        }
        actions.push(r.submit_report.clone());
        self.results.append(&self.button_row(&actions));
    }

    // ── the confirmation ──────────────────────────────────────────────────

    fn render_confirm(self: &Rc<Self>, confirm: Option<&Confirm>) {
        let showing = self
            .confirm
            .borrow()
            .as_ref()
            .map(|c| (c.dialog.clone(), c.ack.clone()));
        match (confirm, showing) {
            (Some(c), Some((dialog, ack))) => {
                ack.set_active(c.ack_checked);
                dialog.set_response_enabled("confirm", c.confirm.enabled);
            }
            (Some(c), None) => self.present_confirm(c),
            (None, Some((dialog, _))) => {
                // The model withdrew the request: close without answering it.
                *self.confirm.borrow_mut() = None;
                dialog.close();
            }
            (None, None) => {}
        }
    }

    /// The Flash/Recovery confirmation, modal to the window. The acknowledgement box starts
    /// as the model has it (unticked on every opening); Confirm stays disabled until the
    /// model enables it. Enter and Escape both answer Cancel. The drive and image shown were
    /// frozen by the model when it asked.
    fn present_confirm(self: &Rc<Self>, c: &Confirm) {
        let dialog = adw::MessageDialog::new(
            Some(&self.window),
            Some(&c.title),
            Some(&c.details.join("\n")),
        );
        dialog.add_response("cancel", &c.cancel.text);
        dialog.add_response("confirm", &c.confirm.text);
        dialog.set_response_appearance("confirm", adw::ResponseAppearance::Destructive);
        dialog.set_response_enabled("confirm", c.confirm.enabled);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");

        let extra = gtk::Box::new(gtk::Orientation::Vertical, 10);
        extra.append(&widgets::label(&c.danger, &["error"]));
        for w in &c.warnings {
            extra.append(&widgets::label(w, &["warning"]));
        }
        if let Some(p) = &c.prompt {
            extra.append(&widgets::label(p, &["heading"]));
        }
        if let Some(n) = &c.note {
            extra.append(&widgets::label(n, &[]));
        }
        if !c.technical_details.is_empty() {
            let expander = gtk::Expander::new(Some(&c.details_label));
            let body = gtk::Box::new(gtk::Orientation::Vertical, 6);
            for detail in &c.technical_details {
                let label = widgets::label(detail, &[]);
                label.set_selectable(true);
                body.append(&label);
            }
            let scroll = gtk::ScrolledWindow::builder()
                .hscrollbar_policy(gtk::PolicyType::Never)
                .max_content_height(180)
                .propagate_natural_height(true)
                .child(&body)
                .build();
            expander.set_child(Some(&scroll));
            let (show, hide) = (c.details_label.clone(), c.hide_details_label.clone());
            expander.connect_expanded_notify(move |expander| {
                expander.set_label(Some(if expander.is_expanded() { &hide } else { &show }));
            });
            extra.append(&expander);
        }
        if let Some(value) = &c.code_entry {
            let entry = gtk::Entry::new();
            entry.set_text(value);
            entry.set_max_length(5);
            entry.set_input_purpose(gtk::InputPurpose::Digits);
            let me = self.clone();
            entry.connect_changed(move |entry| {
                me.send(Input::FamilyOverrideCode(entry.text().to_string()));
            });
            extra.append(&entry);
        }
        let ack = gtk::CheckButton::with_label(&c.ack_text);
        ack.set_visible(!c.ack_text.is_empty());
        ack.set_active(c.ack_checked);
        let me = self.clone();
        ack.connect_toggled(move |b| {
            if !me.painting.get() {
                me.send(Input::SetCheck(ui::CheckId::RiskAck, b.is_active()));
            }
        });
        extra.append(&ack);
        dialog.set_extra_child(Some(&extra));

        let me = self.clone();
        dialog.connect_response(None, move |_, response| {
            // Answer only a confirmation the model still wants answered.
            if me.confirm.borrow_mut().take().is_none() {
                return;
            }
            me.send(if response == "confirm" {
                Input::Confirm
            } else {
                Input::CancelConfirm
            });
        });
        *self.confirm.borrow_mut() = Some(ConfirmDialog {
            dialog: dialog.clone(),
            ack,
        });
        dialog.present();
    }

    // ── the extra windows ─────────────────────────────────────────────────

    fn render_diagnostics(self: &Rc<Self>, d: Option<&Diagnostics>) {
        let Some(d) = d else {
            if let Some(w) = self.diag.borrow().as_ref() {
                w.window.set_visible(false);
            }
            let mut memo = self.memo.borrow_mut();
            memo.diag_lines = None;
            memo.diag_buttons = None;
            return;
        };
        if self.diag.borrow().is_none() {
            let w = self.build_diagnostics();
            *self.diag.borrow_mut() = Some(w);
        }
        let diag = self.diag.borrow();
        let Some(w) = diag.as_ref() else { return };
        w.title.set_title(&d.title);
        w.window.set_title(Some(&d.title));
        if self.memo.borrow().diag_buttons.as_ref() != Some(&d.buttons) {
            widgets::clear(&w.buttons);
            for b in &d.buttons {
                w.buttons.append(&self.button(b));
            }
            self.memo.borrow_mut().diag_buttons = Some(d.buttons.clone());
        }
        w.hint.set_label(&d.hint);
        w.path.set_label(d.path.as_deref().unwrap_or(""));
        w.notice.set_visible(d.notice.is_some());
        w.notice.set_label(d.notice.as_deref().unwrap_or(""));
        let fresh = self
            .memo
            .borrow()
            .diag_lines
            .as_ref()
            .is_none_or(|l| !Arc::ptr_eq(l, &d.lines));
        if fresh {
            widgets::set_text(&w.text, &d.lines.join("\n"));
            self.memo.borrow_mut().diag_lines = Some(d.lines.clone());
        }
        if !w.window.is_visible() {
            w.window.present();
        }
    }

    fn build_diagnostics(self: &Rc<Self>) -> DiagWindow {
        let (window, title, root) = widgets::window(&self.window, 680, 460);
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let hint = widgets::label("", &[]);
        let path = widgets::label("", &["caption", "dim-label"]);
        path.set_selectable(true);
        let notice = widgets::label("", &["caption"]);
        let (scroll, text) = widgets::text_pane();
        scroll.set_vexpand(true);
        for w in [
            buttons.upcast_ref::<gtk::Widget>(),
            hint.upcast_ref(),
            path.upcast_ref(),
            notice.upcast_ref(),
            scroll.upcast_ref(),
        ] {
            root.append(w);
        }
        let me = self.clone();
        window.connect_close_request(move |_| {
            me.send(Input::CloseDiagnostics);
            glib::Propagation::Proceed
        });
        DiagWindow {
            window,
            title,
            buttons,
            hint,
            path,
            notice,
            text,
        }
    }

    fn render_analysis(self: &Rc<Self>, v: &View) {
        let Some(a) = &v.analysis else {
            if let Some(w) = self.analysis.borrow().as_ref() {
                w.window.set_visible(false);
            }
            self.memo.borrow_mut().tree = None;
            return;
        };
        if self.analysis.borrow().is_none() {
            let w = self.build_analysis();
            *self.analysis.borrow_mut() = Some(w);
        }
        let analysis = self.analysis.borrow();
        let Some(w) = analysis.as_ref() else { return };
        w.notice.set_visible(a.notice.is_some());
        w.notice.set_label(a.notice.as_deref().unwrap_or(""));
        let fresh = self
            .memo
            .borrow()
            .tree
            .as_ref()
            .is_none_or(|t| !Arc::ptr_eq(t, &a.tree));
        if !fresh {
            return;
        }
        let tree = &a.tree;
        w.title.set_title(&tree.title);
        w.window.set_title(Some(&tree.title));
        w.heading.set_label(&tree.heading);
        widgets::clear(&w.actions);
        widgets::clear(&w.body);
        for b in &tree.actions {
            w.actions.append(&self.button(b));
        }
        let me = self.clone();
        let button = move |b: &ui::Button| me.button(b);
        for n in &tree.nodes {
            // Top-level button rows join the actions, as in the macOS shell.
            if let ui::NodeKind::Buttons(bs) = &n.kind {
                for b in bs {
                    w.actions.append(&button(b));
                }
            }
        }
        widgets::nodes(&w.body, &tree.nodes, &button, true);
        self.memo.borrow_mut().tree = Some(tree.clone());
        w.window.present();
    }

    fn build_analysis(self: &Rc<Self>) -> AnalysisWindow {
        let (window, title, root) = widgets::window(&self.window, 1000, 720);
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let notice = widgets::label("", &["caption"]);
        let heading = widgets::label("", &["title-2"]);
        let body = gtk::Box::new(gtk::Orientation::Vertical, 6);
        let scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .child(&body)
            .build();
        for w in [
            actions.upcast_ref::<gtk::Widget>(),
            notice.upcast_ref(),
            heading.upcast_ref(),
            scroll.upcast_ref(),
        ] {
            root.append(w);
        }
        let me = self.clone();
        window.connect_close_request(move |_| {
            me.send(Input::CloseResults);
            glib::Propagation::Proceed
        });
        AnalysisWindow {
            window,
            title,
            actions,
            notice,
            heading,
            body,
        }
    }
}
