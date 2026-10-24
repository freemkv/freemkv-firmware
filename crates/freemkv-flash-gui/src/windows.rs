//! Windows Win32 shell: draws `ui::App::view()` with stock common controls and forwards
//! input to `App::dispatch`, after freemkv's `windows.rs`.
//!
//! One window, laid out like the macOS shell: a drive combo box and Refresh, a tab strip
//! for the tasks, the task form, status and progress, the results (a grouped list view) and
//! the activity log. Flash and Recovery confirm in a modal task dialog; diagnostics and
//! analysis results have their own windows. File choosers are the OS's common dialogs.
//!
//! winsafe cannot create a control once its window exists, so the task form draws from
//! pools built up front (`win_layout` sizes them) and the extra windows are built hidden.
//! Every handler goes through `send`; `render` is the only place controls are written, and
//! it computes nothing. Geometry comes from `win_layout`, DPI-aware (PerMonitorV2).

// qa's GUI gate (`FREEMKV_FLASH_GATE`), a debug-build hook.
#[cfg(debug_assertions)]
mod gate;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use winsafe::{self as w, co, gui, msg, prelude::*};

use crate::ui::{
    self, AnalysisView, Button, ButtonStyle, CardBody, CheckId, Confirm, Diagnostics, DriveItem,
    Effect, Input, Item, MediaRow, Node, NodeKind, Results, Status, Task, Tri, View,
};
use crate::win_layout::{self as lay, Column, Line, Rect, Scale};

/// The icon group `build.rs` embeds (winresource's default id).
const IDI_APP: u16 = 1;
/// Poll period for a running job, as on macOS.
const TICK_MS: u32 = 200;
const TIMER_TICK: usize = 1;
/// One shot: open the confirmation once the handler that asked for it has returned.
const TIMER_CONFIRM: usize = 2;

// Menu ids. Nothing here is IDOK (1) or IDCANCEL (2): Escape in the window, or in a file
// dialog it owns, must never reach a command that closes it.
const IDM_REFRESH: u16 = 2001;
const IDM_DIAGNOSTICS: u16 = 2002;
const IDM_EXIT: u16 = 2003;
const IDM_COPY: u16 = 2004;
const IDM_SELECT_ALL: u16 = 2005;
const IDM_LANGUAGE_FIRST: u16 = 2100;

// The confirmation's buttons, clear of the common dialog ids.
const TD_CONFIRM: u16 = 1001;
/// The confirmation's task-dialog flags. No `VERIFICATION_FLAG_CHECKED`: the risk box opens
/// unticked, which the qa gate checks against these flags.
pub(crate) fn confirm_flags() -> co::TDF {
    co::TDF::ALLOW_DIALOG_CANCELLATION
        | co::TDF::CALLBACK_TIMER
        | co::TDF::POSITION_RELATIVE_TO_WINDOW
}
const TD_CANCEL: u16 = 1002;
const TDM_CLICK_BUTTON: u32 = 0x0400 + 102;
const TDM_ENABLE_BUTTON: u32 = 0x0400 + 111;
const EM_SETSEL: u32 = 0x00B1;
const EM_SCROLLCARET: u32 = 0x00B7;
const BM_SETSTYLE: u32 = 0x00F4;
const LVM_SETCOLUMNWIDTH: u32 = 0x101E;
const LVM_REMOVEALLGROUPS: u32 = 0x10A0;
const LVSCW_AUTOSIZE_USEHEADER: isize = -2;

/// How a label's text is coloured (`WM_CTLCOLORSTATIC`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tone {
    Success,
    Normal,
    Secondary,
    Caution,
    Error,
}

/// A push button and the input it currently forwards, rebound on every render.
#[derive(Clone)]
struct Bound {
    btn: gui::Button,
    input: Rc<RefCell<Option<Input>>>,
}

impl Bound {
    fn new(parent: &(impl GuiParent + 'static), s: Scale) -> Self {
        Self {
            btn: gui::Button::new(
                parent,
                gui::ButtonOpts {
                    text: "",
                    width: s.px(lay::BUTTON_MIN_W),
                    height: s.px(lay::ROW_H),
                    window_style: co::WS::CHILD | co::WS::TABSTOP | co::WS::GROUP,
                    ..Default::default()
                },
            ),
            input: Rc::new(RefCell::new(None)),
        }
    }

    /// Show `b`: its text, enabled state, style and the input a click sends.
    fn bind(&self, b: &Button) {
        let _ = self.btn.hwnd().SetWindowText(&mnemonic_free(&b.text));
        self.btn.hwnd().EnableWindow(b.enabled);
        // The default-button look marks the primary action; it is never an Enter target.
        let style = if b.style == ButtonStyle::Primary {
            1
        } else {
            0
        };
        send_raw(self.btn.hwnd(), BM_SETSTYLE, style, 1);
        *self.input.borrow_mut() = Some(b.input.clone());
    }

    fn unbind(&self) {
        show(&self.btn, false);
        *self.input.borrow_mut() = None;
    }
}

/// `&` is a mnemonic in a button or checkbox caption; the model's text is literal.
fn mnemonic_free(text: &str) -> String {
    text.replace('&', "&&")
}

fn send_raw(hwnd: &w::HWND, id: u32, wparam: usize, lparam: isize) -> isize {
    unsafe {
        hwnd.SendMessage(msg::Wm {
            msg_id: co::WM::from_raw(id),
            wparam,
            lparam,
        })
    }
}

fn put(c: &impl GuiWindow, r: Rect) {
    let _ = c.hwnd().SetWindowPos(
        w::HwndPlace::None,
        w::POINT::with(r.x, r.y),
        w::SIZE::with(r.w.max(0), r.h.max(0)),
        co::SWP::NOZORDER | co::SWP::NOACTIVATE,
    );
    show(c, true);
}

fn show(c: &impl GuiWindow, visible: bool) {
    c.hwnd().ShowWindow(if visible {
        co::SW::SHOWNA
    } else {
        co::SW::HIDE
    });
}

fn set_text(c: &impl GuiWindow, text: &str) {
    if c.hwnd().GetWindowText().ok().as_deref() != Some(text) {
        let _ = c.hwnd().SetWindowText(text);
    }
}

/// An edit control's text: CRLF line ends, caret and view at the end.
fn set_edit_lines(e: &gui::Edit, lines: &[String]) {
    let _ = e.set_text(&lines.join("\r\n"));
    let end = e.hwnd().GetWindowTextLength().unwrap_or(0) as usize;
    send_raw(e.hwnd(), EM_SETSEL, end, end as isize);
    send_raw(e.hwnd(), EM_SCROLLCARET, 0, 0);
}

// ── DPI and fonts ─────────────────────────────────────────────────────────

mod extra {
    use std::ffi::c_void;

    #[link(name = "user32")]
    unsafe extern "system" {
        /// The DPI-aware `SystemParametersInfo`: the plain one answers for the system DPI.
        pub fn SystemParametersInfoForDpi(
            action: u32,
            ui_param: u32,
            pv_param: *mut c_void,
            win_ini: u32,
            dpi: u32,
        ) -> i32;
        /// The primary monitor's DPI, the only one known before a window exists.
        pub fn GetDpiForSystem() -> u32;
    }

    pub const SPI_GETNONCLIENTMETRICS: u32 = 0x0029;
}

fn system_dpi() -> u32 {
    match unsafe { extra::GetDpiForSystem() } {
        0 => lay::BASE_DPI,
        d => d,
    }
}

fn window_dpi(hwnd: &w::HWND) -> u32 {
    match hwnd.GetDpiForWindow() {
        0 => system_dpi(),
        d => d,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Face {
    Ui,
    Bold,
    Large,
    Mono,
}

/// A font made for one (DPI, face).
type Font = ((u32, u8), w::guard::DeleteObjectGuard<w::HFONT>);

thread_local! {
    // Fonts per (DPI, face), alive for the GUI thread: a control only borrows its HFONT.
    static FONTS: RefCell<Vec<Font>> = const { RefCell::new(Vec::new()) };
}

/// The shell UI font (winsafe's own face, `lfMenuFont`) at `dpi`, in one of its variants.
fn font(dpi: u32, face: Face) -> Option<w::HFONT> {
    FONTS.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (dpi, face as u8);
        if let Some((_, f)) = cache.iter().find(|(k, _)| *k == key) {
            return Some(unsafe { f.raw_copy() });
        }
        let mut ncm = w::NONCLIENTMETRICS::default();
        let size = std::mem::size_of::<w::NONCLIENTMETRICS>() as u32;
        let got = unsafe {
            extra::SystemParametersInfoForDpi(
                extra::SPI_GETNONCLIENTMETRICS,
                size,
                &mut ncm as *mut _ as *mut std::ffi::c_void,
                0,
                dpi,
            ) != 0
        };
        if !got {
            return None;
        }
        let mut lf = ncm.lfMenuFont;
        match face {
            Face::Ui => {}
            Face::Bold => lf.lfWeight = co::FW::BOLD,
            Face::Large => {
                lf.lfWeight = co::FW::BOLD;
                lf.lfHeight = lf.lfHeight * 4 / 3;
            }
            Face::Mono => {
                lf.set_lfFaceName("Consolas");
            }
        }
        let f = w::HFONT::CreateFontIndirect(&lf).ok()?;
        let handle = unsafe { f.raw_copy() };
        cache.push((key, f));
        Some(handle)
    })
}

fn set_font(hwnd: &w::HWND, dpi: u32, face: Face) {
    if let Some(f) = font(dpi, face) {
        unsafe {
            hwnd.SendMessage(msg::WmSetFont {
                hfont: f,
                redraw: true,
            });
        }
    }
}

/// The UI font on a window and every control in it.
fn apply_ui_font(hwnd: &w::HWND, dpi: u32) {
    set_font(hwnd, dpi, Face::Ui);
    hwnd.EnumChildWindows(|child: w::HWND| {
        set_font(&child, dpi, Face::Ui);
        true
    });
}

/// The pixel size `text` takes in `hwnd`'s font: one line, or wrapped to `width`.
fn measure(hwnd: &w::HWND, text: &str, width: Option<i32>) -> (i32, i32) {
    let Ok(hdc) = hwnd.GetDC() else {
        return (0, 0);
    };
    let font = unsafe { hwnd.SendMessage(msg::WmGetFont {}) };
    let _held = font.as_ref().and_then(|f| hdc.SelectObject(f).ok());
    let mut rc = w::RECT {
        left: 0,
        top: 0,
        right: width.unwrap_or(0).max(1),
        bottom: 0,
    };
    let flags = co::DT::CALCRECT
        | co::DT::NOPREFIX
        | if width.is_some() {
            co::DT::WORDBREAK
        } else {
            co::DT::SINGLELINE
        };
    let shown = if text.is_empty() { " " } else { text };
    match hdc.DrawText(shown, &mut rc, flags) {
        Ok(h) => (rc.right - rc.left, h),
        Err(_) => (0, 0),
    }
}

/// Attach the embedded icon at the window's DPI (title bar, Alt-Tab, taskbar).
fn set_icons(hwnd: &w::HWND) {
    let Ok(hinst) = w::HINSTANCE::GetModuleHandle(None) else {
        return;
    };
    let dpi = window_dpi(hwnd);
    for (slot, cx, cy) in [
        (co::ICON_SZ::SMALL, co::SM::CXSMICON, co::SM::CYSMICON),
        (co::ICON_SZ::BIG, co::SM::CXICON, co::SM::CYICON),
    ] {
        let cx = w::GetSystemMetricsForDpi(cx, dpi).unwrap_or_else(|_| w::GetSystemMetrics(cx));
        let cy = w::GetSystemMetricsForDpi(cy, dpi).unwrap_or_else(|_| w::GetSystemMetrics(cy));
        let Ok(mut icon) = hinst.LoadImageIcon(
            w::IdOicStr::Id(IDI_APP),
            w::SIZE::with(cx, cy),
            co::LR::DEFAULTCOLOR,
        ) else {
            continue;
        };
        // Leaked on purpose: the window points at it for the life of the process.
        let hicon = icon.leak();
        unsafe {
            hwnd.SendMessage(msg::WmSetIcon { size: slot, hicon });
        }
    }
}

// ── the extra windows ─────────────────────────────────────────────────────

/// The diagnostic log window, built hidden with the main window.
#[derive(Clone)]
struct DiagWindow {
    wnd: gui::WindowModeless,
    buttons: Rc<Vec<Bound>>,
    hint: gui::Label,
    path: gui::Edit,
    notice: gui::Label,
    text: gui::Edit,
}

/// The analysis results window: actions, heading and the result tree.
#[derive(Clone)]
struct AnalysisWindow {
    wnd: gui::WindowModeless,
    buttons: Rc<Vec<Bound>>,
    notice: gui::Label,
    heading: gui::Label,
    tree: gui::TreeView<()>,
}

fn modeless(
    parent: &gui::WindowMain,
    title: &str,
    class: &str,
    w: i32,
    h: i32,
) -> gui::WindowModeless {
    gui::WindowModeless::new(
        parent,
        gui::WindowModelessOpts {
            title,
            class_name: class,
            size: (w, h),
            // Not visible: shown when the view asks for it.
            style: co::WS::CAPTION
                | co::WS::SYSMENU
                | co::WS::CLIPCHILDREN
                | co::WS::BORDER
                | co::WS::SIZEBOX
                | co::WS::MINIMIZEBOX
                | co::WS::MAXIMIZEBOX,
            ..Default::default()
        },
    )
}

fn label(
    parent: &(impl GuiParent + 'static),
    style: co::SS,
    resize: (gui::Horz, gui::Vert),
) -> gui::Label {
    gui::Label::new(
        parent,
        gui::LabelOpts {
            text: "",
            size: (10, 10),
            control_style: style | co::SS::NOPREFIX,
            window_style: co::WS::CHILD,
            resize_behavior: resize,
            ..Default::default()
        },
    )
}

impl DiagWindow {
    fn new(parent: &gui::WindowMain, s: Scale) -> Self {
        let (ww, wh) = (s.px(lay::DIAG_W), s.px(lay::DIAG_H));
        let wnd = modeless(parent, "", "FmkFlashDiag", ww, wh);
        let p = s.px(lay::PAD);
        let inner = ww - 2 * p;
        let buttons: Vec<Bound> = (0..lay::DIAG_BUTTONS)
            .map(|_| Bound::new(&wnd, s))
            .collect();
        let mut col = Column::new(
            p,
            p + s.px(lay::ROW_H) + s.px(lay::GAP),
            inner,
            s.px(lay::GAP),
        );
        let mk_label = |r: Rect, horz| {
            let l = label(
                &wnd,
                co::SS::LEFT | co::SS::ENDELLIPSIS,
                (horz, gui::Vert::None),
            );
            (l, r)
        };
        let (hint, hint_r) = mk_label(col.take(s.px(lay::LINE_H)), gui::Horz::Resize);
        let path_r = col.take(s.px(lay::ROW_H) - 4);
        let path = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                position: (path_r.x, path_r.y),
                width: path_r.w,
                height: path_r.h,
                control_style: co::ES::READONLY | co::ES::AUTOHSCROLL,
                resize_behavior: (gui::Horz::Resize, gui::Vert::None),
                ..Default::default()
            },
        );
        let (notice, notice_r) = mk_label(col.take(s.px(lay::LINE_H)), gui::Horz::Resize);
        let text_h = wh - col.y - p;
        let text = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                position: (p, col.y),
                width: inner,
                height: text_h,
                control_style: co::ES::MULTILINE
                    | co::ES::READONLY
                    | co::ES::AUTOVSCROLL
                    | co::ES::AUTOHSCROLL
                    | co::ES::NOHIDESEL,
                window_style: co::WS::CHILD
                    | co::WS::VISIBLE
                    | co::WS::TABSTOP
                    | co::WS::VSCROLL
                    | co::WS::HSCROLL,
                resize_behavior: (gui::Horz::Resize, gui::Vert::Resize),
                ..Default::default()
            },
        );
        let me = Self {
            wnd,
            buttons: Rc::new(buttons),
            hint,
            path,
            notice,
            text,
        };
        let me2 = me.clone();
        me.wnd.on().wm_create(move |_| {
            put(&me2.hint, hint_r);
            put(&me2.notice, notice_r);
            Ok(0)
        });
        me
    }
}

impl AnalysisWindow {
    fn new(parent: &gui::WindowMain, s: Scale) -> Self {
        let (ww, wh) = (s.px(lay::ANALYSIS_W), s.px(lay::ANALYSIS_H));
        let wnd = modeless(parent, "", "FmkFlashAnalysis", ww, wh);
        let p = s.px(lay::PAD);
        let inner = ww - 2 * p;
        let buttons: Vec<Bound> = (0..lay::ANALYSIS_BUTTONS)
            .map(|_| Bound::new(&wnd, s))
            .collect();
        let mut col = Column::new(
            p,
            p + s.px(lay::ROW_H) + s.px(lay::GAP),
            inner,
            s.px(lay::GAP),
        );
        let notice_r = col.take(s.px(lay::LINE_H));
        let heading_r = col.take(s.px(lay::LINE_H) * 3 / 2);
        let notice = label(
            &wnd,
            co::SS::LEFT | co::SS::ENDELLIPSIS,
            (gui::Horz::Resize, gui::Vert::None),
        );
        let heading = label(
            &wnd,
            co::SS::LEFT | co::SS::ENDELLIPSIS,
            (gui::Horz::Resize, gui::Vert::None),
        );
        let tree = gui::TreeView::new(
            &wnd,
            gui::TreeViewOpts {
                position: (p, col.y),
                size: (inner, wh - col.y - p),
                control_style: co::TVS::HASLINES
                    | co::TVS::LINESATROOT
                    | co::TVS::HASBUTTONS
                    | co::TVS::SHOWSELALWAYS
                    | co::TVS::INFOTIP,
                resize_behavior: (gui::Horz::Resize, gui::Vert::Resize),
                ..Default::default()
            },
        );
        let me = Self {
            wnd,
            buttons: Rc::new(buttons),
            notice,
            heading,
            tree,
        };
        let me2 = me.clone();
        me.wnd.on().wm_create(move |_| {
            put(&me2.notice, notice_r);
            put(&me2.heading, heading_r);
            Ok(0)
        });
        me
    }
}

// ── the shell ─────────────────────────────────────────────────────────────

/// What the shell last drew, so `render` rebuilds only what changed. Not model state.
#[derive(Default)]
struct Memo {
    language: Option<crate::localization::Language>,
    drives: Option<Vec<DriveItem>>,
    panel: Option<Vec<Item>>,
    results: Option<Option<Results>>,
    log: Vec<String>,
    diag_lines: Option<Arc<Vec<String>>>,
    tree: Option<Arc<AnalysisView>>,
    title: String,
}

/// A pooled checkbox and the model check it currently reports.
type Check = (gui::CheckBox, Rc<Cell<Option<CheckId>>>);

#[derive(Clone)]
struct Shell {
    wnd: gui::WindowMain,
    /// The single source of truth. The shell holds no state of its own.
    app: Rc<RefCell<ui::App>>,

    drive_label: gui::Label,
    drives: gui::ComboBox,
    refresh: Bound,
    drive_chips: gui::Label,
    tabs: gui::Tab,

    // The task form's pools.
    texts: Rc<Vec<gui::Label>>,
    lines: Rc<Vec<gui::Label>>,
    buttons: Rc<Vec<Bound>>,
    checks: Rc<Vec<Check>>,
    rule: gui::Label,

    status: gui::Label,
    progress_label: gui::Label,
    progress: gui::ProgressBar,
    note: gui::Label,
    cancel: Bound,

    open_results: Bound,
    list: gui::ListView<()>,
    failure: gui::Label,
    save_log: Bound,
    notice: gui::Label,
    view_log: Bound,
    submit_report: Bound,

    log_title: gui::Label,
    log: gui::Edit,

    diag: DiagWindow,
    analysis: AnalysisWindow,

    memo: Rc<RefCell<Memo>>,
    /// Label colours, by control handle; set while rendering.
    tones: Rc<RefCell<Vec<(isize, Tone)>>>,
    dpi: Rc<Cell<u32>>,
    /// True while `render` writes controls, so their change notifications are not input.
    painting: Rc<Cell<bool>>,
    confirming: Rc<Cell<bool>>,
    /// The confirmation's risk box as its dialog last reported it: cleared on creation, then
    /// every verification click, whatever caused it. Only the qa gate reads it, so debug
    /// builds only.
    #[cfg(debug_assertions)]
    risk_box: Rc<Cell<bool>>,
}

fn build_menu(language: crate::localization::Language) -> w::SysResult<w::HMENU> {
    let t = |id| crate::localization::get(language, id);
    let refresh = format!("{}\tF5", t("menu.refresh_drives"));
    let quit = format!("{}\tAlt+F4", t("menu.quit"));
    let copy = format!("{}\tCtrl+C", t("menu.copy"));
    let select_all = format!("{}\tCtrl+A", t("menu.select_all"));
    let bar = w::HMENU::CreateMenu()?;
    let file = w::HMENU::CreatePopupMenu()?;
    file.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_REFRESH,
            text: &refresh,
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_EXIT,
            text: &quit,
        },
    ])?;
    let edit = w::HMENU::CreatePopupMenu()?;
    edit.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_COPY,
            text: &copy,
        },
        w::MenuItem::Entry {
            cmd_id: IDM_SELECT_ALL,
            text: &select_all,
        },
    ])?;
    let view = w::HMENU::CreatePopupMenu()?;
    view.append_item(&[w::MenuItem::Entry {
        cmd_id: IDM_DIAGNOSTICS,
        text: t("menu.diagnostic_log"),
    }])?;
    let languages = w::HMENU::CreatePopupMenu()?;
    let choices: Vec<_> = crate::localization::Language::ALL
        .iter()
        .enumerate()
        .map(|(i, choice)| w::MenuItem::Entry {
            cmd_id: IDM_LANGUAGE_FIRST + i as u16,
            text: choice.native_name(),
        })
        .collect();
    languages.append_item(&choices)?;
    for (index, choice) in crate::localization::Language::ALL.iter().enumerate() {
        languages.CheckMenuItem(
            w::IdPos::Id(IDM_LANGUAGE_FIRST + index as u16),
            *choice == language,
        )?;
    }
    let language_label = crate::localization::text(language, "settings.language");
    bar.append_item(&[
        w::MenuItem::Submenu {
            submenu: &file,
            text: t("menu.file"),
        },
        w::MenuItem::Submenu {
            submenu: &edit,
            text: t("menu.edit"),
        },
        w::MenuItem::Submenu {
            submenu: &view,
            text: t("menu.view"),
        },
        w::MenuItem::Submenu {
            submenu: &languages,
            text: &language_label,
        },
    ])?;
    Ok(bar)
}

/// F5 refreshes. Ctrl+C / Ctrl+A stay with the focused edit control, which runs them itself.
fn build_accels() -> w::SysResult<w::guard::DestroyAcceleratorTableGuard> {
    w::HACCEL::CreateAcceleratorTable(&[w::ACCEL {
        fVirt: co::ACCELF::VIRTKEY,
        key: co::VK::F5,
        cmd: IDM_REFRESH,
    }])
}

impl Shell {
    fn new(app: ui::App) -> Self {
        // Only the system DPI exists before the window; `wm_create` re-lays out at the real one.
        let s = Scale::new(system_dpi());
        let language = app.language;
        let wnd = gui::WindowMain::new(gui::WindowMainOpts {
            title: crate::localization::get(language, "app.name"),
            class_name: "FmkFlashMain",
            class_icon: gui::Icon::Id(IDI_APP),
            size: lay::default_size(s.dpi()),
            style: co::WS::CAPTION
                | co::WS::SYSMENU
                | co::WS::CLIPCHILDREN
                | co::WS::BORDER
                | co::WS::VISIBLE
                | co::WS::MINIMIZEBOX
                | co::WS::MAXIMIZEBOX
                | co::WS::SIZEBOX,
            menu: build_menu(language).unwrap_or(w::HMENU::NULL),
            accel_table: build_accels().ok(),
            ..Default::default()
        });
        let none = (gui::Horz::None, gui::Vert::None);
        let wrap = co::SS::LEFT;
        let one_line = co::SS::LEFT | co::SS::PATHELLIPSIS;

        let drive_label = label(&wnd, one_line, none);
        let drives = gui::ComboBox::new(
            &wnd,
            gui::ComboBoxOpts {
                width: s.px(300),
                control_style: co::CBS::DROPDOWNLIST,
                ..Default::default()
            },
        );
        let refresh = Bound::new(&wnd, s);
        let drive_chips = label(&wnd, one_line, none);
        let tabs = gui::Tab::new(
            &wnd,
            gui::TabOpts {
                size: (s.px(400), s.px(lay::ROW_H)),
                ..Default::default()
            },
        );
        let texts = (0..lay::POOL_TEXT)
            .map(|_| label(&wnd, wrap, none))
            .collect();
        let lines = (0..lay::POOL_LINE)
            .map(|_| label(&wnd, one_line, none))
            .collect();
        let buttons = (0..lay::POOL_BUTTONS)
            .map(|_| Bound::new(&wnd, s))
            .collect();
        let checks = (0..lay::POOL_CHECKS)
            .map(|_| {
                let c = gui::CheckBox::new(
                    &wnd,
                    gui::CheckBoxOpts {
                        size: (s.px(300), s.px(lay::CHECK_H)),
                        window_style: co::WS::CHILD | co::WS::TABSTOP | co::WS::GROUP,
                        ..Default::default()
                    },
                );
                (c, Rc::new(Cell::new(None)))
            })
            .collect();
        let rule = label(&wnd, co::SS::ETCHEDHORZ, none);
        let status = label(&wnd, co::SS::LEFT | co::SS::ENDELLIPSIS, none);
        let progress_label = label(&wnd, co::SS::LEFT | co::SS::ENDELLIPSIS, none);
        let progress = gui::ProgressBar::new(
            &wnd,
            gui::ProgressBarOpts {
                size: (s.px(400), s.px(lay::PROGRESS_H)),
                range: (0, 1000),
                window_style: co::WS::CHILD,
                ..Default::default()
            },
        );
        let note = label(&wnd, wrap, none);
        let cancel = Bound::new(&wnd, s);
        let open_results = Bound::new(&wnd, s);
        let list = gui::ListView::new(
            &wnd,
            gui::ListViewOpts {
                size: (s.px(400), s.px(200)),
                control_style: co::LVS::REPORT
                    | co::LVS::NOSORTHEADER
                    | co::LVS::SHOWSELALWAYS
                    | co::LVS::SINGLESEL,
                control_ex_style: co::LVS_EX::FULLROWSELECT
                    | co::LVS_EX::DOUBLEBUFFER
                    | co::LVS_EX::INFOTIP
                    | co::LVS_EX::LABELTIP,
                window_style: co::WS::CHILD | co::WS::TABSTOP | co::WS::GROUP,
                columns: &[
                    (
                        crate::localization::get(app.language, "field.item"),
                        s.px(lay::FIELD_COL_W),
                    ),
                    (
                        crate::localization::get(app.language, "field.value"),
                        s.px(400),
                    ),
                ],
                ..Default::default()
            },
        );
        let failure = label(&wnd, wrap, none);
        let save_log = Bound::new(&wnd, s);
        let notice = label(&wnd, wrap, none);
        let view_log = Bound::new(&wnd, s);
        let submit_report = Bound::new(&wnd, s);
        let log_title = label(&wnd, one_line, none);
        let log = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                width: s.px(400),
                height: s.px(lay::LOG_H),
                control_style: co::ES::MULTILINE
                    | co::ES::READONLY
                    | co::ES::AUTOVSCROLL
                    | co::ES::NOHIDESEL,
                window_style: co::WS::CHILD | co::WS::TABSTOP | co::WS::GROUP | co::WS::VSCROLL,
                ..Default::default()
            },
        );
        let diag = DiagWindow::new(&wnd, s);
        let analysis = AnalysisWindow::new(&wnd, s);
        Self {
            wnd,
            app: Rc::new(RefCell::new(app)),
            drive_label,
            drives,
            refresh,
            drive_chips,
            tabs,
            texts: Rc::new(texts),
            lines: Rc::new(lines),
            buttons: Rc::new(buttons),
            checks: Rc::new(checks),
            rule,
            status,
            progress_label,
            progress,
            note,
            cancel,
            open_results,
            list,
            failure,
            save_log,
            notice,
            view_log,
            submit_report,
            log_title,
            log,
            diag,
            analysis,
            memo: Rc::default(),
            tones: Rc::default(),
            dpi: Rc::new(Cell::new(s.dpi())),
            painting: Rc::new(Cell::new(false)),
            confirming: Rc::new(Cell::new(false)),
            #[cfg(debug_assertions)]
            risk_box: Rc::new(Cell::new(false)),
        }
    }

    fn view(&self) -> View {
        self.app.borrow().view()
    }

    /// The single choke-point: dispatch, perform the effects, repaint.
    fn send(&self, input: Input) {
        let fx = self.app.borrow_mut().dispatch(input);
        self.perform(fx);
    }

    fn perform(&self, effects: Vec<Effect>) {
        for e in effects {
            match e {
                Effect::OpenFile { pick, filter } => match self.open_dialog(filter) {
                    Ok(Some(path)) => self.send(Input::Chosen(pick, path.into())),
                    Ok(None) => {}
                    Err(error) => self.send(Input::DialogFailed(pick, format!("{error:?}"))),
                },
                Effect::SaveFile { pick, file_name } => match self.save_dialog(&file_name) {
                    Ok(Some(path)) => self.send(Input::Chosen(pick, path.into())),
                    Ok(None) => {}
                    Err(error) => self.send(Input::DialogFailed(pick, format!("{error:?}"))),
                },
                Effect::ReportPrompt {
                    summary,
                    description,
                } => {
                    let response = self.report_prompt(&summary, &description);
                    self.send(response);
                }
                Effect::CopyText(text) => self.copy(&text),
                Effect::OpenPath(path) => {
                    let _ = crate::external::open_path(&path);
                }
                Effect::StartTicking => {
                    if let Err(_e) = self.wnd.hwnd().SetTimer(TIMER_TICK, TICK_MS, None) {
                        let language = self.app.borrow().language;
                        let _ = self.wnd.hwnd().MessageBox(
                            crate::localization::get(language, "errors.timer"),
                            "freemkv",
                            co::MB::ICONERROR,
                        );
                    }
                }
                Effect::StopTicking => {
                    let _ = self.wnd.hwnd().KillTimer(TIMER_TICK);
                }
            }
        }
        self.render();
    }

    /// The OS open dialog (`IFileOpenDialog`), owned by and modal to the main window.
    fn open_dialog(&self, filter: Option<ui::FileFilter>) -> w::HrResult<Option<String>> {
        let dlg = w::CoCreateInstance::<w::IFileOpenDialog>(
            &co::CLSID::FileOpenDialog,
            None::<&w::IUnknown>,
            co::CLSCTX::INPROC_SERVER,
        )?;
        let opts = dlg.GetOptions()? | co::FOS::FORCEFILESYSTEM | co::FOS::FILEMUSTEXIST;
        dlg.SetOptions(opts)?;
        if let Some(f) = filter.and_then(ui::FileFilter::validated) {
            let spec = f
                .extensions
                .iter()
                .map(|e| format!("*.{e}"))
                .collect::<Vec<_>>()
                .join(";");
            dlg.SetFileTypes(&[(f.name, spec.as_str())])?;
        }
        if !dlg.Show(self.wnd.hwnd())? {
            return Ok(None);
        }
        dlg.GetResult()?
            .GetDisplayName(co::SIGDN::FILESYSPATH)
            .and_then(|path| {
                if path.is_empty() || path.contains('\0') {
                    Err(co::HRESULT::E_INVALIDARG)
                } else {
                    Ok(Some(path))
                }
            })
    }

    /// The OS save dialog; it asks before replacing a file, which the model relies on.
    fn save_dialog(&self, file_name: &str) -> w::HrResult<Option<String>> {
        if file_name.is_empty() || file_name.contains('\0') {
            return Err(co::HRESULT::E_INVALIDARG);
        }
        let dlg = w::CoCreateInstance::<w::IFileSaveDialog>(
            &co::CLSID::FileSaveDialog,
            None::<&w::IUnknown>,
            co::CLSCTX::INPROC_SERVER,
        )?;
        let opts = dlg.GetOptions()?
            | co::FOS::FORCEFILESYSTEM
            | co::FOS::OVERWRITEPROMPT
            | co::FOS::NOREADONLYRETURN;
        dlg.SetOptions(opts)?;
        dlg.SetFileName(file_name)?;
        if !dlg.Show(self.wnd.hwnd())? {
            return Ok(None);
        }
        dlg.GetResult()?
            .GetDisplayName(co::SIGDN::FILESYSPATH)
            .and_then(|path| {
                if path.is_empty() || path.contains('\0') {
                    Err(co::HRESULT::E_INVALIDARG)
                } else {
                    Ok(Some(path))
                }
            })
    }

    fn copy(&self, text: &str) {
        let Ok(clip) = self.wnd.hwnd().OpenClipboard() else {
            return;
        };
        let wide: Vec<u8> = text
            .replace("\r\n", "\n")
            .replace('\n', "\r\n")
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        let _ = clip.EmptyClipboard();
        let _ = clip.SetClipboardData(co::CF::UNICODETEXT, &wide);
    }

    fn tone(&self, c: &impl GuiWindow, tone: Tone) {
        let key = c.hwnd().ptr() as isize;
        let mut tones = self.tones.borrow_mut();
        tones.retain(|(k, _)| *k != key);
        if tone != Tone::Normal {
            tones.push((key, tone));
        }
    }

    // ── rendering ─────────────────────────────────────────────────────────

    /// Apply a fully-decided `View` to the controls. The only place controls are written.
    fn render(&self) {
        let v = self.view();
        self.painting.set(true);
        {
            let mut memo = self.memo.borrow_mut();
            if memo.language.replace(v.language) != Some(v.language) {
                memo.drives = None;
                memo.results = None;
                for (index, id) in [(0, "field.item"), (1, "field.value")] {
                    let _ = self
                        .list
                        .cols()
                        .get(index)
                        .set_title(crate::localization::get(v.language, id));
                }
                if let Ok(menu) = build_menu(v.language) {
                    let old = self.wnd.hwnd().GetMenu();
                    if self.wnd.hwnd().SetMenu(&menu).is_ok() {
                        if let Some(mut old) = old {
                            let _ = old.DestroyMenu();
                        }
                    }
                }
            }
            if memo.title != v.title {
                let _ = self.wnd.hwnd().SetWindowText(&v.title);
                memo.title.clone_from(&v.title);
            }
        }
        self.render_drives(&v);
        for (index, tab) in v.tabs.iter().enumerate() {
            let _ = self.tabs.items().get(index as u32).set_text(&tab.title);
        }
        if let Some(i) = Task::ALL.iter().position(|t| *t == v.task) {
            unsafe {
                self.tabs
                    .hwnd()
                    .SendMessage(msg::TcmSetCurSel { index: i as u32 });
            }
        }
        // Navigation follows the model's busy lock. Unsupported operations show
        // their availability explanation instead of silently snapping back.
        self.tabs
            .hwnd()
            .EnableWindow(v.controls_enabled && v.tabs.iter().any(|t| t.enabled));
        self.render_status(v.status.as_ref());
        self.render_results(v.results.as_ref());
        if self.memo.borrow().log != v.log {
            set_edit_lines(&self.log, &v.log);
            self.memo.borrow_mut().log.clone_from(&v.log);
        }
        self.render_menu(&v);
        self.relayout(&v);
        self.render_diagnostics(v.diagnostics.as_ref());
        self.render_analysis(&v);
        self.painting.set(false);
        if v.confirm.is_some() && !self.confirming.replace(true) {
            // Not from inside the handler that asked: the dialog runs its own modal loop.
            let _ = self.wnd.hwnd().SetTimer(TIMER_CONFIRM, 1, None);
        }
    }

    fn render_menu(&self, v: &View) {
        let Some(menu) = self.wnd.hwnd().GetMenu() else {
            return;
        };
        let _ = menu.EnableMenuItem(w::IdPos::Id(IDM_REFRESH), v.drives.refresh.enabled);
        let _ = self.wnd.hwnd().DrawMenuBar();
    }

    fn render_drives(&self, v: &View) {
        let bar = &v.drives;
        set_text(&self.drive_label, &bar.label);
        set_text(&self.drive_chips, &bar.chips.join("  \u{b7}  "));
        let changed = self.memo.borrow().drives.as_ref() != Some(&bar.items);
        if changed {
            self.drives.items().delete_all();
            if bar.items.is_empty() {
                let _ = self.drives.items().add(&[bar.placeholder.as_str()]);
            } else {
                let texts: Vec<&str> = bar.items.iter().map(|d| d.text.as_str()).collect();
                let _ = self.drives.items().add(&texts);
            }
            self.memo.borrow_mut().drives = Some(bar.items.clone());
        }
        self.drives
            .items()
            .select(Some(bar.selected.unwrap_or(0) as u32));
        self.drives
            .hwnd()
            .EnableWindow(v.controls_enabled && !bar.items.is_empty());
        self.refresh.bind(&bar.refresh);
    }

    fn render_status(&self, status: Option<&Status>) {
        let Some(s) = status else {
            for c in [&self.status, &self.progress_label, &self.note] {
                show(c, false);
            }
            show(&self.progress, false);
            self.cancel.unbind();
            return;
        };
        set_text(&self.status, &s.text);
        match &s.progress {
            Some(p) => {
                set_text(&self.progress_label, &p.label);
                match p.fraction {
                    Some(f) => {
                        self.progress.set_marquee(false);
                        self.progress
                            .set_position((f.clamp(0.0, 1.0) * 1000.0).round() as u32);
                    }
                    None => self.progress.set_marquee(true),
                }
            }
            None => self.progress.set_marquee(false),
        }
        set_text(&self.note, s.note.as_deref().unwrap_or(""));
        match &s.cancel {
            Some(b) => self.cancel.bind(b),
            None => self.cancel.unbind(),
        }
    }

    fn render_results(&self, results: Option<&Results>) {
        if self.memo.borrow().results.as_ref() == Some(&results.cloned()) {
            return;
        }
        self.memo.borrow_mut().results = Some(results.cloned());
        let _ = self.list.items().delete_all();
        send_raw(self.list.hwnd(), LVM_REMOVEALLGROUPS, 0, 0);
        let Some(r) = results else {
            return;
        };
        if let Some(b) = &r.open_results {
            self.open_results.bind(b);
        } else {
            self.open_results.unbind();
        }
        self.list.set_redraw(false);
        let grouped = !r.cards.is_empty();
        unsafe {
            let _ = self
                .list
                .hwnd()
                .SendMessage(msg::LvmEnableGroupView { enable: grouped });
        }
        if grouped {
            for (id, card) in r.cards.iter().enumerate() {
                self.add_group(id as i32, &card.title, card.subtitle.as_deref());
                for (label, value) in card_rows(&card.body) {
                    self.add_row(&label, &value, Some(id as i32));
                }
            }
        } else {
            for (label, value) in &r.fields {
                self.add_row(label, value, None);
            }
        }
        self.list.set_redraw(true);
        set_text(
            &self.failure,
            r.failure.as_ref().map_or("", |f| f.text.as_str()),
        );
        self.tone(&self.failure, Tone::Error);
        match &r.failure {
            Some(f) => self.save_log.bind(&f.save_log),
            None => self.save_log.unbind(),
        }
        set_text(&self.notice, r.notice.as_deref().unwrap_or(""));
        self.view_log.bind(&r.view_log);
        self.submit_report.bind(&r.submit_report);
    }

    fn add_group(&self, id: i32, title: &str, subtitle: Option<&str>) {
        let mut header = w::WString::from_str(title);
        let mut sub = w::WString::from_str(subtitle.unwrap_or(""));
        let mut g = w::LVGROUP::default();
        g.mask = co::LVGF::HEADER | co::LVGF::GROUPID | co::LVGF::STATE;
        g.iGroupId = id;
        g.state = co::LVGS::NORMAL;
        g.set_pszHeader(Some(&mut header));
        if subtitle.is_some() {
            g.mask |= co::LVGF::SUBTITLE;
            g.set_pszSubtitle(Some(&mut sub));
        }
        unsafe {
            let _ = self
                .list
                .hwnd()
                .SendMessage(msg::LvmInsertGroup { group: &g });
        }
    }

    fn add_row(&self, label: &str, value: &str, group: Option<i32>) {
        let Ok(item) = self.list.items().add(&[label, value], None, ()) else {
            return;
        };
        if let Some(id) = group {
            let mut lvi = w::LVITEM::default();
            lvi.mask = co::LVIF::GROUPID;
            lvi.iItem = item.index() as i32;
            lvi.iGroupId = unsafe { co::LVI_GROUPID::from_raw(id) };
            unsafe {
                let _ = self
                    .list
                    .hwnd()
                    .SendMessage(msg::LvmSetItem { lvitem: &lvi });
            }
        }
    }

    // ── layout ────────────────────────────────────────────────────────────

    /// Position every main-window control for the view at the window's size and DPI.
    fn relayout(&self, v: &View) {
        let s = Scale::new(self.dpi.get());
        let Ok(rc) = self.wnd.hwnd().GetClientRect() else {
            return;
        };
        let (cw, ch) = (rc.right - rc.left, rc.bottom - rc.top);
        let pad = s.px(lay::PAD);
        let mut col = Column::new(pad, pad, cw - 2 * pad, s.px(lay::GAP));

        // Drive bar. A drop-down list's height includes its open list.
        let mut line = col.line(s.px(lay::ROW_H));
        put(
            &self.drive_label,
            Line::centre(line.take(s.px(lay::DRIVE_LABEL_W)), s.px(lay::LINE_H)),
        );
        put(&self.refresh.btn, line.take_right(s.px(lay::REFRESH_W)));
        let combo = line.rest();
        put(
            &self.drives,
            Rect {
                h: s.px(300),
                ..combo
            },
        );
        if v.drives.chips.is_empty() {
            show(&self.drive_chips, false);
        } else {
            self.tone(&self.drive_chips, Tone::Secondary);
            put(&self.drive_chips, col.take(s.px(lay::LINE_H)));
        }
        col.space(s.px(4));
        put(&self.tabs, col.take(s.px(lay::ROW_H)));
        col.space(s.px(4));

        self.layout_panel(s, &v.panel, &mut col);
        put(&self.rule, col.take(2));

        show(&self.log_title, false);
        show(&self.log, false);

        let (Some(st), Some(r)) = (&v.status, &v.results) else {
            for c in [
                &self.status,
                &self.progress_label,
                &self.note,
                &self.failure,
                &self.notice,
            ] {
                show(c, false);
            }
            show(&self.progress, false);
            show(&self.list, false);
            for b in [
                &self.cancel,
                &self.open_results,
                &self.save_log,
                &self.view_log,
                &self.submit_report,
            ] {
                b.unbind();
            }
            return;
        };
        // Status and progress.
        put(&self.status, col.take(s.px(lay::LINE_H)));
        let running = st.progress.is_some();
        if running {
            put(&self.progress_label, col.take(s.px(lay::LINE_H)));
            put(&self.progress, col.take(s.px(lay::PROGRESS_H)));
        } else {
            show(&self.progress_label, false);
            show(&self.progress, false);
        }
        if st.note.is_some() {
            let h = measure(
                self.note.hwnd(),
                &self.note.hwnd().GetWindowText().unwrap_or_default(),
                Some(col.w),
            )
            .1;
            self.tone(&self.note, Tone::Secondary);
            put(&self.note, col.take(h));
        } else {
            show(&self.note, false);
        }
        if let Some(b) = &st.cancel {
            let mut l = col.line(s.px(lay::ROW_H));
            put(&self.cancel.btn, l.take(self.button_w(s, b)));
        }

        // Results: the list takes what the rows above and below it leave.
        let bottom = ch - pad;
        if let Some(b) = &r.open_results {
            let mut l = col.line(s.px(lay::ROW_H));
            put(&self.open_results.btn, l.take(self.button_w(s, b)));
        }
        let fail_h = r
            .failure
            .as_ref()
            .map(|f| measure(self.failure.hwnd(), &f.text, Some(col.w)).1);
        let notice_h = r
            .notice
            .as_ref()
            .map(|n| measure(self.notice.hwnd(), n, Some(col.w)).1);
        let gap = s.px(lay::GAP);
        let row = s.px(lay::ROW_H) + gap;
        let tail = fail_h.map_or(0, |h| h + gap) + notice_h.map_or(0, |h| h + gap) + row;
        let has_rows = !r.cards.is_empty() || !r.fields.is_empty();
        if has_rows {
            let h = (bottom - col.y - tail - gap).max(s.px(lay::RESULTS_MIN_H).min(bottom - col.y));
            let lr = col.take(h);
            put(&self.list, lr);
            send_raw(
                self.list.hwnd(),
                LVM_SETCOLUMNWIDTH,
                1,
                LVSCW_AUTOSIZE_USEHEADER,
            );
        } else {
            show(&self.list, false);
        }
        match fail_h {
            Some(h) => {
                put(&self.failure, col.take(h));
            }
            None => show(&self.failure, false),
        }
        match notice_h {
            Some(h) => put(&self.notice, col.take(h)),
            None => show(&self.notice, false),
        }
        let mut l = col.line(s.px(lay::ROW_H));
        put(&self.view_log.btn, l.take(self.button_w(s, &r.view_log)));
        if let Some(f) = &r.failure {
            put(&self.save_log.btn, l.take(self.button_w(s, &f.save_log)));
        }
        put(
            &self.submit_report.btn,
            l.take(self.button_w(s, &r.submit_report)),
        );
    }

    fn button_w(&self, s: Scale, b: &Button) -> i32 {
        let (w, _) = measure(self.view_log.btn.hwnd(), &b.text, None);
        lay::button_width(s, w, b.style == ButtonStyle::Primary)
    }

    /// Lay out (and, when the form changed, rebind) the task form from the pools.
    fn layout_panel(&self, s: Scale, items: &[Item], col: &mut Column) {
        let fresh = {
            let memo = self.memo.borrow();
            memo.panel.as_deref() != Some(items)
        };
        // The pools are sized for every form the model makes (tested in win_layout).
        debug_assert!(lay::panel_needs(items).fits());
        let (mut t, mut l, mut b, mut c) = (0, 0, 0, 0);
        let row_h = s.px(lay::ROW_H);
        for item in items {
            match item {
                Item::Origin(origin) => {
                    let Some(lbl) = self.texts.get(t) else {
                        continue;
                    };
                    t += 1;
                    let translated =
                        crate::localization::render(self.app.borrow().language, origin.label_id());
                    let text = translated.as_str();
                    if fresh {
                        set_text(lbl, text);
                        set_font(lbl.hwnd(), s.dpi(), Face::Bold);
                        self.tone(
                            lbl,
                            match origin {
                                crate::ui::FileOrigin::OemLikely => Tone::Success,
                                crate::ui::FileOrigin::UserBackupLikely => Tone::Caution,
                                crate::ui::FileOrigin::Unknown => Tone::Secondary,
                            },
                        );
                    }
                    let h = measure(lbl.hwnd(), text, Some(col.w)).1;
                    put(lbl, col.take(h));
                }
                Item::Text(text) | Item::Heading(text) | Item::Note(text) | Item::Warning(text) => {
                    let Some(lbl) = self.texts.get(t) else {
                        continue;
                    };
                    t += 1;
                    let (face, tone) = match item {
                        Item::Heading(_) => (Face::Bold, Tone::Normal),
                        Item::Note(_) => (Face::Ui, Tone::Secondary),
                        Item::Warning(_) => (Face::Ui, Tone::Caution),
                        _ => (Face::Ui, Tone::Normal),
                    };
                    if fresh {
                        set_text(lbl, text);
                        set_font(lbl.hwnd(), s.dpi(), face);
                        self.tone(lbl, tone);
                    }
                    let h = measure(lbl.hwnd(), text, Some(col.w)).1;
                    put(lbl, col.take(h));
                }
                Item::Check {
                    id,
                    text,
                    checked,
                    enabled,
                } => {
                    let Some((chk, slot)) = self.checks.get(c) else {
                        continue;
                    };
                    c += 1;
                    if fresh {
                        set_text(chk, &mnemonic_free(text));
                    }
                    slot.set(Some(*id));
                    chk.set_check(*checked);
                    chk.hwnd().EnableWindow(*enabled);
                    put(chk, col.take(s.px(lay::CHECK_H)));
                }
                Item::Path { button, path } => {
                    let mut line = col.line(row_h);
                    if let Some(bound) = self.buttons.get(b) {
                        b += 1;
                        bound.bind(button);
                        put(&bound.btn, line.take(self.button_w(s, button)));
                    }
                    if let Some(p) = path {
                        if let Some(lbl) = self.lines.get(l) {
                            l += 1;
                            set_text(lbl, &p.full);
                            put(lbl, Line::centre(line.rest(), s.px(lay::LINE_H)));
                        }
                    }
                }
                Item::Buttons { label, buttons } => {
                    let mut line = col.line(row_h);
                    if let Some(text) = label {
                        if let Some(lbl) = self.lines.get(l) {
                            l += 1;
                            set_text(lbl, text);
                            put(
                                lbl,
                                Line::centre(line.take(s.px(lay::LEAD_W)), s.px(lay::LINE_H)),
                            );
                        }
                    }
                    for button in buttons {
                        let Some(bound) = self.buttons.get(b) else {
                            continue;
                        };
                        b += 1;
                        bound.bind(button);
                        put(&bound.btn, line.take(self.button_w(s, button)));
                    }
                }
            }
        }
        for lbl in &self.texts[t.min(self.texts.len())..] {
            show(lbl, false);
        }
        for lbl in &self.lines[l.min(self.lines.len())..] {
            show(lbl, false);
        }
        for bound in &self.buttons[b.min(self.buttons.len())..] {
            bound.unbind();
        }
        for (chk, slot) in &self.checks[c.min(self.checks.len())..] {
            show(chk, false);
            slot.set(None);
        }
        if fresh {
            self.memo.borrow_mut().panel = Some(items.to_vec());
        }
    }

    // ── the extra windows ─────────────────────────────────────────────────

    fn render_diagnostics(&self, d: Option<&Diagnostics>) {
        let win = &self.diag;
        let Some(d) = d else {
            win.wnd.hwnd().ShowWindow(co::SW::HIDE);
            self.memo.borrow_mut().diag_lines = None;
            return;
        };
        set_text(&win.wnd, &d.title);
        let s = Scale::new(window_dpi(win.wnd.hwnd()));
        let mut line = Column::new(s.px(lay::PAD), s.px(lay::PAD), 0, 0).line(s.px(lay::ROW_H));
        line.right = i32::MAX / 2;
        for (i, bound) in win.buttons.iter().enumerate() {
            match d.buttons.get(i) {
                Some(b) => {
                    bound.bind(b);
                    put(&bound.btn, line.take(self.button_w(s, b)));
                }
                None => bound.unbind(),
            }
        }
        set_text(&win.hint, &d.hint);
        set_text(&win.path, d.path.as_deref().unwrap_or(""));
        set_text(&win.notice, d.notice.as_deref().unwrap_or(""));
        let fresh = self
            .memo
            .borrow()
            .diag_lines
            .as_ref()
            .is_none_or(|l| !Arc::ptr_eq(l, &d.lines));
        if fresh {
            set_edit_lines(&win.text, &d.lines);
            self.memo.borrow_mut().diag_lines = Some(d.lines.clone());
        }
        if !win.wnd.hwnd().IsWindowVisible() {
            win.wnd.hwnd().ShowWindow(co::SW::SHOW);
        }
    }

    fn render_analysis(&self, v: &View) {
        let win = &self.analysis;
        let Some(a) = &v.analysis else {
            win.wnd.hwnd().ShowWindow(co::SW::HIDE);
            self.memo.borrow_mut().tree = None;
            return;
        };
        set_text(&win.notice, a.notice.as_deref().unwrap_or(""));
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
        set_text(&win.wnd, &tree.title);
        set_text(&win.heading, &tree.heading);
        // Top-level button rows join the actions, as in the macOS shell.
        let extra: Vec<Button> = tree
            .nodes
            .iter()
            .filter_map(|n| match &n.kind {
                NodeKind::Buttons(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let s = Scale::new(window_dpi(win.wnd.hwnd()));
        let mut line = Column::new(s.px(lay::PAD), s.px(lay::PAD), 0, 0).line(s.px(lay::ROW_H));
        line.right = i32::MAX / 2;
        let all: Vec<&Button> = tree.actions.iter().chain(&extra).collect();
        for (i, bound) in win.buttons.iter().enumerate() {
            match all.get(i) {
                Some(b) => {
                    bound.bind(b);
                    put(&bound.btn, line.take(self.button_w(s, b)));
                }
                None => bound.unbind(),
            }
        }
        let items = win.tree.items();
        let _ = items.delete_all();
        for n in &tree.nodes {
            if matches!(n.kind, NodeKind::Buttons(_)) {
                continue;
            }
            for (text, kids, open) in tree_rows(n) {
                if let Ok(item) = items.add_root(&text, None, ()) {
                    add_children(&item, &kids);
                    let _ = item.expand(open);
                }
            }
        }
        self.memo.borrow_mut().tree = Some(tree.clone());
        if !win.wnd.hwnd().IsWindowVisible() {
            win.wnd.hwnd().ShowWindow(co::SW::SHOW);
        }
        let _ = win.wnd.hwnd().SetForegroundWindow();
    }

    // ── the confirmation ──────────────────────────────────────────────────

    /// The Flash/Recovery confirmation as a modal task dialog. Its verification box is the
    /// model's acknowledgement: unticked on every opening, and the confirm button stays
    /// disabled (and refuses a click) until the model says it may run. Enter and Escape
    /// both mean Cancel; the drive and image were frozen by the model when it asked.
    fn confirm(&self) {
        let Some(c) = self.view().confirm else {
            self.confirming.set(false);
            return;
        };
        if c.code_entry.is_some() {
            self.confirm_code(&c);
            return;
        }
        let mut content = format!("{}\n\n{}", c.details.join("\n"), c.danger);
        if let Some(prompt) = &c.prompt {
            content.push_str(&format!("\n\n{prompt}"));
        }
        let footer = c
            .warnings
            .iter()
            .map(String::as_str)
            .chain(c.note.as_deref())
            .collect::<Vec<_>>()
            .join("\n\n");
        let technical_details = c.technical_details.join("\n\n");
        let me = self.clone();
        let cfg = w::TASKDIALOGCONFIG {
            hwnd_parent: Some(self.wnd.hwnd()),
            flags: confirm_flags(),
            window_title: Some(&c.title),
            main_icon: w::IconIdTd::Td(co::TD_ICON::WARNING),
            main_instruction: Some(&c.title),
            content: Some(&content),
            buttons: &[
                (TD_CONFIRM, c.confirm.text.as_str()),
                (TD_CANCEL, c.cancel.text.as_str()),
            ],
            default_button_id: TD_CANCEL,
            verification_text: (!c.ack_text.is_empty()).then_some(&c.ack_text),
            // Expanded information is native-local and starts collapsed. Safety
            // warnings remain in the always-visible content/footer above.
            more_info: (!technical_details.is_empty()).then_some(technical_details.as_str()),
            more_info_btn_collapsed: Some(&c.details_label),
            more_info_btn_expanded: Some(&c.hide_details_label),
            footer_text: (!footer.is_empty()).then_some(footer.as_str()),
            callback: Some(Box::new(move |hwnd: &w::HWND, tdn: w::Tdn| {
                me.on_confirm(hwnd, tdn)
            })),
            ..Default::default()
        };
        let answer = w::TaskDialogIndirect(&cfg);
        self.confirming.set(false);
        // Answer only a confirmation the model still wants answered.
        let Some(c) = self.view().confirm else {
            self.render();
            return;
        };
        let chosen = matches!(answer, Ok((id, _, _)) if id.raw() == TD_CONFIRM);
        self.send(if chosen && c.confirm.enabled {
            Input::Confirm
        } else {
            Input::CancelConfirm
        });
    }

    /// Own the draft outside App: Windows pumps messages while the modal is open.
    /// Capture edits before destruction, including closing with Escape or the title bar.
    fn report_prompt(&self, summary: &str, description: &str) -> Input {
        let language = self.app.borrow().language;
        let tr = |key| crate::localization::get(language, key);
        let limit_message = crate::localization::render(
            language,
            &crate::localization::message(
                "report.description_too_long",
                &[("summary", summary.to_owned())],
            ),
        );
        let summary = crate::localization::render(language, summary);
        let dialog = gui::WindowModal::new(gui::WindowModalOpts {
            title: tr("report.prompt_title"),
            size: gui::dpi(620, 430),
            ..Default::default()
        });
        let summary_label = gui::Label::new(
            &dialog,
            gui::LabelOpts {
                text: &summary,
                position: gui::dpi(20, 20),
                size: gui::dpi(580, 100),
                control_style: co::SS::LEFT | co::SS::NOPREFIX,
                ..Default::default()
            },
        );
        let _label = gui::Label::new(
            &dialog,
            gui::LabelOpts {
                text: tr("report.description_label"),
                position: gui::dpi(20, 125),
                size: gui::dpi(580, 25),
                control_style: co::SS::LEFT | co::SS::NOPREFIX,
                ..Default::default()
            },
        );
        let entry = gui::Edit::new(
            &dialog,
            gui::EditOpts {
                text: description,
                position: gui::dpi(20, 155),
                width: gui::dpi_x(580),
                height: gui::dpi_y(180),
                control_style: co::ES::MULTILINE
                    | co::ES::AUTOVSCROLL
                    | co::ES::WANTRETURN
                    | co::ES::NOHIDESEL,
                window_style: co::WS::CHILD
                    | co::WS::VISIBLE
                    | co::WS::TABSTOP
                    | co::WS::GROUP
                    | co::WS::VSCROLL,
                ..Default::default()
            },
        );
        let cancel = gui::Button::new(
            &dialog,
            gui::ButtonOpts {
                text: tr("ui.cancel"),
                position: gui::dpi(240, 380),
                width: gui::dpi_x(170),
                ..Default::default()
            },
        );
        let proceed = gui::Button::new(
            &dialog,
            gui::ButtonOpts {
                text: tr("report.send"),
                position: gui::dpi(430, 380),
                width: gui::dpi_x(170),
                ..Default::default()
            },
        );
        let draft = Rc::new(RefCell::new(description.to_owned()));
        let accepted = Rc::new(Cell::new(false));
        let field = entry.clone();
        let button = proceed.clone();
        let label = summary_label.clone();
        #[cfg(debug_assertions)]
        let popup = dialog.clone();
        let initial_valid = description.len() <= crate::support::DESCRIPTION_LIMIT;
        let initial_message = if initial_valid {
            summary.clone()
        } else {
            limit_message.clone()
        };
        dialog.on().wm_create(move |_| {
            // The byte limit is visible validation, never silent native truncation.
            field.limit_text(None);
            button.hwnd().EnableWindow(initial_valid);
            set_text(&label, &initial_message);
            #[cfg(debug_assertions)]
            gate::arm_report_probe(popup.hwnd())?;
            Ok(0)
        });
        let field = entry.clone();
        let text = draft.clone();
        let button = proceed.clone();
        let label = summary_label.clone();
        entry.on().en_change(move || {
            if let Ok(value) = field.text() {
                let valid = value.len() <= crate::support::DESCRIPTION_LIMIT;
                *text.borrow_mut() = value;
                button.hwnd().EnableWindow(valid);
                set_text(&label, if valid { &summary } else { &limit_message });
            }
            Ok(())
        });
        let popup = dialog.clone();
        cancel.on().bn_clicked(move || {
            popup.close();
            Ok(())
        });
        // IsDialogMessage generates IDCANCEL for Escape even without an IDCANCEL button.
        let popup = dialog.clone();
        dialog.on().wm_command(2u16, co::BN::CLICKED, move || {
            popup.close();
            Ok(())
        });
        let popup = dialog.clone();
        let chosen = accepted.clone();
        let text = draft.clone();
        proceed.on().bn_clicked(move || {
            if text.borrow().len() > crate::support::DESCRIPTION_LIMIT {
                return Ok(());
            }
            chosen.set(true);
            popup.close();
            Ok(())
        });
        #[cfg(debug_assertions)]
        gate::install_report_probe(&dialog, &entry, &summary_label, &proceed, &cancel);
        // Keep the label alive in release builds, too.
        let _summary_label = summary_label;
        let shown = dialog.show_modal(&self.wnd);
        let description = draft.borrow().clone();
        if shown.is_ok() && accepted.get() {
            Input::SendReport(description)
        } else {
            Input::DismissReport(description)
        }
    }

    /// Typed challenge uses a native edit control; policy remains in the shared model.
    fn confirm_code(&self, c: &Confirm) {
        let dialog = gui::WindowModal::new(gui::WindowModalOpts {
            title: &c.title,
            size: gui::dpi(600, 360),
            ..Default::default()
        });
        let text = format!(
            "{}\n\n{}\n\n{}",
            c.details.join("\n"),
            c.danger,
            c.prompt.as_deref().unwrap_or_default()
        );
        let _message = gui::Label::new(
            &dialog,
            gui::LabelOpts {
                text: &text,
                position: gui::dpi(20, 20),
                size: gui::dpi(560, 230),
                control_style: co::SS::LEFT | co::SS::NOPREFIX,
                ..Default::default()
            },
        );
        let entry = gui::Edit::new(
            &dialog,
            gui::EditOpts {
                text: c.code_entry.as_deref().unwrap_or_default(),
                position: gui::dpi(20, 260),
                width: gui::dpi_x(180),
                control_style: co::ES::AUTOHSCROLL | co::ES::NUMBER,
                ..Default::default()
            },
        );
        let cancel = gui::Button::new(
            &dialog,
            gui::ButtonOpts {
                text: &c.cancel.text,
                position: gui::dpi(210, 310),
                width: gui::dpi_x(170),
                ..Default::default()
            },
        );
        let proceed = gui::Button::new(
            &dialog,
            gui::ButtonOpts {
                text: &c.confirm.text,
                position: gui::dpi(390, 310),
                width: gui::dpi_x(190),
                ..Default::default()
            },
        );
        let accepted = Rc::new(Cell::new(false));
        let button = proceed.clone();
        let field = entry.clone();
        dialog.on().wm_create(move |_| {
            field.limit_text(Some(5));
            button.hwnd().EnableWindow(false);
            Ok(0)
        });
        let me = self.clone();
        let field = entry.clone();
        let button = proceed.clone();
        entry.on().en_change(move || {
            me.app
                .borrow_mut()
                .dispatch(Input::FamilyOverrideCode(field.text().unwrap_or_default()));
            button
                .hwnd()
                .EnableWindow(me.view().confirm.is_some_and(|c| c.confirm.enabled));
            Ok(())
        });
        let popup = dialog.clone();
        cancel.on().bn_clicked(move || {
            popup.close();
            Ok(())
        });
        let popup = dialog.clone();
        let chosen = accepted.clone();
        let me = self.clone();
        proceed.on().bn_clicked(move || {
            if me.view().confirm.is_some_and(|c| c.confirm.enabled) {
                chosen.set(true);
                popup.close();
            }
            Ok(())
        });
        let shown = dialog.show_modal(&self.wnd);
        self.confirming.set(false);
        self.send(if shown.is_ok() && accepted.get() {
            Input::Confirm
        } else {
            Input::CancelConfirm
        });
    }

    fn on_confirm(&self, hwnd: &w::HWND, tdn: w::Tdn) -> co::HRESULT {
        let enabled = |me: &Self| {
            me.view()
                .confirm
                .is_some_and(|c: Confirm| c.confirm.enabled)
        };
        #[cfg(debug_assertions)]
        if let w::Tdn::ExpandoButtonClicked(expanded) = tdn {
            gate::disclosure_changed(expanded);
        }
        #[cfg(debug_assertions)]
        if matches!(tdn, w::Tdn::Timer(_)) && gate::probe(self, hwnd) {
            return co::HRESULT::S_OK;
        }
        match tdn {
            w::Tdn::Created => {
                #[cfg(debug_assertions)]
                self.risk_box.set(false);
                send_raw(
                    hwnd,
                    TDM_ENABLE_BUTTON,
                    TD_CONFIRM.into(),
                    isize::from(enabled(self)),
                );
            }
            w::Tdn::VerificationClicked(on) => {
                #[cfg(debug_assertions)]
                self.risk_box.set(on);
                let _ = self
                    .app
                    .borrow_mut()
                    .dispatch(Input::SetCheck(CheckId::RiskAck, on));
                send_raw(
                    hwnd,
                    TDM_ENABLE_BUTTON,
                    TD_CONFIRM.into(),
                    isize::from(enabled(self)),
                );
            }
            w::Tdn::ButtonClicked(id) if id == TD_CONFIRM && !enabled(self) => {
                return co::HRESULT::S_FALSE;
            }
            w::Tdn::Timer(_) if self.view().confirm.is_none() => {
                send_raw(hwnd, TDM_CLICK_BUTTON, TD_CANCEL.into(), 0);
            }
            _ => {}
        }
        co::HRESULT::S_OK
    }

    // ── events ────────────────────────────────────────────────────────────

    /// The main window's fonts at `dpi`; the task form re-styles on its next render.
    fn apply_fonts(&self, dpi: u32) {
        self.dpi.set(dpi);
        apply_ui_font(self.wnd.hwnd(), dpi);
        // Native tabs otherwise crowd their labels against the borders. Reapply
        // their internal padding with the fonts when changing monitor DPI.
        let s = Scale::new(dpi);
        unsafe {
            self.tabs.hwnd().SendMessage(msg::TcmSetPadding {
                horizontal: s.px(12) as u16,
                vertical: s.px(3) as u16,
            });
        }
        set_font(self.log.hwnd(), dpi, Face::Mono);
        set_font(self.status.hwnd(), dpi, Face::Bold);
        self.memo.borrow_mut().panel = None;
    }

    fn on_bound(&self, b: &Bound) {
        let me = self.clone();
        let input = b.input.clone();
        b.btn.on().bn_clicked(move || {
            let i = input.borrow().clone();
            if let Some(i) = i {
                me.send(i);
            }
            Ok(())
        });
    }

    fn events(&self) {
        for b in [
            &self.refresh,
            &self.cancel,
            &self.open_results,
            &self.save_log,
            &self.view_log,
            &self.submit_report,
        ]
        .into_iter()
        .chain(self.buttons.iter())
        .chain(self.diag.buttons.iter())
        .chain(self.analysis.buttons.iter())
        {
            self.on_bound(b);
        }
        for (chk, slot) in self.checks.iter() {
            let me = self.clone();
            let (chk2, slot) = (chk.clone(), slot.clone());
            chk.on().bn_clicked(move || {
                if let Some(id) = slot.get() {
                    me.send(Input::SetCheck(id, chk2.is_checked()));
                }
                Ok(())
            });
        }
        let me = self.clone();
        self.drives.on().cbn_sel_change(move || {
            let has_drives = me
                .memo
                .borrow()
                .drives
                .as_ref()
                .is_some_and(|d| !d.is_empty());
            if let (false, true, Some(i)) = (
                me.painting.get(),
                has_drives,
                me.drives.items().selected_index(),
            ) {
                me.send(Input::SelectDrive(i as usize));
            }
            Ok(())
        });
        let me = self.clone();
        self.tabs.on().tcn_sel_change(move || {
            let i = unsafe { me.tabs.hwnd().SendMessage(msg::TcmGetCurSel {}) };
            match i.and_then(|i| Task::ALL.get(i as usize)) {
                Some(task) if !me.painting.get() => me.send(Input::SelectTask(*task)),
                _ => me.render(),
            }
            Ok(())
        });

        for (id, input) in [
            (IDM_REFRESH, Input::Refresh),
            (IDM_DIAGNOSTICS, Input::OpenDiagnostics),
        ] {
            let me = self.clone();
            self.wnd.on().wm_command_acc_menu(id, move || {
                me.send(input.clone());
                Ok(())
            });
        }
        for (index, language) in crate::localization::Language::ALL.into_iter().enumerate() {
            let me = self.clone();
            self.wnd
                .on()
                .wm_command_acc_menu(IDM_LANGUAGE_FIRST + index as u16, move || {
                    me.send(Input::SetLanguage(language));
                    Ok(())
                });
        }
        // File > Exit is the window's X: one guarded way out.
        let me = self.clone();
        self.wnd.on().wm_command_acc_menu(IDM_EXIT, move || {
            me.wnd.close();
            Ok(())
        });
        // Edit > Copy / Select All act on the focused control (the log, a path field).
        for (id, wm, wp, lp) in [
            (IDM_COPY, co::WM::COPY.raw(), 0usize, 0isize),
            (IDM_SELECT_ALL, EM_SETSEL, 0, -1),
        ] {
            self.wnd.on().wm_command_acc_menu(id, move || {
                if let Some(focused) = w::HWND::GetFocus() {
                    send_raw(&focused, wm, wp, lp);
                }
                Ok(())
            });
        }

        let me = self.clone();
        self.wnd.on().wm_create(move |_| {
            me.apply_fonts(window_dpi(me.wnd.hwnd()));
            for win in [me.diag.wnd.hwnd(), me.analysis.wnd.hwnd()] {
                apply_ui_font(win, window_dpi(win));
            }
            set_font(
                me.diag.text.hwnd(),
                window_dpi(me.diag.wnd.hwnd()),
                Face::Mono,
            );
            set_font(
                me.analysis.heading.hwnd(),
                window_dpi(me.analysis.wnd.hwnd()),
                Face::Large,
            );
            set_icons(me.wnd.hwnd());
            for tab in me.view().tabs {
                unsafe {
                    me.tabs.items().add(&tab.title);
                }
            }
            let fx = me.app.borrow_mut().start();
            me.perform(fx);
            Ok(0)
        });
        let me = self.clone();
        self.wnd.on().wm_size(move |_| {
            let v = me.view();
            me.painting.set(true);
            me.relayout(&v);
            me.painting.set(false);
            Ok(())
        });
        let me = self.clone();
        self.wnd.on().wm_get_min_max_info(move |p| {
            let (w, h) = lay::min_size(me.dpi.get());
            let frame = w::AdjustWindowRectExForDpi(
                w::RECT {
                    left: 0,
                    top: 0,
                    right: w,
                    bottom: h,
                },
                me.wnd.hwnd().style(),
                true,
                me.wnd.hwnd().style_ex(),
                me.dpi.get(),
            );
            if let Ok(r) = frame {
                p.info.ptMinTrackSize = w::POINT::with(r.right - r.left, r.bottom - r.top);
            }
            Ok(())
        });
        // Moved to a monitor with another scale: new fonts, the suggested size, a relayout.
        let me = self.clone();
        self.wnd.on().wm(co::WM::DPICHANGED, move |p: msg::Wm| {
            me.apply_fonts((p.wparam & 0xffff) as u32);
            let r = unsafe { std::ptr::read(p.lparam as *const w::RECT) };
            let _ = me.wnd.hwnd().SetWindowPos(
                w::HwndPlace::None,
                w::POINT::with(r.left, r.top),
                w::SIZE::with(r.right - r.left, r.bottom - r.top),
                co::SWP::NOZORDER | co::SWP::NOACTIVATE,
            );
            me.render();
            Ok(0)
        });
        let me = self.clone();
        self.wnd.on().wm_timer(TIMER_TICK, move || {
            let fx = me.app.borrow_mut().poll();
            me.perform(fx);
            Ok(())
        });
        let me = self.clone();
        self.wnd.on().wm_timer(TIMER_CONFIRM, move || {
            let _ = me.wnd.hwnd().KillTimer(TIMER_CONFIRM);
            me.confirm();
            Ok(())
        });
        // The model decides whether closing would orphan a job; the shell only says so.
        let me = self.clone();
        self.wnd.on().wm_close(move || {
            if me.view().can_close {
                me.wnd.hwnd().DestroyWindow()?;
            } else {
                // MessageBox pumps window events; polling must be able to borrow App.
                let message =
                    crate::localization::render(me.app.borrow().language, ui::CLOSE_BLOCKED);
                me.wnd
                    .hwnd()
                    .MessageBox(&message, "freemkv", co::MB::ICONWARNING)?;
            }
            Ok(())
        });
        let me = self.clone();
        self.wnd.on().wm_ctl_color_static(move |p| {
            let key = p.hwnd.ptr() as isize;
            let tone = me
                .tones
                .borrow()
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, t)| *t);
            let color = match tone {
                Some(Tone::Secondary) => w::GetSysColor(co::COLOR::GRAYTEXT),
                Some(Tone::Caution) => w::COLORREF::from_rgb(160, 70, 0),
                Some(Tone::Error) => w::COLORREF::from_rgb(170, 30, 30),
                Some(Tone::Success) => w::COLORREF::from_rgb(20, 125, 55),
                Some(Tone::Normal) | None => w::GetSysColor(co::COLOR::WINDOWTEXT),
            };
            let _ = p.hdc.SetTextColor(color);
            let _ = p.hdc.SetBkColor(w::GetSysColor(co::COLOR::BTNFACE));
            Ok(w::HBRUSH::GetSysColorBrush(co::COLOR::BTNFACE)?)
        });
        // Closing an extra window is the model's Close.
        for (win, input) in [
            (self.diag.wnd.clone(), Input::CloseDiagnostics),
            (self.analysis.wnd.clone(), Input::CloseResults),
        ] {
            let me = self.clone();
            win.on().wm_close(move || {
                me.send(input.clone());
                Ok(())
            });
        }
    }
}

/// A card's rows as (label, value) pairs for the list view.
fn card_rows(body: &CardBody) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match body {
        CardBody::Rows(rows) => out.extend(rows.iter().cloned()),
        CardBody::Media { left, right } => {
            for r in left.iter().chain(right) {
                out.push((r.label.clone(), media_ticks(r)));
            }
        }
    }
    out
}

fn glyph(on: bool) -> char {
    if on {
        '\u{2611}'
    } else {
        '\u{2610}'
    }
}

/// "R/W: ☑ ☐", with a blank for a capability the drive did not report.
fn media_ticks(r: &MediaRow) -> String {
    let tick = |t: Tri| match t {
        Tri::Yes => glyph(true),
        Tri::No => glyph(false),
        Tri::Unknown => ' ',
    };
    match r.write {
        Some(wr) => format!(
            "{}: {} {}",
            crate::localization::get(crate::localization::Language::En, "media.header"),
            tick(r.read),
            tick(wr)
        ),
        None => format!(
            "{}: {}",
            crate::localization::get(crate::localization::Language::En, "media.header"),
            tick(r.read)
        ),
    }
}

/// One analysis node as tree rows: (text, children, expanded). A table is a row per line.
fn tree_rows(n: &Node) -> Vec<(String, Vec<Node>, bool)> {
    match &n.kind {
        NodeKind::Section(name) => vec![(name.clone(), n.children.clone(), n.open)],
        NodeKind::Field { label, value } => vec![(format!("{label} {value}"), Vec::new(), false)],
        NodeKind::Text(t) | NodeKind::Note(t) | NodeKind::Mono(t) => {
            vec![(t.clone(), Vec::new(), false)]
        }
        NodeKind::Buttons(b) => vec![(
            b.iter()
                .map(|b| b.text.as_str())
                .collect::<Vec<_>>()
                .join(" \u{00B7} "),
            Vec::new(),
            false,
        )],
        NodeKind::Table { header, rows } => rows
            .iter()
            .map(|line| {
                let rest = header
                    .iter()
                    .zip(line)
                    .skip(1)
                    .map(|(h, c)| format!("{h}: {c}"))
                    .collect::<Vec<_>>()
                    .join("   \u{00B7}   ");
                let first = line.first().cloned().unwrap_or_default();
                (format!("{first}   \u{00B7}   {rest}"), Vec::new(), false)
            })
            .collect(),
    }
}

fn add_children(parent: &gui::TreeViewItem<()>, kids: &[Node]) {
    for k in kids {
        for (text, grand, open) in tree_rows(k) {
            if let Ok(item) = parent.add_child(&text, None, ()) {
                add_children(&item, &grand);
                if open {
                    let _ = item.expand(true);
                }
            }
        }
    }
}

/// Run the Win32 shell until the window closes.
pub fn run() -> i32 {
    // The file dialogs are COM objects: the apartment lives as long as the app.
    let _com = w::CoInitializeEx(co::COINIT::APARTMENTTHREADED | co::COINIT::DISABLE_OLE1DDE);
    #[cfg(debug_assertions)]
    let (model, gate) = crate::gui_gate::model_or(ui::App::new);
    #[cfg(not(debug_assertions))]
    let model = ui::App::new();
    let shell = Shell::new(model);
    shell.events();
    #[cfg(debug_assertions)]
    if let Some(dir) = gate {
        gate::install(&shell, dir);
    }
    if let Err(e) = shell.wnd.run_main(None) {
        crate::application_failure(&format!("Win32 event loop failed: {e}"), false);
        let message = {
            let app = shell.app.borrow();
            app.runtime_issue().render(app.language)
        };
        let _ = w::HWND::NULL.MessageBox(&message, "freemkv", co::MB::ICONERROR);
        return 1;
    }
    0
}
