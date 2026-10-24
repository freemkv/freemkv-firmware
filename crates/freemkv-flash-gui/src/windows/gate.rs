//! qa's GUI gate on the Win32 shell (`crate::gui_gate`), run by a debug build with
//! `FREEMKV_FLASH_GATE=<dir>` once the window is shown: every tab through `send`, checked in
//! the tab control and in a `PrintWindow` capture of the real window, then the flash
//! confirmation's task dialog driven from its own callback (`probe`): its verification box
//! ticked with `TDM_CLICK_VERIFICATION`, its Confirm button read from the button window, and
//! Cancel clicked. Writes `<dir>/gate.txt` and a PNG per tab and dialog, and exits with the
//! verdict.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant};

use winsafe::{self as w, co, gui, msg, prelude::*};

use super::{send_raw, Shell, TDM_CLICK_BUTTON, TD_CANCEL};
use crate::gui_gate::{self, Capture, Gate, Order, Region, SheetRun, TabRun};
use crate::ui::{Effect, Input, Msg, ProfileState, Task};

/// One shot: start the gate once the window is shown and painted.
const TIMER_GATE: usize = 9;
/// Probe the blocked-close warning from its nested native message loop.
const TIMER_CLOSE_PROBE: usize = 10;
const CLOSE_MARKER: &str = "GUI gate: worker polled while the close warning was visible";
const TDM_CLICK_VERIFICATION: u32 = 0x0400 + 113;
/// `PrintWindow`: draw the full content, DirectComposition included.
const PW_RENDERFULLCONTENT: u32 = 2;
/// How long a step lets the window lay out and paint before it looks.
const SETTLE_MS: u64 = 400;

#[link(name = "user32")]
unsafe extern "system" {
    fn PrintWindow(hwnd: *mut c_void, hdc_blt: *mut c_void, flags: u32) -> i32;
}

/// What the dialog's callback is asked to do, and what it saw.
struct Probe {
    tick: bool,
    dialog: Option<w::HWND>,
    run: SheetRun,
    shot: Option<Capture>,
    done: bool,
    disclosure: Vec<(&'static str, bool)>,
}

struct CloseProbe {
    sender: Sender<Msg>,
    expected: String,
    started: Instant,
    done: bool,
    opened: bool,
    polled: bool,
    visible_after_poll: bool,
    dismissal_posted: bool,
    timed_out: bool,
}

thread_local! {
    static EXPANSIONS: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
    static CLOSE_PROBE: RefCell<Option<CloseProbe>> = const { RefCell::new(None) };
}

/// Run the gate from a timer once the window is shown.
pub(super) fn install(shell: &Shell, dir: PathBuf) {
    let armed = Rc::new(Cell::new(false));
    let me = shell.clone();
    shell.wnd.on().wm_show_window(move |_| {
        if !armed.replace(true) {
            me.wnd.hwnd().SetTimer(TIMER_GATE, 500, None)?;
        }
        Ok(())
    });
    let me = shell.clone();
    shell.wnd.on().wm_timer(TIMER_GATE, move || {
        let _ = me.wnd.hwnd().KillTimer(TIMER_GATE);
        run(&me, &dir);
        Ok(())
    });
    let me = shell.clone();
    shell.wnd.on().wm_timer(TIMER_CLOSE_PROBE, move || {
        probe_close_warning(&me);
        Ok(())
    });
}

fn run(me: &Shell, dir: &Path) {
    let mut g = Gate::default();
    g.no_drive_io("start", &me.app.borrow());
    pump(SETTLE_MS);
    let hwnd = me.wnd.hwnd();
    let shot = capture(hwnd);
    g.check(
        "window-not-blank",
        shot.as_ref()
            .zip(client(hwnd))
            .is_some_and(|(s, r)| s.has_ink(r)),
        shot.as_ref().map_or("no capture".into(), |s| {
            format!("{}x{} px", s.width, s.height)
        }),
    );

    for task in gui_gate::TABS {
        // Exercise the native hit-test and TCN_SELCHANGE handler, not a direct
        // model dispatch that would pass even with broken tab event wiring.
        let index = Task::ALL.iter().position(|t| *t == task).unwrap();
        let mut rect = w::RECT::default();
        let hit = unsafe {
            me.tabs.hwnd().SendMessage(msg::TcmGetItemRect {
                index: index as u32,
                rect: &mut rect,
            })
        };
        g.check("tab-hit-rectangle", hit.is_ok(), format!("{task:?}"));
        if hit.is_ok() {
            let x = (rect.left + rect.right) / 2;
            let y = (rect.top + rect.bottom) / 2;
            let point = ((y as u32 & 0xffff) << 16 | (x as u32 & 0xffff)) as isize;
            send_raw(me.tabs.hwnd(), 0x0201, 1, point); // WM_LBUTTONDOWN, MK_LBUTTON
            send_raw(me.tabs.hwnd(), 0x0202, 0, point); // WM_LBUTTONUP
        }
        pump(SETTLE_MS);
        let v = me.view();
        let index = Task::ALL.iter().position(|t| *t == task);
        let selected = unsafe { me.tabs.hwnd().SendMessage(msg::TcmGetCurSel {}) };
        let shot = capture(hwnd);
        let ink = shot.as_ref().zip(panel(me)).map(|(s, r)| s.has_ink(r));
        gui_gate::tab_checks(
            &mut g,
            &TabRun {
                task,
                model: v.task == task && v.tabs.iter().any(|t| t.task == task && t.enabled),
                widget: Some(selected.map(|i| i as usize) == index),
                ink,
            },
        );
        g.save(
            dir,
            &format!("tab-{}", gui_gate::tab_name(task)),
            shot.as_ref(),
        );
    }

    origin_error_results(me, dir, &mut g);
    report_prompts(me, &mut g);
    firmware_pickers(me, &mut g);
    me.send(Input::SelectTask(Task::Flash));
    let first = sheet(me, dir, true, &mut g);
    let reopened = sheet(me, dir, false, &mut g);
    gui_gate::sheet_checks(&mut g, &first, &reopened);
    close_warning(me, &mut g);
    g.no_drive_io("end", &me.app.borrow());
    std::process::exit(g.finish(dir));
}

/// An origin-only error has diagnostic actions even before any task has a status.
fn origin_error_results(me: &Shell, dir: &Path, g: &mut Gate) {
    me.send(Input::SelectTask(Task::Flash));
    let missing = std::env::temp_dir()
        .join(format!("freemkv-gate-missing-{}", std::process::id()))
        .join("missing-firmware.bin");
    me.send(Input::Chosen(crate::ui::Pick::FlashFirmware, missing));
    let deadline = Instant::now() + Duration::from_secs(5);
    while me.view().results.is_none() && Instant::now() < deadline {
        pump(50);
    }
    let view = me.view();
    g.check(
        "origin-error-without-status",
        view.status.is_none() && view.results.is_some(),
        "file-origin failure independently supplies diagnostic actions",
    );
    g.check(
        "origin-error-actions-visible",
        me.view_log.btn.hwnd().IsWindowVisible() && me.submit_report.btn.hwnd().IsWindowVisible(),
        "View log and Submit report remain visible without an operation status",
    );
    g.check(
        "origin-error-actions-bound",
        me.view_log.input.borrow().as_ref() == Some(&Input::ViewLog)
            && me.submit_report.input.borrow().as_ref() == Some(&Input::SubmitReport),
        "visible actions retain their actual model inputs",
    );
    g.save(dir, "origin-error", capture(me.wnd.hwnd()).as_ref());
    g.no_drive_io("origin-error", &me.app.borrow());
}

#[derive(Clone, Copy, Debug)]
enum ReportAnswer {
    Send,
    Cancel,
    Escape,
    Close,
}

struct ReportProbe {
    answer: ReportAnswer,
    initial: String,
    text: String,
    summary: String,
    newline: bool,
}

thread_local! {
    static REPORT_PROBE: RefCell<Option<ReportProbe>> = const { RefCell::new(None) };
}

/// Exercise the actual editor and production button handlers with a pending report.
/// The inert model consumes Send without starting any network worker.
fn report_prompts(me: &Shell, g: &mut Gate) {
    const DRAFT: &str = "  描述 🦀\nsecond line  ";
    for answer in [
        ReportAnswer::Cancel,
        ReportAnswer::Send,
        ReportAnswer::Escape,
        ReportAnswer::Close,
    ] {
        REPORT_PROBE.with(|p| {
            *p.borrow_mut() = Some(ReportProbe {
                answer,
                initial: String::new(),
                text: String::new(),
                summary: String::new(),
                newline: false,
            })
        });
        let effects = me.app.borrow_mut().dispatch(Input::SubmitReport);
        let summary = effects.into_iter().find_map(|effect| match effect {
            crate::ui::Effect::ReportPrompt { summary, .. } => Some(summary),
            _ => None,
        });
        let Some(summary) = summary else {
            g.check(
                "report-prompt-opens",
                false,
                "SubmitReport produced no prompt",
            );
            continue;
        };
        let rendered_summary = crate::localization::render(me.app.borrow().language, &summary);
        let response = me.report_prompt(&summary, DRAFT);
        let observed = REPORT_PROBE.with(|p| p.borrow_mut().take()).unwrap();
        let expected = format!("{DRAFT}\r\n");
        let correct = match &response {
            Input::SendReport(text) => matches!(answer, ReportAnswer::Send) && text == &expected,
            Input::DismissReport(text) => {
                !matches!(answer, ReportAnswer::Send) && text == &expected
            }
            _ => false,
        };
        g.check(
            "report-native-unicode-newline-answer",
            correct
                && observed.newline
                && observed.initial == DRAFT
                && observed.text == expected
                && observed.summary == rendered_summary,
            format!("{answer:?}: editor and callback preserve Unicode, whitespace and newline"),
        );
        me.send(response);
        let app = me.app.borrow();
        let (draft, open) = app.report_prompt_state();
        g.check(
            "report-prompt-model-draft",
            draft == expected && !open,
            format!("{answer:?}: model retained the exact draft and consumed the prompt"),
        );
        g.no_drive_io("report prompt inert callback", &app);
    }
}

pub(super) fn arm_report_probe(hwnd: &w::HWND) -> w::SysResult<()> {
    if REPORT_PROBE.with(|p| p.borrow().is_some()) {
        hwnd.SetTimer(10, 100, None)?;
        hwnd.SetTimer(11, 5000, None)?;
    }
    Ok(())
}

pub(super) fn install_report_probe(
    dialog: &gui::WindowModal,
    entry: &gui::Edit,
    summary: &gui::Label,
    proceed: &gui::Button,
    cancel: &gui::Button,
) {
    if !REPORT_PROBE.with(|p| p.borrow().is_some()) {
        return;
    }
    let popup = dialog.clone();
    dialog.on().wm_timer(11, move || {
        popup.hwnd().KillTimer(11)?;
        REPORT_PROBE.with(|p| {
            if let Some(probe) = p.borrow_mut().as_mut() {
                probe.newline = false;
            }
        });
        popup.close();
        Ok(())
    });
    let popup = dialog.clone();
    let field = entry.clone();
    let summary = summary.clone();
    let proceed = proceed.clone();
    let cancel = cancel.clone();
    dialog.on().wm_timer(10, move || {
        popup.hwnd().KillTimer(10)?;
        let initial = field.text()?;
        // Append a real WM_CHAR carriage return, as the keyboard does. WANTRETURN
        // must insert a newline rather than activate Send or close the window.
        let end = field.hwnd().GetWindowTextLength()? as usize;
        send_raw(field.hwnd(), super::EM_SETSEL, end, end as isize);
        send_raw(field.hwnd(), 0x0102, 13, 0); // WM_CHAR, Return
        let text = field.text()?;
        let summary = summary.hwnd().GetWindowText()?;
        let answer = REPORT_PROBE.with(|p| {
            let mut state = p.borrow_mut();
            let probe = state.as_mut().unwrap();
            probe.initial = initial;
            probe.text = text;
            probe.summary = summary;
            probe.newline = popup.hwnd().IsWindowVisible();
            probe.answer
        });
        match answer {
            ReportAnswer::Send => {
                send_raw(proceed.hwnd(), 0x00f5, 0, 0);
            } // BM_CLICK
            ReportAnswer::Cancel => {
                send_raw(cancel.hwnd(), 0x00f5, 0, 0);
            }
            ReportAnswer::Escape => {
                let mut key = w::MSG {
                    hwnd: unsafe { w::HWND::from_ptr(field.hwnd().ptr()) },
                    message: co::WM::KEYDOWN,
                    wParam: 27,
                    ..Default::default()
                };
                let _ = popup.hwnd().IsDialogMessage(&mut key);
            }
            ReportAnswer::Close => popup.close(),
        }
        Ok(())
    });
}

/// Exercise the production WM_CLOSE and WM_TIMER handlers with a synthetic active job.
/// Keep the sender alive until the receiver is removed, so no disconnect changes the job.
fn close_warning(me: &Shell, g: &mut Gate) {
    let ready = gui_gate::inert(&me.app.borrow());
    g.check("close-warning-inert-before-job", ready, "synthetic fixture");
    if !ready {
        return;
    }
    let expected = crate::localization::render(me.app.borrow().language, crate::ui::CLOSE_BLOCKED);
    let (sender, receiver) = mpsc::channel();
    me.app.borrow_mut().rx = Some(receiver);
    CLOSE_PROBE.with(|p| {
        *p.borrow_mut() = Some(CloseProbe {
            sender: sender.clone(),
            expected,
            started: Instant::now(),
            done: false,
            opened: false,
            polled: false,
            visible_after_poll: false,
            dismissal_posted: false,
            timed_out: false,
        });
    });
    // Install through the shell's normal effect and keep its real polling timer active.
    // The probe runs first, making the marker check deterministic even on a slow runner.
    let armed = me.wnd.hwnd().SetTimer(TIMER_CLOSE_PROBE, 50, None).is_ok();
    g.check("close-warning-probe-timer", armed, "native timer installed");
    if armed {
        me.perform(vec![Effect::StartTicking]);
        // No App or probe borrow may span this call: WM_CLOSE opens a modal message loop.
        eprintln!("GATE TRACE close-warning: entering production WM_CLOSE");
        send_raw(me.wnd.hwnd(), co::WM::CLOSE.raw(), 0, 0);
        eprintln!("GATE TRACE close-warning: production WM_CLOSE returned");
    }
    let probe = CLOSE_PROBE.with(|p| p.borrow_mut().take());
    let app = me.app.borrow();
    g.check(
        "close-warning-opened",
        probe.as_ref().is_some_and(|p| p.opened),
        "visible owned #32770 dialog with the localized warning text",
    );
    g.check(
        "close-warning-polls-worker",
        probe
            .as_ref()
            .is_some_and(|p| p.polled && p.visible_after_poll),
        "unique marker consumed by production WM_TIMER while warning remained visible",
    );
    g.check(
        "close-warning-dismissed",
        probe.as_ref().is_some_and(|p| {
            p.dismissal_posted && !p.timed_out && close_dialog(me, Some(&p.expected)).is_none()
        }),
        "native close posted and warning gone before WM_CLOSE returned without timeout",
    );
    g.check(
        "close-warning-keeps-job-and-window",
        me.wnd.hwnd().IsWindow() && app.rx.is_some() && app.inert && !app.view().can_close,
        "WM_CLOSE returned with the synthetic job still active",
    );
    drop(app);
    me.app.borrow_mut().rx = None;
    let _ = me.wnd.hwnd().KillTimer(super::TIMER_TICK);
    let _ = me.wnd.hwnd().KillTimer(TIMER_CLOSE_PROBE);
    drop(sender);
}

/// Find only a message box owned by the main window, optionally checking its text.
fn close_dialog(me: &Shell, expected: Option<&str>) -> Option<w::HWND> {
    let (thread_id, _) = me.wnd.hwnd().GetWindowThreadProcessId();
    let mut found = None;
    let _ = w::EnumThreadWindows(thread_id, |hwnd| {
        if !hwnd.IsWindowVisible()
            || hwnd.GetClassName().ok().as_deref() != Some("#32770")
            || !hwnd
                .GetWindow(co::GW::OWNER)
                .is_ok_and(|owner| owner == *me.wnd.hwnd())
        {
            return true;
        }
        let mut matches = expected.is_none();
        hwnd.EnumChildWindows(|child| {
            matches |= child.GetWindowText().ok().as_deref() == expected;
            !matches
        });
        if matches {
            found = Some(hwnd);
            return false;
        }
        true
    });
    found
}

/// Runs inside MessageBox's native loop. Never retain a test borrow across SendMessage.
fn probe_close_warning(me: &Shell) {
    let pending = CLOSE_PROBE.with(|p| {
        p.borrow().as_ref().map(|p| {
            (
                p.expected.clone(),
                p.started.elapsed() >= Duration::from_secs(10),
                p.sender.clone(),
                p.done,
            )
        })
    });
    let Some((expected, timed_out, sender, done)) = pending else {
        return;
    };
    if timed_out {
        let _ = me.wnd.hwnd().KillTimer(TIMER_CLOSE_PROBE);
        CLOSE_PROBE.with(|p| {
            if let Some(p) = p.borrow_mut().as_mut() {
                p.timed_out = true;
            }
        });
        eprintln!("GATE TRACE close-warning: 10 s deadline; posting fallback WM_CLOSE");
        if let Some(dialog) = close_dialog(me, None) {
            unsafe {
                let posted = dialog.PostMessage(msg::WmClose {});
                eprintln!("GATE TRACE close-warning: fallback post {posted:?}");
            }
        }
        return;
    }
    if done {
        return;
    }
    let dialog = close_dialog(me, Some(&expected));
    let Some(dialog) = dialog else { return };
    eprintln!("GATE TRACE close-warning: owned warning found");
    CLOSE_PROBE.with(|p| {
        if let Some(p) = p.borrow_mut().as_mut() {
            p.done = true;
            p.opened = true;
        }
    });
    let sent = sender.send(gui_gate::worker_message(CLOSE_MARKER));
    // This is the shell's actual registered polling callback, reached with MessageBox
    // still on the stack. Unfixed code panics here on the App's retained Ref borrow.
    eprintln!("GATE TRACE close-warning: entering production WM_TIMER");
    send_raw(me.wnd.hwnd(), co::WM::TIMER.raw(), super::TIMER_TICK, 0);
    let polled = sent.is_ok() && me.app.borrow().log.iter().any(|s| s == CLOSE_MARKER);
    eprintln!("GATE TRACE close-warning: production WM_TIMER returned; marker {polled}");
    // Dismiss through the warning's native close action. Do not assume the OS uses an
    // IDOK child control: the hosted Windows warning does not expose that control ID.
    // Posting lets MessageBox process the close after this nested timer returns.
    let posted = unsafe { dialog.PostMessage(msg::WmClose {}) };
    eprintln!("GATE TRACE close-warning: native warning close queued {posted:?}");
    CLOSE_PROBE.with(|p| {
        if let Some(p) = p.borrow_mut().as_mut() {
            p.polled = polled;
            p.visible_after_poll = dialog.IsWindowVisible();
            p.dismissal_posted = posted.is_ok();
        }
    });
    // gui_gate::arm's process watchdog also bounds a modal loop that stops servicing timers.
}

fn close_next_picker(thread_id: u32) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(10);
        let mut opened = false;
        while Instant::now() < until && !opened {
            let _ = w::EnumThreadWindows(thread_id, |hwnd| {
                if hwnd.GetClassName().ok().as_deref() == Some("#32770") && hwnd.IsWindowVisible() {
                    opened = true;
                    unsafe {
                        let _ = hwnd.PostMessage(msg::WmClose {});
                    }
                }
                true
            });
            if !opened {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        opened
    })
}

/// Open the actual common dialog for each filter shape and cancel it on its UI thread.
fn firmware_pickers(me: &Shell, g: &mut Gate) {
    let original = me.app.borrow().profile.clone();
    let (thread_id, _) = me.wnd.hwnd().GetWindowThreadProcessId();
    for (name, extensions) in gui_gate::PICKER_PROFILES {
        if let ProfileState::Ready(profile) = &mut me.app.borrow_mut().profile {
            profile.firmware_picker = crate::ui::FirmwarePickerFormats::prefer(extensions.to_vec());
        }
        for pick in gui_gate::FIRMWARE_PICKS {
            let closer = close_next_picker(thread_id);
            me.send(Input::Choose(pick));
            let opened = closer.join().unwrap_or(false);
            let app = me.app.borrow();
            g.check(
                "firmware-picker-opens-and-cancels",
                opened && app.failure.is_none(),
                format!("{name} {pick:?}"),
            );
            g.check(
                "firmware-picker-keeps-main-window",
                me.wnd.hwnd().IsWindowVisible(),
                format!("{name} {pick:?}"),
            );
            g.no_drive_io(&format!("picker {name} {pick:?}"), &app);
        }
    }
    // Bypass the model policy to exercise the native boundary independently.
    for filter in [
        crate::ui::FileFilter {
            name: "Firmware",
            extensions: vec![],
        },
        crate::ui::FileFilter {
            name: "",
            extensions: vec!["bin"],
        },
        crate::ui::FileFilter {
            name: "Firmware\0",
            extensions: vec!["bin"],
        },
        crate::ui::FileFilter {
            name: "Firmware",
            extensions: vec!["", "bin;*", "\0"],
        },
    ] {
        let description = format!("{filter:?}");
        let closer = close_next_picker(thread_id);
        let result = me.open_dialog(Some(filter));
        let opened = closer.join().unwrap_or(false);
        g.check(
            "invalid-filter-opens-unfiltered-and-cancels",
            opened && matches!(result, Ok(None)),
            description,
        );
        g.no_drive_io("invalid filter boundary", &me.app.borrow());
    }
    me.app.borrow_mut().profile = original;
}

/// Ask the confirmation over the synthetic plan and let the shell open its dialog as it
/// always does; `probe` reads and answers it from the dialog's own callback.
fn sheet(me: &Shell, dir: &Path, tick: bool, g: &mut Gate) -> SheetRun {
    PROBE.with(|p| {
        *p.borrow_mut() = Some(Probe {
            tick,
            dialog: None,
            run: SheetRun::default(),
            shot: None,
            done: false,
            disclosure: Vec::new(),
        })
    });
    EXPANSIONS.with(|events| events.borrow_mut().clear());
    gui_gate::open_flash_sheet(&mut me.app.borrow_mut());
    me.render();
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until && !(probed() && me.view().confirm.is_none()) {
        pump(100);
    }
    let probe = PROBE.with(|p| p.borrow_mut().take());
    let Some(mut probe) = probe else {
        return SheetRun::default();
    };
    for (name, passed) in &probe.disclosure {
        g.check(
            name,
            *passed,
            "native disclosure leaves acknowledgement and authorization unchanged",
        );
    }
    let name = if tick { "sheet" } else { "sheet-reopened" };
    g.save(dir, name, probe.shot.as_ref());
    let gone = probe.dialog.as_ref().is_none_or(|d| !d.IsWindow());
    probe.run.closed = probe.done && gone && me.view().confirm.is_none();
    probe.run
}

fn probed() -> bool {
    PROBE.with(|p| p.borrow().as_ref().is_some_and(|p| p.done))
}

/// Called on the confirmation dialog's timer: read the dialog's controls, tick its box when
/// asked, capture it and click Cancel. True when the gate handled the notification.
pub(super) fn probe(me: &Shell, dialog: &w::HWND) -> bool {
    // Claimed before anything pumps: the dialog's next timer must not probe it again.
    let pending = PROBE.with(|p| {
        p.borrow_mut().as_mut().filter(|p| !p.done).map(|p| {
            p.done = true;
            p.tick
        })
    });
    let Some(tick) = pending else {
        return false;
    };
    let Some(c) = me.view().confirm else {
        return false;
    };
    let confirm = button(dialog, &c.confirm.text);
    let mut run = SheetRun {
        opened: dialog.IsWindowVisible(),
        // A task dialog draws its verification box itself (no Button window to read), so
        // "unticked" is its creation flags, the state it last reported and the model.
        unticked: Some(gui_gate::task_dialog_unticked(
            super::confirm_flags().has(co::TDF::VERIFICATION_FLAG_CHECKED),
            me.risk_box.get(),
            c.ack_checked,
        )),
        confirm_before: confirm.as_ref().map(|b| b.IsWindowEnabled()),
        ..Default::default()
    };
    let mut disclosure = Vec::new();
    disclosure.push((
        "confirmation-details-present",
        !c.technical_details.is_empty(),
    ));
    let details_control = button(dialog, &c.details_label);
    let initial_expansions = EXPANSIONS.with(|events| events.borrow().clone());
    eprintln!(
        "GATE TRACE details start: expanded_by_default={} control_visible={} class={:?} text={:?} events={initial_expansions:?} controls={:?}",
        super::confirm_flags().has(co::TDF::EXPANDED_BY_DEFAULT),
        details_control.as_ref().is_some_and(|b| b.IsWindowVisible()),
        details_control.as_ref().and_then(|b| b.GetClassName().ok()),
        details_control.as_ref().and_then(|b| b.GetWindowText().ok()),
        dialog_controls(dialog),
    );
    disclosure.push((
        "confirmation-details-start-collapsed",
        !super::confirm_flags().has(co::TDF::EXPANDED_BY_DEFAULT)
            && details_control.is_some_and(|b| b.IsWindowVisible())
            && EXPANSIONS.with(|events| events.borrow().is_empty()),
    ));
    disclosure.push((
        "confirmation-details-without-ack",
        toggle_details(me, dialog, &c),
    ));
    if tick {
        send_raw(dialog, TDM_CLICK_VERIFICATION, 1, 0);
        pump(150);
        let acked = me.view().confirm.is_some_and(|v| v.ack_checked);
        run.ticked = Some((acked, confirm.as_ref().map(|b| b.IsWindowEnabled())));
        run.box_reads_ticked = Some(me.risk_box.get());
        disclosure.push((
            "confirmation-details-preserve-ack",
            toggle_details(me, dialog, &c),
        ));
    }
    let shot = capture(dialog);
    let raw = unsafe { w::HWND::from_ptr(dialog.ptr()) };
    PROBE.with(|p| {
        *p.borrow_mut() = Some(Probe {
            tick,
            dialog: Some(raw),
            run,
            shot,
            done: true,
            disclosure,
        })
    });
    send_raw(dialog, TDM_CLICK_BUTTON, TD_CANCEL.into(), 0);
    true
}

/// Record the actual common-control notification; clicking Details cannot dispatch
/// a model input or change the risk checkbox.
pub(super) fn disclosure_changed(expanded: bool) {
    EXPANSIONS.with(|events| events.borrow_mut().push(expanded));
}

fn toggle_details(me: &Shell, dialog: &w::HWND, c: &crate::ui::Confirm) -> bool {
    let state = || {
        let confirm = me.view().confirm?;
        Some((
            confirm.ack_checked,
            me.risk_box.get(),
            button(dialog, &c.confirm.text)?.IsWindowEnabled(),
        ))
    };
    let before = state();
    let height = || dialog.GetWindowRect().ok().map(|r| r.bottom - r.top);
    let collapsed_height = height();
    let Some(expand) = button(dialog, &c.details_label) else {
        eprintln!("GATE TRACE details toggle: collapsed control not found");
        return false;
    };
    eprintln!(
        "GATE TRACE details toggle before: class={:?} text={:?} visible={} bounds={:?} height={collapsed_height:?} state={before:?} controls={:?}",
        expand.GetClassName().ok(),
        expand.GetWindowText().ok(),
        expand.IsWindowVisible(),
        expand.GetWindowRect().ok().map(|r| (r.left, r.top, r.right, r.bottom)),
        dialog_controls(dialog),
    );
    EXPANSIONS.with(|events| events.borrow_mut().clear());
    send_raw(&expand, 0x00f5, 0, 0); // BM_CLICK on the real expando control
    pump(200);
    let expanded_height = height();
    let expanded = EXPANSIONS.with(|events| events.borrow().as_slice() == [true]);
    let unchanged_expanded = before.is_some() && state() == before;
    let Some(collapse) = button(dialog, &c.hide_details_label) else {
        let events = EXPANSIONS.with(|events| events.borrow().clone());
        eprintln!(
            "GATE TRACE details toggle expanded: notification={expanded} events={events:?} height={expanded_height:?} state={:?}; expanded control not found",
            state(),
        );
        return false;
    };
    let expanded_events = EXPANSIONS.with(|events| events.borrow().clone());
    eprintln!(
        "GATE TRACE details toggle expanded: notification={expanded} events={expanded_events:?} height={expanded_height:?} state={:?} collapse_visible={} controls={:?}",
        state(),
        collapse.IsWindowVisible(),
        dialog_controls(dialog),
    );
    send_raw(&collapse, 0x00f5, 0, 0);
    pump(200);
    let collapsed = EXPANSIONS.with(|events| events.borrow().as_slice() == [true, false]);
    expanded
        && collapsed
        && unchanged_expanded
        && state() == before
        && expanded_height
            .zip(collapsed_height)
            .is_some_and(|(expanded, collapsed)| expanded > collapsed)
        && height() == collapsed_height
        && button(dialog, &c.details_label).is_some_and(|b| b.IsWindowVisible())
}

fn dialog_controls(dialog: &w::HWND) -> Vec<String> {
    let mut controls = Vec::new();
    dialog.EnumChildWindows(|h: w::HWND| {
        controls.push(format!(
            "id={:?} class={:?} text={:?} visible={} enabled={}",
            h.GetDlgCtrlID().ok(),
            h.GetClassName().ok(),
            h.GetWindowText().ok(),
            h.IsWindowVisible(),
            h.IsWindowEnabled(),
        ));
        true
    });
    controls
}

/// The dialog's button (or checkbox) window whose caption is `text`.
fn button(dialog: &w::HWND, text: &str) -> Option<w::HWND> {
    let mut found = None;
    dialog.EnumChildWindows(|h: w::HWND| {
        let is_button = h
            .GetClassName()
            .is_ok_and(|c| c.eq_ignore_ascii_case("Button"));
        if is_button && h.GetWindowText().is_ok_and(|t| t.replace('&', "") == text) {
            found = Some(h);
            return false;
        }
        true
    });
    found
}

/// The client area, in the window capture's pixels.
fn client(hwnd: &w::HWND) -> Option<Region> {
    let win = hwnd.GetWindowRect().ok()?;
    let rc = hwnd.GetClientRect().ok()?;
    let at = hwnd.ClientToScreen(w::POINT::new()).ok()?;
    Some(Region {
        x: at.x - win.left,
        y: at.y - win.top,
        w: rc.right,
        h: rc.bottom,
    })
}

/// The task form: the visible pooled controls' bounds, in the window capture's pixels.
fn panel(me: &Shell) -> Option<Region> {
    let win = me.wnd.hwnd().GetWindowRect().ok()?;
    let hwnds = me
        .texts
        .iter()
        .chain(me.lines.iter())
        .map(|l| l.hwnd())
        .chain(me.buttons.iter().map(|b| b.btn.hwnd()))
        .chain(me.checks.iter().map(|(c, _)| c.hwnd()));
    let mut bounds: Option<w::RECT> = None;
    for h in hwnds.filter(|h| h.IsWindowVisible()) {
        let Ok(r) = h.GetWindowRect() else { continue };
        bounds = Some(match bounds {
            None => r,
            Some(b) => w::RECT {
                left: b.left.min(r.left),
                top: b.top.min(r.top),
                right: b.right.max(r.right),
                bottom: b.bottom.max(r.bottom),
            },
        });
    }
    let b = bounds?;
    Some(Region {
        x: b.left - win.left,
        y: b.top - win.top,
        w: b.right - b.left,
        h: b.bottom - b.top,
    })
}

/// Let Windows lay out and paint: controls draw lazily from the message loop.
fn pump(ms: u64) {
    let until = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < until {
        let mut m = w::MSG::default();
        while w::PeekMessage(&mut m, None, 0, 0, co::PM::REMOVE) {
            w::TranslateMessage(&m);
            unsafe {
                w::DispatchMessage(&m);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A window as it draws itself (`PrintWindow`, as macOS's `cacheDisplayInRect:`), 32-bit
/// BGRA rows bottom-up. Each way of drawing is tried until one is not a blank plate: full
/// content needs DWM composition, which a CI session may lack; a screen copy is last.
fn capture(hwnd: &w::HWND) -> Option<Capture> {
    let rc = hwnd.GetWindowRect().ok()?;
    let (cx, cy) = ((rc.right - rc.left).max(1), (rc.bottom - rc.top).max(1));
    let screen = w::HWND::DESKTOP.GetDC().ok()?;
    let bmp = screen.CreateCompatibleBitmap(cx, cy).ok()?;
    let mem = screen.CreateCompatibleDC().ok()?;
    let mut px = vec![0u8; cx as usize * cy as usize * 4];
    for way in 0..3u8 {
        {
            let _sel = mem.SelectObject(&*bmp).ok()?;
            match way {
                0 => unsafe {
                    PrintWindow(hwnd.ptr(), mem.ptr(), PW_RENDERFULLCONTENT);
                },
                1 => unsafe {
                    PrintWindow(hwnd.ptr(), mem.ptr(), 0);
                },
                _ => {
                    let _ = mem.BitBlt(
                        w::POINT::new(),
                        w::SIZE::with(cx, cy),
                        &screen,
                        w::POINT::with(rc.left, rc.top),
                        co::ROP::SRCCOPY,
                    );
                }
            }
        }
        // A fresh header each time: GetDIBits writes back into the one it is given.
        let mut bi = w::BITMAPINFO::default();
        bi.bmiHeader.biWidth = cx;
        bi.bmiHeader.biHeight = cy;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = co::BI::RGB;
        let read = unsafe {
            screen.GetDIBits(
                &bmp,
                0,
                cy as u32,
                Some(&mut px),
                &mut bi,
                co::DIB::RGB_COLORS,
            )
        };
        let shot = Capture {
            width: cx,
            height: cy,
            px: px.clone(),
            order: Order::Bgra,
            bottom_up: true,
        };
        if read.is_ok() && shot.has_ink(shot.full()) {
            return Some(shot);
        }
    }
    None
}
