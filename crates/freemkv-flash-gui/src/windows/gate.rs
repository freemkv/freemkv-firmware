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
use std::time::{Duration, Instant};

use winsafe::{self as w, co, msg, prelude::*};

use super::{send_raw, Shell, TDM_CLICK_BUTTON, TD_CANCEL};
use crate::gui_gate::{self, Capture, Gate, Order, Region, SheetRun, TabRun};
use crate::ui::{Input, Task};

/// One shot: start the gate once the window is shown and painted.
const TIMER_GATE: usize = 9;
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
}

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
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
        me.send(Input::SelectTask(task));
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

    me.send(Input::SelectTask(Task::Flash));
    let first = sheet(me, dir, true, &mut g);
    let reopened = sheet(me, dir, false, &mut g);
    gui_gate::sheet_checks(&mut g, &first, &reopened);
    g.no_drive_io("end", &me.app.borrow());
    std::process::exit(g.finish(dir));
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
        })
    });
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
    if tick {
        send_raw(dialog, TDM_CLICK_VERIFICATION, 1, 0);
        pump(150);
        let acked = me.view().confirm.is_some_and(|v| v.ack_checked);
        run.ticked = Some((acked, confirm.as_ref().map(|b| b.IsWindowEnabled())));
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
        })
    });
    send_raw(dialog, TDM_CLICK_BUTTON, TD_CANCEL.into(), 0);
    true
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
