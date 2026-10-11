//! qa's GUI gate on the AppKit shell (`crate::gui_gate`), run by a debug build with
//! `FREEMKV_FLASH_GATE=<dir>` once the window is up: every tab through `send`, checked in
//! the segmented control and in a capture (`cacheDisplayInRect:`) of the real window, then
//! a file picker dismissed with Escape (the main window must survive it), then
//! the flash confirmation sheet driven through its own checkbox and Cancel button. Writes
//! `<dir>/gate.txt` and a PNG per tab and sheet, and exits with the verdict.

use std::path::Path;
use std::time::{Duration, Instant};

use objc2::{DefinedClass, MainThreadOnly};
use objc2_app_kit::{NSApplication, NSBitmapFormat, NSEventMask, NSView, NSWindow};
use objc2_foundation::{NSDate, NSDefaultRunLoopMode};

use super::Controller;
use crate::gui_gate::{self, Capture, Gate, Order, Region, SheetRun, TabRun};
use crate::ui::{Input, Pick, Task};

/// How long a step lets AppKit lay out, draw and animate before it looks.
const SETTLE: Duration = Duration::from_millis(400);

pub(super) fn run(c: &Controller, dir: &Path) {
    let mut g = Gate::default();
    c.with_app(|a| g.no_drive_io("start", a));
    let window = c.ivars().window.borrow().clone();
    let Some(content) = window.as_ref().and_then(|w| w.contentView()) else {
        g.check("window", false, "no main window");
        std::process::exit(g.finish(dir));
    };
    settle(c, SETTLE);
    let shot = capture(&content);
    g.check(
        "window-not-blank",
        shot.as_ref().is_some_and(|s| s.has_ink(s.full())),
        shot.as_ref().map_or("no capture".into(), |s| {
            format!("{}x{} px", s.width, s.height)
        }),
    );

    for task in gui_gate::TABS {
        c.send(Input::SelectTask(task));
        settle(c, SETTLE);
        let v = c.view();
        let index = Task::ALL.iter().position(|t| *t == task);
        let widget = c
            .ivars()
            .tabs
            .borrow()
            .as_ref()
            .map(|tabs| usize::try_from(tabs.selectedSegment()).ok() == index);
        let shot = capture(&content);
        let ink = shot.as_ref().and_then(|s| {
            let panel = c.ivars().panel.borrow().clone()?;
            Some(s.has_ink(region(&panel, &content, s)))
        });
        gui_gate::tab_checks(
            &mut g,
            &TabRun {
                task,
                model: v.task == task && v.tabs.iter().any(|t| t.task == task && t.enabled),
                widget,
                ink,
            },
        );
        g.save(
            dir,
            &format!("tab-{}", gui_gate::tab_name(task)),
            shot.as_ref(),
        );
    }

    c.send(Input::SelectTask(Task::Flash));
    escape_closes_only_the_picker(c, &mut g);
    let first = sheet(c, dir, true, &mut g);
    let reopened = sheet(c, dir, false, &mut g);
    gui_gate::sheet_checks(&mut g, &first, &reopened);
    c.with_app(|a| g.no_drive_io("end", a));
    std::process::exit(g.finish(dir));
}

/// Open the confirmation over the synthetic plan, read it, tick its box when `tick`, and
/// cancel it through its own button.
fn sheet(c: &Controller, dir: &Path, tick: bool, g: &mut Gate) -> SheetRun {
    let mut run = SheetRun::default();
    c.with_app(gui_gate::open_flash_sheet);
    c.render();
    settle(c, SETTLE);
    let alert = c.ivars().alert.borrow().clone();
    let main = c.ivars().window.borrow().clone();
    let (Some(alert), Some(main)) = (alert, main) else {
        return run;
    };
    let sheet_window = alert.window();
    run.opened = main
        .attachedSheet()
        .is_some_and(|s| std::ptr::eq(&*s, &*sheet_window));
    let ack = c.ivars().alert_ack.borrow().clone();
    let confirm = c.ivars().alert_confirm.borrow().clone();
    run.unticked = ack.as_ref().map(|b| b.state() == 0);
    run.confirm_before = confirm.as_ref().map(|b| b.isEnabled());
    if tick {
        if let Some(ack) = &ack {
            unsafe { ack.performClick(None) };
            settle(c, SETTLE);
            let acked = c.view().confirm.is_some_and(|v| v.ack_checked);
            run.ticked = Some((acked, confirm.as_ref().map(|b| b.isEnabled())));
            run.box_reads_ticked = Some(ack.state() == 1);
        }
    }
    let name = if tick { "sheet" } else { "sheet-reopened" };
    g.save(
        dir,
        name,
        sheet_window
            .contentView()
            .and_then(|v| capture(&v))
            .as_ref(),
    );

    let cancel_text = c.view().confirm.map(|v| v.cancel.text).unwrap_or_default();
    let cancel = alert
        .buttons()
        .iter()
        .find(|b| b.title().to_string() == cancel_text);
    if let Some(b) = cancel {
        unsafe { b.performClick(None) };
    }
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && !closed(c, &main) {
        settle(c, Duration::from_millis(100));
    }
    run.closed = closed(c, &main);
    run
}

/// Open the flash file picker and press Escape in it: the picker must close and the main
/// window must stay up (Escape once closed the window and quit the app).
fn escape_closes_only_the_picker(c: &Controller, g: &mut Gate) {
    let Some(main) = c.ivars().window.borrow().clone() else {
        return;
    };
    c.send(Input::Choose(Pick::FlashFirmware));
    settle(c, SETTLE);
    let picker = main.attachedSheet();
    g.check(
        "picker-opens-as-sheet",
        picker.is_some(),
        if picker.is_some() {
            "attached"
        } else {
            "no sheet"
        },
    );
    let Some(picker) = picker else {
        return;
    };
    // The panel runs out of process, so a synthetic key event never reaches it; Escape
    // there sends the panel `cancel:`, which is sent here directly.
    unsafe {
        let _: () = objc2::msg_send![&*picker, cancel: Option::<&objc2::runtime::AnyObject>::None];
    }
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && main.attachedSheet().is_some() {
        settle(c, Duration::from_millis(100));
    }
    g.check(
        "escape-closes-picker",
        main.attachedSheet().is_none(),
        "cancel: (Escape) in the picker",
    );
    g.check(
        "main-window-survives-escape",
        main.isVisible() && c.view().confirm.is_none(),
        if main.isVisible() {
            "visible"
        } else {
            "closed"
        },
    );
}

fn closed(c: &Controller, main: &NSWindow) -> bool {
    c.view().confirm.is_none()
        && c.ivars().alert.borrow().is_none()
        && main.attachedSheet().is_none()
}

/// Run the app's event loop for `d`: events dispatched, timers and animations run.
fn settle(c: &Controller, d: Duration) {
    let app = NSApplication::sharedApplication(c.mtm());
    let until = Instant::now() + d;
    while Instant::now() < until {
        let date = NSDate::dateWithTimeIntervalSinceNow(0.02);
        let event = app.nextEventMatchingMask_untilDate_inMode_dequeue(
            NSEventMask::Any,
            Some(&date),
            unsafe { NSDefaultRunLoopMode },
            true,
        );
        if let Some(e) = event {
            app.sendEvent(&e);
        }
    }
}

/// `v` as AppKit draws it, top-down RGBA at the display's scale.
fn capture(v: &NSView) -> Option<Capture> {
    v.layoutSubtreeIfNeeded();
    let bounds = v.bounds();
    let rep = v.bitmapImageRepForCachingDisplayInRect(bounds)?;
    v.cacheDisplayInRect_toBitmapImageRep(bounds, &rep);
    let (w, h) = (rep.pixelsWide(), rep.pixelsHigh());
    let stride = usize::try_from(rep.bytesPerRow()).ok()?;
    let data = rep.bitmapData();
    if rep.bitsPerPixel() != 32 || rep.isPlanar() || w <= 0 || h <= 0 || data.is_null() {
        return None;
    }
    let row = w as usize * 4;
    if stride < row {
        return None;
    }
    // SAFETY: a meshed 32-bit rep holds `bytesPerRow` × `pixelsHigh` bytes at `bitmapData`.
    let bytes = unsafe { std::slice::from_raw_parts(data, stride * h as usize) };
    let mut px: Vec<u8> = bytes
        .chunks_exact(stride)
        .flat_map(|r| &r[..row])
        .copied()
        .collect();
    if rep.bitmapFormat().contains(NSBitmapFormat::AlphaFirst) {
        for p in px.as_chunks_mut::<4>().0 {
            p.rotate_left(1);
        }
    }
    let mut shot = Capture {
        width: w as i32,
        height: h as i32,
        px,
        order: Order::Rgba,
        bottom_up: false,
    };
    // Transparent pixels would read as black and hide light-mode text; grey suits both modes.
    let premultiplied = !rep
        .bitmapFormat()
        .contains(NSBitmapFormat::AlphaNonpremultiplied);
    shot.flatten([128, 128, 128], premultiplied);
    Some(shot)
}

/// Where `part` sits in a capture of `root`.
fn region(part: &NSView, root: &NSView, shot: &Capture) -> Region {
    let r = part.convertRect_toView(part.bounds(), Some(root));
    let b = root.bounds();
    let scale = f64::from(shot.width) / b.size.width.max(1.0);
    let y = if root.isFlipped() {
        b.size.height - r.origin.y - r.size.height
    } else {
        r.origin.y
    };
    Region::from_bottom_left(
        r.origin.x,
        y,
        r.size.width,
        r.size.height,
        b.size.height,
        scale,
    )
}
