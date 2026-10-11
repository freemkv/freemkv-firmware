//! qa's GUI gate on the GTK shell (`crate::gui_gate`), run by a debug build with
//! `FREEMKV_FLASH_GATE=<dir>` once the window is presented: every tab through `send`,
//! checked in the task buttons and in a render of the real window (`GtkSnapshot`), then the
//! flash confirmation driven through its own checkbox and Cancel button, its Confirm button
//! read from the dialog's widget tree. Writes `<dir>/gate.txt` and a PNG per tab and dialog,
//! and exits with the verdict.

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use gtk4 as gtk;
use gtk4::glib;
use gtk4::prelude::*;

use super::Shell;
use crate::gui_gate::{self, Capture, Gate, Order, Region, SheetRun, TabRun};
use crate::ui::{Input, Task};

/// How long a step lets GTK lay out and draw before it looks.
const SETTLE: Duration = Duration::from_millis(500);

/// Run the gate once the window has had time to map and draw.
pub(super) fn start(shell: &Rc<Shell>, dir: PathBuf) {
    let me = shell.clone();
    glib::timeout_add_local_once(SETTLE, move || run(&me, &dir));
}

fn run(shell: &Rc<Shell>, dir: &Path) {
    let mut g = Gate::default();
    g.no_drive_io("start", &shell.app.borrow());
    settle(SETTLE);
    let win: gtk::Widget = shell.window.clone().upcast();
    let shot = capture(&win);
    g.check(
        "window-not-blank",
        shot.as_ref().is_some_and(|s| s.has_ink(s.full())),
        shot.as_ref().map_or("no capture".into(), |s| {
            format!("{}x{} px", s.width, s.height)
        }),
    );

    for task in gui_gate::TABS {
        shell.send(Input::SelectTask(task));
        settle(SETTLE);
        let v = shell.view();
        let widget = Task::ALL
            .iter()
            .position(|t| *t == task)
            .and_then(|i| shell.tabs.get(i))
            .map(|b| b.is_active());
        let shot = capture(&win);
        let ink = shot
            .as_ref()
            .zip(region(shell.panel.upcast_ref(), &win))
            .map(|(s, r)| s.has_ink(r));
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

    shell.send(Input::SelectTask(Task::Flash));
    let first = sheet(shell, dir, true, &mut g);
    let reopened = sheet(shell, dir, false, &mut g);
    gui_gate::sheet_checks(&mut g, &first, &reopened);
    g.no_drive_io("end", &shell.app.borrow());
    std::process::exit(g.finish(dir));
}

/// Open the confirmation over the synthetic plan, read it, tick its box when `tick`, and
/// cancel it through its own button.
fn sheet(shell: &Rc<Shell>, dir: &Path, tick: bool, g: &mut Gate) -> SheetRun {
    let mut run = SheetRun::default();
    gui_gate::open_flash_sheet(&mut shell.app.borrow_mut());
    shell.render();
    settle(SETTLE);
    let open = shell
        .confirm
        .borrow()
        .as_ref()
        .map(|c| (c.dialog.clone(), c.ack.clone()));
    let (Some((dialog, ack)), Some(c)) = (open, shell.view().confirm) else {
        return run;
    };
    let root: gtk::Widget = dialog.clone().upcast();
    let confirm = button(&root, &c.confirm.text);
    run.opened = dialog.is_visible() && dialog.is_mapped();
    run.unticked = Some(!ack.is_active());
    run.confirm_before = confirm.as_ref().map(|b| b.is_sensitive());
    if tick {
        // As a click does: GTK's own activate signal toggles the box and runs the shell's
        // toggled handler.
        WidgetExt::activate(&ack);
        settle(SETTLE);
        let acked = shell.view().confirm.is_some_and(|v| v.ack_checked);
        run.ticked = Some((acked, confirm.as_ref().map(|b| b.is_sensitive())));
        run.box_reads_ticked = Some(ack.is_active());
    }
    let name = if tick { "sheet" } else { "sheet-reopened" };
    g.save(dir, name, capture(&root).as_ref());

    match button(&root, &c.cancel.text) {
        Some(b) => b.emit_clicked(),
        None => libadwaita::prelude::MessageDialogExt::response(&dialog, "cancel"),
    }
    let closed = || {
        shell.view().confirm.is_none() && shell.confirm.borrow().is_none() && !dialog.is_visible()
    };
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && !closed() {
        settle(Duration::from_millis(100));
    }
    run.closed = closed();
    run
}

/// Run the main loop for `d`: signals, layout and drawing.
fn settle(d: Duration) {
    let ctx = glib::MainContext::default();
    let until = Instant::now() + d;
    while Instant::now() < until {
        while ctx.iteration(false) {}
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn descendants(w: &gtk::Widget) -> Vec<gtk::Widget> {
    let mut out = Vec::new();
    let mut child = w.first_child();
    while let Some(c) = child {
        out.extend(descendants(&c));
        child = c.next_sibling();
        out.push(c);
    }
    out
}

/// The button under `root` labelled `text`, by its own label or its label child's.
fn button(root: &gtk::Widget, text: &str) -> Option<gtk::Button> {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Button>().ok())
        .find(|b| {
            b.label().is_some_and(|l| l.replace('_', "") == text)
                || descendants(b.upcast_ref())
                    .iter()
                    .filter_map(|w| w.downcast_ref::<gtk::Label>())
                    .any(|l| l.text().replace('_', "") == text)
        })
}

/// `w`'s bounds within `root`, in the capture's pixels.
fn region(w: &gtk::Widget, root: &gtk::Widget) -> Option<Region> {
    let b = w.compute_bounds(root)?;
    Some(Region {
        x: b.x().floor() as i32,
        y: b.y().floor() as i32,
        w: b.width().ceil() as i32,
        h: b.height().ceil() as i32,
    })
}

/// A render of `w` as GTK draws it, its own box from pixel (0, 0).
fn texture(w: &gtk::Widget) -> Option<gtk::gdk::Texture> {
    let paintable = gtk::WidgetPaintable::new(Some(w));
    let snap = gtk::Snapshot::new();
    paintable.snapshot(&snap, f64::from(w.width()), f64::from(w.height()));
    let node = snap.to_node()?;
    let area = gtk::graphene::Rect::new(0.0, 0.0, w.width() as f32, w.height() as f32);
    Some(w.native()?.renderer()?.render_texture(node, Some(&area)))
}

/// `w`'s render as 32-bit rows top-down, in GDK's default (BGRA, little-endian) layout.
fn capture(w: &gtk::Widget) -> Option<Capture> {
    let t = texture(w)?;
    let (cw, ch) = (t.width(), t.height());
    let mut px = vec![0u8; cw as usize * ch as usize * 4];
    t.download(&mut px, cw as usize * 4);
    Some(Capture {
        width: cw,
        height: ch,
        px,
        order: Order::Bgra,
        bottom_up: false,
    })
}
