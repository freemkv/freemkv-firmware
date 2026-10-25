//! qa's GUI gate on the AppKit shell (`crate::gui_gate`), run by a debug build with
//! `FREEMKV_FLASH_GATE=<dir>` once the window is up: every tab through `send`, checked in
//! the segmented control and in a capture (`cacheDisplayInRect:`) of the real window, then
//! a file picker dismissed through its own `cancel:` and a real Escape key event delivered
//! to the main window (the main window must survive both), then
//! the flash confirmation sheet driven through its own checkbox and Cancel button. Writes
//! `<dir>/gate.txt` and a PNG per tab and sheet, and exits with the verdict.

use std::path::Path;
use std::time::{Duration, Instant};

use objc2::{DefinedClass, MainThreadOnly, Message};
use objc2_app_kit::{
    NSApplication, NSBitmapFormat, NSEvent, NSEventMask, NSEventModifierFlags, NSEventType, NSMenu,
    NSView, NSWindow,
};
use objc2_foundation::{NSArray, NSDate, NSDefaultRunLoopMode, NSPoint};

use super::{ns, Controller};
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

    registration_checks(c, &mut g);
    language_checks(c, dir, &content, &mut g);
    analysis_header_languages(c, &mut g);

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

    firmware_pickers(c, &mut g);
    c.send(Input::SelectTask(Task::Flash));
    let first = sheet(c, dir, true, &mut g);
    let reopened = sheet(c, dir, false, &mut g);
    gui_gate::sheet_checks(&mut g, &first, &reopened);
    backup_question(c, dir, &mut g);
    report_prompt(c, dir, &mut g);
    c.with_app(|a| g.no_drive_io("end", a));
    std::process::exit(g.finish(dir));
}

/// Select languages through AppKit's real menu and read the controls that previously stayed English.
fn registration_checks(c: &Controller, g: &mut Gate) {
    c.send(Input::SelectTask(Task::Flash));
    c.send(Input::SelectTask(Task::Info));
    let counts = || {
        (
            c.ivars().actions.borrow().len(),
            c.ivars().checks.borrow().len(),
        )
    };
    let before = counts();
    for _ in 0..32 {
        c.send(Input::SelectTask(Task::Flash));
        c.send(Input::SelectTask(Task::Info));
    }
    g.check(
        "control-registrations-bounded",
        counts() == before,
        format!(
            "removed panels release tags: before={before:?}, after={:?}",
            counts()
        ),
    );
}

fn language_checks(c: &Controller, dir: &Path, content: &NSView, g: &mut Gate) {
    use crate::localization::{Language, Preferences};
    let original = c.with_app(|app| {
        let original = (app.drives.clone(), app.device.clone(), app.profile.clone());
        app.drives.clear();
        app.device.clear();
        app.profile = crate::ui::ProfileState::NoDrive;
        app.preferences = Preferences::User(Some(dir.join("language-preference")));
        original
    });
    c.render();
    let appkit = NSApplication::sharedApplication(c.mtm());
    for language in Language::ALL {
        let application_menu = appkit.mainMenu().and_then(|menu| {
            menu.itemArray()
                .iter()
                .next()
                .and_then(|item| item.submenu())
        });
        let parent = application_menu.and_then(|menu| {
            menu.itemArray()
                .iter()
                .find(|item| item.submenu().is_some())
        });
        let Some(parent) = parent else {
            g.check("language-menu-exists", false, language.code());
            break;
        };
        let menu = parent.submenu().expect("language submenu");
        menu.update();
        let index = Language::ALL
            .iter()
            .position(|choice| *choice == language)
            .unwrap();
        let item = menu.itemAtIndex(index as isize).expect("language item");
        g.check(
            &format!("language-{}-enabled", language.code()),
            parent.isEnabled() && item.isEnabled(),
            language.code(),
        );
        menu.performActionForItemAtIndex(index as isize);
        settle(c, Duration::from_millis(60));
        let view = c.view();
        let iv = c.ivars();
        let drive = iv
            .drive_label
            .borrow()
            .as_ref()
            .map(|label| label.stringValue().to_string());
        let placeholder = iv
            .drive_popup
            .borrow()
            .as_ref()
            .and_then(|popup| popup.titleOfSelectedItem())
            .map(|title| title.to_string());
        let refresh = iv
            .refresh
            .borrow()
            .as_ref()
            .map(|button| button.title().to_string());
        let tabs_match = iv.tabs.borrow().as_ref().is_some_and(|tabs| {
            view.tabs.iter().enumerate().all(|(index, tab)| {
                tabs.labelForSegment(index as isize)
                    .is_some_and(|title| title.to_string() == tab.title)
            })
        });
        let stored = c.with_app(|model| model.preferences.load());
        g.check(&format!("language-{}-widgets-and-startup", language.code()),
            view.language == language && stored == language
                && drive.as_deref() == Some(view.drives.label.as_str())
                && placeholder.as_deref() == Some(view.drives.placeholder.as_str())
                && refresh.as_deref() == Some(view.drives.refresh.text.as_str()) && tabs_match,
            format!("drive={drive:?}; placeholder={placeholder:?}; refresh={refresh:?}; tabs={tabs_match}"));
        if matches!(language, Language::Fr | Language::Ja | Language::ZhHant) {
            settle(c, SETTLE);
            let shot = capture(content);
            g.save(dir, &format!("language-{}", language.code()), shot.as_ref());
        }
    }
    c.with_app(|app| {
        app.drives = original.0;
        app.device = original.1;
        app.profile = original.2;
        app.language = Language::En;
        app.preferences = Preferences::Memory;
    });
    c.render();
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
    disclosure(c, dir, g);
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
            disclosure(c, dir, g);
        }
    }
    sheet_language_checks(c, g);
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
    if tick {
        if let Some(b) = cancel {
            unsafe { b.performClick(None) };
        }
    } else {
        let enter = ns("\r");
        let key = NSEvent::keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode(
            NSEventType::KeyDown, NSPoint::new(0.0, 0.0), NSEventModifierFlags::empty(),
            0.0, sheet_window.windowNumber(), None, &enter, &enter, false, 36,
        );
        g.check(
            "confirmation-return-cancels",
            key.is_some_and(|key| sheet_window.performKeyEquivalent(&key)),
            "Return activates Cancel after disclosure relayout",
        );
    }
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && !closed(c, &main) {
        settle(c, Duration::from_millis(100));
    }
    run.closed = closed(c, &main);
    run
}

/// The disclosure is native-local state: even opening long Unicode technical text
/// cannot acknowledge risk, remove a warning or change any model input.
fn sheet_language_checks(c: &Controller, g: &mut Gate) {
    let alert = c.ivars().alert.borrow().clone().unwrap();
    let old_ack = c.view().confirm.unwrap().ack_checked;
    let disclosure = c.ivars().alert_details.borrow().clone().unwrap().0;
    unsafe { disclosure.performClick(None) };
    c.send(Input::SetLanguage(crate::localization::Language::Fr));
    let expected = c.view().confirm.unwrap();
    let actual = c.ivars().alert.borrow().clone().unwrap();
    let accessory = actual.accessoryView().unwrap();
    let danger = accessory.subviews().iter().any(|view| {
        view.downcast_ref::<super::NSTextField>()
            .is_some_and(|label| label.stringValue().to_string() == expected.danger)
    });
    let ack = c.ivars().alert_ack.borrow().clone().unwrap();
    let details = c.ivars().alert_details.borrow().clone().unwrap();
    g.check(
        "confirmation-language-refresh",
        std::ptr::eq(&*actual, &*alert)
            && actual.messageText().to_string() == expected.title
            && actual.informativeText().to_string() == expected.details.join("\n")
            && actual.buttons().objectAtIndex(0).title().to_string() == expected.confirm.text
            && actual.buttons().objectAtIndex(1).title().to_string() == expected.cancel.text
            && danger
            && ack.title().to_string() == expected.ack_text
            && (ack.state() != 0) == old_ack
            && expected.ack_checked == old_ack
            && !details.1.isHidden()
            && details.0.title().to_string() == expected.hide_details_label
            && actual
                .buttons()
                .objectAtIndex(0)
                .keyEquivalent()
                .to_string()
                .is_empty()
            && actual
                .buttons()
                .objectAtIndex(1)
                .keyEquivalent()
                .to_string()
                == "\r",
        "same open sheet follows language while preserving consent, disclosure and Cancel default",
    );
    c.send(Input::SetLanguage(crate::localization::Language::En));
    let disclosure = c.ivars().alert_details.borrow().clone().unwrap().0;
    unsafe { disclosure.performClick(None) };
}

fn disclosure(c: &Controller, dir: &Path, g: &mut Gate) {
    let details = c.ivars().alert_details.borrow().clone();
    let alert = c.ivars().alert.borrow().clone().unwrap();
    g.check(
        "confirmation-details-control",
        details.is_some(),
        "technical plan has a Details control",
    );
    let Some((button, scroll)) = details else {
        return;
    };
    let before = c.view();
    let confirm = before.confirm.as_ref().unwrap();
    g.check(
        "confirmation-details-start-collapsed",
        scroll.isHidden() && button.title().to_string() == confirm.details_label,
        "a new sheet starts collapsed",
    );
    let height = alert.window().frame().size.height;
    for expanded in [true, false] {
        unsafe { button.performClick(None) };
        settle(c, SETTLE);
        let warnings_visible = alert.accessoryView().is_some_and(|accessory| {
            confirm.warnings.iter().all(|warning| {
                accessory.subviews().iter().any(|view| {
                    view.downcast_ref::<super::NSTextField>()
                        .is_some_and(|label| {
                            !label.isHidden() && label.stringValue().to_string() == *warning
                        })
                })
            })
        });
        let content = scroll.documentView().is_some_and(|document| {
            document.subviews().iter().any(|view| {
                view.downcast_ref::<super::NSTextField>()
                    .is_some_and(|text| {
                        text.stringValue().to_string() == confirm.technical_details.join("\n\n")
                            && !text.isEditable()
                    })
            })
        });
        let iv = c.ivars();
        let ack_unchanged = iv
            .alert_ack
            .borrow()
            .as_ref()
            .is_some_and(|ack| (ack.state() != 0) == confirm.ack_checked);
        let write_unchanged = iv.alert_confirm.borrow().as_ref().is_some_and(|write| {
            write.isEnabled() == confirm.confirm.enabled
                && write.keyEquivalent().to_string().is_empty()
        });
        g.check(
            if expanded {
                "confirmation-details-expanded"
            } else {
                "confirmation-details-collapsed"
            },
            scroll.isHidden() != expanded
                && content
                && warnings_visible
                && ack_unchanged
                && write_unchanged
                && c.view() == before
                && button.title().to_string().as_str()
                    == if expanded {
                        &confirm.hide_details_label
                    } else {
                        &confirm.details_label
                    },
            "exact details, warnings, acknowledgement and write gate preserved",
        );
        g.check(
            "confirmation-details-resizes",
            if expanded {
                alert.window().frame().size.height > height
            } else {
                (alert.window().frame().size.height - height).abs() < 1.0
            },
            "expanded text is scrollable; collapse restores the compact sheet",
        );
        if expanded {
            g.check(
                "confirmation-details-start-at-top",
                scroll.contentView().bounds().origin.y.abs() < 1.0,
                format!(
                    "the first technical detail is immediately visible; clip {:?}",
                    scroll.contentView().bounds()
                ),
            );
        }
        if expanded {
            alert.window().display();
            g.save(
                dir,
                "confirmation-details",
                alert
                    .window()
                    .contentView()
                    .and_then(|v| capture(&v))
                    .as_ref(),
            );
        }
    }
}

/// Open the flash file picker and cancel it through the panel's own `cancel:`: the picker
/// must close and the main window must stay up (Escape once closed the window and quit the
/// app). Then press Escape in the main window itself.
fn firmware_pickers(c: &Controller, g: &mut Gate) {
    let original = c.with_app(|app| app.profile.clone());
    for (_, extensions) in gui_gate::PICKER_PROFILES {
        c.with_app(|app| {
            if let crate::ui::ProfileState::Ready(profile) = &mut app.profile {
                profile.firmware_picker =
                    crate::ui::FirmwarePickerFormats::prefer(extensions.to_vec());
            }
        });
        for pick in gui_gate::FIRMWARE_PICKS {
            escape_closes_only_the_picker(c, pick, g);
            c.with_app(|app| g.no_drive_io(&format!("picker {pick:?}"), app));
        }
    }
    c.with_app(|app| app.profile = original);
}

fn escape_closes_only_the_picker(c: &Controller, pick: Pick, g: &mut Gate) {
    let Some(main) = c.ivars().window.borrow().clone() else {
        return;
    };
    c.send(Input::Choose(pick));
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
    // A synthetic key event did not reach the panel in testing, so the gate sends the
    // panel's own `cancel:`.
    unsafe {
        let _: () = objc2::msg_send![&*picker, cancel: Option::<&objc2::runtime::AnyObject>::None];
    }
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && main.attachedSheet().is_some() {
        settle(c, Duration::from_millis(100));
    }
    g.check(
        "picker-cancel-closes-picker",
        main.attachedSheet().is_none(),
        "the panel's cancel:",
    );
    g.check(
        "main-window-survives-picker-cancel",
        main.isVisible() && c.view().confirm.is_none(),
        if main.isVisible() {
            "visible"
        } else {
            "closed"
        },
    );
    escape_key_leaves_main_window(c, &main, g);
}

/// Press Escape in the main window itself: no menu item may take a bare Escape, and a real
/// Escape key event (keyCode 53) must leave the window up, the app running and the model
/// unchanged. The window is made key and first responder, and the event goes through the
/// window's `sendEvent:` (key-down and key-up), its `keyDown:`, the key bindings
/// (`interpretKeyEvents:`), and its views' and the main menu's key equivalents. In testing,
/// with the gate's app inactive, `sendEvent:` and `keyDown:` did not bring a
/// `cancelOperation:` to the controller (the window's and the app's delegate); the key
/// bindings did.
fn escape_key_leaves_main_window(c: &Controller, main: &NSWindow, g: &mut Gate) {
    let app = NSApplication::sharedApplication(c.mtm());
    let bare = app
        .mainMenu()
        .map(|m| bare_escape_items(&m))
        .unwrap_or_default();
    g.check(
        "no-bare-escape-menu-item",
        bare.is_empty(),
        if bare.is_empty() {
            "none".into()
        } else {
            bare.join(", ")
        },
    );
    let (Some(down), Some(up)) = (
        escape(main, NSEventType::KeyDown),
        escape(main, NSEventType::KeyUp),
    ) else {
        g.check("escape-key-leaves-main-window", false, "no key event");
        return;
    };
    let before = c.view();
    let responder = main.firstResponder();
    main.makeKeyWindow();
    main.makeFirstResponder(None);
    main.sendEvent(&down);
    main.sendEvent(&up);
    let key = main.isKeyWindow();
    main.keyDown(&down);
    main.interpretKeyEvents(&NSArray::from_slice(&[&*down]));
    let by_view = main.performKeyEquivalent(&down);
    let by_menu = app
        .mainMenu()
        .is_some_and(|m| m.performKeyEquivalent(&down));
    settle(c, SETTLE);
    main.makeFirstResponder(responder.as_deref());
    let visible = main.isVisible();
    let unchanged = c.view() == before;
    g.check(
        "escape-key-leaves-main-window",
        visible && app.isRunning() && unchanged,
        format!(
            "window {}, model {}, key window {key}, key equivalent taken by views {by_view}, \
             by menu {by_menu}",
            if visible { "visible" } else { "closed" },
            if unchanged { "unchanged" } else { "changed" },
        ),
    );
}

/// An Escape key event of type `kind` addressed to `window`.
fn escape(window: &NSWindow, kind: NSEventType) -> Option<objc2::rc::Retained<NSEvent>> {
    let esc = ns("\u{1b}");
    NSEvent::keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode(
        kind,
        NSPoint::new(0.0, 0.0),
        NSEventModifierFlags::empty(),
        0.0,
        window.windowNumber(),
        None,
        &esc,
        &esc,
        false,
        53,
    )
}

/// The titles of `menu`'s items, submenus included, whose key equivalent is Escape with
/// no Command, Option or Control modifier.
fn bare_escape_items(menu: &NSMenu) -> Vec<String> {
    let chord = NSEventModifierFlags::Command
        | NSEventModifierFlags::Option
        | NSEventModifierFlags::Control;
    let mut out = Vec::new();
    for item in menu.itemArray().iter() {
        if item.keyEquivalent().to_string() == "\u{1b}"
            && !item.keyEquivalentModifierMask().intersects(chord)
        {
            out.push(item.title().to_string());
        }
        if let Some(sub) = item.submenu() {
            out.extend(bare_escape_items(&sub));
        }
    }
    out
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

fn backup_question(c: &Controller, dir: &Path, g: &mut Gate) {
    c.with_app(gui_gate::open_backup_question);
    c.render();
    settle(c, SETTLE);
    let iv = c.ivars();
    let alert = iv.alert.borrow().clone().expect("backup question");
    let buttons = alert.buttons();
    g.check(
        "backup-question-yes-no",
        buttons.len() == 2
            && buttons.objectAtIndex(0).title().to_string() == "Yes"
            && buttons.objectAtIndex(1).title().to_string() == "No",
        "native Yes and No buttons",
    );
    g.check(
        "backup-question-explicit-yes",
        buttons.objectAtIndex(0).isEnabled()
            && buttons
                .objectAtIndex(0)
                .keyEquivalent()
                .to_string()
                .is_empty()
            && buttons.objectAtIndex(1).keyEquivalent().to_string() == "\r",
        format!(
            "confirm enabled={} key={:?}; cancel key={:?}",
            buttons.objectAtIndex(0).isEnabled(),
            buttons.objectAtIndex(0).keyEquivalent().to_string(),
            buttons.objectAtIndex(1).keyEquivalent().to_string()
        ),
    );
    g.check(
        "backup-question-no-extra-checkbox",
        iv.alert_ack
            .borrow()
            .as_ref()
            .is_some_and(|ack| ack.isHidden()),
        "risk acknowledgement is reserved for final Flash confirmation",
    );
    if let Some(content) = alert.window().contentView() {
        let shot = capture(&content);
        g.save(dir, "backup-question", shot.as_ref());
    }
    c.send(Input::CancelConfirm);
    settle(c, SETTLE);
    g.check(
        "backup-question-closes-on-no",
        c.view().confirm.is_none(),
        "no update was authorized",
    );
}

fn analysis_header_languages(c: &Controller, g: &mut Gate) {
    use crate::localization::{get, Language};
    let mut view = c.view();
    view.analysis = Some(crate::ui::AnalysisWindow {
        tree: std::sync::Arc::new(crate::ui::AnalysisView {
            title: "Synthetic analysis".into(),
            actions: Vec::new(),
            heading: "Synthetic".into(),
            nodes: Vec::new(),
        }),
        notice: None,
    });
    for language in [Language::En, Language::Fr, Language::Ja, Language::En] {
        view.language = language;
        c.render_analysis(&view);
        let outline = c.ivars().an_outline.borrow().clone().unwrap();
        let columns = outline.tableColumns();
        g.check(
            &format!("analysis-headers-{}", language.code()),
            columns.objectAtIndex(0).title().to_string() == get(language, "field.item")
                && columns.objectAtIndex(1).title().to_string() == get(language, "field.value"),
            "existing table updates without replacing its data",
        );
    }
    c.render_analysis(&c.view());
}

/// Exercise AppKit's actual multiline editor and sheet completion, with an inert
/// model: Send consumes the draft but cannot start a browser or network worker.
fn report_prompt(c: &Controller, dir: &Path, g: &mut Gate) {
    use crate::localization::{get, Language};
    let main = c.ivars().window.borrow().clone().unwrap();
    let mut previous = String::new();
    for (action, description) in [
        ("cancel", "  日本語 🦀\nsecond line\n  "),
        ("send", "Résumé\n描述 🦀\n"),
        ("close", "closing\n保留 🦀"),
        ("send-blank", ""),
    ] {
        c.send(Input::SubmitReport);
        settle(c, SETTLE);
        let alert = c.ivars().report_alert.borrow().clone();
        g.check(
            "report-prompt-opens",
            alert.is_some() && main.attachedSheet().is_some(),
            "report action opens a native sheet",
        );
        let Some(alert) = alert else {
            return;
        };
        let editor = alert.accessoryView().and_then(|v| report_editor(&v));
        g.check(
            "report-multiline-editor",
            editor.is_some(),
            "native NSTextView in report accessory",
        );
        let Some(editor) = editor else {
            return;
        };
        g.check(
            "report-draft-restored",
            editor.string().to_string() == previous,
            action,
        );
        g.check(
            "report-required-description-label",
            alert.accessoryView().is_some_and(|accessory| {
                accessory.subviews().iter().any(|child| {
                    child
                        .downcast_ref::<super::NSTextField>()
                        .is_some_and(|label| {
                            label.stringValue().to_string() == "Description (required)"
                        })
                })
            }),
            "exact English label on the actual accessory control",
        );
        if action == "cancel" {
            g.save(
                dir,
                "report-prompt",
                alert
                    .window()
                    .contentView()
                    .and_then(|v| capture(&v))
                    .as_ref(),
            );
        }
        let buttons = alert.buttons();
        g.check(
            "report-controls-localized",
            alert.messageText().to_string() == get(Language::En, "report.prompt_title")
                && buttons.objectAtIndex(0).title().to_string() == get(Language::En, "report.send")
                && buttons.objectAtIndex(1).title().to_string() == get(Language::En, "ui.cancel")
                && buttons
                    .objectAtIndex(0)
                    .keyEquivalent()
                    .to_string()
                    .is_empty(),
            "Send requires an explicit click; Return belongs to the multiline editor",
        );
        editor.setString(&ns(description));
        // Pump while editing to exercise timer/render reentrancy without resetting text.
        settle(c, SETTLE);
        g.check(
            "report-editor-keeps-unicode",
            editor.string().to_string() == description,
            action,
        );
        match action {
            "close" => main.endSheet_returnCode(&alert.window(), 0),
            "cancel" => unsafe { buttons.objectAtIndex(1).performClick(None) },
            _ => unsafe { buttons.objectAtIndex(0).performClick(None) },
        }
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until && main.attachedSheet().is_some() {
            settle(c, Duration::from_millis(100));
        }
        settle(c, SETTLE);
        let (draft, open) = c.with_app(|app| {
            let (draft, open) = app.report_prompt_state();
            (draft.to_owned(), open)
        });
        if action == "send-blank" {
            let required =
                get(Language::En, "report.description_required").replace("{summary}", "");
            let reopened = c.ivars().report_alert.borrow().clone();
            g.check(
                "report-blank-description-requires-input",
                draft.is_empty()
                    && open
                    && main.attachedSheet().is_some()
                    && reopened.as_ref().is_some_and(|alert| {
                        alert
                            .informativeText()
                            .to_string()
                            .contains(required.trim())
                    }),
                "blank Send reopens the required-description prompt without network or drive I/O",
            );
            c.with_app(|app| g.no_drive_io(action, app));
            if let Some(alert) = reopened {
                unsafe { alert.buttons().objectAtIndex(1).performClick(None) };
                settle(c, SETTLE);
            }
            previous = description.to_owned();
            continue;
        }
        g.check(
            &format!("report-{action}-retains-description"),
            draft == description
                && !open
                && main.attachedSheet().is_none()
                && c.ivars().report_alert.borrow().is_none(),
            format!("draft={draft:?}; prompt open={open}"),
        );
        c.with_app(|app| g.no_drive_io(action, app));
        previous = description.to_owned();
    }
}

fn report_editor(view: &NSView) -> Option<objc2::rc::Retained<super::NSTextView>> {
    if let Some(editor) = view.downcast_ref::<super::NSTextView>() {
        return Some(editor.retain());
    }
    view.subviews()
        .iter()
        .find_map(|child| report_editor(&child))
}
