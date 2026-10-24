use super::*;
use crate::ui::{CheckId, View};

/// The gate's model with the test recorder on: any job or profile read that got past
/// `inert` would land in `dry_run` or `profile_worker`.
fn recorded() -> App {
    let mut app = fixture();
    app.dry_run = Some(Vec::new());
    app
}

fn assert_no_io(app: &App, after: &str) {
    assert!(
        app.dry_run.as_ref().is_some_and(Vec::is_empty),
        "{after}: a job was started: {:?}",
        app.dry_run
            .as_ref()
            .map(|j| j.iter().map(|(l, d, _)| (l, d)).collect::<Vec<_>>())
    );
    assert!(
        app.profile_worker.is_none(),
        "{after}: a profile read began"
    );
    assert!(inert(app), "{after}: the model left the gate's hands");
    assert_eq!(app.drives.len(), 1, "{after}: the drives were rescanned");
    assert_eq!(app.drives[0].path, DRIVE);
}

fn confirm(view: &View) -> &crate::ui::Confirm {
    view.confirm.as_ref().expect("the confirmation is open")
}

#[test]
fn fixture_offers_every_tab_with_its_full_form() {
    let mut app = recorded();
    for task in TABS {
        app.dispatch(Input::SelectTask(task));
        let view = app.view();
        assert_eq!(view.task, task);
        assert!(view.tabs.iter().all(|t| t.enabled), "{task:?}");
        assert!(view.controls_enabled);
    }
    assert_eq!(TABS.len(), Task::ALL.len());
    assert!(Task::ALL.iter().all(|t| TABS.contains(t)));
    app.dispatch(Input::SelectTask(Task::Flash));
    assert!(app.view().panel.iter().any(|item| matches!(
        item,
        crate::ui::Item::Buttons { buttons, .. }
            if buttons.iter().any(|b| b.text == "Flash now" && b.enabled)
    )));
    assert_no_io(&app, "walking the tabs");
}

/// The gate path can never construct a workflow call: every input that runs work on a real
/// drive, and the sheet's own Confirm, end at `inert`.
#[test]
fn the_gate_model_never_reaches_a_device() {
    let mut app = recorded();
    assert!(app.start().is_empty());
    assert_no_io(&app, "start");
    let work = [
        Input::Refresh,
        Input::SelectDrive(0),
        Input::ReadInfo,
        Input::CheckFlashFile,
        Input::FlashNow,
        Input::Chosen(Pick::CheckFile, "gate.bin".into()),
        Input::Chosen(Pick::Backup, "gate.backup.bin".into()),
        Input::Chosen(Pick::Dump, "gate.dump.bin".into()),
        Input::Chosen(Pick::AnalysisDrive(0), "gate.capture".into()),
        Input::SelectTask(Task::Inspect),
        Input::RunAnalysis,
        Input::SelectTask(Task::Compare),
        Input::RunAnalysis,
        Input::SelectTask(Task::Recovery),
        Input::Recover,
        Input::SetCheck(CheckId::RiskAck, true),
        Input::Confirm,
    ];
    for input in work {
        let label = format!("{input:?}");
        app.dispatch(input);
        app.poll();
        assert_no_io(&app, &label);
    }
    open_flash_sheet(&mut app);
    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    app.dispatch(Input::Confirm);
    app.poll();
    assert_no_io(&app, "confirming the synthetic flash");
}

#[test]
fn the_synthetic_sheet_gates_confirm_on_a_fresh_tick() {
    let mut app = recorded();
    open_flash_sheet(&mut app);
    let view = app.view();
    let c = confirm(&view);
    assert_eq!(c.title, "Update this drive?");
    assert!(!c.ack_checked && !c.confirm.enabled);
    assert!(c.details.iter().any(|d| d.contains("synthetic plan")));
    assert!(!view.controls_enabled, "the sheet locks the window");

    app.dispatch(Input::SetCheck(CheckId::RiskAck, true));
    assert!(confirm(&app.view()).confirm.enabled);
    app.dispatch(Input::CancelConfirm);
    assert!(app.view().confirm.is_none());

    open_flash_sheet(&mut app);
    let view = app.view();
    let c = confirm(&view);
    assert!(
        !c.ack_checked && !c.confirm.enabled,
        "a reopened sheet starts over"
    );
    app.dispatch(Input::CancelConfirm);
    assert_no_io(&app, "the sheet");
}

fn capture(w: i32, h: i32, fill: [u8; 4]) -> Capture {
    Capture {
        width: w,
        height: h,
        px: fill.repeat((w * h) as usize),
        order: Order::Bgra,
        bottom_up: false,
    }
}

fn paint(c: &mut Capture, x: i32, y: i32, p: [u8; 4]) {
    let row = if c.bottom_up { c.height - 1 - y } else { y };
    let i = ((row * c.width + x) * 4) as usize;
    c.px[i..i + 4].copy_from_slice(&p);
}

#[test]
fn ink_is_more_than_one_colour_in_the_region() {
    let mut c = capture(8, 6, [240, 240, 240, 255]);
    assert!(!c.has_ink(c.full()), "a blank fill");
    paint(&mut c, 5, 4, [0, 0, 0, 255]);
    assert!(c.has_ink(c.full()));
    assert!(c.has_ink(Region {
        x: 4,
        y: 3,
        w: 2,
        h: 2
    }));
    assert!(
        !c.has_ink(Region {
            x: 0,
            y: 0,
            w: 4,
            h: 4
        }),
        "the dot is elsewhere"
    );
    assert!(
        !c.has_ink(Region {
            x: 20,
            y: 20,
            w: 5,
            h: 5
        }),
        "outside the capture"
    );
    // Alpha alone is not ink.
    let mut c = capture(4, 4, [9, 9, 9, 255]);
    paint(&mut c, 1, 1, [9, 9, 9, 0]);
    assert!(!c.has_ink(c.full()));
}

#[test]
fn ink_follows_the_row_order() {
    let mut c = capture(4, 4, [255, 255, 255, 255]);
    c.bottom_up = true;
    paint(&mut c, 0, 0, [0, 0, 0, 255]);
    assert!(c.has_ink(
        Region {
            x: 0,
            y: 0,
            w: 1,
            h: 1
        }
        .grow()
    ));
    assert!(
        !c.has_ink(Region {
            x: 0,
            y: 2,
            w: 4,
            h: 2
        }),
        "the dot is at the top"
    );
    assert_eq!(
        &c.px[12 * 4..12 * 4 + 3],
        &[0, 0, 0],
        "stored in the last row"
    );
}

impl Region {
    fn grow(self) -> Self {
        Self {
            w: self.w + 1,
            h: self.h + 1,
            ..self
        }
    }
}

#[test]
fn a_short_capture_has_no_ink() {
    let mut c = capture(4, 4, [1, 2, 3, 255]);
    paint(&mut c, 3, 3, [0, 0, 0, 255]);
    c.px.truncate(8);
    assert!(!c.has_ink(c.full()));
}

#[test]
fn rgba_is_top_down_opaque_and_reordered() {
    let mut c = capture(2, 2, [10, 20, 30, 0]);
    c.bottom_up = true;
    paint(&mut c, 1, 0, [1, 2, 3, 0]);
    assert_eq!(
        c.rgba(),
        [30, 20, 10, 255, 3, 2, 1, 255, 30, 20, 10, 255, 30, 20, 10, 255]
    );
    let rgba = Capture {
        order: Order::Rgba,
        bottom_up: false,
        ..capture(1, 1, [7, 8, 9, 0])
    };
    assert_eq!(rgba.rgba(), [7, 8, 9, 255]);
}

#[test]
fn a_capture_saves_as_a_png_of_its_pixels() {
    let dir = std::env::temp_dir().join(format!("fmk-gate-png-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = capture(3, 2, [200, 100, 50, 255]);
    paint(&mut c, 2, 1, [0, 0, 255, 255]);
    let mut g = Gate::default();
    g.save(&dir, "tab", Some(&c));
    assert!(g.passed(), "{}", g.report());
    let png = image::open(dir.join("tab.png")).unwrap().to_rgba8();
    assert_eq!(png.dimensions(), (3, 2));
    assert_eq!(png.get_pixel(0, 0).0, [50, 100, 200, 255]);
    assert_eq!(png.get_pixel(2, 1).0, [255, 0, 0, 255]);

    let mut g = Gate::default();
    g.save(&dir, "missing", None);
    assert!(!g.passed());
    assert!(g.report().contains("GATE FAIL capture"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_appkit_frame_maps_to_top_down_pixels() {
    // A 100×20 pt frame 30 pt above the bottom of a 200 pt view, on a 2× display.
    assert_eq!(
        Region::from_bottom_left(10.0, 30.0, 100.0, 20.0, 200.0, 2.0),
        Region {
            x: 20,
            y: 300,
            w: 200,
            h: 40
        }
    );
    assert_eq!(
        Region::from_bottom_left(0.0, 0.0, 50.0, 50.0, 50.0, 1.0),
        Region {
            x: 0,
            y: 0,
            w: 50,
            h: 50
        }
    );
}

#[test]
fn the_verdict_needs_every_check_and_at_least_one() {
    let g = Gate::default();
    assert!(!g.passed(), "a gate that checked nothing has not passed");
    assert!(g.report().contains("GATE FAILED: 0 of 0"));

    let mut g = Gate::default();
    g.check("one", true, "fine");
    g.check("two", true, "also");
    assert!(g.passed());
    assert_eq!(
        g.report(),
        "GATE PASS one — fine\nGATE PASS two — also\nGATE OK: 2 checks\n"
    );
    g.check("three", false, "broken");
    assert!(!g.passed());
    assert!(g
        .report()
        .ends_with("GATE FAIL three — broken\nGATE FAILED: 1 of 3 checks\n"));
}

#[test]
fn finish_writes_the_report_and_returns_the_exit_code() {
    let dir = std::env::temp_dir().join(format!("fmk-gate-finish-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut g = Gate::default();
    g.check("ok", true, "");
    assert_eq!(g.finish(&dir), 0);
    assert!(std::fs::read_to_string(dir.join("gate.txt"))
        .unwrap()
        .contains("GATE OK: 1 checks"));
    g.check("bad", false, "");
    assert_eq!(g.finish(&dir), 1);
    assert_eq!(
        g.finish(&dir.join("no-such-directory")),
        1,
        "an unwritten report fails"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

fn good_sheets() -> (SheetRun, SheetRun) {
    let first = SheetRun {
        opened: true,
        unticked: Some(true),
        confirm_before: Some(false),
        ticked: Some((true, Some(true))),
        box_reads_ticked: Some(true),
        closed: true,
    };
    let reopened = SheetRun {
        ticked: None,
        box_reads_ticked: None,
        ..first.clone()
    };
    (first, reopened)
}

fn sheet_verdict(first: &SheetRun, reopened: &SheetRun) -> Gate {
    let mut g = Gate::default();
    sheet_checks(&mut g, first, reopened);
    g
}

#[test]
fn a_sheet_that_gates_confirm_passes() {
    let (first, reopened) = good_sheets();
    let g = sheet_verdict(&first, &reopened);
    assert!(g.passed(), "{}", g.report());
    assert_eq!(g.report().lines().count(), 12);
}

#[test]
fn every_sheet_fault_fails_the_gate() {
    let (good, reopened) = good_sheets();
    let faults: [(&str, SheetRun, SheetRun); 10] = [
        (
            "the box does not read back as ticked",
            SheetRun {
                box_reads_ticked: Some(false),
                ..good.clone()
            },
            reopened.clone(),
        ),
        ("never opened", SheetRun::default(), reopened.clone()),
        (
            "confirm enabled before the tick",
            SheetRun {
                confirm_before: Some(true),
                ..good.clone()
            },
            reopened.clone(),
        ),
        (
            "confirm not found",
            SheetRun {
                confirm_before: None,
                ..good.clone()
            },
            reopened.clone(),
        ),
        (
            "opened ticked",
            SheetRun {
                unticked: Some(false),
                ..good.clone()
            },
            reopened.clone(),
        ),
        (
            "the tick never reached the model",
            SheetRun {
                ticked: Some((false, Some(true))),
                ..good.clone()
            },
            reopened.clone(),
        ),
        (
            "confirm stayed disabled after the tick",
            SheetRun {
                ticked: Some((true, Some(false))),
                ..good.clone()
            },
            reopened.clone(),
        ),
        (
            "cancel left it open",
            SheetRun {
                closed: false,
                ..good.clone()
            },
            reopened.clone(),
        ),
        (
            "reopened with confirm enabled",
            good.clone(),
            SheetRun {
                confirm_before: Some(true),
                ..reopened.clone()
            },
        ),
        (
            "reopened ticked",
            good.clone(),
            SheetRun {
                unticked: Some(false),
                ..reopened.clone()
            },
        ),
    ];
    for (what, first, again) in faults {
        assert!(!sheet_verdict(&first, &again).passed(), "{what} passed");
    }
}

#[test]
fn tab_checks_need_model_widget_and_ink() {
    let good = TabRun {
        task: Task::Flash,
        model: true,
        widget: Some(true),
        ink: Some(true),
    };
    let mut g = Gate::default();
    tab_checks(&mut g, &good);
    assert!(g.passed(), "{}", g.report());
    for bad in [
        TabRun {
            model: false,
            ..good.clone()
        },
        TabRun {
            widget: None,
            ..good.clone()
        },
        TabRun {
            widget: Some(false),
            ..good.clone()
        },
        TabRun {
            ink: Some(false),
            ..good.clone()
        },
        TabRun {
            ink: None,
            ..good.clone()
        },
    ] {
        let mut g = Gate::default();
        tab_checks(&mut g, &bad);
        assert!(!g.passed(), "{bad:?} passed");
    }
}

#[test]
fn tab_names_suit_file_names() {
    let names: Vec<String> = TABS.iter().map(|t| tab_name(*t)).collect();
    assert_eq!(
        names,
        [
            "drive-info",
            "backup",
            "dump",
            "flash",
            "recovery",
            "inspect",
            "compare"
        ]
    );
}

/// The gate names workflow types only, never a call, and never the ops layer.
#[test]
fn the_gate_source_calls_no_workflow() {
    let src = include_str!("gui_gate.rs");
    for (n, line) in src.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        assert!(!code.contains("ops::"), "gui_gate.rs:{}: {line}", n + 1);
        if code.contains("workflow") {
            assert_eq!(
                code,
                "use freemkv_flash::workflow::{DriveChoice, FlashOptions, FlashSheet};",
                "gui_gate.rs:{}",
                n + 1
            );
        }
    }
}

#[test]
fn flatten_reveals_black_text_on_a_transparent_background() {
    // One transparent pixel and one opaque black text pixel: identical RGB until flattened.
    let mut shot = Capture {
        width: 2,
        height: 1,
        px: vec![0, 0, 0, 0, 0, 0, 0, 255],
        order: Order::Rgba,
        bottom_up: false,
    };
    assert!(!shot.has_ink(shot.full()));
    shot.flatten([128, 128, 128], true);
    assert!(shot.has_ink(shot.full()));
    assert_eq!(shot.px, [128, 128, 128, 255, 0, 0, 0, 255]);
}

#[test]
fn a_task_dialog_box_is_unticked_only_when_nothing_ticked_it() {
    assert!(task_dialog_unticked(false, false, false));
    // Ticked by its creation flags, by a reported click of any cause, or in the model.
    assert!(!task_dialog_unticked(true, false, false));
    assert!(!task_dialog_unticked(false, true, false));
    assert!(!task_dialog_unticked(false, false, true));
}
