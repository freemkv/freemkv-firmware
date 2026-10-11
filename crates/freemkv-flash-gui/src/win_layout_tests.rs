use super::*;
use crate::ui::{App, CheckId, Input, Pick, Task};

#[test]
fn scale_rounds_like_muldiv_and_clamps_a_missing_dpi() {
    assert_eq!(Scale::new(0).dpi(), BASE_DPI);
    assert_eq!(Scale::new(96).px(PAD), PAD);
    assert_eq!(Scale::new(144).px(PAD), 24);
    assert_eq!(Scale::new(120).px(7), 9); // 8.75 rounds up
    assert_eq!(Scale::new(120).px(-7), -9);
    assert_eq!(default_size(192), (2 * W, 2 * H));
    assert_eq!(min_size(96), (MIN_W, MIN_H));
}

#[test]
fn column_stacks_rows_a_gap_apart() {
    let mut c = Column::new(10, 20, 300, 8);
    assert_eq!(c.take(26), Rect::new(10, 20, 300, 26));
    c.space(4);
    assert_eq!(c.take(18), Rect::new(10, 58, 300, 18));
    assert_eq!(c.take(-5).h, 0);
    assert_eq!(c.y, 84 + 8);
}

#[test]
fn line_fills_from_both_ends_and_never_goes_negative() {
    let mut c = Column::new(0, 0, 400, 8);
    let mut l = c.line(26);
    assert_eq!(l.take(96), Rect::new(0, 0, 96, 26));
    assert_eq!(l.take_right(90), Rect::new(310, 0, 90, 26));
    assert_eq!(l.rest(), Rect::new(104, 0, 198, 26));
    assert_eq!(l.take(50).w, 0);
    assert_eq!(l.take_right(50).w, 0);
    assert_eq!(
        Line::centre(Rect::new(0, 10, 40, 26), 18),
        Rect::new(0, 14, 40, 18)
    );
}

#[test]
fn buttons_fit_their_text_and_keep_a_minimum() {
    let s = Scale::new(96);
    assert_eq!(button_width(s, 10, false), BUTTON_MIN_W);
    assert_eq!(button_width(s, 10, true), PRIMARY_MIN_W);
    assert_eq!(button_width(s, 200, false), 200 + BUTTON_PAD);
    assert_eq!(button_width(Scale::new(192), 10, false), 2 * BUTTON_MIN_W);
}

/// Every task form the model can produce fits the pools the Windows shell builds up front.
#[test]
fn every_task_form_fits_the_control_pools() {
    let mut app = App::with_drives(Vec::new());
    let mut forms = Vec::new();
    for task in Task::ALL {
        app.dispatch(Input::SelectTask(task));
        forms.push(app.view().panel);
    }
    for (pick, name) in [
        (Pick::FlashFirmware, "a.bin"),
        (Pick::RecoveryCurrent, "current.bin"),
        (Pick::RecoveryInput, "new.bin"),
        (Pick::AnalysisFile(0), "left.bin"),
        (Pick::AnalysisFile(1), "right.bin"),
    ] {
        app.dispatch(Input::Chosen(pick, name.into()));
    }
    app.dispatch(Input::SetCheck(CheckId::RecoveryReadFromDrive, true));
    for task in Task::ALL {
        app.dispatch(Input::SelectTask(task));
        forms.push(app.view().panel);
    }
    for form in &forms {
        let needs = panel_needs(form);
        assert!(
            needs.fits(),
            "{needs:?} does not fit the pools for {form:?}"
        );
    }
    assert!(forms.iter().any(|f| panel_needs(f).checks == 1));
    assert!(forms.iter().any(|f| panel_needs(f).line >= 2));
}
