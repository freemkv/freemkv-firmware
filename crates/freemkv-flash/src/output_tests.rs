use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn backup_bypass_without_interactive_input_is_localized_and_never_auto_approved() {
    let reason = crate::user_error::UserError {
        id: "errors.backup_failed",
        arguments: Vec::new(),
        consequence: Some("errors.no_firmware_write"),
    }
    .encoded();
    let mut input = b"yes\n".as_slice();
    let error = confirm_backup_with(
        &reason,
        false,
        &mut input,
        crate::localization::Language::Fr,
    )
    .unwrap_err();
    let issue = crate::workflow::user_error(&error);
    assert_eq!(issue.id, "errors.backup_confirmation_required");
    assert_eq!(issue.consequence, Some("errors.no_firmware_write"));
    let text = issue.render(crate::localization::Language::Fr);
    assert!(text.contains(crate::localization::get(
        crate::localization::Language::Fr,
        "errors.backup_confirmation_required"
    )));
    assert!(!text.contains("TTY"));
    assert_eq!(
        input, b"yes\n",
        "no answer can be consumed without an interactive terminal"
    );
}

#[test]
fn captures_both_streams_and_restores_after_panic() {
    let messages = Arc::new(Mutex::new(Vec::new()));
    let received = messages.clone();
    let _ = std::panic::catch_unwind(|| {
        capture(
            move |s| received.lock().unwrap().push(s),
            || {
                println!("information");
                eprintln!("warning");
                panic!("worker failed");
            },
        )
    });
    assert_eq!(*messages.lock().unwrap(), ["information", "warning"]);
    assert!(!captured());
}

#[test]
fn simultaneous_operations_keep_their_output_separate() {
    let workers: Vec<_> = (0..2)
        .map(|n| {
            std::thread::spawn(move || {
                let messages = Arc::new(Mutex::new(Vec::new()));
                let received = messages.clone();
                capture(
                    move |s| received.lock().unwrap().push(s),
                    || println!("job {n}"),
                );
                assert_eq!(*messages.lock().unwrap(), [format!("job {n}")]);
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn confirm_auto_proceeds_when_stdin_is_not_a_tty() {
    // The consent carries from --execute/--i-understand-risk: no prompt is read.
    let mut empty: &[u8] = b"";
    assert!(confirm_with(false, &mut empty).unwrap());
}

#[test]
fn confirmations_use_the_selected_language_and_keep_no_as_the_default() {
    for language in crate::localization::Language::ALL {
        let prompt = consent_prompt(language, "confirm.proceed");
        assert!(prompt.contains(crate::localization::get(language, "confirm.proceed")));
        assert!(prompt.contains(crate::localization::get(language, "action.yes")));
        assert!(prompt.contains(crate::localization::get(language, "action.no")));
        let yes = format!("{}\n", crate::localization::get(language, "action.yes"));
        assert!(confirm_in_language(true, &mut yes.as_bytes(), language).unwrap());
        let no = format!("{}\n", crate::localization::get(language, "action.no"));
        assert!(!confirm_in_language(true, &mut no.as_bytes(), language).unwrap());
        assert!(!confirm_in_language(true, &mut b"\n".as_slice(), language).unwrap());
        assert!(confirm_in_language(false, &mut b"".as_slice(), language).unwrap());
    }
}

#[test]
fn confirm_on_a_tty_requires_an_explicit_yes() {
    for input in ["y\n", "yes\n", "Y\n", "YES\n"] {
        let mut bytes = input.as_bytes();
        assert!(confirm_with(true, &mut bytes).unwrap());
    }
    for input in ["\n", "n\n", "no\n", "nope\n"] {
        let mut bytes = input.as_bytes();
        assert!(!confirm_with(true, &mut bytes).unwrap());
    }
}

#[test]
fn proceed_without_backup_prompt_requires_an_explicit_yes() {
    for input in ["y\n", "yes\n", "Y\n", "YES\n"] {
        let mut bytes = input.as_bytes();
        assert!(
            proceed_without_backup_with(&mut bytes, crate::localization::Language::En).unwrap()
        );
    }
    for input in ["\n", "n\n", "no\n", "nope\n"] {
        let mut bytes = input.as_bytes();
        assert!(
            !proceed_without_backup_with(&mut bytes, crate::localization::Language::En).unwrap()
        );
    }
}

#[test]
fn encoded_ui_messages_have_english_diagnostic_events_without_changing_the_event() {
    let value = crate::localization::message(
        "status.operation_failed",
        &[("operation", "task.flash".into())],
    );
    let event = Event::Report(
        crate::report::Row::gui("result", "status.ready", value.clone().into()).into(),
    );
    let diagnostic = diagnostic_event(&event);
    assert!(diagnostic.contains("Flash failed"));
    assert!(diagnostic.contains("Ready"));
    assert!(!diagnostic.contains("status.operation_failed"));
    let Event::Report(report) = event else {
        unreachable!()
    };
    assert_eq!(report.gui_fields()[0].1, value);
}

#[test]
fn captured_is_true_only_inside_a_capture_scope() {
    assert!(!captured());
    assert!(capture_events(|_| {}, captured));
    assert!(!captured());
}

#[test]
fn terminal_phase_buckets_progress_by_five_percent() {
    let state = || TERMINAL_PHASE.with(|s| s.borrow().clone());
    terminal_phase("preparing", "filter.firmware", Some(50), Some(100));
    assert_eq!(
        state(),
        Some(("preparing:filter.firmware".to_string(), Some(10)))
    );
    terminal_phase("preparing", "filter.firmware", Some(100), Some(100));
    assert_eq!(state().unwrap().1, Some(20));
    terminal_phase("preparing", "filter.firmware", Some(7), Some(0));
    assert_eq!(state().unwrap().1, None);
    terminal_phase("preparing", "filter.firmware", None, None);
    assert_eq!(state().unwrap().1, None);
}

#[test]
fn show_flushes_gui_rows_before_each_cli_line() {
    use crate::report::{Report, Row};
    let report = Report {
        rows: vec![
            Row::gui("a", "A", "1".into()),
            Row::cli("b", "B", "2".into()),
            Row::gui("c", "C", "3".into()),
        ],
    };
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = seen.clone();
    capture_events(
        move |event| {
            sink.borrow_mut().push(match event {
                Event::Report(report) => format!("report:{}", report.rows.len()),
                Event::Message(_) => "message".to_string(),
                _ => "other".to_string(),
            })
        },
        || show(&report),
    );
    assert_eq!(*seen.borrow(), ["report:1", "message", "report:1"]);
    let only_cli = Report {
        rows: vec![Row::cli("b", "B", "2".into())],
    };
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = seen.clone();
    capture_events(
        move |event| {
            sink.borrow_mut().push(match event {
                Event::Report(_) => "report",
                _ => "other",
            })
        },
        || show(&only_cli),
    );
    assert_eq!(*seen.borrow(), ["other"]);
}

#[test]
fn terminal_backup_prompt_never_proceeds_without_an_interactive_answer() {
    use crate::backend::Confirm;
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return;
    }
    let error = TerminalConfirm
        .proceed_without_backup("no backup could be saved")
        .unwrap_err();
    assert_eq!(
        crate::workflow::user_error(&error).id,
        "errors.backup_confirmation_required"
    );
}
