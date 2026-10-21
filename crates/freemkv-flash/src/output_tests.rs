use super::*;
use std::sync::{Arc, Mutex};

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
        assert!(proceed_without_backup_with(&mut bytes).unwrap());
    }
    for input in ["\n", "n\n", "no\n", "nope\n"] {
        let mut bytes = input.as_bytes();
        assert!(!proceed_without_backup_with(&mut bytes).unwrap());
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
