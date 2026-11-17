use super::*;

#[test]
fn status_line_aligns_short_and_long_labels() {
    // Colors are disabled under `cargo test` (stdout isn't a tty), so we
    // can assert on plain text layout directly.
    let short = status_line("Identity", "added", Status::Ok);
    let long = status_line("Read-through errors", "skipped", Status::Warn);
    assert!(short.starts_with("  Identity "));
    assert!(short.contains("added"));
    assert!(long.starts_with("  Read-through errors "));
    assert!(long.contains("skipped"));
}

#[test]
fn plain_when_color_disabled() {
    // color_enabled() is cached per-process and false here (no tty), so
    // painters must be pure passthrough.
    if !color_enabled() {
        assert_eq!(green("added"), "added");
        assert_eq!(amber("skipped"), "skipped");
        assert_eq!(red("failed"), "failed");
        assert_eq!(dim("0x1000"), "0x1000");
        assert_eq!(bold("freemkv-fw"), "freemkv-fw");
    }
}

#[test]
fn kv_contains_both_parts() {
    let s = kv("vendor", "HL-DT-ST");
    assert!(s.contains("vendor"));
    assert!(s.contains("HL-DT-ST"));
}

#[test]
fn printable_neutralizes_control_characters() {
    // A hostile drive/bundle string carrying an ANSI escape must not survive
    // to the terminal: ESC, CR, and other C0/C1 controls become U+FFFD.
    let hostile = "BDR-\x1b[2JUD04\r\x07";
    let safe = printable(hostile);
    assert!(!safe.contains('\x1b'));
    assert!(!safe.chars().any(|c| c.is_control()));
    // Ordinary text is untouched.
    assert_eq!(
        printable("PIONEER BD-RW BDR-UD04"),
        "PIONEER BD-RW BDR-UD04"
    );
}

fn progress_events(len: usize, steps: &[usize]) -> Vec<usize> {
    use std::{cell::RefCell, rc::Rc};
    let seen = Rc::new(RefCell::new(Vec::new()));
    let sink = seen.clone();
    crate::output::capture_events(
        move |event| {
            if let crate::output::Event::Progress { done, total, .. } = event {
                assert_eq!(total, len);
                sink.borrow_mut().push(done);
            }
        },
        || {
            let mut progress = Progress::new("reading", len);
            for &done in steps {
                progress.set(done);
            }
        },
    );
    let events = seen.borrow().clone();
    events
}

#[test]
fn progress_publishes_only_whole_percent_advances_and_every_completion() {
    let len = 2 * Progress::MIN_BYTES;
    assert_eq!(
        progress_events(
            len,
            &[0, 10_000, 20_972, 20_973, len / 2, len, len, len + 5]
        ),
        vec![0, 20_972, len / 2, len, len, len]
    );
}

#[test]
fn small_transfers_are_silent_and_the_threshold_is_inclusive() {
    assert!(progress_events(Progress::MIN_BYTES - 1, &[0, 1, Progress::MIN_BYTES - 1]).is_empty());
    assert_eq!(
        progress_events(Progress::MIN_BYTES, &[0, Progress::MIN_BYTES]),
        vec![0, Progress::MIN_BYTES]
    );
}

#[test]
fn the_prompt_glyph_is_a_dollar_sign() {
    assert!(prompt().contains('$'));
    assert!(prompt().len() <= "\x1b[1;32m$\x1b[0m".len());
}
