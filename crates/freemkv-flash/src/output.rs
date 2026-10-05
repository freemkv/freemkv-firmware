//! Scoped application output shared by terminal and graphical front-ends.

use std::cell::RefCell;
use std::fmt;
use std::io::{self, Write};

/// Presentation-independent updates from an operation.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// Diagnostic text for optional details.
    Message(String),
    /// Actual transfer counts, independent of terminal formatting.
    Progress {
        /// Operation phase.
        label: String,
        /// Bytes transferred.
        done: usize,
        /// Bytes in this phase.
        total: usize,
    },
    /// A labeled result for the information panel.
    Field {
        /// Human-readable name.
        label: String,
        /// Display value.
        value: String,
    },
}

type Sink = Box<dyn FnMut(Event)>;
thread_local! {
    static SINK: RefCell<Option<Sink>> = RefCell::new(None);
}

/// Deliver this thread's operation output to a GUI instead of process file descriptors.
/// Restores the previous destination even if the operation panics.
pub fn capture<R>(mut sink: impl FnMut(String) + 'static, operation: impl FnOnce() -> R) -> R {
    capture_events(
        move |event| match event {
            Event::Message(text) => sink(text),
            Event::Progress { label, done, total } => sink(format!(
                "{label}: {}%",
                done.saturating_mul(100) / total.max(1)
            )),
            Event::Field { .. } => {}
        },
        operation,
    )
}

/// Receive structured updates, restoring the previous sink even after a panic.
pub fn capture_events<R>(sink: impl FnMut(Event) + 'static, operation: impl FnOnce() -> R) -> R {
    struct Restore(Option<Sink>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SINK.with(|s| *s.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(SINK.with(|s| s.replace(Some(Box::new(sink)))));
    operation()
}

/// Whether the calling operation has a graphical output destination.
pub fn captured() -> bool {
    SINK.with(|s| s.borrow().is_some())
}

/// Publish a structured update; returns whether a front-end received it.
pub fn publish(event: Event) -> bool {
    crate::diagnostics::record(format!("{event:?}"));
    SINK.with(|s| {
        if let Some(sink) = s.borrow_mut().as_mut() {
            sink(event);
            true
        } else {
            false
        }
    })
}

/// Publish a result field for graphical presentation.
pub fn field(label: impl Into<String>, value: impl Into<String>) {
    publish(Event::Field {
        label: label.into(),
        value: value.into(),
    });
}

pub(crate) fn emit(args: fmt::Arguments<'_>, newline: bool, error: bool) {
    let text = args.to_string();
    crate::diagnostics::record(&text);
    let captured = SINK.with(|s| {
        if let Some(sink) = s.borrow_mut().as_mut() {
            for line in text.lines() {
                sink(Event::Message(line.to_string()));
            }
            true
        } else {
            false
        }
    });
    if !captured {
        let mut writer: Box<dyn Write> = if error {
            Box::new(io::stderr())
        } else {
            Box::new(io::stdout())
        };
        let _ = writer.write_all(text.as_bytes());
        if newline {
            let _ = writer.write_all(b"\n");
        }
        let _ = writer.flush();
    }
}

macro_rules! println {
    () => { $crate::output::emit(format_args!(""), true, false) };
    ($($arg:tt)*) => { $crate::output::emit(format_args!($($arg)*), true, false) };
}
macro_rules! eprintln {
    () => { $crate::output::emit(format_args!(""), true, true) };
    ($($arg:tt)*) => { $crate::output::emit(format_args!($($arg)*), true, true) };
}
macro_rules! print {
    ($($arg:tt)*) => { $crate::output::emit(format_args!($($arg)*), false, false) };
}
macro_rules! eprint {
    ($($arg:tt)*) => { $crate::output::emit(format_args!($($arg)*), false, true) };
}

#[cfg(test)]
mod tests {
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
}
