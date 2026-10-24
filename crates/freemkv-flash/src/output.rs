//! Scoped application output shared by terminal and graphical front-ends.

pub use pioneer_optical::settings as device_settings;

use std::cell::RefCell;
use std::fmt;
use std::io::{self, Write};

/// Presentation-independent updates from an operation.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// Protocol-neutral work or waiting; absent counts mean no measurable percentage.
    Phase {
        /// Stable phase name used by every backend and session report.
        phase: &'static str,
        /// Localizable region label, independent of protocol details.
        component: &'static str,
        /// Completed bytes, when measurable.
        done: Option<usize>,
        /// Total bytes, when measurable.
        total: Option<usize>,
    },
    /// Normalized settings from the selected Pioneer protocol codec.
    DeviceSettings(device_settings::Settings),
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
    /// Result rows for the information panel; the GUI shows the rows that
    /// have a GUI label.
    Report(crate::report::Report),
}

type Sink = Box<dyn FnMut(Event)>;
thread_local! {
    static SINK: RefCell<Option<Sink>> = RefCell::new(None);
    static TERMINAL_PHASE: RefCell<Option<(String, Option<usize>)>> = const { RefCell::new(None) };
}

/// Deliver this thread's operation output to a GUI instead of process file descriptors.
/// Restores the previous destination even if the operation panics.
pub fn capture<R>(mut sink: impl FnMut(String) + 'static, operation: impl FnOnce() -> R) -> R {
    capture_events(
        move |event| match event {
            Event::Phase {
                phase,
                component,
                done,
                total,
            } => sink(format!("{phase} {component}: {done:?}/{total:?}")),
            Event::Message(text) => sink(text),
            Event::Progress { label, done, total } => sink(format!(
                "{label}: {}%",
                done.saturating_mul(100) / total.max(1)
            )),
            Event::Report(_) | Event::DeviceSettings(_) => {}
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
    crate::diagnostics::record(diagnostic_event(&event));
    SINK.with(|s| {
        if let Some(sink) = s.borrow_mut().as_mut() {
            sink(event);
            true
        } else {
            if let Event::Phase {
                phase,
                component,
                done,
                total,
            } = event
            {
                terminal_phase(phase, component, done, total);
            }
            false
        }
    })
}

fn terminal_phase(phase: &str, component: &str, done: Option<usize>, total: Option<usize>) {
    let percent = done
        .zip(total)
        .filter(|(_, total)| *total > 0)
        .map(|(done, total)| {
            done.saturating_mul(100)
                .checked_div(total)
                .unwrap_or(0)
                .min(100)
        });
    let key = format!("{phase}:{component}");
    let changed = TERMINAL_PHASE.with(|state| {
        let mut state = state.borrow_mut();
        let bucket = percent.map(|p| p / 5);
        if state
            .as_ref()
            .is_some_and(|old| old.0 == key && old.1 == bucket)
        {
            return false;
        }
        *state = Some((key, bucket));
        true
    });
    if changed {
        let language = crate::localization::Preferences::user().load();
        let label = crate::localization::message(
            &format!("phase.{phase}"),
            &[("component", component.to_owned())],
        );
        let label = crate::localization::render(language, &label);
        let mut stderr = io::stderr().lock();
        if let Some(percent) = percent {
            let _ = writeln!(stderr, "{label}: {percent}%");
        } else {
            let _ = writeln!(stderr, "{label}");
        }
    }
}

/// Present a catalog warning without exposing its technical diagnostic cause.
pub fn guidance(id: &'static str) {
    if !publish(Event::Message(id.into())) {
        let language = crate::localization::Preferences::user().load();
        let _ = writeln!(
            io::stderr().lock(),
            "{}",
            crate::localization::render(language, id)
        );
    }
}

// Resolve presentation messages for logs without changing what reaches the GUI.
fn diagnostic_event(event: &Event) -> String {
    let mut diagnostic = event.clone();
    match &mut diagnostic {
        Event::Message(text) | Event::Progress { label: text, .. } => {
            *text = crate::localization::english(text)
        }
        Event::Report(report) => {
            for row in &mut report.rows {
                if let Some(label) = &mut row.gui_label {
                    *label = crate::localization::english(label);
                }
                if let crate::report::Value::Message(message) = &mut row.value {
                    *message = crate::localization::english(message);
                }
            }
        }
        Event::DeviceSettings(_) | Event::Phase { .. } => {}
    }
    format!("{diagnostic:?}")
}

/// Publish one GUI-only result row.
pub fn field(label: impl AsRef<str>, value: impl Into<crate::report::Value>) {
    let row = crate::report::Row::gui("field", label.as_ref(), value.into());
    publish(Event::Report(row.into()));
}

/// Emit text to the active diagnostic log and GUI sink or terminal stream.
pub fn emit(args: fmt::Arguments<'_>, newline: bool, error: bool) {
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

/// Render a report: GUI rows go to the front-end as [`Event::Report`]s and
/// CLI rows are printed, interleaved in row order.
pub fn show(report: &crate::report::Report) {
    let mut gui = crate::report::Report::default();
    for row in &report.rows {
        if row.gui_label.is_some() {
            gui.rows.push(row.clone());
        }
        if let Some(line) = row.cli_line() {
            if !gui.rows.is_empty() {
                publish(Event::Report(std::mem::take(&mut gui)));
            }
            println!("{line}");
        }
    }
    if !gui.rows.is_empty() {
        publish(Event::Report(gui));
    }
}

/// The CLI's confirmation. On a terminal, require `y`/`yes`; when stdin is
/// not a terminal the `--execute`/`--i-understand-risk` flags already are the
/// consent, so proceed and say so.
pub struct TerminalConfirm;

impl crate::backend::Confirm for TerminalConfirm {
    fn confirm(&mut self, _plan: &crate::backend::AuthorizedPlan) -> anyhow::Result<bool> {
        use std::io::IsTerminal;
        let is_tty = std::io::stdin().is_terminal();
        confirm_with(is_tty, &mut std::io::stdin().lock())
    }

    fn proceed_without_backup(&mut self, reason: &str) -> anyhow::Result<bool> {
        use std::io::IsTerminal;
        confirm_backup_with(
            reason,
            std::io::stdin().is_terminal(),
            &mut std::io::stdin().lock(),
            crate::localization::Preferences::user().load(),
        )
    }
}

/// Render the backup refusal at the terminal boundary, preserving explicit consent.
pub(crate) fn confirm_backup_with(
    reason: &str,
    is_tty: bool,
    reader: &mut impl io::BufRead,
    language: crate::localization::Language,
) -> anyhow::Result<bool> {
    println!(
        "{}",
        crate::style::amber(&crate::localization::render(language, reason))
    );
    // Without an interactive answer, never auto-proceed without the backup.
    if !is_tty {
        return Err(
            anyhow::Error::new(crate::user_error::IssueCode::BackupConfirmationRequired)
                .context(crate::user_error::NoFirmwareWrite),
        );
    }
    proceed_without_backup_with(reader, language)
}

/// The backup question with its input and language supplied by the caller.
pub(crate) fn proceed_without_backup_with(
    reader: &mut impl io::BufRead,
    language: crate::localization::Language,
) -> anyhow::Result<bool> {
    print!(
        "{} [y/N] ",
        crate::localization::get(language, "backup.proceed")
    );
    let _ = io::stdout().flush();
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// [`TerminalConfirm`] with the terminal check and input injected.
pub(crate) fn confirm_with(is_tty: bool, reader: &mut impl io::BufRead) -> anyhow::Result<bool> {
    if !is_tty {
        println!(
            "{}",
            crate::style::dim(
                "stdin is not a TTY; proceeding on the --execute / --i-understand-risk consent."
            )
        );
        return Ok(true);
    }
    print!("Proceed? [y/N] ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
