//! Minimal, dependency-free terminal styling for the `freemkv-fw` and
//! `freemkv-flash` CLIs.
//!
//! House rules:
//! * Color is only emitted when stdout is a real terminal AND `NO_COLOR` is
//!   unset — a pipe/redirect (`| cat`, `> log.txt`) or an explicit `NO_COLOR`
//!   always gets plain text, byte-for-byte the same content minus escapes.
//! * No new crate dependency: everything here is hand-rolled ANSI (SGR)
//!   escapes plus [`std::io::IsTerminal`] (stable since Rust 1.70).
//! * Semantics, not raw codes, at call sites: [`green`]/[`amber`]/[`red`] for
//!   success/warn/fail, [`dim`]/[`bold`] for secondary/primary emphasis, and
//!   [`status_line`] for the dotted-leader aligned "label ... status" rows.

use std::io::{IsTerminal, Write};
use std::sync::OnceLock;

/// A reusable byte-count progress line for a long transfer (a firmware read or
/// write), printed to stderr so it never pollutes parseable stdout. Shared by
/// backup/recover reads and the flash write path.
///
/// Throttled to whole-percent advances, so a redirected/piped stderr gets at
/// most ~100 lines while a TTY sees a single carriage-return-updated line.
/// Silent for small transfers (below [`Progress::MIN_BYTES`]).
pub struct Progress {
    label: String,
    len: usize,
    last_pct: Option<usize>,
    enabled: bool,
}

impl Progress {
    /// Transfers smaller than this print nothing (probes, headers, tiny reads).
    pub const MIN_BYTES: usize = 0x100000;

    /// Start a progress line labeled `label` (e.g. `"reading normal"`) for a
    /// transfer of `len` bytes.
    pub fn new(label: impl Into<String>, len: usize) -> Self {
        Self {
            label: label.into(),
            len,
            last_pct: None,
            enabled: len >= Self::MIN_BYTES,
        }
    }

    /// Report `done` bytes transferred. Emits a line only when the whole-percent
    /// figure advances (or at completion), and finishes the line at `done >=
    /// len`.
    pub fn set(&mut self, done: usize) {
        if !self.enabled {
            return;
        }
        let pct = done * 100 / self.len.max(1);
        if self.last_pct == Some(pct) && done < self.len {
            return;
        }
        self.last_pct = Some(pct);
        let mib = |b: usize| b as f64 / (1024.0 * 1024.0);
        if crate::output::publish(crate::output::Event::Progress {
            label: self.label.clone(),
            done: done.min(self.len),
            total: self.len,
        }) {
            return;
        }
        if !std::io::stderr().is_terminal() {
            eprintln!(
                "  {}: {:.2} / {:.2} MiB ({pct}%)",
                self.label,
                mib(done),
                mib(self.len)
            );
            return;
        }
        eprint!(
            "\r  {}: {:.2} / {:.2} MiB ({pct}%)   ",
            self.label,
            mib(done),
            mib(self.len)
        );
        let _ = std::io::stderr().flush();
        if done >= self.len {
            eprintln!();
        }
    }
}

/// Whether ANSI color output is enabled for this process.
///
/// Computed once (stdout's terminal-ness does not change mid-process) and
/// cached; honors `NO_COLOR` (<https://no-color.org>) unconditionally.
pub fn color_enabled() -> bool {
    if crate::output::captured() {
        return false;
    }
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

/// Wrap `s` in the given SGR code(s) if color is enabled; otherwise return it
/// unchanged.
fn paint(code: &str, s: &str) -> String {
    if color_enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Bold (primary emphasis: headers, labels).
pub fn bold(s: &str) -> String {
    paint("1", s)
}

/// Dim/grey (secondary detail: sub-lines, hex offsets, byte counts).
pub fn dim(s: &str) -> String {
    paint("2", s)
}

/// Whether debug tracing is on. Enabled by setting `FREEMKV_DEBUG` (any value).
pub fn trace_enabled() -> bool {
    std::env::var_os("FREEMKV_DEBUG").is_some()
}

/// Emit a debug trace to stderr when [`trace_enabled`] (the `FREEMKV_DEBUG`
/// env var is set). No-op otherwise, so it is safe to sprinkle on hot paths.
pub fn trace(msg: &str) {
    if trace_enabled() {
        eprintln!("{}", dim(&format!("[trace] {msg}")));
    }
}

/// Bold green (success: `added`, `ok`, `on`).
pub fn green(s: &str) -> String {
    paint("1;32", s)
}

/// Bold amber/yellow (warn: `skipped`, `not yet implemented`).
pub fn amber(s: &str) -> String {
    paint("1;33", s)
}

/// Bold red (error/failure).
pub fn red(s: &str) -> String {
    paint("1;31", s)
}

/// The green `$` shell-prompt glyph used in worked examples/help text.
pub fn prompt() -> String {
    green("$")
}

/// Semantic outcome of one status line or word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Success: green.
    Ok,
    /// Non-fatal caveat: amber.
    Warn,
    /// Failure: red.
    Fail,
}

impl Status {
    /// Paint `s` in this status's color.
    pub fn paint(self, s: &str) -> String {
        match self {
            Status::Ok => green(s),
            Status::Warn => amber(s),
            Status::Fail => red(s),
        }
    }
}

/// Target column (label + dotted leader) that [`status_line`] aligns to.
const LEADER_COL: usize = 26;

/// Shortest dotted leader [`status_line`] will draw, even for a label that
/// overruns [`LEADER_COL`].
const MIN_DOTS: usize = 3;

/// Render a dotted-leader status row: `  <label> <....> <status>`.
///
/// `label` and the leader are aligned so the status column lines up across a
/// block of calls with differing label lengths (see the module docs' house
/// aesthetic). The leader itself is always dimmed; `status` is painted per
/// `style`.
pub fn status_line(label: &str, status: &str, style: Status) -> String {
    let used = label.chars().count() + 1; // label + one space before the dots
    let dots = LEADER_COL.saturating_sub(used).max(MIN_DOTS);
    format!(
        "  {label} {} {}",
        dim(&".".repeat(dots)),
        style.paint(status)
    )
}

/// A bold section header line (e.g. `== flash plan ==`, the `freemkv-fw
/// <version> — detected ...` banner).
pub fn header(s: &str) -> String {
    bold(s)
}

/// A `key: value` row with the key dimmed (secondary) and the value left
/// plain (primary content) — used for info/dump fact tables.
pub fn kv(key: &str, value: &str) -> String {
    format!("{}{value}", dim(&format!("{key}: ")))
}

/// A whole line rendered dimmed (secondary detail: On/Off sub-lines, hex
/// offsets, byte counts that aren't the headline fact of the line).
pub fn dim_line(s: &str) -> String {
    dim(s)
}

/// Neutralize terminal control characters in a string that came from an
/// untrusted source — a drive's INQUIRY/identity response or a firmware
/// bundle's manifest/member names — before printing it, so a hostile device
/// or file cannot emit escape sequences to the user's terminal.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

#[cfg(test)]
#[path = "style_tests.rs"]
mod tests;
