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

use std::io::IsTerminal;
use std::sync::OnceLock;

/// Whether ANSI color output is enabled for this process.
///
/// Computed once (stdout's terminal-ness does not change mid-process) and
/// cached; honors `NO_COLOR` (<https://no-color.org>) unconditionally.
pub fn color_enabled() -> bool {
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

#[cfg(test)]
#[path = "style_tests.rs"]
mod tests;
