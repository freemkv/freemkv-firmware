//! Typed report rows that both front-ends render the same way.
//!
//! The producer decides order. A row may differ per front-end through its two
//! labels: `None` hides it from that front-end, and an empty CLI label prints
//! the value as a whole line. Every drive- or file-derived string is a
//! [`Clean`], so terminal control bytes never reach either front-end.

use std::fmt;
use std::path::PathBuf;

use crate::style;

/// A drive- or file-derived string with every control character replaced.
/// Only [`Clean::new`] builds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clean(String);

impl Clean {
    /// Sanitize `text` for display (see [`style::printable`]).
    pub fn new(text: &str) -> Self {
        Self(style::printable(text))
    }

    /// The sanitized text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Clean {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the CLI paints a span; the GUI shows the text plainly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Unstyled.
    Plain,
    /// Secondary detail.
    Dim,
    /// Success.
    Ok,
    /// A caveat.
    Warn,
    /// A failure.
    Fail,
}

impl Tone {
    fn paint(self, text: &str) -> String {
        match self {
            Tone::Plain => text.to_string(),
            Tone::Dim => style::dim(text),
            Tone::Ok => style::green(text),
            Tone::Warn => style::amber(text),
            Tone::Fail => style::red(text),
        }
    }
}

/// One differently painted piece of a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    /// How the CLI paints it.
    pub tone: Tone,
    /// The text.
    pub text: Clean,
}

impl Span {
    /// A span of `text` painted `tone`.
    pub fn new(tone: Tone, text: &str) -> Self {
        Self {
            tone,
            text: Clean::new(text),
        }
    }
}

/// A row's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Drive- or file-derived text.
    Text(Clean),
    /// Text painted as a whole.
    Status(Tone, Clean),
    /// Text painted in pieces.
    Styled(Vec<Span>),
    /// A byte count.
    Size(u64),
    /// A digest or fingerprint, shown verbatim.
    Hex(String),
    /// A local path, shown with `display()`.
    Path(PathBuf),
    /// Text the tool composed (it may span lines); never drive or file data.
    Message(String),
}

impl Value {
    /// Sanitized drive or file text.
    pub fn text(text: &str) -> Self {
        Value::Text(Clean::new(text))
    }

    /// The value as the GUI shows it.
    pub fn plain(&self) -> String {
        match self {
            Value::Text(t) | Value::Status(_, t) => t.to_string(),
            Value::Styled(spans) => spans.iter().map(|s| s.text.as_str()).collect(),
            Value::Size(n) => style::human_size(*n as usize),
            Value::Hex(h) => h.clone(),
            Value::Path(p) => p.display().to_string(),
            Value::Message(m) => m.clone(),
        }
    }

    /// The value as the CLI prints it.
    pub fn cli(&self) -> String {
        match self {
            Value::Status(tone, t) => tone.paint(t.as_str()),
            Value::Styled(spans) => spans
                .iter()
                .map(|s| s.tone.paint(s.text.as_str()))
                .collect(),
            other => other.plain(),
        }
    }
}

impl From<String> for Value {
    fn from(message: String) -> Self {
        Value::Message(message)
    }
}

impl From<&str> for Value {
    fn from(message: &str) -> Self {
        Value::Message(message.to_string())
    }
}

impl From<&String> for Value {
    fn from(message: &String) -> Self {
        Value::Message(message.clone())
    }
}

impl From<PathBuf> for Value {
    fn from(path: PathBuf) -> Self {
        Value::Path(path)
    }
}

/// The GUI card a row belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// Identity and interface.
    General,
    /// Vendor identity and production details.
    Additional,
    /// Media read/write support.
    Media,
    /// DVD region state.
    Region,
    /// Drive settings.
    Settings,
    /// What the tool can do with the drive.
    Operations,
}

/// Where a backend's rows join the standard `info` rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// After the identity header, before the standard snapshot.
    AfterIdentity,
    /// After the interface rows (serial, buffer, loader, interface).
    AfterInterface,
    /// After the media rows.
    AfterMedia,
    /// After the DVD region rows.
    AfterRegion,
    /// After everything else.
    End,
}

impl Slot {
    /// Every slot, in report order.
    pub const ALL: [Slot; 5] = [
        Slot::AfterIdentity,
        Slot::AfterInterface,
        Slot::AfterMedia,
        Slot::AfterRegion,
        Slot::End,
    ];
}

/// One labelled fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Stable identifier, independent of wording.
    pub key: &'static str,
    /// The GUI label; `None` keeps the row out of the GUI.
    pub gui_label: Option<String>,
    /// The CLI label; `None` keeps the row out of the CLI, and an empty label
    /// prints the value as a whole line.
    pub cli_label: Option<String>,
    /// The value.
    pub value: Value,
    /// The GUI card.
    pub group: Group,
}

impl Row {
    /// A row both front-ends show under `label`.
    pub fn both(key: &'static str, label: &str, value: Value) -> Self {
        Self::new(key, Some(label), Some(label), value)
    }

    /// A row only the GUI shows.
    pub fn gui(key: &'static str, label: &str, value: Value) -> Self {
        Self::new(key, Some(label), None, value)
    }

    /// A row only the CLI prints, as `label: value`.
    pub fn cli(key: &'static str, label: &str, value: Value) -> Self {
        Self::new(key, None, Some(label), value)
    }

    /// A CLI-only whole line.
    pub fn line(key: &'static str, value: Value) -> Self {
        Self::new(key, None, Some(""), value)
    }

    /// A row with explicit labels.
    pub fn new(
        key: &'static str,
        gui_label: Option<&str>,
        cli_label: Option<&str>,
        value: Value,
    ) -> Self {
        Self {
            key,
            gui_label: gui_label.map(str::to_string),
            cli_label: cli_label.map(str::to_string),
            value,
            group: Group::General,
        }
    }

    /// This row in `group`.
    pub fn in_group(mut self, group: Group) -> Self {
        self.group = group;
        self
    }

    /// The CLI line, when the CLI prints this row.
    pub fn cli_line(&self) -> Option<String> {
        match self.cli_label.as_deref()? {
            "" => Some(self.value.cli()),
            label => Some(style::kv(label, &self.value.cli())),
        }
    }
}

/// An ordered set of rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The rows, in display order.
    pub rows: Vec<Row>,
}

impl Report {
    /// The `(label, value)` pairs the GUI shows, in order.
    pub fn gui_fields(&self) -> Vec<(String, String)> {
        self.rows
            .iter()
            .filter_map(|r| Some((r.gui_label.clone()?, r.value.plain())))
            .collect()
    }

    /// The lines the CLI prints, in order.
    pub fn cli_lines(&self) -> Vec<String> {
        self.rows.iter().filter_map(Row::cli_line).collect()
    }
}

impl From<Row> for Report {
    fn from(row: Row) -> Self {
        Self { rows: vec![row] }
    }
}
