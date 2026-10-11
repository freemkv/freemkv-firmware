//! Backend identity and the file formats each backend owns.
//!
//! A drive family is a module under [`crate::backends`] plus one line in
//! [`registry`]. Core code identifies a backend only by the [`Descriptor`] it
//! declares; no core module names a backend module.

use std::fmt;

pub mod registry;

/// Stable protocol name of a backend (`"mtk19xx"`, `"pioneer-oem"`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BackendId(pub &'static str);

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// What a backend declares about itself.
#[derive(Debug)]
pub struct Descriptor {
    /// Stable protocol name.
    pub id: BackendId,
    /// User-facing family name (`"MediaTek MT19xx"`, `"Pioneer"`).
    pub display_name: &'static str,
    /// The `flash:` line `info` prints for a live drive, when one applies.
    pub flash_summary: Option<&'static str>,
    /// Every file format this backend reads, in recognition order.
    pub formats: &'static [FileFormat],
}

impl Descriptor {
    /// Whether `format` is one of this backend's own formats.
    pub fn owns(&self, format: &FileFormat) -> bool {
        self.formats.contains(format)
    }
}

/// How the engine treats a flash input of a given format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatRole {
    /// A firmware image written as is.
    Image,
    /// A backup archive, decoded back to an image before writing.
    Backup,
    /// A multi-component update package.
    Package,
}

/// One file format a backend owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileFormat {
    /// Stable id (`"mtk-image"`, `"pioneer-package"`).
    pub id: &'static str,
    /// User-facing wording (`"Pioneer firmware bundle"`).
    pub label: &'static str,
    /// Usual file-name endings, for pickers and help text.
    pub extensions: &'static [&'static str],
    /// How a flash treats this format.
    pub role: FormatRole,
}

/// Family name shown for a drive no backend recognizes.
pub const UNKNOWN_FAMILY: &str = "Unknown";
