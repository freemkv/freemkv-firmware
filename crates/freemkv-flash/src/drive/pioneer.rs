//! Pioneer drive family (stub).
//!
//! Classifies positive (READ_BUFFER 0xF1 succeeds) but every command that would
//! touch the drive returns an `Unsupported` error, so the MTK-gate keeps a
//! Pioneer drive safe. A real Pioneer flasher only needs to replace this with
//! its own CDBs — the generic engine loop is unchanged.

use super::Family;

/// The Pioneer drive family (classified, unsupported).
pub struct Pioneer;

crate::unsupported_drive_family!(Pioneer, Family::Pioneer);
