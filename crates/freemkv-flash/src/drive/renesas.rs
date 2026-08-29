//! HL-DT-ST / Renesas drive family (stub).
//!
//! Classifies positive (READ_BUFFER 0xF1 succeeds, Renesas INQUIRY vendor) but
//! every command that would touch the drive returns an `Unsupported` error, so
//! the MTK-gate keeps a Renesas drive safe. A real Renesas flasher only needs to
//! replace this with its own CDBs — the generic engine loop is unchanged.

use super::Family;

/// The Renesas drive family (classified, unsupported).
pub struct Renesas;

crate::unsupported_drive_family!(Renesas, Family::Renesas);
