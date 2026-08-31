//! HL-DT-ST / Renesas drive family — read-only DUMP support.
//!
//! Renesas / HL-DT-ST (`RENESAS` INQUIRY vendor) is the SAME silicon and
//! protocol as Pioneer here, so it shares the implementation in
//! [`super::pioneer`] via [`crate::renesas_pioneer_drive_family!`]: DUMP
//! (read-only) is supported; FLASH is not. The only write ever issued is the
//! vendor enable knock on the dump path (see [`super::pioneer`]).

use super::Family;

/// The Renesas drive family (read-only dump).
pub struct Renesas;

crate::renesas_pioneer_drive_family!(Renesas, Family::Renesas);
