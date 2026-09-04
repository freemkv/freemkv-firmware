//! Shared optical-drive chipset kernel — the **step-1 identity** both freemkv
//! tools agree on.
//!
//! `freemkv-fw` (modify) and `freemkv-flash` (flash) must identify a firmware
//! image's chipset family the *same* way, or the two drift. This crate is the
//! single source of that logic so they can't:
//!
//! * [`detect_chip`] — family + model/rev from image bytes, keyed on the
//!   authoritative `MTEKMT19xx` identity string (pattern-searched, not a
//!   fixed-offset read — see [`detect`] for why the banner and the `+0x50`
//!   marker are deliberately *not* family gates);
//! * [`Capability`] / [`capability_for`] — the media-class + lever-scope
//!   taxonomy the per-image "which features apply" gate consults.
//!
//! It depends only on `std` + `anyhow` (no crypto, no engine code), so it sits
//! *below* both tools in the dependency graph and breaks the fw↔flash cycle:
//! the AES-CMAC integrity engine stays in `freemkv-flash`.

mod capability;
mod detect;

pub use capability::{capability_for, Capability, MediaClass};
pub use detect::{detect_chip, ChipFamily, ChipInfo, Confidence, BANNER_OFFSET, DESCRIPTOR_OFFSET};
