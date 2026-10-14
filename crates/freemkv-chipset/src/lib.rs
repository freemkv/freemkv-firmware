//! Shared optical-drive chipset kernel — the **step-1 identity** both freemkv
//! tools agree on.
//!
//! `freemkv-fw` (modify) and `freemkv-flash` (flash) must identify a firmware
//! image's chipset family the *same* way, or the two drift. Detection itself
//! lives in [`mediatek_optical::image::detect_chip`]; this crate re-exports it
//! under the names both tools use and adds the media-capability taxonomy:
//!
//! * [`detect_chip`] — family + model/rev from image bytes, decided by the boot
//!   loader banner at `0x3000`;
//! * [`Capability`] / [`capability_for`] — the media-class + lever-scope
//!   taxonomy the per-image "which features apply" gate consults.

mod capability;

pub use capability::{capability_for, Capability, MediaClass};
pub use mediatek_optical::image::{ChipError, ChipInfo};
pub use mediatek_optical::Chip as ChipFamily;

/// File offset of the boot-banner ASCII string.
pub const BANNER_OFFSET: usize = mediatek_optical::layout::BANNER.start;
/// File offset of the ASCII drive descriptor.
pub const DESCRIPTOR_OFFSET: usize = mediatek_optical::layout::DESCRIPTOR.start;

/// Detect the chip family + model/rev from `image`; see
/// [`mediatek_optical::image::detect_chip`], which holds the rationale (the chip
/// generation is decided by the boot loader banner; the `MTEKMT19xx` identity
/// tag and the `+0x50` marker are display-only).
pub fn detect_chip(image: &[u8]) -> anyhow::Result<ChipInfo> {
    Ok(mediatek_optical::image::detect_chip(image)?)
}
