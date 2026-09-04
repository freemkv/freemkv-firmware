//! Chip-family + capability detection.
//!
//! This logic now lives in the shared [`freemkv_chipset`] crate so that both the
//! modify tool (this crate) and the flash tool identify a firmware image's
//! chipset the *same* way (step 1 of the two-step "detect → per-image feature
//! scope" model). This module re-exports it under the historical
//! `crate::family::…` path so existing call sites keep compiling; new code may
//! use `freemkv_chipset` directly.
//!
//! See [`freemkv_chipset::detect_chip`] for why the `MTEKMT19xx` identity string
//! (pattern-searched) is authoritative and the boot banner / `+0x50` marker are
//! display-only.

pub use freemkv_chipset::{
    capability_for, detect_chip, Capability, ChipFamily, ChipInfo, Confidence, MediaClass,
    BANNER_OFFSET, DESCRIPTOR_OFFSET,
};
