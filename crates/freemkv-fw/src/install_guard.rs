//! Emit-time decode-back guards for Thumb-2 wide-branch install patches.
//!
//! Every detour install site in this crate writes a 4-byte Thumb-2 wide branch
//! (`BL` T2 or `B.W` T4) over an OEM instruction pair. These helpers decode
//! the freshly-written 4 bytes with the shape-appropriate decoder from
//! `thumb_asm` and refuse to ship an image whose install doesn't decode back
//! to the intended stub VA. Would have caught the 0.8.13 BL-over-tail-call
//! bug at emit time.
//!
//! The two guards live here — not in `thumb_asm` — because they wrap the
//! generic Thumb primitives in `anyhow::bail!` so mismatches surface as
//! bail-messages next to the rest of the fw's `anyhow::Result`-typed emit
//! contract. When a framework-agnostic equivalent lands in `thumb_asm` these
//! collapse to one-liners.

use thumb_asm::{decode_b_wide, decode_bl};

/// Emit-time decode-back guard for a Thumb-2 wide `BL` install at `site` that
/// was just written into `img`. Bails with the `lever` label when the 4 bytes
/// at `site` don't decode as a `BL` targeting `expected`.
pub fn assert_bl_install(
    img: &[u8],
    site: usize,
    expected: u32,
    lever: &str,
) -> anyhow::Result<()> {
    let decoded = decode_bl(img, site);
    if decoded != Some(expected) {
        anyhow::bail!(
            "{lever} detour install verification failed: 4 bytes at 0x{site:x} decode to \
             {decoded:?}, want BL -> 0x{expected:x}"
        );
    }
    Ok(())
}

/// Emit-time decode-back guard for a Thumb-2 wide `B.W` (T4) install — same
/// contract as [`assert_bl_install`] but decodes via [`decode_b_wide`]. Used
/// at install sites where the OEM prelude ended in a tail-call `b <shared>`
/// (a `BL` install there would clobber `lr`; see `AkeInstallShape::WideB` in
/// `crate::engine::core`).
pub fn assert_b_wide_install(
    img: &[u8],
    site: usize,
    expected: u32,
    lever: &str,
) -> anyhow::Result<()> {
    let decoded = decode_b_wide(img, site);
    if decoded != Some(expected) {
        anyhow::bail!(
            "{lever} detour install verification failed: 4 bytes at 0x{site:x} decode to \
             {decoded:?}, want B.W -> 0x{expected:x}"
        );
    }
    Ok(())
}
