//! Emit-time decode-back guards for Thumb-2 wide-branch install patches.
//!
//! Every detour install site in this crate writes a 4-byte Thumb-2 wide branch
//! (`BL` T1 or `B.W` T4) over an OEM instruction pair. `thumb_asm` does the
//! encode/write/decode-back; these helpers only re-flavour its typed error as
//! an `anyhow` bail carrying the lever name, so mismatches read consistently
//! with the rest of the fw's `anyhow::Result`-typed emit contract.
//!
//! The decode-back is what would have caught the 0.8.13 BL-over-tail-call bug
//! at emit time rather than on a flashed drive.

use thumb_asm::BranchKind;

/// Write the 4-byte `kind` branch at `site` reaching `target`, then decode it
/// back and confirm it does. Bails with the `lever` label on any mismatch —
/// including a displacement too far to encode.
///
/// **Pre-flight** with [`thumb_asm::can_install`] (0.11.1+): every branch we
/// install is 4 bytes wide, so a site holding a 16-bit `b` — or any 2-byte
/// instruction whose successor is 4 bytes — silently gets its trailing bytes
/// consumed as a fresh instruction, which is the class of hazard a
/// field-reported brick is made of. Refusing here turns it into an emit-time
/// bail instead. The library `install_branch` already checks displacement fits;
/// this adds the "what is currently at the site" check that displacement alone
/// cannot see.
pub fn install_branch(
    img: &mut [u8],
    site: usize,
    kind: BranchKind,
    target: u32,
    lever: &str,
) -> anyhow::Result<()> {
    thumb_asm::can_install(img, site, kind)
        .map_err(|e| anyhow::anyhow!("{lever} detour site refuses a 4-byte install: {e}"))?;
    thumb_asm::install_branch(img, site, kind, target)
        .map_err(|e| anyhow::anyhow!("{lever} detour install failed: {e}"))
}

/// Confirm the 4 bytes already at `site` decode as a `kind` branch to
/// `expected`, without writing anything.
pub fn verify_branch(
    img: &[u8],
    site: usize,
    kind: BranchKind,
    expected: u32,
    lever: &str,
) -> anyhow::Result<()> {
    thumb_asm::verify_branch(img, site, kind, expected)
        .map_err(|e| anyhow::anyhow!("{lever} detour install verification failed: {e}"))
}

/// Emit-time absence guard: the Thumb-tagged VA `forbidden` (auto-ORed with 1)
/// MUST NOT appear as a 32-bit little-endian literal anywhere in `img[start..end]`.
///
/// Proves the AACS session-rearm wrapper is never baked as a `blx` target in
/// the injected handler. Strategy A (0.9.0) removed the rearm-on-SET call after
/// an image-wide scan showed the OEM never gates that wrapper; firing it from a
/// vendor-CDB context wedges every subsequent vendor CDB when no medium is
/// loaded. A refactor that silently reintroduces it fails here instead.
pub fn assert_literal_absent(
    img: &[u8],
    start: usize,
    end: usize,
    forbidden: u32,
    lever: &str,
) -> anyhow::Result<()> {
    let want = forbidden | 1;
    let end = end.min(img.len());
    if start < end
        && img[start..end]
            .windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == want)
    {
        anyhow::bail!(
            "{lever}: forbidden literal 0x{want:08x} baked in handler at 0x{start:x}..0x{end:x}"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "install_guard_tests.rs"]
mod tests;
