//! Standalone source-bound private U/5 identity-cache reset emitter.
//! Emission neither allocates SRAM nor installs a detour or a DI producer.
use anyhow::{ensure, Context, Result};
use mediatek_optical::image::analysis::{LegacyIdentityReset, LegacyStackDi};
use sha2::{Digest, Sha256};
use thumb_asm::{isa::decode_at, Asm};

/// Address within the existing conversion workspace; static/free-RAM checks
/// remain an integration obligation, not a guarantee provided by this helper.
pub fn marker_address(flags: u32) -> Result<u32> {
    let marker = flags
        .checked_add(super::core::UHD_IDENTITY_OFF)
        .context("identity address overflow")?;
    ensure!(
        (super::core::SRAM_LO..super::core::SRAM_END).contains(&marker),
        "identity cache outside supported SRAM"
    );
    Ok(marker)
}

/// Emit the reset detour for an immutable source-bound native initializer.
///
/// The integration must separately check the marker and guard bytes with
/// `assert_sram_cell_free`, clear it before original boot initialization, and
/// bind accepted DI producers. This function does not grant those guarantees.
/// The native source proves R1 is zero at this site on every terminating path.
/// Its existing mode clear is replayed; the private marker is a distinct byte.
pub fn reset_stub(image: &[u8], flags: u32, reset: &LegacyIdentityReset) -> Result<Vec<u8>> {
    let marker = marker_address(flags)?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(image)) == reset.caller.source_sha256(),
        "identity reset source changed"
    );
    let bound = LegacyIdentityReset::detect(image).context("identity reset source contract")?;
    ensure!(
        reset.entry == bound.entry
            && reset.site == bound.site
            && reset.original == bound.original
            && reset.continuation == bound.continuation
            && reset.mode == bound.mode
            && reset.density_class == bound.density_class
            && reset.zero_register == bound.zero_register
            && reset.zero_definition == bound.zero_definition
            && reset.store_instruction == bound.store_instruction
            && reset.literal_register == bound.literal_register
            && reset.boot_clear_required == bound.boot_clear_required
            && reset.caller == bound.caller,
        "identity reset binding changed"
    );
    let di = LegacyStackDi::detect(image).context("identity DI state role")?;
    ensure!(
        ![bound.mode, bound.density_class, di.state].contains(&marker),
        "identity cache aliases a native RAM role"
    );
    ensure!(
        bound.zero_register == 1
            && bound.literal_register == 0
            && bound.store_instruction == 0x7001
            && bound.original.len() == 4
            && bound.continuation == bound.site + 4,
        "unsupported identity reset replay"
    );
    ensure!(
        bound.continuation & 1 == 0 && u32::try_from(bound.continuation).is_ok(),
        "invalid identity continuation"
    );
    let mut a = Asm::new();
    // All instructions preserve NZCV. Source R1=0 eliminates a MOVS, and the
    // relocated mode LDR leaves R0 with precisely the original native value.
    a.ldr_lit(0, marker);
    a.strb_imm(1, 0, 0);
    a.ldr_lit(0, bound.mode);
    a.raw16(bound.store_instruction);
    // Preserve R3 and SP while branching without flag changes. The source
    // SavedLink proof permits the detour's BL to replace volatile LR.
    a.push(0x108);
    a.ldr_lit(3, bound.continuation as u32 | 1);
    a.str_sp(3, 4);
    a.pop(0x108);
    let end = a.pos();
    let bytes = a.finish()?;
    for at in (0..end).step_by(2) {
        let ins = decode_at(&bytes, at).context("identity instruction decode")?;
        ensure!(
            ins.len() == 2
                && !ins.sets_flags
                && matches!(ins.mnemonic, "ldr" | "strb" | "str" | "push" | "pop"),
            "identity reset is not flag-preserving Thumb-1 at {at:#x}"
        );
    }
    Ok(bytes)
}
