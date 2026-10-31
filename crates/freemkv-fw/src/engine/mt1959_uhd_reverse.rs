//! Standalone G05 reverse arithmetic emitter. It does not install a patch.
//! All addresses must come from a source-bound native analysis; in particular,
//! a guessed mode byte is not an acceptable input.
use anyhow::{ensure, Result};
use thumb_asm::Asm;

/// Native gate and arithmetic bindings, all addresses being image offsets except RAM addresses.
pub(super) struct ReverseBindings {
    pub state: u32,
    pub mode: u32,
    pub flags: u32,
    pub replay: u16,
    pub accept: usize,
    pub reject: usize,
    pub divide: usize,
    pub mode_zero: usize,
    pub normalize: usize,
}

/// Emit a Thumb-1 detour for the bound BICS R2,R0 / BNE gate.
/// The caller must independently establish the native saved-LR frame.
pub(super) fn reverse_stub(b: &ReverseBindings) -> Result<Vec<u8>> {
    ensure!(b.replay == 0x4382, "reverse gate is not BICS R2,R0");
    ensure!(
        b.divide & 3 == 0 && b.divide <= u32::MAX as usize,
        "invalid ARM divide target"
    );
    for target in [b.accept, b.reject, b.mode_zero, b.normalize] {
        ensure!(
            target & 1 == 0 && target <= u32::MAX as usize,
            "invalid Thumb target"
        );
    }
    ensure!(
        b.flags
            .checked_add(crate::abi::Feature::Unrestricted as u32)
            .is_some(),
        "flags address overflow"
    );
    let mut a = Asm::new();
    // BICS preserves C/V; select one of four copies before the comparisons.
    let v = a.label();
    let c = a.label();
    let cv = a.label();
    a.bvs(v);
    a.bhs(c);
    emit_case(&mut a, b, 0);
    a.bind(c);
    emit_case(&mut a, b, 0xffff_ffff);
    a.bind(v);
    a.bhs(cv);
    emit_case(&mut a, b, 0x4000_0000);
    a.bind(cv);
    emit_case(&mut a, b, 0x8000_0000);
    let end = a.pos();
    let bytes = a.finish()?;
    for at in (0..end).step_by(2) {
        let h = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let ordinary = h & 0xf800 < 0xe800;
        let stack = h & 0xf000 != 0xb000 || h & 0xff00 == 0xb000 || h & 0xf600 == 0xb400;
        let conditional = h & 0xf000 != 0xd000 || h & 0xff00 < 0xde00;
        ensure!(
            ordinary && stack && conditional,
            "non Thumb-1 instruction at {at:#x}"
        );
    }
    Ok(bytes)
}
fn tail(a: &mut Asm, target: usize) {
    a.push(0x108);
    a.ldr_lit(3, target as u32 | 1);
    a.str_sp(3, 4);
    a.pop(0x108);
}
fn emit_case(a: &mut Asm, b: &ReverseBindings, cv: u32) {
    let native = a.label();
    let reject = a.label();
    let nonzero = a.label();
    a.push(8);
    a.ldr_lit(3, b.flags + crate::abi::Feature::Unrestricted as u32);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, crate::abi::STATE_ON);
    a.bne(native);
    a.ldr_lit(3, b.state);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, 0xc7);
    a.bne(native);
    // Replay the gate for R2, then choose the existing source-bound mode.
    a.ldr_lit(3, cv);
    a.adds_reg(3, 3, 3);
    a.pop(8);
    a.raw16(b.replay);
    a.push(8);
    a.ldr_lit(3, b.mode);
    a.ldrb_imm(3, 3, 0);
    a.cmp_imm(3, 0);
    a.bne(nonzero);
    a.pop(8);
    tail(a, b.mode_zero);
    a.bind(nonzero);
    a.pop(8);
    // Native divide uses ARM interworking. The enclosing native function has
    // already saved its incoming LR, as required by the detector contract.
    a.raw16(0x8820); // ldrh r0, [r4]
    a.movs_imm(1, 10);
    a.ldr_lit(3, b.divide as u32);
    a.blx(3);
    a.lsls_imm(3, 0, 3);
    a.adds_reg(0, 3, 0);
    a.raw16(0x1a28); // subs r0, r5, r0
    tail(a, b.normalize);
    a.bind(native);
    a.ldr_lit(3, cv);
    a.adds_reg(3, 3, 3);
    a.pop(8);
    a.raw16(b.replay);
    a.bne(reject);
    tail(a, b.accept);
    a.bind(reject);
    tail(a, b.reject);
}
