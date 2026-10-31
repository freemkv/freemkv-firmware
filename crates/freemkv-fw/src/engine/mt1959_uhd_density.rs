//! Standalone source-bound density target emitter; it installs no patch.
use anyhow::{ensure, Result};
use mediatek_optical::image::analysis::SLIM_UHD_DENSITY_TARGETS;
use thumb_asm::Asm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Adjustment {
    Add,
    Sub,
    None,
}

/// All bindings must be derived from the same unmodified source image.
pub(super) struct DensityBindings {
    pub state: u32,
    pub flags: u32,
    pub normal_table: usize,
    pub continuation: usize,
    pub lookup_displaced: bool,
    pub adjustment: Adjustment,
    /// Source analysis proves that incoming N and Z cannot both be set.
    pub incoming_nz_valid: bool,
}

/// The emitted stub must be placed on a four-byte boundary: ADR addresses its
/// embedded table relative to the aligned Thumb PC.
pub(super) fn density_stub(b: &DensityBindings) -> Result<Vec<u8>> {
    ensure!(
        b.normal_table > 0 && b.normal_table < 0x8000_0000 && b.normal_table & 1 == 0,
        "invalid native table address"
    );
    ensure!(
        b.continuation <= u32::MAX as usize && b.continuation & 1 == 0,
        "invalid continuation"
    );
    ensure!(
        b.flags
            .checked_add(crate::abi::Feature::Unrestricted as u32)
            .is_some(),
        "flags address overflow"
    );
    ensure!(
        if b.lookup_displaced {
            b.adjustment == Adjustment::None && b.incoming_nz_valid
        } else {
            b.adjustment != Adjustment::None
        },
        "unproven displaced instruction flags"
    );
    let mut a = Asm::new();
    let table = a.data_blob(
        SLIM_UHD_DENSITY_TARGETS
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect(),
    );
    a.push(0x0e); // r1-r3; push and branches preserve NZCV
    let common = a.label();
    if b.lookup_displaced {
        let v = a.label();
        let c = a.label();
        let cv = a.label();
        a.bvs(v);
        a.bhs(c);
        capture_nz(&mut a, common, 0);
        a.bind(c);
        capture_nz(&mut a, common, 3);
        a.bind(v);
        a.bhs(cv);
        capture_nz(&mut a, common, 6);
        a.bind(cv);
        capture_nz(&mut a, common, 9);
    }
    a.bind(common);
    if b.lookup_displaced {
        a.push(8); // captured NZCV tag
    }
    let native = a.label();
    let high = a.label();
    let selected = a.label();
    a.ldr_lit(1, b.flags + crate::abi::Feature::Unrestricted as u32);
    a.ldrb_imm(1, 1, 0);
    a.cmp_imm(1, crate::abi::STATE_ON);
    a.bne(native);
    a.ldr_lit(1, b.state);
    a.ldrb_imm(1, 1, 0);
    a.cmp_imm(1, 0xc7);
    a.beq(high);
    a.lsrs_imm(1, 1, 2);
    a.cmp_imm(1, 0x32);
    a.bne(native);
    a.bind(high);
    a.adr(0, table);
    a.b(selected);
    a.bind(native);
    a.ldr_lit(0, b.normal_table as u32);
    a.bind(selected);
    if b.lookup_displaced {
        a.ldrh_reg(0, 0, 6);
    }
    if b.lookup_displaced {
        a.pop(8); // r3 = saved flag tag
        for tag in 0..12u8 {
            let next = a.label();
            a.cmp_imm(3, tag);
            a.bne(next);
            let seed = match tag / 3 {
                0 => 0,
                1 => 0xffff_ffff,
                2 => 0x4000_0000,
                _ => 0x8000_0000,
            };
            a.ldr_lit(3, seed);
            a.adds_reg(3, 3, 3);
            match tag % 3 {
                0 => {
                    a.movs_imm(3, 1);
                }
                1 => {
                    a.movs_imm(3, 0);
                }
                _ => {
                    a.ldr_lit(3, 0x8000_0000);
                    a.movs_reg(3, 3);
                }
            }
            a.pop(0x0e);
            tail(&mut a, b.continuation);
            a.bind(next);
        }
        // Tags are constructed locally; this cannot be reached.
        tail(&mut a, b.continuation);
    } else {
        // The source-bound pointer adjustment produces N=Z=V=0. Its
        // carry is fixed: ADD has C=0; SUB has C=1. No runtime tag is needed.
        a.ldr_lit(
            3,
            if b.adjustment == Adjustment::Add {
                0
            } else {
                u32::MAX
            },
        );
        a.adds_reg(3, 3, 3);
        a.movs_imm(3, 1); // N=Z=0, preserving the established C/V.
        a.pop(0x0e);
        tail(&mut a, b.continuation);
    }
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

fn capture_nz(a: &mut Asm, common: u16, base: u8) {
    let negative = a.label();
    let zero = a.label();
    a.bmi(negative);
    a.beq(zero);
    a.movs_imm(3, base);
    a.b(common);
    a.bind(zero);
    a.movs_imm(3, base + 1);
    a.b(common);
    a.bind(negative);
    a.movs_imm(3, base + 2);
    a.b(common);
}
fn tail(a: &mut Asm, target: usize) {
    a.push(0x108);
    a.ldr_lit(3, target as u32 | 1);
    a.str_sp(3, 4);
    a.pop(0x108);
}
