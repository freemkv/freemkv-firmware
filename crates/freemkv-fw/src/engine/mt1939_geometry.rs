//! Shared emission for the captured-disc geometry repair under qualification.
//! Source locators must supply every operand; these functions do not establish
//! installation safety, source applicability, integrity or physical readability.
//! The classic conversion plan installs both helpers atomically; normal engine
//! finalization owns output integrity. Physical readability remains unqualified.
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use thumb_asm::Asm;

#[path = "mt1939_geometry_locator.rs"]
mod locator;

/// Source-instruction binding. The digest prevents stale-plan application; it
/// does not select a firmware model, patch site or operand.
#[derive(Debug, Clone, Copy)]
pub struct GeometryPlan {
    source_hash: [u8; 32],
    copy_site: usize,
    geometry_site: usize,
    operands: GeometryOperands,
}

impl GeometryPlan {
    /// Source-owned operands for independent installed-helper execution tests.
    pub fn operands(&self) -> GeometryOperands {
        self.operands
    }

    pub fn inspect(image: &[u8]) -> Result<Self> {
        locator::detect(image)
    }

    /// Prepare both repairs together. The owning conversion plan must install
    /// them atomically and re-sign through its normal production workflow.
    /// Preparation alone is not source-storage or physical-read qualification.
    pub fn prepared_patches(
        &self,
        image: &[u8],
        flags: u32,
    ) -> Result<Vec<super::mt1939_uhd::UhdPatch>> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(image)) == self.source_hash,
            "geometry source changed"
        );
        ensure!(
            (0x01ff0000..0x02010000).contains(&flags),
            "geometry flag address outside RAM"
        );
        let mut patches = Vec::new();
        for (role, site, original, bytes) in [
            (
                "DiRecordLifetime",
                self.copy_site,
                vec![0x28, 0x68, 0x40, 0x22],
                emit_record_copy(&self.operands, flags)?,
            ),
            (
                "DiscGeometry",
                self.geometry_site,
                vec![0x01, 0x20, 0xf8, 0xbd],
                emit_initializer(&self.operands, flags)?,
            ),
        ] {
            ensure!(
                image.get(site..site + original.len()) == Some(original.as_slice()),
                "geometry patch preimage changed"
            );
            patches.push(super::mt1939_uhd::UhdPatch {
                role: role.into(),
                site,
                original,
                bytes,
            });
        }
        Ok(patches)
    }
}

/// Native addresses supplied by independently validated source contracts.
/// Function pointers include the Thumb bit; data addresses do not.
#[derive(Debug, Clone, Copy)]
pub struct GeometryOperands {
    pub state: u32,
    pub di: u32,
    pub translation: u32,
    pub copy_leaf: u32,
    pub word_reader: u32,
    pub bypass: u32,
    pub status: u32,
    pub descriptor: u32,
    pub last_physical: u32,
    pub layer_one_end: u32,
    pub normalize: u32,
    pub end_cell: u32,
}

fn capture_cv(a: &mut Asm, register: u16) {
    let overflow = a.label();
    let carry = a.label();
    let both = a.label();
    let done = a.label();
    a.bvs(overflow);
    a.bhs(carry);
    a.ldr_lit(register, 0);
    a.b(done);
    a.bind(carry);
    a.ldr_lit(register, 0xffff_ffff);
    a.b(done);
    a.bind(overflow);
    a.bhs(both);
    a.ldr_lit(register, 0x4000_0000);
    a.b(done);
    a.bind(both);
    a.ldr_lit(register, 0x8000_0000);
    a.bind(done);
}

fn translated(a: &mut Asm, c: &GeometryOperands) {
    a.lsls_imm(0, 0, 8);
    a.lsrs_imm(0, 0, 8);
    a.ldr_lit(3, c.translation);
    a.ldr_imm(3, 3, 0);
    a.adds_reg(0, 0, 3);
}

/// Guard actual U/5 identity; require final state/layers only after classification.
/// On success R1 is the layer count. Only R0..R3 are scratched.
fn guard(a: &mut Asm, c: &GeometryOperands, flags: u32, source: bool, no: u16) {
    a.ldr_lit(0, flags + 3);
    a.ldrb_imm(0, 0, 0);
    a.cmp_imm(0, 1);
    a.bne(no);
    if !source {
        a.ldr_lit(2, c.state);
        a.ldrb_imm(2, 2, 0);
        let media = a.label();
        a.cmp_imm(2, 0xc7);
        a.beq(media);
        a.cmp_imm(2, 0xc8);
        a.bne(no);
        a.bind(media);
    }
    if source {
        a.mov_reg(0, 4);
    } else {
        a.ldr_lit(0, c.di);
        a.ldr_imm(0, 0, 0);
    }
    translated(a, c);
    for (offset, value) in [
        (0, b'D'),
        (1, b'I'),
        (8, b'B'),
        (9, b'D'),
        (10, b'U'),
        (13, 5),
    ] {
        a.ldrb_imm(1, 0, offset);
        a.cmp_imm(1, value);
        a.bne(no);
    }
    a.ldrb_imm(1, 0, 12);
    a.lsrs_imm(1, 1, 4);
    if source {
        // Copying precedes the c.di classifier. Preserve records according to the
        // captured c.di itself, not an assumed final C7/C8 classification.
        let valid = a.label();
        a.cmp_imm(1, 2);
        a.beq(valid);
        a.cmp_imm(1, 3);
        a.bne(no);
        a.bind(valid);
        return;
    }
    let three = a.label();
    let done = a.label();
    a.cmp_imm(2, 0xc7);
    a.bne(three);
    a.cmp_imm(1, 2);
    a.bne(no);
    a.b(done);
    a.bind(three);
    a.cmp_imm(1, 3);
    a.bne(no);
    a.bind(done);
}

pub fn emit_record_copy(c: &GeometryOperands, flags: u32) -> Result<Vec<u8>> {
    let mut a = Asm::new();
    let done = a.label();
    let three = a.label();
    a.push(0x14f); // R0..R3,R6,LR: aligned through the native copy call.
    capture_cv(&mut a, 6);
    guard(&mut a, c, flags, true, done);
    a.cmp_imm(1, 3);
    a.beq(three);
    // Two-layer UHD has no third c.di record. Clear the reused slot explicitly.
    a.ldr_imm(0, 5, 0);
    a.adds_imm(0, 0xe0);
    translated(&mut a, c);
    a.movs_imm(1, 0);
    a.movs_imm(2, 64);
    let clear = a.label();
    a.bind(clear);
    a.strb_imm(1, 0, 0);
    a.adds_imm(0, 1);
    a.subs_imm(2, 1);
    a.bne(clear);
    a.b(done);
    a.bind(three);
    a.ldr_imm(0, 5, 0);
    a.adds_imm(0, 0xe0);
    a.mov_reg(1, 4);
    a.adds_imm(1, 0x80);
    a.movs_imm(2, 64);
    a.ldr_lit(3, c.copy_leaf); // This image's actual translated copy leaf.
    a.blx(3);
    a.bind(done);
    a.mov_reg(3, 6);
    a.adds_reg(3, 3, 3);
    a.pop(0x4f);
    a.ldr_imm(0, 5, 0); // Replay displaced second-copy setup.
    a.movs_imm(2, 64);
    a.pop(0x100); // Saved detour return; original worker frame remains intact.
    Ok(a.finish()?)
}

fn read_word(a: &mut Asm, c: &GeometryOperands, offset: u8) {
    a.mov_reg(0, 6);
    a.adds_imm(0, offset);
    a.ldr_lit(3, c.word_reader); // Source-owned big-endian c.di word reader.
    a.blx(3);
}

pub fn emit_initializer(c: &GeometryOperands, flags: u32) -> Result<Vec<u8>> {
    let mut a = Asm::new();
    let done = a.label();
    a.push(6); // Preserve the caller-clobbered R1/R2 too; native frame owns R3..R7.
    capture_cv(&mut a, 7);
    a.ldr_lit(0, c.bypass); // The native bypass must still bypass initialization.
    a.ldrb_imm(0, 0, 0);
    a.cmp_imm(0, 0);
    a.bne(done);
    a.ldr_lit(0, c.status);
    a.ldrb_imm(0, 0, 0);
    a.lsls_imm(0, 0, 30);
    a.bpl(done);
    guard(&mut a, c, flags, false, done);
    a.ldr_lit(5, c.descriptor);
    a.ldrb_imm(0, 5, 1);
    a.movs_imm(1, 15);
    a.ands(0, 1);
    a.adds_imm(0, 0x20);
    a.strb_imm(0, 5, 1);
    a.ldr_lit(6, c.di);
    a.ldr_imm(6, 6, 0);
    read_word(&mut a, c, 0x14);
    a.mov_reg(4, 0);
    a.ldr_lit(1, c.last_physical);
    a.str_imm(0, 1, 0);
    read_word(&mut a, c, 0x8c);
    a.adds_imm(0, 1);
    a.ldr_lit(1, c.layer_one_end);
    a.str_imm(0, 1, 0);
    a.ldr_lit(0, c.state);
    a.ldrb_imm(0, 0, 0);
    a.cmp_imm(0, 0xc7);
    let three = a.label();
    let store = a.label();
    a.bne(three);
    a.movs_imm(0, 0);
    a.b(store);
    a.bind(three);
    read_word(&mut a, c, 0xf8);
    a.lsrs_imm(0, 0, 3);
    a.bind(store);
    a.str_imm(0, 5, 12);
    a.mov_reg(0, 4);
    a.ldr_lit(3, c.normalize); // Existing dense physical-address normalization.
    a.blx(3);
    a.adds_imm(0, 1);
    a.ldr_lit(1, c.end_cell);
    a.str_imm(0, 1, 0);
    a.bind(done);
    a.mov_reg(3, 7);
    a.adds_reg(3, 3, 3);
    a.pop(6);
    a.movs_imm(0, 1);
    a.pop(0x1f8); // Replay the actual initializer's return frame.
    Ok(a.finish()?)
}
