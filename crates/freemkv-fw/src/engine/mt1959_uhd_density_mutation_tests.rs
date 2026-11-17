//! Flag-tag restoration and adjustment literals of the density stub.

use super::*;

fn has_word(bytes: &[u8], word: u32) -> bool {
    bytes.windows(4).any(|w| w == word.to_le_bytes())
}

fn count_seq(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn bindings(lookup_displaced: bool, adjustment: Adjustment) -> DensityBindings {
    DensityBindings {
        state: 0x2000_1000,
        flags: 0x2000_2000,
        normal_table: 0x123400,
        continuation: 0x345600,
        lookup_displaced,
        adjustment,
        incoming_nz_valid: lookup_displaced,
    }
}

fn movs_r3(value: u8) -> Vec<u8> {
    let mut a = Asm::with_target(thumb_asm::isa::Target::Thumb1);
    a.movs_imm(3, value);
    let mut bytes = a.finish().unwrap();
    bytes.truncate(2);
    bytes
}

#[test]
fn displaced_lookup_restores_each_captured_flag_combination() {
    let stub = density_stub(&bindings(true, Adjustment::None)).unwrap();
    for seed in [0u32, 0xffff_ffff, 0x4000_0000, 0x8000_0000] {
        assert!(has_word(&stub, seed), "{seed:#x}");
    }
    // Twelve captured tags, each set by one `movs r3,#tag`; tags 0 and 1 are
    // also the N-clear immediates restored for the three flag shapes.
    for tag in 0..12u8 {
        let want = if tag < 2 { 5 } else { 1 };
        assert!(
            count_seq(&stub, &movs_r3(tag)) >= want,
            "movs r3,#{tag} appears fewer than {want} times"
        );
    }
}

#[test]
fn pointer_adjustment_selects_the_carry_seed() {
    let add = density_stub(&bindings(false, Adjustment::Add)).unwrap();
    let sub = density_stub(&bindings(false, Adjustment::Sub)).unwrap();
    assert!(has_word(&sub, u32::MAX));
    assert!(!has_word(&add, u32::MAX));
}
