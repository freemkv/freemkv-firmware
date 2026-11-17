//! Guard, footprint and fill-coverage contracts of the SRAM placement policy.

use super::*;

const BU40N: &[u8] = include_bytes!("../../tests/fixtures/BU40N_OEM_1.00.bin");

fn footprint() -> u32 {
    (FLASHWRITE_SCRATCH_OFF + 1).max(u32::from(NUM_FEATURES) + 1)
}

#[test]
fn free_cells_need_four_guard_bytes_inside_the_placement_range() {
    let blank = vec![0u8; 0x1000];
    let ceiling = SRAM_LO + 0x100;
    let p = SramPlacement::inspect(&blank).with_ceiling(ceiling);
    let len = 8;
    assert!(p.assert_free(SRAM_LO + 4, len, "t").is_ok());
    assert!(p.assert_free(SRAM_LO + 3, len, "t").is_err());
    assert!(p.assert_free(ceiling - 4 - len, len, "t").is_ok());
    assert!(p.assert_free(ceiling - 3 - len, len, "t").is_err());
    assert!(p.assert_free(0, len, "t").is_err());
    assert!(p.assert_free(u32::MAX - 2, len, "t").is_err());
}

#[test]
fn candidate_is_the_first_aligned_slot_with_guards_and_a_full_footprint() {
    let blank = vec![0u8; 0x1000];
    let want = (SRAM_LO + 4 + 3) & !3;
    let exact = want + footprint() + 4;
    let fits = SramPlacement::inspect(&blank).with_ceiling(exact);
    assert_eq!(fits.candidate().unwrap(), want);
    let tight = SramPlacement::inspect(&blank).with_ceiling(exact - 1);
    assert!(tight.candidate().is_err());
}

#[test]
fn candidate_on_a_real_image_avoids_every_referenced_byte() {
    let p = SramPlacement::inspect(BU40N);
    let at = p.candidate().unwrap();
    assert_eq!(at % 4, 0);
    p.assert_free(at, footprint(), "candidate").unwrap();
    let used = p.used_bytes();
    assert!((at - 4..at + footprint() + 4).all(|a| !used.contains(&a)));
}

#[test]
fn shared_fills_are_part_of_the_used_set() {
    let p = SramPlacement::inspect(BU40N);
    let used = p.used_bytes();
    for &(_, addr, len, private) in p.references.fills() {
        if len > 0 && !private {
            let lo = addr.max(SRAM_LO);
            let hi = addr.saturating_add(len).min(p.ceiling);
            assert!((lo..hi).all(|a| used.contains(&a)), "{addr:#x}+{len}");
        }
    }
}
