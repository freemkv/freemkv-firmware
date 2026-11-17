//! Literal pool and flag-seed contracts of the reverse-arithmetic stub.

use super::*;

fn has_word(bytes: &[u8], word: u32) -> bool {
    bytes.windows(4).any(|w| w == word.to_le_bytes())
}

#[test]
fn reverse_stub_embeds_every_binding_and_all_four_flag_seeds() {
    let b = ReverseBindings {
        state: 0x2000_1000,
        mode: 0x2000_1100,
        flags: 0x2000_2000,
        replay: 0x4382,
        accept: 0x1000,
        reject: 0x2000,
        divide: 0x3000,
        mode_zero: 0x4000,
        normalize: 0x5000,
    };
    let stub = reverse_stub(&b).unwrap();
    assert!(stub.len() > 64);
    for word in [
        b.state,
        b.mode,
        b.flags + crate::abi::Feature::Unrestricted as u32,
        b.divide as u32,
        b.accept as u32 | 1,
        b.reject as u32 | 1,
        b.mode_zero as u32 | 1,
        b.normalize as u32 | 1,
        0,
        0xffff_ffff,
        0x4000_0000,
        0x8000_0000,
    ] {
        assert!(has_word(&stub, word), "missing {word:#x}");
    }
}

#[test]
fn reverse_stub_refuses_unproven_bindings() {
    let ok = || ReverseBindings {
        state: 0x2000_1000,
        mode: 0x2000_1100,
        flags: 0x2000_2000,
        replay: 0x4382,
        accept: 0x1000,
        reject: 0x2000,
        divide: 0x3000,
        mode_zero: 0x4000,
        normalize: 0x5000,
    };
    let mut b = ok();
    b.replay = 0x4383;
    assert!(reverse_stub(&b).is_err());
    let mut b = ok();
    b.divide = 0x3002;
    assert!(reverse_stub(&b).is_err());
    let mut b = ok();
    b.accept = 0x1001;
    assert!(reverse_stub(&b).is_err());
    let mut b = ok();
    b.flags = u32::MAX;
    assert!(reverse_stub(&b).is_err());
}
