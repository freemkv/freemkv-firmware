//! Exact-byte and window contracts of the classic scanner whitelist patch and
//! the classic speed selector stub.

use super::*;

fn put_hw(img: &mut [u8], off: usize, hws: &[u16]) {
    for (k, &h) in hws.iter().enumerate() {
        img[off + 2 * k..off + 2 * k + 2].copy_from_slice(&h.to_le_bytes());
    }
}

fn has_word(bytes: &[u8], word: u32) -> bool {
    bytes.windows(4).any(|w| w == word.to_le_bytes())
}

/// OEM-shaped whitelist at `base`: `cmp #0x3C; bne;` then `[ldrb; cmp; beq]` per
/// mode, every `beq` aimed at `handler` which holds the handler-call halfword.
fn plant(buf: &mut [u8], base: usize, modes: &[u8], handler: usize) {
    put_hw(buf, base, &[0x2A3C, 0xD17F]);
    let mut p = base + 4;
    for &m in modes {
        let off = (handler as i32 - (p + 4) as i32 - 4) / 2;
        put_hw(
            buf,
            p,
            &[0x786A, 0x2A00 | u16::from(m), 0xD000 | (off as u16 & 0xFF)],
        );
        p += 6;
    }
    put_hw(buf, handler, &[0x6860]);
}

/// The compressed whitelist the patch must produce, computed independently.
fn expected(start: usize, handler: usize, modes: &[u8], available: usize) -> Vec<u8> {
    let mut p = vec![0x6A, 0x78];
    for &m in modes {
        let beq_pc = start + p.len() + 2;
        let off = (handler as i32 - beq_pc as i32 - 4) / 2;
        p.extend_from_slice(&(0x2A00u16 | u16::from(m)).to_le_bytes());
        p.extend_from_slice(&(0xD000u16 | (off as u16 & 0xFF)).to_le_bytes());
    }
    while p.len() < available {
        p.extend_from_slice(&0x46C0u16.to_le_bytes());
    }
    p
}

const OEM: [u8; 5] = [0x06, 0x07, 0x0A, 0x0B, 0x0C];

fn with_knock() -> Vec<u8> {
    let mut m = OEM.to_vec();
    m.push(abi::KNOCK_MODE);
    m
}

#[test]
fn whitelist_patch_writes_the_exact_compressed_block() {
    let mut buf = vec![0u8; 0x400];
    plant(&mut buf, 0x100, &OEM, 0x126);
    let before = buf.clone();
    assert!(patch_scanner_mode_whitelist(&mut buf, 0x100).unwrap());
    let want = expected(0x104, 0x126, &with_knock(), 30);
    assert_eq!(&buf[0x104..0x104 + 30], &want[..]);
    assert_eq!(&buf[..0x104], &before[..0x104]);
    assert_eq!(&buf[0x104 + 30..], &before[0x104 + 30..]);
}

#[test]
fn whitelist_patch_handles_a_block_that_ends_the_image_with_a_backward_handler() {
    let start = 0x104;
    let mut buf = vec![0u8; start + 30];
    plant(&mut buf, 0x100, &OEM, 0x80);
    assert!(patch_scanner_mode_whitelist(&mut buf, 0x100).unwrap());
    let want = expected(start, 0x80, &with_knock(), 30);
    assert_eq!(&buf[start..], &want[..]);
}

#[test]
fn whitelist_patch_needs_room_for_the_knock_pair() {
    let mut two = vec![0u8; 0x400];
    plant(&mut two, 0x100, &[0x06, 0x07], 0x120);
    let before = two.clone();
    let e = format!(
        "{:#}",
        patch_scanner_mode_whitelist(&mut two, 0x100).unwrap_err()
    );
    assert!(e.contains("not enough space"), "{e}");
    assert_eq!(two, before);

    let mut three = vec![0u8; 0x400];
    plant(&mut three, 0x100, &[0x06, 0x07, 0x0A], 0x130);
    assert!(patch_scanner_mode_whitelist(&mut three, 0x100).unwrap());
}

#[test]
fn whitelist_search_stops_after_the_scanner_window() {
    let mut buf = vec![0u8; 0x800];
    plant(&mut buf, 0x320, &OEM, 0x346);
    let before = buf.clone();
    assert!(!patch_scanner_mode_whitelist(&mut buf, 0x100).unwrap());
    assert_eq!(buf, before);
}

#[test]
fn classic_speed_stub_embeds_its_flag_and_maximum_cells() {
    let bytes = Mt1959Engine
        .build_speed_stub_classic(0x0200_1100, 0x0200_2234)
        .unwrap();
    assert!(bytes.len() > 8);
    assert!(has_word(&bytes, 0x0200_1100 + abi::Feature::Speed as u32));
    assert!(has_word(&bytes, 0x0200_2234));
}
