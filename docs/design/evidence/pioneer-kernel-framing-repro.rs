use pioneer_optical::envelope::{decode_envelope, Layout};
fn receiver_decode(staged: &[u8]) -> Vec<u8> {
    let key = &staged[0x200..0x1200];
    staged[0x1200..0x11200].chunks_exact(4).enumerate().flat_map(|(i, word)| {
        let offset = (i * 4) % key.len();
        let k = u32::from_le_bytes(key[offset..offset+4].try_into().unwrap());
        (u32::from_le_bytes(word.try_into().unwrap()) ^ k).rotate_right(k & 31).to_le_bytes()
    }).collect()
}
fn sum(image: &[u8]) -> u32 {
    image.chunks_exact(4).fold(0u32, |s,w| s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap())))
}
fn main() {
    for path in std::env::args().skip(1) {
        let env = std::fs::read(&path).unwrap();
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.info().layout, Layout::KernelDerived);
        let mut staged = vec![0; 0x12200];
        staged[..0x1200].copy_from_slice(&env[..0x1200]);
        staged[..0x200].fill(0xa5); // Generated header bytes do not affect this decoder.
        for (dest, src, len) in [(0x1200,0x200,0x8000),(0x9200,0x8200,0x8000),(0x11200,0x10200,0x1000)] {
            staged[dest..dest+len].copy_from_slice(&env[src..src+len]);
        }
        let bad = receiver_decode(&staged);
        assert!(bad[..0x1000].iter().all(|b| *b == 0));
        assert_eq!(bad[0xfe], 0);
        let mut corrected = env[..0x200].to_vec();
        let mut state = decoded.encoding_seed().unwrap();
        for _ in 0..0x1000 {
            state = state.wrapping_mul(214013).wrapping_add(2531011) & 0xffffff;
            corrected.push((state >> 16) as u8);
        }
        corrected.extend_from_slice(&env[0x200..0x10200]);
        let good = receiver_decode(&corrected);
        assert_eq!(good, decoded.image);
        assert_eq!(sum(&good), 0);
        assert_eq!(decode_envelope(&corrected).unwrap().image, decoded.image);
        println!("{path}: old marker={:02x} old sum={:08x}; normalized marker={:02x} sum={:08x}, exact body match", bad[0xfe], sum(&bad), good[0xfe], sum(&good));
    }
}
