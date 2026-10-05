//! Envelope fingerprint for crossflash clustering. Bytes in -> one terse line.
//! Usage: fingerprint <in.enc>
use std::env;
fn main() {
    let p = env::args().nth(1).expect("usage: fingerprint <in.enc>");
    let data = std::fs::read(&p).expect("read");
    match pioneer_codec::decode_envelope(&data) {
        Some(d) => {
            let i = &d.info;
            // crc of decoded body's first + last 4 KiB = cheap layout/geometry fp
            let img = &d.image;
            let head = &img[..img.len().min(0x1000)];
            let tail = &img[img.len().saturating_sub(0x1000)..];
            let mut h: u64 = 1469598103934665603;
            for b in head.iter().chain(tail.iter()) {
                h ^= *b as u64;
                h = h.wrapping_mul(1099511628211);
            }
            println!(
                "model={} rev={} type={} layout={} psize={} dsize={:?} w0x10={:?} len={} fp={:016x}",
                i.model, i.revision, i.file_type, i.layout, i.payload_size,
                i.declared_size, i.unknown_word_0x10, img.len(), h
            );
        }
        None => println!("DECODE_FAILED"),
    }
}
