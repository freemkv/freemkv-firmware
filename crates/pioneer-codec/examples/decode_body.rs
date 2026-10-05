//! Decode a Pioneer firmware envelope (.enc/.100/.114) to its raw body .bin.
//! Usage: decode_body <in.enc> <out.bin>
use std::{env, fs};
fn main() {
    let a: Vec<String> = env::args().skip(1).collect();
    let data = fs::read(&a[0]).expect("read input");
    match pioneer_codec::decode_envelope(&data) {
        Some(d) => {
            fs::write(&a[1], &d.image).expect("write body");
            eprintln!(
                "decoded {} -> {} ({} bytes) model={} rev={} type={}",
                a[0], a[1], d.image.len(), d.info.model, d.info.revision, d.info.file_type
            );
        }
        None => {
            eprintln!("DECODE FAILED (unknown/unsupported layout): {}", a[0]);
            std::process::exit(2);
        }
    }
}
