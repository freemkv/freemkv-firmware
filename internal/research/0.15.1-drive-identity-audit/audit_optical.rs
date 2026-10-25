// Offline corpus adapter over the current optical crate; tab-separated output.
// Input: content hash<TAB>absolute path. No device access or firmware changes.
use std::{fs, io::{self, BufRead}};
use pioneer_optical::{envelope, image, startup};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (sha, path) = line.split_once('\t').unwrap();
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) => { println!("{sha}\tERROR\tread:{e}"); continue }
        };
        let decoded = if path.ends_with(".enc") {
            match envelope::decode_envelope(&bytes) {
                Some(d) => d.image,
                None => { println!("{sha}\tERROR\tdecode:unrecognized envelope"); continue }
            }
        } else { bytes };
        let (family, asic, board, pins, servo) = match image::family_fingerprint(&decoded) {
            Some(f) => (f.family.to_string(), f.asic, f.board, f.pins, f.servo),
            None => ("UNKNOWN".into(), "".into(), "".into(), "".into(), "".into())
        };
        let requirement = match startup::discover(&decoded) {
            Ok(Some(r)) => format!("explicit:{:04x}:{:04x}", r.parameter, r.required),
            Ok(None) => "unrecognized".into(),
            Err(_) => "ambiguous".into(),
        };
        let native = startup::surface::discover(&decoded).is_some();
        println!("{sha}\t{family}\t{asic}\t{board}\t{pins}\t{servo}\t{requirement}\t{native}");
    }
}
