//! T0 pipeline proof: recompute the MT1959 AES-CMAC integrity table over the
//! stock base image and assert every active entry matches the stored tag.
//!
//! The fixture is a real LG BU40N N1.02 (2017-12-08) stock dump. By default the
//! test uses the copy committed under `tests/fixtures/`; set
//! `FREEMKV_FIRMWARE_FIXTURE` to point at a different image.

use std::path::PathBuf;

use freemkv_flash::cmac;

fn fixture_path() -> PathBuf {
    if let Ok(p) = std::env::var("FREEMKV_FIRMWARE_FIXTURE") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/HL-DT-ST_BU40N_N1.02_2017-12-08.bin")
}

fn load_fixture() -> Vec<u8> {
    let path = fixture_path();
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()))
}

#[test]
fn stock_image_cmac_table_verifies() {
    let image = load_fixture();
    assert_eq!(image.len(), 0x200000, "stock image must be exactly 2 MB");

    let verdicts = cmac::verify_detailed(&image).expect("parse+compute CMAC table");
    assert!(
        !verdicts.is_empty(),
        "expected at least one active CMAC entry"
    );

    for v in &verdicts {
        assert!(
            v.matches,
            "entry [{}] 0x{:06x}-0x{:06x}: computed {:02x?} != stored {:02x?}",
            v.entry.index, v.entry.start, v.entry.end, v.computed, v.entry.stored
        );
    }

    // Whole-image convenience wrapper agrees.
    assert!(cmac::verify(&image), "verify() must accept the stock image");
}

#[test]
fn known_entry0_digest_matches_reference() {
    // Entry [0] covers 0x11000-0x19FFF; its stored (byte-reversed) digest is a
    // documented reference value proven against real bytes.
    let image = load_fixture();
    let table = cmac::parse_table(&image).unwrap();
    let e0 = table[0];
    assert!(e0.is_active());
    assert_eq!(e0.start, 0x0001_1000);
    assert_eq!(e0.end, 0x0001_9FFF);

    let computed = cmac::compute_stored_digest(&image, e0.start, e0.end).unwrap();
    let expected =
        hex_to_16("f93fda32e5dba3e62520ba61b176b74d").expect("valid hex reference digest");
    assert_eq!(computed, expected, "entry[0] digest must match reference");
    assert_eq!(
        e0.stored, expected,
        "entry[0] stored bytes must match reference"
    );
}

#[test]
fn resign_roundtrips_and_reverifies() {
    let image = load_fixture();
    // A pristine stock image should be unchanged by a re-sign (already valid).
    let resigned = cmac::resign(&image).expect("resign");
    assert_eq!(
        resigned, image,
        "re-signing an already-valid image must be a no-op"
    );

    // Corrupt a byte inside entry [0]'s range, then re-sign, then verify.
    let mut tampered = image.clone();
    tampered[0x11000] ^= 0xFF;
    assert!(
        !cmac::verify(&tampered),
        "tampering must break verification"
    );
    let fixed = cmac::resign(&tampered).expect("resign tampered");
    assert!(cmac::verify(&fixed), "re-signed tampered image must verify");
}

fn hex_to_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
