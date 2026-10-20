//! Opt-in witness for the supplied S12JX -> WX1DM startup failure.
//! This evaluates one traced prerequisite, not a full CPU/hardware emulation.
use freemkv_flash::backends::pioneer::dump::directory;

fn captured(bytes: &[u8], offset: usize, length: usize) {
    let dir = directory(bytes).unwrap().unwrap();
    let mut next = offset;
    for read in dir["reads"].as_array().unwrap() {
        let start = read["file_offset"].as_u64().unwrap() as usize;
        let received = read["received"].as_u64().unwrap() as usize;
        if read["status"] == "captured" && start <= next && next < start + received {
            next = start + received;
            if next >= offset + length {
                return;
            }
        }
    }
    panic!("range {offset:x}+{length:x} was not completely captured");
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap())
}

#[test]
#[ignore = "requires the supplied S12JX backup and held WX1DM installer package"]
fn real_packages_select_forward_and_reverse_flash_startup_settings() {
    use freemkv_flash::backends::pioneer::bundle::{Bundle, Role};
    use pioneer_optical::{envelope::Update, receiver::Receiver};
    let load = |key: &str| {
        let bytes = std::fs::read(std::env::var(key).unwrap()).unwrap();
        let bundle = Bundle::from_tar_bytes(&bytes).unwrap();
        let kernel = &bundle
            .components
            .iter()
            .find(|c| c.role == Role::Kernel)
            .unwrap()
            .bytes;
        let normal = &bundle
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap()
            .bytes;
        if let Ok(update) = Update::load(kernel, normal) {
            return update;
        }
        // Match the app's zero-signature transfer-copy preparation; never
        // treat a nonzero invalid signature as an unsigned capture.
        assert!(normal[0x170..0x1c0].iter().all(|b| *b == 0));
        use pioneer_optical::envelope::{
            builder::{normal_authentication_from_kernel, NormalAuthentication},
            signature::SigningKey,
            Envelope,
        };
        let k = Envelope::load(kernel).unwrap();
        let signer = SigningKey::random().unwrap();
        let mut signed = normal.clone();
        match normal_authentication_from_kernel(&k.image).unwrap() {
            NormalAuthentication::KeyAndCiphertext => signer.sign_normal(&mut signed).unwrap(),
            NormalAuthentication::CiphertextOnly => {
                signer.sign_normal_ciphertext_only(&mut signed).unwrap()
            }
            other => panic!("unexpected backup authentication {other:?}"),
        }
        Update::load(kernel, &signed).unwrap()
    };
    let original = load("PIONEER_STARTUP_ORIGINAL_PACKAGE");
    let wx = load("PIONEER_STARTUP_WX_PACKAGE");
    let forward = Receiver::from_installed(&original)
        .unwrap()
        .prepare(wx.clone())
        .unwrap();
    let selected = forward
        .startup_setting()
        .expect("source native A0 write surface");
    assert_eq!(
        (selected.parameter, selected.value, selected.explicit),
        (0x9f, 0xfe24, true)
    );
    let reverse = Receiver::from_installed(&wx)
        .unwrap()
        .prepare(original)
        .unwrap();
    let selected = reverse
        .startup_setting()
        .expect("WX native A0 write surface");
    assert_eq!(
        (selected.parameter, selected.value, selected.explicit),
        (0x9f, 0xffff, false)
    );
}

#[test]
#[ignore = "requires the separately supplied working PR1M 1.75 dump"]
fn working_pr1m_parameter_response_matches_the_native_record() {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("PIONEER_STARTUP_WORKING_PR1M_DUMP").unwrap()).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "c82506d3e20ef0abc99c999988162503b09a5106c95615b717aeb827ce64e575"
    );
    for (at, expected) in [
        (0x48c8ac, &[0x79, 1, 0, 0x9f, 0x5e, 0x5e, 0xff, 0x0c][..]),
        (0x48c8b4, &[0x79, 0x20, 0xff, 1][..]),
        (0x5f0e9c, &[0x79, 0x21, 0, 0x9f][..]),
        (0x5f0ea2, &[0x7a, 0, 0, 0x7f, 0, 0][..]),
        (0x5f0cce, &[0x7a, 0, 0, 0, 1, 0x40][..]),
        (0x5f0d20, &[0x7a, 0, 0, 0, 0x32, 0x50][..]),
        (0x5f0ca4, &[0x0d, 0x55, 0x46, 4, 0x19, 0, 0x40, 6][..]),
    ] {
        captured(&bytes, at, expected.len());
        assert_eq!(&bytes[at..at + expected.len()], expected, "at {at:x}");
    }
    let key = 0x7f0000;
    let unit = 0x140;
    let log_length = ((0x3250 + 2) / unit) * 2;
    captured(&bytes, key, log_length);
    let used = (0..log_length)
        .step_by(2)
        .take_while(|i| bytes[key + i] != 0xff)
        .count();
    assert_eq!(used, 3);
    let record = key + log_length + (used - 1) * unit;
    captured(&bytes, record, unit);
    let dir = directory(&bytes).unwrap().unwrap();
    let response = dir["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "parameters")
        .unwrap()["file_offset"]
        .as_u64()
        .unwrap() as usize;
    captured(&bytes, response, unit);
    for index in 0..0xa0 {
        let stored = u16::from_le_bytes(
            bytes[record + index * 2..record + index * 2 + 2]
                .try_into()
                .unwrap(),
        );
        assert_eq!(stored, be16(&bytes, response + index * 2), "word {index:x}");
    }
    assert_eq!(be16(&bytes, response + 0x13e), 0xff01);
    // This is a different supplied working capture, not the failed user's
    // post-write state. Read equivalence does not certify the A0 write path.
}

#[test]
#[ignore = "requires decoded PR1ML 1.75 Normal firmware"]
fn pr1ml_has_an_independent_persistent_startup_prerequisite() {
    use sha2::{Digest, Sha256};
    let normal = std::fs::read(std::env::var("PIONEER_STARTUP_PR1ML_NORMAL").unwrap()).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&normal)),
        "bdaae2e8f10b6c7cb399fd905d4b4281b1e0bc8195b0830711447eb678d12a2b"
    );
    let requirement = pioneer_optical::startup::discover(&normal)
        .unwrap()
        .unwrap();
    assert_eq!(
        (requirement.parameter, requirement.required),
        (0x9f, 0xff01)
    );
    assert_eq!(requirement.check_address, 0x48c964);
    let instruction = |at: usize, expected: &[u8]| {
        assert_eq!(
            &normal[at - 0x410000..at - 0x410000 + expected.len()],
            expected,
            "at {at:x}"
        );
    };
    instruction(0x412000, &[0x5a, 0x53, 0xab, 0xc6]);
    instruction(0x53acb8, &[0x5e, 0x5f, 0x4c, 0xd4]);
    instruction(0x5f4cd8, &[0x5e, 0x48, 0xc8, 0x7a]);
    instruction(
        0x48c964,
        &[
            0x79, 1, 0, 0x9f, 0x5e, 0x5f, 5, 0xa8, 0x79, 0x20, 0xff, 1, 0x47, 0x12,
        ],
    );
    instruction(
        0x48c978,
        &[
            0xf8, 1, 0x5e, 0x48, 0x2a, 0x54, 0x18, 0x88, 0x5e, 0x53, 0xac, 0xf0,
        ],
    );
    instruction(0x482a54, &[0x5e, 0x40, 0x0a, 0x1a]);
    instruction(0x53ad38, &[0x55, 0x98]);
    instruction(0x53acda, &[0x5a, 0x48, 0x2a, 0x36]);
    instruction(0x482a36, &[0x5e, 0x40, 0x0a, 4]);
    instruction(0x5f1538, &[0x79, 0x21, 0, 0x9f, 0x42, 0x18]);
    instruction(0x5f153e, &[0x7a, 0, 0, 0x7f, 0, 0]);
    // This validates the firmware path only: no PR1ML persistent dump was
    // supplied, so it deliberately makes no assertion about the live value.
}

#[test]
#[ignore = "requires the supplied original S12JX and WX1DM dumps"]
fn wx1dm_boot_parameter_rejects_the_original_s12jx_state() {
    let original = std::fs::read(std::env::var("PIONEER_STARTUP_ORIGINAL_DUMP").unwrap()).unwrap();
    let target = std::fs::read(std::env::var("PIONEER_STARTUP_TARGET_DUMP").unwrap()).unwrap();
    captured(&target, 0x410000, 0x1bb600);
    let requirement = pioneer_optical::startup::discover(&target[0x410000..0x5cb600])
        .unwrap()
        .unwrap();
    assert_eq!(
        (requirement.parameter, requirement.required),
        (0x9f, 0xfe24)
    );
    assert_eq!(requirement.check_address, 0x45faf8);
    let target_access = pioneer_optical::startup::surface::discover(&target[0x410000..0x5cb600])
        .expect("audited WX A0 native binding");
    assert_eq!(target_access.selector, 0x44ced4);
    assert_eq!(target_access.access, 0x43fd6a);
    assert_eq!(target_access.getter, requirement.getter_address);
    assert_eq!(target_access.setter, 0x54dd2c);
    let source_access = pioneer_optical::startup::surface::discover(&original[0x410000..0x5dd400])
        .expect("audited S12JX A0 native binding");
    assert_eq!(source_access.selector, 0x44be00);
    assert_eq!(source_access.access, 0x43f148);
    assert_eq!(source_access.getter, 0x551466);
    assert_eq!(source_access.setter, 0x5510f0);

    // Bind every derived constant to the traced instructions, rather than
    // calling a hand-translated parser on an unrelated firmware generation.
    let instruction = |at: usize, expected: &[u8]| {
        captured(&target, at, expected.len());
        assert_eq!(&target[at..at + expected.len()], expected, "at {at:x}");
    };
    instruction(
        0x45faf8,
        &[
            0x79, 0, 0, 0x9f, 0x5e, 0x54, 0xe0, 0xa2, 0x79, 0x20, 0xfe, 0x24, 0x47, 0x16,
        ],
    );
    instruction(
        0x45fb10,
        &[
            0xf8, 1, 0x5e, 0x45, 0x83, 0x14, 0x18, 0x88, 0x5e, 0x4a, 0xf3, 0xf6,
        ],
    );
    instruction(0x458314, &[0x5e, 0x40, 0x0a, 0x1a]);
    instruction(0x400a1a, &[0x5e, 0x40, 4, 0x7a]);
    instruction(0x400482, &[0x6a, 0x38, 0, 0, 1, 0x44, 0x67, 0x70]);
    instruction(0x4af43e, &[0x55, 0x98]); // -> 4af3d8 -> Kernel warm entry
    instruction(0x4af3e0, &[0x5a, 0x45, 0x82, 0xf6]);
    instruction(0x4582f6, &[0x5e, 0x40, 0x0a, 4]);
    instruction(0x400a04, &[0x5a, 0x40, 1, 0]);
    instruction(0x4001ac, &[0x6a, 0x30, 0, 0, 1, 0x44, 0x77, 0x70]);
    instruction(0x4001ba, &[0x5e, 0x40, 2, 0x6a]); // bit 7 -> loader
    instruction(0x400284, &[0x5a, 0x40, 0x5e, 0x1e]);
    assert_eq!(&target[0x406b4a..0x406b4e], b"0000");

    // The parameter lookup selects key 9984 for indices <= 9f, with unit
    // 0x140, area 0x1928 and a two-byte update log per slot. Its getter reads
    // the low byte first, then the high byte (54e0da..54e0ec).
    instruction(0x54ea0e, &[0x7a, 0, 0, 0, 0x99, 0x84]);
    instruction(0x54e8e8, &[0x7a, 0, 0, 0, 1, 0x40]);
    instruction(0x54e93e, &[0x7a, 0, 0, 0, 0x19, 0x28]);
    // Bulk caching also includes 9f; the mere existence of its RAM copy is
    // not evidence of another functional consumer. Verify the indexed loop
    // and the inspected three-entry consumer table against captured bytes.
    instruction(0x54e152, &[0x79, 0x10, 0, 0x60, 0x5e, 0x54, 0xe0, 0xa2]);
    instruction(0x54e178, &[0x0a, 0x0d, 0xad, 0x40, 0x45, 0xce]);
    instruction(0x595e3e, &[0x74, 0x72, 0x70]);
    // Bind the blank-bank evidence to actual captured code. This initializes
    // metadata only; it is not a whole-startup/default-value certificate.
    instruction(0x45f9cc, &[0x5e, 0x54, 0xf2, 0x5c]);
    instruction(0x54f268, &[0x7a, 5, 0xfe, 0xdc, 0x43, 0x21]);
    instruction(0x54f294, &[0x7a, 0x22, 0xff, 0xff, 0xff, 0xff]);
    instruction(0x54f2a6, &[0x0b, 0x70, 0x46, 0x2a]);
    instruction(0x54f2aa, &[0x79, 1, 0, 1]);
    instruction(0x54f2b2, &[0x79, 2, 0, 1]);
    instruction(0x54f2b8, &[0x5e, 0x54, 0xf6, 0x64]);
    instruction(0x54f2c0, &[0x7a, 0x10, 0, 0, 0xff, 0xfa]);
    instruction(0x54f2ca, &[0x79, 2, 0, 2]);
    instruction(0x54f2ce, &[0x5e, 0x54, 0xf6, 0x64, 0x40, 0x16]);
    instruction(0x54e8c2, &[0x0d, 0x55, 0x46, 4, 0x19, 0, 0x40, 6]);
    let cached_word = 0xa0add0 + 2 * (0x9f - 0x60);
    assert_eq!(cached_word, 0xa0ae4e);
    // The source generation stores this field in the same record layout.
    // This proves layout agreement, not that every field has equal semantics.
    for (at, expected) in [
        (0x551e38, [0x7a, 0, 0, 0, 0x99, 0x84]),
        (0x551d02, [0x7a, 0, 0, 0, 1, 0x40]),
        (0x551d58, [0x7a, 0, 0, 0, 0x19, 0x28]),
    ] {
        captured(&original, at, expected.len());
        assert_eq!(
            &original[at..at + expected.len()],
            &expected,
            "source at {at:x}"
        );
    }
    for (at, expected) in [
        (0x44be00, &[0xa2, 0xa0, 0x58, 0x70, 0x0d, 0x76][..]),
        (0x44cb7c, &[0xf1, 2, 0x40, 6][..]),
        (0x44cb90, &[0xf9, 1][..]),
        (0x44cb9e, &[0x5e, 0x43, 0xf1, 0x48][..]),
        (0x59de0c, &[0x80, 2, 8, 0][..]),
        (0x43f190, &[0x0f, 0xa0, 0x11, 0x30, 0x0d, 3][..]),
        (
            0x43f292,
            &[
                0x5e, 0x43, 0xec, 0xc0, 0x0d, 8, 0x0d, 0x30, 0x5e, 0x55, 0x10, 0xf0,
            ][..],
        ),
    ] {
        captured(&original, at, expected.len());
        assert_eq!(
            &original[at..at + expected.len()],
            expected,
            "source setter at {at:x}"
        );
    }
    let parameter = be16(&target, 0x45fafa) as usize;
    let required = be16(&target, 0x45fb02);
    let key = 0x9984;
    let unit = 0x140;
    let log_length = ((0x1928 + 2) / unit) * 2;

    // The original dump has valid two-bank markers; compare sequences exactly
    // as 54f7c6 does. Check coverage before using bytes (not zero fill).
    let bases = [0x5e0000, 0x5f0000];
    for base in bases {
        captured(&original, base, 0x10000);
        assert_eq!(
            &original[base + 0xfffa..base + 0xfffe],
            &[0xfe, 0xdc, 0x43, 0x21]
        );
    }
    let active = if be16(&original, bases[0] + 0xfffe) > be16(&original, bases[1] + 0xfffe) {
        bases[0]
    } else {
        bases[1]
    };
    let used = (0..log_length)
        .step_by(2)
        .take_while(|i| original[active + key + i] != 0xff)
        .count();
    assert!(used > 0, "empty log would require the factory/default path");
    let value_at = active + key + log_length + (used - 1) * unit + parameter * 2;
    let actual = u16::from_le_bytes(original[value_at..value_at + 2].try_into().unwrap());
    assert_eq!(actual, 0xffff);
    assert_eq!(required, 0xfe24);
    assert_ne!(
        actual, required,
        "mismatch takes the verified loader-return branch"
    );
    eprintln!("active bank={active:x}, parameter={parameter:x}, slot={}, address={value_at:x}, actual={actual:04x}, required={required:04x}: loader-return branch", used - 1);
    // This is the original state. The later dump cannot prove whether Normal
    // initialization or another attempt changed those persistent bytes.
}
