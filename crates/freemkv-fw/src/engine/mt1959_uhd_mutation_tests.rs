//! Emission, padding and diagnostic contracts of the MT1959 UHD conversion.

use super::*;

const FLAGS: u32 = crate::engine::core::FLAG_TABLE_BASE;
const OLDER: &[u8] =
    include_bytes!("../../tests/fixtures/BP50NB40_NB50_1.02_unmodified_backup.bin");
const NATIVE: &[u8] = include_bytes!("../../tests/fixtures/BU40N_OEM_1.05.bin");

fn has_word(bytes: &[u8], word: u32) -> bool {
    bytes.windows(4).any(|w| w == word.to_le_bytes())
}

fn count_seq(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn enc(f: impl FnOnce(&mut Asm)) -> Vec<u8> {
    let mut a = Asm::with_target(thumb_asm::isa::Target::Thumb1);
    f(&mut a);
    let mut bytes = a.finish().unwrap();
    bytes.truncate(2);
    bytes
}

fn raw_t1(halfword: u16) -> Result<Vec<u8>> {
    let mut a = Asm::with_target(thumb_asm::isa::Target::Thumb1);
    a.raw16_unchecked(halfword);
    finish_t1(a)
}

#[test]
fn older_conversion_plan_exposes_every_bound_contract() {
    let plan = Plan::inspect(OLDER, FLAGS).unwrap();
    assert!(!plan.gaps().is_empty());
    assert!(plan.pending().is_empty());
    assert!(!plan.candidates().is_empty());
    assert!(plan.reverse_arithmetic().is_some());
    assert!(plan.density_target().is_some());
    assert!(plan.disc_information_mode().is_some());
    assert!(plan.identity_reset().is_some());
    for c in plan.candidates() {
        assert_eq!(&OLDER[c.site..c.site + c.original.len()], &c.original[..]);
        assert!(!c.bytes.is_empty());
    }
}

#[test]
fn thumb1_filter_accepts_only_sixteen_bit_armv5_encodings() {
    for ok in [0x2000u16, 0xb000, 0xb080, 0xb4f0, 0xd100, 0xdd00, 0xe7ff] {
        assert!(raw_t1(ok).is_ok(), "{ok:#x}");
    }
    for bad in [0xe800u16, 0xde00, 0xdf00, 0xb100, 0xbf08, 0xba00] {
        assert!(raw_t1(bad).is_err(), "{bad:#x}");
    }
}

#[test]
fn tail_embeds_a_thumb_tagged_target() {
    let mut a = Asm::with_target(thumb_asm::isa::Target::Thumb1);
    tail(&mut a, 0x1_0101);
    assert!(has_word(&a.finish().unwrap(), 0x1_0101));
}

#[test]
fn native_branch_helpers_follow_only_the_requested_condition() {
    let mut img = vec![0u8; 32];
    img[0..2].copy_from_slice(&0xD102u16.to_le_bytes());
    img[8..10].copy_from_slice(&0x46C0u16.to_le_bytes());
    assert_eq!(conditional_target(&img, 0, Cond::Ne).unwrap(), 8);
    assert!(conditional_target(&img, 0, Cond::Eq).is_err());
    assert_eq!(follow_taken_bne(&img, 0).unwrap(), 8);
    assert_eq!(follow_taken_bne(&img, 8).unwrap(), 8);

    let mut plain = vec![0u8; 32];
    plain[0..2].copy_from_slice(&0xE002u16.to_le_bytes());
    assert_eq!(follow_taken_bne(&plain, 0).unwrap(), 0);

    let mut cycle = vec![0u8; 32];
    cycle[0..2].copy_from_slice(&0xD1FEu16.to_le_bytes());
    assert!(follow_taken_bne(&cycle, 0).is_err());
}

#[test]
fn selection_stub_saves_carry_and_overflow_only_for_bic_replays() {
    let bic = selection_stub(0x0200_0f00, FLAGS, &[0x4382], 0x1_0101, 0x1_0203, 0x1_0305).unwrap();
    let plain =
        selection_stub(0x0200_0f00, FLAGS, &[0x2000], 0x1_0101, 0x1_0203, 0x1_0305).unwrap();
    assert!(bic.len() > plain.len());
    for stub in [&bic, &plain] {
        for word in [0x1_0101, 0x1_0203, 0x1_0305, 0x0200_0f00] {
            assert!(has_word(stub, word), "{word:#x}");
        }
        assert!(has_word(
            stub,
            FLAGS + crate::abi::Feature::Unrestricted as u32
        ));
    }
    for seed in [0u32, 0xffff_ffff, 0x4000_0000, 0x8000_0000] {
        assert!(has_word(&bic, seed), "{seed:#x}");
    }
    assert!(!has_word(&plain, 0x4000_0000));
    assert!(!has_word(&plain, 0x8000_0000));
}

#[test]
fn legacy_di_candidates_bind_this_images_stack_layout() {
    let di = LegacyStackDi::detect(OLDER).unwrap();
    let marker = FLAGS + crate::engine::core::UHD_IDENTITY_OFF;
    let with = di_candidates(OLDER, FLAGS, &di, Some(marker)).unwrap();
    let without = di_candidates(OLDER, FLAGS, &di, None).unwrap();
    assert_eq!(with.len(), 2);
    assert_eq!(without.len(), 2);
    let io = u16::from(di.identifier_offset);
    for (k, c) in with.iter().enumerate() {
        let layers = k == 1;
        let site = if layers { di.layers } else { di.prevalidation };
        assert_eq!(c.site, site);
        assert!(has_word(
            &c.bytes,
            FLAGS + crate::abi::Feature::Unrestricted as u32
        ));
        assert!(has_word(&c.bytes, (site + 8) as u32 | 1));
        assert!(has_word(&c.bytes, marker));
        for off in [1u16, 2, 3] {
            let want = enc(|a| {
                a.ldrb_imm(0, 3, io + off);
            });
            let expected = if layers && off == 2 { 2 } else { 1 };
            assert_eq!(count_seq(&c.bytes, &want), expected, "{layers} +{off}");
        }
    }
    let grew = |k: usize| with[k].bytes.len() - without[k].bytes.len();
    assert!(grew(0) > grew(1), "only the primary hook clears the marker");
}

#[test]
fn verify_checks_the_displaced_span_padding() {
    let mut plan = Plan::inspect(NATIVE, FLAGS).unwrap();
    let site = 0x80000;
    let stub_at = 0x1f_f000;
    let bytes = vec![0x70, 0x47, 0xc0, 0x46];
    plan.candidates.push(Candidate {
        gap: Gap::ControlBit,
        site,
        original: NATIVE[site..site + 8].to_vec(),
        bytes: bytes.clone(),
    });
    let mut out = NATIVE.to_vec();
    out[stub_at..stub_at + bytes.len()].copy_from_slice(&bytes);
    let bl = thumb_asm::encode_bl(site, stub_at as u32).unwrap();
    out[site..site + 4].copy_from_slice(&bl);
    out[site + 4..site + 8].copy_from_slice(&[0xc0, 0x46, 0xc0, 0x46]);
    plan.verify(&out).unwrap();
    for at in [site + 4, site + 6] {
        let mut bad = out.clone();
        bad[at] ^= 1;
        assert!(plan.verify(&bad).is_err(), "{at:#x}");
    }
}

#[test]
fn authentication_diagnostics_mirror_the_key_path_of_each_fixture() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let img = std::fs::read(&path).unwrap();
        let Ok(plan) = Plan::inspect(&img, FLAGS) else {
            continue;
        };
        let plan = plan.with_authentication_diagnostics(&img);
        match UhdKeyPath::inspect(&img) {
            Ok(keys) => {
                let mut want = Vec::new();
                if !keys.report.legacy_selectors.is_empty()
                    || !keys.send.legacy_selectors.is_empty()
                {
                    want.push(Gap::KeyRouting);
                }
                if keys.mode.is_none() || keys.certificate.is_none() {
                    want.push(Gap::ExtendedAuthentication);
                }
                assert_eq!(
                    plan.authentication_differences(),
                    want.as_slice(),
                    "{path:?}"
                );
                assert!(plan.authentication_diagnostic_error().is_none());
            }
            Err(_) => assert!(plan.authentication_diagnostic_error().is_some()),
        }
        seen += 1;
    }
    assert!(seen > 0);
}
