//! Candidate placement, emission and padding contracts of the classic UHD plan.

use super::*;
use mediatek_optical::classify::analysis as an;

const CLASSIC: &[u8] = include_bytes!("../../tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin");
const FLAGS: u32 = 0x0200_f000;

fn has_word(bytes: &[u8], word: u32) -> bool {
    bytes.windows(4).any(|w| w == word.to_le_bytes())
}

fn count_seq(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

#[test]
fn verify_checks_the_displaced_span_padding() {
    let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
    let patches = plan.prepared_patches(CLASSIC, FLAGS).unwrap();
    let mut output = CLASSIC.to_vec();
    plan.apply(CLASSIC, &mut output, FLAGS).unwrap();
    let mut checked = 0;
    for p in patches.iter().filter(|p| p.original.len() > 4) {
        for at in [p.site + 4, p.site + p.original.len() - 2] {
            let mut bad = output.clone();
            bad[at] ^= 1;
            assert!(plan.verify(CLASSIC, &bad, FLAGS).is_err(), "{}", p.role);
        }
        checked += 1;
    }
    assert!(checked > 0);
}

#[test]
fn classic_lineage_is_reported() {
    let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
    assert!(plan.uses_classic_application());
}

#[test]
fn routing_candidates_start_at_their_contract_and_end_at_the_calculation_join() {
    let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
    for c in plan.routing_candidates(CLASSIC, FLAGS).unwrap() {
        let contract = plan.areas().area(c.area).unwrap();
        assert_eq!(c.region_start, contract.site());
        assert_eq!(
            c.calculation_end,
            contract.coefficient_continuation().map(|pc| pc + 2)
        );
    }
}

#[test]
fn completion_candidates_use_their_own_regions() {
    let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
    let contract = an::ClassicReadCompletion::inspect(CLASSIC, plan.state).unwrap();
    let got = plan.completion_candidates(CLASSIC, FLAGS).unwrap();
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].region_start, contract.controller_region);
    assert_eq!(got[1].region_start, contract.controller_region);
    assert_eq!(got[2].region_start, contract.boundary_region);
    for (k, c) in got.iter().enumerate() {
        assert_eq!(c.site, contract.selections[k].site());
        assert_eq!(c.caller.entry(), contract.callers[k].entry());
    }
}

#[test]
fn position_candidates_bind_entry_relative_regions_and_callers() {
    let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
    let pos = an::ClassicPosition::detect(CLASSIC, plan.state).unwrap();
    let got = plan.position_candidates(CLASSIC, FLAGS).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].region_start, pos.entry + 2);
    assert_eq!(got[1].region_start, pos.output.site() - 2);
    assert_eq!(got[0].caller.entry(), pos.callers[0].entry());
    assert_eq!(got[1].caller.entry(), pos.callers[1].entry());

    let setup = an::ClassicPositionSetup::detect(CLASSIC, plan.state).unwrap();
    let got = plan.position_setup_candidates(CLASSIC, FLAGS).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].region_start, setup.entry + 6);
    assert_eq!(got[1].region_start, setup.entry + 118);
    assert_eq!(got[0].caller.entry(), setup.callers[0].entry());
    assert_eq!(got[1].caller.entry(), setup.callers[1].entry());
}

#[test]
fn read_position_ranges_are_ordered_upper_then_lower() {
    let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
    let (decode, ranges) = plan.read_position_candidates(CLASSIC, FLAGS).unwrap();
    assert_eq!(ranges.len(), decode.contract.ranges.len());
    assert!(ranges.len() >= 2);
    assert!(matches!(ranges[0].area, PositionRole::ReadUpperRange));
    assert!(matches!(ranges[1].area, PositionRole::ReadLowerRange));
    assert_eq!(ranges[0].region_start, ranges[0].site - 6);
    assert_eq!(ranges[1].region_start, ranges[1].site - 2);
    for (k, r) in ranges.iter().enumerate() {
        assert_eq!(r.caller.entry(), decode.contract.callers[k + 1].entry());
    }
    assert!(has_word(
        &decode.bytes,
        decode.contract.decode.accept() as u32 | 1
    ));
    assert!(has_word(
        &decode.bytes,
        decode.contract.decode.reject() as u32 | 1
    ));
}

#[test]
fn parameter_and_calibration_candidates_follow_their_contracts() {
    let plan = UhdConversionPlan::inspect(CLASSIC).unwrap();
    let param = plan.parameter_candidate(CLASSIC, FLAGS).unwrap();
    if let Some(hook) = &param.hook {
        assert_eq!(hook.region_start, param.contract.entry + 2);
    }
    let contract = an::ClassicCalibration::detect(CLASSIC, plan.state).unwrap();
    let cal = plan.calibration_candidate(CLASSIC, FLAGS).unwrap();
    assert_eq!(cal.is_some(), contract.c7_coefficients.is_some());
    if let Some(c) = cal {
        assert_eq!(c.original.len(), 6);
        assert!(has_word(&c.bytes, (contract.site + 6) as u32 | 1));
        assert!(has_word(&c.bytes, contract.original_base));
    }
}

#[test]
fn tail_embeds_a_thumb_tagged_target() {
    let mut a = Asm::with_target(thumb_asm::isa::Target::Thumb1);
    tail(&mut a, 0x1_0101);
    assert!(has_word(&a.finish().unwrap(), 0x1_0101));
}

#[test]
fn c7_selection_saves_carry_and_overflow_only_for_bic_replays() {
    let state = 0x0200_0f00;
    let bic = emit_c7_selection(state, FLAGS, &[0x4382], 0x1_0101, 0x1_0203).unwrap();
    let plain = emit_c7_selection(state, FLAGS, &[0x2000], 0x1_0101, 0x1_0203).unwrap();
    assert!(bic.len() > plain.len());
    for stub in [&bic, &plain] {
        for word in [0x1_0101, 0x1_0203, state, FLAGS + 3] {
            assert!(has_word(stub, word), "{word:#x}");
        }
    }
    for seed in [0u32, 0xffff_ffff, 0x4000_0000, 0x8000_0000] {
        assert!(has_word(&bic, seed), "{seed:#x}");
    }
    assert!(!has_word(&plain, 0x4000_0000));
    assert!(!has_word(&plain, 0x8000_0000));
    let moved =
        emit_c7_selection_relocated(state, FLAGS, &[0x2000], 0x1_0101, 0x1_0203, Some((1, 0x77)))
            .unwrap();
    assert!(has_word(&moved, 0x77));
    assert!(!has_word(&plain, 0x77));
}

#[test]
fn format_one_detection_drops_the_format_five_check() {
    let base = di_prevalidation_candidate(CLASSIC, FLAGS).unwrap();
    let detection = di_detection_candidate(CLASSIC, FLAGS).unwrap();
    let probe = {
        let mut a = Asm::with_target(thumb_asm::isa::Target::Thumb1);
        a.ldrb_imm(0, 3, 19);
        a.finish().unwrap()
    };
    assert!(count_seq(&base.bytes, &probe) > count_seq(&detection.bytes, &probe));
}
