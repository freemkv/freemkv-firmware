//! Refusal and window contracts of the grounded MT1959 finders.

use super::*;
use crate::engine::lever::LeverOutcome;
use crate::engine::Engine;

const BU40N: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/BU40N_OEM_1.00.bin"
);

fn bu40n() -> Vec<u8> {
    std::fs::read(BU40N).expect("committed BU40N OEM fixture")
}

fn put_hw(img: &mut [u8], off: usize, hws: &[u16]) {
    for (k, &h) in hws.iter().enumerate() {
        img[off + 2 * k..off + 2 * k + 2].copy_from_slice(&h.to_le_bytes());
    }
}

fn materialize(sig: &[(u16, u16)]) -> Vec<u16> {
    sig.iter().map(|&(v, _)| v).collect()
}

fn err_text<T: std::fmt::Debug>(r: Result<T>) -> String {
    format!("{:#}", r.expect_err("must refuse"))
}

#[test]
fn find_masked_rejects_degenerate_windows_and_finds_the_first_match() {
    let mut img = [0u8; 16];
    put_hw(&mut img, 6, &[0x1234, 0x5678]);
    let sig = &[(0x1234, 0xffff), (0x5678, 0xffff)];
    assert_eq!(find_masked(&img, &[], 0, 16), None);
    assert_eq!(find_masked(&img, sig, 8, 4), None);
    assert_eq!(find_masked(&img, sig, 0, 2), None);
    assert_eq!(find_masked(&img, sig, 0, 100), Some(6));
    assert_eq!(find_masked(&img, sig, 0, 9), None);
    assert!(find_masked_all(&img, &[], 0, 16).is_empty());
    assert!(find_masked_all(&img, sig, 10, 4).is_empty());
}

#[test]
fn find_unique_names_empty_and_ambiguous_windows() {
    let sig = &[(0xBEEF, 0xffff), (0xCAFE, 0xffff)];
    let mut img = [0u8; 64];
    let empty = err_text(find_unique(&img, sig, 32, 32, "probe"));
    assert!(
        empty.contains("probe signature: empty search window"),
        "{empty}"
    );
    let clamped = err_text(find_unique(&img, sig, 80, 200, "probe"));
    assert!(clamped.contains("empty search window"), "{clamped}");
    let none = err_text(find_unique(&img, sig, 0, 64, "probe"));
    assert!(none.contains("matched 0 time(s)"), "{none}");
    put_hw(&mut img, 8, &[0xBEEF, 0xCAFE]);
    assert_eq!(find_unique(&img, sig, 0, 64, "probe").unwrap(), 8);
    put_hw(&mut img, 40, &[0xBEEF, 0xCAFE]);
    let many = err_text(find_unique(&img, sig, 0, 64, "probe"));
    assert!(many.contains("matched 2 time(s)"), "{many}");
    assert!(many.contains("first at 0x8"), "{many}");
}

#[test]
fn boot_init_convergence_requires_a_negative_branch() {
    let mut img = [0u8; 16];
    put_hw(&mut img, 4, &[0x2000, 0x2000]);
    assert_eq!(boot_init_convergence(&img, 0), None);
    assert_eq!(boot_init_convergence(&img, usize::MAX), None);
}

#[test]
fn boot_init_site_reports_either_shape() {
    assert_eq!(BootInitSite::Modern(0x13_d41a).site(), 0x13_d41a);
    assert_eq!(BootInitSite::ClassicUnconfirmed(0x1234).site(), 0x1234);
}

#[test]
fn find_boot_init_selects_one_shape_and_refuses_duplicates() {
    let modern = materialize(BOOT_INIT_SIG);
    let classic = materialize(BOOT_INIT_SIG_CLASSIC);
    let engine = Mt1959Engine;

    let mut one = vec![0u8; 0x1000];
    put_hw(&mut one, 0x100, &modern);
    assert_eq!(
        engine.find_boot_init(&one).unwrap(),
        Some(BootInitSite::Modern(0x104))
    );
    let mut two = one.clone();
    put_hw(&mut two, 0x200, &modern);
    let many = err_text(engine.find_boot_init(&two));
    assert!(
        many.contains("boot-init signature matched 2 time(s)"),
        "{many}"
    );

    let mut c1 = vec![0u8; 0x1000];
    put_hw(&mut c1, 0x300, &classic);
    assert_eq!(
        engine.find_boot_init(&c1).unwrap(),
        Some(BootInitSite::ClassicUnconfirmed(0x304))
    );
    put_hw(&mut c1, 0x400, &classic);
    let many = err_text(engine.find_boot_init(&c1));
    assert!(
        many.contains("classic boot-init signature matched 2"),
        "{many}"
    );
    assert_eq!(engine.find_boot_init(&vec![0u8; 0x1000]).unwrap(), None);
}

#[test]
fn bu40n_scanner_wrappers_resolve_the_frozen_anchors() {
    let img = bu40n();
    let engine = Mt1959Engine;
    assert_eq!(engine.sense_setter(&img).unwrap(), 0x000a_2d6a);
    assert!(engine.sense_setter(&vec![0u8; 0x1000]).is_err());

    let record = engine
        .find_live_record_in(&img, abi::READ_BUFFER_OPCODE, 0x14_0000, 0x16_0000)
        .unwrap();
    assert_eq!(record.off, 0x0014_fd74);
    assert_eq!(record.handler, 0x0009_ad5b);
    let outside = err_text(engine.find_live_record_in(&img, abi::READ_BUFFER_OPCODE, 0, 0x1000));
    assert!(
        outside.contains("outside the requested extent"),
        "{outside}"
    );
}

#[test]
fn response_commit_window_matches_the_whole_image_search() {
    let img = bu40n();
    let engine = Mt1959Engine;
    let (entry, cell) = engine.find_response_commit(&img).unwrap();
    let at = entry as usize;
    assert_eq!(
        engine.find_response_commit_in(&img, at, at + 2).unwrap(),
        (entry, cell)
    );
    let none = err_text(engine.find_response_commit_in(&img, 0, 0));
    assert!(none.contains("native response committer"), "{none}");
}

#[test]
fn region_emitter_window_is_honoured() {
    let img = bu40n();
    let engine = Mt1959Engine;
    let emitter = engine.find_region_emitter(&img).unwrap();
    let at = emitter as usize;
    let span = REGION_EMIT_SIG.len() * 2;
    assert_eq!(
        engine.find_region_emitter_in(&img, at, at + span).unwrap(),
        emitter
    );
    assert!(engine.find_region_emitter_in(&img, 0, at).is_err());
    let past = err_text(engine.find_region_emitter_in(&img, usize::MAX, usize::MAX));
    assert!(past.contains("empty search window"), "{past}");
}

#[test]
fn ake_nb_v5_gate_is_found_only_when_present() {
    let engine = Mt1959Engine;
    let mut img = vec![0u8; 0x2000];
    assert!(engine.find_ake_gate_nb_v5(&img).is_err());
    put_hw(&mut img, 0x800, &materialize(AKE_GATE_SIG_NB_V5));
    assert_eq!(engine.find_ake_gate_nb_v5(&img).unwrap(), 0x800);
}

#[test]
fn find_aacs_requires_dispatcher_deny_sense_and_auth_literal() {
    let engine = Mt1959Engine;
    let mut img = vec![0u8; 0x14_0000];
    let e = err_text(engine.find_aacs(&img));
    assert!(e.contains("format-dispatcher"), "{e}");
    put_hw(&mut img, 0xa_0000, &[0xB510, 0x79C1, 0x297F, 0xD805]);
    let e = err_text(engine.find_aacs(&img));
    assert!(e.contains("deny sense"), "{e}");
    put_hw(&mut img, 0x13_0000, &[0x2202, 0x216F, 0x2005]);
    let e = err_text(engine.find_aacs(&img));
    assert!(e.contains("auth-flag base literal"), "{e}");
    img[0x13_0010..0x13_0014].copy_from_slice(&0x0200_0c80u32.to_le_bytes());
    assert_eq!(engine.find_aacs(&img).unwrap(), (0xa_0000, 0x0200_0c82));
}

#[test]
fn flash_and_nv_finders_refuse_blank_or_ambiguous_images() {
    let engine = Mt1959Engine;
    let blank = vec![0u8; 0x4000];
    let e = err_text(engine.find_flash_program(&blank));
    assert!(e.contains("matched 0 candidate(s)"), "{e}");
    let e = err_text(engine.find_nv_dram_base_from(&blank, 0));
    assert!(e.contains("0 SRAM literal(s)"), "{e}");

    let mut nv = vec![0xFFu8; 0x8_0000];
    nv[0x4_14b0..0x4_14b3].copy_from_slice(&[0x00, 0x04, 0x05]);
    assert_eq!(engine.find_nv_block(&nv).unwrap(), 0x4_1000);
    nv[0x4_34b0..0x4_34b3].copy_from_slice(&[0x00, 0x04, 0x05]);
    let e = err_text(engine.find_nv_block(&nv));
    assert!(e.contains("matched 2 candidate(s)"), "{e}");
}

#[test]
fn aacs_session_reset_refuses_missing_duplicate_or_entryless_loops() {
    let img = bu40n();
    let engine = Mt1959Engine;
    let entry = engine.find_aacs_session_reset(&img).unwrap() as usize;
    assert_eq!(entry, 0x000c_ae18);
    let setter = engine.find_vid_gate_setter(&img).unwrap();
    let loop_at = entry + 0x24;
    assert_eq!(&img[loop_at..loop_at + 4], &[0x00, 0x21, 0x00, 0x20]);

    let mut missing = img.clone();
    missing[loop_at + 24] = 0x03;
    let e = err_text(engine.find_aacs_session_reset(&missing));
    assert!(e.contains("AGID-reset loop signature not found"), "{e}");

    let mut twice = img.clone();
    let copy = 0x1f_ff00;
    twice.copy_within(loop_at..loop_at + 28, copy);
    let bl = thumb_asm::encode_bl(copy + 14, setter).unwrap();
    twice[copy + 14..copy + 18].copy_from_slice(&bl);
    let e = err_text(engine.find_aacs_session_reset(&twice));
    assert!(e.contains("matched 2 time(s)"), "{e}");

    let mut headless = img.clone();
    headless[entry..entry + 2].fill(0);
    let e = err_text(engine.find_aacs_session_reset(&headless));
    assert!(e.contains("prologue"), "{e}");
}

#[test]
fn aacs_session_rearm_refuses_missing_or_duplicate_wrappers() {
    let img = bu40n();
    let engine = Mt1959Engine;
    let rearm = engine.find_aacs_session_rearm(&img).unwrap() as usize;
    let reset = engine.find_aacs_session_reset(&img).unwrap();

    let mut missing = img.clone();
    missing[rearm..rearm + 2].fill(0);
    let e = err_text(engine.find_aacs_session_rearm(&missing));
    assert!(e.contains("aacs_session_rearm signature not found"), "{e}");

    let mut twice = img.clone();
    let copy = 0x1f_fe00;
    twice.copy_within(rearm..rearm + 30, copy);
    let bl = thumb_asm::encode_bl(copy + 30, reset).unwrap();
    twice[copy + 30..copy + 34].copy_from_slice(&bl);
    let e = err_text(engine.find_aacs_session_rearm(&twice));
    assert!(e.contains("matched 2 time(s)"), "{e}");
}

#[test]
fn de_byte_requires_a_full_descriptor_with_the_family_tag() {
    let engine = Mt1959Engine;
    let e = err_text(engine.find_de_byte(&[0u8; 0x10]));
    assert!(e.contains("image too small"), "{e}");
    let e = err_text(engine.find_de_byte(&vec![0u8; 0x20_0000]));
    assert!(e.contains("family tag"), "{e}");
}

#[test]
fn build_handler_matches_the_create_path() {
    let img = bu40n();
    let report = Mt1959Engine.create(&img).unwrap();
    let bytes = Mt1959Engine
        .build_handler(
            &img,
            report.record.handler,
            FLAG_TABLE_BASE,
            report.boot_function_entry,
        )
        .unwrap();
    assert_eq!(bytes, report.handler_bytes);
    assert!(bytes.ends_with(&identity_blob()));
}

#[test]
fn scoped_auth_stub_bounds_the_class_and_validates_its_contract() {
    let engine = Mt1959Engine;
    let plain = engine
        .build_authcell_widen_scoped_stub(FLAG_TABLE_BASE, 0x1000, 0, None, None)
        .unwrap();
    let scoped = engine
        .build_authcell_widen_scoped_stub(FLAG_TABLE_BASE, 0x1000, 1, Some(4), Some(0x2000))
        .unwrap();
    assert!(scoped.len() > plain.len());
    assert!(scoped.windows(4).any(|w| w == 0x2001u32.to_le_bytes()));
    assert!(scoped.windows(4).any(|w| w == 0x1001u32.to_le_bytes()));
    assert!(engine
        .build_authcell_widen_scoped_stub(FLAG_TABLE_BASE, 0x1000, 2, None, None)
        .is_err());
    assert!(engine
        .build_authcell_widen_scoped_stub(FLAG_TABLE_BASE, 0x1000, 0, Some(4), None)
        .is_err());
}

#[test]
fn refusal_detour_is_selected_only_for_the_alternate_contract() {
    use mediatek_optical::classify::analysis::{AuthCell, AuthCellVariant};
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let engine = Mt1959Engine;
    for name in [
        "BU40N_OEM_1.00.bin",
        "BU40N_OEM_1.05.bin",
        "BE14NU40_MT1939_JB7_1.01.bin",
        "BP50NB40_NB50_1.02_unmodified_backup.bin",
        "UH12NS40_OEM_1.03.bin",
        "WH14NS40_OEM_1.05.bin",
        "WH16NS58_OEM_1.V9.bin",
        "WH16NS60_OEM_1.03.bin",
    ] {
        let img = std::fs::read(format!("{dir}/{name}")).unwrap();
        let alternate = AuthCell::detect(&img)
            .map(|c| c.variant() == AuthCellVariant::R0StateR1Alternate)
            .unwrap_or(false);
        let refusal = engine.auth_cell_refusal_detour(&img, FLAG_TABLE_BASE);
        if alternate {
            let refusal = refusal.unwrap();
            assert!(!refusal.1.is_empty(), "{name}");
            let widened = engine
                .auth_cell_widen_detour(&img, FLAG_TABLE_BASE)
                .unwrap();
            assert_eq!(widened, refusal, "{name}");
        } else {
            assert!(refusal.is_err(), "{name}");
        }
    }
}

#[test]
fn hrl_sites_refuse_disagreeing_targets_and_a_foreign_revoke_head() {
    let img = bu40n();
    let engine = Mt1959Engine;
    let (sites, target) = engine.find_hrl_skip_sites(&img).unwrap();
    assert!(sites.len() >= 2, "{sites:x?}");

    let mut split = img.clone();
    split[sites[1] + 2] = 0xF0;
    let e = err_text(engine.find_hrl_skip_sites(&split));
    assert!(e.contains("disagree on the revoke target"), "{e}");

    let mut headless = img.clone();
    headless[target as usize] = 0;
    let e = err_text(engine.find_hrl_skip_sites(&headless));
    assert!(e.contains("lacks the OEM revoke HEAD"), "{e}");
}

fn de_outcome(levers: &[LeverReport]) -> &LeverOutcome {
    &levers
        .iter()
        .find(|l| l.id == LeverId::DowngradeEnable)
        .expect("DE lever reported")
        .outcome
}

#[test]
fn downgrade_lever_distinguishes_absent_and_malformed_descriptors() {
    let img = bu40n();
    let engine = Mt1959Engine;
    let chip = crate::family::detect_chip(&img).unwrap();
    assert!(chip.descriptor_present);
    let cap = Capability {
        family: chip.family,
        media_class: crate::family::MediaClass::Cd,
        bd_aacs: false,
        region_lockable: false,
    };
    let mut bare = chip.clone();
    bare.descriptor_present = false;

    let mut out = img.clone();
    let report = engine.lever_de(&img, &mut out, &bare);
    assert!(matches!(report.outcome, LeverOutcome::NotApplicable { .. }));
    assert_eq!(out, img);

    let mut untagged = img.clone();
    let tag = crate::family::DESCRIPTOR_OFFSET + 0x34;
    untagged[tag..tag + 8].fill(0);
    let mut out = untagged.clone();
    let report = engine.lever_de(&untagged, &mut out, &chip);
    assert!(matches!(
        report.outcome,
        LeverOutcome::SignatureNotFound { .. }
    ));
    assert_eq!(out, untagged);

    let r = engine.already_present_report(&img, &bare, &cap, "MT1959");
    assert!(matches!(
        de_outcome(&r.levers),
        LeverOutcome::NotApplicable { .. }
    ));
    let r = engine.already_present_report(&untagged, &chip, &cap, "MT1959");
    assert!(matches!(
        de_outcome(&r.levers),
        LeverOutcome::SignatureNotFound { .. }
    ));
}
