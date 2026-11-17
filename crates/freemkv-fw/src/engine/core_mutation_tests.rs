//! Boundary, literal-pool and arithmetic contracts of the MT1959 finders and
//! stub builders, pinned with synthetic images and odd addresses.

use super::*;
use crate::engine::Engine;

const BU40N: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/BU40N_OEM_1.00.bin"
);
const FLAGS: u32 = 0x0200_1000;

fn bu40n() -> Vec<u8> {
    std::fs::read(BU40N).expect("committed BU40N OEM fixture")
}

fn put_hw(img: &mut [u8], off: usize, hws: &[u16]) {
    for (k, &h) in hws.iter().enumerate() {
        img[off + 2 * k..off + 2 * k + 2].copy_from_slice(&h.to_le_bytes());
    }
}

fn put_bl(img: &mut [u8], at: usize, target: usize) {
    let bl = thumb_asm::encode_bl(at, target as u32).unwrap();
    img[at..at + 4].copy_from_slice(&bl);
}

fn materialize(sig: &[(u16, u16)]) -> Vec<u16> {
    sig.iter().map(|&(v, _)| v).collect()
}

fn err_text<T: std::fmt::Debug>(r: Result<T>) -> String {
    format!("{:#}", r.expect_err("must refuse"))
}

fn has_word(bytes: &[u8], word: u32) -> bool {
    bytes.windows(4).any(|w| w == word.to_le_bytes())
}

#[test]
fn masked_search_accepts_an_exact_fit_and_never_underflows() {
    let mut img = [0u8; 16];
    put_hw(&mut img, 6, &[0x1234, 0x5678]);
    let sig = &[(0x1234, 0xffff), (0x5678, 0xffff)];
    assert_eq!(find_masked(&img, sig, 6, 10), Some(6));
    assert_eq!(find_masked_all(&img, sig, 6, 10), vec![6]);
    assert_eq!(find_masked(&img, sig, 3, 3), None);
    assert!(find_masked_all(&img, sig, 3, 3).is_empty());
    assert_eq!(find_masked(&img, sig, 4, 6), None);
    assert!(find_masked_all(&img, sig, 4, 6).is_empty());
    assert_eq!(find_masked_all(&img, sig, 0, 100), vec![6]);
}

#[test]
fn find_aacs_auth_literal_must_sit_within_the_gate_window() {
    let engine = Mt1959Engine;
    for lit in [0x13_0040usize, 0x13_0100] {
        let mut img = vec![0u8; 0x14_0000];
        put_hw(&mut img, 0xa_0000, &[0xB510, 0x79C1, 0x297F, 0xD805]);
        put_hw(&mut img, 0x13_0000, &[0x2202, 0x216F, 0x2005]);
        img[lit..lit + 4].copy_from_slice(&0x0200_0c80u32.to_le_bytes());
        let e = err_text(engine.find_aacs(&img));
        assert!(e.contains("auth-flag base literal"), "{e}");
    }
    let mut img = vec![0u8; 0x14_0000];
    put_hw(&mut img, 0xa_0000, &[0xB510, 0x79C1, 0x297F, 0xD805]);
    put_hw(&mut img, 0x13_0000, &[0x2202, 0x216F, 0x2005]);
    img[0x13_003c..0x13_0040].copy_from_slice(&0x0200_0c80u32.to_le_bytes());
    assert!(engine.find_aacs(&img).is_ok());
}

#[test]
fn sense_setter_requires_the_exact_register_triple_and_its_bl() {
    let mut img = vec![0u8; 0x200];
    let entry = 0x20;
    put_hw(&mut img, entry, &[0x2200, 0x2100, 0x2000]);
    put_bl(&mut img, entry + 6, 0x100);
    let want = thumb::decode_bl(&img, entry + 6).unwrap();
    assert_eq!(Mt1959Engine::sense_setter_at(&img, entry).unwrap(), want);

    let mut wrong = vec![0u8; 0x200];
    put_hw(&mut wrong, entry, &[0x2300, 0x2300, 0x2300]);
    put_bl(&mut wrong, entry + 6, 0x100);
    assert!(Mt1959Engine::sense_setter_at(&wrong, entry).is_err());
}

#[test]
fn boot_init_convergence_follows_only_a_conditional_minus_branch() {
    let site = 0x10;
    for (hw, ok) in [(0xD405u16, true), (0xD005, false), (0xE005, false)] {
        let mut img = vec![0u8; 0x100];
        put_hw(&mut img, site + 4, &[hw]);
        put_bl(&mut img, 0x22, 0x80);
        let got = boot_init_convergence(&img, site);
        if ok {
            let target = thumb::decode_bl(&img, 0x22).unwrap();
            assert_eq!(got, Some((0x22, target)));
        } else {
            assert_eq!(got, None, "{hw:#x}");
        }
    }
}

#[test]
fn flash_write_tags_the_program_entry_with_the_thumb_bit() {
    let mut a = Asm::with_target(thumb_asm::isa::Target::Thumb1);
    emit_flash_write(&mut a, 0x0200_0C78, 0x1E_A000, 0x0200_1000, 4, 0x000C_1235);
    let bytes = a.finish().unwrap();
    assert!(has_word(&bytes, 0x000C_1235));
}

#[test]
fn stubs_embed_thumb_tagged_continuations() {
    let e = Mt1959Engine;
    for idx in [2u8, 0] {
        let b = e.build_speed_stub(FLAGS, 0x1_0101, 0x1_0203, idx).unwrap();
        assert!(has_word(&b, 0x1_0101), "fallthrough {idx}");
        assert!(has_word(&b, 0x1_0203), "exit {idx}");
    }
    let b = e.build_ake_stub(FLAGS, 0x2_0101, 0x2_0203).unwrap();
    assert!(has_word(&b, 0x2_0101) && has_word(&b, 0x2_0203));
    let b = e.build_ake_stub_nb(FLAGS, 0x3_0101, 0x3_0203).unwrap();
    assert!(has_word(&b, 0x3_0101) && has_word(&b, 0x3_0203));
    assert!(has_word(&b, FLAGS + abi::Feature::Encryption as u32));
    let b = e.build_hrl_skip_stub(FLAGS, 0x4_0101).unwrap();
    assert!(has_word(&b, 0x4_0101));
    assert!(has_word(&b, FLAGS + abi::Feature::Hrl as u32));
    let b = e
        .build_gatea_stub(FLAGS, 0x0200_2000, 0x5_0101, 0x5_0203, 0x5_0305)
        .unwrap();
    assert!(has_word(&b, 0x5_0101) && has_word(&b, 0x5_0203) && has_word(&b, 0x5_0305));
    let b = e.build_deny_reset_stub(0x6_0101).unwrap();
    assert!(has_word(&b, 0x6_0101));
    let b = e
        .build_authcell_widen_scoped_stub(FLAGS, 0x7_0101, 1, Some(4), Some(0x7_0203))
        .unwrap();
    assert!(has_word(&b, 0x7_0101) && has_word(&b, 0x7_0203));
    for classic in [false, true] {
        let b = e
            .build_boot_init_inner(FLAGS, 0x8_0101, &BootSettings::standard(), None, classic)
            .unwrap();
        assert!(has_word(&b, 0x8_0101), "classic={classic}");
    }
}

#[test]
fn handler_tags_an_odd_boot_function_entry() {
    let img = bu40n();
    let report = Mt1959Engine.create(&img).unwrap();
    let bytes = Mt1959Engine
        .build_handler(&img, report.record.handler, FLAG_TABLE_BASE, 0x0010_0101)
        .unwrap();
    assert!(has_word(&bytes, 0x0010_0101));
}

#[test]
fn refusal_detour_embeds_the_flag_cell_and_both_exits() {
    use mediatek_optical::classify::analysis::{AuthCell, AuthCellVariant};
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let img = std::fs::read(&path).unwrap();
        let Ok(c) = AuthCell::detect(&img) else {
            continue;
        };
        if c.variant() != AuthCellVariant::R0StateR1Alternate {
            continue;
        }
        let (_, bytes) = Mt1959Engine.auth_cell_refusal_detour(&img, FLAGS).unwrap();
        assert!(has_word(&bytes, FLAGS + abi::Feature::Unrestricted as u32));
        assert!(has_word(&bytes, c.refusal() as u32 | 1));
        assert!(has_word(&bytes, c.deny() as u32 | 1));
        seen += 1;
    }
    assert!(seen > 0);
}

#[test]
fn finders_return_real_addresses_on_the_oem_fixture() {
    let img = bu40n();
    let e = Mt1959Engine;
    assert!(e.find_setdiscmode(&img).unwrap() > 1);
    assert!(e.find_bd_gate(&img).unwrap() > 1);
}

#[test]
fn session_reset_prologue_search_window_is_exact() {
    let img = bu40n();
    let e = Mt1959Engine;
    let entry = e.find_aacs_session_reset(&img).unwrap() as usize;
    let setter = e.find_vid_gate_setter(&img).unwrap() as usize;
    let loop_at = entry + 0x24;

    let mut base = img.clone();
    base[loop_at + 24] = 0x03;
    let sig: Vec<u8> = img[loop_at..loop_at + 28].to_vec();
    base[entry..entry + 2].fill(0);

    // Loop copied to 0x1f_ff00, with the entry push placed `gap` bytes before it.
    let probe = |gap: usize| {
        let mut t = base.clone();
        let copy = 0x1f_ff00;
        t[copy - 0x50..copy].fill(0);
        t[copy..copy + 28].copy_from_slice(&sig);
        put_bl(&mut t, copy + 14, setter);
        put_hw(&mut t, copy - gap, &[0xB570]);
        (e.find_aacs_session_reset(&t), copy - gap)
    };
    let (ok, at) = probe(0x40);
    assert_eq!(ok.unwrap() as usize, at);
    let (far, _) = probe(0x42);
    assert!(err_text(far).contains("prologue"));
}

#[test]
fn session_reset_prologue_search_stops_at_the_image_start() {
    let img = bu40n();
    let e = Mt1959Engine;
    let entry = e.find_aacs_session_reset(&img).unwrap() as usize;
    let setter = e.find_vid_gate_setter(&img).unwrap() as usize;
    let loop_at = entry + 0x24;
    let sig: Vec<u8> = img[loop_at..loop_at + 28].to_vec();
    let mut t = img.clone();
    t[loop_at + 24] = 0x03;
    t[0..0x40].fill(0);
    t[4..32].copy_from_slice(&sig);
    put_bl(&mut t, 4 + 14, setter);
    put_hw(&mut t, 2, &[0xB570]);
    assert_eq!(e.find_aacs_session_reset(&t).unwrap(), 2);
    put_hw(&mut t, 2, &[0x0000]);
    assert!(e.find_aacs_session_reset(&t).is_err());
}

struct Hrl {
    img: Vec<u8>,
}

fn hrl_image(len: usize, hrl: usize) -> Hrl {
    let mut img = vec![0u8; len];
    put_hw(&mut img, hrl, &materialize(HRL_LOOKUP_SIG));
    Hrl { img }
}

impl Hrl {
    fn site(mut self, hrl: usize, bl: usize, cmp: usize, bne: u16) -> Self {
        put_bl(&mut self.img, bl, hrl);
        put_hw(&mut self.img, cmp, &[0x2800, bne]);
        self
    }
    fn head(mut self, at: usize) -> Self {
        put_hw(&mut self.img, at, &[0x78A0, 0x2800, 0xD100]);
        self
    }
}

#[test]
fn hrl_sites_resolve_forward_and_backward_bne_targets() {
    let e = Mt1959Engine;
    let fwd = hrl_image(0x400, 0x100)
        .site(0x100, 0x20, 0x24, 0xD120)
        .head(0x6A);
    assert_eq!(e.find_hrl_skip_sites(&fwd.img).unwrap(), (vec![0x24], 0x6A));
    let back = hrl_image(0x400, 0x100)
        .site(0x100, 0x180, 0x184, 0xD1F0)
        .head(0x16A);
    assert_eq!(
        e.find_hrl_skip_sites(&back.img).unwrap(),
        (vec![0x184], 0x16A)
    );
}

#[test]
fn hrl_site_search_window_ends_a_fixed_distance_after_the_call() {
    let e = Mt1959Engine;
    let edge = hrl_image(0x400, 0x100)
        .site(0x100, 0x20, 0x38, 0xD110)
        .head(0x5E);
    assert_eq!(e.find_hrl_skip_sites(&edge.img).unwrap().0, vec![0x38]);
    let past = hrl_image(0x400, 0x100)
        .site(0x100, 0x20, 0x3A, 0xD110)
        .head(0x5E);
    assert!(err_text(e.find_hrl_skip_sites(&past.img)).contains("no HRL cert-path"));
}

#[test]
fn hrl_compare_must_be_followed_by_a_conditional_branch() {
    let e = Mt1959Engine;
    let lone = hrl_image(0x400, 0x100).site(0x100, 0x20, 0x24, 0x0000);
    assert!(err_text(e.find_hrl_skip_sites(&lone.img)).contains("no HRL cert-path"));
}

#[test]
fn hrl_revoke_head_must_fit_inside_the_image() {
    let e = Mt1959Engine;
    let mut short = hrl_image(0x100, 0x80).site(0x80, 0x20, 0x24, 0xD169);
    put_hw(&mut short.img, 0xFC, &[0x78A0, 0x2800]);
    assert!(err_text(e.find_hrl_skip_sites(&short.img)).contains("lacks the OEM revoke HEAD"));
}
