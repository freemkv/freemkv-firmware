//! Known-Answer Test for the MT1959 `3C 0E` build.
//!
//! The reference image was produced by hand-modifying the OEM BU40N 1.00 base
//! (see `tests/kat/mt1959_bu40n_1.00_3c0e.json`) and verified offline. This test
//! requires the engine's `create` to reproduce that artifact **exactly** —
//! grounded facts, injected handler bytes, and the re-signed CMAC digests. It is
//! the falsifiable-against-reality gate the old fixture tests never were.
//!
//! The OEM base is not committed (cleanroom / licensing); the test reads it from
//! `$FREEMKV_KAT_BASE` or the private hoard, and **skips** (does not fail) when
//! the image is absent, so CI without it still passes.

use crate::engine::mt1959::Mt1959Engine;
use crate::engine::Engine;

const EXPECT_BASE_SHA: &str = "221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4";
const EXPECT_CDB_BASE: u32 = 0x0200_0d38;
const EXPECT_SENSE: u32 = 0x000a_2d6a;
const EXPECT_RECORD_OFF: usize = 0x0014_fd74;
const EXPECT_OEM_HANDLER: u32 = 0x0009_ad5b;
const EXPECT_HANDLER_VA: u32 = 0x0015_3968;
/// The dispatching handler for the `verb [feature] [state]` grammar: SET writes
/// `flag[cdb[5]]=cdb[6]`; RESET writes 0xFF to every feature flag; GET returns
/// `flag[cdb[5]]`; IDENTITY returns RESP_MAGIC+version+the live feature-state
/// table; DUMPALL peeks RAM. Speed/Region/UHD/BD/HRL/AKE/Bus act via flag-gated
/// OEM-code trampolines keyed by Feature id, not this handler.
///
/// NOTE: the handler embeds the crate version string (`freemkv <CARGO_PKG_VERSION>`),
/// so a version bump changes these injected bytes AND the two CMAC digests below
/// (the version bytes fall inside CMAC entries 1 and 15). When the version bumps,
/// regenerate all three constants (run this test with `FREEMKV_KAT_BASE` set and
/// copy the `left:` values). This is expected drift, not a real regression.
const EXPECT_HANDLER_HEX: &str =
    "9e4b58780e2806d19878c02803d1d878de2800d101e09a4b1847f0b5994f1c79022c07d198485979082968d240189979017064e0042c62d19879ff2826d19248ff21017041708170c170017141718171c1718e4806688e48056876198a4801783170417871708178b170c178f17001793171417971718179b171c179f171281c844908220123844da84738e0012811d17d48ff210170ff214170ff2181700121c17001210171ff214171ff218171ff21c17124e0744e774a1178ff2910d1ff213170ff217170ff21b1700121f17001213171ff217171ff21b171ff21f1710ee0517871709178b170d178f17011793171517971719179b171d179f171ffe70025402d04d2281c0021b8470135f8e70a2c42d15e793602987936183602d87936183602187a3618587a5c490870594886420ad35b48864207d25848311c01220123554da847041c00e0564c350e0020291cb84735022d0e0120291cb84735042d0e0220291cb84735062d0e0320291cb847250e0420291cb84725022d0e0520291cb84725042d0e0620291cb84725062d0e0720291cb8476ae00b2c33d13a48012101703a4806683a4805687619364801783170417871708178b170c178f17001793171417971718179b171c179f171281c304908220123304da847041c250e0020291cb84725022d0e0120291cb84725042d0e0220291cb84725062d0e0320291cb84734e0032c08d11f485979082904d2401801780020b84729e0092c11d15e793602987936183602d87936183602187a36180025402d1ad2281c715db8470135f8e7012c13d11ba600250d2d04d2281c715db8470135f8e70b4e0d250122082a05d2b15c281cb84701350132f7e740200d4908800d480e4a9047f0bd380d00025bad090075200a00400e0002780c00027c0c000200a01e002bda1300500e000200b01e0055464552720c000290af000081810900667265656d6b7620302e382e33";
// Re-signed CMAC stored digests that must change (entry index -> stored hex).
//
// NOTE: the injected band (3C handler + every stub) and the OEM-code detours all fall
// in CMAC-covered regions, so these two digests must be regenerated whenever any of
// them change — including the tri-state redesign: the new always-on boot-init detour
// (at the cold/warm convergence bl, 0x13d428) + its stub, the Speed stub losing its
// `0x00->OEM` branch, the Region stub
// gaining a `0x00` region-lock arm, and the BD-refuse gate moving from the `0x02`
// sentinel to the uniform `0x00` OFF. Regenerate against the OEM base (run this test
// with FREEMKV_KAT_BASE set and copy the `left:` values). Expected drift, not a
// regression — the test skips when the base is absent.
const EXPECT_CMAC_1: &str = "8d8482ec69502148762a608a0cb459b4";
const EXPECT_CMAC_15: &str = "b4d4b04384f9116335348da4e9c10568";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal SHA-256 (only used to confirm the KAT input is the exact base).
fn sha256(data: &[u8]) -> String {
    // FIPS 180-4, straightforward reference implementation.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            *wi = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (hi, vi) in h.iter_mut().zip(v.iter()) {
            *hi = hi.wrapping_add(*vi);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn load_base() -> Option<Vec<u8>> {
    // `FREEMKV_KAT_BASE` (an explicit OEM BU40N 1.00 path) wins when set. Otherwise
    // fall back to the committed fixture so the golden KAT actually runs in CI
    // instead of silently skipping — a skip that passes is the one failure mode this
    // test exists to prevent. If neither is present/readable, skip (never fail).
    if let Some(v) = std::env::var("FREEMKV_KAT_BASE")
        .ok()
        .and_then(|p| std::fs::read(&p).ok())
    {
        return Some(v);
    }
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    );
    std::fs::read(fixture).ok()
}

#[test]
fn create_reproduces_hand_built_kat_byte_for_byte() {
    let Some(base) = load_base() else {
        eprintln!("SKIP: KAT base image not present (set FREEMKV_KAT_BASE) — cannot run KAT");
        return;
    };
    assert_eq!(
        sha256(&base),
        EXPECT_BASE_SHA,
        "KAT base image is not the expected OEM BU40N 1.00"
    );

    let report = Mt1959Engine
        .create(&base)
        .expect("create must succeed on the OEM base");

    // grounded facts, every one derived from the image (no consts in the engine)
    assert_eq!(report.cdb_base, EXPECT_CDB_BASE, "cdb_base");
    assert_eq!(report.sense_setter, EXPECT_SENSE, "sense_setter");
    assert_eq!(report.record.off, EXPECT_RECORD_OFF, "0x3C record offset");
    assert_eq!(report.record.handler, EXPECT_OEM_HANDLER, "OEM handler");
    assert_eq!(
        report.record.flags, 0x01,
        "record flags must be the live 0x01 (ready-gated, not media-gated)"
    );
    assert_eq!(
        report.handler_va, EXPECT_HANDLER_VA,
        "handler injection address"
    );

    // our exact injected code
    assert_eq!(
        hex(&report.handler_bytes),
        EXPECT_HANDLER_HEX,
        "injected handler bytes"
    );

    // the re-signed image, byte-exact where it must change
    let img = &report.image;
    assert_eq!(img.len(), base.len(), "image size preserved");
    // DE (downgrade-enable) byte is ALWAYS written on every create — a guaranteed
    // build step, never a toggle. Guards the "DE in modify every time" contract.
    assert_eq!(
        img[report.de_off as usize], 0xDE,
        "DE byte must be 0xDE at the found identity-page slot on every create"
    );
    // handler landed
    assert_eq!(
        hex(&img
            [EXPECT_HANDLER_VA as usize..EXPECT_HANDLER_VA as usize + report.handler_bytes.len()]),
        EXPECT_HANDLER_HEX,
        "handler bytes in image"
    );
    // record repointed, flags preserved
    let ptr = u32::from_le_bytes([
        img[EXPECT_RECORD_OFF + 4],
        img[EXPECT_RECORD_OFF + 5],
        img[EXPECT_RECORD_OFF + 6],
        img[EXPECT_RECORD_OFF + 7],
    ]);
    assert_eq!(
        ptr,
        EXPECT_HANDLER_VA | 1,
        "record handler repointed (Thumb)"
    );
    assert_eq!(img[EXPECT_RECORD_OFF + 1], 0x01, "flags untouched");
    // re-signed CMAC digests exact (proves signer + placement are byte-perfect)
    let dig = |idx: usize| {
        let o = freemkv_flash::cmac::TABLE_OFFSET + idx * freemkv_flash::cmac::ENTRY_SIZE + 12;
        hex(&img[o..o + 16])
    };
    assert_eq!(dig(1), EXPECT_CMAC_1, "CMAC entry 1 digest");
    assert_eq!(dig(15), EXPECT_CMAC_15, "CMAC entry 15 digest");
    // and the whole image passes its own integrity check
    assert!(
        freemkv_flash::cmac::verify(img),
        "re-signed image must verify"
    );

    // Every changed byte must fall in an accounted-for region: the injected band
    // (3C handler + every stub), the repointed record, the CMAC table, the OEM-code
    // detours (speed/region/ake/gatea/deny/busenc/uhd/bd/hrl), or the DE byte. 0x400
    // bounds the injected band.
    let injected = EXPECT_HANDLER_VA as usize..EXPECT_HANDLER_VA as usize + 0x520;
    // Always-on boot-init hook: the cold/warm-boot convergence `bl <orig_init>`
    // (the anchor's `bmi` target, after the SRAM clear) replaced by a `bl` to the
    // boot stub, which tail-calls `orig_init`.
    let boot_detour = report.boot_init_site as usize..report.boot_init_site as usize + 4;
    let speed_detour = report.speed_gate as usize + 4..report.speed_gate as usize + 8;
    let region_detour = report.region_emitter as usize + 6..report.region_emitter as usize + 10;
    let ake_detour = report.ake_gate as usize + 12..report.ake_gate as usize + 16;
    let gatea_detour = report.gatea_gate as usize..report.gatea_gate as usize + 4;
    let deny_detour = report.deny_reset_gate as usize..report.deny_reset_gate as usize + 4;
    // Raw Read `04 03` "data clear" (bus-off): the AACS opcode-0x45 arm detour
    // (report.busenc_detour_site), 4 bytes of the arm's leading `bl`.
    let busenc_detour = report.busenc_detour_site as usize..report.busenc_detour_site as usize + 4;
    // `Feature::Uhd` UHD media accept/refuse: the REPORT KEY class-3 arm detour
    // (report.uhd_classifier_site), 4 bytes replacing `ldrb r0,[r2,#7]; cmp r0,#3`.
    let uhd_detour = report.uhd_classifier_site as usize..report.uhd_classifier_site as usize + 4;
    // `Feature::Bd` BD-refuse: the REPORT KEY mode-0 class check detour
    // (report.bd_gate_site), 4 bytes replacing `ldrb r0,[r2,#7]; cmp r0,#2`.
    let bd_detour = report.bd_gate_site as usize..report.bd_gate_site as usize + 4;
    // HRL skip (`flag[Feature::Hrl]==STATE_OFF`): three cert-path detour sites, 4
    // bytes each (a `bl` to the shared HRL-skip stub, replacing `cmp r0,#0; bne`).
    let in_hrl = |i: usize| {
        report
            .hrl_sites
            .iter()
            .any(|&s| (s as usize..s as usize + 4).contains(&i))
    };
    for (i, (a, b)) in base.iter().zip(img.iter()).enumerate() {
        if a != b {
            let in_record = (EXPECT_RECORD_OFF + 4..EXPECT_RECORD_OFF + 8).contains(&i);
            let in_cmac = (freemkv_flash::cmac::TABLE_OFFSET
                ..freemkv_flash::cmac::TABLE_OFFSET
                    + freemkv_flash::cmac::ENTRY_COUNT * freemkv_flash::cmac::ENTRY_SIZE)
                .contains(&i);
            assert!(
                injected.contains(&i)
                    || in_record
                    || in_cmac
                    || boot_detour.contains(&i)
                    || speed_detour.contains(&i)
                    || region_detour.contains(&i)
                    || ake_detour.contains(&i)
                    || gatea_detour.contains(&i)
                    || deny_detour.contains(&i)
                    || busenc_detour.contains(&i)
                    || uhd_detour.contains(&i)
                    || bd_detour.contains(&i)
                    || in_hrl(i)
                    || i == report.de_off as usize,
                "unexpected byte change at 0x{i:x}"
            );
        }
    }

    // The build-time SRAM scanner still reports its (unsound) candidate for audit,
    // but the flag base actually used is the validated 204-byte free hole at
    // 0x02000e40 (hardware-proven writable+free; 0x02001a00 was unmapped).
    assert_eq!(
        report.free_sram_cell, 0x0200_120c,
        "scanner free SRAM cell (audit-only, unsound)"
    );
    assert_eq!(
        report.flag_base, 0x0200_0e40,
        "flag-table base (validated free hole)"
    );
    // Always-on boot-init hook: the cold/warm-boot convergence `bl <orig_init>` (the
    // BOOT_INIT_SIG anchor's `bmi` target, 0x13d428 on 1.00 — the first call AFTER the
    // cold-boot SRAM clear), detoured to a stub that writes 0xFF into every flag at
    // power-on (tri-state safety) then tail-calls orig_init.
    assert_eq!(
        report.boot_init_site, 0x0013_d428,
        "always-on boot-init hook site (1.00)"
    );
    assert!(report.boot_stub_va != 0, "boot-init stub wired");
    assert_eq!(
        report.speed_gate, 0x0001_bb22,
        "Speed ramp-ceiling gate (1.00)"
    );
    assert_eq!(report.region_emitter, 0x0011_9890, "RPC emitter (1.00)");
    assert_eq!(report.ake_gate, 0x0013_6594, "AACS AKE accept gate (1.00)");
    assert!(report.ake_stub_va != 0, "Raw Read (0x04) AKE stub wired");
    assert_eq!(
        report.gatea_gate, 0x0013_67ae,
        "VID producer Gate-A cmp (1.00)"
    );
    assert!(
        report.gatea_stub_va != 0,
        "Raw Read (0x04) Gate-A stub wired"
    );
    assert_eq!(
        report.deny_reset_gate, 0x0013_67f8,
        "VID producer deny-path AACS-reset detour site (1.00)"
    );
    assert!(
        report.deny_stub_va != 0,
        "Raw Read (0x04) deny-path AACS-reset stub wired"
    );
    // Raw Read `04 03` "data clear" (bus-off): the MK-style detour of the OEM
    // `bl <key-prog>` at the start of the AACS opcode-0x45 arm (0x95eec on 1.00).
    assert_eq!(
        report.busenc_detour_site, 0x0009_5eec,
        "bus-off (04 03) detours the AACS opcode-0x45 arm's leading bl (1.00)"
    );
    assert!(
        report.busenc_stub_va != 0,
        "Raw Read `04 03` bus-off (data clear) stub wired"
    );
    // `Feature::Uhd` UHD media accept/refuse (REPORT KEY class-3 arm): the UHD class
    // check `ldrb r0,[r2,#7]; cmp r0,#3` at the accept gate's anchor+4 (0x1365be anchor
    // → 0x1365c2 site on 1.00), the UHD sibling of the BD arm on the SAME gate.
    assert_eq!(
        report.uhd_classifier_site, 0x0013_65c2,
        "UHD media-gate arm detours the REPORT KEY class-3 check (1.00)"
    );
    assert!(
        report.uhd_stub_va != 0,
        "UHD media-gate accept/refuse stub wired"
    );
    // `Feature::Bd` BD-refuse (REPORT KEY mode-0 class gate): the mode-0 class check
    // `ldrb r0,[r2,#7]; cmp r0,#2` at the gate anchor+16 (0x1365be anchor → 0x1365ce
    // site on 1.00), detoured to a stub that forces the OEM deny (6F) when
    // `flag[Bd]==STATE_OFF` and replays OEM otherwise (stealth).
    assert_eq!(
        report.bd_gate_site, 0x0013_65ce,
        "BD-refuse (Feature::Bd) detours the REPORT KEY mode-0 class check (1.00)"
    );
    assert!(report.bd_stub_va != 0, "Feature::Bd BD-refuse stub wired");
    // HRL skip (`flag[Feature::Hrl]==STATE_OFF`): the three cert-path check sites
    // (`cmp r0,#0; bne <6F/00>`) after each `bl <hrl_lookup>` (0x13550e on 1.00),
    // all detoured to one shared HRL-skip stub.
    assert_eq!(
        report.hrl_sites,
        vec![0x0013_6334, 0x0013_6378, 0x0013_63aa],
        "HRL-skip cert-path detour sites (1.00)"
    );
    assert!(
        report.hrl_stub_va != 0,
        "Feature::Hrl STATE_OFF (HRL skip) stub wired"
    );
    assert_eq!(report.de_off, 0x001e_c056, "DE byte offset (1.00)");
}

/// The two firmware images the VID (0x03) finders must resolve identically,
/// supplied from the environment only (no owned path is baked into this public
/// repo): `FREEMKV_KAT_BASE` = OEM BU40N 1.00, `FREEMKV_KAT_MK103` = MK-signed
/// BU40N 1.03. Unset entries are simply absent, so CI without the private hoard
/// still passes.
fn required_images() -> Vec<String> {
    ["FREEMKV_KAT_BASE", "FREEMKV_KAT_MK103"]
        .into_iter()
        .filter_map(|k| std::env::var(k).ok())
        .collect()
}

/// Roots swept for owned ~2 MiB MT1959 images — colon-separated directories in
/// `FREEMKV_KAT_HOARD` (unset = no sweep).
fn hoard_roots() -> Vec<String> {
    std::env::var("FREEMKV_KAT_HOARD")
        .into_iter()
        .flat_map(|s| s.split(':').map(str::to_string).collect::<Vec<_>>())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The producer's clear-VID scratch buffer — a runtime address (above the 2 MiB
/// flash) that proved identical across every owned VID-capable image.
const EXPECT_VID_OUT_BUF: u32 = 0x0021_0c00;

/// The scanner-derived largest free SRAM gap base — identical on the two required
/// BU40N images (1.00 + 1.03): `0x0200120c..0x02002000` (3572 bytes), which
/// contains the `0x02001a00` gap the live sweep found.
const EXPECT_FREE_SRAM: u32 = 0x0200_120c;

/// The downgrade-enable byte offset (identity-page slot), identical fleet-wide.
const EXPECT_DE_OFF: u32 = 0x001e_c056;

fn collect_bins(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_bins(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("bin") {
            if let Ok(m) = std::fs::metadata(&p) {
                if (2_000_000..2_200_000).contains(&(m.len() as usize)) {
                    out.push(p);
                }
            }
        }
    }
}

/// Every VID-capable owned image must resolve the 0x03 finders (producer,
/// gate-setter, scratch buffer) and the 0x04 hook (`SetDiscMode`) uniquely, and
/// the two required images must build clean. Skips (does not fail) when the
/// private hoard is absent, so CI without it still passes.
#[test]
fn finders_hold_across_owned_images() {
    let eng = Mt1959Engine;

    // The two named targets must build end-to-end and agree on the VID facts.
    let required = required_images();
    let mut checked_required = 0;
    for path in &required {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let report = eng
            .create(&bytes)
            .unwrap_or_else(|e| panic!("required image {path} must build: {e}"));
        assert_eq!(
            report.vid_out_buf, EXPECT_VID_OUT_BUF,
            "VID scratch buffer for {path}"
        );
        assert!(report.vid_producer != 0, "VID producer for {path}");
        assert!(report.vid_gate_setter != 0, "VID gate-setter for {path}");
        assert!(report.setdiscmode != 0, "SetDiscMode for {path}");
        // Speed (0x02) + Region-free (0x03) must be wired, and the DE byte + the
        // scanner-derived free cell must agree across both required BU40N images.
        assert!(report.speed_stub_va != 0, "Speed (0x02) wired for {path}");
        assert!(
            report.region_stub_va != 0,
            "Region-free (0x03) wired for {path}"
        );
        assert_eq!(report.de_off, EXPECT_DE_OFF, "DE byte for {path}");
        assert_eq!(
            report.free_sram_cell, EXPECT_FREE_SRAM,
            "scanner free SRAM cell for {path}"
        );
        checked_required += 1;
    }
    if checked_required == 0 {
        eprintln!(
            "SKIP: no required images present (set FREEMKV_KAT_BASE / FREEMKV_KAT_MK103) \
             — cannot run fleet finder test"
        );
        return;
    }
    assert_eq!(
        checked_required,
        required.len(),
        "every configured required image must be present and build"
    );

    // Every owned VID-capable image: finders unique + consistent scratch buffer.
    // The broader sweep only runs when a hoard root is configured.
    let roots = hoard_roots();
    if roots.is_empty() {
        eprintln!(
            "SKIP: FREEMKV_KAT_HOARD unset — fleet sweep skipped (required images verified above)"
        );
        return;
    }
    let mut files = Vec::new();
    for root in &roots {
        collect_bins(std::path::Path::new(root), &mut files);
    }
    files.sort();
    files.dedup();

    let mut vid_capable = 0;
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        // Only images this engine recognises as a 3C target are candidates.
        if eng.find_scanner_entry(&bytes).is_err() {
            continue;
        }
        // Images without the VID producer are refused cleanly by the finder (the
        // engine will decline to build them); only assert on VID-capable ones.
        let Ok((producer, out_buf)) = eng.find_vid_producer(&bytes) else {
            continue;
        };
        vid_capable += 1;
        let disp = path.display();
        assert!(producer != 0, "VID producer @ {disp}");
        assert_eq!(out_buf, EXPECT_VID_OUT_BUF, "VID scratch buffer @ {disp}");
        eng.find_vid_gate_setter(&bytes)
            .unwrap_or_else(|e| panic!("VID gate-setter @ {disp}: {e}"));
        eng.find_setdiscmode(&bytes)
            .unwrap_or_else(|e| panic!("SetDiscMode @ {disp}: {e}"));
        // MK-style bus-off (`04 03`): the AACS opcode-0x45 arm must resolve UNIQUELY
        // on every image whose desktop OR notebook AKE gate is present (the MT1959
        // lineage this mechanism applies to). JB8/MT1939-classic images have no such
        // AKE gate, so `ake_detour` (hence bus-off) is intentionally not asserted.
        if eng.ake_detour(&bytes, super::FLAG_TABLE_BASE).is_ok() {
            let (site, _keyprog) = eng
                .find_aacs45_arm(&bytes)
                .unwrap_or_else(|e| panic!("AACS opcode-0x45 arm @ {disp}: {e}"));
            assert!(site != 0, "bus-off detour site @ {disp}");
        }
        // UHD media accept/refuse arm on the REPORT KEY accept gate (the UHD sibling
        // of the BD arm on the SAME gate). Resolves on the explicit REPORT KEY gate
        // shape; asserted only where it resolves — the descriptor-classifier gate
        // shape has no class-3 arm, so UHD is intentionally unavailable there.
        if let Ok((uhd, _bytes)) = eng.uhd_gate_detour(&bytes, super::FLAG_TABLE_BASE) {
            assert!(uhd != 0, "UHD media-gate arm @ {disp}");
        }
        // The SRAM scanner is model-agnostic — it must resolve a free gap on every
        // VID-capable owned image. The Speed/Region/DE finders are BU40N-shaped, so
        // other hoard models are not asserted fleet-wide here.
        eng.find_free_sram_cell(&bytes)
            .unwrap_or_else(|e| panic!("free SRAM cell @ {disp}: {e}"));
    }
    assert!(
        vid_capable >= required.len(),
        "expected several VID-capable owned images, found {vid_capable}"
    );
    eprintln!("fleet finder check: {vid_capable} VID-capable owned images verified");
}

/// The SRAM scanner must return the base of the LARGEST unreferenced gap, derived
/// purely from the image — no hoard needed. A single `ldr r0,[pc,#0]` pins one
/// low SRAM cell as used; the whole high tail is then the largest free gap.
#[test]
fn find_free_sram_cell_picks_largest_unreferenced_gap() {
    let mut img = vec![0u8; 8];
    img[0..2].copy_from_slice(&0x4800u16.to_le_bytes()); // ldr r0,[pc,#0]
    img[4..8].copy_from_slice(&0x0200_0010u32.to_le_bytes()); // literal -> SRAM cell
    let cell = Mt1959Engine
        .find_free_sram_cell(&img)
        .expect("a free gap must exist");
    // 0x02000010..0x02000014 is used; the largest gap is the high tail, whose base
    // (0x02000014) is already 4-aligned.
    assert_eq!(cell, 0x0200_0014);
}

/// Base-register reach: a literal used as `[rX,#off]` marks the whole span, so the
/// gap after it starts past the accessed offset.
#[test]
fn find_free_sram_cell_marks_base_register_reach() {
    // ldr r0,[pc,#0]; ldrb r1,[r0,#0x1f]; then the literal.
    let mut img = vec![0u8; 12];
    img[0..2].copy_from_slice(&0x4800u16.to_le_bytes()); // ldr r0,[pc,#0]
    img[2..4].copy_from_slice(&0x7fc1u16.to_le_bytes()); // ldrb r1,[r0,#0x1f]
                                                         // pool = ((0+4)&!3)+0 = 4
    img[4..8].copy_from_slice(&0x0200_0010u32.to_le_bytes()); // base literal
    let cell = Mt1959Engine.find_free_sram_cell(&img).unwrap();
    // 0x02000010..(0x02000010+0x1f+1)=0x02000030 marked used → high gap base 0x30.
    assert_eq!(cell, 0x0200_0030);
}

/// A valid `ldr r0,[pc,#0]` whose literal pool (offset 4) lies past this 2-byte
/// image must decode to None, never panic — the SRAM scan reaches the image
/// tail and OEM images may be malformed.
#[test]
fn pc_literal_past_the_image_tail_is_none_not_panic() {
    assert_eq!(super::pc_literal(&0x4800u16.to_le_bytes(), 0), None);
}

/// STATIC behavioral guard for the re-slotted feature-flag gating — the mapping
/// this test protects does NOT change on a version bump, unlike the byte snapshot
/// above. It fails loudly if a stub reads the wrong feature cell or gates on the
/// wrong value. Each stub reads its own `flag[Feature::X]` (`flag_base + id`) and
/// arms on `STATE_ON` (0x01):
///   AKE null / Gate-A → flag[Ake] (0x06), gate `cmp r2,#STATE_OFF` (0x2A00)
///   Bus off           → flag[Bus] (0x07), gate `cmp r3,#STATE_OFF` (0x2B00)
///   UHD force         → flag[Uhd] (0x03), gate `cmp r3,#STATE_ON`  (0x2B01)
///   Speed / Region    → flag[Speed] (0x01) / flag[Region] (0x02)
/// Thumb `cmp rN,#imm8` = `0x2800 | (N<<8) | imm`.
#[test]
fn feature_flag_gating_is_reslotted() {
    use crate::abi::Feature;
    fn has(hay: &[u8], n: u16) -> bool {
        hay.windows(2)
            .any(|w| u16::from_le_bytes([w[0], w[1]]) == n)
    }
    fn reads(hay: &[u8], cell: u32) -> bool {
        hay.windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == cell)
    }
    const CMP_R3_ON: u16 = 0x2B01; // cmp r3,#STATE_ON (UHD/Region enable direction)
    const CMP_R2_OFF: u16 = 0x2A00; // cmp r2,#STATE_OFF (AKE/Bus off-direction)
    let base = super::FLAG_TABLE_BASE;

    let ake = Mt1959Engine
        .build_ake_stub(base, 0x0010_0000)
        .expect("ake stub");
    assert!(
        has(&ake, CMP_R2_OFF),
        "AKE-null stub gates on cmp r2,#STATE_OFF (bypass on OFF)"
    );
    assert!(
        reads(&ake, base + Feature::Ake as u32),
        "AKE-null stub reads flag[Ake]"
    );

    let gatea = Mt1959Engine
        .build_gatea_stub(base, 0x0010_0000, 0x0010_0100, 0x0010_0200)
        .expect("gatea stub");
    assert!(
        has(&gatea, CMP_R2_OFF),
        "Gate-A stub gates on cmp r2,#STATE_OFF (AKE bypass on OFF)"
    );
    assert!(
        reads(&gatea, base + Feature::Ake as u32),
        "Gate-A stub reads flag[Ake] (pre-authenticated path)"
    );

    let busenc = Mt1959Engine
        .build_busenc_stub(base, 0x0009_4790)
        .expect("busenc stub");
    assert!(
        has(&busenc, CMP_R3_OFF),
        "bus-off stub gates on cmp r3,#STATE_OFF"
    );
    assert!(
        reads(&busenc, base + Feature::Bus as u32),
        "bus-off stub reads flag[Bus]"
    );
    // Materializes BUSENC_REG (movs r1,#1; lsls r1,r1,#26), clears the enable bit
    // (movs r3,#0x10; bics r2,r3), and replays the OEM key-prog call through r4
    // (blx r4 — NOT a low arg register, so the key-prog args in r0-r3 survive).
    for (needle, what) in [
        (0x2101u16, "movs r1,#1 (BUSENC_REG base)"),
        (0x0689u16, "lsls r1,r1,#26 (BUSENC_REG = 1<<26)"),
        (0x2310u16, "movs r3,#0x10 (BUSENC_ENABLE_BIT)"),
        (0x439au16, "bics r2,r3 (clear the bus-enc enable bit)"),
        (
            0x47a0u16,
            "blx r4 (replay OEM key-prog; r0-r3 args preserved)",
        ),
    ] {
        assert!(has(&busenc, needle), "busenc stub must emit {what}");
    }

    // UHD media-gate arm gates on `cmp r3,#STATE_OFF` (0x2B00) — the uniform `0x00`
    // OFF, symmetric with the BD arm on the same accept gate — and reads flag[Uhd].
    let uhd = Mt1959Engine
        .build_uhd_gate_stub(base)
        .expect("uhd gate stub");
    assert!(
        has(&uhd, CMP_R3_OFF),
        "UHD gate stub gates on cmp r3,#STATE_OFF"
    );
    assert!(
        reads(&uhd, base + Feature::Uhd as u32),
        "UHD gate stub reads flag[Uhd]"
    );

    let speed = Mt1959Engine
        .build_speed_stub(base, 0x0001_0000, 0x0001_0100, 2)
        .expect("speed stub");
    assert!(
        reads(&speed, base + Feature::Speed as u32),
        "Speed stub reads flag[Speed]"
    );

    let region = Mt1959Engine.build_region_stub(base).expect("region stub");
    assert!(
        reads(&region, base + Feature::Region as u32),
        "Region stub reads flag[Region]"
    );

    // BD-refuse gates on `cmp r3,#STATE_OFF` (0x2B00) — the uniform `0x00` OFF (the
    // old distinct `0x02` sentinel is retired; the boot hook keeps `0x00` unreachable
    // at power-on) — and reads flag[Bd] (0x04).
    const CMP_R3_OFF: u16 = 0x2B00; // cmp r3,#STATE_OFF
    let bd = Mt1959Engine.build_bd_stub(base).expect("bd stub");
    assert!(
        has(&bd, CMP_R3_OFF),
        "BD-refuse stub gates on cmp r3,#STATE_OFF"
    );
    assert!(
        !has(&bd, 0x2B02),
        "BD-refuse stub must NOT gate on the retired `cmp r3,#0x02` sentinel"
    );
    assert!(
        reads(&bd, base + Feature::Bd as u32),
        "BD-refuse stub reads flag[Bd]"
    );

    // Region tri-state encodes all three canonical states: reads flag[Region], gates
    // on `cmp r3,#STATE_ON` (0x2B01, region-free) and `cmp r3,#STATE_OFF` (0x2B00,
    // region-locked). The locked arm materializes RegionMask 0xFF (`movs r2,#0xFF`).
    assert!(
        has(&region, CMP_R3_ON),
        "Region stub encodes ON (region-free)"
    );
    assert!(
        has(&region, CMP_R3_OFF),
        "Region stub encodes OFF (region-locked)"
    );
    assert!(
        has(&region, 0x22FF),
        "Region OFF materializes RegionMask 0xFF (movs r2,#0xFF)"
    );

    // Speed (idx_reg=2) encodes ON (unlimited) as `cmp r0,#STATE_ON` (0x2801) and
    // OEM as `cmp r2,#0x32` (0x2A32). OFF (0x00) is NOT a special case: it reaches the
    // floor via the explicit-cap path (`cmp r2,r0`), so the retired `cmp r0,#STATE_OFF`
    // (0x2800) branch back to OEM must be gone.
    assert!(
        has(&speed, 0x2801),
        "Speed stub gates ON on cmp r0,#STATE_ON"
    );
    assert!(
        has(&speed, 0x2A32),
        "Speed stub keeps the OEM 0x32 band compare"
    );
    assert!(
        !has(&speed, 0x2800),
        "Speed stub must not route STATE_OFF (0x00) back to OEM — 0x00 is the floor cap"
    );
}

/// The HRL-skip stub (`flag[Feature::Hrl]==STATE_OFF`) must read `flag[Hrl]`, gate
/// on `cmp r3,#STATE_OFF` (0x2B00), and carry the 6F/00 revoke target as a literal.
#[test]
fn hrl_skip_stub_gates_on_hrl_cell() {
    let base = super::FLAG_TABLE_BASE;
    let stub = Mt1959Engine
        .build_hrl_skip_stub(base, 0x0013_63ba)
        .expect("hrl skip stub");
    assert!(
        stub.windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])
                == base + crate::abi::Feature::Hrl as u32),
        "HRL-skip stub reads flag[Hrl]"
    );
    assert!(
        stub.windows(2)
            .any(|w| u16::from_le_bytes([w[0], w[1]]) == 0x2B00),
        "HRL-skip stub gates on cmp r3,#STATE_OFF (skip on OFF)"
    );
    assert!(
        stub.windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == (0x0013_63ba | 1)),
        "HRL-skip stub carries the 6F/00 revoke target"
    );
}

/// The gated HRL wipe-once record codegen: a well-formed valid-empty AACS HRL
/// (record type 0x21, total-entries 0x0000 — NOT the 0xFFFF blank sentinel). The
/// destructive on-drive flash program stays gated off by default.
#[test]
fn hrl_valid_empty_record_is_count_zero_type_0x21() {
    let r = Mt1959Engine.hrl_valid_empty_record();
    assert_eq!(r[0], 0x21, "record type = Host Revocation List (0x21)");
    assert_eq!(
        &r[4..6],
        &[0x00, 0x00],
        "total entries = 0 (NOT the 0xFFFF blank sentinel)"
    );
    assert_ne!(
        &r[4..6],
        &[0xFF, 0xFF],
        "must never emit the blank sentinel"
    );
    // The destructive on-drive HRL wipe stays gated off by default.
    if super::HRL_WIPE_ARMED {
        panic!("destructive HRL wipe must stay gated off by default");
    }
}

/// STATIC encoding guard for the **classic** AKE accept stub (`build_ake_stub_classic`).
/// It must (a) replay the overwritten `lsrs r0,r0,#6` as its FIRST instruction (the
/// classic reject writer folds the AGID compute into the 4 replaced bytes), (b) gate
/// on `cmp r2,#STATE_OFF` (null AKE bypass), and (c) carry both the OEM reject `movs r1,#1`
/// and the forced-accept `movs r1,#6`. Thumb: `lsrs r0,r0,#6` = 0x0980,
/// `cmp r2,#STATE_OFF` = 0x2A00.
#[test]
fn classic_ake_stub_replays_lsrs_and_gates_on_state_on() {
    fn has_u16le(hay: &[u8], needle: u16) -> bool {
        hay.windows(2)
            .any(|w| u16::from_le_bytes([w[0], w[1]]) == needle)
    }
    let stub = Mt1959Engine
        .build_ake_stub_classic(super::FLAG_TABLE_BASE, 0x0010_0000)
        .expect("classic ake stub");
    assert_eq!(
        u16::from_le_bytes([stub[0], stub[1]]),
        0x0980,
        "first instruction must replay `lsrs r0,r0,#6`"
    );
    assert!(
        has_u16le(&stub, 0x2A00),
        "must gate on cmp r2,#STATE_OFF (null AKE bypass)"
    );
    assert!(
        has_u16le(&stub, 0x2101),
        "must carry the OEM reject `movs r1,#1`"
    );
    assert!(
        has_u16le(&stub, 0x2106),
        "must carry the forced-accept `movs r1,#6`"
    );
    assert!(
        !has_u16le(&stub, 0x2A02),
        "classic AKE stub must NOT gate on the old `cmp r2,#2` (04 02) value"
    );
}

/// STATIC guard against the class of bug that wedged the drive: the control
/// toggles (Speed/Region/Raw Read) return a ZERO-length GOOD, so the handler must
/// carry NO data payload for them. The old build shipped "Command NN WIP"
/// placeholder strings that were committed as a 64-byte response — fatal for a
/// command the host issues with no data phase (ABORTED COMMAND → wedged FIFO).
/// This pins the fix independent of the byte snapshot: if anyone reintroduces a
/// per-subfn placeholder payload, the ASCII shows up in the handler and this fails.
#[test]
fn handler_carries_no_placeholder_payloads() {
    // Hex for the ASCII that must never appear in the handler again.
    assert!(
        !EXPECT_HANDLER_HEX.contains("574950"), // "WIP"
        "handler must not contain the ASCII 'WIP' placeholder payload"
    );
    assert!(
        !EXPECT_HANDLER_HEX.contains("436f6d6d616e64"), // "Command"
        "handler must not contain the ASCII 'Command NN WIP' placeholder payload"
    );
}

// --- RE-derived variant signatures (research/hoard-campaign-2026-09-03) ---------
//
// These lock the wiring of the NB-class VID gate and the r0 speed gate discovered
// this pass. They are pure synthetic buffers (no owned image needed) that assert
// (a) the variant is found where the original is absent, and (b) the original is
// still preferred when present — the invariant that keeps the KAT byte-identical.

/// Write little-endian halfwords into `img` starting at `off`.
fn put_hw(img: &mut [u8], off: usize, hws: &[u16]) {
    for (k, &h) in hws.iter().enumerate() {
        img[off + 2 * k..off + 2 * k + 2].copy_from_slice(&h.to_le_bytes());
    }
}

#[test]
fn speed_gate_finds_r0_variant_and_prefers_original() {
    // r0 variant: `ldr r1,[pc]; ldrb r0,[r1]; cmp r0,#0x32; bhi` → reg 0.
    let mut img = vec![0u8; 0x2_0010];
    put_hw(&mut img, 0x1_1000, &[0x4900, 0x7808, 0x2832, 0xD800]);
    let (off, reg) = Mt1959Engine.find_speed_gate(&img).unwrap();
    assert_eq!(off, 0x1_1000);
    assert_eq!(reg, 0, "variant register");

    // original (r2) present alongside → original wins (reg 2), variant ignored.
    put_hw(&mut img, 0x1_2000, &[0x4900, 0x780A, 0x2A32, 0xD800]);
    let (off, reg) = Mt1959Engine.find_speed_gate(&img).unwrap();
    assert_eq!(off, 0x1_2000);
    assert_eq!(reg, 2, "original preferred when present");
}

#[test]
fn vid_gate_finds_nb_variant_when_original_absent() {
    // NB variant: the two leading halfwords differ (`adds r0,r0,r1; ldr r1,[r5]`),
    // the gate `ldrb r0,[r0]; cmp r0,#6; bne` sits at match+16.
    let nb: [u16; 11] = [
        0x1840, 0x6829, 0x1808, 0x4900, 0x0200, 0x6809, 0x0A00, 0x1840, 0x7800, 0x2806, 0xD100,
    ];
    let mut img = vec![0u8; 0x18_1000];
    put_hw(&mut img, 0x13_0000, &nb);
    let off = Mt1959Engine.find_vid_gate(&img).unwrap();
    assert_eq!(off, 0x13_0000);
    // the `ldrb r0,[r0]` gate is at match+16 for both variants.
    assert_eq!(
        u16::from_le_bytes([img[off + 16], img[off + 17]]),
        0x7800,
        "gate ldrb at match+16"
    );

    // the r6 base-register form (`ldr r1,[r6]` = 0x6831) also matches (masked field).
    let mut img6 = vec![0u8; 0x18_1000];
    let mut nb6 = nb;
    nb6[1] = 0x6831;
    put_hw(&mut img6, 0x13_0000, &nb6);
    assert_eq!(Mt1959Engine.find_vid_gate(&img6).unwrap(), 0x13_0000);
}

#[test]
fn ake_gate_finds_nb_variant_and_original_absent() {
    // NB-class AKE gate: AGID via r4 (`ldrb r0,[r4,#0xa]` = 0x7AA0), accept
    // (`movs r1,#6`) and reject (`movs r1,#1`) arms converge on a shared
    // `bl set_agid_state` at anchor+12 (the reject writer is a bare `movs r1,#1`
    // at anchor+10).
    let nb: [u16; 6] = [0x7AA0, 0x0980, 0x2106, 0xE000, 0x0980, 0x2101];
    let mut img = vec![0u8; 0x14_1000];
    put_hw(&mut img, 0x13_4000, &nb);
    put_hw(&mut img, 0x13_4000 + 12, &[0xF000, 0xF800]); // shared bl (any target)
    assert_eq!(Mt1959Engine.find_ake_gate_nb(&img).unwrap(), 0x13_4000);
    // the reject writer sits at anchor+10 — the NB detour precondition.
    assert_eq!(
        u16::from_le_bytes([img[0x13_4000 + 10], img[0x13_4000 + 11]]),
        0x2101
    );
    // the original (r5, twin-`ldrb`) signature must NOT match the NB idiom, and
    // absence is a clean error (→ RawRead SignatureNotFound), never a panic.
    assert!(
        Mt1959Engine.find_ake_gate(&img).is_err(),
        "original AKE sig must miss on the NB idiom"
    );
    assert!(Mt1959Engine
        .find_ake_gate_nb(&vec![0u8; 0x14_1000])
        .is_err());
}

/// The desktop AKE gate (the `04 01/02/03` anchor). Success writer `movs r1,#6` at
/// index 2 (anchor+4), its `b <set_agid_state>` at index 3 (anchor+6); reset writer
/// `movs r1,#1` at index 6 (anchor+12).
/// The invariant tail of the AACS opcode-0x45 arm body (after its leading 4-byte
/// `bl <key-prog>`), variant A (BU40N/notebook order) and variant B (BH/WH desktop
/// order). Prefixed at build time with a real `bl` to the synthetic key-prog target.
const ARM_A_TAIL: [u16; 6] = [0x2006, 0x4900, 0x4360, 0x310C, 0x5A08, 0x9009];
const ARM_B_TAIL: [u16; 5] = [0x2006, 0x4360, 0x4900, 0x5A08, 0x9009];

/// Lay down a synthetic opcode-0x45 arm (leading `bl <keyprog>` + body tail) at
/// `anchor` and return the image.
fn arm_image(anchor: usize, keyprog: u32, tail: &[u16]) -> Vec<u8> {
    let mut img = vec![0u8; 0x14_1000];
    let bl = crate::thumb::encode_bl(anchor, keyprog).expect("bl encodes");
    crate::thumb::write(&mut img, anchor, &bl);
    put_hw(&mut img, anchor + 4, tail);
    img
}

/// `busenc_detour` must resolve variant A's opcode-0x45 arm, return the arm's
/// leading `bl` as the detour site, and emit a stub that REPLAYS the decoded
/// key-prog target — on a synthetic arm, no owned image needed.
#[test]
fn busenc_detour_resolves_arm_variant_a() {
    let anchor = 0x9_5000usize;
    let keyprog = 0x9_4790u32;
    let img = arm_image(anchor, keyprog, &ARM_A_TAIL);
    let (site, bytes) = Mt1959Engine
        .busenc_detour(&img, super::FLAG_TABLE_BASE)
        .expect("busenc detour must resolve on the variant-A arm");
    assert_eq!(site, anchor, "detour replaces the arm's leading bl");
    // The stub must carry the decoded key-prog target as a literal (| thumb bit) so
    // it can replay the OEM key-programming call.
    let carries = bytes
        .windows(4)
        .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == (keyprog | 1));
    assert!(
        carries,
        "stub must replay the decoded key-prog call (keyprog|1)"
    );
}

/// `busenc_detour` must also resolve the BH/WH desktop variant-B arm shape (tried
/// after A), same detour-site + key-prog-replay contract.
#[test]
fn busenc_detour_resolves_arm_variant_b() {
    let anchor = 0x9_6000usize;
    let keyprog = 0x9_4568u32;
    let img = arm_image(anchor, keyprog, &ARM_B_TAIL);
    let (site, bytes) = Mt1959Engine
        .busenc_detour(&img, super::FLAG_TABLE_BASE)
        .expect("busenc detour must resolve on the variant-B arm");
    assert_eq!(site, anchor, "detour replaces the arm's leading bl");
    assert!(
        bytes
            .windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == (keyprog | 1)),
        "stub must replay the decoded key-prog call"
    );
}

/// `busenc_detour` must return a clean error (never panic, never mis-patch) when the
/// arm body matches neither variant — the `04 03` mode is then left unwired.
#[test]
fn busenc_detour_errors_on_unknown_arm() {
    let mut img = arm_image(0x9_5000, 0x9_4790, &ARM_A_TAIL);
    // Corrupt the `str r0,[sp,#0x24]` tail halfword so neither SIG_A nor SIG_B matches.
    put_hw(&mut img, 0x9_5000 + 4 + 2 * 5, &[0x9008]);
    assert!(
        Mt1959Engine
            .busenc_detour(&img, super::FLAG_TABLE_BASE)
            .is_err(),
        "an unknown opcode-0x45 arm must yield a clean error, never a wrong patch"
    );
}

/// The bus-off stub must assemble, be halfword-aligned, gate on `cmp r3,#STATE_OFF`,
/// materialize `BUSENC_REG` (`1<<26`) and clear `BUSENC_ENABLE_BIT`, and read the
/// Bus feature cell (`flag_base + Feature::Bus`).
#[test]
fn busenc_stub_is_wellformed_and_encodes_the_decision() {
    let bytes = Mt1959Engine
        .build_busenc_stub(super::FLAG_TABLE_BASE, 0x0009_4790)
        .expect("stub assembles");
    assert!(!bytes.is_empty());
    assert_eq!(bytes.len() % 2, 0, "Thumb code is halfword-aligned");
    let has = |n: u16| {
        bytes
            .windows(2)
            .any(|w| u16::from_le_bytes([w[0], w[1]]) == n)
    };
    assert!(has(0x2B00), "gates on cmp r3,#STATE_OFF (bus off on OFF)");
    assert!(
        has(0x2101) && has(0x0689),
        "materializes BUSENC_REG (1<<26)"
    );
    assert!(
        has(0x2310) && has(0x439A),
        "clears BUSENC_ENABLE_BIT (movs r3,#0x10; bics r2,r3)"
    );
    // Reads the Bus feature flag byte (flag_base + Feature::Bus).
    let flag_cell = super::FLAG_TABLE_BASE + crate::abi::Feature::Bus as u32;
    let reads_flag = bytes
        .windows(4)
        .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == flag_cell);
    assert!(reads_flag, "stub loads &flag[Bus] as a literal");
}

/// TEMPORARY flash-write probe ([`abi::Verb::FlashWrite`]): the destination
/// allowlist is a compile-time constant that provably brackets ONLY the safe
/// erased non-CMAC gap, and the emitted handler must actually range-check
/// against both bounds, stage through the SRAM scratch cell, and call the OEM
/// PROGRAM routine. This is the safety proof that the probe verb can physically
/// only write `[0x1ED000, 0x1EF000)`.
#[test]
fn flashwrite_probe_is_range_bounded_to_the_safe_cell() {
    use super::{
        FLAG_TABLE_BASE, FLASHWRITE_ALLOW_HI, FLASHWRITE_ALLOW_LO, FLASHWRITE_REFUSE_STATUS,
        FLASHWRITE_SCRATCH_OFF,
    };

    // Compile-time bound proof: the window is the NV block 0x1EA000..0x1EB000 — the
    // SAVE home. Corpus-wide block-writability scan (all 118 OEM images) proves this
    // block is OEM-WRITTEN in every image (holds the region record at 0x1EA4B0), so the
    // flash controller unlocks it — writes here PERSIST. Its head 0x1EA000..0x1EA4B0 is
    // blank in every image and outside CMAC coverage (corpus-wide max covered end is
    // 0x1CFFFF). The retired 0x1ED000 and 0x1D0000 windows were ALWAYS-BLANK/never
    // OEM-written = controller-LOCKED (writes did not persist — the failed hardware
    // probe). These are const asserts so a bad widening fails to compile.
    const _: () = {
        assert!(FLASHWRITE_ALLOW_LO == 0x001E_A000);
        assert!(FLASHWRITE_ALLOW_HI == 0x001E_B000);
        assert!(FLASHWRITE_ALLOW_LO < FLASHWRITE_ALLOW_HI);
        // must clear the corpus-wide max CMAC-covered end (0x1CFFFF)
        assert!(FLASHWRITE_ALLOW_LO >= 0x001E_A000);
        // stays within the single unlocked NV block
        assert!(FLASHWRITE_ALLOW_HI <= 0x001E_B000);
        // must be 4-KiB erase-sector aligned
        assert!(FLASHWRITE_ALLOW_LO.is_multiple_of(0x1000));
        assert!(FLASHWRITE_ALLOW_HI.is_multiple_of(0x1000));
    };

    let Some(base) = load_base() else {
        eprintln!("SKIP: KAT base image not present (set FREEMKV_KAT_BASE)");
        return;
    };
    let report = Mt1959Engine
        .create(&base)
        .expect("create must succeed on the OEM base");
    let hb = &report.handler_bytes;
    let has_u32 = |v: u32| {
        hb.windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == v)
    };

    // Both allowlist bounds are materialized as literals — the runtime range
    // check that gates the PROGRAM call.
    assert!(
        has_u32(FLASHWRITE_ALLOW_LO),
        "handler must load the allowlist LO bound for the range check"
    );
    assert!(
        has_u32(FLASHWRITE_ALLOW_HI),
        "handler must load the allowlist HI bound for the range check"
    );
    // The OEM flash PROGRAM routine (thumb bit set) is the call target — its VA is
    // now recovered by the signature finder (0x13da2a on BU40N), not a hardcoded const.
    let flash_program = Mt1959Engine
        .find_flash_program(&base)
        .expect("flash PROGRAM routine must resolve on the base");
    assert_eq!(flash_program, 0x0013_da2a, "BU40N flash PROGRAM VA");
    assert!(
        has_u32(flash_program | 1),
        "handler must call the OEM flash PROGRAM routine (0x13da2a)"
    );
    // The 1-byte SRAM source-staging scratch cell literal.
    assert!(
        has_u32(FLAG_TABLE_BASE + FLASHWRITE_SCRATCH_OFF),
        "handler must stage the source byte via the SRAM scratch cell"
    );
    // The distinct refuse status word for the out-of-range path.
    assert!(
        has_u32(FLASHWRITE_REFUSE_STATUS),
        "handler must carry the refuse status sentinel"
    );
}

/// The never-abort MODIFY driver must emit byte-for-byte the same image as the
/// strict `build_report` on the all-levers-succeed base, and report every lever
/// Applied. This is what lets the framework refactor ride on the frozen KAT.
#[test]
fn create_and_modify_agree_on_base() {
    let Some(base) = load_base() else {
        eprintln!("SKIP: KAT base image not present (set FREEMKV_KAT_BASE)");
        return;
    };
    let created = Mt1959Engine
        .create(&base)
        .expect("create must succeed on the OEM base");
    let chip = crate::family::detect_chip(&base).expect("detect base");
    let cap = crate::family::capability_for(&chip.model, chip.family);
    let modified = Mt1959Engine
        .build_modify(&base, &chip, &cap)
        .expect("modify must succeed on the OEM base");

    assert_eq!(
        modified.image, created.image,
        "build_modify must be byte-identical to build_report on the base"
    );

    // Every lever is effective on the base. DowngradeEnable is AlreadyPresent
    // here because the KAT base (`DE_LG_BU40N_1.00`) already carries 0xDE at the
    // identity-page slot; the other four are freshly Applied.
    use crate::engine::lever::{LeverId, LeverOutcome};
    for l in &modified.levers {
        assert!(
            l.outcome.is_effective(),
            "lever {:?} not effective on the base: {:?}",
            l.id,
            l.outcome
        );
        if l.id != LeverId::DowngradeEnable {
            assert!(
                matches!(l.outcome, LeverOutcome::Applied),
                "lever {:?} should be Applied on the base: {:?}",
                l.id,
                l.outcome
            );
        }
    }
    assert_eq!(modified.levers.len(), 5, "Identity+Speed+Region+RawRead+DE");
}

/// The committed BU40N 1.00 fixture (third-party OEM firmware, present in-tree for
/// interoperability testing — see `tests/fixtures/README.md`). Loaded directly so
/// the signature-based finders are exercised without any environment setup.
fn bu40n_fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("BU40N fixture must be present at {path}: {e}"))
}

/// PHASE 1 invariant: the signature-based flash-PROGRAM finder must resolve to the
/// SAME address the old absolute `FLASH_PROGRAM_VA` held on BU40N (`0x13da2a`), so
/// the FlashWrite probe emits byte-identical code and the golden KAT stays frozen.
#[test]
fn find_flash_program_resolves_bu40n() {
    let img = bu40n_fixture();
    let va = Mt1959Engine
        .find_flash_program(&img)
        .expect("flash PROGRAM routine must resolve uniquely on BU40N");
    assert_eq!(
        va, 0x0013_da2a,
        "flash PROGRAM finder must resolve to the frozen BU40N VA"
    );
}

/// PHASE 1: the NV-block (SAVE home) finder must resolve to the region-record block
/// base `0x1EA000` on BU40N, purely by signature (region record `00 04 05` at
/// block+0x4B0 with a blank head) — no hardcoded offset.
#[test]
fn find_nv_block_resolves_bu40n() {
    let img = bu40n_fixture();
    let base = Mt1959Engine
        .find_nv_block(&img)
        .expect("NV block must resolve uniquely on BU40N");
    assert_eq!(
        base, 0x001E_A000,
        "NV/SAVE block base must be the frozen 0x1EA000"
    );
    // structural: the region record sits at base+0x4B0 and the head is blank scratch.
    assert_eq!(&img[0x1E_A4B0..0x1E_A4B3], &[0x00, 0x04, 0x05]);
    assert!(img[0x1E_A000..0x1E_A4B0].iter().all(|&b| b == 0xFF));
}

/// PHASE 1: the NV DRAM-window base pointer finder must resolve to `0x02000C78` on
/// BU40N — the SRAM global that holds the flash-write staging translation base. This
/// value is MT1959-uniform but per-image on MT1939 (7 distinct values), so SAVE must
/// signature-derive it, not hardcode.
#[test]
fn find_nv_dram_base_resolves_bu40n() {
    let img = bu40n_fixture();
    let p = Mt1959Engine
        .find_nv_dram_base(&img)
        .expect("NV DRAM-window base pointer must resolve on BU40N");
    assert_eq!(p, 0x0200_0C78, "BU40N flash-write staging base pointer");
}

/// PHASE 1: the boot-init finder must resolve to the boot-init hook site
/// (`anchor+4 == 0x13d41a`) on BU40N, and (verified in the fleet sweep) return
/// `None` on the MT1939-classic lineage rather than failing.
#[test]
fn find_boot_init_resolves_bu40n() {
    let img = bu40n_fixture();
    let site = Mt1959Engine
        .find_boot_init(&img)
        .expect("boot-init finder must not error on BU40N");
    assert_eq!(
        site,
        Some(super::BootInitSite::Modern(0x0013_d41a)),
        "boot-init finder must resolve BU40N via the MODERN signature to the frozen hook site"
    );
}

/// PHASE 2: the always-on boot-init trampoline. `build_boot_init` must preserve the
/// original init call's args, fill the flag table (slot 0 marker + features 1..=7)
/// with the baked [`super::DEFAULT_FLAGS`] (UHD/BD = `STATE_ON`, the rest `0xFF`
/// passthrough), then apply the persisted config ONLY when NV slot-0 marker != 0xFF
/// (marker-gated overlay), then tail-call `orig_init` and return. No default is
/// `0x00`, so a freshly powered drive still never sees an OFF flag at boot (the
/// invariant that keeps tri-state `0x00 == OFF` safe). It must NOT replay the
/// boot-status reload (that stays at the old `anchor+4` site).
#[test]
fn build_boot_init_fills_defaults_marker_gated_and_tail_calls_orig() {
    let base = super::FLAG_TABLE_BASE;
    let orig_init = 0x000a_1dd0u32; // BU40N convergence bl target
    let stub = Mt1959Engine
        .build_boot_init(base, orig_init, super::SAVE_HOME)
        .expect("boot-init stub");
    let has16 = |v: u16| {
        stub.windows(2)
            .any(|w| u16::from_le_bytes([w[0], w[1]]) == v)
    };
    let has32 = |v: u32| {
        stub.windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == v)
    };
    // Preserves orig_init's args + lr: `push {r0,r1,r2,r3,lr}` (0xB50F).
    assert!(has16(0xB50F), "boot stub pushes {{r0-r3,lr}}");
    // Loads the flag-table base as a literal.
    assert!(has32(base), "boot stub loads the flag-table base");
    // Materializes the DEFAULTS: 0xFF passthrough (movs r1,#0xFF = 0x21FF) for the
    // OEM-default features AND 0x01 STATE_ON (movs r1,#0x01 = 0x2101) for UHD/BD.
    assert!(
        has16(0x21FF),
        "boot stub materializes 0xFF passthrough default"
    );
    assert!(
        has16(0x2101),
        "boot stub materializes 0x01 (UHD/BD ship ON by default)"
    );
    // Sanity on the constant itself: UHD and BD default ON, everything else OFF-safe
    // (never 0x00) passthrough.
    assert_eq!(
        super::DEFAULT_FLAGS[crate::abi::Feature::Uhd as usize],
        crate::abi::STATE_ON,
        "UHD default is ON"
    );
    assert_eq!(
        super::DEFAULT_FLAGS[crate::abi::Feature::Bd as usize],
        crate::abi::STATE_ON,
        "BD default is ON"
    );
    assert!(
        super::DEFAULT_FLAGS
            .iter()
            .all(|&b| b != crate::abi::STATE_OFF),
        "no default may be 0x00 (would make a fresh drive boot a feature OFF)"
    );
    // Eight `strb r1,[r0,#off]` (0x7001 | off<<6) — off 0..=7 (slot 0 marker + all 7 flags).
    for off in 0u16..=7 {
        assert!(has16(0x7001 | (off << 6)), "boot stub writes flag[{off}]");
    }
    // Marker-gated overlay: loads SAVE_HOME as a literal, reads the slot-0 marker,
    // and compares it to 0xFF (cmp r1,#0xFF = 0x29FF) — the "is a config saved?" gate.
    assert!(
        has32(super::SAVE_HOME),
        "boot stub loads the SAVE_HOME literal"
    );
    assert!(
        has16(0x29FF),
        "boot stub tests the saved-marker against 0xFF (marker-gated overlay)"
    );
    // Restores the args before the tail-call: `pop {r0,r1,r2,r3}` (0xBC0F).
    assert!(
        has16(0xBC0F),
        "boot stub pops {{r0-r3}} before tail-calling"
    );
    // Loads orig_init with the Thumb bit set and tail-calls it: `blx r3` (0x4798).
    assert!(has32(orig_init | 1), "boot stub loads orig_init|1");
    assert!(has16(0x4798), "boot stub tail-calls orig_init via blx r3");
    // Returns to conv+4: `pop {pc}` (0xBD00).
    assert!(has16(0xBD00), "boot stub returns via pop {{pc}}");
    // Must NOT replay the boot-status reload (left in place at anchor+4).
    assert!(
        !has16(0x6980),
        "boot stub must not replay ldr r0,[r0,#0x18]"
    );
    assert!(!has16(0x0600), "boot stub must not replay lsls r0,r0,#0x18");
}

/// PHASE 2: `emit_boot_init` on the BU40N fixture must follow the anchor's `bmi` to
/// the cold/warm convergence `bl <orig_init>` (0x13d428, orig_init = 0xa1dd0) and
/// detour THAT — not the pre-clear reload at anchor+4 (0x13d41a, left untouched) —
/// landing a stub that tail-calls orig_init.
#[test]
fn emit_boot_init_installs_detour_on_bu40n() {
    let img = bu40n_fixture();
    let conv = 0x0013_d428_usize;
    let orig_init = 0x000a_1dd0u32;
    // Precondition: conv holds the original `bl <orig_init>` we repoint...
    assert_eq!(
        crate::thumb::decode_bl(&img, conv),
        Some(orig_init),
        "convergence bl decodes to orig_init"
    );
    // ...and the pre-clear reload at anchor+4 is the untouched boot-status reload.
    let reload = 0x0013_d41a_usize;
    assert_eq!(u16::from_le_bytes([img[reload], img[reload + 1]]), 0x6980);
    assert_eq!(
        u16::from_le_bytes([img[reload + 2], img[reload + 3]]),
        0x0600
    );

    let mut out = img.clone();
    let (s, stub_va) = Mt1959Engine
        .emit_boot_init(&img, &mut out, super::FLAG_TABLE_BASE)
        .expect("boot hook installs on BU40N");
    assert_eq!(s, conv as u32, "detour site is the convergence bl");
    assert!(stub_va != 0, "boot stub landed");

    // conv now holds a `bl` to the stub (recomputed via encode_bl)...
    let expected = crate::thumb::encode_bl(conv, stub_va).expect("bl encodes");
    assert_eq!(
        &out[conv..conv + 4],
        &expected,
        "boot detour bl installed at conv"
    );
    // ...and the anchor+4 reload is left byte-identical (no longer detoured).
    assert_eq!(
        &out[reload..reload + 4],
        &img[reload..reload + 4],
        "anchor+4 reload untouched"
    );
    // The stub tail-calls orig_init (loads its Thumb-tagged address) rather than
    // replaying the reload.
    let stub = &out[stub_va as usize..stub_va as usize + 0x80];
    assert!(
        stub.windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == orig_init | 1),
        "boot stub tail-calls orig_init"
    );
}

/// PHASE 2 fail-closed: an image with no boot-init site (no `BOOT_INIT_SIG`) must make
/// the build BAIL — never ship an image that would boot every feature to OFF (`0x00`).
#[test]
fn emit_boot_init_fails_closed_without_a_site() {
    let img = vec![0u8; 0x20_0000];
    let mut out = img.clone();
    let err = Mt1959Engine
        .emit_boot_init(&img, &mut out, super::FLAG_TABLE_BASE)
        .expect_err("must fail closed when no boot-init site exists");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("boot-init") && msg.contains("unsafe"),
        "fail-closed error must explain the missing boot-init site: {msg}"
    );
}

/// Fleet sweep (hoard-gated): both new finders must resolve n==1 across every owned
/// MT19xx image the engine recognises. `find_flash_program` must be unique on ALL of
/// them; `find_boot_init` is unique on the MT1959 lineage and legitimately `None` on
/// MT1939-classic — so it is asserted "either a real site or a clean None", never a
/// hard error. Skips (does not fail) when `FREEMKV_KAT_HOARD` is unset.
#[test]
fn flash_and_boot_finders_hold_across_owned_images() {
    let eng = Mt1959Engine;
    let roots = hoard_roots();
    if roots.is_empty() {
        eprintln!("SKIP: FREEMKV_KAT_HOARD unset — flash/boot finder fleet sweep skipped");
        return;
    }
    let mut files = Vec::new();
    for root in &roots {
        collect_bins(std::path::Path::new(root), &mut files);
    }
    files.sort();
    files.dedup();

    let mut checked = 0;
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        // Only images this engine recognises as a 3C target are candidates.
        if eng.find_scanner_entry(&bytes).is_err() {
            continue;
        }
        let disp = path.display();
        let va = eng
            .find_flash_program(&bytes)
            .unwrap_or_else(|e| panic!("flash PROGRAM finder @ {disp}: {e}"));
        assert!(va != 0, "flash PROGRAM VA @ {disp}");
        // boot-init: Ok(Some(site)) on MT1959, Ok(None) on MT1939-classic — both fine;
        // an Err means the signature matched more than once, which must never happen.
        eng.find_boot_init(&bytes)
            .unwrap_or_else(|e| panic!("boot-init finder @ {disp}: {e}"));
        checked += 1;
    }
    assert!(checked > 0, "expected at least one recognised owned image");
    eprintln!("flash/boot finder fleet sweep: {checked} owned images verified");
}

/// Per-family PASS matrix row for the MT19xx corpus validation below.
#[derive(Default)]
struct CorpusRow {
    total: usize,
    flash_n1: usize,
    boot_modern: usize,
    boot_classic: usize,
    boot_none: usize,
    boot_ambiguous: usize,
}

/// PHASE 3a corpus regression guard (hoard-gated): over EVERY ~2 MiB image the
/// chipset detector classifies as MT19xx (`MTEKMT1959`/`MTEKMT1939`) under
/// `FREEMKV_KAT_HOARD`, prove the two family-agnostic finders that the whole
/// portability claim rests on:
///
/// * `find_flash_program` resolves n==1 (a real, non-zero VA) on ALL of them;
/// * `find_boot_init` resolves to exactly ONE site — `Modern` on the MT1959-shape
///   prologue, `ClassicUnconfirmed` on the MT1939-classic prologue — and is NEVER
///   ambiguous (`Err`) and NEVER `None` (unknown shape).
///
/// A per-family PASS matrix is printed, and on ANY per-image violation the test
/// panics with that matrix so a regression names the family that broke. Skips
/// (does not fail) when `FREEMKV_KAT_HOARD` is unset, so plain `cargo test` still
/// passes without the private corpus.
#[test]
fn mt19xx_corpus_finders_validate() {
    let eng = Mt1959Engine;
    let roots = hoard_roots();
    if roots.is_empty() {
        eprintln!("SKIP: FREEMKV_KAT_HOARD unset — MT19xx corpus finder validation skipped");
        return;
    }
    let mut files = Vec::new();
    for root in &roots {
        collect_bins(std::path::Path::new(root), &mut files);
    }
    files.sort();
    files.dedup();

    use crate::family::{detect_chip, ChipFamily};
    let mut rows: std::collections::BTreeMap<String, CorpusRow> = std::collections::BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();

    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(chip) = detect_chip(&bytes) else {
            continue; // not an identifiable MTK part (Pioneer/Renesas etc.)
        };
        if !matches!(chip.family, ChipFamily::Mt1959 | ChipFamily::Mt1939) {
            continue;
        }
        // Scope to images the engine RECOGNISES as a 3C target (same gate the fleet
        // sweeps and the `create` path use). Older DVD-lineage / ASUS BC-12* parts
        // that merely carry an MTEKMT19xx tag are refused cleanly by the scanner and
        // are out of scope for the tri-state build's portability claim.
        if eng.find_scanner_entry(&bytes).is_err() {
            continue;
        }
        let key = if chip.model.is_empty() {
            chip.family.label().to_string()
        } else {
            format!("{} {}", chip.family.label(), chip.model)
        };
        let row = rows.entry(key).or_default();
        row.total += 1;
        let disp = path.display();

        match eng.find_flash_program(&bytes) {
            Ok(va) if va != 0 => row.flash_n1 += 1,
            Ok(_) => failures.push(format!("flash PROGRAM VA==0 @ {disp}")),
            Err(e) => failures.push(format!("flash PROGRAM finder @ {disp}: {e}")),
        }

        match eng.find_boot_init(&bytes) {
            Ok(Some(super::BootInitSite::Modern(_))) => row.boot_modern += 1,
            Ok(Some(super::BootInitSite::ClassicUnconfirmed(_))) => row.boot_classic += 1,
            Ok(None) => {
                row.boot_none += 1;
                failures.push(format!(
                    "boot-init resolved None (unknown prologue) @ {disp}"
                ));
            }
            Err(e) => {
                row.boot_ambiguous += 1;
                failures.push(format!("boot-init AMBIGUOUS @ {disp}: {e}"));
            }
        }

        // NV/SAVE block must resolve by signature to the corpus-universal 0x1EA000.
        match eng.find_nv_block(&bytes) {
            Ok(0x001E_A000) => {}
            Ok(b) => failures.push(format!("NV block resolved 0x{b:x} != 0x1EA000 @ {disp}")),
            Err(e) => failures.push(format!("NV block finder @ {disp}: {e}")),
        }

        // Flash-write staging base pointer must resolve (per-image; value varies on
        // MT1939) and be a 4-aligned SRAM pointer — required for SAVE to persist.
        match eng.find_nv_dram_base(&bytes) {
            Ok(p) if (0x0200_0000..0x0200_2000).contains(&p) && p & 3 == 0 => {}
            Ok(p) => failures.push(format!(
                "NV DRAM base 0x{p:x} not a 4-aligned SRAM ptr @ {disp}"
            )),
            Err(e) => failures.push(format!("NV DRAM-base finder @ {disp}: {e}")),
        }
    }

    // Render the per-family matrix (always, for evidence).
    let mut matrix = String::from(
        "\nMT19xx corpus finder matrix (family: total flash_n1 modern classic none ambiguous):\n",
    );
    let (mut t_total, mut t_flash, mut t_mod, mut t_cls) = (0, 0, 0, 0);
    for (k, r) in &rows {
        matrix.push_str(&format!(
            "  {k:<32} {:>4} {:>4} {:>4} {:>4} {:>4} {:>4}\n",
            r.total, r.flash_n1, r.boot_modern, r.boot_classic, r.boot_none, r.boot_ambiguous
        ));
        t_total += r.total;
        t_flash += r.flash_n1;
        t_mod += r.boot_modern;
        t_cls += r.boot_classic;
    }
    matrix.push_str(&format!(
        "  {:<32} {t_total:>4} {t_flash:>4} {t_mod:>4} {t_cls:>4}\n",
        "TOTAL"
    ));
    eprintln!("{matrix}");

    assert!(
        t_total > 0,
        "expected at least one MT19xx image under FREEMKV_KAT_HOARD"
    );
    assert!(
        failures.is_empty(),
        "MT19xx corpus finder validation FAILED ({} violation(s)):\n{}\n{matrix}",
        failures.len(),
        failures.join("\n")
    );
    // Every MT19xx image must resolve BOTH finders cleanly.
    assert_eq!(
        t_flash, t_total,
        "find_flash_program must be n==1 on every MT19xx image"
    );
    assert_eq!(
        t_mod + t_cls,
        t_total,
        "find_boot_init must resolve exactly one site (Modern or ClassicUnconfirmed) on every image"
    );
    // Both populations must be represented (the whole point of the classic fallback).
    assert!(t_mod > 0, "expected Modern boot-init sites in the corpus");
    assert!(
        t_cls > 0,
        "expected ClassicUnconfirmed boot-init sites in the corpus"
    );
    eprintln!(
        "MT19xx corpus finders: {t_total} images — flash n==1 on all; boot-init modern {t_mod} / classic {t_cls}"
    );
}

/// PHASE 3a (hoard-gated): the classic boot-init fallback resolves, and
/// `emit_boot_init` still fails CLOSED on it. Finds the first MT1939-classic image
/// in the corpus whose `find_boot_init` returns `ClassicUnconfirmed`, asserts the
/// site's four bytes are the `ldr r0,[r0,#0x18]; lsls r0,r0,#0x18` reload
/// (`80 69 00 06`), and asserts the production emit path bails rather than shipping
/// the unblessed hook. Skips when the corpus (or any classic image) is absent.
#[test]
fn classic_boot_init_resolves_but_emit_fails_closed() {
    let eng = Mt1959Engine;
    let roots = hoard_roots();
    if roots.is_empty() {
        eprintln!("SKIP: FREEMKV_KAT_HOARD unset — classic boot-init fallback test skipped");
        return;
    }
    let mut files = Vec::new();
    for root in &roots {
        collect_bins(std::path::Path::new(root), &mut files);
    }
    files.sort();
    files.dedup();

    let mut checked = 0usize;
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(Some(super::BootInitSite::ClassicUnconfirmed(site))) = eng.find_boot_init(&bytes)
        else {
            continue;
        };
        checked += 1;
        let s = site as usize;
        // site+? : the four bytes AT the returned hook site are the reload we replay.
        assert_eq!(
            &bytes[s..s + 4],
            &[0x80, 0x69, 0x00, 0x06],
            "classic boot-init site @ {} must land on `ldr r0,[r0,#0x18]; lsls r0,r0,#0x18`",
            path.display()
        );
        // Production emit MUST fail closed on the unconfirmed classic site.
        let mut out = bytes.clone();
        let err = eng
            .emit_boot_init(&bytes, &mut out, super::FLAG_TABLE_BASE)
            .expect_err("emit_boot_init must fail closed on a ClassicUnconfirmed site");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("hardware-unconfirmed") || msg.contains("classic"),
            "fail-closed error must name the unconfirmed classic site: {msg}"
        );
        break;
    }
    if checked == 0 {
        eprintln!("SKIP: no MT1939-classic image found in the corpus for the fallback test");
    }
}
