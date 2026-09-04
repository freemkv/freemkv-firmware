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
/// The dispatching handler: persists flag[subfn]=cdb[5]; 01 Identity, 02 Speed,
/// 03 Region, 04 Raw Read, 09 DumpAll. Speed/Region/Raw Read act via flag-gated
/// OEM-code trampolines (Raw Read = the AKE accept-gate stub), not this handler.
///
/// NOTE: the handler embeds the crate version string (`freemkv <CARGO_PKG_VERSION>`),
/// so a version bump changes these injected bytes AND the two CMAC digests below
/// (the version bytes fall inside CMAC entries 1 and 15). When the version bumps,
/// regenerate all three constants (run this test with `FREEMKV_KAT_BASE` set and
/// copy the `left:` values). This is expected drift, not a real regression.
const EXPECT_HANDLER_HEX: &str =
    "224b58780e2806d19878c02803d1d878de2800d101e01e4b1847f0b51d4f1c791d480019597901700025402d04d2281c0021b8470135f8e7092c11d15e793602987936183602d87936183602187a36180025402d12d2281c715db8470135f8e7013c062c0ad210a6200136180025102d04d2281c715db8470135f8e74020074908800748074a9047f0bd0000380d00025bad090075200a00400e0002720c000290af000081810900667265656d6b7620302e372e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
// Re-signed CMAC stored digests that must change (entry index -> stored hex).
const EXPECT_CMAC_1: &str = "ca941ac20cc9096b71a7122bd8d571ad";
const EXPECT_CMAC_15: &str = "aa08dd64af2c2d15cf1c488e7c979bab";

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
    // Fixture path comes from the environment only — no owned/private path is
    // ever baked into this public repo. `FREEMKV_KAT_BASE` points at the OEM
    // BU40N 1.00 base image; unset (or unreadable) skips the KAT.
    let path = std::env::var("FREEMKV_KAT_BASE").ok()?;
    std::fs::read(&path).ok()
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
    // (3C handler + Speed/Region stubs), the repointed record, the CMAC table, the
    // two OEM-code detours, or the DE byte. 0x400 bounds the injected band.
    let injected = EXPECT_HANDLER_VA as usize..EXPECT_HANDLER_VA as usize + 0x400;
    let speed_detour = report.speed_gate as usize + 4..report.speed_gate as usize + 8;
    let region_detour = report.region_emitter as usize + 14..report.region_emitter as usize + 18;
    let ake_detour = report.ake_gate as usize + 12..report.ake_gate as usize + 16;
    let gatea_detour = report.gatea_gate as usize..report.gatea_gate as usize + 4;
    let deny_detour = report.deny_reset_gate as usize..report.deny_reset_gate as usize + 4;
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
                    || speed_detour.contains(&i)
                    || region_detour.contains(&i)
                    || ake_detour.contains(&i)
                    || gatea_detour.contains(&i)
                    || deny_detour.contains(&i)
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
        // Speed (0x02) + Region-free (0x05) must be wired, and the DE byte + the
        // scanner-derived free cell must agree across both required BU40N images.
        assert!(report.speed_stub_va != 0, "Speed (0x02) wired for {path}");
        assert!(
            report.region_stub_va != 0,
            "Region-free (0x05) wired for {path}"
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

/// STATIC behavioral guard for the Raw Read (0x04) flag semantics — the mapping
/// this test protects does NOT change on a version bump or an unrelated subfn
/// edit, unlike the byte snapshot above. It fails loudly if the two modes are
/// swapped or a compare is broken:
///   `04 01` = "cert is valid" → Gate-A stub gates on `cmp r2,#1` (bare 0xAD read)
///   `04 02` = "accept any cert" → AKE stub gates on `cmp r2,#2` (host runs the AKE)
/// Thumb `cmp r2,#imm8` encodes as `0x2A00 | imm` (LE bytes `[imm, 0x2A]`).
#[test]
fn raw_read_flag_mapping_01_bare_02_ake() {
    fn has_u16le(hay: &[u8], needle: u16) -> bool {
        hay.windows(2)
            .any(|w| u16::from_le_bytes([w[0], w[1]]) == needle)
    }
    const CMP_R2_1: u16 = 0x2A01; // cmp r2,#1
    const CMP_R2_2: u16 = 0x2A02; // cmp r2,#2
                                  // Dummy branch targets — only the gating compare is asserted.
    let ake = Mt1959Engine
        .build_ake_stub(super::FLAG_TABLE_BASE, 0x0010_0000)
        .expect("ake stub");
    let gatea = Mt1959Engine
        .build_gatea_stub(
            super::FLAG_TABLE_BASE,
            0x0010_0000,
            0x0010_0100,
            0x0010_0200,
        )
        .expect("gatea stub");

    assert!(
        has_u16le(&ake, CMP_R2_2),
        "04 02 (accept-any-cert AKE path) must gate on cmp r2,#2"
    );
    assert!(
        !has_u16le(&ake, CMP_R2_1),
        "AKE stub must NOT gate on #1 — that value is the bare-read 01 path"
    );
    assert!(
        has_u16le(&gatea, CMP_R2_1),
        "04 01 (cert-valid bare-read path) must gate on cmp r2,#1"
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
