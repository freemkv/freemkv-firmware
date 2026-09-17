//! MediaTek MT1939 engine.
//!
//! MT1939 is **two code generations** (proven across 42 real images,
//! `research/hoard-campaign-2026-09-03/reports/mt1939-engine-scope.md`):
//!
//! * **JB8 / JBP6 / JBC6** (banner `"MT1959 Boot …"`, marker `+0x50 = 0x18`, 28
//!   images) — MT1959-lineage silicon. The MT1959 scanner / CDB-base / dispatch
//!   table / VID / AKE / Speed / Region signatures **transfer unchanged**, so these
//!   images run the **full** MT1959 lever machinery ([`Mt1959Engine::build_modify`])
//!   verbatim — only the family label differs. Empirically verified: a JB8 image
//!   yields `Identity + Speed + Region + Raw read` applied + `DE`.
//! * **Classic** (banner `"MT1939 Boot Code"`, marker `+0x50 = 0x58`, 14 images) —
//!   its own scanner (`0x182e8`, CDB base in **r5** not r3), its own dispatch table
//!   (`~0x1a4000`), and its own VID/AKE code shapes. `create` now ships the classic
//!   **base** ([`Mt1959Engine::build_report_classic`]): the injected 0x3C-0E handler
//!   (Identity/SET/GET/SAVE/RESET/DumpAll) + record repoint + CMAC re-sign, proven
//!   17/17. The always-on boot hook and feature stubs stay gated behind the on-silicon
//!   boot blessing (`CLASSIC_BOOT_BLESSED`); until then `modify` still applies only the
//!   **family-agnostic downgrade-enable (DE)** lever and reports the rest as pending —
//!   never an opaque refusal.
//!
//! Integrity: `freemkv_flash::cmac` re-signs **both** generations unchanged
//! (proven zero-change, table `0x10400`), so `MtkCmac` auto-accepts MT1939.

use anyhow::{anyhow, bail, Result};

use freemkv_flash::cmac;

use super::lever::{LeverId, LeverReport};
use super::mt1959::Mt1959Engine;
use super::{CreateReport, Engine, ModifyReport};
use crate::family;

/// Downgrade-enable byte offset within the MTEK identity page (`0x1EC056`).
const DE_OFF_IN_DESCRIPTOR: usize = 0x56;

/// Classic-generation VID producer raw-read gate (`cmp auth_state,#6; bne <deny>`).
///
/// Reversed from a classic image (`STOCK_LG_BH16NS40_1.01 @ 0x17f414`), masking the
/// pc-relative `imm8`s and the `bne` displacement; the gate `cmp`/`bne` sit at
/// `match+28`/`match+30`. **Proven UNIQUE on every classic image** (engine-scope
/// report §3a). Captured here for the classic Identity-base wiring block; not yet
/// used to emit (the classic detour needs the classic handler base first).
pub(crate) const VID_GATE_SIG_CLASSIC: &[(u16, u16)] = &[
    (0x7AA8, 0xFFFF), // ldrb r0,[r5,#0xa]
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm8]   (scratch/table base)
    (0x0980, 0xFFFF), // lsrs r0,r0,#6
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm8]   (auth-state ptr A)
    (0x0400, 0xFFFF), // lsls r0,r0,#16
    (0x6809, 0xFFFF), // ldr  r1,[r1]
    (0x0C00, 0xFFFF), // lsrs r0,r0,#16
    (0x1808, 0xFFFF), // adds r0,r1,r0
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm8]   (auth-state ptr B)
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x6809, 0xFFFF), // ldr  r1,[r1]
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1840, 0xFFFF), // adds r0,r0,r1
    (0x7800, 0xFFFF), // ldrb r0,[r0]         (gate load, match+28)
    (0x2806, 0xFFFF), // cmp  r0,#6           (gate,      match+30)
    (0xD100, 0xFF00), // bne  <deny>          (detour anchor)
];

/// Classic-generation AKE accept/reject gate (writes auth-state 6/1 then
/// `bl set_agid_state`). Reversed from `STOCK_LG_BH16NS40_1.01 @ 0x17f2d4`; the
/// reject writer sits at `match+6`. **Proven UNIQUE on every classic image**
/// (engine-scope report §3b).
pub(crate) const AKE_GATE_SIG_CLASSIC: &[(u16, u16)] = &[
    (0x0980, 0xFFFF), // lsrs r0,r0,#6
    (0x2106, 0xFFFF), // movs r1,#6           (accept)
    (0xE000, 0xF800), // b    <skip reject>
    (0x0980, 0xFFFF), // lsrs r0,r0,#6        (detour site, match+6)
    (0x2101, 0xFFFF), // movs r1,#1           (reject)
    (0xF000, 0xF800), // bl   set_agid_state
];

/// Classic-generation OEM AACS opcode-`0x45` (**Read Data Key**) arm — the in-transit
/// bus-encryption key-prog path, and the classic analogue of the modern
/// [`super::core::AACS45_ARM_SIG_B`]. The arm BODY is byte-shape-identical to the
/// modern B-shape (`bl <key-prog>; movs r0,#6; muls r0,r4,r0; ldr r1,[pc]; ldrh
/// r0,[r1,r0]; str r0,[sp,#slot]`); the ONE distinguishing byte is the final spill
/// slot — classic frames spill the read-data-key halfword to `[sp,#0x1c]` (`0x9007`),
/// where the modern desktop fleet uses `#0x24` and the BD-combo drives `#0x20`. Pinning
/// `0x9007` makes this signature match **only** the classic generation (measured: unique
/// on all 17 MT1939-classic images, `0x9a382`-class arm at `~0x9c280`; **zero** matches
/// on every modern MT1959 / combo image), so the modern finder and this one never
/// cross-wire. The match offset IS the arm's leading `bl` (the detour site); its target
/// is the OEM key-prog primitive the injected stub replays.
///
/// Disasm proof (3 of 17): `BH16NS40-NS50 @0x9c280`, `BH40N @0x9c002`,
/// `BE14NU40 @0x9b942` — all `bl <key-prog>; movs r0,#6; muls r0,r4,r0; ldr r1,[pc];
/// ldrh r0,[r1,r0]; str r0,[sp,#0x1c]`.
pub(crate) const AACS45_ARM_SIG_CLASSIC: &[(u16, u16)] = &[
    (0xF000, 0xF800), // bl <key-prog>   hi   ← match = arm entry / detour site
    (0xF800, 0xF800), //                 lo
    (0x2006, 0xFFFF), // movs r0,#6
    (0x4360, 0xFFFF), // muls r0,r4,r0
    (0x4900, 0xFF00), // ldr  r1,[pc,#imm]
    (0x5A08, 0xFFFF), // ldrh r0,[r1,r0]
    (0x9007, 0xFFFF), // str  r0,[sp,#0x1c]   (classic frame slot — generation marker)
];

/// Signature of the **classic**-generation flash-resident Host-Revocation-List
/// (HRL) lookup routine — the classic-codegen analogue of [`super::core::HRL_LOOKUP_SIG`].
///
/// The classic AACS cert path checks host revocation with the SAME algorithm as
/// modern (range-lookup over 8-byte HRL records; returns `1`=host revoked,
/// `2`=blank/`0xFFFF` sentinel, `0`=clean), and the routine's first **nine**
/// halfwords are byte-identical to the modern body (`push {r0,r1,r4-r7,lr}; sub
/// sp,#0xc; ldr r0,[sp,#0xc]; movs r4,r1; bl <count-reader>; movs r7,r0; movs
/// r0,r4; bl <helper>; str r0,[sp,#8]`). It then DIVERGES: where modern does `adds
/// r0,r4,#4; lsls r1,r0,#8; ldr r0,[pc,…]` the classic scheduler emits `ldr
/// r1,[pc,…]; adds r0,r4,#4; ldr r2,[r1]; lsls r0,r0,#8; …` — a different
/// flash-address-translate order — so [`super::core::HRL_LOOKUP_SIG`] (which pins
/// modern's 10th halfword `1D20`) matches **0×** on every classic image. This
/// signature carries the shared prologue plus that classic continuation through the
/// BE-16 count read (`ldr r2,[r1]; lsls r0,r0,#8; lsrs r0,r0,#8; adds r0,r0,r2;
/// ldrb r0,[r0]; mov r3,sp; strb r0,[r3,#5]`), masking only the two body `bl`
/// displacements and the `ldr r1,[pc]` `imm8`.
///
/// **Proven UNIQUE (n==1) on every one of the 17 classic images** and **0× on all
/// 98 non-classic corpus images** — reversed from `STOCK_LG_BH16NS40` and verified
/// against the capstone traces of BE14NU40 1.00/1.01, BH14NS40, BH16NS40-NS50,
/// BH40N and WH14/16NS40-NS50. The cert path calls it and tests `cmp r0,#0; bne
/// <revoke>`; the classic revoke target carries the OEM 6F-deny head `ldrb
/// r0,[r5,#2]; cmp r0,#0; bne …; movs r0,#0x6f` (register `r5`, i.e. `0x78A8` — the
/// modern head is `r4`/`0x78A0`). Consumed by [`Mt1959Engine::emit_hrl_classic`].
pub(crate) const HRL_LOOKUP_SIG_CLASSIC: &[(u16, u16)] = &[
    (0xB5F3, 0xFFFF), // push {r0,r1,r4,r5,r6,r7,lr}
    (0xB083, 0xFFFF), // sub  sp,#0xc
    (0x9803, 0xFFFF), // ldr  r0,[sp,#0xc]
    (0x000C, 0xFFFF), // movs r4,r1
    (0xF000, 0xF800), // bl   <count-reader>  hi
    (0xF800, 0xF800), //                      lo
    (0x0007, 0xFFFF), // movs r7,r0
    (0x0020, 0xFFFF), // movs r0,r4
    (0xF000, 0xF800), // bl   <helper>        hi
    (0xF800, 0xF800), //                      lo
    (0x9002, 0xFFFF), // str  r0,[sp,#8]
    (0x4900, 0xF800), // ldr  r1,[pc,#imm8]   (classic divergence: HRL base cell)
    (0x1D20, 0xFFFF), // adds r0,r4,#4
    (0x680A, 0xFFFF), // ldr  r2,[r1]
    (0x0200, 0xFFFF), // lsls r0,r0,#8
    (0x0A00, 0xFFFF), // lsrs r0,r0,#8
    (0x1880, 0xFFFF), // adds r0,r0,r2
    (0x7800, 0xFFFF), // ldrb r0,[r0]
    (0x466B, 0xFFFF), // mov  r3,sp
    (0x7158, 0xFFFF), // strb r0,[r3,#5]
];

/// The MT1939 platform engine.
pub struct Mt1939Engine;

/// True when this MT1939 image is the classic generation (banner `"MT1939 Boot
/// Code"` at `0x3000`). JB8/JBP6/JBC6 parts carry an `"MT1959 Boot …"` banner.
fn is_classic(image: &[u8]) -> bool {
    let banner = freemkv_chipset::BANNER_OFFSET;
    image
        .get(banner..banner + 16)
        .map(|b| b.starts_with(b"MT1939 Boot"))
        .unwrap_or(false)
}

/// File offsets where masked signature `sig` matches in `image[lo..hi]` (local
/// matcher so this module stays decoupled from `core`'s private one).
pub(crate) fn masked_matches(image: &[u8], sig: &[(u16, u16)], lo: usize, hi: usize) -> Vec<usize> {
    let hi = hi.min(image.len());
    let span = sig.len() * 2;
    let mut hits = Vec::new();
    if lo + span > hi {
        return hits;
    }
    let mut off = lo;
    while off + span <= hi {
        let ok = sig.iter().enumerate().all(|(i, &(val, mask))| {
            let hw = u16::from_le_bytes([image[off + i * 2], image[off + i * 2 + 1]]);
            hw & mask == val & mask
        });
        if ok {
            hits.push(off);
        }
        off += 2;
    }
    hits
}

/// Locate the classic-generation raw-read levers' anchors (VID gate + AKE gate),
/// each required unique. Returns the two offsets when both are cleanly present.
/// Full-image scan (de-hardcoded): the classic VID/AKE gates are unique image-wide
/// on all 17 classic images, but a fixed 0x170000..0x180000 window missed the ones
/// whose AACS block is relocated (BH16NS40 ~0x139k, BE14NU40 1.01 ~0x180640). The
/// unique-match guard below keeps it safe.
fn classic_rawread_anchors(image: &[u8]) -> Option<(u32, u32)> {
    let vid = masked_matches(image, VID_GATE_SIG_CLASSIC, 0, image.len());
    let ake = masked_matches(image, AKE_GATE_SIG_CLASSIC, 0, image.len());
    match (vid.as_slice(), ake.as_slice()) {
        ([v], [a]) => Some((*v as u32, *a as u32)),
        _ => None,
    }
}

impl Engine for Mt1939Engine {
    fn name(&self) -> &'static str {
        "MT1939"
    }

    fn create(&self, image: &[u8]) -> Result<CreateReport> {
        // Classic-generation MT1939 ("MT1939 Boot Code") has its own base shape
        // (dispatch-table window, SRAM flag base, inline sense). It builds through
        // build_report_classic; the modern monolith below covers JB8/JBP6/JBC6.
        if is_classic(image) {
            return Mt1959Engine
                .build_report_classic(image)
                .map_err(|e| anyhow!("MT1939 classic create: {e:#}"));
        }
        // JB8/MT1959-lineage images build via the shared modern machinery.
        Mt1959Engine.build_report(image).map_err(|e| {
            anyhow!(
                "MT1939 create: {e:#} (base build failed; use `modify` for the \
                 downgrade-enable lever)"
            )
        })
    }

    fn modify(&self, image: &[u8]) -> Result<ModifyReport> {
        let chip = family::detect_chip(image)?;
        let cap = family::capability_for(&chip.model, chip.family);

        // JB8 / JBP6 / JBC6 (MT1959-lineage): the full MT1959 lever machinery
        // applies verbatim — the base finders, VID/AKE/Speed/Region signatures and
        // detours all transfer. Delegate and relabel the family. Any lever whose
        // signature misses (e.g. a JB8-base image whose VID uses classic
        // scheduling) is reported SignatureNotFound by the never-abort driver, so
        // the image still partial-applies.
        if !is_classic(image) {
            if let Ok(mut report) = Mt1959Engine.build_modify(image, &chip, &cap) {
                report.engine = "MT1939";
                return Ok(report);
            }
            // Fall through to the DE-only path if the shared build unexpectedly
            // fails on a non-classic image (degrade, never refuse).
        }

        // Classic generation: produce the full classic emit (Identity + Region-free
        // + DE) — structurally valid, self-verifies, passes the structural audit, so
        // it ships unconditionally (Raw-read stays withheld inside as unsafe). If the
        // classic base can't be located on this specific image, degrade to the
        // DE-only fallback below (never refuse).
        if is_classic(image) {
            if let Ok(report) = Mt1959Engine.build_modify_classic(image, &chip, &cap) {
                return Ok(report);
            }
        }

        // DE-only fallback: family-agnostic downgrade-enable when the classic base
        // isn't locatable. The classic VID/AKE gate signatures are reversed + proven
        // unique (consts above) but need the classic Identity base to emit.
        let mut out = image.to_vec();
        let mut levers = Vec::new();

        let de = if chip.descriptor_present {
            let off = family::DESCRIPTOR_OFFSET + DE_OFF_IN_DESCRIPTOR;
            if off >= out.len() {
                LeverReport::not_applicable(LeverId::DowngradeEnable, "identity page truncated")
            } else if out[off] == 0xDE {
                LeverReport::already(LeverId::DowngradeEnable, vec![("de_off", off as u32)])
            } else {
                out[off] = 0xDE;
                LeverReport::applied(LeverId::DowngradeEnable, vec![("de_off", off as u32)])
            }
        } else {
            LeverReport::not_applicable(LeverId::DowngradeEnable, "no MTEK identity page")
        };
        levers.push(de);

        // In scope for these BD-writer parts, but the classic-generation emit is
        // pending its Identity base — report precisely (never-abort partial).
        levers.push(LeverReport::missed(
            LeverId::RegionFree,
            "MT1939 classic generation — RPC emitter transfers but the flag-gated \
             detour needs the classic Identity base (sense-setter + injected handler)",
        ));
        // Raw read: the classic VID + AKE gates are reversed and proven-unique; when
        // both are located we report their offsets so the image is auditably
        // wireable, with only the classic Identity base + detour still pending.
        levers.push(match classic_rawread_anchors(image) {
            Some((vid_gate, ake_gate)) => LeverReport {
                id: LeverId::RawRead,
                outcome: super::lever::LeverOutcome::SignatureNotFound {
                    detail: "classic VID + AKE gates located (reversed, proven-unique); full \
                             raw-read detour pending the classic Identity base"
                        .to_string(),
                },
                facts: vec![
                    ("vid_gate_classic", vid_gate),
                    ("ake_gate_classic", ake_gate),
                ],
            },
            None => LeverReport::missed(
                LeverId::RawRead,
                "MT1939 classic generation — VID/AKE gate anchors not located in this image",
            ),
        });
        levers.push(LeverReport::missed(
            LeverId::Speed,
            "MT1939 classic generation — no MT1959-style ramp-ceiling gate exists (classic \
             uses a disc-type halfword read-speed clamp through a shared limiter primitive, \
             no byte speed_index ramp / no 0x32 ceiling); residual RE miss, independent of \
             the other levers",
        ));

        if !levers.iter().any(|l| l.outcome.is_effective()) {
            bail!("nothing modifiable on this MT1939 image (no identity page for the DE byte)");
        }

        let signed = cmac::resign(&out).map_err(|e| anyhow!("re-sign failed: {e}"))?;

        Ok(ModifyReport {
            engine: "MT1939",
            family: chip.family.label().to_string(),
            vendor: chip.vendor.clone(),
            model: chip.model.clone(),
            rev: chip.rev.clone(),
            vendor_specific: chip.vendor_specific.clone(),
            media: cap.media_class.label().to_string(),
            levers,
            image: signed,
            validation: super::lever::Validation::StaticOnly,
        })
    }
}

#[cfg(test)]
#[path = "mt1939_tests.rs"]
mod tests;
