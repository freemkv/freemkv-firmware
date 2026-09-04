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
//!   (`~0x1a4000`), and its own VID/AKE code shapes. The classic VID/AKE gate
//!   signatures are reversed and proven-unique (captured below), but the classic
//!   **Identity base** (its sense-setter + injectable handler) is not yet wired, so
//!   today classic images apply only the **family-agnostic downgrade-enable (DE)**
//!   lever and report the rest as pending — never an opaque refusal.
//!
//! Integrity: `freemkv_flash::cmac` re-signs **both** generations unchanged
//! (proven zero-change, table `0x10400`), so `MtkCmac` auto-accepts MT1939.

use anyhow::{anyhow, bail, Result};

use freemkv_flash::cmac;

use super::lever::{LeverId, LeverReport};
use super::mt1959::Mt1959Engine;
use super::{CreateReport, Engine, ModifyOpts, ModifyReport};
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

/// The MT1939 platform engine.
pub struct Mt1939Engine;

/// True when this MT1939 image is the classic generation (banner `"MT1939 Boot
/// Code"` at `0x3000`). JB8/JBP6/JBC6 parts carry an `"MT1959 Boot …"` banner.
fn is_classic(image: &[u8]) -> bool {
    const BANNER: usize = 0x3000;
    image
        .get(BANNER..BANNER + 16)
        .map(|b| b.starts_with(b"MT1939 Boot"))
        .unwrap_or(false)
}

/// File offsets where masked signature `sig` matches in `image[lo..hi]` (local
/// matcher so this module stays decoupled from `mt1959_build`'s private one).
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

/// Classic AACS producer window the VID/AKE gates live in (engine-scope §3).
const CLASSIC_AACS_LO: usize = 0x17_0000;
const CLASSIC_AACS_HI: usize = 0x18_0000;

/// Locate the classic-generation raw-read levers' anchors (VID gate + AKE gate),
/// each required unique. Returns the two offsets when both are cleanly present.
fn classic_rawread_anchors(image: &[u8]) -> Option<(u32, u32)> {
    let vid = masked_matches(
        image,
        VID_GATE_SIG_CLASSIC,
        CLASSIC_AACS_LO,
        CLASSIC_AACS_HI,
    );
    let ake = masked_matches(
        image,
        AKE_GATE_SIG_CLASSIC,
        CLASSIC_AACS_LO,
        CLASSIC_AACS_HI,
    );
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
        // JB8/MT1959-lineage classic images build via the shared machinery.
        Mt1959Engine.build_report(image).map_err(|e| {
            anyhow!(
                "MT1939 create: {e:#} (classic-generation full build is pending its Identity base; \
                 use `modify` for the downgrade-enable lever)"
            )
        })
    }

    fn modify_with(&self, image: &[u8], opts: &ModifyOpts) -> Result<ModifyReport> {
        // BETA: classic-generation full(er) emit (Identity + Region + DE) only under
        // the explicit opt-in. On any classic-base miss, degrade to the stable path.
        if opts.beta && is_classic(image) {
            let chip = family::detect_chip(image)?;
            let cap = family::capability_for(&chip.model, chip.family);
            if let Ok(report) = Mt1959Engine.build_modify_classic(image, &chip, &cap) {
                return Ok(report);
            }
        }
        self.modify(image)
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

        // Classic generation: only the family-agnostic DE lever is wired. The
        // classic VID/AKE gate signatures are reversed + proven unique (see the
        // consts above), but activating them needs the classic Identity base
        // (its own sense-setter + injected handler + flag table) — the next block.
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
                beta: false,
            },
            None => LeverReport::missed(
                LeverId::RawRead,
                "MT1939 classic generation — VID/AKE gate anchors not located in this image",
            ),
        });
        levers.push(LeverReport::missed(
            LeverId::Speed,
            "MT1939 classic generation — read-ramp ceiling not yet reversed (NEEDS-RE; \
             independent of the other levers)",
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
            media: cap.media_class.label().to_string(),
            levers,
            image: signed,
        })
    }
}

#[cfg(test)]
#[path = "mt1939_tests.rs"]
mod tests;
