//! MediaTek MT1939 engine.
//!
//! Classic firmware carries an MT1939 boot banner and uses its own command,
//! boot, speed and media contracts. The other MT1939 code generation delegates
//! to the MT1959 machinery while retaining the MT1939 family label.
//!
//! Both paths install only source-qualified hooks and derive advertised settings
//! from installed facts. If the base cannot be built, `modify` can fall back to
//! downgrade-enable alone. Complete media conversion requires its whole group;
//! bounded software validation does not establish physical reading behavior.
//! Both generations use the shared MediaTek CMAC implementation.

use crate::boot::BootSettings;
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
/// pc-relative `imm8`s and the `bne` displacement; the gate
/// load/`cmp`/`bne` sit at `match+28`/`+30`/`+32`. **Proven UNIQUE on every classic
/// image** (engine-scope report §3a). The classic Gate-A detour overwrites the
/// `cmp`/`bne` pair (`emit_rawread_classic`); `classic_rawread_anchors` reuses it
/// for the degraded-path audit.
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

/// Signature of the **classic**-generation flash-resident Host-Revocation-List
/// (HRL) lookup routine — the classic-codegen analogue of [`super::core::HRL_LOOKUP_SIG`].
///
/// Same algorithm as modern (range-lookup over 8-byte HRL records; returns
/// `1`=host revoked, `2`=blank/`0xFFFF` sentinel, `0`=clean) and the first nine
/// halfwords match the modern body (`push {r0,r1,r4-r7,lr}; sub sp,#0xc; ldr
/// r0,[sp,#0xc]; movs r4,r1; bl <count-reader>; movs r7,r0; movs r0,r4; bl
/// <helper>; str r0,[sp,#8]`). It then diverges: modern does `adds r0,r4,#4; lsls
/// r1,r0,#8; ldr r0,[pc,…]`, classic does `ldr r1,[pc,…]; adds r0,r4,#4; ldr
/// r2,[r1]; lsls r0,r0,#8; …` (different flash-address-translate order), so
/// [`super::core::HRL_LOOKUP_SIG`] (pins modern's 10th halfword `1D20`) matches 0x
/// on classic. This signature covers the shared prologue plus the classic
/// continuation through the BE-16 count read, masking only the two body `bl`
/// displacements and the `ldr r1,[pc]` `imm8`.
///
/// **Proven UNIQUE (n==1) on all 17 classic images** and 0x on all 98 non-classic
/// corpus images; reversed from `STOCK_LG_BH16NS40`. The cert path calls it and
/// tests `cmp r0,#0; bne <revoke>`; the classic revoke target carries the OEM
/// 6F-deny head `ldrb r0,[r5,#2]; cmp r0,#0; bne …; movs r0,#0x6f` (`r5`/`0x78A8`;
/// modern uses `r4`/`0x78A0`). Consumed by [`Mt1959Engine::emit_hrl_classic`].
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

/// Locate the classic VID gate + AKE gate, each required unique; `None` otherwise.
/// Scans the whole image: a fixed 0x170000..0x180000 window missed images whose
/// AACS block is relocated (BH16NS40 ~0x139k, BE14NU40 1.01 ~0x180640), and the
/// unique-match requirement keeps the wide scan safe.
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
        self.create_with_defaults(image, &BootSettings::standard())
    }

    fn create_with_defaults(&self, image: &[u8], defaults: &BootSettings) -> Result<CreateReport> {
        // Classic has its own base shape (dispatch-table window, SRAM flag base,
        // inline sense); JB8/JBP6/JBC6 build via the shared MT1959 machinery below.
        if is_classic(image) {
            return Mt1959Engine
                .build_report_classic_with_defaults(image, defaults)
                .map_err(|e| anyhow!("MT1939 classic create: {e:#}"));
        }
        Mt1959Engine
            .build_report_with_defaults(image, defaults)
            .map_err(|e| {
                anyhow!(
                    "MT1939 create: {e:#} (base build failed; use `modify` for the \
                 downgrade-enable lever)"
                )
            })
    }

    fn modify(&self, image: &[u8]) -> Result<ModifyReport> {
        self.modify_with_defaults(image, &BootSettings::standard())
    }

    fn modify_with_defaults(&self, image: &[u8], defaults: &BootSettings) -> Result<ModifyReport> {
        let chip = family::detect_chip(image)?;
        let cap = family::capability_for(&chip.model, chip.family);

        // JB8 / JBP6 / JBC6 (MT1959 lineage): MT1959 finders, signatures and
        // detours transfer verbatim; delegate and relabel the engine. A lever whose
        // signature misses (e.g. a JB8-base image with classic VID scheduling) is
        // reported SignatureNotFound, so the image still partial-applies.
        // A failed base build degrades to the DE-only path below (never refuse).
        let base_err = if is_classic(image) {
            match Mt1959Engine.build_modify_classic_with_defaults(image, &chip, &cap, defaults) {
                Ok(report) => return Ok(report),
                Err(error) => error,
            }
        } else {
            match Mt1959Engine.build_modify_with_defaults(image, &chip, &cap, defaults) {
                Ok(mut report) => {
                    report.engine = "MT1939";
                    return Ok(report);
                }
                Err(error) => error,
            }
        };
        let degraded = format!("base build failed: {base_err:#}; downgrade-enable only");

        // Downgrade-enable is family-agnostic, so it survives a failed base build.
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

        // In scope for these parts; report the real base-build failure.
        levers.push(LeverReport::missed(LeverId::RegionFree, degraded.clone()));
        // Audit-only: located gate offsets are reported as facts, but no hook is
        // installed, so the outcome stays SignatureNotFound (never advertised).
        levers.push(match classic_rawread_anchors(image) {
            Some((vid_gate, ake_gate)) => LeverReport {
                id: LeverId::RawRead,
                outcome: super::lever::LeverOutcome::SignatureNotFound {
                    detail: format!(
                        "classic VID + AKE gates located (reversed, proven-unique); {degraded}"
                    ),
                },
                hooks: vec![],
                facts: vec![
                    ("vid_gate_classic", vid_gate),
                    ("ake_gate_classic", ake_gate),
                ],
            },
            None => LeverReport::missed(
                LeverId::RawRead,
                format!("VID/AKE gate anchors not located in this image; {degraded}"),
            ),
        });
        levers.push(LeverReport::missed(LeverId::Speed, degraded));

        if !levers.iter().any(|l| l.outcome.is_effective()) {
            bail!(
                "{} (MT1939: no identity page for the DE byte)",
                super::lever::NOT_MODIFIABLE
            );
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
