//! Flash routing decision for Pioneer drives.
//!
//! Given the drive's installed identity and the target bundle, this module
//! decides *which* flash path applies: a plain same-model flash, a kernel-mode
//! downgrade, a kernel-mode crossflash, or a refusal. It is pure classification
//! — no device I/O, no flashing, no state change. The live kernel-mode unlock
//! ([`crate::pioneer_flash::enter_kernel_mode`]) and the executor wiring are
//! deliberately NOT driven from here yet: whether the vendor kernel-mode state
//! actually clears the receiver's Site-1 generation gate is still unproven, so
//! downgrade/crossflash stay behind `--execute` + a mandatory OEM backup until
//! that is settled (see the kernel-mode trace notes).
//!
//! Gates recapped (whitepaper Ch.13/15):
//! - **Site 1** (incoming-marker gate, newer receiver): rejects an incoming
//!   Kernel whose decoded-body `0xFE` marker is `FF` or `00`; accepts otherwise.
//!   This is the generation barrier a downgrade crosses.
//! - **Site 2** (startup equality): the installed Normal/Kernel pair must agree,
//!   so a downgrade/crossflash MUST write a self-consistent Kernel+Normal pair —
//!   never Normal-only onto a retained newer Kernel, nor Kernel-only.
//! - Crossflash additionally needs the target to be a vetted same-chipset
//!   sibling (the [`SAFE_CROSSFLASH`] table) and a full foreign pair.

use anyhow::{anyhow, Context, Result};

/// Generation class derived from a decoded Kernel body offset `0xFE`
/// (runtime `0x4000FE`). The marker is a coarse generation indicator, not a
/// version (whitepaper §15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    /// Marker `0x01` — newer generation. Site 1 accepts it.
    Newer,
    /// Marker `0xFF` or `0x00` — older/legacy. Site 1 (new-gen receiver) rejects.
    Older,
    /// Any other raw `0xFE` value (`0x0C`/`0x0D`/`0x18`/`0x55`, …): not a named
    /// generation class, retained as a raw observation. Site 1 does not reject it
    /// (it rejects only `FF`/`00`).
    Other(u8),
}

impl Generation {
    /// Classify a raw decoded-body `0xFE` marker byte.
    pub fn from_marker(marker: u8) -> Self {
        match marker {
            0x01 => Generation::Newer,
            0xFF | 0x00 => Generation::Older,
            other => Generation::Other(other),
        }
    }

    /// Whether a new-generation receiver's Site-1 gate rejects this incoming
    /// marker. Only `FF`/`00` are rejected; everything else passes.
    pub fn site1_rejected(self) -> bool {
        matches!(self, Generation::Older)
    }
}

/// An advertised firmware date (`YY/MM/DD`, as stored in the header
/// `Generated Date` field, e.g. `20/06/15`). This is the §14.5 recency / pairing
/// key. Two-digit years are all 2000s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FwDate {
    year: u16,
    month: u8,
    day: u8,
}

impl FwDate {
    /// Parse a `YY/MM/DD` (or `YYYY/MM/DD`) header date. Returns `None` for the
    /// historical null date `00/00/00` and for anything unparseable, so callers
    /// treat "no usable date" explicitly rather than ordering against a zero.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.trim().split('/');
        let year: u16 = parts.next()?.trim().parse().ok()?;
        let month: u8 = parts.next()?.trim().parse().ok()?;
        let day: u8 = parts.next()?.trim().parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let year = if year < 100 { 2000 + year } else { year };
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        Some(FwDate { year, month, day })
    }
}

/// Facts about the drive's currently-installed firmware. The caller populates
/// these by probing the drive (identity + installed revision/date, and whether
/// the installed receiver carries the new-generation Site-1 gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    /// Controller id (SAT value), i.e. the model.
    pub controller_id: u16,
    /// The installed receiver has the new-generation Site-1 incoming-marker gate.
    pub receiver_new_gen: bool,
    /// Advertised date of the installed Normal (recency reference). `None` when
    /// the drive reports no usable date.
    pub normal_date: Option<FwDate>,
}

/// One target component's recency/generation facts, extracted from its envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentInfo {
    /// Advertised date from the component header (`None` if unusable).
    pub date: Option<FwDate>,
}

/// A target Kernel component's facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelInfo {
    /// Advertised date from the Kernel header (`None` if unusable).
    pub date: Option<FwDate>,
    /// Decoded-body `0xFE` generation marker.
    pub marker: u8,
}

/// Facts about the target `.tar` bundle. The caller extracts these from the
/// bundle's component headers (dates) plus a decode of the Kernel (marker).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// Controller id (SAT value) of the target image, i.e. the model it makes.
    pub controller_id: u16,
    /// The Normal component, if the bundle carries one.
    pub normal: Option<ComponentInfo>,
    /// The Kernel component, if the bundle carries one.
    pub kernel: Option<KernelInfo>,
}

/// The chosen flash path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashPlan {
    /// Same model, same-or-newer, or same-generation older: write the components
    /// as present, no kernel-mode unlock.
    Plain,
    /// Same model, older, crossing the `FF`/`00` generation barrier on a new-gen
    /// receiver: requires kernel mode and a full self-consistent Kernel+Normal
    /// pair.
    KernelDowngrade,
    /// Different model on the vetted safe list: requires kernel mode and a full
    /// self-consistent foreign Kernel+Normal pair.
    KernelCrossflash,
    /// Refused, with a human-readable reason. `--force` turns this into
    /// [`FlashPlan::Forced`].
    Refused(String),
    /// `--force`: proceed without the safety classification — on your own. Only
    /// produced when a plan would otherwise have been refused.
    Forced,
}

/// Vetted same-chipset crossflash pairs `(from_controller_id, to_controller_id)`
/// (from the maintained safe list). Nearly all are a non-UHD → UHD sibling
/// differing only in the low nibble of the controller id. Multi-hop routes
/// (e.g. `8301 → 8600 → 8800`) are represented only by their listed direct rows.
pub const SAFE_CROSSFLASH: &[(u16, u16)] = &[
    (0x8231, 0x8B30), // BDR-XD05 → BDR-XD06J-UHD
    (0x8232, 0x8B30), // BDR-XD05 → BDR-XD06J-UHD
    (0x8301, 0x8800), // BDR-208  → BDR-211 v1
    (0x8510, 0x8A10), // BDR-UD03 v1 → BDR-UD04
    (0x8511, 0x8A10), // BDR-UD03 v2 → BDR-UD04
    (0x8590, 0x8691), // BDR-US03 → Asus SBC-06D2X-U
    (0x8600, 0x8800), // BDR-209 v1 → BDR-211 v1
    (0x8601, 0x8801), // BDR-209 v2 → BDR-211 v2
    (0x8D30, 0x8D31), // BDR-XD07 → BDR-XD07U
    (0x8E20, 0x8E21), // BDR-XS07 → BDR-XS07U
    (0x8F00, 0x8F01), // BDR-212  → BDR-S12U
    (0x9000, 0x9001), // BDR-X12  → BDR-X12U
    (0x9200, 0x9201), // BDR-XD08 → BDR-XD08U
    (0x9400, 0x9401), // BDR-X13  → BDR-X13U
];

/// Whether `from → to` is a vetted safe crossflash.
pub fn is_safe_crossflash(from: u16, to: u16) -> bool {
    SAFE_CROSSFLASH.contains(&(from, to))
}

/// Decide the flash path. Pure: no I/O. `force` converts an otherwise-`Refused`
/// plan into [`FlashPlan::Forced`]; it never weakens a known-good plan.
pub fn decide_flash_plan(installed: &Installed, target: &Target, force: bool) -> FlashPlan {
    match classify(installed, target) {
        FlashPlan::Refused(reason) if force => {
            let _ = reason;
            FlashPlan::Forced
        }
        plan => plan,
    }
}

fn classify(installed: &Installed, target: &Target) -> FlashPlan {
    if target.controller_id == installed.controller_id {
        classify_same_model(installed, target)
    } else {
        classify_crossflash(installed, target)
    }
}

fn classify_same_model(installed: &Installed, target: &Target) -> FlashPlan {
    let Some(normal) = target.normal else {
        return FlashPlan::Refused(
            "bundle has no Normal component — nothing to flash for this model".to_string(),
        );
    };

    // Same-or-newer (or indeterminate recency) is a plain flash: an upgrade's
    // incoming Kernel marker is `01`, which Site 1 accepts, and a same-version
    // reflash is trivially fine. Normal-only is allowed here.
    if !target_is_older(installed.normal_date, normal.date) {
        return FlashPlan::Plain;
    }

    // Older than installed → a downgrade. It must write a full, self-consistent
    // Kernel+Normal pair (Site 2).
    if let Err(reason) = require_consistent_pair(target) {
        return FlashPlan::Refused(reason);
    }
    let kernel = target.kernel.expect("pair check guarantees a kernel");

    // Kernel mode is only needed when the downgrade actually crosses the
    // generation barrier: a new-gen receiver rejecting an incoming `FF`/`00`
    // Kernel. A same-generation older pair (`01`) passes Site 1 unaided.
    if installed.receiver_new_gen && Generation::from_marker(kernel.marker).site1_rejected() {
        FlashPlan::KernelDowngrade
    } else {
        FlashPlan::Plain
    }
}

fn classify_crossflash(installed: &Installed, target: &Target) -> FlashPlan {
    if !is_safe_crossflash(installed.controller_id, target.controller_id) {
        return FlashPlan::Refused(format!(
            "crossflash from {:#06X} to {:#06X} is not on the vetted safe list",
            installed.controller_id, target.controller_id
        ));
    }
    if let Err(reason) = require_consistent_pair(target) {
        return FlashPlan::Refused(reason);
    }
    FlashPlan::KernelCrossflash
}

/// A downgrade/crossflash must carry BOTH a Kernel and a Normal, and they must
/// pair: the Kernel's advertised date must be no newer than the Normal's
/// (§14.5). A lone component (or a Kernel newer than its Normal) risks a Site-2
/// mismatch soft-brick.
fn require_consistent_pair(target: &Target) -> Result<(), String> {
    match (target.kernel, target.normal) {
        (None, _) => Err(
            "this flash needs a matched Kernel+Normal pair, but the bundle has no Kernel \
             (a Normal-only downgrade/crossflash can soft-brick on the Site-2 startup check)"
                .to_string(),
        ),
        (_, None) => Err(
            "this flash needs a matched Kernel+Normal pair, but the bundle has no Normal \
             (a Kernel-only flash can soft-brick on the Site-2 startup check)"
                .to_string(),
        ),
        (Some(kernel), Some(normal)) => {
            // Only reject when both dates are known and the Kernel is strictly
            // newer than the Normal. Unknown dates can't prove inconsistency.
            if let (Some(kd), Some(nd)) = (kernel.date, normal.date) {
                if kd > nd {
                    return Err(format!(
                        "bundle Kernel (dated {kd:?}) is newer than its Normal (dated {nd:?}); \
                         an inconsistent pair can soft-brick on the Site-2 startup check"
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Whether the target is strictly older than what's installed. Indeterminate
/// (either date missing) is treated as "not older" — we do not infer a downgrade
/// without evidence; `--force` remains the escape hatch for odd cases.
fn target_is_older(installed: Option<FwDate>, target: Option<FwDate>) -> bool {
    match (installed, target) {
        (Some(installed), Some(target)) => target < installed,
        _ => false,
    }
}

/// Build [`Target`] facts from the bundle's component bytes, using the codec
/// headers (dates) and a decode of the Kernel (generation marker). `kernel` and
/// `normal` are the raw envelope bytes when present. The controller id is taken
/// from whichever component is present (they must agree for a valid bundle).
pub fn target_from_components(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> Result<Target> {
    let controller_id = component_controller_id(kernel)
        .or(component_controller_id(normal))
        .context("bundle has no component with a resolvable SAT controller id")?;

    let normal_info = normal.map(|_| ComponentInfo {
        date: normal.and_then(component_date),
    });

    let kernel_info = match kernel {
        Some(bytes) => {
            let marker = decoded_kernel_marker(bytes)
                .context("could not decode the bundle Kernel to read its generation marker")?;
            Some(KernelInfo {
                date: component_date(bytes),
                marker,
            })
        }
        None => None,
    };

    Ok(Target {
        controller_id,
        normal: normal_info,
        kernel: kernel_info,
    })
}

fn component_controller_id(bytes: Option<&[u8]>) -> Option<u16> {
    let info = pioneer_codec::header_info(bytes?)?;
    crate::pioneer_keys::controller_id_from_sat(&info.hardware_version)
}

fn component_date(bytes: &[u8]) -> Option<FwDate> {
    FwDate::parse(&pioneer_codec::header_info(bytes)?.generated_date)
}

/// Decode an envelope and read its decoded-body `0xFE` generation marker.
fn decoded_kernel_marker(bytes: &[u8]) -> Result<u8> {
    let decoded =
        pioneer_codec::decode_envelope(bytes).ok_or_else(|| anyhow!("envelope did not decode"))?;
    decoded
        .image
        .get(0xFE)
        .copied()
        .ok_or_else(|| anyhow!("decoded Kernel body is shorter than 0xFF bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(s: &str) -> Option<FwDate> {
        FwDate::parse(s)
    }

    fn installed(cid: u16, new_gen: bool, d: &str) -> Installed {
        Installed {
            controller_id: cid,
            receiver_new_gen: new_gen,
            normal_date: date(d),
        }
    }

    fn pair_target(cid: u16, kd: &str, nd: &str, marker: u8) -> Target {
        Target {
            controller_id: cid,
            normal: Some(ComponentInfo { date: date(nd) }),
            kernel: Some(KernelInfo {
                date: date(kd),
                marker,
            }),
        }
    }

    #[test]
    fn date_parse_and_order() {
        assert!(date("20/06/15").unwrap() < date("22/12/12").unwrap());
        assert_eq!(FwDate::parse("00/00/00"), None); // null date -> unusable
        assert_eq!(FwDate::parse("20/13/01"), None); // bad month
        assert_eq!(FwDate::parse("2022/01/02"), FwDate::parse("22/01/02"));
    }

    #[test]
    fn marker_generation_and_site1() {
        assert_eq!(Generation::from_marker(0x01), Generation::Newer);
        assert_eq!(Generation::from_marker(0xFF), Generation::Older);
        assert_eq!(Generation::from_marker(0x00), Generation::Older);
        assert_eq!(Generation::from_marker(0x0C), Generation::Other(0x0C));
        assert!(Generation::from_marker(0xFF).site1_rejected());
        assert!(Generation::from_marker(0x00).site1_rejected());
        assert!(!Generation::from_marker(0x01).site1_rejected());
        assert!(!Generation::from_marker(0x0C).site1_rejected()); // Site 1 rejects only FF/00
    }

    #[test]
    fn same_model_same_or_newer_is_plain_normal_only_ok() {
        let inst = installed(0x8A10, true, "22/01/01");
        // Newer, normal-only.
        let tgt = Target {
            controller_id: 0x8A10,
            normal: Some(ComponentInfo {
                date: date("23/01/01"),
            }),
            kernel: None,
        };
        assert_eq!(decide_flash_plan(&inst, &tgt, false), FlashPlan::Plain);
        // Same date reflash.
        let tgt_same = Target {
            controller_id: 0x8A10,
            normal: Some(ComponentInfo {
                date: date("22/01/01"),
            }),
            kernel: None,
        };
        assert_eq!(decide_flash_plan(&inst, &tgt_same, false), FlashPlan::Plain);
    }

    #[test]
    fn same_model_older_across_barrier_is_kernel_downgrade() {
        let inst = installed(0x8A10, true, "23/01/01");
        let tgt = pair_target(0x8A10, "20/06/15", "20/06/15", 0xFF);
        assert_eq!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::KernelDowngrade
        );
    }

    #[test]
    fn same_model_older_same_generation_is_plain() {
        // Older, but incoming Kernel marker is 01 -> Site 1 accepts, no unlock.
        let inst = installed(0x8A10, true, "23/06/01");
        let tgt = pair_target(0x8A10, "23/01/01", "23/01/01", 0x01);
        assert_eq!(decide_flash_plan(&inst, &tgt, false), FlashPlan::Plain);
    }

    #[test]
    fn same_model_older_on_old_receiver_is_plain() {
        // Receiver lacks Site 1, so even an FF kernel needs no unlock.
        let inst = installed(0x8A10, false, "23/01/01");
        let tgt = pair_target(0x8A10, "20/06/15", "20/06/15", 0xFF);
        assert_eq!(decide_flash_plan(&inst, &tgt, false), FlashPlan::Plain);
    }

    #[test]
    fn downgrade_without_kernel_is_refused_then_forced() {
        let inst = installed(0x8A10, true, "23/01/01");
        let tgt = Target {
            controller_id: 0x8A10,
            normal: Some(ComponentInfo {
                date: date("20/06/15"),
            }),
            kernel: None,
        };
        assert!(matches!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::Refused(_)
        ));
        assert_eq!(decide_flash_plan(&inst, &tgt, true), FlashPlan::Forced);
    }

    #[test]
    fn inconsistent_pair_kernel_newer_than_normal_is_refused() {
        let inst = installed(0x8A10, true, "23/01/01");
        let tgt = pair_target(0x8A10, "22/06/01", "20/06/15", 0xFF);
        assert!(matches!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::Refused(_)
        ));
    }

    #[test]
    fn crossflash_on_list_with_pair_is_kernel_crossflash() {
        let inst = installed(0x8F00, true, "22/01/01");
        let tgt = pair_target(0x8F01, "22/01/01", "22/01/01", 0x01);
        assert_eq!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::KernelCrossflash
        );
    }

    #[test]
    fn crossflash_off_list_is_refused_then_forced() {
        let inst = installed(0x8F00, true, "22/01/01");
        // 8F00 -> 9401 is not a listed pair.
        let tgt = pair_target(0x9401, "22/01/01", "22/01/01", 0x01);
        assert!(matches!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::Refused(_)
        ));
        assert_eq!(decide_flash_plan(&inst, &tgt, true), FlashPlan::Forced);
    }

    #[test]
    fn crossflash_on_list_without_pair_is_refused() {
        let inst = installed(0x8F00, true, "22/01/01");
        let tgt = Target {
            controller_id: 0x8F01,
            normal: Some(ComponentInfo {
                date: date("22/01/01"),
            }),
            kernel: None,
        };
        assert!(matches!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::Refused(_)
        ));
    }

    #[test]
    fn safe_crossflash_table_is_directional() {
        assert!(is_safe_crossflash(0x8F00, 0x8F01));
        assert!(!is_safe_crossflash(0x8F01, 0x8F00)); // reverse is not listed
        assert!(is_safe_crossflash(0x8301, 0x8800));
    }

    #[test]
    fn fwdate_two_digit_year_boundary_is_strict_less_than_100() {
        // A 3-digit year (100) must NOT be treated as a 2-digit year (+2000):
        // original `< 100` keeps 100 (ancient), so it sorts BEFORE a real 2-digit
        // year like 99 -> 2099. The `<=` mutant would make 100 -> 2100 (after 2099).
        assert!(FwDate::parse("100/01/01") < FwDate::parse("99/01/01"));
        // And a genuine 2-digit year still gets the +2000 treatment (2022 > 2021).
        assert!(FwDate::parse("22/01/01") > FwDate::parse("21/12/31"));
    }

    /// Build a structurally-valid FrontKey Kernel envelope whose DECODED body
    /// byte at 0xFE equals `marker`, via the pioneer-codec public builder. Mirrors
    /// the codec's own `front_kernel` test fixture.
    fn encoded_kernel_with_marker(marker: u8) -> Vec<u8> {
        use pioneer_codec::builder::{encode_kernel_envelope, KernelBuild};
        fn be32_fix(buf: &mut [u8], at: usize) {
            buf[at..at + 4].copy_from_slice(&[0; 4]);
            let mut sum = 0u32;
            let mut i = 0;
            while i + 4 <= buf.len() {
                sum = sum
                    .wrapping_add(u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]));
                i += 4;
            }
            buf[at..at + 4].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
        }
        fn write_branch(buf: &mut [u8], at: usize, offs: [u32; 2]) {
            buf[at] = 0x7a;
            buf[at + 1] = 0x20;
            buf[at + 2..at + 6].copy_from_slice(&offs[0].to_be_bytes());
            buf[at + 6] = 0x47;
            buf[at + 7] = 12;
            buf[at + 8] = 0x7a;
            buf[at + 9] = 0x20;
            buf[at + 10..at + 14].copy_from_slice(&offs[1].to_be_bytes());
            buf[at + 14] = 0x47;
            buf[at + 15] = 4;
            buf[at + 16..at + 20].copy_from_slice(&[1, 0xf0, 0x65, 5]);
        }
        let mut k = vec![0u8; 0x10000];
        k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
        k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
        k[0x1010..0x1014].copy_from_slice(b"0000");
        k[0x40] = 0xae;
        k[0x41] = 0xfe;
        k[0x46] = 0xae;
        k[0x47] = 0xf0;
        write_branch(&mut k, 0x100, [0x100, 0x200]);
        k[0xFE] = marker; // the generation marker we read back
        be32_fix(&mut k, 0xff00);
        encode_kernel_envelope(&k, "PIONEER BDR-TEST", &KernelBuild::from_seed(0x123456))
            .expect("encode synthetic kernel")
    }

    #[test]
    fn decoded_kernel_marker_reads_body_offset_0xfe() {
        // Round-trips a real encoded Kernel and reads its decoded 0xFE marker,
        // killing the "always Ok(0)/Ok(1)" stubs of decoded_kernel_marker.
        assert_eq!(decoded_kernel_marker(&encoded_kernel_with_marker(0xFF)).unwrap(), 0xFF);
        assert_eq!(decoded_kernel_marker(&encoded_kernel_with_marker(0x01)).unwrap(), 0x01);
        assert_eq!(decoded_kernel_marker(&encoded_kernel_with_marker(0xAB)).unwrap(), 0xAB);
    }
}
