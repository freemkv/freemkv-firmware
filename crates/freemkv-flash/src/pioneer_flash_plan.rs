//! Flash routing decision for Pioneer drives.
//!
//! Given the drive's installed identity and the target bundle, this module
//! decides *which* flash path applies: a plain same-model flash, a cross-generation
//! downgrade, a crossflash, or a refusal. It is pure classification — no device
//! I/O, no flashing, no state change.
//!
//! **Family gate.** Every non-forced flash is gated by a deterministic FAMILY
//! MATCH: `get_family(installed Normal body)` and `get_family(target Normal body)`
//! (`pioneer_optical::fw`) must both profile (`Some`) and be EQUAL — equal
//! [`FamilyKey`] means the same silicon/optical platform, i.e. crossflash
//! compatible. Anything else is [`FlashPlan::Refused`]. The planner stays pure:
//! the caller computes the two keys (from the pre-flash backup it already holds
//! and from the target bundle) and passes them in [`Installed::family`] /
//! [`Target::family`]. `--force` ignores the family match ([`FlashPlan::Forced`]).
//!
//! **Kernel mode is not used.** The F3/F2 "kernel mode" handshake is not
//! cold-reachable on any Pioneer BD firmware (only present at internal OEM-update
//! phase 9, inert for flashing); a live BDR-UD04 flat-rejects a cold F3/F2 with
//! sense 05/24/00. See [`kernel_mode_required`]. Every flash goes through the
//! ordinary OEM-update route, whose real generation lever is the decoded-body
//! `0xFE` marker (Site 1). Executing a cross-generation downgrade is NOT yet
//! wired: the plan is still reported ([`FlashPlan::KernelDowngrade`]) but the
//! executor refuses it (see `check_plan_executable` in `crate::drive::pioneer`).
//!
//! Gates recapped (whitepaper Ch.13/15):
//! - **Site 1** (incoming-marker gate, newer receiver): rejects an incoming
//!   Kernel whose decoded-body `0xFE` marker is `FF` or `00`; accepts otherwise.
//!   This is the generation barrier a downgrade crosses.
//! - **Site 2** (startup equality): the installed Normal/Kernel pair must agree,
//!   so a downgrade/crossflash MUST write a self-consistent Kernel+Normal pair —
//!   never Normal-only onto a retained newer Kernel, nor Kernel-only.
//! - Crossflash additionally needs a family match (see above) and a full foreign
//!   pair.

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// Controller id (SAT value), i.e. the model.
    pub controller_id: u16,
    /// The installed receiver has the new-generation Site-1 incoming-marker gate.
    pub receiver_new_gen: bool,
    /// Advertised date of the installed Normal (recency reference). `None` when
    /// the drive reports no usable date.
    pub normal_date: Option<FwDate>,
    /// Family of the installed Normal body (`None` if it could not be profiled).
    pub family: Option<FamilyKey>,
    /// Installed Kernel-generation ID tag (e.g. `"ID58"`). From the installed
    /// Normal envelope header's `Kernel Version` field, or equivalently from the
    /// live drive's vendor identity `3C/02/F1` response at bytes `0x18..0x20`
    /// (see [`pioneer_optical::flash::Identity::kernel_tag`]). This is the
    /// value the OEM Normal-only tag gate compares against the incoming
    /// Normal's declared required-Kernel tag. `None` if the backup didn't
    /// carry a usable Normal header.
    pub kernel_tag: Option<String>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Controller id (SAT value) of the target image, i.e. the model it makes.
    pub controller_id: u16,
    /// The Normal component, if the bundle carries one.
    pub normal: Option<ComponentInfo>,
    /// The Kernel component, if the bundle carries one.
    pub kernel: Option<KernelInfo>,
    /// Family of the target Normal body (`None` if it could not be profiled).
    pub family: Option<FamilyKey>,
    /// The incoming Normal's declared required-Kernel ID tag (its envelope
    /// header `Kernel Version` field, e.g. `"ID58"`). The Normal-only tag gate
    /// requires this to equal [`Installed::kernel_tag`]; a mismatch means the
    /// drive's installed Kernel is a different ABI generation and the OEM
    /// updater would refuse "Model name of kernel part is not matched." `None`
    /// if the target has no Normal or its header is missing/corrupt.
    pub required_kernel_tag: Option<String>,
}

/// The chosen flash path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashPlan {
    /// Same model, same-or-newer, or same-generation older: write the components
    /// as present, no kernel-mode unlock.
    Plain,
    /// Older, crossing the `FF`/`00` generation barrier on a new-gen receiver, with
    /// a full self-consistent Kernel+Normal pair. Reported only: executing a
    /// cross-generation downgrade is not yet wired and the executor refuses it.
    /// (Despite the name it needs no kernel mode; see [`kernel_mode_required`].)
    KernelDowngrade,
    /// Different model in the same family: a full self-consistent foreign
    /// Kernel+Normal pair written via the ordinary OEM-update route (no kernel
    /// mode; see [`kernel_mode_required`]).
    KernelCrossflash,
    /// Refused, with a human-readable reason (including any family-gate failure).
    /// `--force` turns this into [`FlashPlan::Forced`].
    Refused(String),
    /// `--force`: proceed without the safety classification — on your own. Only
    /// produced when a plan would otherwise have been refused.
    Forced,
}

/// Opaque crossflash-family key: the lowercase-hex rendering of
/// `pioneer_optical::fw::FamilyId`. Equal keys mean crossflash-compatible
/// (same silicon/optical platform). Held as a string so the planner is pure and
/// unit tests can inject families without any firmware.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FamilyKey(String);

impl FamilyKey {
    /// Wrap an already-rendered family id (tests / injected values).
    pub fn new(id: impl Into<String>) -> Self {
        FamilyKey(id.into())
    }

    /// Profile an envelope-DECODED firmware body (`decode_envelope(..).image`).
    /// `None` for a body that cannot be profiled (a Kernel component, a
    /// non-Pioneer blob, ...).
    pub fn from_body(body: &[u8]) -> Option<Self> {
        pioneer_optical::fw::get_family(body).map(|id| FamilyKey(id.to_string()))
    }
}

impl std::fmt::Display for FamilyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Family of a NORMAL component's raw envelope bytes: decode the envelope and
/// profile the decoded body. `None` if it does not decode or cannot be profiled.
pub fn normal_family(normal: &[u8]) -> Option<FamilyKey> {
    FamilyKey::from_body(&pioneer_codec::decode_envelope(normal)?.image)
}

/// Whether a flash needs the vendor F3/F2 "kernel mode" unlock. Always `false`.
///
/// Kernel mode is NOT needed (and not available) for Blu-ray flashing: the
/// F3/F2 handshake is not cold-reachable on ANY Pioneer BD firmware — it exists
/// only at internal OEM-update phase 9 and is inert for flashing — and a live
/// BDR-UD04 flat-rejects a cold F3/F2 with SCSI sense 05/24/00. The real
/// downgrade lever is the ordinary OEM-update route (`04/FF` entry, `07/FE`+`07/F0`
/// transfers, `05/FF` finish) gated by the decoded-body `0xFE` generation marker
/// (Site 1). `backup`/`dump` never use it either. The flasher issues the update
/// session solely through `pioneer_optical::flash::enter_kernel_mode`, which adds
/// the DVR handshake only for a DVR-class drive; a BD drive never sees it.
pub fn kernel_mode_required(_plan: &FlashPlan) -> bool {
    false
}

/// The deterministic family-match gate. `Ok` only when BOTH families profiled
/// and are equal; otherwise the refusal reason.
pub fn family_gate(
    installed: Option<&FamilyKey>,
    target: Option<&FamilyKey>,
) -> Result<(), String> {
    match (installed, target) {
        (Some(i), Some(t)) if i == t => Ok(()),
        (Some(i), Some(t)) => Err(format!(
            "family mismatch: installed firmware is family {i}, target is family {t} \
             (different silicon/optical platform; not crossflash-compatible)"
        )),
        (None, _) => Err(
            "could not determine the installed firmware family (no usable installed Normal \
             to profile); refusing without --force"
                .to_string(),
        ),
        (_, None) => Err(
            "could not determine the target firmware family (the target Normal could not be \
             profiled); refusing without --force"
                .to_string(),
        ),
    }
}

/// Plan for `flash --recover`: re-push a same/known-good image to a degraded
/// drive. Bypasses the date/"older" downgrade and Kernel+Normal pair refusals
/// (the drive is degraded; the image is the user's chosen known-good one) but
/// still honours the family gate unless `force`.
pub fn decide_recover_plan(
    installed: Option<&FamilyKey>,
    target: Option<&FamilyKey>,
    force: bool,
) -> FlashPlan {
    match family_gate(installed, target) {
        Ok(()) => FlashPlan::Plain,
        Err(_) if force => FlashPlan::Forced,
        Err(reason) => FlashPlan::Refused(reason),
    }
}

/// Refuse an image whose decoded envelope has an unrecoverable tail (bytes a
/// spliced envelope does not carry and decoding could not prove). Such an image
/// must never be flashed — not even with `--force` / `--recover`.
pub fn ensure_no_unrecovered_tail(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> Result<()> {
    for (label, bytes) in [("Kernel", kernel), ("Normal", normal)] {
        let Some(bytes) = bytes else { continue };
        if let Some(tail) = pioneer_codec::decode_envelope(bytes).and_then(|d| d.unrecovered_tail())
        {
            return Err(anyhow!(
                "the {label} envelope has an unrecoverable tail ({:#x}..{:#x} cannot be \
                 reproduced); refusing to flash an incomplete image",
                tail.start,
                tail.end
            ));
        }
    }
    Ok(())
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
    if let Err(reason) = family_gate(installed.family.as_ref(), target.family.as_ref()) {
        return FlashPlan::Refused(reason);
    }
    if target.controller_id == installed.controller_id {
        classify_same_model(installed, target)
    } else {
        classify_crossflash(installed, target)
    }
}

fn classify_same_model(installed: &Installed, target: &Target) -> FlashPlan {
    let Some(_normal) = target.normal else {
        return FlashPlan::Refused(
            "bundle has no Normal component — nothing to flash for this model".to_string(),
        );
    };

    // The OEM Normal-only tag gate: whenever the bundle has no Kernel, the
    // installed Kernel ID tag MUST equal the incoming Normal's declared
    // required-Kernel tag. This is the exact check Pioneer's own updater
    // performs (`memcmp(F1+0x18, file+0xD0, 8)` → "Model name of kernel part is
    // not matched"). A match proves the installed Kernel is the ABI generation
    // this Normal expects; a mismatch means the user needs a Kernel+Normal
    // package instead.
    if target.kernel.is_none() {
        return match (
            installed.kernel_tag.as_deref(),
            target.required_kernel_tag.as_deref(),
        ) {
            (Some(inst), Some(req)) if inst == req => FlashPlan::Plain,
            (Some(inst), Some(req)) => FlashPlan::Refused(format!(
                "Normal-only flash refused: this Normal needs installed Kernel tag {req:?}, \
                 but the drive currently has Kernel tag {inst:?}. Use a Kernel+Normal \
                 package instead."
            )),
            (None, _) => FlashPlan::Refused(
                "Normal-only flash refused: could not read the drive's installed Kernel ID \
                 tag (no usable pre-flash backup); use a Kernel+Normal package or --force"
                    .to_string(),
            ),
            (_, None) => FlashPlan::Refused(
                "Normal-only flash refused: this Normal has no declared required-Kernel tag \
                 in its envelope header (malformed or truncated); refusing"
                    .to_string(),
            ),
        };
    }

    // Bundle carries BOTH a Kernel and a Normal. Pair-side consistency is a
    // bundle-build concern (the bundle creator knows what Kernel its Normal
    // needs); the only runtime special case is Site 1 — a new-gen receiver
    // rejects an incoming `FF`/`00` Kernel. That's a KernelDowngrade and
    // triggers the §15.3 patch at write time.
    let kernel = target.kernel.expect("has_kernel branch");
    if installed.receiver_new_gen && Generation::from_marker(kernel.marker).site1_rejected() {
        FlashPlan::KernelDowngrade
    } else {
        FlashPlan::Plain
    }
}

/// Different model, same family (gate 1 already passed). A crossflash always
/// changes the target Kernel generation, so the bundle MUST carry both — a
/// Normal-only crossflash would land on the drive's existing (wrong-model)
/// Kernel. If the incoming Kernel marker would be rejected by a new-gen
/// receiver's Site 1 the crossflash is also a cross-generation downgrade and
/// gets the §15.3 patch at write time.
fn classify_crossflash(installed: &Installed, target: &Target) -> FlashPlan {
    let Some(kernel) = target.kernel else {
        return FlashPlan::Refused(
            "crossflash refused: a different-SAT target needs a Kernel+Normal pair; this \
             bundle is Normal-only"
                .to_string(),
        );
    };
    if target.normal.is_none() {
        return FlashPlan::Refused(
            "crossflash refused: a different-SAT target needs a Kernel+Normal pair; this \
             bundle is Kernel-only"
                .to_string(),
        );
    }
    if installed.receiver_new_gen && Generation::from_marker(kernel.marker).site1_rejected() {
        FlashPlan::KernelDowngrade
    } else {
        FlashPlan::KernelCrossflash
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
        family: normal.and_then(normal_family),
        required_kernel_tag: normal.and_then(component_kernel_tag),
    })
}

fn component_controller_id(bytes: Option<&[u8]>) -> Option<u16> {
    let info = pioneer_codec::header_info(bytes?)?;
    crate::pioneer_keys::controller_id_from_sat(&info.hardware_version)
}

fn component_date(bytes: &[u8]) -> Option<FwDate> {
    FwDate::parse(&pioneer_codec::header_info(bytes)?.generated_date)
}

/// Parse the envelope header's `Kernel Version` field — for a Normal, the
/// declared required-Kernel ID tag; for a Kernel, the Kernel's own ID tag
/// (Pioneer uses the same header field on both, so both callers reach it the
/// same way). Empty/missing → `None`.
fn component_kernel_tag(bytes: &[u8]) -> Option<String> {
    let tag = pioneer_codec::header_info(bytes)?.kernel_version;
    let tag = tag.trim();
    (!tag.is_empty()).then(|| tag.to_string())
}

/// Pre-flash sanity check on a BUNDLE'S own self-consistency — "did whoever
/// built this bundle screw it up?" Independent of the drive. Runs before any
/// gate decision, and before any write. Catches malformed / mismatched /
/// mis-labelled bundles (hand-rolled, scripted, downloaded-corrupt) that
/// would otherwise reach the drive and brick it.
///
/// What it enforces, in order:
/// 1. Each present component (Kernel, Normal) decodes to a well-formed Pioneer
///    envelope with a parseable header.
/// 2. Each component declares the correct `File Type` (`Kernel` / `Normal`).
/// 3. If both are present, both components agree on the SAT / hardware id.
/// 4. If both are present, the Kernel's own ID tag equals the Normal's
///    declared required-Kernel ID tag — the bundle is self-consistent (the
///    Normal says it needs Kernel tag X, and the bundled Kernel is tag X). A
///    mismatch is a bundler error: this bundle would land a Normal on the
///    wrong Kernel and risk a Site-2 soft-brick.
/// 5. Neither component has an unrecovered envelope tail (orthogonal, but we
///    package it here so a bundle's integrity is a single call-site).
pub fn validate_bundle(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> Result<(), String> {
    for (label, bytes, expected_type) in [
        ("Kernel", kernel, "Kernel"),
        ("Normal", normal, "Normal"),
    ] {
        let Some(bytes) = bytes else { continue };
        let header = pioneer_codec::header_info(bytes).ok_or_else(|| {
            format!("malformed bundle: {label} component has no readable envelope header")
        })?;
        if !header.file_type.eq_ignore_ascii_case(expected_type) {
            return Err(format!(
                "malformed bundle: {label} slot carries a component whose header declares \
                 File Type {:?}, not {expected_type:?}",
                header.file_type
            ));
        }
    }
    if let (Some(k), Some(n)) = (kernel, normal) {
        let kh = pioneer_codec::header_info(k).expect("checked above");
        let nh = pioneer_codec::header_info(n).expect("checked above");
        if !kh.hardware_version.eq_ignore_ascii_case(&nh.hardware_version)
            && !kh.hardware_version.is_empty()
            && !nh.hardware_version.is_empty()
        {
            return Err(format!(
                "malformed bundle: Kernel's Hardware Version {:?} does not match Normal's {:?}",
                kh.hardware_version, nh.hardware_version
            ));
        }
        let k_tag = kh.kernel_version.trim();
        let n_tag = nh.kernel_version.trim();
        if !k_tag.is_empty() && !n_tag.is_empty() && k_tag != n_tag {
            return Err(format!(
                "malformed bundle: Normal declares required-Kernel tag {n_tag:?} but the \
                 bundled Kernel's own tag is {k_tag:?}. These must be equal; a Normal paired \
                 with a Kernel of a different ABI generation will soft-brick on Site 2."
            ));
        }
    }
    // Tail guard is reused from the executor path; bubble its reason up as a
    // bundle-sanity error if it fires here.
    ensure_no_unrecovered_tail(kernel, normal)
        .map_err(|e| format!("malformed bundle: {e}"))?;
    Ok(())
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

    /// The injected family every fixture shares unless a test overrides it.
    fn fam() -> Option<FamilyKey> {
        Some(FamilyKey::new("f1"))
    }

    /// The injected tag every fixture shares unless a test overrides it. The
    /// gate-2 Normal-only tag check compares `Installed.kernel_tag` to
    /// `Target.required_kernel_tag`; tests use this value on both sides so a
    /// Normal-only target lands as `Plain`.
    fn tag() -> Option<String> {
        Some("ID58".to_string())
    }

    fn installed(cid: u16, new_gen: bool, d: &str) -> Installed {
        Installed {
            controller_id: cid,
            receiver_new_gen: new_gen,
            normal_date: date(d),
            family: fam(),
            kernel_tag: tag(),
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
            family: fam(),
            required_kernel_tag: tag(),
        }
    }

    /// Normal-only target with a matching tag by default; override to test
    /// mismatch.
    fn normal_only_target(cid: u16, nd: &str) -> Target {
        Target {
            controller_id: cid,
            normal: Some(ComponentInfo { date: date(nd) }),
            kernel: None,
            family: fam(),
            required_kernel_tag: tag(),
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
    fn normal_only_passes_when_installed_kernel_tag_matches_targets_required_tag() {
        let inst = installed(0x8A10, true, "22/01/01");
        // Date direction is irrelevant to the new policy; tag match is the gate.
        assert_eq!(
            decide_flash_plan(&inst, &normal_only_target(0x8A10, "23/01/01"), false),
            FlashPlan::Plain
        );
        assert_eq!(
            decide_flash_plan(&inst, &normal_only_target(0x8A10, "22/01/01"), false),
            FlashPlan::Plain
        );
        // Same-era older with Normal-only is now ALSO allowed if tags match
        // (OEM Normal-only patches ride on the installed Kernel regardless of
        // date direction).
        assert_eq!(
            decide_flash_plan(&inst, &normal_only_target(0x8A10, "20/01/01"), false),
            FlashPlan::Plain
        );
    }

    #[test]
    fn normal_only_refused_when_tags_differ() {
        let inst = installed(0x8A10, true, "22/01/01");
        let mut tgt = normal_only_target(0x8A10, "23/01/01");
        tgt.required_kernel_tag = Some("ID81".to_string());
        let plan = decide_flash_plan(&inst, &tgt, false);
        match plan {
            FlashPlan::Refused(reason) => {
                assert!(reason.contains("ID81"));
                assert!(reason.contains("ID58"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        // --force bypasses the tag gate.
        assert_eq!(decide_flash_plan(&inst, &tgt, true), FlashPlan::Forced);
    }

    #[test]
    fn normal_only_refused_when_installed_tag_unknown() {
        let mut inst = installed(0x8A10, true, "22/01/01");
        inst.kernel_tag = None;
        let tgt = normal_only_target(0x8A10, "23/01/01");
        assert!(matches!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::Refused(_)
        ));
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
    fn normal_only_with_mismatched_tag_still_refused_even_for_newer_date() {
        // Previously the "same-or-newer date → Plain" rule allowed ANY
        // Normal-only upgrade. The new policy refuses it on tag mismatch
        // regardless of date direction — matching the OEM updater.
        let inst = installed(0x8A10, true, "20/01/01");
        let mut tgt = normal_only_target(0x8A10, "23/01/01");
        tgt.required_kernel_tag = Some("ID99".to_string());
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
    fn crossflash_family_mismatch_is_refused_then_forced() {
        let inst = installed(0x8F00, true, "22/01/01");
        let mut tgt = pair_target(0x9401, "22/01/01", "22/01/01", 0x01);
        tgt.family = Some(FamilyKey::new("f2"));
        assert!(matches!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::Refused(r) if r.contains("family mismatch")
        ));
        assert_eq!(decide_flash_plan(&inst, &tgt, true), FlashPlan::Forced);
    }

    #[test]
    fn crossflash_without_kernel_is_refused() {
        // Different-SAT target requires a pair; Normal-only crossflash is never
        // safe (would land the new Normal on the drive's existing wrong-model
        // Kernel).
        let inst = installed(0x8F00, true, "22/01/01");
        let tgt = normal_only_target(0x8F01, "22/01/01");
        assert!(matches!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::Refused(reason) if reason.contains("crossflash")
        ));
    }

    #[test]
    fn same_family_crossflash_is_not_gated_by_any_table() {
        // Any same-family pair is crossflash-compatible in BOTH directions; the
        // the family-match gate is deterministic from `fw::get_family`;
        // no hard-coded compatibility table gates anything.
        let fwd = decide_flash_plan(
            &installed(0x8F00, true, "22/01/01"),
            &pair_target(0x8F01, "22/01/01", "22/01/01", 0x01),
            false,
        );
        let rev = decide_flash_plan(
            &installed(0x8F01, true, "22/01/01"),
            &pair_target(0x8F00, "22/01/01", "22/01/01", 0x01),
            false,
        );
        assert_eq!(fwd, FlashPlan::KernelCrossflash);
        assert_eq!(rev, FlashPlan::KernelCrossflash);
    }

    #[test]
    fn family_gate_requires_both_some_and_equal() {
        let a = FamilyKey::new("aa");
        let b = FamilyKey::new("bb");
        assert!(family_gate(Some(&a), Some(&a)).is_ok());
        assert!(family_gate(Some(&a), Some(&b))
            .unwrap_err()
            .contains("mismatch"));
        assert!(family_gate(None, Some(&a))
            .unwrap_err()
            .contains("installed"));
        assert!(family_gate(Some(&a), None).unwrap_err().contains("target"));
        assert!(family_gate(None, None).is_err());
    }

    #[test]
    fn same_model_is_refused_on_family_mismatch_or_unknown_then_forced() {
        let inst = installed(0x8A10, true, "22/01/01");
        let mut mismatch = pair_target(0x8A10, "23/01/01", "23/01/01", 0x01);
        mismatch.family = Some(FamilyKey::new("other"));
        let mut unknown_target = mismatch.clone();
        unknown_target.family = None;
        let mut unknown_installed = inst.clone();
        unknown_installed.family = None;
        let ok_target = pair_target(0x8A10, "23/01/01", "23/01/01", 0x01);
        for (i, t) in [
            (&inst, &mismatch),
            (&inst, &unknown_target),
            (&unknown_installed, &ok_target),
        ] {
            assert!(matches!(
                decide_flash_plan(i, t, false),
                FlashPlan::Refused(_)
            ));
            assert_eq!(decide_flash_plan(i, t, true), FlashPlan::Forced);
        }
        assert_eq!(
            decide_flash_plan(&inst, &ok_target, false),
            FlashPlan::Plain
        );
    }

    #[test]
    fn crossflash_across_generation_barrier_is_reported_as_downgrade() {
        let inst = installed(0x8F00, true, "22/01/01");
        let tgt = pair_target(0x8F01, "20/01/01", "20/01/01", 0xFF);
        assert_eq!(
            decide_flash_plan(&inst, &tgt, false),
            FlashPlan::KernelDowngrade
        );
    }

    #[test]
    fn recover_plan_respects_family_unless_forced() {
        let a = FamilyKey::new("aa");
        let b = FamilyKey::new("bb");
        assert_eq!(
            decide_recover_plan(Some(&a), Some(&a), false),
            FlashPlan::Plain
        );
        assert!(matches!(
            decide_recover_plan(Some(&a), Some(&b), false),
            FlashPlan::Refused(_)
        ));
        assert!(matches!(
            decide_recover_plan(None, Some(&a), false),
            FlashPlan::Refused(_)
        ));
        assert_eq!(decide_recover_plan(None, Some(&a), true), FlashPlan::Forced);
        assert_eq!(
            decide_recover_plan(Some(&a), Some(&b), true),
            FlashPlan::Forced
        );
    }

    #[test]
    fn kernel_mode_is_never_required() {
        for plan in [
            FlashPlan::Plain,
            FlashPlan::KernelDowngrade,
            FlashPlan::KernelCrossflash,
            FlashPlan::Forced,
            FlashPlan::Refused("x".into()),
        ] {
            assert!(!kernel_mode_required(&plan));
        }
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
                sum = sum.wrapping_add(u32::from_be_bytes([
                    buf[i],
                    buf[i + 1],
                    buf[i + 2],
                    buf[i + 3],
                ]));
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
        assert_eq!(
            decoded_kernel_marker(&encoded_kernel_with_marker(0xFF)).unwrap(),
            0xFF
        );
        assert_eq!(
            decoded_kernel_marker(&encoded_kernel_with_marker(0x01)).unwrap(),
            0x01
        );
        assert_eq!(
            decoded_kernel_marker(&encoded_kernel_with_marker(0xAB)).unwrap(),
            0xAB
        );
    }
}
