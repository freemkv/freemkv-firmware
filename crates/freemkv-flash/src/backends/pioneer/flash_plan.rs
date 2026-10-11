//! Flash routing for Pioneer drives: from the installed identity and the
//! target bundle, decide between a plain flash, a cross-generation downgrade,
//! a crossflash or a refusal. Pure classification: no device I/O.
//!
//! **Family gate.** `family(installed Normal body)` and `family(target Normal
//! body)` must both profile and be equal ([`FamilyKey`]: the same silicon and
//! optical platform); anything else is [`FlashPlan::Refused`]. The caller
//! computes both keys and passes them in [`Installed::family`] and
//! [`Target::family`].
//!
//! **Kernel mode is not used** (see [`kernel_mode_required`]). Every flash takes
//! the ordinary OEM-update route, whose generation lever is the decoded-body
//! `0xFE` marker. A [`FlashPlan::KernelDowngrade`] is executable: the marker
//! patch is applied to the Kernel at write time.
//!
//! Gates: Site 1 (a newer receiver rejects an incoming Kernel whose marker is
//! `FF` or `00`: the generation barrier) and Site 2 (the installed Kernel and
//! Normal must agree, so a downgrade or crossflash writes a consistent pair).

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
    /// `None` when unknown (no usable installed Kernel); classification treats
    /// unknown as `false`.
    pub receiver_new_gen: Option<bool>,
    /// Advertised date of the installed Normal (recency reference). `None` when
    /// the drive reports no usable date.
    pub normal_date: Option<FwDate>,
    /// Family of the installed Normal body (`None` if it could not be profiled).
    pub family: Option<FamilyKey>,
    /// Installed Kernel-generation ID tag (e.g. `"ID58"`). From the installed
    /// Normal envelope header's `Kernel Version` field, or equivalently from the
    /// live drive's vendor identity `3C/02/F1` response at bytes `0x18..0x20`
    /// (see [`pioneer_optical::Identity::kernel_tag`]). This is the
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
    /// a full self-consistent Kernel+Normal pair. Executable: the §15.3 marker
    /// patch is applied to the Kernel at write time.
    /// (Despite the name it needs no kernel mode; see [`kernel_mode_required`].)
    KernelDowngrade,
    /// Different model in the same family: a full self-consistent foreign
    /// Kernel+Normal pair written via the ordinary OEM-update route (no kernel
    /// mode; see [`kernel_mode_required`]).
    KernelCrossflash,
    /// Refused, with a human-readable reason (including any family-gate failure).
    Refused(String),
}

/// Opaque crossflash-family key: the lowercase-hex rendering of
/// `pioneer_optical::image::Family`. Equal keys mean crossflash-compatible
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
        pioneer_optical::image::family(body).map(|id| FamilyKey(id.to_string()))
    }
}

impl std::fmt::Display for FamilyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Hardware family decoded using the receiver's Kernel policy.
pub fn normal_family_with_kernel(normal: &[u8], kernel: &[u8]) -> Option<FamilyKey> {
    let kernel = pioneer_optical::envelope::decode_envelope(kernel)?;
    let normal = pioneer_optical::envelope::decode_envelope_with_kernel(normal, &kernel)?;
    FamilyKey::from_body(&normal.image)
}

/// Family of a NORMAL component's raw envelope bytes: decode the envelope and
/// profile the decoded body. `None` if it does not decode or cannot be profiled.
pub fn normal_family(normal: &[u8]) -> Option<FamilyKey> {
    FamilyKey::from_body(&pioneer_optical::envelope::decode_envelope(normal)?.image)
}

/// Whether a flash needs the vendor F3/F2 "kernel mode" unlock. Always `false`.
///
/// The F3/F2 handshake is not cold-reachable on any Pioneer BD firmware (a live
/// BDR-UD04 rejects it with sense 05/24/00). Downgrades use the ordinary
/// OEM-update route gated by the decoded-body `0xFE` marker (Site 1), and
/// `pioneer_optical::drive::enter_update` adds the DVR handshake only for a
/// DVR-class drive.
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
             to profile); normal Flash requires a known family"
                .to_string(),
        ),
        (_, None) => Err(
            "could not determine the target firmware family (the target Normal could not be \
             profiled); normal Flash requires a known family"
                .to_string(),
        ),
    }
}

/// Refuse an image whose decoded envelope has an unrecoverable tail (bytes a
/// spliced envelope does not carry and decoding could not prove). Such an image
/// must never be flashed.
pub fn ensure_no_unrecovered_tail(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> Result<()> {
    for (label, bytes) in [("Kernel", kernel), ("Normal", normal)] {
        let Some(bytes) = bytes else { continue };
        if let Some(tail) =
            pioneer_optical::envelope::decode_envelope(bytes).and_then(|d| d.unrecovered_tail())
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

/// Decide the flash path. Pure: no I/O. The family gate refuses first; a
/// family match then classifies the flash.
pub fn decide_flash_plan(installed: &Installed, target: &Target) -> FlashPlan {
    match family_gate(installed.family.as_ref(), target.family.as_ref()) {
        Ok(()) => classify(installed, target),
        Err(reason) => FlashPlan::Refused(reason),
    }
}

fn classify(installed: &Installed, target: &Target) -> FlashPlan {
    if target.controller_id == installed.controller_id {
        classify_same_model(installed, target)
    } else {
        classify_crossflash(installed, target)
    }
}

fn normal_only_tag_mismatch(inst: &str, req: &str) -> FlashPlan {
    FlashPlan::Refused(format!(
        "Normal-only flash refused: this Normal needs installed Kernel tag {req:?}, \
         but the drive currently has Kernel tag {inst:?}. Use a Kernel+Normal \
         package instead."
    ))
}

fn normal_only_no_tag() -> FlashPlan {
    FlashPlan::Refused(
        "Normal-only flash refused: this Normal has no declared required-Kernel tag \
         in its envelope header (malformed or truncated); refusing"
            .to_string(),
    )
}

fn classify_same_model(installed: &Installed, target: &Target) -> FlashPlan {
    let Some(_normal) = target.normal else {
        return FlashPlan::Refused(
            "bundle has no Normal component — nothing to flash for this model".to_string(),
        );
    };

    // OEM Normal-only gate: the installed Kernel ID tag must equal the incoming
    // Normal's required-Kernel tag (the vendor updater's own check); a mismatch
    // needs a Kernel+Normal package.
    if target.kernel.is_none() {
        return match (
            installed.kernel_tag.as_deref(),
            target.required_kernel_tag.as_deref(),
        ) {
            (Some(inst), Some(req)) if inst == req => FlashPlan::Plain,
            (Some(inst), Some(req)) => normal_only_tag_mismatch(inst, req),
            (_, None) => normal_only_no_tag(),
            (None, _) => FlashPlan::Refused(
                "Normal-only flash refused: could not read the drive's installed Kernel ID \
                 tag (no usable pre-flash backup); use a Kernel+Normal package"
                    .to_string(),
            ),
        };
    }

    // A Kernel+Normal bundle: the only runtime special case is Site 1, where a
    // new-generation receiver rejects an `FF`/`00` Kernel (a KernelDowngrade,
    // patched at write time).
    let kernel = target.kernel.expect("has_kernel branch");
    if installed.receiver_new_gen.unwrap_or(false)
        && Generation::from_marker(kernel.marker).site1_rejected()
    {
        FlashPlan::KernelDowngrade
    } else {
        FlashPlan::Plain
    }
}

/// Same-family cross-SAT updates require both components. The receiver's
/// marker policy determines whether an intermediate Kernel is required.
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
    if installed.receiver_new_gen.unwrap_or(false)
        && Generation::from_marker(kernel.marker).site1_rejected()
    {
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
        family: normal.and_then(|n| match kernel {
            Some(k) => normal_family_with_kernel(n, k),
            None => normal_family(n),
        }),
        required_kernel_tag: normal.and_then(component_kernel_tag),
    })
}

fn component_controller_id(bytes: Option<&[u8]>) -> Option<u16> {
    let info = pioneer_optical::envelope::header_info(bytes?)?;
    controller_id_from_sat(&info.hardware_version)
}

fn component_date(bytes: &[u8]) -> Option<FwDate> {
    FwDate::parse(&pioneer_optical::envelope::header_info(bytes)?.generated_date)
}

/// Parse the envelope header's `Kernel Version` field — for a Normal, the
/// declared required-Kernel ID tag; for a Kernel, the Kernel's own ID tag
/// (Pioneer uses the same header field on both, so both callers reach it the
/// same way). Empty/missing → `None`.
fn component_kernel_tag(bytes: &[u8]) -> Option<String> {
    let tag = pioneer_optical::envelope::header_info(bytes)?.kernel_version;
    let tag = tag.trim();
    (!tag.is_empty()).then(|| tag.to_string())
}

/// Pre-flash check of a bundle's own consistency, independent of the drive and
/// before any gate or write:
/// 1. each present component decodes to a well-formed envelope header;
/// 2. each declares the right `File Type` (`Kernel` / `Normal`);
/// 3. with both present, they agree on the SAT/hardware id, and the Kernel's ID
///    tag equals the Normal's required-Kernel tag (else a Site-2 soft-brick);
/// 4. neither has an unrecovered envelope tail.
pub fn validate_bundle(kernel: Option<&[u8]>, normal: Option<&[u8]>) -> Result<(), String> {
    validate_component_headers(kernel, normal)?;
    ensure_no_unrecovered_tail(kernel, normal).map_err(|e| format!("malformed bundle: {e}"))?;
    Ok(())
}

/// Validate component identity and pairing before attempting any body decode.
pub fn validate_component_headers(
    kernel: Option<&[u8]>,
    normal: Option<&[u8]>,
) -> Result<(), String> {
    for (label, bytes, expected_type) in [
        ("Kernel", kernel, pioneer_optical::ComponentKind::Kernel),
        ("Normal", normal, pioneer_optical::ComponentKind::Normal),
    ] {
        let Some(bytes) = bytes else { continue };
        let header = pioneer_optical::envelope::header_info(bytes).ok_or_else(|| {
            format!("malformed bundle: {label} component has no readable envelope header")
        })?;
        if header.kind != Some(expected_type) {
            return Err(format!(
                "malformed bundle: {label} slot carries a component whose header declares \
                 File Type {:?}, not {:?}",
                header.kind.map_or("unknown", |t| t.as_str()),
                expected_type.as_str()
            ));
        }
    }
    if let (Some(k), Some(n)) = (kernel, normal) {
        let kh = pioneer_optical::envelope::header_info(k).expect("checked above");
        let nh = pioneer_optical::envelope::header_info(n).expect("checked above");
        if !kh
            .hardware_version
            .eq_ignore_ascii_case(&nh.hardware_version)
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
        if k_tag.is_empty() || n_tag.is_empty() {
            return Err(format!(
                "malformed bundle: the Kernel's own tag ({k_tag:?}) or the Normal's required-Kernel \
                 tag ({n_tag:?}) is empty, so the pair cannot be proven consistent"
            ));
        }
        if k_tag != n_tag {
            return Err(format!(
                "malformed bundle: Normal declares required-Kernel tag {n_tag:?} but the \
                 bundled Kernel's own tag is {k_tag:?}. These must be equal; a Normal paired \
                 with a Kernel of a different ABI generation will soft-brick on Site 2."
            ));
        }
    }
    Ok(())
}

/// Decode an envelope and read its decoded-body `0xFE` generation marker.
fn decoded_kernel_marker(bytes: &[u8]) -> Result<u8> {
    let decoded = pioneer_optical::envelope::decode_envelope(bytes)
        .ok_or_else(|| anyhow!("envelope did not decode"))?;
    decoded
        .image
        .get(0xFE)
        .copied()
        .ok_or_else(|| anyhow!("decoded Kernel body is shorter than 0xFF bytes"))
}

/// Parse a controller id from a `SAT xxxx` hardware tag (as it appears in a
/// Pioneer banner's `Hardware Version :` field) or a bare hex string. The SAT
/// value is the controller id in hex, e.g. `"SAT 8A10"` / `"8A10"` -> `0x8A10`.
pub fn controller_id_from_sat(hardware: &str) -> Option<u16> {
    let token = hardware
        .trim()
        .strip_prefix("SAT")
        .or_else(|| hardware.trim().strip_prefix("sat"))
        .unwrap_or(hardware)
        .trim();
    u16::from_str_radix(token, 16).ok()
}

#[cfg(test)]
#[path = "flash_plan_tests.rs"]
mod tests;
