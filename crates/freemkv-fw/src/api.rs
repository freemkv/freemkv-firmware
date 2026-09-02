//! Typed, front-end-agnostic wrappers over the authoring engine.
//!
//! These mirror the CLI's pure cores but return structured outcomes instead of
//! printing, so a GUI can drive `create` / `verify` / `sign` and render the
//! results itself. Every operation here is file-based (bytes in, bytes/verdicts
//! out) and never touches a device.

use anyhow::{bail, Context, Result};

use freemkv_flash::platform;

use crate::abi;
use crate::engine::{self, CreateReport};
use crate::family::{self, ChipInfo};
use crate::scheme::{self, Family, IntegrityScheme, MtkCmac, RegionChange, RegionVerdict};

/// Outcome of verifying a firmware image's integrity table(s).
pub struct VerifyOutcome {
    /// The integrity scheme that was selected for the image.
    pub scheme: &'static str,
    /// Per-region match/mismatch verdicts.
    pub verdicts: Vec<RegionVerdict>,
    /// `true` iff there is at least one active region and all regions match.
    pub ok: bool,
}

/// Select a scheme and verify `image`.
pub fn verify(image: &[u8], forced: Option<Family>) -> Result<VerifyOutcome> {
    let scheme = scheme::select_scheme(image, forced)?;
    let verdicts = scheme.verify(image)?;
    let ok = !verdicts.is_empty() && verdicts.iter().all(|v| v.ok);
    Ok(VerifyOutcome {
        scheme: scheme.name(),
        verdicts,
        ok,
    })
}

/// Outcome of re-signing a firmware image.
pub struct SignOutcome {
    /// The integrity scheme that was selected for the image.
    pub scheme: &'static str,
    /// The re-signed image bytes (guaranteed to self-verify).
    pub image: Vec<u8>,
    /// The regions whose digests changed.
    pub changes: Vec<RegionChange>,
}

/// Select a scheme, re-sign every active region, and self-verify the result.
pub fn sign(image: &[u8], forced: Option<Family>) -> Result<SignOutcome> {
    let scheme = scheme::select_scheme(image, forced)?;
    let (signed, changes) = scheme.sign(image)?;
    let verdicts = scheme.verify(&signed)?;
    if verdicts.is_empty() || verdicts.iter().any(|v| !v.ok) {
        bail!("internal error: re-signed image does not self-verify");
    }
    Ok(SignOutcome {
        scheme: scheme.name(),
        image: signed,
        changes,
    })
}

/// Outcome of creating freemkv firmware from an OEM image.
pub struct CreateOutcome {
    /// The platform engine that built the image.
    pub engine: &'static str,
    /// The detected chip (vendor/model/rev), if identification succeeded.
    pub chip: Option<ChipInfo>,
    /// The full build report (addresses, hooks, injected handler).
    pub report: CreateReport,
    /// Post-build CMAC verdicts (guaranteed all-OK on success).
    pub verdicts: Vec<RegionVerdict>,
}

impl CreateOutcome {
    /// The produced freemkv firmware image bytes.
    pub fn image(&self) -> &[u8] {
        &self.report.image
    }
}

/// Build freemkv firmware from an OEM image: pick the platform engine, inject
/// the mods, re-sign, and refuse to return an image that does not re-verify.
pub fn create(image: &[u8]) -> Result<CreateOutcome> {
    let eng = engine::detect(image).context("selecting a platform engine for this image")?;
    let chip = family::detect_chip(image).ok();
    let report = eng.create(image).context("building freemkv firmware")?;

    let verdicts = MtkCmac.verify(&report.image)?;
    if verdicts.is_empty() || verdicts.iter().any(|v| !v.ok) {
        bail!("internal error: modified image does not re-verify");
    }
    Ok(CreateOutcome {
        engine: eng.name(),
        chip,
        report,
        verdicts,
    })
}

/// Outcome of probing a live drive for freemkv firmware (the CLI's `info`
/// identity check). Opens the device read-only — never writes anything.
pub struct ProbeOutcome {
    /// Whether the drive answered the freemkv identity knock.
    pub detected: bool,
    /// A human-readable one-line detail (version if known, or why not detected).
    pub detail: String,
}

/// Send the freemkv identity command (`3C 0E C0 DE 01 …`) to `device` and
/// report whether a freemkv drive answered. Read-only; never writes.
pub fn probe_device(device: &str) -> Result<ProbeOutcome> {
    let mut dev = platform::open(device, false).with_context(|| format!("opening {device}"))?;

    const ALLOC_LEN: usize = 96;
    let cdb = abi::build_cdb(abi::SubFn::Identity, None, ALLOC_LEN as u16);

    match dev.command_in(&cdb, ALLOC_LEN) {
        Ok(resp) if abi::verify_response(&resp) => {
            let detail = match resp.get(abi::RESP_MAGIC.len()) {
                Some(&v) => format!("DETECTED (version 0x{v:02x})"),
                None => "DETECTED".to_string(),
            };
            Ok(ProbeOutcome {
                detected: true,
                detail,
            })
        }
        // A well-formed non-freemkv reply, or a SCSI-level error from a drive
        // that doesn't recognize the knock — both mean "not freemkv".
        Ok(_) | Err(_) => Ok(ProbeOutcome {
            detected: false,
            detail: "NOT DETECTED (stock/OEM or other firmware)".to_string(),
        }),
    }
}
