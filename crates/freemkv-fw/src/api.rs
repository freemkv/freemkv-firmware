//! Typed, front-end-agnostic wrappers over the authoring engine.
//!
//! These mirror the CLI's pure cores but return structured outcomes instead of
//! printing, so a GUI can drive `create` / `verify` / `sign` and render the
//! results itself. Every operation here is file-based (bytes in, bytes/verdicts
//! out) and never touches a device.

use anyhow::{bail, Context, Result};

use freemkv_flash::platform;

use crate::engine::{self, CreateReport};
use crate::family::{self, ChipInfo};
use crate::scheme::{self, Family, IntegrityScheme, MtkCmac, RegionChange, RegionVerdict};
use crate::{abi, diagnostics};

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
    diagnostics::run("verify", || {
        diagnostics::image("input image", image);
        verify_inner(image, forced)
    })
}

fn verify_inner(image: &[u8], forced: Option<Family>) -> Result<VerifyOutcome> {
    let scheme = scheme::select_scheme(image, forced)?;
    diagnostics::record(format!(
        "verify: selected scheme={} forced={forced:?}",
        scheme.name()
    ));
    let verdicts = scheme.verify(image)?;
    for verdict in &verdicts {
        diagnostics::record(format!("integrity verdict: {verdict:?}"));
    }
    let ok = !verdicts.is_empty() && verdicts.iter().all(|v| v.ok);
    diagnostics::record(format!(
        "verification result: ok={ok} regions={}",
        verdicts.len()
    ));
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
    diagnostics::run("sign", || {
        diagnostics::image("input image", image);
        sign_inner(image, forced)
    })
}

fn sign_inner(image: &[u8], forced: Option<Family>) -> Result<SignOutcome> {
    let scheme = scheme::select_scheme(image, forced)?;
    diagnostics::record(format!(
        "sign: selected scheme={} forced={forced:?}",
        scheme.name()
    ));
    let (signed, changes) = scheme.sign(image)?;
    for change in &changes {
        diagnostics::record(format!("integrity change: {change:?}"));
    }
    diagnostics::image("signed image", &signed);
    let verdicts = scheme.verify(&signed)?;
    for verdict in &verdicts {
        diagnostics::record(format!("post-sign integrity: {verdict:?}"));
    }
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
    diagnostics::run("create", || {
        diagnostics::image("input image", image);
        create_inner(image)
    })
}

fn create_inner(image: &[u8]) -> Result<CreateOutcome> {
    let eng = engine::detect(image).context("selecting a platform engine for this image")?;
    diagnostics::record(format!("create: engine={}", eng.name()));
    let chip = family::detect_chip(image).ok();
    diagnostics::record(format!("create: chip={chip:?}"));
    let report = eng.create(image).context("building freemkv firmware")?;

    let mut resolved_facts = report.clone();
    resolved_facts.image.clear();
    resolved_facts.handler_bytes.clear();
    diagnostics::record(format!(
        "create resolved facts (payloads omitted): {resolved_facts:?}"
    ));
    diagnostics::image("created image", &report.image);
    diagnostics::record(format!("create: scanner_entry=0x{:x} cdb_base=0x{:x} handler_va=0x{:x} handler_bytes={} boot_init_site=0x{:x} boot_stub_va=0x{:x} flag_base=0x{:x}", report.scanner_entry, report.cdb_base, report.handler_va, report.handler_bytes.len(), report.boot_init_site, report.boot_stub_va, report.flag_base));
    let verdicts = MtkCmac.verify(&report.image)?;
    for verdict in &verdicts {
        diagnostics::record(format!("post-create integrity: {verdict:?}"));
    }
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

/// Send the freemkv identity command (`abi::build_identity_cdb`) to `device` and
/// report whether a freemkv drive answered. Read-only; never writes.
pub fn probe_device(device: &str) -> Result<ProbeOutcome> {
    diagnostics::run("probe_device", || {
        diagnostics::record(format!("probe: device={device:?}"));
        probe_device_inner(device)
    })
}

fn probe_device_inner(device: &str) -> Result<ProbeOutcome> {
    let mut dev = platform::open(device, false).with_context(|| format!("opening {device}"))?;

    const ALLOC_LEN: usize = 96;
    let cdb = abi::build_identity_cdb(ALLOC_LEN as u16);

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
        other => {
            diagnostics::record(format!("identity probe did not match: {other:?}"));
            Ok(ProbeOutcome {
                detected: false,
                detail: "NOT DETECTED (stock/OEM or other firmware)".to_string(),
            })
        }
    }
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
