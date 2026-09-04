//! Emitter-aware **structural detour audit**.
//!
//! `create --json` says a lever was `Applied`, and the image self-verifies (CMAC),
//! but neither proves the detour actually landed where it must. This audit closes
//! that gap: for every `Applied` lever it recomputes the **exact** expected hook
//! bytes with the emitter's own [`crate::thumb::encode_bl`] and asserts they are
//! present in the produced image at the emitter's real hook site (`speed_gate+4`,
//! `region_emitter+14`, the AKE/Gate-A/deny `bl` sites), that the injected stub is
//! not blank flash, that the hijacked record was repointed to the injected handler,
//! that the DE byte is `0xDE`, and that the CMAC tables verify.
//!
//! It works off the lever `facts` (the addresses the emitter recorded), NOT the
//! finder anchor addresses — those are where a signature *matched*, not where the
//! `bl` was written, which is why a by-hand anchor check is misleading.

use crate::engine::lever::{LeverId, LeverOutcome, ModifyReport};
use crate::engine::mt1959_build::is_freemkv_patched;
use crate::thumb;
use freemkv_flash::cmac;

/// One structural check with its verdict.
#[derive(Debug, Clone)]
pub struct AuditCheck {
    /// The lever this check belongs to.
    pub lever: &'static str,
    /// What was checked.
    pub what: String,
    /// Whether it passed.
    pub ok: bool,
    /// Human detail (addresses, expected vs found).
    pub detail: String,
}

/// The result of a structural audit: one check per verified property.
#[derive(Debug, Clone)]
pub struct AuditResult {
    /// All checks run, in order.
    pub checks: Vec<AuditCheck>,
}

impl AuditResult {
    /// True if every check passed.
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
    /// The checks that failed.
    pub fn failures(&self) -> impl Iterator<Item = &AuditCheck> {
        self.checks.iter().filter(|c| !c.ok)
    }
}

/// Look up a grounded fact value by key on a lever report.
fn fact(l: &crate::engine::lever::LeverReport, key: &str) -> Option<u32> {
    l.facts.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// True if the 16 bytes at `va` are not all erased flash (`0xFF`) — i.e. a stub
/// was actually written there.
fn stub_present(img: &[u8], va: u32) -> bool {
    let a = va as usize;
    a + 16 <= img.len() && img[a..a + 16].iter().any(|&b| b != 0xFF)
}

/// Assert the 4 bytes at `site` are exactly the `bl` the emitter would write to
/// reach `stub` (recomputed via [`thumb::encode_bl`]).
fn check_bl(
    checks: &mut Vec<AuditCheck>,
    lever: &'static str,
    what: &str,
    img: &[u8],
    site: u32,
    stub: u32,
) {
    let s = site as usize;
    let expected = thumb::encode_bl(s, stub);
    let (ok, detail) = match expected {
        None => (
            false,
            format!("bl 0x{site:08x} -> 0x{stub:08x} out of range"),
        ),
        Some(exp) => {
            if s + 4 > img.len() {
                (false, format!("hook site 0x{site:08x} past end of image"))
            } else {
                let found = &img[s..s + 4];
                (
                    found == exp,
                    format!(
                        "site 0x{site:08x} -> stub 0x{stub:08x}: expected {:02x?}, found {:02x?}",
                        exp, found
                    ),
                )
            }
        }
    };
    let mut ok = ok;
    let mut detail = detail;
    if ok && !stub_present(img, stub) {
        ok = false;
        detail = format!("bl present but stub at 0x{stub:08x} is blank (0xFF)");
    }
    checks.push(AuditCheck {
        lever,
        what: what.to_string(),
        ok,
        detail,
    });
}

/// Structurally audit that a `ModifyReport`'s Applied levers actually landed in
/// its produced image. `original` is the pre-modify image (for reference); all
/// structural assertions are against `report.image`.
pub fn audit_image(original: &[u8], report: &ModifyReport) -> AuditResult {
    let img = &report.image;
    let mut checks = Vec::new();
    let _ = original;

    for l in &report.levers {
        if l.outcome != LeverOutcome::Applied {
            continue; // AlreadyPresent has no fresh detour to check; N/A + skipped emit nothing.
        }
        let name = l.id.label();
        match l.id {
            LeverId::Identity => {
                // The hijacked record's handler pointer must now target the
                // injected handler (VA | thumb-bit), and the injected handler
                // carries the RESP_MAGIC identity string.
                match (fact(l, "handler_va"), fact(l, "record_off")) {
                    (Some(hva), Some(roff)) => {
                        let ok_ptr = (roff as usize) + 8 <= img.len()
                            && thumb::read_u32(img, roff as usize + 4) == (hva | 1);
                        checks.push(AuditCheck {
                            lever: name,
                            what: "record repointed to injected handler".into(),
                            ok: ok_ptr,
                            detail: format!(
                                "record 0x{roff:08x}+4 -> 0x{:08x} (want 0x{:08x})",
                                thumb::read_u32(img, roff as usize + 4),
                                hva | 1
                            ),
                        });
                        checks.push(AuditCheck {
                            lever: name,
                            what: "handler injected (RESP_MAGIC present)".into(),
                            ok: is_freemkv_patched(img) && stub_present(img, hva),
                            detail: format!("handler_va 0x{hva:08x}"),
                        });
                    }
                    _ => checks.push(AuditCheck {
                        lever: name,
                        what: "handler facts present".into(),
                        ok: false,
                        detail: "missing handler_va/record_off".into(),
                    }),
                }
            }
            LeverId::Speed => {
                if let (Some(gate), Some(stub)) = (fact(l, "speed_gate"), fact(l, "speed_stub_va"))
                {
                    check_bl(&mut checks, name, "speed detour bl", img, gate + 4, stub);
                }
            }
            LeverId::RegionFree => {
                if let (Some(emitter), Some(stub)) =
                    (fact(l, "region_emitter"), fact(l, "region_stub_va"))
                {
                    check_bl(
                        &mut checks,
                        name,
                        "region detour bl",
                        img,
                        emitter + 14,
                        stub,
                    );
                }
            }
            LeverId::RawRead => {
                if let (Some(site), Some(stub)) = (fact(l, "ake_site"), fact(l, "ake_stub_va")) {
                    check_bl(&mut checks, name, "AKE detour bl", img, site, stub);
                }
                if let (Some(site), Some(stub)) = (fact(l, "gatea_gate"), fact(l, "gatea_stub_va"))
                {
                    check_bl(&mut checks, name, "Gate-A detour bl", img, site, stub);
                }
                if let (Some(site), Some(stub)) = (fact(l, "deny_site"), fact(l, "deny_stub_va")) {
                    check_bl(&mut checks, name, "deny-reset detour bl", img, site, stub);
                }
            }
            LeverId::DowngradeEnable => {
                if let Some(de) = fact(l, "de_off") {
                    let a = de as usize;
                    let ok = a < img.len() && img[a] == 0xDE;
                    checks.push(AuditCheck {
                        lever: name,
                        what: "DE byte set".into(),
                        ok,
                        detail: format!(
                            "0x{de:08x} = 0x{:02x} (want 0xDE)",
                            img.get(a).copied().unwrap_or(0)
                        ),
                    });
                }
            }
        }
    }

    // Integrity: the produced image must carry valid CMAC tables.
    checks.push(AuditCheck {
        lever: "integrity",
        what: "CMAC tables verify".into(),
        ok: cmac::verify(img),
        detail: "AES-CMAC over active regions".into(),
    });

    AuditResult { checks }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
