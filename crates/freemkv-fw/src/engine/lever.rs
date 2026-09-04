//! Family-agnostic MODIFY model: levers + per-lever report.
//!
//! A **lever** is one independent unit of modification (Region-free, VID/Raw-read,
//! Speed, Downgrade-enable, …). Each lever is attempted on its own; a miss on one
//! lever never aborts the others. The whole run aborts only when the image is
//! undetectable or nothing at all can be built (see [`crate::engine::Engine::modify`]).
//!
//! These types carry **no chip-specific fields** — they are the shared vocabulary
//! every engine (`MT1959`, `MT1939`, future Pioneer/…) reports in, and are the
//! natural home for the eventual `freemkv-chipset` crate.

/// Stable machine id for a lever, independent of the engine that implements it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeverId {
    /// The vendor-command handler + DumpAll — the base that makes toggles addressable.
    Identity,
    /// Region-free (RPC-1).
    RegionFree,
    /// Raw read / clear VID (VID producer gate + AKE accept + deny reset).
    RawRead,
    /// Read-ramp ceiling unlock.
    Speed,
    /// Downgrade-enable byte (family-agnostic; any image with an identity page).
    DowngradeEnable,
}

impl LeverId {
    /// Human label used in the report.
    pub fn label(self) -> &'static str {
        match self {
            LeverId::Identity => "Identity",
            LeverId::RegionFree => "Region Free",
            LeverId::RawRead => "Raw read",
            LeverId::Speed => "Speed",
            LeverId::DowngradeEnable => "Downgrade (DE)",
        }
    }

    /// Stable serialization key.
    pub fn key(self) -> &'static str {
        match self {
            LeverId::Identity => "Identity",
            LeverId::RegionFree => "RegionFree",
            LeverId::RawRead => "RawRead",
            LeverId::Speed => "Speed",
            LeverId::DowngradeEnable => "DowngradeEnable",
        }
    }
}

/// The four states a lever attempt can end in (the MODIFY UX model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeverOutcome {
    /// Patched on this run (bytes changed).
    Applied,
    /// The feature is already in the image — idempotent no-op (DE already 0xDE,
    /// or a re-fed freemkv/MK image). Not a failure.
    AlreadyPresent,
    /// Out of scope for this drive's capability (e.g. VID on a DVD-only part).
    NotApplicable { reason: String },
    /// In scope, but the grounded find missed on THIS image. Not a whole-run
    /// abort — the other levers still run.
    SignatureNotFound { detail: String },
}

impl LeverOutcome {
    /// The short status word shown in the human report.
    pub fn word(&self) -> &'static str {
        match self {
            LeverOutcome::Applied => "applied",
            LeverOutcome::AlreadyPresent => "already set",
            LeverOutcome::NotApplicable { .. } => "n/a",
            LeverOutcome::SignatureNotFound { .. } => "skipped",
        }
    }

    /// True when the lever changed or already had its effect (counts as success).
    pub fn is_effective(&self) -> bool {
        matches!(self, LeverOutcome::Applied | LeverOutcome::AlreadyPresent)
    }
}

/// One audited byte edit (for the audit trail + KAT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchSite {
    /// File offset written.
    pub off: u32,
    /// The `u16` before the edit.
    pub before: u16,
    /// The `u16` after the edit.
    pub after: u16,
    /// What the edit is.
    pub what: &'static str,
}

/// The outcome of one lever, with its grounded facts.
#[derive(Debug, Clone)]
pub struct LeverReport {
    /// Which lever.
    pub id: LeverId,
    /// The outcome.
    pub outcome: LeverOutcome,
    /// Grounded addresses (name → value) for the `details:` block and audit.
    pub facts: Vec<(&'static str, u32)>,
}

impl LeverReport {
    /// Applied, with grounded facts.
    pub fn applied(id: LeverId, facts: Vec<(&'static str, u32)>) -> Self {
        Self {
            id,
            outcome: LeverOutcome::Applied,
            facts,
        }
    }
    /// Already present (idempotent).
    pub fn already(id: LeverId, facts: Vec<(&'static str, u32)>) -> Self {
        Self {
            id,
            outcome: LeverOutcome::AlreadyPresent,
            facts,
        }
    }
    /// Out of scope for this capability.
    pub fn not_applicable(id: LeverId, reason: impl Into<String>) -> Self {
        Self {
            id,
            outcome: LeverOutcome::NotApplicable {
                reason: reason.into(),
            },
            facts: vec![],
        }
    }
    /// In scope but the signature missed on this image.
    pub fn missed(id: LeverId, detail: impl Into<String>) -> Self {
        Self {
            id,
            outcome: LeverOutcome::SignatureNotFound {
                detail: detail.into(),
            },
            facts: vec![],
        }
    }
}

/// Hardware-validation confidence of a modification. Today every family/lever is
/// `StaticOnly` — the emitted bytes are structurally valid and self-verify, but no
/// modification has been confirmed on a real drive yet. A label, never a gate: it
/// never blocks producing a structurally-valid modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    /// Confirmed working on real hardware.
    HardwareConfirmed,
    /// Structurally valid + self-verifying, but not yet hardware-validated.
    StaticOnly,
}

impl Validation {
    /// Short machine key.
    pub fn key(self) -> &'static str {
        match self {
            Validation::HardwareConfirmed => "hardware-confirmed",
            Validation::StaticOnly => "static-only",
        }
    }
    /// Human note.
    pub fn note(self) -> &'static str {
        match self {
            Validation::HardwareConfirmed => "hardware-confirmed",
            Validation::StaticOnly => {
                "static-only (structurally valid + self-verifying; pending hardware validation)"
            }
        }
    }
}

/// The result of a MODIFY run: the re-signed image plus per-lever outcomes.
#[derive(Debug, Clone)]
pub struct ModifyReport {
    /// Engine label (e.g. `"MT1959"`).
    pub engine: &'static str,
    /// Detected chip family label.
    pub family: String,
    /// Drive vendor/model/rev (display), from the descriptor.
    pub vendor: String,
    /// Drive model.
    pub model: String,
    /// Drive revision.
    pub rev: String,
    /// Media class label (e.g. `"BD/UHD"`, `"DVD"`).
    pub media: String,
    /// Per-lever outcomes, in a fixed order.
    pub levers: Vec<LeverReport>,
    /// The re-signed, self-verified image.
    pub image: Vec<u8>,
    /// Hardware-validation confidence (uniform label, never a gate).
    pub validation: Validation,
}

impl ModifyReport {
    /// A one-line summary: engine · media · what applied.
    pub fn summary(&self) -> String {
        let applied: Vec<String> = self
            .levers
            .iter()
            .filter(|l| l.outcome == LeverOutcome::Applied)
            .map(|l| l.id.label().to_string())
            .collect();
        let already: Vec<&str> = self
            .levers
            .iter()
            .filter(|l| l.outcome == LeverOutcome::AlreadyPresent)
            .map(|l| l.id.label())
            .collect();
        let skipped: Vec<&str> = self
            .levers
            .iter()
            .filter(|l| matches!(l.outcome, LeverOutcome::SignatureNotFound { .. }))
            .map(|l| l.id.label())
            .collect();
        let mut parts = Vec::new();
        if !applied.is_empty() {
            parts.push(format!("{} applied", applied.join(" + ")));
        }
        if !already.is_empty() {
            parts.push(format!("{} already set", already.join(" + ")));
        }
        if !skipped.is_empty() {
            parts.push(format!("{} skipped", skipped.join(" + ")));
        }
        if parts.is_empty() {
            parts.push("nothing applied".to_string());
        }
        format!("{} {} — {}", self.family, self.media, parts.join(" · "))
    }

    /// True if at least one lever took effect (exit code 0).
    pub fn any_effective(&self) -> bool {
        self.levers.iter().any(|l| l.outcome.is_effective())
    }

    /// Machine-readable JSON (hand-rolled — no serde dependency).
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push('{');
        s.push_str(&format!("\"engine\":{},", jstr(self.engine)));
        s.push_str(&format!("\"family\":{},", jstr(&self.family)));
        s.push_str(&format!("\"vendor\":{},", jstr(&self.vendor)));
        s.push_str(&format!("\"model\":{},", jstr(&self.model)));
        s.push_str(&format!("\"rev\":{},", jstr(&self.rev)));
        s.push_str(&format!("\"media\":{},", jstr(&self.media)));
        s.push_str(&format!("\"validation\":{},", jstr(self.validation.key())));
        s.push_str(&format!("\"summary\":{},", jstr(&self.summary())));
        s.push_str("\"levers\":[");
        for (i, l) in self.levers.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("{{\"id\":{},", jstr(l.id.key())));
            s.push_str(&format!("\"label\":{},", jstr(l.id.label())));
            s.push_str("\"outcome\":");
            match &l.outcome {
                LeverOutcome::Applied => s.push_str("\"Applied\""),
                LeverOutcome::AlreadyPresent => s.push_str("\"AlreadyPresent\""),
                LeverOutcome::NotApplicable { reason } => s.push_str(&format!(
                    "{{\"NotApplicable\":{{\"reason\":{}}}}}",
                    jstr(reason)
                )),
                LeverOutcome::SignatureNotFound { detail } => s.push_str(&format!(
                    "{{\"SignatureNotFound\":{{\"detail\":{}}}}}",
                    jstr(detail)
                )),
            }
            s.push_str(",\"facts\":{");
            for (j, (k, v)) in l.facts.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str(&format!("{}:{}", jstr(k), v));
            }
            s.push_str("}}");
        }
        s.push_str("]}");
        s
    }
}

/// Minimal JSON string escaping.
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

#[cfg(test)]
#[path = "lever_tests.rs"]
mod tests;
