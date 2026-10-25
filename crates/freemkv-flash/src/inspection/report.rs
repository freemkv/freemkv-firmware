//! Provider-independent presentation and exports.
use serde::Serialize;
use std::{ops::Range, sync::Arc};

/// A display field; units and interpretation are supplied by its provider.
#[derive(Clone, Debug, Serialize)]
pub struct Field {
    /// English field label.
    pub label: String,
    /// Printable value.
    pub value: String,
}
impl Field {
    pub(crate) fn new(label: impl Into<String>, value: impl ToString) -> Self {
        Self {
            label: label.into(),
            value: value.to_string(),
        }
    }
}
pub use crate::firmware_comparison::{FamilyRelationship, HardwareFamily};
/// One record with its original position and all interpreted fields.
#[derive(Clone, Debug, Serialize)]
pub struct RecordView {
    /// Source-order record number.
    pub index: usize,
    /// Region-relative byte range.
    pub range: Range<usize>,
    /// Interpreted values; remaining data remains accessible in region bytes.
    pub fields: Vec<Field>,
}
/// Structurally recognized table.
#[derive(Clone, Debug, Serialize)]
pub struct TableView {
    /// Recognition format.
    pub format: String,
    /// Logical byte range.
    pub range: Range<usize>,
    /// All records, in original order.
    pub records: Vec<RecordView>,
}
/// What a region holds. Compare treats differences in [`RegionRole::PerUnit`]
/// and [`RegionRole::ReadBack`] regions as expected, every other as unexpected.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum RegionRole {
    /// Firmware code or data an update writes.
    Code,
    /// Digests or signatures over other regions.
    Integrity,
    /// Identity strings: vendor, model, revision, banner.
    Identity,
    /// Build-wide settings an update writes.
    Configuration,
    /// Data each drive writes for itself (calibration, per-unit settings).
    PerUnit,
    /// Bytes a drive read returns in place of what flash stores.
    ReadBack,
    /// Purpose not established.
    Unknown,
}
impl RegionRole {
    /// Whether two sources of the same build are expected to differ here.
    pub fn expected_difference(self) -> bool {
        matches!(self, Self::PerUnit | Self::ReadBack)
    }
    /// English display name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Code => "Code",
            Self::Integrity => "Integrity",
            Self::Identity => "Identity",
            Self::Configuration => "Configuration",
            Self::PerUnit => "Per-unit",
            Self::ReadBack => "Read-back",
            Self::Unknown => "Unknown",
        }
    }
}
/// A logical, possibly decompressed region.
#[derive(Clone, Debug, Serialize)]
pub struct RegionView {
    /// Provider region identifier.
    pub id: usize,
    /// Display name.
    pub name: String,
    /// What the region holds.
    pub role: RegionRole,
    /// Region facts and coordinates.
    pub fields: Vec<Field>,
    /// Recognized tables.
    pub tables: Vec<TableView>,
}
/// A component inventory with its region tree.
#[derive(Clone, Debug, Serialize)]
pub struct ComponentView {
    /// Component name supplied by the format provider.
    pub name: String,
    /// Identity/integrity/capability facts.
    pub fields: Vec<Field>,
    /// Logical regions.
    pub regions: Vec<RegionView>,
    /// Nonfatal limitations.
    pub diagnostics: Vec<String>,
    /// Indexes into `diagnostics` of the analyser's standing caveats, true of
    /// every file it reads; summary views may leave them out.
    #[serde(skip)]
    pub standing: Vec<usize>,
}
impl ComponentView {
    /// The diagnostics about this component, without the standing caveats.
    pub fn findings(&self) -> impl Iterator<Item = &String> {
        self.diagnostics
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.standing.contains(i))
            .map(|(_, d)| d)
    }
}
/// Live facts, captured separately from firmware-file contents.
#[derive(Clone, Debug, Serialize)]
pub struct LiveState {
    /// Capture time, Unix seconds.
    pub captured_at: u64,
    /// Read-only drive state fields.
    pub fields: Vec<Field>,
    /// Unsupported/failed optional queries.
    pub diagnostics: Vec<String>,
}
/// One immutable inspection. Raw firmware is deliberately omitted from exports.
#[derive(Debug, Serialize)]
pub struct Inspection {
    /// Export schema version.
    pub schema: u32,
    /// Application build that produced this report.
    pub application_version: &'static str,
    /// File basename only; private local paths are not exported.
    pub source: String,
    /// Actual input bytes' digest.
    pub sha256: String,
    /// Hardware compatibility family, when derivable.
    pub family: Option<HardwareFamily>,
    /// Whether the provider derives hardware families at all. When it does
    /// not, reports omit the family line rather than call a known file Unknown.
    #[serde(skip)]
    pub derives_family: bool,
    /// Firmware components.
    pub components: Vec<ComponentView>,
    /// Expected components absent from this source; never silently synthesized.
    pub missing_components: Vec<String>,
    /// Drive state exists only for live capture.
    pub live: Option<LiveState>,
    #[serde(skip)]
    pub(crate) analyses: Vec<super::comparison::FirmwareAnalysis>,
}
impl Inspection {
    /// Logical region data for bounded hex/detail rendering, never encrypted offsets.
    pub fn region_bytes(&self, component: usize, region: usize) -> Option<&[u8]> {
        self.analyses
            .iter()
            .find(|a| {
                a.identity.component
                    == self
                        .components
                        .get(component)
                        .map(|c| c.name.as_str())
                        .unwrap_or("")
            })?
            .regions
            .iter()
            .find(|r| r.id == region)
            .map(|r| r.bytes())
    }
    /// Versioned JSON without raw firmware or full filesystem paths.
    pub fn json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
    /// The hardware family line's value, or `None` when the provider derives
    /// no families.
    pub fn family_line(&self) -> Option<String> {
        match &self.family {
            Some(f) => Some(format!("{} ({})", f.id, f.scheme)),
            None => self.derives_family.then(|| "Unknown".into()),
        }
    }
    /// Forum-friendly text, with hardware family first when the provider
    /// derives one.
    pub fn text(&self) -> String {
        let mut out = self
            .family_line()
            .map_or_else(String::new, |f| format!("Hardware family: {f}\n"));
        out.push_str(&format!(
            "Source: {}\nSHA-256: {}\n",
            self.source, self.sha256
        ));
        if let Some(live) = &self.live {
            out.push_str(&format!(
                "Drive capture: {} Unix seconds\n",
                live.captured_at
            ));
            for f in &live.fields {
                out.push_str(&format!("{}: {}\n", f.label, f.value));
            }
            for d in &live.diagnostics {
                out.push_str(&format!("Note: {d}\n"));
            }
        }
        for name in &self.missing_components {
            out.push_str(&format!("\n{name}: Not included in this source.\n"));
        }
        for c in &self.components {
            out.push_str(&format!("\n{}\n", c.name));
            for f in &c.fields {
                out.push_str(&format!("  {}: {}\n", f.label, f.value));
            }
            for d in &c.diagnostics {
                out.push_str(&format!("  Note: {d}\n"));
            }
            for r in &c.regions {
                out.push_str(&format!("  {}\n", r.name));
                for f in &r.fields {
                    out.push_str(&format!("    {}: {}\n", f.label, f.value));
                }
                for t in &r.tables {
                    out.push_str(&format!(
                        "    Table {}: {} records\n",
                        t.format,
                        t.records.len()
                    ));
                    for record in &t.records {
                        out.push_str(&format!(
                            "      {} @ {:#x}: {}\n",
                            record.index,
                            record.range.start,
                            record
                                .fields
                                .iter()
                                .map(|f| format!("{}={}", f.label, f.value))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                }
            }
        }
        out
    }
}
/// High-level content findings for one logical firmware region.
#[derive(Debug, Serialize)]
pub struct RegionSummary {
    /// Human-readable region name without inferred purpose.
    pub name: String,
    /// The region's role (source A's, else source B's).
    pub role: RegionRole,
    /// Whether a difference here is expected (per-unit or read-back data on
    /// either side); the verdict counts only unexpected differences.
    pub expected: bool,
    /// Bytes changed on source A, excluding established metadata/relocations.
    pub left_changed: usize,
    /// Bytes changed on source B, excluding established metadata/relocations.
    pub right_changed: usize,
    /// Whether part of this region could not be compared.
    pub unresolved: bool,
    /// Total decoded/expanded bytes across both sources.
    pub total_bytes: usize,
    /// Bytes not compared, across both sources.
    pub unresolved_bytes: usize,
    /// Symmetric percentage different after alignment and exclusions.
    pub difference_percent: Option<f64>,
    /// Positional changes in recognized text tables, distinct from strategy semantics.
    pub table_changes: usize,
    /// Recognized table records compared at equal positions.
    pub table_records: usize,
}
impl RegionSummary {
    /// Whether any content changed or could not be compared.
    pub fn differs(&self) -> bool {
        self.left_changed != 0 || self.right_changed != 0 || self.unresolved
    }
}
/// Provider-neutral comparison section.
#[derive(Debug, Serialize)]
pub struct ComparisonSection {
    /// Shared relation facts, absent when a component could not be compared.
    pub facts: Option<crate::firmware_comparison::ComparisonFacts>,
    /// Component or region name.
    pub name: String,
    /// Summary of established findings.
    pub fields: Vec<Field>,
    /// Plain-English findings for the default view.
    pub summary: Vec<String>,
    /// Per-region summary, separate from byte-level evidence.
    pub regions: Vec<RegionSummary>,
    /// Detailed findings as printable rows.
    pub details: Vec<String>,
    /// Verified relocations, excluded from substantive change counts.
    pub relocations: Vec<String>,
}
/// Comparison output plus retained sources for Inspect A/B navigation.
#[derive(Debug, Serialize)]
pub struct ComparisonReport {
    /// Versioned export schema.
    pub schema: u32,
    /// Application build that produced this report.
    pub application_version: &'static str,
    /// Always the first user-facing result.
    pub family: FamilyRelationship,
    /// Source A's family identity.
    pub left_family: Option<HardwareFamily>,
    /// Source B's family identity.
    pub right_family: Option<HardwareFamily>,
    /// Component results including absent-component notices.
    pub sections: Vec<ComparisonSection>,
    /// Retained source A, including its inventory and input digest.
    #[serde(serialize_with = "serialize_inspection")]
    pub left: Arc<Inspection>,
    /// Retained source B, including its inventory and input digest.
    #[serde(serialize_with = "serialize_inspection")]
    pub right: Arc<Inspection>,
}
impl ComparisonReport {
    /// Regions with unexpected differences: changed or unresolved content
    /// outside per-unit and read-back regions. Zero means no unexpected change.
    pub fn unexpected_regions(&self) -> usize {
        self.sections
            .iter()
            .flat_map(|s| &s.regions)
            .filter(|r| !r.expected && r.differs())
            .count()
    }
    /// Forum-friendly summary, family relationship first when either
    /// provider derives families.
    pub fn text(&self) -> String {
        let mut out = if self.left.derives_family || self.right.derives_family {
            format!(
                "Hardware family: {:?}\nA: {} — {}\nB: {} — {}\n",
                self.family,
                self.left.source,
                self.left_family
                    .as_ref()
                    .map_or("Unknown", |f| f.id.as_str()),
                self.right.source,
                self.right_family
                    .as_ref()
                    .map_or("Unknown", |f| f.id.as_str())
            )
        } else {
            format!("A: {}\nB: {}\n", self.left.source, self.right.source)
        };
        for s in &self.sections {
            out.push_str(&format!("\n{}\n", s.name));
            for finding in &s.summary {
                out.push_str(&format!("{finding}\n"));
            }
        }
        out
    }
    /// JSON export without raw firmware.
    pub fn json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

fn serialize_inspection<S: serde::Serializer>(
    value: &Arc<Inspection>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_ref().serialize(serializer)
}

impl LiveState {
    /// An empty state stamped with the current time.
    pub(crate) fn now() -> Self {
        Self {
            captured_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            fields: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
    /// Append the drive's DVD region state (standard MMC REPORT KEY, RPC
    /// format). A drive that cannot report it adds a note instead.
    pub(crate) fn read_dvd_region(&mut self, dev: &mut dyn crate::platform::ScsiDevice) {
        match dev.command_in(
            &pioneer_optical::rpc::report_key(),
            pioneer_optical::rpc::RESPONSE_LEN,
        ) {
            Ok(bytes) => match pioneer_optical::rpc::State::parse(&bytes) {
                Some(rpc) => {
                    self.fields
                        .push(Field::new("DVD region", dvd_region_label(rpc)));
                    if rpc.scheme == 1 {
                        self.fields.push(Field::new(
                            "User region changes remaining",
                            rpc.user_changes_remaining,
                        ));
                        self.fields.push(Field::new(
                            "Vendor region resets remaining",
                            rpc.vendor_resets_remaining,
                        ));
                        self.fields.push(Field::new("RPC type", rpc.type_code));
                    }
                    self.fields.push(Field::new("RPC scheme", rpc.scheme));
                }
                None => self
                    .diagnostics
                    .push("DVD region response was incomplete or malformed.".into()),
            },
            Err(e) => {
                crate::diagnostics::record(format!("Optional DVD RPC read failed: {e:#}"));
                self.diagnostics.push(
                    "DVD region and remaining changes could not be read from this drive.".into(),
                );
            }
        }
    }
}

/// The regions the drive's RPC mask permits. The mask, not the type code, is
/// what the drive enforces: 0x00 permits all eight, 0xFF permits none.
pub(crate) fn dvd_region_label(rpc: pioneer_optical::rpc::State) -> String {
    if rpc.scheme == 0 {
        return "Region-free".into();
    }
    if rpc.prohibited_regions == 0xff {
        return "Not set".into();
    }
    (1..=8)
        .filter(|&r| rpc.allows(r))
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
