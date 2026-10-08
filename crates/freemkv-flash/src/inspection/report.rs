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
    pub(super) fn new(label: impl Into<String>, value: impl ToString) -> Self {
        Self {
            label: label.into(),
            value: value.to_string(),
        }
    }
}
/// A namespaced compatibility fingerprint, not a broad vendor/chipset label.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HardwareFamily {
    /// Derivation namespace/version.
    pub scheme: String,
    /// Opaque printable fingerprint.
    pub id: String,
}
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
/// A logical, possibly decompressed region.
#[derive(Clone, Debug, Serialize)]
pub struct RegionView {
    /// Provider region identifier.
    pub id: usize,
    /// Display name.
    pub name: String,
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
    /// Firmware components.
    pub components: Vec<ComponentView>,
    /// Expected components absent from this source; never silently synthesized.
    pub missing_components: Vec<String>,
    /// Drive state exists only for live capture.
    pub live: Option<LiveState>,
    #[serde(skip)]
    pub(super) analyses: Vec<super::comparison::FirmwareAnalysis>,
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
    /// Forum-friendly text, with hardware family first.
    pub fn text(&self) -> String {
        let mut out = format!(
            "Hardware family: {}\nSource: {}\nSHA-256: {}\n",
            self.family
                .as_ref()
                .map_or("Unknown".into(), |f| format!("{} ({})", f.id, f.scheme)),
            self.source,
            self.sha256
        );
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
/// Relationship between namespaced family identifiers.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum FamilyRelationship {
    /// Both fingerprints match under one scheme.
    Same,
    /// Both fingerprints are known and differ under one scheme.
    Different,
    /// At least one fingerprint is unavailable.
    Unknown,
    /// The fingerprints use unrelated derivation schemes.
    NotComparable,
}
/// High-level content findings for one logical firmware region.
#[derive(Debug, Serialize)]
pub struct RegionSummary {
    /// Human-readable region name without inferred purpose.
    pub name: String,
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
/// Provider-neutral comparison section.
#[derive(Debug, Serialize)]
pub struct ComparisonSection {
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
    /// Forum-friendly summary, family relationship first.
    pub fn text(&self) -> String {
        let mut out = format!(
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
        );
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
