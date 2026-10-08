//! Generic summaries and exports of pairwise findings.
use super::*;
use anyhow::Result;
use std::sync::Arc;

pub(super) fn compare(
    left: Arc<Inspection>,
    right: Arc<Inspection>,
    control: &Control,
) -> Result<ComparisonReport> {
    let family = match (&left.family, &right.family) {
        (Some(a), Some(b)) if a.scheme != b.scheme => FamilyRelationship::NotComparable,
        (Some(a), Some(b)) if a == b => FamilyRelationship::Same,
        (Some(_), Some(_)) => FamilyRelationship::Different,
        _ => FamilyRelationship::Unknown,
    };
    let mut sections = Vec::new();
    for name in left
        .components
        .iter()
        .chain(&right.components)
        .map(|c| c.name.as_str())
        .chain(
            left.missing_components
                .iter()
                .chain(&right.missing_components)
                .map(String::as_str),
        )
        .collect::<std::collections::BTreeSet<_>>()
    {
        let a = left.analyses.iter().find(|a| a.identity.component == name);
        let b = right.analyses.iter().find(|a| a.identity.component == name);
        let mut section = ComparisonSection {
            name: name.into(),
            fields: Vec::new(),
            summary: Vec::new(),
            regions: Vec::new(),
            details: Vec::new(),
            relocations: Vec::new(),
        };
        if let (Some(a), Some(b)) = (a, b) {
            let result = a.compare(b, comparison::Options::default(), control)?;
            section.fields.push(Field::new(
                "Decoded content",
                if result.identical_decoded {
                    "Identical"
                } else if !result.complete {
                    "Partially compared"
                } else {
                    "Different"
                },
            ));
            section.fields.push(Field::new("Coverage", result.coverage));
            section
                .fields
                .push(Field::new("Alignment complete", result.complete));
            let identical = result.identical_decoded;
            let complete = result.complete;
            for region in result.regions {
                let name = region
                    .left
                    .and_then(|id| a.regions.iter().find(|r| r.id == id))
                    .map(|r| r.name.clone())
                    .or_else(|| {
                        region
                            .right
                            .and_then(|id| b.regions.iter().find(|r| r.id == id))
                            .map(|r| r.name.clone())
                    })
                    .unwrap_or_default();
                let descriptor = region
                    .left
                    .and_then(|id| a.regions.iter().find(|r| r.id == id))
                    .or_else(|| {
                        region
                            .right
                            .and_then(|id| b.regions.iter().find(|r| r.id == id))
                    });
                let display_name =
                    descriptor.map_or_else(|| "Unknown region".into(), |r| r.name.clone());
                let accounting = region.accounting();
                section.regions.push(RegionSummary {
                    total_bytes: accounting.total,
                    unresolved_bytes: accounting.unresolved,
                    difference_percent: accounting.difference_percent(),
                    name: display_name,
                    left_changed: region
                        .changes
                        .iter()
                        .filter(|c| {
                            !c.kind.is_excluded() && c.kind != comparison::ChangeKind::Unresolved
                        })
                        .map(|c| c.left.len())
                        .sum(),
                    right_changed: region
                        .changes
                        .iter()
                        .filter(|c| {
                            !c.kind.is_excluded() && c.kind != comparison::ChangeKind::Unresolved
                        })
                        .map(|c| c.right.len())
                        .sum(),
                    unresolved: region
                        .changes
                        .iter()
                        .any(|c| c.kind == comparison::ChangeKind::Unresolved),
                    table_changes: region.tables.iter().map(|t| t.changes.len()).sum(),
                    table_records: region
                        .tables
                        .iter()
                        .map(|t| t.left_records.max(t.right_records))
                        .sum(),
                });
                for table in &region.tables {
                    for record in &table.changes {
                        section.details.push(format!(
                            "Text record {}: {} → {}",
                            record.index,
                            record.left.as_deref().unwrap_or("(absent)"),
                            record.right.as_deref().unwrap_or("(absent)")
                        ));
                    }
                }
                section.details.push(format!(
                    "{name}: {} equal logical bytes; A {} bytes, B {} bytes; {} changed ranges",
                    region.equal_bytes,
                    region.left_size,
                    region.right_size,
                    region
                        .changes
                        .iter()
                        .filter(|c| !c.kind.is_excluded()
                            && c.kind != comparison::ChangeKind::Unresolved)
                        .count()
                ));
                for change in region.changes {
                    let output = if change.kind.is_excluded() {
                        &mut section.relocations
                    } else {
                        &mut section.details
                    };
                    output.push(format!(
                        "  {:?}: A {:#x}..{:#x}; B {:#x}..{:#x} (region-relative)",
                        change.kind,
                        change.left.start,
                        change.left.end,
                        change.right.start,
                        change.right.end
                    ));
                }
            }
            section.summary = summarize(&section.regions, identical, complete);
        } else {
            for (label, source, analysis) in [("A", &left, a), ("B", &right, b)] {
                if analysis.is_none() {
                    section
                        .summary
                        .push(if source.components.iter().any(|c| c.name == name) {
                            format!("Source {label}: this component could not be decoded.")
                        } else {
                            format!("Source {label}: this component is not included.")
                        });
                }
            }
            section
                .summary
                .push("This component was not compared.".into());
        }

        sections.push(section);
    }
    Ok(ComparisonReport {
        schema: 1,
        application_version: env!("CARGO_PKG_VERSION"),
        family,
        left_family: left.family.clone(),
        right_family: right.family.clone(),
        sections,
        left,
        right,
    })
}

pub(super) fn summarize(regions: &[RegionSummary], identical: bool, complete: bool) -> Vec<String> {
    if identical {
        return vec!["0.00% different after alignment. The decoded firmware is identical.".into()];
    }
    let mut out = Vec::new();
    let total: usize = regions.iter().map(|r| r.total_bytes).sum();
    let changed_bytes: usize = regions
        .iter()
        .map(|r| r.left_changed + r.right_changed)
        .sum();
    let unresolved_bytes: usize = regions.iter().map(|r| r.unresolved_bytes).sum();
    if total != 0 {
        out.push(format!(
            "{:.2}% different after alignment.",
            100.0 * changed_bytes as f64 / total as f64
        ));
        if unresolved_bytes != 0 {
            out.push(format!(
                "{:.2}% could not be compared.",
                100.0 * unresolved_bytes as f64 / total as f64
            ));
        }
    }
    if !complete {
        out.push("Comparison is partial; some content could not be fully analyzed.".into());
    }
    let mut changed: Vec<_> = regions
        .iter()
        .filter(|r| r.left_changed != 0 || r.right_changed != 0)
        .collect();
    changed.sort_by_key(|r| std::cmp::Reverse(r.left_changed + r.right_changed));
    if let Some(largest) = changed.first() {
        if changed.len() == 1 {
            out.push(format!(
                "Content changes are confined to {}.",
                largest.name.to_lowercase()
            ));
        } else {
            out.push(format!(
                "{} regions contain content changes; the largest concentration is in {}.",
                changed.len(),
                largest.name.to_lowercase()
            ));
        }
    } else if complete {
        out.push("Only packaging, metadata or verified address relocations differ.".into());
    }
    let unchanged = regions
        .iter()
        .filter(|r| r.left_changed == 0 && r.right_changed == 0 && !r.unresolved)
        .count();
    if unchanged != 0 {
        out.push(format!("{unchanged} of {} regions have no content changes after accounting for metadata and verified address relocations.", regions.len()));
    }
    let records: usize = regions.iter().map(|r| r.table_records).sum();
    let record_changes: usize = regions.iter().map(|r| r.table_changes).sum();
    if records != 0 {
        out.push(if record_changes == 0 {
            format!("All {records} recognized text-table records are unchanged.")
        } else {
            format!("{record_changes} of {records} recognized text-table positions differ. Strategy parameter meanings are not established.")
        });
    }
    out
}
