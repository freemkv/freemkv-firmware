//! MediaTek inspect provider. A flat 2 MiB image becomes identity,
//! provenance and image-type facts plus a region map that covers every byte
//! once, each region with its role: the boot page (read-back in a drive read),
//! the integrity table and the code it covers, identity strings, and the
//! per-unit regions the drive writes for itself.
use std::ops::Range;

use anyhow::{Context, Result};
use mediatek_optical::image::{cmac, detect_chip, is_drive_read, is_uhd, ChipInfo};
use mediatek_optical::{layout, oem};
use sha2::{Digest, Sha256};

use super::{Mtk, IMAGE_SIZE};
use crate::backend::{sanitize_ascii, DetailsFacet, InspectFacet, ReadDevice};
use crate::inspection::comparison::{self, FirmwareAnalysis, Representation};
use crate::inspection::*;

/// The one component a MediaTek image holds.
const COMPONENT: &str = "Firmware";

impl InspectFacet for Mtk {
    fn inspect(
        &self,
        source: String,
        bytes: &[u8],
        control: &Control,
    ) -> Option<Result<Inspection>> {
        if super::is_legacy_archive(bytes) {
            return Some(inspect_legacy(source, bytes, control));
        }
        inspect_file(source, bytes, control)
    }

    fn live_state(&self, dev: &mut ReadDevice<'_>) -> LiveState {
        live_state(dev)
    }

    fn raw_capture(&self) -> bool {
        true
    }
}

/// Inspect a MediaTek image, or `None` when `bytes` name no MT19xx chip.
pub(crate) fn inspect_file(
    source: String,
    bytes: &[u8],
    control: &Control,
) -> Option<Result<Inspection>> {
    let chip = detect_chip(bytes).ok()?;
    if bytes.len() != IMAGE_SIZE {
        return Some(Err(anyhow::anyhow!(
            "A MediaTek firmware image is exactly {IMAGE_SIZE} bytes; this file is {} bytes.",
            bytes.len()
        )));
    }
    Some(analyze(source, bytes, &chip, control))
}

/// Inspect a 0.10.x backup archive as the image Flash would write from it
/// (the archived capture, rebuilt), under the archive's own digest.
fn inspect_legacy(source: String, archive: &[u8], control: &Control) -> Result<Inspection> {
    let image = super::backup::backup_image(archive, IMAGE_SIZE)?;
    let mut inspection = inspect_file(source, &image, control)
        .context("the archived firmware names no MediaTek MT19xx chip")??;
    inspection.sha256 = format!("{:x}", Sha256::digest(archive));
    inspection.components[0].fields.insert(
        0,
        Field::new(
            "Container",
            "0.10.x backup archive (image rebuilt as Flash writes it)",
        ),
    );
    Ok(inspection)
}

/// One region before ids are assigned.
struct Span {
    range: Range<usize>,
    name: String,
    key: String,
    role: RegionRole,
    fields: Vec<Field>,
    tables: Vec<TableView>,
}

impl Span {
    fn new(range: Range<usize>, name: impl Into<String>, key: String, role: RegionRole) -> Self {
        Self {
            range,
            name: name.into(),
            key,
            role,
            fields: Vec::new(),
            tables: Vec::new(),
        }
    }
}

/// One integrity-table entry and its check against the image.
struct Entry {
    entry: cmac::CmacEntry,
    /// `None` for an unused entry or a range outside the image.
    matches: Option<bool>,
}

fn entries(image: &[u8]) -> Result<Vec<Entry>> {
    Ok(cmac::parse_table(image)?
        .into_iter()
        .map(|entry| Entry {
            matches: entry
                .is_active()
                .then(|| cmac::compute_stored_digest(image, entry.start, entry.end).ok())
                .flatten()
                .map(|digest| digest == entry.stored),
            entry,
        })
        .collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn capitalized(name: &str) -> String {
    let mut chars = name.chars();
    chars.next().map_or_else(String::new, |c| {
        c.to_uppercase().chain(chars).collect::<String>()
    })
}

fn analyze(source: String, image: &[u8], chip: &ChipInfo, control: &Control) -> Result<Inspection> {
    control.check()?;
    let drive_read = is_drive_read(image);
    let catalog = super::oem::catalog();
    let key = oem::content_key(image);
    let build = key.as_ref().and_then(|k| catalog.build(k));
    let entries = entries(image)?;
    control.check()?;

    let mut spans = fixed_spans(image, chip, drive_read, build, &entries);
    let mut claimed: Vec<Range<usize>> = spans.iter().map(|s| s.range.clone()).collect();
    claimed.sort_by_key(|r| r.start);
    for e in entries.iter().filter(|e| e.matches.is_some()) {
        let covered = e.entry.start as usize..e.entry.end as usize + 1;
        let pieces = uncovered(covered, &claimed);
        let parts = pieces.len();
        for (n, piece) in pieces.into_iter().enumerate() {
            let name = if parts == 1 {
                format!("Integrity-covered code {}", e.entry.index)
            } else {
                format!("Integrity-covered code {} part {}", e.entry.index, n + 1)
            };
            let mut span = Span::new(
                piece.clone(),
                name,
                format!("covered:{}:{n}", e.entry.index),
                RegionRole::Code,
            );
            span.fields
                .push(Field::new("Integrity entry", e.entry.index));
            span.fields.push(Field::new(
                "Integrity",
                if e.matches == Some(true) {
                    "Verified"
                } else {
                    "Mismatch"
                },
            ));
            spans.push(span);
            claimed.push(piece);
            claimed.sort_by_key(|r| r.start);
        }
    }
    for gap in uncovered(0..IMAGE_SIZE, &claimed) {
        let mut span = Span::new(
            gap.clone(),
            format!("Code outside integrity coverage at {:#08x}", gap.start),
            format!("uncovered:{:#x}", gap.start),
            RegionRole::Code,
        );
        span.fields.push(Field::new(
            "Erased",
            if layout::is_erased(&image[gap]) {
                "Yes"
            } else {
                "No"
            },
        ));
        spans.push(span);
    }
    spans.sort_by_key(|s| s.range.start);

    let mut regions = Vec::with_capacity(spans.len());
    let mut compared = Vec::with_capacity(spans.len());
    for (id, span) in spans.into_iter().enumerate() {
        let bytes = &image[span.range.clone()];
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let mut fields = vec![
            Field::new(
                "Stored range",
                format!(
                    "{:#x}..{:#x} (image offset)",
                    span.range.start, span.range.end
                ),
            ),
            Field::new("Logical bytes", bytes.len()),
            Field::new("SHA-256", &sha256),
        ];
        fields.extend(span.fields);
        compared.push(comparison::Region {
            id,
            name: span.name.clone(),
            role: span.role,
            address: Some(span.range.start as u64),
            metadata: Vec::new(),
            representation: Representation::Decoded,
            pairing_key: span.key,
            sha256,
            tables: Vec::new(),
            references: Vec::new(),
            bytes: bytes.to_vec(),
        });
        regions.push(RegionView {
            id,
            name: span.name,
            role: span.role,
            fields,
            tables: span.tables,
        });
    }

    let active = entries.iter().filter(|e| e.entry.is_active()).count();
    let failed = entries
        .iter()
        .filter(|e| e.entry.is_active() && e.matches != Some(true))
        .count();
    let mut diagnostics = Vec::new();
    if failed != 0 {
        diagnostics.push(format!(
            "{failed} of {active} integrity entries do not match their covered bytes."
        ));
    }
    let fields = vec![
        Field::new(
            "Image type",
            if drive_read {
                "Drive read"
            } else {
                "Stored image"
            },
        ),
        Field::new("Chip", chip.family.label()),
        Field::new("Vendor", sanitize_ascii(&chip.vendor)),
        Field::new("Model", sanitize_ascii(&chip.model)),
        Field::new("Revision", sanitize_ascii(&chip.rev)),
        Field::new("SKU", sanitize_ascii(&chip.vendor_specific)),
        Field::new(
            "Provenance",
            build.map_or("Unknown build (not in the OEM catalog)".into(), |b| {
                format!(
                    "OEM build {} {}",
                    sanitize_ascii(&b.model),
                    sanitize_ascii(&b.revision)
                )
            }),
        ),
        Field::new(
            "Content key",
            key.as_ref().map_or(String::new(), |k| hex(k)),
        ),
        Field::new(
            "Integrity",
            match (active, failed) {
                (0, _) => "No active entries".to_string(),
                (n, 0) => format!("Verified ({n} of {n} entries)"),
                (n, f) => format!("{f} of {n} entries mismatch"),
            },
        ),
        Field::new("UHD", if is_uhd(image) { "Yes" } else { "No" }),
    ];
    let sha256 = format!("{:x}", Sha256::digest(image));
    Ok(Inspection {
        schema: 1,
        application_version: env!("CARGO_PKG_VERSION"),
        source,
        sha256: sha256.clone(),
        // A chip generation is a chipset label, not a compatibility family.
        family: None,
        derives_family: false,
        components: vec![ComponentView {
            name: COMPONENT.into(),
            fields,
            regions,
            diagnostics,
            standing: Vec::new(),
        }],
        missing_components: Vec::new(),
        live: None,
        analyses: vec![FirmwareAnalysis {
            identity: comparison::Identity {
                component: COMPONENT.into(),
                sha256,
                family: None,
                family_scheme: "mtk".into(),
            },
            regions: compared,
            complete: true,
        }],
    })
}

/// The fixed layout regions. Every image has them at the same offsets.
fn fixed_spans(
    image: &[u8],
    chip: &ChipInfo,
    drive_read: bool,
    build: Option<&oem::Build>,
    entries: &[Entry],
) -> Vec<Span> {
    let span = |range: layout::Range, role: RegionRole| {
        Span::new(
            range.start..range.end(),
            capitalized(range.name),
            range.name.to_string(),
            role,
        )
    };
    let mut boot = span(
        layout::BOOT_PAGE,
        if drive_read {
            RegionRole::ReadBack
        } else {
            RegionRole::Code
        },
    );
    boot.fields.push(Field::new(
        "Form",
        if drive_read {
            "Read back (equal to the boot mirror; flash stores a different page)"
        } else if super::oem::catalog().knows_boot_page(&image[..layout::BOOT_PAGE.len]) {
            "Stored (a known OEM boot page)"
        } else {
            "Stored (not a known OEM boot page)"
        },
    ));
    let mut banner = span(layout::BANNER, RegionRole::Identity);
    let text = image[layout::BANNER.start..layout::BANNER.end()]
        .split(|&b| b == 0)
        .next()
        .unwrap_or_default();
    banner.fields.push(Field::new(
        "Banner",
        sanitize_ascii(String::from_utf8_lossy(text).trim()),
    ));
    let mirror = span(layout::BOOT_MIRROR, RegionRole::Code);
    let mut table = span(layout::CMAC_TABLE, RegionRole::Integrity);
    table.fields.push(Field::new(
        "Active entries",
        entries.iter().filter(|e| e.entry.is_active()).count(),
    ));
    table.tables.push(integrity_table(entries));
    let mut descriptor = span(layout::DESCRIPTOR, RegionRole::Identity);
    descriptor.fields.extend([
        Field::new("Vendor", sanitize_ascii(&chip.vendor)),
        Field::new("Model", sanitize_ascii(&chip.model)),
        Field::new("Revision", sanitize_ascii(&chip.rev)),
        Field::new("SKU", sanitize_ascii(&chip.vendor_specific)),
        Field::new(
            "Identity tag",
            chip.identity_tag
                .as_deref()
                .map_or("Not present".into(), sanitize_ascii),
        ),
    ]);
    let mut spans = vec![boot, banner, mirror, table, descriptor];
    for (i, range) in layout::DRIVE_WRITTEN.iter().enumerate() {
        let mut region = span(*range, RegionRole::PerUnit);
        let bytes = &image[range.start..range.end()];
        region.fields.push(Field::new(
            "State",
            if layout::is_erased(bytes) {
                "Erased"
            } else {
                "Written"
            },
        ));
        if let Some(factory) = build.and_then(|b| b.factory.regions().get(i)) {
            let differing = bytes
                .iter()
                .zip(factory.iter())
                .filter(|(a, b)| a != b)
                .count();
            region.fields.push(Field::new(
                "Factory contents",
                if differing == 0 {
                    "Identical".to_string()
                } else {
                    format!("{differing} bytes differ")
                },
            ));
        }
        spans.push(region);
    }
    spans
}

/// The integrity table as records, in table order.
fn integrity_table(entries: &[Entry]) -> TableView {
    TableView {
        format: "AES-CMAC integrity table".into(),
        range: 0..layout::CMAC_TABLE.len,
        records: entries
            .iter()
            .map(|e| {
                let start = e.entry.index * cmac::ENTRY_SIZE;
                let mut fields = vec![Field::new(
                    "Status",
                    if e.entry.is_active() {
                        "Active"
                    } else {
                        "Unused"
                    },
                )];
                if e.entry.is_active() {
                    fields.push(Field::new(
                        "Covers",
                        format!("{:#x}..={:#x}", e.entry.start, e.entry.end),
                    ));
                    fields.push(Field::new("Stored digest", hex(&e.entry.stored)));
                    fields.push(Field::new(
                        "Check",
                        match e.matches {
                            Some(true) => "Match",
                            Some(false) => "Mismatch",
                            None => "Range outside the image",
                        },
                    ));
                }
                RecordView {
                    index: e.entry.index,
                    range: start..start + cmac::ENTRY_SIZE,
                    fields,
                }
            })
            .collect(),
    }
}

/// The parts of `range` no `claimed` range (sorted, disjoint) overlaps.
fn uncovered(range: Range<usize>, claimed: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut at = range.start;
    for c in claimed {
        if c.end <= at || c.start >= range.end {
            continue;
        }
        if c.start > at {
            out.push(at..c.start);
        }
        at = at.max(c.end);
    }
    if at < range.end {
        out.push(at..range.end);
    }
    out
}

/// Read-only drive facts: chipset, the installed firmware's identity and the
/// DVD region state.
pub(crate) fn live_state(dev: &mut ReadDevice<'_>) -> LiveState {
    let mut state = LiveState::now();
    let chip = super::read_chip(dev).map_or("Not reported", |c| c.label());
    state.fields.push(Field::new("Chipset", chip));
    match Mtk.post_flash_identity(dev) {
        Ok(Some(report)) => {
            if let Some(descriptor) = report.descriptor {
                state.fields.push(Field::new(
                    "Installed firmware",
                    sanitize_ascii(&descriptor),
                ));
            }
            state
                .fields
                .push(Field::new("Firmware fingerprint", report.fingerprint));
            state.fields.push(Field::new(
                "Catalog match",
                report.matched.map_or("None", |(desc, _)| desc),
            ));
        }
        Ok(None) => {}
        Err(e) => {
            crate::diagnostics::record(format!("Optional firmware identity read failed: {e:#}"));
            state
                .diagnostics
                .push("The installed firmware's identity could not be read.".into());
        }
    }
    state.read_dvd_region(dev);
    state
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;
