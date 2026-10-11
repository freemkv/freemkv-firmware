//! Pioneer adapter. All decoding and content comparison lives in Optical.
use crate::inspection::*;
use anyhow::{Context, Result};
use pioneer_optical::{
    analysis::{Observer, Options},
    envelope::Envelope,
};
use sha2::{Digest, Sha256};

struct Progress<'a> {
    control: &'a Control,
    last: Option<(&'static str, usize)>,
}
impl Observer for Progress<'_> {
    fn proceed(&mut self, stage: &'static str, done: usize, total: usize) -> bool {
        if self
            .last
            .is_none_or(|(s, n)| s != stage || done.saturating_sub(n) >= 65536)
        {
            crate::output::publish(crate::output::Event::Progress {
                label: stage.into(),
                done,
                total,
            });
            self.last = Some((stage, done));
        }
        !self.control.cancelled()
    }
}

/// Inspect a Pioneer package, or `None` when `bytes` are not a Pioneer
/// format at all (the caller reports unrecognized or unsupported files).
pub(crate) fn inspect_file(
    source: String,
    bytes: &[u8],
    control: &Control,
) -> Option<Result<Inspection>> {
    if pioneer_optical::envelope::header_info(bytes).is_some() {
        return Some(Err(InspectionError::PackageRequired.into()));
    }
    let bundle = match crate::backends::pioneer::bundle::Bundle::from_backup_tar_bytes(bytes) {
        Ok(bundle) => bundle,
        // Recognized archive corruption must not become “unsupported.”
        Err(error) if bytes.get(257..262) == Some(b"ustar") => {
            return Some(Err(error.context("Invalid firmware package")));
        }
        Err(_) => return None,
    };
    Some(analyze(source, bytes, bundle, control))
}

fn analyze(
    source: String,
    bytes: &[u8],
    bundle: crate::backends::pioneer::bundle::Bundle,
    control: &Control,
) -> Result<Inspection> {
    let kernel = bundle
        .components
        .iter()
        .find(|c| c.role == crate::backends::pioneer::bundle::Role::Kernel)
        .and_then(|c| Envelope::load(&c.bytes).ok());
    let mut report = Inspection {
        schema: 1,
        application_version: env!("CARGO_PKG_VERSION"),
        source,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        family: None,
        components: Vec::new(),
        missing_components: Vec::new(),
        live: None,
        analyses: Vec::new(),
    };
    for component in &bundle.components {
        control.check()?;
        let decoded = if component.role == crate::backends::pioneer::bundle::Role::Kernel {
            Envelope::load(&component.bytes).context("Kernel could not be decoded")
        } else if let Some(kernel) = &kernel {
            Envelope::load_with_kernel(&component.bytes, kernel)
                .context("Normal could not be decoded with its supplied Kernel")
        } else {
            Envelope::load(&component.bytes)
                .context("Normal could not be decoded; its matching Kernel may be required")
        };
        let envelope = match decoded {
            Ok(envelope) => envelope,
            Err(error) => {
                report.components.push(ComponentView {
                    name: if component.role == crate::backends::pioneer::bundle::Role::Kernel {
                        "Kernel"
                    } else {
                        "Normal"
                    }
                    .into(),
                    fields: vec![
                        Field::new("Status", "Not decoded"),
                        Field::new(
                            "Revision",
                            component.revision.as_deref().unwrap_or("Unknown"),
                        ),
                    ],
                    regions: Vec::new(),
                    diagnostics: vec![format!("{error:#}")],
                    standing: Vec::new(),
                });
                continue;
            }
        };
        let analysis = envelope.analyze(
            Options::default(),
            &mut Progress {
                control,
                last: None,
            },
        )?;
        let id = &analysis.identity;
        if let Some(family) = &id.family {
            report.family = Some(HardwareFamily {
                scheme: id.family_scheme.into(),
                id: family.clone(),
            });
        }
        let mut fields = vec![
            Field::new("Model", &id.model),
            Field::new("Revision", &id.revision),
            Field::new("Hardware", &id.hardware),
            Field::new("Codec", &id.codec),
            Field::new("Decoded bytes", id.size),
            Field::new("Decoded SHA-256", &id.sha256),
            Field::new(
                "UHD",
                match id.uhd {
                    Some(true) => "Yes",
                    Some(false) => "No",
                    None => "Not applicable to this component",
                },
            ),
        ];
        if let Some(header) = envelope.header() {
            fields.push(Field::new("Build date", header.generated_date));
            fields.push(Field::new("Destination", header.destination));
        }
        fields.push(Field::new(
            "Encoding seed",
            id.encoding_seed
                .map_or("Not recoverable / not applicable".into(), |seed| {
                    format!("{seed:#08x}")
                }),
        ));
        fields.push(Field::new(
            "Signature",
            signature_label(envelope.signature_status()),
        ));
        let regions = analysis
            .regions
            .iter()
            .map(|r| RegionView {
                id: r.id,
                name: r.name.clone(),
                role: region_role(r),
                fields: vec![
                    Field::new(
                        "Stored range",
                        format!(
                            "{:#x}..{:#x} (decoded component)",
                            r.stored.start, r.stored.end
                        ),
                    ),
                    Field::new("Logical bytes", r.size),
                    Field::new("SHA-256", &r.sha256),
                ],
                tables: r
                    .tables
                    .iter()
                    .map(|t| TableView {
                        format: t.format.into(),
                        range: t.range.clone(),
                        records: t
                            .records
                            .iter()
                            .map(|record| RecordView {
                                index: record.index,
                                range: record.range.clone(),
                                fields: vec![Field::new("Value", &record.value)],
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect();
        report.components.push(ComponentView {
            name: id.component.clone(),
            fields,
            regions,
            diagnostics: analysis
                .diagnostics
                .iter()
                .map(|d| format!("{} ({})", d.message, d.code))
                .collect(),
            standing: (analysis.diagnostics.iter().enumerate())
                .filter(|(_, d)| d.code == SEMANTIC_COVERAGE)
                .map(|(i, _)| i)
                .collect(),
        });
        report.analyses.push(comparison_input(&analysis));
    }
    report.missing_components = ["Kernel", "Normal"]
        .into_iter()
        .filter(|name| !report.components.iter().any(|c| c.name == *name))
        .map(str::to_owned)
        .collect();
    Ok(report)
}

pub(crate) fn live_state(dev: &mut dyn crate::platform::ScsiDevice) -> LiveState {
    let mut state = LiveState::now();
    state.read_dvd_region(dev);
    state
}

/// Every region of a decoded Pioneer component (its body and expanded
/// streams) is firmware the update package delivers; none is per-unit.
fn region_role(_region: &pioneer_optical::analysis::Region<'_>) -> RegionRole {
    RegionRole::Code
}

fn signature_label(status: pioneer_optical::envelope::SignatureStatus) -> &'static str {
    use pioneer_optical::envelope::{signature::SignatureCheck, SignatureStatus};
    match status {
        SignatureStatus::Absent => "Not present",
        SignatureStatus::Present(SignatureCheck::ValidKeyAndCiphertext) => {
            "Valid (encoding key and firmware)"
        }
        SignatureStatus::Present(SignatureCheck::ValidCiphertextOnly) => "Valid (firmware)",
        SignatureStatus::Present(SignatureCheck::Invalid) => "Invalid",
        SignatureStatus::Present(_) => "Present; verification unavailable",
        _ => "Verification unavailable for this format",
    }
}

/// The analyser's standing note that unrecognized fields stay raw bytes.
const SEMANTIC_COVERAGE: &str = "pioneer.analysis.semantic_coverage";

fn comparison_input(
    analysis: &pioneer_optical::analysis::FirmwareAnalysis<'_>,
) -> crate::inspection::comparison::FirmwareAnalysis {
    use crate::inspection::comparison::{
        FirmwareAnalysis, Identity, Reference, Region, Representation, Table,
    };
    FirmwareAnalysis {
        identity: Identity {
            component: analysis.identity.component.clone(),
            sha256: analysis.identity.sha256.clone(),
            family: analysis.identity.family.clone(),
            family_scheme: analysis.identity.family_scheme.into(),
        },
        complete: analysis
            .diagnostics
            .iter()
            .all(|d| d.code == SEMANTIC_COVERAGE),
        regions: analysis
            .regions
            .iter()
            .map(|r| Region {
                id: r.id,
                name: match r.stream {
                    Some(index) => format!("Expanded section {}", index + 1),
                    None if r.stored.start == 0 => "Main firmware".into(),
                    None => format!("Stored data section {}", r.id + 1),
                },
                address: r.address.map(u64::from),
                role: region_role(r),
                metadata: r.metadata.clone(),
                representation: if r.stream.is_some() {
                    Representation::Expanded
                } else {
                    Representation::Decoded
                },
                pairing_key: r
                    .stream
                    .map_or_else(|| format!("body:{}", r.id), |i| format!("stream:{i}")),
                sha256: r.sha256.clone(),
                references: r
                    .references
                    .iter()
                    .map(|reference| Reference {
                        instruction: reference.instruction.clone(),
                        operand: reference.operand.clone(),
                        target: u64::from(reference.target),
                    })
                    .collect(),
                tables: r
                    .tables
                    .iter()
                    .map(|t| Table {
                        format: t.format.into(),
                        record_width: t.record_width,
                        records: t.records.iter().map(|r| r.value.clone()).collect(),
                    })
                    .collect(),
                bytes: r.bytes().to_vec(),
            })
            .collect(),
    }
}
