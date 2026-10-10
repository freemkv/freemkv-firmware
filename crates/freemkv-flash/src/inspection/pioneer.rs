//! Pioneer adapter. All decoding and content comparison lives in Optical.
use super::*;
use anyhow::{Context, Result};
use pioneer_optical::{
    analysis::{Observer, Options},
    envelope::Envelope,
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

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

pub(super) fn inspect_file(source: String, bytes: &[u8], control: &Control) -> Result<Inspection> {
    if pioneer_optical::envelope::header_info(bytes).is_some() {
        return Err(InspectionError::PackageRequired.into());
    }
    let bundle = match crate::pioneer_bundle::Bundle::from_backup_tar_bytes(bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            // Recognized archive corruption must not become “unsupported.”
            if bytes.get(257..262) == Some(b"ustar") {
                return Err(error.context("Invalid firmware package"));
            }
            let identity = crate::imageid::identify(bytes);
            return Err(if identity.family == crate::imageid::ImageFamily::Unknown {
                InspectionError::UnrecognizedFormat
            } else {
                InspectionError::UnsupportedFormat(identity.family.label().into())
            }
            .into());
        }
    };
    let kernel = bundle
        .components
        .iter()
        .find(|c| c.role == crate::pioneer_bundle::Role::Kernel)
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
        let decoded = if component.role == crate::pioneer_bundle::Role::Kernel {
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
                    name: if component.role == crate::pioneer_bundle::Role::Kernel {
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

pub(super) fn live_state(dev: &mut dyn crate::platform::ScsiDevice) -> LiveState {
    let mut state = LiveState {
        captured_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        fields: Vec::new(),
        diagnostics: Vec::new(),
    };
    match dev.command_in(
        &pioneer_optical::rpc::report_key(),
        pioneer_optical::rpc::RESPONSE_LEN,
    ) {
        Ok(bytes) => match pioneer_optical::rpc::State::parse(&bytes) {
            Some(rpc) => {
                state
                    .fields
                    .push(Field::new("DVD region", dvd_region_label(rpc)));
                state.fields.push(Field::new(
                    "User region changes remaining",
                    rpc.user_changes_remaining,
                ));
                state.fields.push(Field::new(
                    "Vendor region resets remaining",
                    rpc.vendor_resets_remaining,
                ));
                state.fields.push(Field::new("RPC scheme", rpc.scheme));
                state.fields.push(Field::new("RPC type", rpc.type_code));
            }
            None => state
                .diagnostics
                .push("DVD region response was incomplete or malformed.".into()),
        },
        Err(e) => {
            crate::diagnostics::record(format!("Optional DVD RPC read failed: {e:#}"));
            state
                .diagnostics
                .push("DVD region and remaining changes could not be read from this drive.".into());
        }
    }
    state
}

/// The regions the drive's RPC mask permits. The mask, not the type code, is
/// what the drive enforces: 0x00 permits all eight, 0xFF permits none.
pub(crate) fn dvd_region_label(rpc: pioneer_optical::rpc::State) -> String {
    if rpc.prohibited_regions == 0xff {
        return "Not set".into();
    }
    (1..=8)
        .filter(|&r| rpc.allows(r))
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(", ")
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

fn comparison_input(
    analysis: &pioneer_optical::analysis::FirmwareAnalysis<'_>,
) -> comparison::FirmwareAnalysis {
    use comparison::{FirmwareAnalysis, Identity, Reference, Region, Representation, Table};
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
            .all(|d| d.code == "pioneer.analysis.semantic_coverage"),
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
