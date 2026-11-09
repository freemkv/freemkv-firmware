//! Background authoring operations with structured results and automatic diagnostics.
use anyhow::Result;
use freemkv_flash::localization::message;
use freemkv_flash::output::field;
use freemkv_fw::{
    api,
    boot::{BootFeature, BootSettings},
    diagnostics,
};
use std::path::PathBuf;

/// An integrity verdict whose user guidance must not be reduced to an input-file guess.
#[derive(Debug)]
pub enum VerificationFailure {
    /// An existing image failed verification; region verdicts are available.
    ExistingImage,
    /// The newly generated image failed its internal self-check before saving.
    GeneratedImage,
}

impl std::fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExistingImage => {
                f.write_str("Firmware integrity verification failed; see region results.")
            }
            Self::GeneratedImage => f.write_str("Generated firmware failed integrity verification"),
        }
    }
}

impl std::error::Error for VerificationFailure {}

pub enum Job {
    Verify(PathBuf),
    Create {
        input: PathBuf,
        output: PathBuf,
        defaults: BootSettings,
    },
    Probe(String),
}

pub fn execute(job: &Job) -> Result<()> {
    let operation = match job {
        Job::Verify(_) => "verify",
        Job::Create { .. } => "create",
        Job::Probe(_) => "probe",
    };
    diagnostics::run(operation, || {
        match job {
            Job::Verify(input) => {
                let artifact = freemkv_fw::artifact::Artifact::parse(diagnostics::read(input)?)?;
                let image = artifact.image();
                let outcome = api::verify(image, None)?;
                field("Firmware image", input.display().to_string());
                field("Integrity scheme", outcome.scheme);
                for verdict in &outcome.verdicts {
                    field(
                        message("modify.region", &[("index", verdict.index.to_string())]),
                        message(
                            "modify.region_verdict",
                            &[
                                ("start", format!("0x{:x}", verdict.start)),
                                ("end", format!("0x{:x}", verdict.end)),
                                (
                                    "verdict",
                                    if verdict.ok {
                                        "domain.match"
                                    } else {
                                        "domain.mismatch"
                                    }
                                    .into(),
                                ),
                            ],
                        ),
                    );
                }
                if !outcome.ok {
                    return Err(VerificationFailure::ExistingImage.into());
                }
                field(
                    "Verification",
                    message(
                        "modify.regions_verified",
                        &[("count", outcome.verdicts.len().to_string())],
                    ),
                );
            }
            Job::Create {
                input,
                output,
                defaults,
            } => {
                let artifact = freemkv_fw::artifact::Artifact::parse(diagnostics::read(input)?)?;
                let image = artifact.image();
                let (report, support) = api::modify_with_defaults(image, defaults)?;
                if let Some(reason) = report.refusal() {
                    if freemkv_fw::boot::inspect(image)?.is_none() {
                        return Err(anyhow::anyhow!("{reason}")
                            .context(freemkv_flash::user_error::IssueCode::UnsupportedFirmware));
                    }
                }
                let verification = api::verify(&report.image, None)?;
                if !verification.ok {
                    return Err(VerificationFailure::GeneratedImage.into());
                }
                field("Engine", report.engine);
                field(
                    "Firmware identity",
                    format!("{} {} · {}", report.vendor, report.model, report.rev),
                );
                for feature in BootFeature::ALL {
                    field(
                        feature.label(),
                        if support.supports(feature) {
                            defaults.label(feature)
                        } else {
                            "Not supported by this firmware"
                        },
                    );
                }
                diagnostics::record(defaults.report_json(
                    &support,
                    freemkv_fw::qualification::uhd_for_image(&report.image),
                    &report.to_json(),
                ));
                field(
                    "Verification",
                    message(
                        "modify.regions_verified",
                        &[("count", verification.verdicts.len().to_string())],
                    ),
                );
                diagnostics::write(output, &artifact.output(report.image.clone())?)?;
                field("Saved firmware", output.display().to_string());
                field(
                    "Image size",
                    message("unit.bytes", &[("count", report.image.len().to_string())]),
                );
            }
            Job::Probe(device) => {
                let outcome = api::probe_device(device)?;
                field("Drive", device);
                field("freemkv firmware", probe_field(&outcome)?);
            }
        }
        Ok(())
    })
}

fn probe_field(outcome: &api::ProbeOutcome) -> Result<String> {
    Ok(if outcome.detected {
        message("modify.detected", &[("version", detected_version(outcome))])
    } else if outcome.detail.starts_with("NOT DETERMINED") {
        anyhow::bail!("{}", outcome.detail);
    } else {
        "modify.not_detected".into()
    })
}

fn detected_version(outcome: &api::ProbeOutcome) -> String {
    outcome
        .version
        .map_or_else(|| message("ui.unknown", &[]), |v| format!("0x{v:02x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detected_version_is_the_bare_version_not_the_cli_sentence() {
        let outcome = api::ProbeOutcome {
            detected: true,
            detail: "DETECTED (version 0x01)".into(),
            version: Some(1),
        };
        let text = message(
            "modify.detected",
            &[("version", detected_version(&outcome))],
        );
        assert!(text.contains("0x01"), "{text}");
        assert!(!text.contains("DETECTED"), "{text}");
    }

    #[test]
    fn undetermined_probe_is_an_error_not_a_stock_firmware_claim() {
        let outcome = api::ProbeOutcome {
            detected: false,
            detail: "NOT DETERMINED (probe failed: timeout)".into(),
            version: None,
        };
        let err = probe_field(&outcome).unwrap_err().to_string();
        assert!(err.contains("NOT DETERMINED"), "{err}");
        let stock = api::ProbeOutcome {
            detected: false,
            detail: "NOT DETECTED".into(),
            version: None,
        };
        assert_eq!(probe_field(&stock).unwrap(), "modify.not_detected");
    }
}
