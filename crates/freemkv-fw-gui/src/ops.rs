//! Background authoring operations with structured results and automatic diagnostics.
use anyhow::{bail, Result};
use freemkv_flash::localization::message;
use freemkv_flash::output::field;
use freemkv_fw::{
    api,
    boot::{BootFeature, BootSettings},
    diagnostics,
};
use std::path::PathBuf;

pub enum Job {
    Verify(PathBuf),
    Create {
        input: PathBuf,
        output: PathBuf,
        defaults: BootSettings,
    },
    Sign {
        input: PathBuf,
        output: PathBuf,
    },
    Probe(String),
}

pub fn execute(job: &Job) -> Result<()> {
    let operation = match job {
        Job::Verify(_) => "verify",
        Job::Create { .. } => "create",
        Job::Sign { .. } => "sign",
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
                    bail!("Firmware integrity verification failed; see region results.");
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
                        bail!("{reason}");
                    }
                }
                let verification = api::verify(&report.image, None)?;
                if !verification.ok {
                    bail!("Generated firmware failed integrity verification");
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
                diagnostics::record(defaults.report_json(&support, &report.to_json()));
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
            Job::Sign { input, output } => {
                let artifact = freemkv_fw::artifact::Artifact::parse(diagnostics::read(input)?)?;
                let image = artifact.image();
                let outcome = api::sign(image, None)?;
                field("Integrity scheme", outcome.scheme);
                field("Re-signed regions", outcome.changes.len().to_string());
                diagnostics::write(output, &artifact.output(outcome.image.clone())?)?;
                field("Saved firmware", output.display().to_string());
                field("Verification", "Signed image self-verifies");
            }
            Job::Probe(device) => {
                let outcome = api::probe_device(device)?;
                field("Drive", device);
                field(
                    "freemkv firmware",
                    if outcome.detected {
                        message("modify.detected", &[("version", outcome.detail)])
                    } else {
                        "modify.not_detected".into()
                    },
                );
            }
        }
        Ok(())
    })
}
