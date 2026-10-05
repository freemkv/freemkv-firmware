//! Background authoring operations with structured results and automatic diagnostics.
use anyhow::{bail, Result};
use freemkv_flash::output::field;
use freemkv_fw::{api, diagnostics};
use std::path::PathBuf;

pub enum Job {
    Verify(PathBuf),
    Create { input: PathBuf, output: PathBuf },
    Sign { input: PathBuf, output: PathBuf },
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
                let image = diagnostics::read(input)?;
                let outcome = api::verify(&image, None)?;
                field("Firmware image", input.display().to_string());
                field("Integrity scheme", outcome.scheme);
                for verdict in &outcome.verdicts {
                    field(
                        format!("Region {}", verdict.index),
                        format!(
                            "0x{:x}–0x{:x}: {}",
                            verdict.start,
                            verdict.end,
                            if verdict.ok { "Match" } else { "Mismatch" }
                        ),
                    );
                }
                if !outcome.ok {
                    bail!("Firmware integrity verification failed; see region results.");
                }
                field(
                    "Verification",
                    format!("{} regions verified", outcome.verdicts.len()),
                );
            }
            Job::Create { input, output } => {
                let image = diagnostics::read(input)?;
                let outcome = api::create(&image)?;
                field("Engine", outcome.engine);
                if let Some(chip) = &outcome.chip {
                    field(
                        "Firmware identity",
                        format!("{} {} · {}", chip.vendor, chip.model, chip.rev),
                    );
                }
                field(
                    "Verification",
                    format!("{} regions verified", outcome.verdicts.len()),
                );
                diagnostics::write(output, outcome.image())?;
                field("Saved firmware", output.display().to_string());
                field("Image size", format!("{} bytes", outcome.image().len()));
            }
            Job::Sign { input, output } => {
                let image = diagnostics::read(input)?;
                let outcome = api::sign(&image, None)?;
                field("Integrity scheme", outcome.scheme);
                field("Re-signed regions", outcome.changes.len().to_string());
                diagnostics::write(output, &outcome.image)?;
                field("Saved firmware", output.display().to_string());
                field("Verification", "Signed image self-verifies");
            }
            Job::Probe(device) => {
                let outcome = api::probe_device(device)?;
                field("Drive", device);
                field("freemkv firmware", outcome.detail);
            }
        }
        Ok(())
    })
}
