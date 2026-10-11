//! `info <file>` for a Pioneer firmware bundle, and the offline (dry-run)
//! transfer plan.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::backend::{FileFormat, PlanLine};
use crate::style;

/// Print the Pioneer bundle report for `image`, or `None` when it is not one.
pub(crate) fn describe(image: &[u8]) -> Option<Result<()>> {
    let bundle = super::bundle::Bundle::from_tar_bytes(image).ok()?;
    {
        println!("{}", style::kv("family", "Pioneer"));
        if !bundle.source_name.is_empty() {
            println!(
                "{}",
                style::kv("source", &style::printable(&bundle.source_name))
            );
        }
        if let Some(model) = &bundle.public_model {
            println!("{}", style::kv("listed model", &style::printable(model)));
        }
        if let Some(model) = &bundle.embedded_model {
            println!("{}", style::kv("firmware model", &style::printable(model)));
        }
        if let Some(hardware) = bundle
            .components
            .first()
            .and_then(|c| c.hardware.as_deref())
        {
            println!("{}", style::kv("hardware", &style::printable(hardware)));
        }
        println!(
            "{}",
            style::kv("components", &bundle.components.len().to_string())
        );
        let provenance = super::backup::package_provenance(image);
        println!(
            "{}",
            style::kv(
                "kernel",
                if provenance.kernel_generation_patched {
                    "OEM kernel — generation patched"
                } else if provenance.kernel_oem {
                    "OEM kernel — exact match"
                } else {
                    "Not recognized OEM"
                }
            )
        );
        for component in &bundle.components {
            println!(
                "{}",
                style::kv(
                    "component",
                    &format!(
                        "{:?} {} ({} bytes)",
                        component.role,
                        style::printable(&component.path),
                        component.bytes.len()
                    )
                )
            );
        }
        println!(
            "{}",
            style::kv(
                "flash",
                "live OEM write (gated: --execute --i-understand-risk, backup-first)",
            )
        );
    }
    Some(Ok(()))
}

/// The Pioneer dry-run plan, built from the file alone (no device I/O). The
/// live write is planned and run by the flash facet's execute stages.
pub fn plan_offline(
    image: &[u8],
    format: &FileFormat,
    model: &str,
    verbose: bool,
) -> Result<Vec<PlanLine>> {
    if !super::DESCRIPTOR.owns(format) {
        bail!("Pioneer planning requires an envelope or Pioneer bundle");
    }
    let (kernel, normal) = super::classify_flash_input(image)?;
    let normal = normal.as_deref().context("Normal component missing")?;
    let transcript = match kernel.as_deref() {
        Some(kernel) => super::offline_pair_data_out(kernel, normal)?,
        None => super::generic_normal_transcript(normal)?,
    };
    let mut lines = vec![
        PlanLine::Header("== Pioneer offline transfer plan ==".into()),
        PlanLine::Field("stated model", style::ident_or_unknown(model).into()),
        PlanLine::Field("SHA-256", format!("{:x}", Sha256::digest(image))),
        PlanLine::Text(format!(
            "Validated envelope integrity and transfer framing; {} data-out commands.",
            transcript.len()
        )),
        PlanLine::Text("Live execution reads the receiver descriptor and control word; offline control bytes are illustrative only.".into()),
        PlanLine::Text("Installed-family compatibility is checked against the live backup.".into()),
    ];
    if verbose {
        for step in &transcript {
            lines.push(PlanLine::Text(format!(
                "  {:?} {:02X?} {} B",
                step.stage,
                step.cdb,
                step.data.len()
            )));
        }
    }
    lines.push(PlanLine::Text("DRY RUN: no device I/O or writes.".into()));
    Ok(lines)
}
