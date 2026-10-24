//! `info <file>` for a Pioneer firmware bundle, and the offline (dry-run)
//! transfer plan.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::backend::{FileFormat, PlanLine};
use crate::style;

/// Conservative origin evidence, never inferred from mathematical signature validity.
pub(crate) fn file_origin(bytes: &[u8]) -> crate::workflow::FileOrigin {
    use super::bundle::Role;
    use crate::workflow::FileOrigin;
    use pioneer_optical::envelope;
    let components = match super::bundle::Bundle::from_backup_tar_bytes(bytes) {
        Ok(bundle) => bundle
            .components
            .into_iter()
            .map(|c| (c.role, c.bytes))
            .collect::<Vec<_>>(),
        Err(_) => {
            let Some(header) = envelope::header_info(bytes) else {
                return FileOrigin::Unknown;
            };
            let role = match header.kind {
                Some(pioneer_optical::ComponentKind::Normal) => Role::Main,
                Some(pioneer_optical::ComponentKind::Kernel) => Role::Kernel,
                _ => return FileOrigin::Unknown,
            };
            vec![(role, bytes.to_vec())]
        }
    };
    let Some((_, normal)) = components.iter().find(|(role, _)| *role == Role::Main) else {
        return FileOrigin::Unknown;
    };
    let signature = normal.get(envelope::builder::NORMAL_SIGNATURE_RANGE);
    if signature.is_some_and(|sig| sig.iter().all(|&b| b == 0)) {
        return FileOrigin::UserBackupLikely;
    }
    let kernel = components
        .iter()
        .find(|(role, _)| *role == Role::Kernel)
        .and_then(|(_, bytes)| envelope::decode_envelope(bytes));
    let Some(kernel) = kernel else {
        return FileOrigin::Unknown;
    };
    let kernel_oem = super::k::recognize(&kernel.image).is_some_and(|m| !m.generation_patched);
    let normal_oem =
        envelope::decode_envelope_with_kernel(normal, &kernel).is_some_and(|decoded| {
            super::n::lookup(&format!("{:x}", Sha256::digest(&decoded.image)))
                .is_some_and(|entry| signature == Some(entry.signature.as_slice()))
        });
    if kernel_oem
        && normal_oem
        && envelope::builder::normal_authentication_valid(normal, &kernel.image)
    {
        FileOrigin::OemLikely
    } else {
        FileOrigin::Unknown
    }
}

/// Print the Pioneer bundle report for `image`, or `None` when it is not one.
pub(crate) fn describe(image: &[u8]) -> Option<Result<()>> {
    let bundle = super::bundle::Bundle::from_backup_tar_bytes(image).ok()?;
    let kernel_only = bundle
        .components
        .iter()
        .all(|component| component.role == super::bundle::Role::Kernel);
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
        if kernel_only {
            println!(
                "{}",
                style::kv("backup", "partial: Kernel only; Normal was not captured")
            );
        }
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
                if kernel_only {
                    "not flashable: Normal component missing"
                } else {
                    "live OEM write (gated: --execute --i-understand-risk, backup-first)"
                },
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
        PlanLine::Text("Package checks passed. Drive compatibility is still pending; it is checked against the pre-flash backup before confirmation or writing.".into()),
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
    lines.push(PlanLine::Text("DRY RUN: no firmware writes or backup capture. Drive discovery may read identity metadata.".into()));
    Ok(lines)
}
