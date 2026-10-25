//! Pioneer's `info` rows: the vendor identity and production details after
//! the interface rows, and Quiet Drive / PureRead after the region rows.

use anyhow::{anyhow, Result};
use pioneer_optical::device::settings::{Capability, Observed, PureReadMode, QuietMode};
use pioneer_optical::production;

use super::Pioneer;
use crate::backend::{DetailsFacet, InfoSoFar, ReadDevice, SettingsFacet};
use crate::output::device_settings::Settings;
use crate::report::{Group, Row, Slot};
use crate::standard::{available, row, with_device};

impl DetailsFacet for Pioneer {
    fn rows(&self, dev: &mut ReadDevice<'_>, read: &InfoSoFar<'_>, slot: Slot) -> Vec<Row> {
        match slot {
            Slot::AfterInterface => identity_rows(dev, read),
            Slot::AfterRegion => read.settings.map(settings_rows).unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

impl SettingsFacet for Pioneer {
    fn read(&self, dev: &mut ReadDevice<'_>) -> Result<Settings> {
        with_device(dev, |d| d.settings()).map_err(|e| anyhow!("{e}"))
    }
}

/// The vendor identity from the standard snapshot, then the production
/// parameters (the one extra read).
fn identity_rows(dev: &mut ReadDevice<'_>, read: &InfoSoFar<'_>) -> Vec<Row> {
    let mut rows = match &read.standard.information.pioneer {
        Ok(id) => vec![
            row("hardware_type", "Hardware type", id.platform()),
            row("kernel_type", "Kernel type", id.kernel_tag()),
            row("firmware_type", "Firmware type", id.normal_tag()),
            row("kernel_version", "Kernel version", id.code()),
        ],
        Err(e) => {
            crate::diagnostics::record(format!("Pioneer identity read failed: {e:#}"));
            vec![row("pioneer_identity", "Pioneer identity", "Unavailable")]
        }
    };
    let mut b = [0; production::PARAMETERS_LEN];
    let made =
        with_device(dev, |d| d.parameters(&mut b).ok()).and_then(|n| production::parse(&b[..n]));
    rows.push(row(
        "product_code",
        "Factory product code",
        &available(made.map(|p| p.product_code)),
    ));
    rows.push(row(
        "manufactured",
        "Factory test date",
        &available(
            made.and_then(|p| p.manufactured)
                .map(|d| format!("{:04}-{:02}-{:02}", d.year, d.month, d.day)),
        ),
    ));
    rows.push(row(
        "product_origin",
        "Product origin",
        &available(read.standard.serial().and_then(production::origin)),
    ));
    rows.into_iter()
        .map(|r| r.in_group(Group::Additional))
        .collect()
}

fn settings_rows(settings: &Result<Settings>) -> Vec<Row> {
    let s = match settings {
        Ok(s) => s,
        Err(e) => {
            crate::diagnostics::record(format!("Pioneer settings read failed: {e:#}"));
            return vec![
                row("quiet_drive", "Quiet Drive", "Unavailable").in_group(Group::Settings),
                row("pure_read", "PureRead", "Unavailable").in_group(Group::Settings),
            ];
        }
    };
    let mut rows = Vec::new();
    let q = s.quiet_drive();
    if matches!(q.current, Observed::Known(_)) && q.current == q.saved {
        let value = format!("{} (active and saved)", observed(q.current, quiet));
        rows.push(row("quiet_drive", "Quiet Drive", &value));
    } else {
        let value = format!("{} (active)", observed(q.current, quiet));
        rows.push(row("quiet_drive", "Quiet Drive", &value));
        rows.push(row(
            "saved_quiet_drive",
            "Saved Quiet Drive",
            &observed(q.saved, quiet),
        ));
    }
    match s.pure_read() {
        Capability::Supported(p) => {
            rows.push(row("pure_read", "PureRead", &observed(p.current, pure)));
            if let Some(version) = p.version {
                rows.push(row(
                    "pure_read_version",
                    "PureRead version",
                    &version.to_string(),
                ));
            }
            if let Capability::Supported(real_time) = p.real_time {
                rows.push(row(
                    "real_time_pure_read",
                    "Real-time PureRead",
                    &observed(real_time, |v| if v { "On" } else { "Off" }),
                ));
            }
        }
        Capability::Unknown => rows.push(row("pure_read", "PureRead", "Not reported")),
        _ => {}
    }
    rows.extend(mode_rows(s));
    rows.into_iter()
        .map(|r| r.in_group(Group::Settings))
        .collect()
}

/// The GUI's list of each setting's codec-defined modes, marking the active and
/// saved ones, as 0.11.x's read-only choice controls showed them. The CLI never
/// listed them, so these rows are GUI-only.
fn mode_rows(s: &Settings) -> Vec<Row> {
    use pioneer_optical::device::settings::{SettingId, Value as Mode};
    let name = |v: Mode| match v {
        Mode::Quiet(q) => quiet(q),
        Mode::PureRead(p) => pure(p),
        Mode::Boolean(true) => "On",
        Mode::Boolean(false) => "Off",
    };
    s.entries()
        .filter(|e| {
            e.control.choices.len() > 1 && !matches!(e.control.choices, [Mode::Boolean(_), ..])
        })
        .map(|e| {
            let (key, label) = match e.id {
                SettingId::QuietDrive => ("quiet_drive_modes", "Quiet Drive modes"),
                SettingId::PureRead => ("pure_read_modes", "PureRead modes"),
                SettingId::RealTimePureRead => {
                    ("real_time_pure_read_modes", "Real-time PureRead modes")
                }
            };
            let modes: Vec<String> = e
                .control
                .choices
                .iter()
                .map(|&v| {
                    let mut marks = Vec::new();
                    if e.current == Observed::Known(v) {
                        marks.push("active");
                    }
                    if e.saved == Observed::Known(v) {
                        marks.push("saved");
                    }
                    match marks.is_empty() {
                        true => name(v).to_string(),
                        false => format!("{} ({})", name(v), marks.join(", ")),
                    }
                })
                .collect();
            Row::gui(key, label, crate::report::Value::text(&modes.join(" · ")))
        })
        .collect()
}

fn observed<V>(value: Observed<V>, label: impl FnOnce(V) -> &'static str) -> String {
    match value {
        Observed::Known(v) => label(v).into(),
        Observed::Unknown(v) => format!("Unknown (0x{v:02X})"),
        Observed::NotReported => "Not reported".into(),
    }
}

fn quiet(mode: QuietMode) -> &'static str {
    match mode {
        QuietMode::Standard => "Standard",
        QuietMode::Performance => "Performance",
        QuietMode::Quiet => "Quiet",
        QuietMode::PersistentQuiet => "Persistent quiet",
    }
}

fn pure(mode: PureReadMode) -> &'static str {
    match mode {
        PureReadMode::Standard => "Standard",
        PureReadMode::Master => "Master",
        PureReadMode::Perfect => "Perfect",
    }
}

#[cfg(test)]
#[path = "details_tests.rs"]
mod tests;
