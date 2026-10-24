//! Test-only workflow boundary: record real dispatcher arguments before any IO.

use crate::parity_0_11_2_tests::{record, src, Call, Current};
pub use freemkv_flash::workflow::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn recorded<T>() -> anyhow::Result<T> {
    Err(anyhow::anyhow!("workflow call recorded; no IO"))
}

pub fn info(device: Option<&str>) -> anyhow::Result<()> {
    if record(Call::Info {
        device: device.map(str::to_owned),
    }) {
        recorded()
    } else {
        freemkv_flash::workflow::info(device)
    }
}

pub fn check_file(path: &Path) -> anyhow::Result<()> {
    if record(Call::CheckFile(path.into())) {
        recorded()
    } else {
        freemkv_flash::workflow::check_file(path)
    }
}

pub fn backup_with_replace(
    device: Option<&str>,
    out: Option<PathBuf>,
    dump: bool,
    replace: bool,
) -> anyhow::Result<()> {
    if record(Call::Backup {
        device: device.map(str::to_owned),
        out: out.clone().expect("GUI supplies destination"),
        dump,
        replace,
    }) {
        recorded()
    } else {
        freemkv_flash::workflow::backup_with_replace(device, out, dump, replace)
    }
}

pub fn flash(options: FlashOptions, confirm: &mut dyn Confirm) -> anyhow::Result<UpdateOutcome> {
    if record(Call::Flash {
        device: options.device.clone(),
        input: options.input.clone(),
        backup: options.backup.clone(),
        execute: options.execute,
        acknowledged_risk: options.acknowledged_risk,
    }) {
        recorded()
    } else {
        freemkv_flash::workflow::flash(options, confirm)
    }
}

pub fn preview_flash(options: &FlashOptions) -> anyhow::Result<FlashPreview> {
    if record(Call::Preview {
        device: options.device.clone(),
        input: options.input.clone(),
        backup: options.backup.clone(),
        acknowledged_risk: options.acknowledged_risk,
    }) {
        recorded()
    } else {
        freemkv_flash::workflow::preview_flash(options)
    }
}

fn recover_call(options: &RecoveryOptions) -> Call {
    Call::Recover {
        device: options.device.clone(),
        input: options.input.clone(),
        current: match &options.current {
            CurrentFirmware::NotRequired => Current::NotRequired,
            CurrentFirmware::File(path) => Current::File(path.clone()),
            CurrentFirmware::ReadFromDrive => Current::ReadFromDrive,
        },
        execute: options.execute,
        acknowledged_risk: options.acknowledged_risk,
    }
}

pub fn recover(options: RecoveryOptions) -> anyhow::Result<UpdateOutcome> {
    if record(recover_call(&options)) {
        recorded()
    } else {
        freemkv_flash::workflow::recover(options)
    }
}

pub fn prepare_recovery(options: RecoveryOptions) -> anyhow::Result<PreparedRecovery> {
    if record(recover_call(&options)) {
        recorded()
    } else {
        freemkv_flash::workflow::prepare_recovery(options)
    }
}

pub fn inspect(source: &Source, control: &Control) -> anyhow::Result<Arc<Inspection>> {
    if record(Call::Inspect(src(source))) {
        recorded()
    } else {
        freemkv_flash::workflow::inspect(source, control)
    }
}

pub fn compare(a: &Source, b: &Source, control: &Control) -> anyhow::Result<ComparisonReport> {
    if record(Call::Compare(src(a), src(b))) {
        recorded()
    } else {
        freemkv_flash::workflow::compare(a, b, control)
    }
}
