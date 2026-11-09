//! MediaTek package stage composition for offline compatibility decisions.
use crate::crossflash::{compose_routes, Evaluation, Route, RouteStatus};
use anyhow::Result;

pub(crate) fn evaluate(installed: &[u8], target: &[u8]) -> Result<Evaluation> {
    let installed_package = (installed.get(257..262) == Some(b"ustar"))
        .then(|| super::package::Package::parse(installed))
        .transpose()?;
    let target_package = (target.get(257..262) == Some(b"ustar"))
        .then(|| super::package::Package::parse(target))
        .transpose()?;
    let installed = installed_package
        .as_ref()
        .map_or(installed, |p| p.firmware());
    if let Some(package) = &target_package {
        if let Some(intermediate) = package.intermediate() {
            let first = single_stage(installed, intermediate)?;
            let second = single_stage(intermediate, package.firmware())?;
            let mut reasons: Vec<_> = [first.reason, second.reason]
                .into_iter()
                .flatten()
                .collect();
            reasons.sort();
            reasons.dedup();
            return Ok(Evaluation {
                routes: compose_routes(&first.routes, &second.routes),
                reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
            });
        }
        return single_stage(installed, package.firmware());
    }
    single_stage(installed, target)
}

pub(crate) fn single_stage(installed: &[u8], target: &[u8]) -> Result<Evaluation> {
    super::decide_offline(installed, target)?;
    Ok(Evaluation {
        routes: vec![Route {
            native_supported: true,
            status: RouteStatus::Allowed,
            requirements: Vec::new(),
        }],
        reason: None,
    })
}
