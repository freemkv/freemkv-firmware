//! Best-effort stable-release check; network failure never blocks diagnostics.
use anyhow::{bail, Context, Result};
use semver::Version;
use serde_json::Value;
use std::time::Duration;

pub fn newer_release() -> Result<Option<String>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(8)))
        .build()
        .into();
    let release: Value = agent
        .get("https://api.github.com/repos/freemkv/freemkv-firmware/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .header(
            "User-Agent",
            concat!("freemkv-firmware/", env!("CARGO_PKG_VERSION")),
        )
        .call()?
        .body_mut()
        .read_json()?;
    compare(&release, env!("CARGO_PKG_VERSION"))
}

fn compare(release: &Value, running: &str) -> Result<Option<String>> {
    if release["draft"].as_bool() != Some(false) || release["prerelease"].as_bool() != Some(false) {
        bail!("not a confirmed stable release");
    }
    let tag = release["tag_name"]
        .as_str()
        .context("missing release tag")?;
    let latest = Version::parse(tag.strip_prefix('v').unwrap_or(tag))?;
    if !latest.pre.is_empty() || !latest.build.is_empty() {
        bail!("not a stable release version");
    }
    let current = Version::parse(running)?;
    Ok((latest > current).then(|| latest.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn only_a_confirmed_newer_stable_release_blocks_reports() {
        let release = |tag| json!({"tag_name":tag,"draft":false,"prerelease":false});
        assert_eq!(
            compare(&release("v0.15.2"), "0.15.1").unwrap(),
            Some("0.15.2".into())
        );
        assert_eq!(compare(&release("v0.15.2"), "0.15.2").unwrap(), None);
        assert_eq!(compare(&release("v0.15.1"), "0.15.2").unwrap(), None);
        assert_eq!(
            compare(&release("v0.16.0"), "0.15.9").unwrap(),
            Some("0.16.0".into())
        );
        for bad in [
            json!({}),
            json!({"tag_name":"v0.15.3","draft":true,"prerelease":false}),
            json!({"tag_name":"v0.15.3","draft":false,"prerelease":true}),
            release("bad"),
            release("v0.15.3-rc1"),
        ] {
            assert!(compare(&bad, "0.15.2").is_err());
        }
    }
}
