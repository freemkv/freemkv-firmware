//! Best-effort check for a newer stable GitHub release.

use std::time::Duration;

const LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/freemkv/freemkv-firmware/releases/latest";
const RELEASE_PAGE: &str = "https://github.com/freemkv/freemkv-firmware/releases/latest";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Return the newer stable release tag, or None when offline, rate-limited, or current.
pub(crate) fn latest_version() -> Option<String> {
    check_latest_at(env!("CARGO_PKG_VERSION"), LATEST_RELEASE_API)
}

fn check_latest_at(current: &str, endpoint: &str) -> Option<String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build();
    let response = agent
        .get(endpoint)
        .header("User-Agent", "freemkv-firmware")
        .call()
        .ok()?;
    let release: serde_json::Value = response.into_body().read_json().ok()?;
    if release["draft"].as_bool().unwrap_or(true)
        || release["prerelease"].as_bool().unwrap_or(true)
    {
        return None;
    }
    let tag = release["tag_name"].as_str()?;
    let latest = semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag)).ok()?;
    let current = semver::Version::parse(current).ok()?;
    (latest > current).then(|| tag.to_owned())
}

pub(crate) fn release_page() -> &'static str {
    RELEASE_PAGE
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn candidate(current: &str, value: serde_json::Value) -> Option<String> {
        if value["draft"].as_bool().unwrap_or(true)
            || value["prerelease"].as_bool().unwrap_or(true)
        {
            return None;
        }
        let tag = value["tag_name"].as_str()?;
        let latest = semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag)).ok()?;
        let current = semver::Version::parse(current).ok()?;
        (latest > current).then(|| tag.to_owned())
    }

    #[test]
    fn only_newer_stable_semver_tags_are_announced() {
        assert_eq!(
            candidate("0.15.1", json!({"tag_name":"v0.15.2","draft":false,"prerelease":false})),
            Some("v0.15.2".into())
        );
        for value in [
            json!({"tag_name":"v0.15.1","draft":false,"prerelease":false}),
            json!({"tag_name":"v0.16.0-rc.1","draft":false,"prerelease":true}),
            json!({"tag_name":"v0.16.0","draft":true,"prerelease":false}),
            json!({"tag_name":"untrusted","draft":false,"prerelease":false}),
            json!({"draft":false,"prerelease":false}),
        ] {
            assert_eq!(candidate("0.15.1", value), None);
        }
    }

    #[test]
    fn release_page_is_the_official_repository_latest_release() {
        assert_eq!(
            release_page(),
            "https://github.com/freemkv/freemkv-firmware/releases/latest"
        );
    }
}
