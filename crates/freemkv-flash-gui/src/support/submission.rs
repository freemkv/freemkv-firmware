//! Bounded report approval and upload; tests use a local server and no browser.

use super::{BundleSource, Scope, BUNDLE_LIMIT};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Submission {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    request_limit: Duration,
    interval: Duration,
    approval_limit: Duration,
}

impl Submission {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(15 * 60),
            request_limit: Duration::from_secs(30),
            interval: Duration::from_secs(2),
            approval_limit: Duration::from_secs(10 * 60),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.cancelled() {
            bail!("Report submission cancelled");
        }
        if Instant::now() >= self.deadline {
            bail!("Report submission timed out");
        }
        Ok(())
    }
    fn timeout(&self) -> Result<Duration> {
        self.check()?;
        Ok(self
            .request_limit
            .min(self.deadline.saturating_duration_since(Instant::now())))
    }
    fn pause(&self) -> Result<()> {
        let until = Instant::now() + self.interval;
        while Instant::now() < until {
            self.check()?;
            std::thread::sleep(
                Duration::from_millis(50).min(until.saturating_duration_since(Instant::now())),
            );
        }
        self.check()
    }
}

/// Browser approval chooses scope; cancellation is checked between bounded requests.
pub fn submit(
    source: BundleSource,
    control: Submission,
    progress: impl FnMut(String),
) -> Result<String> {
    let base = if cfg!(debug_assertions) {
        std::env::var("FREEMKV_REPORT_API")
            .unwrap_or_else(|_| "https://freemkv.org/api/flash-reports".into())
    } else {
        "https://freemkv.org/api/flash-reports".into()
    };
    submit_at(
        source,
        &control,
        &base,
        |url| webbrowser::open(url).map_err(Into::into),
        progress,
    )
}

fn submit_at(
    source: BundleSource,
    control: &Submission,
    base: &str,
    open: impl FnOnce(&str) -> Result<()>,
    mut progress: impl FnMut(String),
) -> Result<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(control.timeout()?))
        .build()
        .into();
    progress("report.opening".into());
    let request: Value = agent
        .post(&format!("{base}/requests"))
        .config()
        .timeout_global(Some(control.timeout()?))
        .build()
        .send_json(json!({"application":"freemkv-flash","version":env!("CARGO_PKG_VERSION")}))
        .context("Could not start a report request")?
        .body_mut()
        .read_json()?;
    control.check()?;
    let id = request["id"]
        .as_str()
        .context("Missing report request ID")?;
    let poll_token = request["poll_token"]
        .as_str()
        .context("Missing polling token")?;
    open(
        request["approval_url"]
            .as_str()
            .context("Missing approval URL")?,
    )
    .context("Could not open report approval")?;
    let approval_deadline = (Instant::now() + control.approval_limit).min(control.deadline);
    let approved = loop {
        control.pause()?;
        if Instant::now() >= approval_deadline {
            bail!("Report approval timed out");
        }
        let mut reply = agent
            .get(&format!("{base}/requests/{id}/poll"))
            .header("Authorization", &format!("Bearer {poll_token}"))
            .config()
            .timeout_global(Some(
                control
                    .timeout()?
                    .min(approval_deadline.saturating_duration_since(Instant::now())),
            ))
            .build()
            .call()
            .context("Report approval failed")?;
        control.check()?;
        match reply.status().as_u16() {
            200 => break reply.body_mut().read_json::<Value>()?,
            202 => {}
            status => bail!("Unexpected report approval status: {status}"),
        }
    };
    let scope = match approved["scope"].as_str() {
        Some("all") => Scope::AllHistory,
        Some("session") => Scope::Session,
        _ => bail!("Invalid report scope"),
    };
    let upload_token = approved["upload_token"]
        .as_str()
        .context("Missing upload token")?;
    control.check()?;
    progress(format!("Creating {} report ZIP…", scope.label()));
    let path = source.bundle_with_control(scope, Some(control))?;
    control.check()?;
    let data = std::fs::read(&path)?;
    if data.len() as u64 > BUNDLE_LIMIT {
        bail!("The report ZIP exceeds 50 MiB. Choose this session or remove old logs.");
    }
    use sha2::Digest;
    let checksum: String = sha2::Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    progress("report.uploading".into());
    for attempt in 1..=3 {
        let response = agent
            .put(&format!("{base}/requests/{id}/bundle"))
            .header("Authorization", &format!("Bearer {upload_token}"))
            .header("Content-Type", "application/zip")
            .header("X-Content-SHA256", &checksum)
            .config()
            .timeout_global(Some(control.timeout()?))
            .build()
            .send(data.as_slice());
        // A received upload receipt wins over a concurrent cancellation: the
        // server has already accepted the report and may have sent its email.
        if response.is_err() {
            control.check()?;
        }
        match response {
            Ok(mut response) => {
                let receipt: Value = response.body_mut().read_json()?;
                let id = receipt["report_id"]
                    .as_str()
                    .context("Missing report receipt")?;
                return Ok(crate::localization::message(
                    "report.received",
                    &[("receipt", id.into()), ("path", path.display().to_string())],
                ));
            }
            Err(ureq::Error::StatusCode(503)) if attempt < 3 => {
                progress("report.retrying".into());
                control.pause()?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Could not submit report; the ZIP remains at {}",
                        path.display()
                    )
                })
            }
        }
    }
    unreachable!("last upload either returns a receipt or an error")
}

#[cfg(test)]
#[path = "submission_tests.rs"]
mod tests;
