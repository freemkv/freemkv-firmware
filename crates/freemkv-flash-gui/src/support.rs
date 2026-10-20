//! Persistent application events and portable diagnostic bundles.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use zip::write::SimpleFileOptions;

const JOURNAL_LIMIT: u64 = 8 * 1024 * 1024;
const BUNDLE_LIMIT: u64 = 50 * 1024 * 1024;
const MAX_LOGS: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Session,
    AllHistory,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Session => "this session",
            Self::AllHistory => "all saved history",
        }
    }
}

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn random_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn private_file(path: &Path, append: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

pub struct Journal {
    dir: PathBuf,
    file: Option<File>,
    unsaved: Vec<Value>,
    session_id: String,
}

impl Journal {
    pub fn open() -> Result<Self> {
        Self::open_at(freemkv_flash::diagnostics::log_directory())
    }

    fn open_at(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        let path = dir.join("events.jsonl");
        let session_id = random_id()?;
        if fs::metadata(&path).is_ok_and(|m| m.len() >= JOURNAL_LIMIT) {
            fs::rename(
                &path,
                dir.join(format!("events-{}-{session_id}.jsonl", stamp())),
            )?;
        }
        let file = private_file(&path, true)?;
        let mut journal = Self {
            dir,
            file: Some(file),
            unsaved: Vec::new(),
            session_id,
        };
        journal.record(
            "app_opened",
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH
            }),
        )?;
        Ok(journal)
    }

    /// Keep this session reportable even when the events file cannot be opened.
    pub fn memory() -> Self {
        Self::memory_at(freemkv_flash::diagnostics::log_directory())
    }

    pub(crate) fn memory_at(dir: PathBuf) -> Self {
        let mut journal = Self {
            dir,
            file: None,
            unsaved: Vec::new(),
            session_id: freemkv_flash::diagnostics::new_operation_id(),
        };
        let _ = journal.record(
            "app_opened",
            json!({
                "version": env!("CARGO_PKG_VERSION"), "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH, "history_persistence": "unavailable",
            }),
        );
        journal
    }

    pub fn record(&mut self, kind: &str, data: Value) -> Result<()> {
        let line = json!({
            "schema": 1,
            "ts_ms": stamp(),
            "session_id": self.session_id,
            "event": kind,
            "data": data,
        });
        let result = (|| -> Result<()> {
            let file = self
                .file
                .as_mut()
                .context("Session history is available only in memory")?;
            let mut encoded = serde_json::to_vec(&line)?;
            encoded.push(b'\n');
            file.write_all(&encoded)?;
            file.flush()?;
            Ok(())
        })();
        if result.is_err() {
            self.file = None;
            if self.unsaved.len() >= 10_000 {
                self.unsaved.remove(0);
            }
            self.unsaved.push(line);
        }
        result
    }

    pub fn source(&self) -> BundleSource {
        BundleSource {
            dir: self.dir.clone(),
            session_id: self.session_id.clone(),
            unsaved: self.unsaved.clone(),
        }
    }
}

#[derive(Clone)]
pub struct BundleSource {
    dir: PathBuf,
    session_id: String,
    unsaved: Vec<Value>,
}

impl BundleSource {
    pub fn bundle(&self, scope: Scope) -> Result<PathBuf> {
        let mut events = self.unsaved.clone();
        let mut logs = Vec::<PathBuf>::new();
        for event in &events {
            if let Some(log) = event["data"]["log_file"].as_str() {
                let path = PathBuf::from(log);
                if valid_linked_log(&path, &self.dir) && !logs.contains(&path) {
                    logs.push(path);
                }
            }
        }
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => Some(entries),
            Err(_) if !self.unsaved.is_empty() => None,
            Err(error) => return Err(error.into()),
        };
        for entry in entries.into_iter().flatten() {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "events.jsonl" || (name.starts_with("events-") && name.ends_with(".jsonl")) {
                for line in BufReader::new(File::open(&path)?).lines() {
                    let line = line?;
                    let Ok(event) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if scope == Scope::Session
                        && event["session_id"].as_str() != Some(self.session_id.as_str())
                    {
                        continue;
                    }
                    if let Some(log) = event["data"]["log_file"].as_str() {
                        let path = PathBuf::from(log);
                        if valid_linked_log(&path, &self.dir) && !logs.contains(&path) {
                            logs.push(path);
                        }
                    }
                    events.push(event);
                }
            } else if scope == Scope::AllHistory
                && valid_log(&path, &self.dir)
                && !logs.contains(&path)
            {
                logs.push(path);
            }
        }
        events.sort_by_key(|e| e["ts_ms"].as_u64().unwrap_or(0));
        logs.sort();
        if logs.len() > MAX_LOGS {
            bail!("There are more than {MAX_LOGS} logs. Choose this session or remove old logs.");
        }
        let size = logs
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum::<u64>();
        if size > BUNDLE_LIMIT {
            bail!("The selected logs exceed 50 MiB. Choose this session or remove old logs.");
        }
        let mut reports = self.dir.join("reports");
        if fs::create_dir_all(&reports).is_err() {
            reports = std::env::temp_dir().join("freemkv-reports");
            fs::create_dir_all(&reports)?;
        }
        let name = format!("freemkv-report-{}-{}.zip", stamp(), self.session_id);
        let path = reports.join(name);
        let file = private_file(&path, false)?;
        let mut zip = zip::ZipWriter::new(file);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let mut included = Vec::new();
        let mut missing = Vec::new();
        for log in logs {
            let name = log
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("diagnostic.log");
            match File::open(&log) {
                Ok(mut source) => {
                    zip.start_file(format!("logs/{name}"), opts)?;
                    io::copy(&mut source, &mut zip)?;
                    included.push(name.to_owned());
                }
                Err(_) => missing.push(name.to_owned()),
            }
        }
        zip.start_file("events.jsonl", opts)?;
        for event in events {
            serde_json::to_writer(&mut zip, &event)?;
            zip.write_all(b"\n")?;
        }
        zip.start_file("manifest.json", opts)?;
        serde_json::to_writer_pretty(
            &mut zip,
            &json!({
                "schema": 1,
                "application": "freemkv-flash",
                "version": env!("CARGO_PKG_VERSION"),
                "created_at_ms": stamp(),
                "scope": scope.label(),
                "session_id": self.session_id,
                "logs": included,
                "missing_logs": missing,
            }),
        )?;
        zip.finish().context("Could not finish report ZIP")?;
        Ok(path)
    }
}

/// Browser approval chooses the scope; the native app keeps the ZIP and uploads it.
pub fn submit(source: BundleSource, mut progress: impl FnMut(String)) -> Result<String> {
    let base = if cfg!(debug_assertions) {
        std::env::var("FREEMKV_REPORT_API")
            .unwrap_or_else(|_| "https://freemkv.org/api/flash-reports".into())
    } else {
        "https://freemkv.org/api/flash-reports".into()
    };
    progress("Opening report approval in your browser…".into());
    let request: Value = ureq::post(&format!("{base}/requests"))
        .send_json(json!({"application":"freemkv-flash","version":env!("CARGO_PKG_VERSION")}))
        .context("Could not start a report request")?
        .body_mut()
        .read_json()?;
    let id = request["id"]
        .as_str()
        .context("Missing report request ID")?;
    let poll_token = request["poll_token"]
        .as_str()
        .context("Missing polling token")?;
    let approval_url = request["approval_url"]
        .as_str()
        .context("Missing approval URL")?;
    webbrowser::open(approval_url).context("Could not open report approval")?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let approved = (0..300)
        .find_map(|_| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let response = agent
                .get(&format!("{base}/requests/{id}/poll"))
                .header("Authorization", &format!("Bearer {poll_token}"))
                .call();
            match response {
                Ok(mut reply) if reply.status() == 200 => {
                    Some(reply.body_mut().read_json::<Value>().map_err(Into::into))
                }
                Ok(_) => None,
                Err(error) => Some(Err(anyhow::anyhow!("Report approval failed: {error}"))),
            }
        })
        .context("Report approval timed out")??;
    let scope = match approved["scope"].as_str() {
        Some("all") => Scope::AllHistory,
        Some("session") => Scope::Session,
        _ => bail!("Invalid report scope"),
    };
    let upload_token = approved["upload_token"]
        .as_str()
        .context("Missing upload token")?;
    progress(format!("Creating {} report ZIP…", scope.label()));
    let path = source.bundle(scope)?;
    let mut file = File::open(&path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    if data.len() as u64 > BUNDLE_LIMIT {
        bail!("The report ZIP exceeds 50 MiB. Choose this session or remove old logs.");
    }
    use sha2::Digest;
    let sha = sha2::Sha256::digest(&data);
    let checksum: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    progress("Uploading report…".into());
    let mut receipt = None;
    for attempt in 1..=3 {
        let response = agent
            .put(&format!("{base}/requests/{id}/bundle"))
            .header("Authorization", &format!("Bearer {upload_token}"))
            .header("Content-Type", "application/zip")
            .header("X-Content-SHA256", &checksum)
            .send(data.as_slice());
        match response {
            Ok(mut response) => {
                receipt = Some(response.body_mut().read_json::<Value>()?);
                break;
            }
            Err(ureq::Error::StatusCode(503)) if attempt < 3 => {
                progress("Report saved; retrying notification…".into());
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            Err(error) => {
                return Err(error).context("Could not submit report; the ZIP remains on disk")
            }
        }
    }
    let receipt = receipt.context("Could not confirm report receipt; the ZIP remains on disk")?;
    let report_id = receipt["report_id"]
        .as_str()
        .context("Missing report receipt")?;
    Ok(format!(
        "Report {report_id} received. Local copy: {}",
        path.display()
    ))
}

fn valid_linked_log(path: &Path, dir: &Path) -> bool {
    valid_log(path, dir) || valid_log(path, &std::env::temp_dir().join("freemkv-logs"))
}

fn valid_log(path: &Path, dir: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
        && path.parent().and_then(|parent| parent.canonicalize().ok()) == dir.canonicalize().ok()
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("freemkv-flash-") && n.ends_with(".log"))
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.record("app_closed", json!({}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_persists_opened_and_closed_events_as_jsonl() {
        let dir = std::env::temp_dir().join(format!("freemkv-support-{}", random_id().unwrap()));
        let mut journal = Journal::open_at(dir.clone()).unwrap();
        let session_id = journal.session_id.clone();
        journal
            .record("flash_failed", json!({"reason": "test"}))
            .unwrap();
        drop(journal);
        let events: Vec<Value> = fs::read_to_string(dir.join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["event"], "app_opened");
        assert_eq!(events[1]["event"], "flash_failed");
        assert_eq!(events[2]["event"], "app_closed");
        assert!(events.iter().all(|event| event["session_id"] == session_id));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bundles_link_only_the_selected_session() {
        let dir = std::env::temp_dir().join(format!("freemkv-support-{}", random_id().unwrap()));
        fs::create_dir_all(&dir).unwrap();
        let old = dir.join("freemkv-flash-old.log");
        fs::write(&old, "old operation").unwrap();
        let mut first = Journal::open_at(dir.clone()).unwrap();
        first
            .record("diagnostic", json!({"log_file": old}))
            .unwrap();
        drop(first);
        let current = dir.join("freemkv-flash-current.log");
        fs::write(&current, "current operation").unwrap();
        let mut second = Journal::open_at(dir.clone()).unwrap();
        second
            .record("diagnostic", json!({"log_file": current}))
            .unwrap();
        let path = second.source().bundle(Scope::Session).unwrap();
        let mut zip = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        assert!(zip.by_name("logs/freemkv-flash-current.log").is_ok());
        assert!(zip.by_name("logs/freemkv-flash-old.log").is_err());
        drop(zip);
        let path = second.source().bundle(Scope::AllHistory).unwrap();
        let mut zip = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        assert!(zip.by_name("logs/freemkv-flash-old.log").is_ok());
        drop(zip);
        drop(second);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn journal_write_failure_keeps_events_and_existing_logs_reportable() {
        let dir = std::env::temp_dir().join(format!("freemkv-support-{}", random_id().unwrap()));
        let mut journal = Journal::open_at(dir.clone()).unwrap();
        let log = dir.join("freemkv-flash-existing.log");
        fs::write(&log, "operation_id=failed-journal-operation").unwrap();
        journal.file = Some(File::open(dir.join("events.jsonl")).unwrap());
        assert!(journal
            .record(
                "diagnostic",
                json!({
                    "log_file": log, "operation_id": "failed-journal-operation"
                })
            )
            .is_err());
        let path = journal.source().bundle(Scope::Session).unwrap();
        let mut zip = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        assert!(zip.by_name("logs/freemkv-flash-existing.log").is_ok());
        let mut events = String::new();
        zip.by_name("events.jsonl")
            .unwrap()
            .read_to_string(&mut events)
            .unwrap();
        assert!(events.contains("failed-journal-operation"));
        drop(zip);
        drop(journal);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bundle_refuses_a_symlink_to_a_log_outside_the_log_directory() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("freemkv-support-{}", random_id().unwrap()));
        fs::create_dir_all(&dir).unwrap();
        let outside = dir.with_extension("private.log");
        fs::write(&outside, "private data").unwrap();
        let linked = dir.join("freemkv-flash-linked.log");
        symlink(&outside, &linked).unwrap();
        let mut journal = Journal::open_at(dir.clone()).unwrap();
        journal
            .record("diagnostic", json!({"log_file": linked}))
            .unwrap();
        let path = journal.source().bundle(Scope::Session).unwrap();
        let mut zip = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        assert!(zip.by_name("logs/freemkv-flash-linked.log").is_err());
        drop(zip);
        drop(journal);
        fs::remove_dir_all(dir).unwrap();
        fs::remove_file(outside).unwrap();
    }
}
