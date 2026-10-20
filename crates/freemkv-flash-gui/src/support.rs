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
const EVENT_BYTES: usize = 8 * 1024 * 1024;
const SCAN_BYTES: usize = 32 * 1024 * 1024;
const EVENT_LINE: usize = 64 * 1024;

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
    #[cfg(test)]
    pub fn bundle(&self, scope: Scope) -> Result<PathBuf> {
        self.bundle_with_control(scope, None)
    }

    fn bundle_with_control(&self, scope: Scope, control: Option<&Submission>) -> Result<PathBuf> {
        let check = || control.map_or(Ok(()), Submission::check);
        check()?;
        let mut events = Vec::new();
        let mut event_bytes = 0usize;
        for event in &self.unsaved {
            retain_event(event.clone(), &mut events, &mut event_bytes)?;
        }
        let mut scanned = 0usize;
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
            check()?;
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "events.jsonl" || (name.starts_with("events-") && name.ends_with(".jsonl")) {
                let mut reader = BufReader::new(File::open(&path)?);
                loop {
                    check()?;
                    let mut line = Vec::new();
                    let count = Read::by_ref(&mut reader)
                        .take((EVENT_LINE + 1) as u64)
                        .read_until(b'\n', &mut line)?;
                    if count == 0 {
                        break;
                    }
                    anyhow::ensure!(count <= EVENT_LINE, "A saved history event exceeds 64 KiB; archive the affected history file and retry.");
                    scanned += count;
                    anyhow::ensure!(scanned <= SCAN_BYTES, "Saved event history exceeds the 32 MiB scan limit; archive old history and retry.");
                    let Ok(event) = serde_json::from_slice::<Value>(&line) else {
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
                    retain_event(event, &mut events, &mut event_bytes)?;
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
        let mut copied = 0u64;
        for log in logs {
            check()?;
            let name = log
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("diagnostic.log");
            match File::open(&log) {
                Ok(source) => {
                    zip.start_file(format!("logs/{name}"), opts)?;
                    let mut source = source.take(BUNDLE_LIMIT + 1 - copied);
                    let mut buffer = [0u8; 32 * 1024];
                    loop {
                        check()?;
                        let n = source.read(&mut buffer)?;
                        if n == 0 {
                            break;
                        }
                        copied += n as u64;
                        anyhow::ensure!(
                            copied <= BUNDLE_LIMIT,
                            "The selected logs grew beyond 50 MiB while creating the report."
                        );
                        zip.write_all(&buffer[..n])?;
                    }
                    included.push(name.to_owned());
                }
                Err(_) => missing.push(name.to_owned()),
            }
        }
        zip.start_file("events.jsonl", opts)?;
        for event in events {
            check()?;
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

fn retain_event(event: Value, events: &mut Vec<Value>, bytes: &mut usize) -> Result<()> {
    let size = serde_json::to_vec(&event)?.len() + 1;
    anyhow::ensure!(size <= EVENT_LINE, "A report history event exceeds 64 KiB.");
    *bytes += size;
    anyhow::ensure!(
        *bytes <= EVENT_BYTES,
        "Selected event history exceeds 8 MiB. Choose this session or archive old history."
    );
    events.push(event);
    Ok(())
}

mod submission;
pub use submission::{submit, Submission};

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

#[cfg(test)]
mod budget_tests {
    use super::*;
    fn journal() -> (Journal, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("freemkv-history-budget-{}", random_id().unwrap()));
        (Journal::open_at(dir.clone()).unwrap(), dir)
    }
    #[test]
    fn oversized_history_line_is_refused_before_unbounded_allocation() {
        let (journal, dir) = journal();
        fs::write(dir.join("events-huge.jsonl"), vec![b'x'; EVENT_LINE + 1]).unwrap();
        let error = journal.source().bundle(Scope::AllHistory).unwrap_err();
        assert!(error.to_string().contains("64 KiB"));
        assert!(!dir.join("reports").exists());
        drop(journal);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn selected_events_are_bounded_across_files_and_unsaved_history() {
        let (journal, dir) = journal();
        let mut source = journal.source();
        let event = json!({"session_id":source.session_id,"data":"x".repeat(32 * 1024)});
        source.unsaved = vec![event; EVENT_BYTES / (32 * 1024) + 1];
        let error = source.bundle(Scope::Session).unwrap_err();
        assert!(error.to_string().contains("8 MiB"));
        assert!(!dir.join("reports").exists());
        drop(journal);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn unrelated_history_still_has_a_scan_budget() {
        let (journal, dir) = journal();
        let line = format!(
            "{}\n",
            json!({"session_id":"another-session","data":"x".repeat(32 * 1024)})
        );
        let mut file = File::create(dir.join("events-archive.jsonl")).unwrap();
        for _ in 0..=SCAN_BYTES / line.len() {
            file.write_all(line.as_bytes()).unwrap();
        }
        drop(file);
        let error = journal.source().bundle(Scope::Session).unwrap_err();
        assert!(error.to_string().contains("32 MiB scan limit"));
        drop(journal);
        fs::remove_dir_all(dir).unwrap();
    }
}
