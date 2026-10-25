use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

struct Reply {
    status: u16,
    body: String,
    delay: Duration,
    cancel: Option<Submission>,
}
fn reply(status: u16, body: Value) -> Reply {
    Reply {
        status,
        body: body.to_string(),
        delay: Duration::ZERO,
        cancel: None,
    }
}
fn server(script: Vec<Reply>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    server_with_inspection(script, |_| {})
}

fn server_with_inspection(
    script: Vec<Reply>,
    inspect: impl Fn(&[u8]) + Send + 'static,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for reply in script {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("expected HTTP request: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    return seen;
                }
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                headers.push_str(&line);
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            if headers.starts_with("PUT /requests/test-id/bundle ") {
                inspect(&body);
                use sha2::Digest;
                let expected: String = sha2::Sha256::digest(&body)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert!(headers
                    .to_ascii_lowercase()
                    .contains(&format!("x-content-sha256: {expected}")));
                let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&body)).unwrap();
                assert!(zip.by_name("events.jsonl").is_ok());
                assert!(zip.by_name("manifest.json").is_ok());
            }
            if headers.starts_with("PUT /requests/test-id/description ") {
                seen.push(format!("{headers}{}", String::from_utf8_lossy(&body)));
            } else {
                seen.push(headers);
            }
            if let Some(control) = reply.cancel {
                control.cancel();
            }
            std::thread::sleep(reply.delay);
            let _ = write!(stream, "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.status, reply.body.len(), reply.body);
        }
        seen
    });
    (base, task)
}
fn control() -> Submission {
    Submission {
        interval: Duration::from_millis(1),
        request_limit: Duration::from_secs(2),
        approval_limit: Duration::from_secs(3),
        ..Submission::new()
    }
}
fn source() -> (BundleSource, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "freemkv-http-test-{}",
        crate::support::random_id().unwrap()
    ));
    let journal = crate::support::Journal::open_at(dir.clone()).unwrap();
    (
        journal
            .source()
            .with_description("Synthetic diagnostic context".into()),
        dir,
    )
}
fn created() -> Value {
    json!({"id":"test-id","poll_token":"poll-secret","approval_url":"http://localhost/approve"})
}
fn approved() -> Value {
    json!({"scope":"session","upload_token":"upload-secret"})
}

#[test]
fn approval_pending_then_upload_notification_retry_returns_a_receipt() {
    let (base, server) = server(vec![
        reply(200, created()),
        reply(202, json!({})),
        reply(200, approved()),
        reply(200, json!({"saved":true})),
        reply(503, json!({})),
        reply(200, json!({"report_id":"synthetic-report"})),
    ]);
    let (source, dir) = source();
    let mut opened = false;
    let mut progress = Vec::new();
    let result = submit_at(
        source,
        &control(),
        &base,
        |url| {
            assert_eq!(url, "http://localhost/approve");
            opened = true;
            Ok(())
        },
        |message| progress.push(message),
    )
    .unwrap();
    assert!(opened);
    assert!(
        progress.iter().any(|message| message == "report.preparing"),
        "preparation progress must be localized: {progress:?}"
    );
    assert!(result.contains("synthetic-report"));
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with("POST /requests "));
    assert!(requests[1]
        .to_ascii_lowercase()
        .contains("authorization: bearer poll-secret"));
    assert!(requests[3].starts_with("PUT /requests/test-id/description "));
    assert!(requests[3]
        .to_ascii_lowercase()
        .contains("authorization: bearer upload-secret"));
    assert!(requests[3].contains("Synthetic diagnostic context"));
    assert!(requests[4].starts_with("PUT /requests/test-id/bundle "));
    assert!(requests[4]
        .to_ascii_lowercase()
        .contains("authorization: bearer upload-secret"));
    assert!(requests[4]
        .to_ascii_lowercase()
        .contains("x-content-sha256:"));
    assert_eq!(
        requests[4], requests[5],
        "notification retry preserves the exact request"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn expired_approval_never_uploads() {
    let (base, server) = server(vec![
        reply(200, created()),
        reply(403, json!({"error":"expired"})),
    ]);
    let (source, dir) = source();
    let error = submit_at(source, &control(), &base, |_| Ok(()), |_| {}).unwrap_err();
    assert!(format!("{error:#}").contains("403"));
    assert_eq!(server.join().unwrap().len(), 2);
    assert!(!dir.join("reports").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn receipt_is_not_misreported_as_cancelled_when_upload_was_already_accepted() {
    let control = control();
    let mut received = reply(200, json!({"report_id":"accepted-before-cancel"}));
    received.cancel = Some(control.clone());
    let (base, server) = server(vec![
        reply(200, created()),
        reply(200, approved()),
        reply(200, json!({"saved":true})),
        received,
    ]);
    let (source, dir) = source();
    let receipt = submit_at(source, &control, &base, |_| Ok(()), |_| {}).unwrap();
    assert!(control.cancelled());
    assert!(crate::localization::english(&receipt).contains("Diagnostic report sent"));
    assert!(crate::localization::english(&receipt).contains("accepted-before-cancel"));
    assert_eq!(server.join().unwrap().len(), 4);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cancellation_during_an_unsuccessful_upload_prevents_retry() {
    let control = control();
    let mut failed = reply(503, json!({}));
    failed.cancel = Some(control.clone());
    let (base, server) = server(vec![
        reply(200, created()),
        reply(200, approved()),
        reply(200, json!({"saved":true})),
        failed,
    ]);
    let (source, dir) = source();
    let error = submit_at(source, &control, &base, |_| Ok(()), |_| {}).unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(server.join().unwrap().len(), 4);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn initial_request_has_a_timeout_before_opening_the_browser() {
    let mut response = reply(200, created());
    response.delay = Duration::from_millis(200);
    let (base, server) = server(vec![response]);
    let (source, dir) = source();
    let control = Submission {
        request_limit: Duration::from_millis(50),
        ..control()
    };
    let error = submit_at(
        source,
        &control,
        &base,
        |_| panic!("timed out request cannot open a browser"),
        |_| {},
    )
    .unwrap_err();
    assert!(format!("{error:#}")
        .to_ascii_lowercase()
        .contains("timeout"));
    server.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cancellation_after_approval_prevents_bundle_creation_and_upload() {
    let (base, server) = server(vec![reply(200, created())]);
    let (source, dir) = source();
    let control = control();
    let error = submit_at(
        source,
        &control,
        &base,
        |_| {
            control.cancel();
            Ok(())
        },
        |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(server.join().unwrap().len(), 1);
    assert!(!dir.join("reports").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn overall_deadline_bounds_the_initial_request_too() {
    let mut response = reply(200, created());
    response.delay = Duration::from_millis(200);
    let (base, server) = server(vec![response]);
    let (source, dir) = source();
    let control = Submission {
        deadline: Instant::now() + Duration::from_millis(50),
        ..control()
    };
    assert!(submit_at(
        source,
        &control,
        &base,
        |_| panic!("expired request"),
        |_| {}
    )
    .is_err());
    server.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

/// Explicit release smoke test: the approver reads one URL from stdin and must
/// approve its session-only form. No drive or existing diagnostic history is read.
#[test]
#[ignore = "sends one synthetic report to the production maintainer; requires FREEMKV_REPORT_APPROVER"]
fn production_submission_with_synthetic_history() {
    use std::process::{Command, Stdio};
    let approver =
        std::env::var_os("FREEMKV_REPORT_APPROVER").expect("explicit browser approver required");
    let dir = std::env::temp_dir().join(format!(
        "freemkv-production-smoke-{}",
        crate::support::random_id().unwrap()
    ));
    let mut journal = crate::support::Journal::open_at(dir.clone()).unwrap();
    journal.record("synthetic_release_smoke", json!({"application":"freemkv-flash 0.13.4", "note":"Synthetic release verification only. No drive accessed; no user logs included."})).unwrap();
    let receipt = submit_at(
        journal.source(),
        &Submission::new(),
        "https://freemkv.org/api/flash-reports",
        |url| {
            let mut child = Command::new("node")
                .arg(&approver)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            child
                .stdin
                .take()
                .context("approver stdin")?
                .write_all(url.as_bytes())?;
            let output = child.wait_with_output()?;
            anyhow::ensure!(
                output.status.success(),
                "Browser approval failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(())
        },
        |message| eprintln!("{message}"),
    )
    .unwrap();
    assert!(receipt.starts_with("Report ") && receipt.contains(" received. Local copy:"));
    eprintln!("Synthetic production submission: {receipt}");
    drop(journal);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn backup_upload_receipt_describes_actual_bundle_and_required_description() {
    let (base, server) = server_with_inspection(
        vec![
            reply(200, created()),
            reply(200, approved()),
            reply(200, json!({"saved":true})),
            reply(200, json!({"report_id":"backup-receipt"})),
        ],
        |body| {
            let mut zip = zip::ZipArchive::new(std::io::Cursor::new(body)).unwrap();
            let manifest: Value =
                serde_json::from_reader(zip.by_name("manifest.json").unwrap()).unwrap();
            assert_eq!(manifest["artifact"]["kind"], "backup");
            assert_eq!(manifest["description"], "Synthetic diagnostic context");
            let mut bytes = Vec::new();
            zip.by_name("artifacts/backup.bin")
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes, b"exact backup bytes");
        },
    );
    let (source, dir) = source();
    let path = dir.join("backup.tar");
    std::fs::write(&path, b"exact backup bytes").unwrap();
    let source = source.with_artifact(
        crate::support::ReportArtifact::pending(path, "backup")
            .capture("drive", "Drive", "op")
            .unwrap(),
    );
    let result = submit_at(source, &control(), &base, |_| Ok(()), |_| {}).unwrap();
    assert!(crate::localization::english(&result).contains("Diagnostic report and backup sent"));
    assert!(result.contains("backup-receipt"));
    assert_eq!(server.join().unwrap().len(), 4);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn changed_dump_never_reaches_upload_after_approval() {
    let (base, server) = server(vec![reply(200, created()), reply(200, approved())]);
    let (source, dir) = source();
    let path = dir.join("dump.bin");
    std::fs::write(&path, b"original bytes").unwrap();
    let artifact = crate::support::ReportArtifact::pending(path.clone(), "dump")
        .capture("drive", "Drive", "op")
        .unwrap();
    std::fs::write(path, b"modified bytes").unwrap();
    let error = submit_at(
        source.with_artifact(artifact),
        &control(),
        &base,
        |_| Ok(()),
        |_| {},
    )
    .unwrap_err();
    assert!(error.is::<crate::support::AttachmentChanged>());
    assert_eq!(server.join().unwrap().len(), 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn empty_server_receipt_is_not_submission_success() {
    let (base, server) = server(vec![
        reply(200, created()),
        reply(200, approved()),
        reply(200, json!({"saved":true})),
        reply(200, json!({"report_id":""})),
    ]);
    let (source, dir) = source();
    let result = submit_at(source, &control(), &base, |_| Ok(()), |_| {});
    assert!(
        result.is_err(),
        "empty receipt must not claim success: {result:?}"
    );
    assert_eq!(server.join().unwrap().len(), 4);
    std::fs::remove_dir_all(dir).unwrap();
}
