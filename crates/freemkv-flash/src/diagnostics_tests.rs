use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn operation_log_includes_output_native_warning_and_full_error_chain() {
    let path = Arc::new(Mutex::new(None));
    let captured = path.clone();
    let directory =
        std::env::temp_dir().join(format!("freemkv-diagnostics-test-{}", std::process::id()));
    let result: Result<()> = crate::output::capture_events(
        move |event| {
            if let crate::output::Event::Field { label, value } = event {
                if label == "Diagnostic log" {
                    *captured.lock().unwrap() = Some(PathBuf::from(value));
                }
            }
        },
        || {
            run_at(&directory, "test", || {
                println!("capturing drive firmware");
                tracing::warn!(target: "freemkv::scsi", last_error = 87, "DeviceIoControl failed");
                tracing::trace!(target: "freemkv::scsi", host_status = 7, "native transport detail");
                run("nested", || {
                    record("SCSI result: status=0x00 transferred=0");
                    Err(anyhow::anyhow!("short firmware read")
                        .context("probing Pioneer firmware read access"))
                })
            })
        },
    );
    assert!(result.is_err());
    let path = path.lock().unwrap().clone().unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    for expected in [
        "freemkv-flash=",
        "os=",
        "capturing drive firmware",
        "last_error=87",
        "host_status=7",
        "native transport detail",
        "DeviceIoControl failed",
        "status=0x00 transferred=0",
        "RESULT: error: probing Pioneer firmware read access: short firmware read",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert_eq!(text.matches("freemkv-flash=").count(), 1);
    assert!(LOG.with(|slot| slot.borrow().is_none()));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn metadata_log_records_sizes_bytes_headers_and_validation_decisions() {
    use crate::drive::mtk::{Acquire, FEATURE_SERIAL};
    use crate::platform::MockScsiDevice;
    let path = Arc::new(Mutex::new(None));
    let captured = path.clone();
    let directory = std::env::temp_dir().join("freemkv-metadata-log-test");
    crate::output::capture_events(
        move |event| {
            if let crate::output::Event::Field { label, value } = event {
                if label == "Diagnostic log" {
                    *captured.lock().unwrap() = Some(PathBuf::from(value));
                }
            }
        },
        || {
            run_at(&directory, "metadata-test", || {
                for (returned, payload, valid) in
                    [(24usize, 12u8, true), (24, 16, false), (996, 16, false)]
                {
                    let mut data = vec![b'S'; returned];
                    data[..4].copy_from_slice(&(8 + u32::from(payload)).to_be_bytes());
                    data[8..10].copy_from_slice(&FEATURE_SERIAL.to_be_bytes());
                    data[11] = payload;
                    let mut dev = MockScsiDevice::new().on(|_| true, data);
                    assert_eq!(
                        Acquire::GetConfig {
                            feature: FEATURE_SERIAL,
                            alloc: 28
                        }
                        .run(&mut dev)
                        .is_ok(),
                        valid
                    );
                }
                Ok(())
            })
        },
    )
    .unwrap();
    let path = path.lock().unwrap().clone().unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    for expected in [
        "allocation=Some(28)",
        "returned=24",
        "returned=996",
        "response_declared_total=Some(24)",
        "feature_declared_total=Some(28)",
        "additional_length=Some(12)",
        "raw_prefix=[00, 00, 00, 14",
        "omitted_bytes=484",
        "accepted: complete response",
        "rejected: feature",
        "expected 28 declared bytes, got 24",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rollover_keeps_initial_context_and_final_result_bounded() {
    let directory = std::env::temp_dir().join("freemkv-diagnostics-rollover-test");
    let (path, mut log) = create_log(&directory, "freemkv-flash").unwrap();
    log.write("\x1b[32minitial drive identity\x1b[0m").unwrap();
    let row = "command ".repeat(128);
    for _ in 0..(MAX_LOG / row.len() + 20) {
        log.write(&row).unwrap();
    }
    log.write("RESULT: terminal failure").unwrap();
    drop(log);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.len() <= MAX_LOG);
    assert!(text.contains("initial drive identity"));
    assert!(!text.contains('\x1b'));
    assert!(text.contains("older intervening events omitted"));
    assert!(text.ends_with("RESULT: terminal failure\n"));
    std::fs::remove_file(path).unwrap();
}

#[cfg(unix)]
#[test]
fn logging_failure_disables_logging_without_failing_the_operation() {
    let directory = std::env::temp_dir().join("freemkv-diagnostics-failure-test");
    let (path, mut log) = create_log(&directory, "freemkv-flash").unwrap();
    log.file = File::open(&path).unwrap(); // read-only handle makes the write fail
    LOG.with(|slot| *slot.borrow_mut() = Some(log));
    crate::output::capture(|_| {}, || record("cannot write this"));
    assert!(LOG.with(|slot| slot.borrow().is_none()));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn panic_closes_the_log_and_records_unknown_outcome() {
    let path = Arc::new(Mutex::new(None));
    let captured = path.clone();
    let directory = std::env::temp_dir().join("freemkv-diagnostics-panic-test");
    crate::output::capture_events(
        move |event| {
            if let crate::output::Event::Field { label, value } = event {
                if label == "Diagnostic log" {
                    *captured.lock().unwrap() = Some(PathBuf::from(value));
                }
            }
        },
        || {
            assert!(std::panic::catch_unwind(|| run_at::<()>(
                &directory,
                "panic-test",
                || panic!("test panic")
            ))
            .is_err());
        },
    );
    assert!(LOG.with(|slot| slot.borrow().is_none()));
    let path = path.lock().unwrap().clone().unwrap();
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("PANIC: operation unwound; outcome unknown"));
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("PANIC: test panic; operation outcome unknown"));
    std::fs::remove_file(path).unwrap();
}

#[cfg(unix)]
#[test]
fn diagnostic_collection_is_bounded_and_reports_failure() {
    use std::process::Command;
    use std::time::{Duration, Instant};
    let (status, output) = bounded_output(
        Command::new("/bin/sh").args(["-c", "printf context; printf error >&2; exit 7"]),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(status.contains('7'));
    assert!(output.contains("context") && output.contains("error"));
    let (_, output) =
        bounded_output(&mut Command::new("/usr/bin/yes"), Duration::from_secs(2)).unwrap();
    assert!(output.len() <= 32 * 1024);
    assert!(!output.is_empty());
    let start = Instant::now();
    let (status, _) = bounded_output(
        Command::new("/bin/sleep").arg("10"),
        Duration::from_millis(80),
    )
    .unwrap();
    assert!(status.contains("timed out"));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[cfg(target_os = "macos")]
#[test]
fn native_open_failure_is_in_the_operation_log() {
    let directory =
        std::env::temp_dir().join(format!("freemkv-native-open-{}", std::process::id()));
    let result = run_at(&directory, "native-open", || {
        libfreemkv::scsi::open(std::path::Path::new("ioreg:18446744073709551615"))
            .map(|_| ())
            .map_err(anyhow::Error::from)
    });
    assert!(result.is_err());
    let path = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("stage=resolve_service result=not_found"),
        "{text}"
    );
    assert!(text.contains("executable="));
    assert!(text.contains("attribute=com.apple.quarantine"));
    assert!(text.contains("RESULT: error:"));
    std::fs::remove_dir_all(directory).unwrap();
}
