use super::*;

/// Discovery must work even on a host with no optical drive attached.
#[test]
fn enumerate_does_not_panic() {
    let list = enumerate();
    // Every entry a shell would show must be a plausible device path.
    for d in &list {
        assert!(!d.path.is_empty());
    }
}

/// Job dispatch must surface a clean `Err` — never a panic — when the
/// selected device cannot be opened. This exercises the same `execute`
/// path the GUI's worker thread runs, minus the stdout capture.
#[test]
fn info_job_on_missing_device_errs_without_panic() {
    let res = execute("/dev/freemkv-flash-gui-no-such-device", &Job::Info);
    assert!(res.is_err(), "expected an open error, got {res:?}");
}
