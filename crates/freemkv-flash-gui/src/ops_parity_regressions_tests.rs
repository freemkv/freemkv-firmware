use super::*;

#[test]
fn gui_accepts_the_same_pioneer_backend_as_cli() {
    let mut dev = platform::MockScsiDevice::pioneer();
    let backend = freemkv_flash::workflow::classify_gated(&mut dev)
        .expect("Pioneer supports backup and flash");
    assert_eq!(backend, Family::Pioneer);
    assert!(dev.writes.is_empty());
}

#[test]
fn gui_receives_progress_and_warnings() {
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let received = lines.clone();
    capture_lines(
        || {
            freemkv_flash::style::Progress::new("reading firmware", 0x200000).set(0x100000);
        },
        move |line| received.lock().unwrap().push(line),
    );
    assert!(lines.lock().unwrap().iter().any(|l| l.contains("50%")));
}
