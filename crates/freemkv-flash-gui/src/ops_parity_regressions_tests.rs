use freemkv_flash::platform::MockScsiDevice;

#[test]
fn gui_accepts_the_same_pioneer_backend_as_cli() {
    let mut dev = MockScsiDevice::pioneer();
    let backend = freemkv_flash::workflow::classify_gated(&mut dev)
        .expect("Pioneer supports backup and flash");
    assert_eq!(backend.0, "pioneer-oem");
    assert!(dev.writes.is_empty());
}

#[test]
fn gui_receives_progress_and_warnings() {
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let received = lines.clone();
    freemkv_flash::output::capture(
        move |line| received.lock().unwrap().push(line),
        || {
            freemkv_flash::style::Progress::new("reading firmware", 0x200000).set(0x100000);
        },
    );
    assert!(lines.lock().unwrap().iter().any(|l| l.contains("50%")));
}
