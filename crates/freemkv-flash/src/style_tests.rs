use super::*;

#[test]
fn status_line_aligns_short_and_long_labels() {
    // Colors are disabled under `cargo test` (stdout isn't a tty), so we
    // can assert on plain text layout directly.
    let short = status_line("Identity", "added", Status::Ok);
    let long = status_line("Read-through errors", "skipped", Status::Warn);
    assert!(short.starts_with("  Identity "));
    assert!(short.contains("added"));
    assert!(long.starts_with("  Read-through errors "));
    assert!(long.contains("skipped"));
}

#[test]
fn plain_when_color_disabled() {
    // color_enabled() is cached per-process and false here (no tty), so
    // painters must be pure passthrough.
    if !color_enabled() {
        assert_eq!(green("added"), "added");
        assert_eq!(amber("skipped"), "skipped");
        assert_eq!(red("failed"), "failed");
        assert_eq!(dim("0x1000"), "0x1000");
        assert_eq!(bold("freemkv-fw"), "freemkv-fw");
    }
}

#[test]
fn kv_contains_both_parts() {
    let s = kv("vendor", "HL-DT-ST");
    assert!(s.contains("vendor"));
    assert!(s.contains("HL-DT-ST"));
}
