//! Lineage-profile selection tests.

use super::*;

/// A minimal image carrying `banner` at the boot-banner offset and nothing else.
/// Sized to end right after the banner, so a finder that reads anywhere but the
/// banner window reads nothing at all.
fn banner_image(banner: &[u8]) -> Vec<u8> {
    let b = freemkv_chipset::BANNER_OFFSET;
    let mut img = vec![0u8; b + 16];
    img[b..b + banner.len()].copy_from_slice(banner);
    img
}

/// The classic/modern split is read from the 16-byte boot banner **at
/// `BANNER_OFFSET`** — it decides which dispatch-table and commit windows the
/// finders scan, so answering it wrongly (or constantly) points the whole build
/// at the wrong lineage's address space.
#[test]
fn the_classic_banner_is_recognised_only_at_the_banner_offset() {
    assert!(
        is_classic_banner(&banner_image(b"MT1939 Boot Code")),
        "the classic banner must be read from the banner window itself"
    );
    assert!(
        !is_classic_banner(&banner_image(b"MT1959 Boot JB8 ")),
        "an MT1959-lineage banner is modern, not classic"
    );
    assert!(
        !is_classic_banner(&banner_image(b"")),
        "a blank banner is not the classic banner"
    );

    // Same bytes, one window early: not the banner, so not classic.
    let b = freemkv_chipset::BANNER_OFFSET;
    let mut off_by_a_window = banner_image(b"MT1959 Boot JB8 ");
    off_by_a_window[b - 16..b].copy_from_slice(b"MT1939 Boot Code");
    assert!(
        !is_classic_banner(&off_by_a_window),
        "the banner is read at a fixed offset; a matching string elsewhere must not count"
    );

    // Truncated: the window is not fully present, so there is no banner to read.
    assert!(
        !is_classic_banner(&banner_image(b"MT1939 Boot Code")[..b + 8]),
        "a half-present banner window must not be treated as classic"
    );
}

/// An unidentifiable image falls back to the MT1959/modern profile (the
/// historical primary path) rather than refusing or guessing classic.
#[test]
fn an_unidentifiable_image_falls_back_to_the_modern_profile() {
    let lineage = detect_lineage(&banner_image(b"MT1939 Boot Code"));
    assert_eq!(
        lineage,
        Lineage::Mt1959,
        "family detection is authoritative; a bare banner with no MTEK identity page must not \
         select the classic profile on its own"
    );
    assert_eq!(
        profile_for(Lineage::Mt1939Classic).live_record_windows,
        CLASSIC_LIVE_RECORD_WINDOWS,
        "each lineage must keep its own dispatch-table windows"
    );
    assert_eq!(
        profile_for(Lineage::Mt1959).live_record_windows,
        MODERN_LIVE_RECORD_WINDOWS
    );
}
