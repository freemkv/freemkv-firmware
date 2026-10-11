use super::*;
use pioneer_optical::device::settings::{Codec, VendorF4};

/// A Vendor F4 settings block: Quiet active and saved, every other field
/// as the drive leaves it unreported.
fn quiet_settings() -> Settings {
    let mut block = [255u8; 256];
    block[..2].copy_from_slice(&[1, 1]);
    block[2] = 2;
    block[3] = 2;
    VendorF4.decode(&block).expect("a decodable F4 block")
}

#[test]
fn mode_rows_list_every_choice_with_its_marks_for_the_gui_only() {
    let rows = settings_rows(&Ok(quiet_settings()));
    let modes = rows
        .iter()
        .find(|r| r.gui_label.as_deref() == Some("Quiet Drive modes"))
        .expect("a Quiet Drive modes row");
    assert_eq!(modes.cli_label, None, "the CLI never listed modes");
    assert_eq!(
        modes.value.plain(),
        "Standard · Performance · Quiet (active, saved) · Persistent quiet"
    );
    // The CLI rows are the 0.11.x ones.
    let cli: Vec<_> = rows.iter().filter_map(|r| r.cli_line()).collect();
    assert_eq!(
        cli,
        [
            "Quiet Drive: Quiet (active and saved)",
            "PureRead: Not reported"
        ]
    );
}
