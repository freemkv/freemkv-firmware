//! Read-only device information grouped for scanning on desktop and narrow windows.
use eframe::egui;
use freemkv_flash::output::device_settings::{
    Observed, PureReadMode, QuietMode, SettingId, Settings, Support, Value,
};

// Settings edits stay disabled until the apply/re-read interaction is enabled.
const EDIT_SETTINGS: bool = false;

const SECTIONS: [&str; 6] = [
    "General information",
    "Additional information",
    "Media capabilities",
    "DVD region",
    "Device settings",
    "Firmware operations",
];
fn section(label: &str) -> usize {
    match label {
        "Hardware type" | "Kernel type" | "Firmware type" | "Firmware version"
        | "Kernel version" | "Product code" | "Manufactured" | "Product origin"
        | "Pioneer identity" => 1,
        "RPC scheme"
        | "DVD region"
        | "User changes remaining"
        | "Vendor resets remaining"
        | "Region state" => 3,
        "Quiet Drive"
        | "Quiet Drive control"
        | "PureRead"
        | "PureRead version"
        | "Real-time PureRead"
        | "Saved settings"
        | "Saved Quiet Drive"
        | "Saved PureRead" => 4,
        "Backup" | "Firmware update" | "Drive family" => 5,
        s if s.starts_with("CD-")
            || s.starts_with("DVD-")
            || s.starts_with("DVD+")
            || s.starts_with("BD-")
            || s.starts_with("HD DVD-")
            || matches!(s, "LabelFlash" | "LightScribe") =>
        {
            2
        }
        _ => 0,
    }
}
fn check(ui: &mut egui::Ui, value: &str) {
    match value {
        "Yes" | "No" => {
            let mut checked = value == "Yes";
            ui.add_enabled(false, egui::Checkbox::without_text(&mut checked));
        }
        _ => {
            ui.allocate_space(egui::vec2(
                ui.spacing().interact_size.y,
                ui.spacing().interact_size.y,
            ));
        }
    }
}
fn visible_media(value: &str) -> bool {
    value
        .strip_prefix("Read: ")
        .and_then(|s| s.split_once("    Write: "))
        .map_or(value == "Yes", |(read, write)| {
            read == "Yes" || write == "Yes"
        })
}
fn media_column(ui: &mut egui::Ui, rows: &[&(String, String)], id: usize) {
    egui::Grid::new(("media_capabilities", id))
        .num_columns(2)
        .spacing([8.0, 2.0])
        .show(ui, |ui| {
            ui.label("");
            ui.strong("R/W").on_hover_text("Read / Write");
            ui.end_row();
            for (label, value) in rows {
                ui.label(label);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 1.0;
                    if let Some((read, write)) = value
                        .strip_prefix("Read: ")
                        .and_then(|s| s.split_once("    Write: "))
                    {
                        check(ui, read);
                        if !label.ends_with("-ROM") {
                            check(ui, write);
                        }
                    } else {
                        check(ui, value);
                    }
                });
                ui.end_row();
            }
        });
}
fn media_ui(ui: &mut egui::Ui, fields: &[(String, String)]) {
    let (left, right): (Vec<_>, Vec<_>) = fields
        .iter()
        .filter(|(k, v)| section(k) == 2 && visible_media(v))
        .partition(|(k, _)| k.starts_with("CD-") || k.starts_with("DVD-") || k.starts_with("DVD+"));
    if ui.available_width() >= 350.0 && !left.is_empty() && !right.is_empty() {
        ui.columns(2, |columns| {
            media_column(&mut columns[0], &left, 0);
            media_column(&mut columns[1], &right, 1);
        });
    } else {
        let rows: Vec<_> = left.into_iter().chain(right).collect();
        media_column(ui, &rows, 0);
    }
}
fn additional_group(label: &str) -> &'static str {
    match label {
        "Kernel type" | "Kernel version" => "Kernel",
        "Firmware type" | "Firmware version" => "Normal",
        _ => "Device",
    }
}
fn quiet_name(mode: QuietMode) -> &'static str {
    match mode {
        QuietMode::Standard => "Standard",
        QuietMode::Performance => "Performance",
        QuietMode::Quiet => "Quiet",
        QuietMode::PersistentQuiet => "Persistent quiet",
    }
}
fn pure_name(mode: PureReadMode) -> &'static str {
    match mode {
        PureReadMode::Standard => "Standard",
        PureReadMode::Master => "Master",
        PureReadMode::Perfect => "Perfect",
    }
}
fn unreported<T>(ui: &mut egui::Ui, label: &str, state: Observed<T>) {
    match state {
        Observed::Unknown(v) => {
            ui.label(format!("{label}: unknown (0x{v:02X})"));
        }
        Observed::NotReported => {
            ui.label(format!("{label}: not reported"));
        }
        Observed::Known(_) => {}
    }
}
fn value_name(value: Value) -> &'static str {
    match value {
        Value::Quiet(v) => quiet_name(v),
        Value::PureRead(v) => pure_name(v),
        Value::Boolean(true) => "On",
        Value::Boolean(false) => "Off",
    }
}
fn settings_ui(ui: &mut egui::Ui, settings: &Settings) {
    for entry in settings.entries() {
        let name = match entry.id {
            SettingId::QuietDrive => "Quiet Drive",
            SettingId::PureRead => "PureRead",
            SettingId::RealTimePureRead => "Real-time PureRead",
        };
        let title = entry
            .version
            .map_or_else(|| name.to_owned(), |v| format!("{name} {v}"));
        ui.strong(title);
        let editable = EDIT_SETTINGS && entry.control.writable == Support::Supported;
        if entry.control.choices == [Value::Boolean(false), Value::Boolean(true)] {
            if let Observed::Known(Value::Boolean(mut active)) = entry.current {
                ui.add_enabled(editable, egui::Checkbox::new(&mut active, "Enabled"));
            }
        } else if !entry.control.choices.is_empty() {
            egui::Grid::new(("setting_choices", name)).num_columns(2).show(ui, |ui| {
                for (i, value) in entry.control.choices.iter().enumerate() {
                    let saved = entry.saved == Observed::Known(*value);
                    let label = format!("{}{}", value_name(*value), if saved { " · saved" } else { "" });
                    ui.add_enabled(editable, egui::RadioButton::new(entry.current == Observed::Known(*value), label))
                        .on_disabled_hover_text("Selected = active mode; saved = startup mode. Choices come from the settings codec.");
                    if i % 2 == 1 { ui.end_row(); }
                }
            });
        } else if let Observed::Known(value) = entry.current {
            ui.label(value_name(value));
        }
        unreported(ui, "Active mode", entry.current);
        if entry.id == SettingId::QuietDrive {
            unreported(ui, "Saved mode", entry.saved);
        }
        ui.add_space(8.0);
    }
}
fn card(ui: &mut egui::Ui, fields: &[(String, String)], group: usize, settings: Option<&Settings>) {
    if group == 2
        && !fields
            .iter()
            .any(|(k, v)| section(k) == 2 && visible_media(v))
    {
        return;
    }
    if group == 4 && settings.is_some_and(|s| s.entries().next().is_none()) {
        return;
    }
    if !(fields.iter().any(|(k, _)| section(k) == group) || group == 4 && settings.is_some()) {
        return;
    }
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.visuals_mut().disabled_alpha = 0.8;
        ui.strong(SECTIONS[group]);
        if group == 4 {
            ui.small("Current settings · read only");
            if let Some(settings) = settings {
                settings_ui(ui, settings);
                return;
            }
        }
        ui.add_space(8.0);
        if group == 2 {
            media_ui(ui, fields);
            return;
        }
        egui::Grid::new(("drive_information", group))
            .num_columns(2)
            .spacing([12.0, 4.0])
            .max_col_width((ui.available_width() - 16.0) / 2.0)
            .show(ui, |ui| {
                let mut rows: Vec<_> = fields.iter().filter(|(k, _)| section(k) == group).collect();
                if group == 1 {
                    rows.sort_by_key(|(k, _)| match additional_group(k) {
                        "Device" => 0,
                        "Kernel" => 1,
                        _ => 2,
                    });
                }
                let mut previous = "";
                for (label, value) in rows {
                    if group == 1 && additional_group(label) != previous {
                        previous = additional_group(label);
                        ui.strong(previous);
                        ui.label("");
                        ui.end_row();
                    }
                    ui.label(label);
                    ui.add(egui::Label::new(value).wrap().selectable(true));
                    ui.end_row();
                }
            });
    });
    ui.add_space(8.0);
}
pub(crate) fn show(ui: &mut egui::Ui, fields: &[(String, String)], settings: Option<&Settings>) {
    if ui.available_width() >= 760.0 {
        ui.columns(2, |cols| {
            for group in [0, 2] {
                card(&mut cols[0], fields, group, settings);
            }
            for group in [1, 3, 4, 5] {
                card(&mut cols[1], fields, group, settings);
            }
        });
    } else {
        for group in [0, 1, 3, 4, 2, 5] {
            card(ui, fields, group, settings);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn region_and_saved_settings_are_not_misclassified_as_media() {
        assert_eq!(section("DVD region"), 3);
        assert_eq!(section("DVD-R DL"), 2);
        assert_eq!(section("Saved Quiet Drive"), 4);
        assert_eq!(section("Firmware version"), 1);
        assert_eq!(section("Firmware type"), 1);
    }
    #[test]
    fn information_cards_render_in_narrow_and_wide_layouts() {
        let fields: Vec<_> = [
            ("Model", "BDR-XD08U"),
            ("Kernel type", "ID69"),
            ("CD-R", "Read: Yes    Write: Yes"),
            ("DVD region", "2"),
            ("Quiet Drive", "Quiet"),
            ("Saved Quiet Drive", "Performance"),
            ("PureRead", "Master"),
            ("Firmware update", "Supported"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        for width in [680.0, 880.0] {
            let ctx = egui::Context::default();
            for _ in 0..3 {
                let output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 2000.0),
                        )),
                        ..Default::default()
                    },
                    |ui| show(ui, &fields, None),
                );
                let text: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|s| {
                        if let egui::epaint::Shape::Text(t) = &s.shape {
                            Some(t.galley.text())
                        } else {
                            None
                        }
                    })
                    .collect();
                assert!(text.contains(&"Current settings · read only"));
                assert!(text.contains(&"Master"));
                assert!(text.contains(&"Kernel"));

                assert!(text.contains(&"R/W"));
            }
        }
    }
    #[test]
    fn settings_render_from_codec_descriptors_without_unsupported_children() {
        use freemkv_flash::output::device_settings::{Codec, VendorF4};
        let mut response = [0u8; 256];
        response[..2].fill(255);
        response[2] = 2;
        response[3] = 2;
        response[43] = 1;
        response[45] = 1;
        response[49] = 4; // Must remain hidden when PureRead support is zero.
        let settings = VendorF4.decode(&response).unwrap();
        for width in [400.0, 880.0] {
            let ctx = egui::Context::default();
            for _ in 0..3 {
                let output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 1200.0),
                        )),
                        ..Default::default()
                    },
                    |ui| show(ui, &[], Some(&settings)),
                );
                let text: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|s| {
                        if let egui::epaint::Shape::Text(t) = &s.shape {
                            Some(t.galley.text())
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(text.iter().filter(|t| **t == "Quiet · saved").count(), 1);
                assert!(text.contains(&"Persistent quiet"));
                assert!(!text.iter().any(|t| t.contains("PureRead")));
            }
        }
    }
    #[test]
    fn media_visibility_requires_a_positive_capability() {
        for value in [
            "Unknown",
            "No",
            "Read: Unknown    Write: Unknown",
            "Read: Unknown    Write: No",
            "Read: No    Write: No",
            "Read: No    Write: Unknown",
        ] {
            assert!(!visible_media(value), "{value}");
        }
        for value in [
            "Yes",
            "Read: Yes    Write: No",
            "Read: Yes    Write: Unknown",
            "Read: Unknown    Write: Yes",
        ] {
            assert!(visible_media(value), "{value}");
        }
    }
    #[test]
    fn empty_media_card_is_hidden_and_other_information_survives() {
        let fields: Vec<_> = [
            ("Model", "PIONEER"),
            ("BD-R XL", "Read: Unknown    Write: Unknown"),
            ("LabelFlash", "Unknown"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let ctx = egui::Context::default();
        let output = ctx.run_ui(Default::default(), |ui| show(ui, &fields, None));
        let text: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|s| {
                if let egui::epaint::Shape::Text(t) = &s.shape {
                    Some(t.galley.text())
                } else {
                    None
                }
            })
            .collect();
        assert!(text.contains(&"PIONEER"));
        assert!(!text.contains(&"Media capabilities"));
        assert!(!text.contains(&"BD-R XL"));
        assert!(!text.contains(&"LabelFlash"));
    }
}
