//! Presentation of the standard MMC live snapshot (INQUIRY, GET CONFIGURATION,
//! mechanism, media, DVD region) for both front-ends. Vendor extras come from
//! the backend's `print_device_info`.
use crate::{
    drive::transport::{ScsiTransport, SharedDevice},
    platform::ScsiDevice,
};
use pioneer_optical::device::{info::Media, settings::Observed, Device};

pub(crate) fn field(label: &str, value: impl Into<String>) {
    let value = crate::style::printable(&value.into());
    crate::output::field(label, &value);
    println!("{}", crate::style::kv(label, &value));
}
pub(crate) fn available(value: Option<impl ToString>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "Not reported".into())
}
pub(crate) fn boolean(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "Unknown",
    }
}
fn loader(code: u8) -> String {
    match code {
        0 => "Caddy / slot".into(),
        1 => "Tray".into(),
        2 => "Pop-up".into(),
        4 => "Disc changer".into(),
        5 => "Magazine changer".into(),
        v => format!("Unknown ({v})"),
    }
}
fn interface(code: u32) -> String {
    match code {
        0 => "Unspecified".into(),
        1 => "SCSI".into(),
        2 => "ATAPI".into(),
        3 | 4 | 6 => "IEEE 1394".into(),
        5 => "Fibre Channel".into(),
        7 => "Serial ATAPI".into(),
        8 => "USB".into(),
        v => format!("Unknown (0x{v:X})"),
    }
}
pub(crate) fn observed<V>(value: Observed<V>, label: impl FnOnce(V) -> &'static str) -> String {
    match value {
        Observed::Known(v) => label(v).into(),
        Observed::Unknown(v) => format!("Unknown (0x{v:02X})"),
        Observed::NotReported => "Not reported".into(),
    }
}
pub(crate) fn show(dev: &mut dyn ScsiDevice) {
    let shared = SharedDevice::new(dev);
    let mut transport = ScsiTransport::reads(&shared);
    let mut device = Device::new(&mut transport);
    let info = device.info();
    if let Ok(inquiry) = &info.inquiry {
        if !inquiry.extra().is_empty() {
            field("Extra information", inquiry.extra());
        }
    }
    let serial = info
        .pioneer
        .as_ref()
        .ok()
        .map(|i| i.serial())
        .filter(|s| !s.is_empty())
        .or_else(|| info.configuration.serial());
    field("Serial number", available(serial));
    let mechanical = info.mechanical.as_ref().ok();
    field(
        "Buffer size",
        available(
            mechanical
                .and_then(|m| m.buffer_kib())
                .map(|n| format!("{n} KiB")),
        ),
    );
    field(
        "Loader type",
        available(
            info.configuration
                .loader()
                .or_else(|| mechanical.map(|m| m.loader()))
                .map(loader),
        ),
    );
    field(
        "Interface type",
        available(info.configuration.interface().map(interface)),
    );
    for (name, medium) in [
        ("CD-ROM", Media::CdRom),
        ("CD-R", Media::CdR),
        ("CD-RW", Media::CdRw),
        ("DVD-ROM", Media::DvdRom),
        ("DVD-R", Media::DvdR),
        ("DVD-R DL", Media::DvdRDl),
        ("DVD-RW", Media::DvdRw),
        ("DVD+R", Media::DvdPlusR),
        ("DVD+R DL", Media::DvdPlusRDl),
        ("DVD+RW", Media::DvdPlusRw),
        ("DVD+RW DL", Media::DvdPlusRwDl),
        ("DVD-RAM", Media::DvdRam),
        ("BD-ROM", Media::BdRom),
        ("BD-R", Media::BdR),
        ("BD-R XL", Media::BdRXl),
        ("BD-RE", Media::BdRe),
        ("BD-RE XL", Media::BdReXl),
        ("HD DVD-ROM", Media::HdDvdRom),
        ("HD DVD-R", Media::HdDvdR),
        ("HD DVD-RAM", Media::HdDvdRam),
        ("HD DVD-RW", Media::HdDvdRw),
    ] {
        let caps = info.configuration.media(medium, mechanical);
        if caps.read == Some(false) && caps.write == Some(false) {
            continue;
        }
        field(
            name,
            format!(
                "Read: {}    Write: {}",
                boolean(caps.read),
                boolean(caps.write)
            ),
        );
    }
    match device.get(pioneer_optical::device::DvdRegion) {
        Ok(rpc) => {
            field(
                "RPC scheme",
                match rpc.scheme {
                    0 => "RPC-1".into(),
                    1 => "RPC-2".into(),
                    v => format!("Unknown ({v})"),
                },
            );
            field(
                "DVD region",
                crate::inspection::pioneer::dvd_region_label(rpc),
            );
            field(
                "User changes remaining",
                rpc.user_changes_remaining.to_string(),
            );
            field(
                "Vendor resets remaining",
                rpc.vendor_resets_remaining.to_string(),
            );
            field(
                "Region state",
                match rpc.type_code {
                    0 => "Never set",
                    1 => "Set",
                    2 => "Last chance",
                    3 => "Permanent",
                    _ => "Unknown",
                },
            );
        }
        Err(e) => field("DVD region", e.to_string()),
    }
}
