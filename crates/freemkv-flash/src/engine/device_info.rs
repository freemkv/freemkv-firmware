//! Presentation of pioneer-optical's read-only live snapshot for both front-ends.
use crate::{
    drive::pioneer_transport::{ScsiTransport, SharedDevice},
    platform::ScsiDevice,
};
use pioneer_optical::{
    device::{
        info::Media,
        settings::{Capability, Observed, PureReadMode, QuietMode},
        Device,
    },
    production,
};

fn field(label: &str, value: impl Into<String>) {
    let value = crate::style::printable(&value.into());
    crate::output::field(label, &value);
    println!("{}", crate::style::kv(label, &value));
}
fn available(value: Option<impl ToString>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "Not reported".into())
}
fn boolean(value: Option<bool>) -> &'static str {
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
fn observed<V>(value: Observed<V>, label: impl FnOnce(V) -> &'static str) -> String {
    match value {
        Observed::Known(v) => label(v).into(),
        Observed::Unknown(v) => format!("Unknown (0x{v:02X})"),
        Observed::NotReported => "Not reported".into(),
    }
}
fn quiet(mode: QuietMode) -> &'static str {
    match mode {
        QuietMode::Standard => "Standard",
        QuietMode::Performance => "Performance",
        QuietMode::Quiet => "Quiet",
        QuietMode::PersistentQuiet => "Persistent quiet",
    }
}
fn pure(mode: PureReadMode) -> &'static str {
    match mode {
        PureReadMode::Standard => "Standard",
        PureReadMode::Master => "Master",
        PureReadMode::Perfect => "Perfect",
    }
}

pub(super) fn show(dev: &mut dyn ScsiDevice, pioneer: bool) {
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
    if pioneer {
        match &info.pioneer {
            Ok(id) => {
                field("Hardware type", id.platform());
                field("Kernel type", id.kernel_tag());
                field("Firmware type", id.normal_tag());
                field("Kernel version", id.code());
            }
            Err(e) => field("Pioneer identity", e.to_string()),
        }
        let mut b = [0; production::PARAMETERS_LEN];
        let made = device
            .parameters(&mut b)
            .ok()
            .and_then(|n| production::parse(&b[..n]));
        field("Product code", available(made.map(|p| p.product_code)));
        field(
            "Manufactured",
            available(
                made.and_then(|p| p.manufactured)
                    .map(|d| format!("{:04}-{:02}-{:02}", d.year, d.month, d.day)),
            ),
        );
        field(
            "Product origin",
            available(serial.and_then(production::origin)),
        );
    }
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
    if pioneer {
        match device.settings() {
            Ok(s) => {
                crate::output::publish(crate::output::Event::DeviceSettings(s));
                let q = s.quiet_drive();
                let p = s.pure_read();
                if matches!(q.current, Observed::Known(_)) && q.current == q.saved {
                    field(
                        "Quiet Drive",
                        format!("{} (active and saved)", observed(q.current, quiet)),
                    );
                } else {
                    field(
                        "Quiet Drive",
                        format!("{} (active)", observed(q.current, quiet)),
                    );
                    field("Saved Quiet Drive", observed(q.saved, quiet));
                }
                if let Capability::Supported(p) = p {
                    field("PureRead", observed(p.current, pure));
                    if let Some(version) = p.version {
                        field("PureRead version", version.to_string());
                    }
                    if let Capability::Supported(real_time) = p.real_time {
                        field(
                            "Real-time PureRead",
                            observed(real_time, |v| if v { "On" } else { "Off" }),
                        );
                    }
                } else if p == Capability::Unknown {
                    field("PureRead", "Not reported");
                }
            }
            Err(e) => {
                field("Quiet Drive", e.to_string());
                field("PureRead", e.to_string());
            }
        }
    }
}
