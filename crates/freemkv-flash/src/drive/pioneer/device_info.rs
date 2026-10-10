//! Pioneer vendor extras for `info`: hardware/Kernel/Normal identity,
//! production record, Quiet Drive and PureRead settings.

use crate::drive::transport::{ScsiTransport, SharedDevice};
use crate::engine::device_info::{available, field, observed};
use crate::platform::ScsiDevice;
use pioneer_optical::{
    device::{
        settings::{Capability, Observed, PureReadMode, QuietMode},
        Device,
    },
    production,
};

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

/// Print the Pioneer vendor fields of `info`.
pub(crate) fn show(dev: &mut dyn ScsiDevice) {
    let shared = SharedDevice::new(dev);
    let mut transport = ScsiTransport::reads(&shared);
    let mut device = Device::new(&mut transport);
    let info = device.info();
    let serial = info
        .pioneer
        .as_ref()
        .ok()
        .map(|i| i.serial())
        .filter(|s| !s.is_empty())
        .or_else(|| info.configuration.serial());
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
