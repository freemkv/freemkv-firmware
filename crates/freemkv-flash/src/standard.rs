//! Standard drive facts for `info` and `profile` only: pioneer-optical's
//! read-only `Device::info()` snapshot (INQUIRY, the vendor identity probe,
//! MODE SENSE 2A and the GET CONFIGURATION features), read once, plus the DVD
//! region read, and the rows they render as. Backup, flash, recovery and dump
//! never read it.

use pioneer_optical::device::info::{Information, Media};
use pioneer_optical::device::Device;

use crate::backend::ReadDevice;
use crate::report::{Group, Row, Value};
use crate::transport::{ScsiTransport, SharedDevice};

/// The standard snapshot, read once per `info`.
pub struct StandardInfo {
    /// pioneer-optical's per-field results.
    pub information: Information<anyhow::Error>,
}

#[cfg(test)]
thread_local! {
    static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many standard snapshots this thread has read (test instrumentation).
#[cfg(test)]
pub(crate) fn reads() -> usize {
    READS.with(|r| r.get())
}

/// Read the snapshot: exactly today's `Device::info()` command sequence.
pub fn read(dev: &mut ReadDevice<'_>) -> StandardInfo {
    #[cfg(test)]
    READS.with(|r| r.set(r.get() + 1));
    with_device(dev, |device| StandardInfo {
        information: device.info(),
    })
}

/// Run `f` with a pioneer-optical device over `dev`, whose grant refuses the
/// settings writes `Device::set` would send.
pub fn with_device<R>(
    dev: &mut ReadDevice<'_>,
    f: impl FnOnce(&mut Device<'_, ScsiTransport<'_, '_>>) -> R,
) -> R {
    let shared = SharedDevice::new(dev);
    let mut transport = ScsiTransport::reads(&shared);
    f(&mut Device::new(&mut transport))
}

impl StandardInfo {
    /// The serial number: the vendor identity's, else the MMC feature's.
    pub fn serial(&self) -> Option<&str> {
        self.information
            .pioneer
            .as_ref()
            .ok()
            .map(|i| i.serial())
            .filter(|s| !s.is_empty())
            .or_else(|| self.information.configuration.serial())
    }

    /// Extra INQUIRY information, serial, buffer, loader and interface.
    pub fn interface_rows(&self) -> Vec<Row> {
        let info = &self.information;
        let mut rows = Vec::new();
        if let Ok(inquiry) = &info.inquiry {
            if !inquiry.extra().is_empty() {
                rows.push(row("extra", "Extra information", inquiry.extra()));
            }
        }
        rows.push(row("serial", "Serial number", &available(self.serial())));
        let mechanical = info.mechanical.as_ref().ok();
        rows.push(row(
            "buffer",
            "Buffer size",
            &available(
                mechanical
                    .and_then(|m| m.buffer_kib())
                    .map(|n| format!("{n} KiB")),
            ),
        ));
        rows.push(row(
            "loader",
            "Loader type",
            &available(
                info.configuration
                    .loader()
                    .or_else(|| mechanical.map(|m| m.loader()))
                    .map(loader),
            ),
        ));
        rows.push(row(
            "interface",
            "Interface type",
            &available(info.configuration.interface().map(interface)),
        ));
        rows
    }

    /// Read and write support per medium, omitting media with neither.
    pub fn media_rows(&self) -> Vec<Row> {
        let mechanical = self.information.mechanical.as_ref().ok();
        MEDIA
            .iter()
            .filter_map(|&(name, medium)| {
                let caps = self.information.configuration.media(medium, mechanical);
                if caps.read == Some(false) && caps.write == Some(false) {
                    return None;
                }
                let value = format!(
                    "Read: {}    Write: {}",
                    boolean(caps.read),
                    boolean(caps.write)
                );
                Some(row("media", name, &value).in_group(Group::Media))
            })
            .collect()
    }
}

/// Read the DVD region state (REPORT KEY) and render it.
pub fn region_rows(dev: &mut ReadDevice<'_>) -> Vec<Row> {
    let region = with_device(dev, |d| d.get(pioneer_optical::device::DvdRegion));
    let rows = match region {
        Ok(rpc) => reported_region_rows(rpc),
        Err(e) => {
            crate::diagnostics::record(format!("DVD region read failed: {e:#}"));
            vec![row("region", "DVD region", "Unavailable")]
        }
    };
    rows.into_iter()
        .map(|r| r.in_group(Group::Region))
        .collect()
}

fn reported_region_rows(rpc: pioneer_optical::rpc::State) -> Vec<Row> {
    let mut rows = vec![
        row(
            "rpc",
            "RPC scheme",
            &match rpc.scheme {
                0 => "RPC-1".into(),
                1 => "RPC-2".into(),
                v => format!("Unknown ({v})"),
            },
        ),
        row(
            "region",
            "DVD region",
            &crate::inspection::dvd_region_label(rpc),
        ),
    ];
    // RPC-1 does not enforce the RPC-2 change budget. Its zero fields are not
    // exhausted reset counters, including after applying Region-free.
    if rpc.scheme == 1 {
        rows.extend([
            row(
                "user_changes",
                "User changes remaining",
                &rpc.user_changes_remaining.to_string(),
            ),
            row(
                "vendor_resets",
                "Vendor resets remaining",
                &rpc.vendor_resets_remaining.to_string(),
            ),
            row(
                "region_state",
                "Region state",
                match rpc.type_code {
                    0 => "Never set",
                    1 => "Set",
                    2 => "Last chance",
                    3 => "Permanent",
                    _ => "Unknown",
                },
            ),
        ]);
    }
    rows
}

/// A row both front-ends show under the same label, sanitized.
pub fn row(key: &'static str, label: &str, value: &str) -> Row {
    Row::both(key, label, Value::text(value))
}

/// The value, or `Not reported`.
pub fn available(value: Option<impl ToString>) -> String {
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

const MEDIA: [(&str, Media); 21] = [
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
];

#[cfg(test)]
mod region_tests {
    use super::*;
    #[test]
    fn rpc1_hides_inapplicable_reset_budget_after_region_free_modify() {
        let state = pioneer_optical::rpc::State::parse(&[0, 6, 0, 0, 0, 0, 0, 0]).unwrap();
        let rows = reported_region_rows(state);
        assert_eq!(
            rows.iter().map(|r| r.key).collect::<Vec<_>>(),
            ["rpc", "region"]
        );
        assert_eq!(crate::inspection::dvd_region_label(state), "Region-free");
    }
    #[test]
    fn rpc2_keeps_real_zero_counts_and_stock_media_counts() {
        for status in [0, 0x64] {
            let state =
                pioneer_optical::rpc::State::parse(&[0, 6, 0, 0, status, 0xfd, 1, 0]).unwrap();
            let rows = reported_region_rows(state);
            assert_eq!(
                rows.iter().map(|r| r.key).collect::<Vec<_>>(),
                [
                    "rpc",
                    "region",
                    "user_changes",
                    "vendor_resets",
                    "region_state"
                ]
            );
        }
    }
}
