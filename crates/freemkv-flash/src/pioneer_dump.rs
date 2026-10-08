//! One-file diagnostic capture: address-aligned memory, responses, directory and footer.

use crate::platform::{sense_triplet, ScsiDevice};
use anyhow::{ensure, Context, Result};
use pioneer_optical::diagnostic::{self, ReadSurface};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Start of diagnostic responses after the fixed memory regions.
pub const RESPONSES: usize = 0x1010000;
const MAGIC: &[u8; 8] = b"FMVKDMP1";
const FOOTER: usize = 64;

#[derive(Serialize)]
struct Read {
    order: usize,
    cdb: String,
    file_offset: usize,
    requested: usize,
    received: usize,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sense: Option<(u8, u8, u8)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
#[derive(Serialize)]
struct Section {
    name: String,
    namespace: &'static str,
    source_address: Option<u32>,
    file_offset: usize,
    length: usize,
    sha256: String,
}
#[derive(Serialize)]
struct Directory {
    format_version: u32,
    tool_version: &'static str,
    started_unix: u64,
    device: String,
    complete: bool,
    logging: String,
    sections: Vec<Section>,
    reads: Vec<Read>,
    notes: Vec<String>,
}
struct Capture {
    bytes: Vec<u8>,
    directory: Directory,
    stopped: bool,
}
impl Capture {
    fn read(&mut self, dev: &mut dyn ScsiDevice, cdb: &[u8], dest: usize, len: usize) {
        self.bytes.resize(self.bytes.len().max(dest + len), 0);
        if self.stopped {
            return;
        }
        let mut record = Read {
            order: self.directory.reads.len(),
            cdb: hex(cdb),
            file_offset: dest,
            requested: len,
            received: 0,
            status: "captured",
            sense: None,
            error: None,
        };
        match dev.command_in(cdb, len) {
            Ok(b) => {
                let n = b.len().min(len);
                self.bytes[dest..dest + n].copy_from_slice(&b[..n]);
                record.received = b.len();
                if b.len() != len {
                    record.status = if b.len() < len { "short" } else { "overlong" };
                    self.directory.complete = false;
                }
            }
            Err(e) => {
                record.sense = sense_triplet(&e);
                record.error = Some(format!("{e:#}"));
                if record.sense == Some((5, 0x24, 0)) {
                    record.status = "unavailable";
                } else {
                    record.status = "failed";
                    self.directory.complete = false;
                    // A transport failure may be a disconnect. Preserve what was
                    // read and leave subsequent ranges explicitly unattempted.
                    self.stopped = record.sense.is_none();
                }
            }
        }
        self.directory.reads.push(record);
    }
    fn section(
        &mut self,
        name: &str,
        space: &'static str,
        address: Option<u32>,
        off: usize,
        len: usize,
    ) {
        self.directory.sections.push(Section {
            name: name.into(),
            namespace: space,
            source_address: address,
            file_offset: off,
            length: len,
            sha256: hex(&Sha256::digest(&self.bytes[off..off + len])),
        });
    }
    fn region(
        &mut self,
        dev: &mut dyn ScsiDevice,
        surface: ReadSurface,
        off: usize,
        space: &'static str,
        address: u32,
    ) -> Result<()> {
        for delta in (0..surface.length).step_by(surface.chunk) {
            if self.stopped {
                break;
            }
            let n = surface.chunk.min(surface.length - delta);
            let cdb = surface
                .read_cdb(delta, n)
                .context("invalid diagnostic read definition")?;
            self.read(dev, &cdb, off + delta, n);
        }
        self.section(surface.name, space, Some(address), off, surface.length);
        Ok(())
    }
    fn response(&mut self, dev: &mut dyn ScsiDevice, surface: ReadSurface) -> Result<()> {
        let off = self.bytes.len();
        let cdb = surface
            .read_cdb(0, surface.length)
            .context("invalid diagnostic response definition")?;
        self.read(dev, &cdb, off, surface.length);
        self.section(
            surface.name,
            "response",
            Some(surface.offset),
            off,
            surface.length,
        );
        Ok(())
    }
    fn finish(mut self) -> Result<Vec<u8>> {
        let offset = self.bytes.len() as u64;
        let directory = serde_json::to_vec(&self.directory)?;
        self.bytes.extend_from_slice(&directory);
        self.bytes.extend_from_slice(MAGIC);
        self.bytes.extend_from_slice(&1u32.to_le_bytes());
        self.bytes.extend_from_slice(&(FOOTER as u32).to_le_bytes());
        self.bytes.extend_from_slice(&offset.to_le_bytes());
        self.bytes
            .extend_from_slice(&(directory.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(&Sha256::digest(&directory));
        Ok(self.bytes)
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// Capture mapped Pioneer read surfaces. Unavailable reads are zero-filled and
/// recorded. Logging is enabled last, only when firmware discovery succeeds.
pub fn capture(dev: &mut dyn ScsiDevice) -> Result<Vec<u8>> {
    let mut c = Capture { bytes: vec![0; RESPONSES], stopped: false, directory: Directory {
        format_version: 1, tool_version: env!("CARGO_PKG_VERSION"),
        started_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        device: dev.describe(), complete: true, logging: "skipped: not attempted".into(),
        sections: vec![], reads: vec![], notes: vec![
            "Uncovered bytes are unattempted zero fill, not observed drive zeros. Read records define coverage.".into(),
            "Sequential capture, not an atomic snapshot. FC response is preserved in returned ring order.".into(),
            "CPU 0x880000..0xbfffff is unmapped here; controller 93 is a separate address space.".into(),
            "Selectors 80, EB, EC, EE, E2, E3, E8, E9, F8, F4 and A5 are not captured: semantics or side effects are not sufficiently established.".into(),
        ] } };
    // Preserve history before any bulk memory reads, including on the second dump.
    c.response(dev, diagnostic::LOG)?;
    let id_off = c.bytes.len();
    c.read(dev, &pioneer_optical::cdb::inquiry(96), id_off, 96);
    c.section("inquiry", "response", None, id_off, 96);
    if !c.stopped {
        if let Err(e) = dev.command_out(&pioneer_optical::cdb::knock(), &[]) {
            if sense_triplet(&e).is_none() {
                c.stopped = true;
                c.directory.complete = false;
            }
            c.directory.notes.push(format!(
                "Extended read enable failed: {e:#}; transport failures stop capture"
            ));
        }
    }
    crate::output::field("Dump", "capturing high registers and CPU memory");
    c.region(dev, diagnostic::CPU_HIGH, 0xc00000, "cpu", 0xffffe000)?;
    c.region(dev, diagnostic::CPU_ALIAS, 0xc02000, "cpu", 0xff414000)?;
    c.region(dev, diagnostic::CPU_LOW, 0, "cpu", 0)?;
    crate::output::field(
        "Dump",
        "capturing controller memory and diagnostic responses",
    );
    c.region(dev, diagnostic::CONTROLLER, 0xc10000, "controller_93", 0)?;
    for &surface in diagnostic::RESPONSES {
        c.response(dev, surface)?;
    }
    if !c.stopped {
        c.directory.logging = match pioneer_optical::logging::discover(
            &c.bytes[..diagnostic::CPU_LOW.length],
        ) {
            None => {
                "skipped: temporary logging capability not found unambiguously in captured firmware"
                    .into()
            }
            Some(layout) => {
                use crate::drive::pioneer_transport::{ScsiTransport, SharedDevice};
                let shared = SharedDevice::new(dev);
                match pioneer_optical::logging::set_logging_ram(
                    &mut ScsiTransport::flash(&shared),
                    layout,
                    true,
                ) {
                    Ok(()) => format!(
                        "enabled in RAM; mask address {:#x}, group {:#x}, bit {:#x}",
                        layout.mask_address(),
                        layout.group(),
                        layout.bit()
                    ),
                    Err(e) => format!("skipped: {e}; current state not verified"),
                }
            }
        };
    }
    crate::output::field("Drive logging", &c.directory.logging);
    if !c.directory.complete {
        crate::output::field("Dump", "partial capture; failures recorded in directory");
    }
    c.finish()
}

/// Validate the footer/directory checksum and return the capture directory.
/// Legacy raw images without this format's magic return `None`.
pub fn directory(bytes: &[u8]) -> Result<Option<serde_json::Value>> {
    if bytes.len() < FOOTER {
        return Ok(None);
    }
    let start = bytes.len() - FOOTER;
    let f = &bytes[start..];
    if &f[..8] != MAGIC {
        return Ok(None);
    }
    ensure!(
        u32::from_le_bytes(f[8..12].try_into()?) == 1,
        "unsupported dump version"
    );
    ensure!(
        u32::from_le_bytes(f[12..16].try_into()?) == FOOTER as u32,
        "invalid footer size"
    );
    let off = usize::try_from(u64::from_le_bytes(f[16..24].try_into()?))?;
    let len = usize::try_from(u64::from_le_bytes(f[24..32].try_into()?))?;
    ensure!(
        off >= RESPONSES && off.checked_add(len) == Some(start),
        "invalid directory bounds"
    );
    let raw = bytes.get(off..start).context("directory outside dump")?;
    ensure!(
        Sha256::digest(raw)[..] == f[32..64],
        "directory checksum mismatch"
    );
    Ok(Some(serde_json::from_slice(raw)?))
}

#[cfg(test)]
#[path = "pioneer_dump_tests.rs"]
mod tests;
