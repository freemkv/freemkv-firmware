//! One bounded read-only protocol discovery, independent of presentation names.
use super::{decode_identity, Identity, ReadDevice};
use crate::platform::{sense_triplet, ScsiDevice};
use anyhow::{Context, Result};

/// Validated protocol evidence. Neither variant grants a firmware writer.
#[derive(Clone, Debug)]
pub enum Evidence {
    /// Pioneer F1 structure and parsed identity.
    Pioneer(pioneer_optical::protocol::Evidence),
    /// MediaTek boot signature and parsed identity.
    Mediatek(Box<mediatek_optical::protocol::Evidence>),
}
/// Complete discovery conclusion; transport failures remain errors.
#[derive(Clone, Debug)]
pub enum Conclusion {
    /// Exactly one protocol signature matched.
    Detected(Evidence),
    /// No supported signature matched the readable responses.
    Unknown,
    /// Both protocol signatures matched. No backend may be selected.
    Ambiguous,
}
/// A session-local observation. Never cache across update/reset/reconnect.
#[derive(Clone, Debug)]
pub struct Detection {
    /// Display identity from the same INQUIRY used to validate the probes.
    pub identity: Identity,
    /// Independent protocol decision.
    pub conclusion: Conclusion,
    /// Per-command evidence retained for diagnostics.
    pub observations: Vec<String>,
    pub(crate) pioneer_identity: Option<pioneer_optical::Identity>,
}
/// An identification command could not complete; distinct from unsupported.
#[derive(Debug)]
pub struct Unavailable {
    /// Identification operation that failed.
    pub command: &'static str,
    /// Original transport failure.
    pub source: anyhow::Error,
}
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Drive protocol detection unavailable during {}: {}",
            self.command, self.source
        )
    }
}
impl std::error::Error for Unavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}
fn read(
    dev: &mut ReadDevice<'_>,
    name: &'static str,
    cdb: &[u8],
    len: usize,
    notes: &mut Vec<String>,
) -> Result<Option<Vec<u8>>> {
    match dev.diagnostic_in(cdb, len, 5000) {
        Ok(bytes) => {
            notes.push(format!("{name}: {} bytes returned", bytes.len()));
            Ok(Some(bytes))
        }
        Err(error) if matches!(sense_triplet(&error), Some((5, 0x20 | 0x24, 0))) => {
            notes.push(format!("{name}: command rejected ({error:#})"));
            Ok(None)
        }
        Err(source) => Err(Unavailable {
            command: name,
            source,
        }
        .into()),
    }
}
/// Read only INQUIRY, Pioneer F1 identity and the MediaTek 32-byte boot banner.
/// No unlock, update-entry or diagnostic-control commands are issued.
/// GET CONFIGURATION metadata is read by Info, not used as a protocol gate.
pub fn detect(dev: &mut dyn ScsiDevice) -> Result<Detection> {
    let mut dev = ReadDevice::without_unlocks(dev);
    let mut observations = Vec::new();
    let inquiry = read(
        &mut dev,
        "INQUIRY",
        &pioneer_optical::cdb::inquiry(96),
        96,
        &mut observations,
    )?
    .context("INQUIRY was rejected; drive protocol cannot be determined")?;
    anyhow::ensure!(
        inquiry.len() >= 36,
        "Incomplete INQUIRY: {} bytes; at least 36 required",
        inquiry.len()
    );
    let identity = decode_identity(&inquiry)?;
    let mut result = Detection {
        identity,
        conclusion: Conclusion::Unknown,
        observations,
        pioneer_identity: None,
    };
    if inquiry[0] & 0x1f != 5 {
        result
            .observations
            .push("INQUIRY: not an optical device".into());
        return Ok(result);
    }
    let pioneer = read(
        &mut dev,
        "Pioneer F1 identity",
        &pioneer_optical::cdb::vendor_identity(),
        48,
        &mut result.observations,
    )?
    .and_then(|b| {
        result.pioneer_identity = pioneer_optical::Identity::parse(&inquiry, &b);
        match pioneer_optical::protocol::Evidence::parse(&inquiry, &b) {
            Ok(e) => e,
            Err(_) => {
                result
                    .observations
                    .push("Pioneer F1 identity: incomplete structure".into());
                None
            }
        }
    });
    let mediatek = read(
        &mut dev,
        "MediaTek boot banner",
        &mediatek_optical::cdb::read_memory(0x3000, 32),
        32,
        &mut result.observations,
    )?
    .and_then(
        |b| match mediatek_optical::protocol::Evidence::parse(&inquiry, &b) {
            Ok(e) => e,
            Err(_) => {
                result
                    .observations
                    .push("MediaTek boot banner: incomplete structure".into());
                None
            }
        },
    );
    result.conclusion = match (pioneer, mediatek) {
        (Some(_), Some(_)) => Conclusion::Ambiguous,
        (Some(p), None) => Conclusion::Detected(Evidence::Pioneer(p)),
        (None, Some(m)) => {
            result.identity.banner = Some(m.identity().banner().into());
            Conclusion::Detected(Evidence::Mediatek(Box::new(m)))
        }
        (None, None) => Conclusion::Unknown,
    };
    crate::diagnostics::record(format!(
        "Protocol detection: {:?}; {:?}",
        result.conclusion, result.observations
    ));
    Ok(result)
}
