//! Embedded MediaTek OEM catalog (`oem.bin`): a gzip'd JSON table of every OEM
//! MT1959/MT1939 build in our hoard, keyed by [`mediatek_optical::oem::content_key`],
//! plus each chip generation's default factory contents.
//!
//! Built ONLY from OEM update images by `examples/mtk_oem_tables.rs`, which
//! admits a build only if it rebuilds byte-for-byte from a simulated drive read.
//! A recognized build backs up identical to the vendor file; an unknown one
//! gets its chip's defaults and is reported as a reconstruction.
//!
//! Loaded lazily and only when needed (a MediaTek backup), so the Pioneer path
//! and startup pay nothing.

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, OnceLock};

use mediatek_optical::oem::{Build, Catalog, Digest, Factory};
use mediatek_optical::Chip;
use serde::Deserialize;

const MTK_OEM: &[u8] = include_bytes!("oem.bin");

#[derive(Deserialize)]
struct RawFactory {
    boot: String,
    regions: [String; 4],
}

#[derive(Deserialize)]
struct RawBuild {
    key: String,
    model: String,
    revision: String,
    #[serde(flatten)]
    factory: RawFactory,
}

#[derive(Deserialize)]
struct RawTable {
    blobs: HashMap<String, String>,
    builds: Vec<RawBuild>,
    defaults: HashMap<String, RawFactory>,
}

/// The catalog. A malformed embedded table degrades to an empty catalog, so
/// every backup fails closed with "no factory contents" rather than guessing.
pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| parse(MTK_OEM).unwrap_or_default())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex: {e}")))
        .collect()
}

pub(crate) fn parse(gz: &[u8]) -> Result<Catalog, String> {
    let mut json = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut json)
        .map_err(|e| format!("oem.bin gunzip: {e}"))?;
    let raw: RawTable = serde_json::from_str(&json).map_err(|e| format!("oem.bin json: {e}"))?;
    let mut blobs: HashMap<String, Arc<[u8]>> = HashMap::with_capacity(raw.blobs.len());
    for (digest, bytes) in &raw.blobs {
        blobs.insert(digest.clone(), hex_decode(bytes)?.into());
    }
    let blob = |digest: &str| {
        blobs
            .get(digest)
            .cloned()
            .ok_or_else(|| format!("missing blob {digest}"))
    };
    let factory = |f: &RawFactory| -> Result<Factory, String> {
        let regions = [
            blob(&f.regions[0])?,
            blob(&f.regions[1])?,
            blob(&f.regions[2])?,
            blob(&f.regions[3])?,
        ];
        Factory::new(blob(&f.boot)?, regions).map_err(|e| e.to_string())
    };
    let mut catalog = Catalog::new();
    for b in &raw.builds {
        let key: Digest = hex_decode(&b.key)?
            .try_into()
            .map_err(|_| format!("bad key {}", b.key))?;
        catalog.insert(
            key,
            Build {
                model: b.model.clone(),
                revision: b.revision.clone(),
                factory: factory(&b.factory)?,
            },
        );
    }
    for (label, f) in &raw.defaults {
        let chip = match label.as_str() {
            "MT1959" => Chip::Mt1959,
            "MT1939" => Chip::Mt1939,
            other => return Err(format!("unknown chip {other}")),
        };
        catalog.set_default(chip, factory(f)?);
    }
    Ok(catalog)
}

#[cfg(test)]
#[path = "oem_tests.rs"]
mod tests;
