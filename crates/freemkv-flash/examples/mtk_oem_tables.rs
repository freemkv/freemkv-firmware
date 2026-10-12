//! Build the MediaTek OEM backup catalog (`src/backends/mtk/oem.bin`) from a
//! directory of MT1959/MT1939 update images.
//! Usage: cargo run -p freemkv-flash --example mtk_oem_tables -- <images> <output> [sources.json]
//! No device I/O; images are read as data. Drive reads and images whose chip
//! cannot be named are skipped. Only OEM builds are admitted: see `exclusion`.
//! A content key shared by builds with different factory contents is left
//! out. Every admitted build must rebuild byte-for-byte from a simulated
//! drive read and have a hardware family.
use anyhow::{bail, Context, Result};
use flate2::{write::GzEncoder, Compression};
use mediatek_optical::{
    image::{cmac, detect_chip, family, hardware, is_drive_read, FAMILY_SCHEME},
    layout,
    oem::{self, Build, Catalog, Factory},
    Chip,
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Write,
    path::{Path, PathBuf},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            files(&entry.path(), out)?;
        } else if ty.is_file() && entry.metadata()?.len() == layout::IMAGE_SIZE as u64 {
            out.push(entry.path());
        }
    }
    Ok(())
}

/// What a drive returns once `image` is flashed and has written per-unit data.
fn simulated_read(image: &[u8]) -> Vec<u8> {
    let mut read = image.to_vec();
    let mirror = read[layout::BOOT_MIRROR.start..layout::BOOT_MIRROR.end()].to_vec();
    read[..layout::BOOT_PAGE.len].copy_from_slice(&mirror);
    for range in layout::DRIVE_WRITTEN {
        let region = &mut read[range.start..range.end()];
        if !layout::is_erased(region) {
            region[..32].fill(0x52);
        }
    }
    read
}

/// Where the hoard says an image came from: its sidecar's `patched` flag and
/// the names and paths of its source files.
#[derive(Default)]
struct Provenance {
    patched: bool,
    names: Vec<String>,
}

/// Read `<image>.json` (the hoard's sidecar) and, when given, the hoard's
/// source index for the names its sources were found under.
fn provenance(path: &Path, index: &HashMap<String, Vec<String>>) -> Result<Provenance> {
    let sidecar = PathBuf::from(format!("{}.json", path.display()));
    if !sidecar.exists() {
        return Ok(Provenance::default());
    }
    let meta: Value = serde_json::from_slice(&std::fs::read(&sidecar)?)?;
    let mut names = Vec::new();
    for source in meta["sources"].as_array().into_iter().flatten() {
        if let Some(name) = source["candidate"].as_str() {
            names.push(name.to_string());
        }
        if let Some(sha) = source["source_sha256"].as_str() {
            names.extend(index.get(sha).cloned().unwrap_or_default());
        }
    }
    Ok(Provenance {
        patched: meta["mediatek"]["patched"].as_bool() == Some(true),
        names,
    })
}

/// Source-name markers of a modified or community build: downgrade-enabled
/// (`DE_`), MakeMKV-patched or un-patched (`MK`, `unMK_`), OmniDrive, and
/// drive dumps.
const MODIFIED: &[&str] = &[
    "DE_",
    "DE-firmware",
    "Downgrade Enabled",
    "unMK",
    "MK Firmware",
    "MK_edited",
    "OmniDrive",
    "-dump",
    "dump_full",
];

/// The descriptor's downgrade-enable byte: freemkv-fw and community
/// "DE" builds set it to `0xDE` without re-signing, as it is outside every
/// integrity range.
const DE_BYTE: usize = layout::DESCRIPTOR.start + 0x56;

/// Why an image is not an OEM build, or `None` for an OEM build.
fn exclusion(image: &[u8], prov: &Provenance) -> Option<String> {
    if !cmac::verify(image) {
        return Some("integrity table fails (modified or damaged)".into());
    }
    if image.windows(7).any(|w| w == b"freemkv") {
        return Some("a freemkv-fw build (carries its identity magic)".into());
    }
    if prov.patched {
        return Some("patched (hoard sidecar: mediatek.patched)".into());
    }
    for name in &prov.names {
        let file = name.rsplit('/').next().unwrap_or(name);
        for marker in MODIFIED {
            let hit = if *marker == "DE_" {
                file.starts_with("DE_") || name.contains("/DE_")
            } else {
                name.contains(marker)
            };
            if hit {
                return Some(format!("community or modified source ({marker}: {name})"));
            }
        }
    }
    // An update image carries the factory calibration template: the
    // `VENDOR_INFO` header and nothing else. More is one unit's calibration.
    let calibration = layout::CALIBRATION.of(image)?;
    if !layout::is_erased(&calibration[16..]) {
        return Some("carries a unit's calibration (a drive dump)".into());
    }
    if hardware(image).is_none() {
        return Some("no hardware family".into());
    }
    None
}

/// Bytes an update writes and a drive keeps, apart from the DE byte.
fn without_de_byte(image: &[u8]) -> Vec<u8> {
    let mut out = image.to_vec();
    out[DE_BYTE] = 0;
    out[..layout::BOOT_PAGE.len].fill(0);
    for range in layout::DRIVE_WRITTEN {
        out[range.start..range.end()].fill(0);
    }
    out
}

struct Candidate {
    path: PathBuf,
    sha: String,
    chip: Chip,
    model: String,
    revision: String,
    factory: Factory,
    family: String,
    hardware: String,
}

/// The most common value; ties go to the smallest digest, for determinism.
fn mode(values: impl Iterator<Item = String>) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for v in values {
        *counts.entry(v).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
        .map(|(v, _)| v)
        .unwrap_or_default()
}

/// Source sha256 → the names and paths the hoard's index records for it.
fn source_index(path: Option<&String>) -> Result<HashMap<String, Vec<String>>> {
    let mut out = HashMap::new();
    let Some(path) = path else {
        return Ok(out);
    };
    let index: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    for source in index["sources"].as_array().context("sources")? {
        let mut names = Vec::new();
        for field in ["names", "inbound_paths"] {
            for name in source[field].as_array().into_iter().flatten() {
                names.extend(name.as_str().map(str::to_string));
            }
        }
        if let Some(sha) = source["sha256"].as_str() {
            out.insert(sha.to_string(), names);
        }
    }
    Ok(out)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if !(3..=4).contains(&args.len()) {
        bail!("usage: mtk_oem_tables <images-dir> <output.bin> [hoard sources.json]");
    }
    let index = source_index(args.get(3))?;
    let mut paths = Vec::new();
    files(Path::new(&args[1]), &mut paths)?;
    paths.sort();

    let mut admitted: Vec<Candidate> = Vec::new();
    let mut excluded: BTreeMap<String, (String, String)> = BTreeMap::new();
    let (mut reads, mut unnamed) = (0, 0);
    let mut seen = BTreeSet::new();
    for path in paths {
        let image = std::fs::read(&path)?;
        let sha = hex(&oem::sha256(&image));
        if !seen.insert(sha.clone()) {
            continue;
        }
        if is_drive_read(&image) {
            reads += 1;
            continue;
        }
        let Ok(info) = detect_chip(&image) else {
            unnamed += 1;
            continue;
        };
        let label = format!("{} {}", info.model, info.rev);
        if let Some(why) = exclusion(&image, &provenance(&path, &index)?) {
            excluded.insert(sha, (label, why));
            continue;
        }
        let hw = hardware(&image).expect("checked by exclusion");
        admitted.push(Candidate {
            path,
            sha,
            chip: info.family,
            model: info.model,
            revision: info.rev,
            factory: Factory::from_image(&image)?,
            family: hw.family().to_string(),
            hardware: hw.key(),
        });
    }

    // A build equal to another admitted one except for a 0xDE downgrade byte
    // is that build DE-patched.
    let mut originals: HashMap<Vec<u8>, Vec<String>> = HashMap::new();
    for c in &admitted {
        let image = std::fs::read(&c.path)?;
        if image[DE_BYTE] != 0xDE {
            originals
                .entry(without_de_byte(&image))
                .or_default()
                .push(c.sha.clone());
        }
    }
    let mut kept = Vec::new();
    for c in admitted {
        let image = std::fs::read(&c.path)?;
        let original = (image[DE_BYTE] == 0xDE)
            .then(|| originals.get(&without_de_byte(&image)))
            .flatten();
        match original {
            Some(of) => {
                let why = format!("DE-patched copy of {}", &of[0][..16]);
                excluded.insert(c.sha.clone(), (format!("{} {}", c.model, c.revision), why));
            }
            None => kept.push(c),
        }
    }

    let mut by_key: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
    for c in kept {
        let image = std::fs::read(&c.path)?;
        let key = hex(&oem::content_key(&image).context("content key")?);
        by_key.entry(key).or_default().push(c);
    }

    let mut blobs: BTreeMap<String, String> = BTreeMap::new();
    let mut blob = |bytes: &[u8]| -> String {
        let digest = hex(&oem::sha256(bytes));
        blobs.entry(digest.clone()).or_insert_with(|| hex(bytes));
        digest
    };
    let factory_json = |f: &Factory, blob: &mut dyn FnMut(&[u8]) -> String| -> Value {
        json!({
            "boot": blob(f.boot_page()),
            "regions": f.regions().iter().map(|r| blob(r)).collect::<Vec<_>>(),
        })
    };

    let mut builds = Vec::new();
    let mut ambiguous = 0;
    let mut catalog = Catalog::new();
    let mut per_chip: HashMap<Chip, Vec<&Candidate>> = HashMap::new();
    for (key, candidates) in &by_key {
        for c in candidates {
            per_chip.entry(c.chip).or_default().push(c);
        }
        let first = &candidates[0];
        if candidates
            .iter()
            .any(|c| c.factory != first.factory || c.chip != first.chip)
        {
            ambiguous += 1;
            continue;
        }
        let mut digest = [0u8; 32];
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&key[2 * i..2 * i + 2], 16)?;
        }
        catalog.insert(
            digest,
            Build {
                model: first.model.clone(),
                revision: first.revision.clone(),
                factory: first.factory.clone(),
            },
        );
        let mut entry = factory_json(&first.factory, &mut blob);
        entry["key"] = json!(key);
        entry["model"] = json!(first.model);
        entry["revision"] = json!(first.revision);
        entry["chip"] = json!(first.chip.label());
        entry["family"] = json!(first.family);
        entry["hardware"] = json!(first.hardware);
        builds.push(entry);
    }

    // Each chip's default takes the most common boot page and, per region, the
    // most common written (non-erased) contents: rebuild keeps an erased read
    // region erased, so the default only ever replaces a written one.
    let mut defaults = Map::new();
    let mut chips: Vec<_> = per_chip.keys().copied().collect();
    chips.sort();
    for chip in chips {
        let members = &per_chip[&chip];
        let boot = mode(members.iter().map(|c| hex(c.factory.boot_page())));
        let regions: Vec<String> = (0..4)
            .map(|i| {
                let written = members
                    .iter()
                    .map(|c| &c.factory.regions()[i])
                    .filter(|r| !layout::is_erased(r));
                let best = mode(written.map(|r| hex(r)));
                if best.is_empty() {
                    hex(&vec![0xFF; layout::DRIVE_WRITTEN[i].len])
                } else {
                    best
                }
            })
            .collect();
        let decode = |h: &str| -> Vec<u8> {
            (0..h.len() / 2)
                .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
                .collect()
        };
        // Every build of this chip must store the default's boot page: rebuild
        // gives an unknown build the default page, so a second page in the
        // corpus would make that substitution unsafe.
        if let Some(odd) = members.iter().find(|c| hex(c.factory.boot_page()) != boot) {
            bail!(
                "{} stores a different boot page from the {chip} default; a chip-default \
                 rebuild would be unsafe",
                odd.path.display()
            );
        }
        let factory = Factory::new(
            decode(&boot).into(),
            [0, 1, 2, 3].map(|i| decode(&regions[i]).into()),
        )?;
        catalog.set_default(chip, factory.clone());
        defaults.insert(chip.label().into(), factory_json(&factory, &mut blob));
    }

    // Admission check: every cataloged build rebuilds exactly from a drive
    // read, and its family survives the read.
    let mut checked = 0;
    for candidates in by_key.values() {
        let c = &candidates[0];
        let image = std::fs::read(&c.path)?;
        let read = simulated_read(&image);
        let rebuilt = oem::rebuild(&read, &catalog)
            .with_context(|| format!("rebuilding {}", c.path.display()))?;
        let exact = rebuilt.provenance.is_exact();
        if exact && rebuilt.image != image {
            bail!("{} does not rebuild byte-exact", c.path.display());
        }
        if family(&read).map(|f| f.to_string()).as_deref() != Some(c.family.as_str()) {
            bail!("{} changes family under a drive read", c.path.display());
        }
        checked += exact as usize;
    }

    for (sha, (label, why)) in &excluded {
        println!("excluded {} {label:<24} {why}", &sha[..16]);
    }
    let table = json!({
        "family_scheme": FAMILY_SCHEME,
        "blobs": blobs,
        "builds": builds,
        "defaults": defaults,
    });
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&serde_json::to_vec(&table)?)?;
    let bytes = encoder.finish()?;
    std::fs::write(&args[2], &bytes)?;
    println!(
        "{} builds ({checked} verified byte-exact), {} excluded, {ambiguous} ambiguous keys, \
         {} blobs, defaults for {:?}; skipped {reads} drive reads, {unnamed} unnamed; {} bytes",
        builds.len(),
        excluded.len(),
        blobs.len(),
        defaults.keys().collect::<Vec<_>>(),
        bytes.len()
    );
    Ok(())
}
