//! Build the MediaTek OEM backup catalog (`src/drive/mtk/oem.bin`) from a
//! directory of OEM MT1959/MT1939 update images.
//! Usage: cargo run -p freemkv-flash --example mtk_oem_tables -- <images> <output>
//! No device I/O. Drive reads and images whose chip cannot be named are
//! skipped. A content key shared by builds with different factory contents is
//! ambiguous and left out, so those builds fall back to the chip default. Every
//! admitted build must rebuild byte-for-byte from a simulated drive read.
use anyhow::{bail, Context, Result};
use flate2::{write::GzEncoder, Compression};
use mediatek_optical::{
    image::{detect_chip, is_drive_read},
    layout,
    oem::{self, Build, Catalog, Factory},
    Chip,
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, HashMap},
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

struct Candidate {
    path: PathBuf,
    chip: Chip,
    model: String,
    revision: String,
    factory: Factory,
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

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("usage: mtk_oem_tables <images-dir> <output.bin>");
    }
    let mut paths = Vec::new();
    files(Path::new(&args[1]), &mut paths)?;
    paths.sort();

    let mut by_key: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
    let (mut reads, mut unnamed) = (0, 0);
    for path in paths {
        let image = std::fs::read(&path)?;
        if is_drive_read(&image) {
            reads += 1;
            continue;
        }
        let Ok(info) = detect_chip(&image) else {
            unnamed += 1;
            continue;
        };
        let key = hex(&oem::content_key(&image).context("content key")?);
        by_key.entry(key).or_default().push(Candidate {
            path,
            chip: info.family,
            model: info.model,
            revision: info.rev,
            factory: Factory::from_image(&image)?,
        });
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

    // Admission check: every cataloged build rebuilds exactly from a drive read.
    let mut checked = 0;
    for candidates in by_key.values() {
        let c = &candidates[0];
        let image = std::fs::read(&c.path)?;
        let rebuilt = oem::rebuild(&simulated_read(&image), &catalog)
            .with_context(|| format!("rebuilding {}", c.path.display()))?;
        let exact = rebuilt.provenance.is_exact();
        if exact && rebuilt.image != image {
            bail!("{} does not rebuild byte-exact", c.path.display());
        }
        checked += exact as usize;
    }

    let table = json!({ "blobs": blobs, "builds": builds, "defaults": defaults });
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&serde_json::to_vec(&table)?)?;
    let bytes = encoder.finish()?;
    std::fs::write(&args[2], &bytes)?;
    println!(
        "{} builds ({checked} verified byte-exact), {ambiguous} ambiguous keys, {} blobs, \
         defaults for {:?}; skipped {reads} drive reads, {unnamed} unnamed; {} bytes",
        builds.len(),
        blobs.len(),
        defaults.keys().collect::<Vec<_>>(),
        bytes.len()
    );
    Ok(())
}
