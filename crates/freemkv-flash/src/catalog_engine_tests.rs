//! Every MT1959 and MT1939 build of the embedded OEM catalog through the real
//! engine, using only `oem.bin`: per build, a stand-in image with the build's
//! model, hardware record and factory contents (the catalog holds no code
//! bytes). A same-build reflash streams that image verbatim in the OEM
//! session; every pair of builds from different families is refused.

use super::*;
use mediatek_optical::update::{InstalledFirmware, PrepareError, PreparedUpdate};

/// One catalog build, as `oem.bin` records it.
struct CatalogBuild {
    model: String,
    revision: String,
    family: String,
    hardware: String,
    boot: Vec<u8>,
    regions: Vec<Vec<u8>>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn catalog_builds() -> Vec<CatalogBuild> {
    use std::io::Read;
    let gz = include_bytes!("backends/mtk/oem.bin");
    let mut json = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut json)
        .unwrap();
    let table: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(table["family_scheme"], "mediatek.hardware.v1");
    let blob = |digest: &serde_json::Value| {
        unhex(table["blobs"][digest.as_str().unwrap()].as_str().unwrap())
    };
    table["builds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| CatalogBuild {
            model: b["model"].as_str().unwrap().into(),
            revision: b["revision"].as_str().unwrap().into(),
            family: b["family"].as_str().unwrap().into(),
            hardware: b["hardware"].as_str().unwrap().into(),
            boot: blob(&b["boot"]),
            regions: b["regions"].as_array().unwrap().iter().map(blob).collect(),
        })
        .collect()
}

/// The board a hardware key describes.
fn board(key: &str) -> fixture::Board {
    let field = |name: &str| {
        key.split('\x1f')
            .find_map(|f| f.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} in {key:?}"))
    };
    assert_eq!(field("iface"), "00000007", "{key:?}");
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let digits = &field("chip")[4..];
    fixture::Board {
        tag: leak(format!("MTEKMT19{digits}")),
        banner: leak(format!("MT19{digits} Boot {}", field("loader"))),
        platform: leak(field("platform").to_string()),
        medium: u8::from_str_radix(field("medium"), 16).unwrap(),
        bd_write: field("bdwrite") == "1",
    }
}

/// A signed image carrying `build`'s model, revision, hardware record and
/// factory contents.
fn stand_in(build: &CatalogBuild, seed: u8) -> Vec<u8> {
    let mut img = fixture::image(&board(&build.hardware), &build.model, seed);
    let d = ROM_1EC000_OFFSET as usize;
    img[d + 0x18..d + 0x1C].copy_from_slice(&format!("{:<4}", build.revision).as_bytes()[..4]);
    img[..0x400].copy_from_slice(&build.boot);
    for (range, contents) in mediatek_optical::layout::DRIVE_WRITTEN
        .iter()
        .zip(&build.regions)
    {
        img[range.start..range.end()].copy_from_slice(contents);
    }
    crate::cmac::resign(&img).unwrap()
}

fn stand_ins() -> Vec<(CatalogBuild, Vec<u8>)> {
    let builds = catalog_builds();
    assert_eq!(builds.len(), 69, "catalog size");
    builds
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            let image = stand_in(&b, i as u8);
            let family = mediatek_optical::image::family(&image).map(|f| f.to_string());
            assert_eq!(family.as_deref(), Some(b.family.as_str()), "{}", b.model);
            (b, image)
        })
        .collect()
}

#[test]
fn every_catalog_build_reflashes_verbatim_in_the_oem_session() {
    let dir = scratch("catalog-engine");
    let session: Vec<Vec<u8>> = mediatek_optical::DriveClass::Mt19
        .steps()
        .iter()
        .filter(|s| s.direction == mediatek_optical::update::Direction::Out)
        .map(|s| s.cdb.to_vec())
        .collect();
    for (i, (build, image)) in stand_ins().iter().enumerate() {
        let mut req = mtk_request(image.clone(), true, Some(dir.join(format!("{i}.bin"))));
        req.drive_model = build.model.clone();
        let mut dev = Rec::new(
            MockScsiDevice::echoing()
                .with_firmware_image(drive_read(image))
                .with_product(&build.model),
        );
        let outcome = run(|| engine_flash(&mut dev, &Mtk, &req));
        let label = format!("{} {} ({})", build.model, build.revision, build.family);
        assert_eq!(outcome.result, "OK", "{label}: {:#?}", outcome.text);
        let writes = &dev.inner.writes;
        let sent: Vec<Vec<u8>> = writes.iter().map(|(cdb, _)| cdb.clone()).collect();
        assert_eq!(sent, session, "{label}");
        let streamed: Vec<u8> = writes
            .iter()
            .filter(|(cdb, _)| cdb[1] == 0x06)
            .flat_map(|(_, data)| data.clone())
            .collect();
        assert!(streamed == *image, "{label}: not streamed verbatim");
    }
}

#[test]
fn every_cross_family_pair_of_catalog_builds_is_refused() {
    let builds = stand_ins();
    let installed: Vec<InstalledFirmware> = builds
        .iter()
        .map(|(_, image)| {
            InstalledFirmware::new(fixture::identity(image), &drive_read(image)).unwrap()
        })
        .collect();
    let (mut refused, mut allowed) = (0, 0);
    for (on, drive) in installed.iter().enumerate() {
        for (target, (build, image)) in builds.iter().enumerate() {
            let result = PreparedUpdate::prepare(image, drive);
            let same = builds[on].0.family == build.family;
            match (same, result) {
                (true, Ok(_)) => allowed += 1,
                (false, Err(PrepareError::FamilyMismatch { .. }))
                | (false, Err(PrepareError::ChipMismatch { .. })) => refused += 1,
                (_, other) => panic!(
                    "{} onto {}: {:?}",
                    build.model,
                    builds[on].0.model,
                    other.map(|p| p.family())
                ),
            }
            assert!(on != target || same);
        }
    }
    let n = builds.len();
    assert_eq!(refused + allowed, n * n);
    assert!(refused > 0 && allowed >= n);
}

/// Every catalog build as the real OEM image, from a corpus
/// (`FREEMKV_MTK_IMAGES`): a same-build reflash through the real engine streams
/// the image verbatim in the OEM session, and every catalog build is covered.
#[test]
#[ignore = "needs FREEMKV_MTK_IMAGES pointing at OEM MT1959/MT1939 images"]
fn every_catalog_build_reflashes_its_real_oem_image_verbatim() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let dir = std::env::var("FREEMKV_MTK_IMAGES").expect("FREEMKV_MTK_IMAGES");
    let mut paths = Vec::new();
    walk(Path::new(&dir), &mut paths);
    paths.sort();
    let catalog = crate::backends::mtk::oem::catalog();
    let session: Vec<Vec<u8>> = mediatek_optical::DriveClass::Mt19
        .steps()
        .iter()
        .filter(|s| s.direction == mediatek_optical::update::Direction::Out)
        .map(|s| s.cdb.to_vec())
        .collect();
    let recorded = catalog_builds();
    let scratch_dir = scratch("catalog-real");
    let mut covered = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let image = std::fs::read(path).unwrap();
        if image.len() != IMAGE_SIZE || mediatek_optical::image::is_drive_read(&image) {
            continue;
        }
        let Some(key) = mediatek_optical::oem::content_key(&image) else {
            continue;
        };
        let Some(build) = catalog.build(&key) else {
            continue;
        };
        let model = build.model.clone();
        let family = mediatek_optical::image::family(&image).map(|f| f.to_string());
        assert!(
            recorded.iter().any(|b| b.model == model
                && b.revision == build.revision
                && Some(&b.family) == family.as_ref()),
            "{}: family {family:?} is not the one the catalog records",
            path.display()
        );
        let mut req = mtk_request(
            image.clone(),
            true,
            Some(scratch_dir.join(format!("{i}.bin"))),
        );
        req.drive_model = model.clone();
        let mut dev = Rec::new(
            MockScsiDevice::echoing()
                .with_firmware_image(drive_read(&image))
                .with_product(&model),
        );
        let outcome = run(|| engine_flash(&mut dev, &Mtk, &req));
        let label = path.display();
        assert_eq!(outcome.result, "OK", "{label}: {:#?}", outcome.text);
        let writes = &dev.inner.writes;
        let sent: Vec<Vec<u8>> = writes.iter().map(|(cdb, _)| cdb.clone()).collect();
        assert_eq!(sent, session, "{label}");
        let streamed: Vec<u8> = writes
            .iter()
            .filter(|(cdb, _)| cdb[1] == 0x06)
            .flat_map(|(_, data)| data.clone())
            .collect();
        assert!(streamed == image, "{label}: not streamed verbatim");
        if !covered.contains(&key) {
            covered.push(key);
        }
    }
    assert_eq!(
        covered.len(),
        catalog_builds().len(),
        "catalog builds covered"
    );
}
