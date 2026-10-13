//! Every MT1959 and MT1939 build of the embedded OEM catalog through the real
//! engine, using only `oem.bin`: per build, a stand-in image with the build's
//! model, hardware record and factory contents (the catalog holds no code
//! bytes). A same-build reflash streams that image verbatim in the OEM
//! session; every pair of builds from different families is refused.

use super::*;
use fixture::{catalog_builds, stand_ins};
use mediatek_optical::update::{InstalledFirmware, PrepareError, PreparedUpdate};

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
