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

// ---- the same-hardware-family crossflash gate ----------------------------------

use crate::backends::mtk::crossflash::tests::{self as gate};
use crate::backends::mtk::crossflash::{decide_model, Build, Verdict};

/// A drive running `image` and reporting `product`, as a full read shows it.
fn drive_running(image: &[u8], product: &str) -> Rec<MockScsiDevice> {
    assert_eq!(Build::of_image(image).unwrap().product, product);
    // INQUIRY follows the installed descriptor, including the new product after
    // a successful crossflash. Explicit overrides are reserved for stale-startup tests.
    Rec::new(MockScsiDevice::echoing().with_firmware_image(drive_read(image)))
}

/// Flash `image` onto a drive running `drive`, backing up to `backup`; without
/// one, a dry run.
fn flash_onto(
    drive: &[u8],
    product: &str,
    image: &[u8],
    backup: Option<PathBuf>,
) -> (Outcome, Rec<MockScsiDevice>) {
    let mut req = mtk_request(image.to_vec(), backup.is_some(), backup);
    req.drive_model = product.into();
    let mut dev = drive_running(drive, product);
    let outcome = run(|| engine_flash(&mut dev, &Mtk, &req));
    (outcome, dev)
}

/// The dry-run plan of `image` onto a drive running `drive`.
fn preview(drive: &[u8], product: &str, image: &[u8]) -> Result<Vec<String>> {
    let mut req = mtk_request(image.to_vec(), false, None);
    req.drive_model = product.into();
    crate::engine::preview_flash(&mut drive_running(drive, product), &Mtk, &req)
}

fn streamed(dev: &Rec<MockScsiDevice>) -> Vec<u8> {
    dev.inner
        .writes
        .iter()
        .filter(|(cdb, _)| cdb[1] == 0x06)
        .flat_map(|(_, data)| data.clone())
        .collect()
}

fn is_descriptor_read(cdb: &[u8]) -> bool {
    cdb.first() == Some(&0x3C) && cdb.get(3..6) == Some(&[0x1E, 0xC0, 0x00][..])
}

/// A same-family crossflash of `image` onto a drive running `drive` through the
/// engine: the dry-run names it, and the execute streams the image verbatim and
/// confirms the drive's new identity.
fn assert_crossflash(drive: &[u8], image: &[u8], dir: &Path, tag: &str) {
    let (from, to) = (
        Build::of_image(drive).unwrap(),
        Build::of_image(image).unwrap(),
    );
    let plan = preview(drive, &from.product, image).unwrap().join("\n");
    for line in [
        format!("CROSSFLASH: {} \u{2192} {}", from.label(), to.label()),
        format!("the drive will identify as {} after the flash", to.model()),
        format!(
            "your backup restores {} under the same family gate",
            from.label()
        ),
    ] {
        assert!(plan.contains(&line), "{tag}: {line:?} not in\n{plan}");
    }
    assert!(plan.contains("same hardware family"), "{tag}:\n{plan}");
    let backup = Some(dir.join(format!("{tag}.bin")));
    let (outcome, dev) = flash_onto(drive, &from.product, image, backup);
    assert_eq!(outcome.result, "OK", "{tag}: {:#?}", outcome.text);
    assert!(streamed(&dev) == image, "{tag}: not streamed verbatim");
}

/// A same-chip, different-family flash is refused at the dry run with the
/// family message, before any backup or write.
fn assert_cross_family_refused(drive: &[u8], image: &[u8], tag: &str) {
    let product = Build::of_image(drive).unwrap().product;
    let err = format!(
        "{:#}",
        preview(drive, &product, image).expect_err("refused")
    );
    assert!(err.contains("different hardware family"), "{tag}: {err}");
    assert_flash_refused(drive, image, tag);
}

/// Both preview and requested execution refuse the image and write nothing.
fn assert_flash_refused(drive: &[u8], image: &[u8], tag: &str) {
    let product = Build::of_image(drive).unwrap().product;
    assert!(preview(drive, &product, image).is_err(), "{tag}: admitted");
    let dir = scratch(&format!("refused-{tag}"));
    let backup = dir.join("rollback.bin");
    let (outcome, dev) = flash_onto(drive, &product, image, Some(backup.clone()));
    assert!(!backup.exists(), "{tag}: refusal precedes backup capture");
    assert_ne!(outcome.result, "OK", "{tag}: {:#?}", outcome.text);
    assert!(streamed(&dev).is_empty(), "{tag}: wrote despite refusal");
}

#[test]
fn a_same_family_crossflash_runs_through_the_engine() {
    let builds = stand_ins();
    let find = |model: &str, revision: &str| {
        let (_, image) = builds
            .iter()
            .find(|(b, _)| b.model == model && b.revision == revision)
            .unwrap();
        image.clone()
    };
    let wh16ns60 = find("BD-RE  WH16NS60", "1.01");
    let wh16ns58 = find("BD-RE  WH16NS58", "1.V1");
    let bw16d1ht = find("BW-16D1HT", "3.10");
    let dir = scratch("crossflash-engine");

    assert_crossflash(&wh16ns60, &wh16ns58, &dir, "ns60-ns58");
    assert_crossflash(&wh16ns58, &wh16ns60, &dir, "ns58-ns60");
    assert_crossflash(&bw16d1ht, &wh16ns58, &dir, "d1ht-ns58");

    // The drive keeps its old identity: the flash fails.
    let old = wh16ns60[0x1E_C000..0x1E_C100].to_vec();
    let mut req = mtk_request(wh16ns58.clone(), true, Some(dir.join("kept.bin")));
    req.drive_model = "BD-RE  WH16NS60".into();
    let mut dev = Rec::new(
        MockScsiDevice::echoing()
            .with_firmware_image(drive_read(&wh16ns60))
            .with_product("BD-RE  WH16NS60")
            .on_after_stream(is_descriptor_read, old),
    );
    let outcome = run(|| engine_flash(&mut dev, &Mtk, &req));
    assert!(
        outcome
            .result
            .contains("live firmware identity or build differs from the selected target"),
        "{}",
        outcome.result
    );
    assert!(
        outcome.result.contains("target startup"),
        "{}",
        outcome.result
    );
    assert!(outcome.result.contains("progress: "), "{}", outcome.result);
}

#[test]
fn requested_execution_refuses_cross_family_catalog_images() {
    let builds = stand_ins();
    let find = |model: &str, revision: &str| {
        builds
            .iter()
            .find(|(build, _)| build.model == model && build.revision == revision)
            .unwrap()
            .1
            .clone()
    };
    let wh16ns58 = find("BD-RE  WH16NS58", "1.V1");
    let bu40n = find("BD-RE BU40N", "1.02");
    // A JB7 build: a classic MT1939 (banner "MT1939 Boot Code"), a different
    // chip from the JB8 WH16NS58 (now MT1959 by its "MT1959 Boot" banner).
    let jb7 = builds
        .iter()
        .find(|(b, _)| b.family == "11e7527216405467" && b.model != "BD-RE  WH16NS58")
        .map(|(_, image)| image.clone())
        .unwrap();
    // A same-chip (MT1959), different-family image (BU40N) is refused with the
    // family message; a different-chip image (the classic MT1939 JB7) is refused
    // before the family gate. Neither writes.
    assert_cross_family_refused(&bu40n, &wh16ns58, "bu40n-ns58");
    assert_flash_refused(&jb7, &wh16ns58, "jb7-ns58");
}

/// Every 2 MiB MediaTek image under `FREEMKV_MTK_IMAGES` with an identity
/// descriptor, and its sha256.
fn corpus() -> Vec<(String, PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "bin") {
                out.push(path);
            }
        }
    }
    let dir = std::env::var("FREEMKV_MTK_IMAGES").expect("FREEMKV_MTK_IMAGES");
    let mut paths = Vec::new();
    walk(Path::new(&dir), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let image = std::fs::read(&path).ok()?;
            let descriptor = mediatek_optical::layout::DESCRIPTOR.of(&image)?;
            let usable = image.len() == IMAGE_SIZE
                && mediatek_optical::Chip::from_tag(descriptor).is_some()
                && !mediatek_optical::image::is_drive_read(&image);
            usable.then(|| (sha(&image), path, image))
        })
        .collect()
}

/// The same-hardware-family crossflash gate against the real images of the
/// hoard (`FREEMKV_MTK_IMAGES`): the motivating builds' facts, engine dry-runs
/// and flashes of the motivating cases, and every ordered pair of the corpus
/// through the engine dry run.
#[test]
#[ignore = "needs FREEMKV_MTK_IMAGES pointing at the MediaTek image hoard"]
fn crossflash_family_gate_holds_on_real_images() {
    let corpus = corpus();
    let find = |prefix: &str| -> Option<Vec<u8>> {
        let (_, path, image) = corpus.iter().find(|(sha, ..)| sha.starts_with(prefix))?;
        let cmac = if crate::cmac::verify(image) {
            "ok"
        } else {
            "FAILS"
        };
        eprintln!("{prefix}: {} (CMAC {cmac})", path.display());
        Some(image.clone())
    };
    let image = |prefix: &str| find(prefix).unwrap_or_else(|| panic!("no image {prefix}"));
    // The broken unMK WH16NS60 1.03 build, which the hoard may have dropped.
    if let Some(broken) = find("c2279417") {
        assert_eq!(Build::of_image(&broken).unwrap(), gate::wh16ns60_103());
    }
    // The pure tests' facts are the real images'.
    for (prefix, facts) in [
        ("3d901142", gate::wh16ns60_103()),
        ("e2406018", gate::wh16ns58_1v5()),
        ("37a32bfd", gate::bw16d1ht_310()),
        ("3f436c31", gate::bw16d1ht_101()),
        ("6d8b000f", gate::bu40n_102()),
    ] {
        assert_eq!(Build::of_image(&image(prefix)).unwrap(), facts, "{prefix}");
    }

    let wh16ns60 = image("3d901142");
    let wh16ns58 = image("e2406018");
    let bw16d1ht = image("37a32bfd");
    let jb7 = image("3f436c31");
    let bu40n = image("6d8b000f");
    let intm = image("1baed51d");
    let dir = scratch("crossflash-real");

    // Same-family crossflashes admit and flash through the engine.
    assert_crossflash(&wh16ns60, &wh16ns58, &dir, "ns60-ns58");
    assert_crossflash(&wh16ns58, &wh16ns60, &dir, "ns58-ns60");
    assert_crossflash(&bw16d1ht, &wh16ns58, &dir, "d1ht-ns58");
    assert_crossflash(&wh16ns60, &bw16d1ht, &dir, "ns60-d1ht");
    eprintln!("same family: NS60<->NS58, D1HT->NS58, NS60->D1HT flashed");

    // Refused at the dry run, no writes: the MT1959 BU40N is the same chip as
    // the (banner-MT1959) WH16NS58, so it gets the family message; the classic
    // MT1939 JB7 BW-16D1HT refuses one gate earlier, on the chip.
    assert_cross_family_refused(&bu40n, &wh16ns58, "bu40n-ns58");
    assert_flash_refused(&jb7, &wh16ns58, "jb7-ns58");

    // An INTM build of another model is a wrong-model image, refused as today.
    let (outcome, dev) = flash_onto(&wh16ns60, "BD-RE  WH16NS60", &intm, None);
    eprintln!("1baed51d onto WH16NS60: {}", outcome.result);
    assert!(outcome.result.contains("wrong-model"), "{}", outcome.result);
    assert!(streamed(&dev).is_empty());

    // Every ordered pair of the corpus through the gate (the engine's own
    // decision function, `Build::of_image` + `decide`): admitted as a crossflash
    // exactly when the two are one family, of different models; refused
    // otherwise.
    let builds: Vec<Build> = corpus
        .iter()
        .map(|(.., image)| Build::of_image(image).unwrap())
        .collect();
    let (mut crossed, mut same, mut refused) = (0u64, 0u64, 0u64);
    for ba in &builds {
        for bb in &builds {
            let expected = decide_model(&bb.product, &ba.product).is_err()
                && ba.family.is_some()
                && ba.family == bb.family;
            let label = || format!("{} onto {}", bb.label(), ba.label());
            match gate::decide(ba, bb) {
                Ok(Verdict::Crossflash) => {
                    assert!(expected, "{}", label());
                    crossed += 1;
                }
                Ok(Verdict::SameModel) => {
                    assert!(!expected, "{}", label());
                    same += 1;
                }
                Err(_) => {
                    assert!(!expected, "{}", label());
                    refused += 1;
                }
            }
        }
    }
    eprintln!("corpus pairs: {crossed} crossflash, {same} same model, {refused} refused");
    assert!(crossed > 0);

    // One image per family, every ordered pair through the engine dry run: a
    // cross-family flash is refused (no writes); a same-family, same-image
    // reflash is a same-model plan. Same-family crossflash admits are the
    // motivating assert_crossflash cases above.
    let mut reps: Vec<usize> = Vec::new();
    for (i, b) in builds.iter().enumerate() {
        if b.family.is_some() && !reps.iter().any(|&j| builds[j].family == b.family) {
            reps.push(i);
        }
    }
    eprintln!(
        "families represented through the engine dry run: {}",
        reps.len()
    );
    for &i in &reps {
        for &j in &reps {
            let (drive, image) = (&corpus[i].2, &corpus[j].2);
            let product = &builds[i].product;
            let dry = preview(drive, product, image);
            let label = format!("{} onto {}", builds[j].label(), builds[i].label());
            if builds[i].family == builds[j].family {
                let lines = dry.unwrap_or_else(|e| panic!("{label}: {e:#}"));
                assert!(lines.join("\n").contains("flash plan"), "{label}");
            } else {
                // A different family (or, one gate earlier, a different chip) is
                // refused at the dry run.
                assert!(dry.is_err(), "{label}: admitted");
            }
        }
    }
}
