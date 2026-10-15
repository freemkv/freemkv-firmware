//! Unit tests for [`super`]: the model gate and the same-hardware-family
//! crossflash gate. A crossflash is admitted exactly when the image and the
//! drive are one hardware family (`mediatek_optical::image::family`), both
//! non-INTM, with equal boot banners; there is no curated allowlist and no
//! override.

use super::super::fixture::{self, Board, BU3, JB7, JB8};
use super::*;

// JB8 ships an "MT1959 Boot JB8" banner, so it is MT1959 (the MTEKMT1939 tag is
// the stale vendor label); its family hash flips to the MT1959-keyed value.
const JB8_FAMILY: &str = "336e449ab6a827e3";
const JB7_FAMILY: &str = "11e7527216405467";
const BU3_FAMILY: &str = "309829e6c3c8f31d";

const JB8_BANNER: &[u8; 16] = b"MT1959 Boot JB8 ";

fn family(board: &Board) -> Option<Family> {
    mediatek_optical::image::family(&fixture::image(board, "BD-RE  X", 0))
}

fn build(vendor: &str, product: &str, revision: &str, board: &Board, banner: &[u8; 16]) -> Build {
    Build {
        vendor: vendor.into(),
        product: product.into(),
        revision: revision.into(),
        family: family(board),
        platform: board.platform.into(),
        banner: *banner,
    }
}

/// LG WH16NS60 1.03 (`c2279417`, `3d901142`): the motivating drive's firmware.
pub(crate) fn wh16ns60_103() -> Build {
    build("HL-DT-ST", "BD-RE  WH16NS60", "1.03", &JB8, JB8_BANNER)
}

/// LG WH16NS58 1.V5 (`e2406018`): the firmware the owner wants.
pub(crate) fn wh16ns58_1v5() -> Build {
    build("HL-DT-ST", "BD-RE  WH16NS58", "1.V5", &JB8, JB8_BANNER)
}

/// ASUS BW-16D1HT 3.10 (`37a32bfd`), the JB8 board.
pub(crate) fn bw16d1ht_310() -> Build {
    build("ASUS", "BW-16D1HT", "3.10", &JB8, JB8_BANNER)
}

/// ASUS BW-16D1HT 1.01 (`3f436c31`), the JB7 board.
pub(crate) fn bw16d1ht_101() -> Build {
    build("ASUS", "BW-16D1HT", "1.01", &JB7, b"MT1939 Boot Code")
}

/// LG BU40N 1.02 (`6d8b000f`).
pub(crate) fn bu40n_102() -> Build {
    build("HL-DT-ST", "BD-RE BU40N", "1.02", &BU3, b"MT1959 Boot BU5 ")
}

/// The flash path's model decisions for a drive running `drive` and the image
/// `target`, with the drive's full facts known (as a backup or fixture gives
/// them): the plan, then authorize with the backup as the installed build, then
/// the rollback. The whole pure decision.
pub(crate) fn decide(drive: &Build, target: &Build) -> Result<Verdict> {
    let planned = decide_plan(&drive.product, drive, target)?;
    let now = decide_authorized(&drive.product, drive, target)?;
    ensure_unchanged(planned, now)?;
    if now == Verdict::Crossflash {
        decide_rollback(drive, target)?;
    }
    Ok(now)
}

fn refusal(result: Result<Verdict>) -> String {
    format!("{:#}", result.expect_err("refused"))
}

// ---- the families the fixtures build ------------------------------------------

#[test]
fn the_fixture_boards_have_the_expected_families() {
    assert_eq!(
        family(&JB8).map(|f| f.to_string()).as_deref(),
        Some(JB8_FAMILY)
    );
    assert_eq!(
        family(&JB7).map(|f| f.to_string()).as_deref(),
        Some(JB7_FAMILY)
    );
    assert_eq!(
        family(&BU3).map(|f| f.to_string()).as_deref(),
        Some(BU3_FAMILY)
    );
}

// ---- the motivating case ------------------------------------------------------

#[test]
fn wh16ns60_to_wh16ns58_is_a_same_family_crossflash() {
    let (drive, target) = (wh16ns60_103(), wh16ns58_1v5());
    assert_eq!(drive.family, target.family, "both are JB8");
    assert_eq!(decide(&drive, &target).unwrap(), Verdict::Crossflash);
}

#[test]
fn wh16ns58_to_wh16ns60_is_a_same_family_crossflash() {
    let (drive, target) = (wh16ns58_1v5(), wh16ns60_103());
    assert_eq!(decide(&drive, &target).unwrap(), Verdict::Crossflash);
}

#[test]
fn a_jb8_bw16d1ht_crosses_with_the_wh16ns5x_6x_drives() {
    for (drive, target) in [
        (bw16d1ht_310(), wh16ns58_1v5()),
        (wh16ns60_103(), bw16d1ht_310()),
    ] {
        assert_eq!(decide(&drive, &target).unwrap(), Verdict::Crossflash);
    }
}

#[test]
fn a_jb7_bw16d1ht_is_refused_as_a_different_family() {
    let (drive, target) = (bw16d1ht_101(), wh16ns58_1v5());
    assert_ne!(drive.family, target.family, "JB7 vs JB8");
    let err = refusal(decide(&drive, &target));
    assert!(err.contains("different hardware family"), "{err}");
    assert!(
        err.contains(JB7_FAMILY) && err.contains(JB8_FAMILY),
        "{err}"
    );
}

#[test]
fn a_bu40n_is_refused_as_a_different_family() {
    let (drive, target) = (bu40n_102(), wh16ns58_1v5());
    assert_ne!(drive.family, target.family, "BU3 vs JB8");
    let err = refusal(decide(&drive, &target));
    assert!(err.contains("different hardware family"), "{err}");
    assert!(
        err.contains(BU3_FAMILY) && err.contains(JB8_FAMILY),
        "{err}"
    );
}

// ---- the decision table, row by row -------------------------------------------

#[test]
fn an_empty_inquiry_product_is_refused_as_today() {
    let target = wh16ns58_1v5();
    let live = Build::of_drive(&fixture::identity(&fixture::image(
        &JB8,
        "BD-RE  WH16NS60",
        1,
    )));
    let err = format!("{:#}", decide_plan("   ", &live, &target).unwrap_err());
    assert_eq!(err, format!("{:#}", decide_model("x", "   ").unwrap_err()));
    assert!(err.contains("empty INQUIRY product"));
}

#[test]
fn the_same_model_takes_the_fast_path() {
    // The same model is admitted whatever the revision or family; the family
    // gate in `prepare` follows. Nothing crossflash-specific is consulted.
    let target = Build {
        revision: "INTM".into(),
        family: None,
        ..wh16ns58_1v5()
    };
    let unreadable = Build {
        vendor: String::new(),
        product: String::new(),
        family: None,
        ..wh16ns60_103()
    };
    assert_eq!(
        decide_plan("WH16NS58", &unreadable, &target).unwrap(),
        Verdict::SameModel
    );
    assert_eq!(
        decide_authorized("wh16ns58", &unreadable, &target).unwrap(),
        Verdict::SameModel
    );
}

#[test]
fn an_inconsistent_drive_identity_is_refused() {
    let target = wh16ns58_1v5();
    for live in [
        bw16d1ht_310(),
        Build {
            product: String::new(),
            ..wh16ns60_103()
        },
    ] {
        let err = format!(
            "{:#}",
            decide_plan("BD-RE  WH16NS60", &live, &target).unwrap_err()
        );
        assert!(err.contains("drive identity is inconsistent"), "{err}");
    }
}

#[test]
fn an_intm_build_on_either_side_crosses_like_any_other_build() {
    let intm = |b: Build| Build {
        revision: "INTM".into(),
        ..b
    };
    // An INTM build is a complete OEM image: onto and off a drive it passes the
    // same family, chip, CMAC, boot-page and rollback gates as any other build.
    for (drive, target) in [
        (wh16ns60_103(), intm(wh16ns58_1v5())),
        (intm(wh16ns60_103()), wh16ns58_1v5()),
    ] {
        assert!(matches!(decide(&drive, &target), Ok(Verdict::Crossflash)));
    }
}

#[test]
fn an_unknown_family_on_either_side_fails_closed() {
    let (drive, target) = (wh16ns60_103(), wh16ns58_1v5());
    let unknown = |b: &Build| Build {
        family: None,
        ..b.clone()
    };
    // The image's family is unknown at the plan: fail closed before any read.
    let err = refusal(decide(&drive, &unknown(&target)));
    assert!(err.contains("target firmware family"), "{err}");
    // The backup's (installed) family is unknown at authorize.
    let err = format!(
        "{:#}",
        decide_authorized(&drive.product, &unknown(&drive), &target).unwrap_err()
    );
    assert!(err.contains("installed firmware family"), "{err}");
}

#[test]
fn a_different_family_is_refused_at_the_plan() {
    let (drive, target) = (bu40n_102(), wh16ns58_1v5());
    // With the drive's full family known, the exact family gate refuses, naming
    // both hashes.
    let err = format!(
        "{:#}",
        decide_plan(&drive.product, &drive, &target).unwrap_err()
    );
    assert!(err.contains("different hardware family"), "{err}");
    assert!(
        err.contains(BU3_FAMILY) && err.contains(JB8_FAMILY),
        "{err}"
    );
    // At the engine plan the drive is only its descriptor (no full family): a
    // differing platform is refused there too, by platform and boot banner.
    let descriptor_only = Build {
        family: None,
        ..drive.clone()
    };
    let err = format!(
        "{:#}",
        decide_plan(&drive.product, &descriptor_only, &target).unwrap_err()
    );
    assert!(err.contains("different hardware family"), "{err}");
    assert!(
        err.contains(&drive.platform) && err.contains(&target.platform),
        "{err}"
    );
}

#[test]
fn a_drive_that_changed_since_the_plan_is_refused() {
    assert!(ensure_unchanged(Verdict::Crossflash, Verdict::Crossflash).is_ok());
    assert!(ensure_unchanged(Verdict::SameModel, Verdict::SameModel).is_ok());
    let err = ensure_unchanged(Verdict::Crossflash, Verdict::SameModel)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("drive changed between plan and backup"),
        "{err}"
    );
    // The backup's identity is re-decided first: one that no longer names the
    // live model, or names it under another family, is refused before.
    let (live, target) = (wh16ns60_103(), wh16ns58_1v5());
    assert_eq!(
        decide_plan(&live.product, &live, &target).unwrap(),
        Verdict::Crossflash
    );
    for backup in [bw16d1ht_101(), bu40n_102()] {
        assert!(decide_authorized(&live.product, &backup, &target).is_err());
    }
}

#[test]
fn the_boot_banner_must_not_change() {
    let target = Build {
        banner: *b"MT1959 Boot JB9 ",
        ..wh16ns58_1v5()
    };
    let err = refusal(decide(&wh16ns60_103(), &target));
    assert!(err.contains("boot banner differs"), "{err}");
    let blank = |b: Build| Build {
        banner: [0; 16],
        ..b
    };
    let err = refusal(decide(&blank(wh16ns60_103()), &blank(wh16ns58_1v5())));
    assert!(err.contains("boot banner differs"), "{err}");
}

#[test]
fn a_backup_that_cannot_flash_back_is_refused() {
    // The backup's model contains the target's: once the drive runs the
    // target, the backup reads as the same model, not a crossflash back.
    let drive = Build {
        product: "BD-RE  WH16NS58A".into(),
        ..wh16ns60_103()
    };
    let err = refusal(decide(&drive, &wh16ns58_1v5()));
    assert!(
        err.contains("your backup could not be flashed back; refusing"),
        "{err}"
    );
}

#[test]
fn the_rollback_runs_the_update_gates_on_the_backup() {
    use super::super::flash::rollback;
    let backup = fixture::image(&JB8, "BD-RE  WH16NS60", 1);
    let image = fixture::image(&JB8, "BD-RE  WH16NS58", 2);
    rollback(&backup, &image).unwrap();
    let mut corrupt = backup.clone();
    corrupt[0x11000] ^= 1;
    assert!(format!("{:#}", rollback(&corrupt, &image).unwrap_err()).contains("AES-CMAC"));
    // A same-chip (MT1959) but different-family image is a family mismatch. (A
    // different-chip image — e.g. the MT1939 JB7 — would be a chip mismatch
    // instead, since the chip now comes from the banner.)
    let bu3 = fixture::image(&BU3, "BD-RE BU40N", 3);
    let err = format!("{:#}", rollback(&bu3, &image).unwrap_err());
    assert!(err.contains("family mismatch"), "{err}");
}

// ---- every ordered pair of catalog stand-ins ------------------------------------

/// Every stand-in's facts, as an image or backup and as a live drive.
fn catalog_facts() -> Vec<(fixture::CatalogBuild, Build)> {
    fixture::stand_ins()
        .into_iter()
        .map(|(b, image)| {
            let build = Build::of_image(&image).unwrap();
            assert_eq!(
                (build.vendor.as_str(), &build.product),
                (b.vendor(), &b.model)
            );
            (b, build)
        })
        .collect()
}

/// A crossflash is admitted exactly when the two builds are one hardware
/// family, of different models. An INTM build is gated like any other.
fn should_cross(a: &Build, b: &Build) -> bool {
    decide_model(&b.product, &a.product).is_err() && a.family.is_some() && a.family == b.family
}

#[test]
fn every_catalog_pair_crosses_exactly_within_one_family() {
    let facts = catalog_facts();
    let verdict = |a: &Build, b: &Build| decide(a, b).ok();
    let mut crossed = 0usize;
    for (cat_a, a) in &facts {
        for (cat_b, b) in &facts {
            let label = format!("{} onto {}", b.label(), a.label());
            let v = verdict(a, b);
            if should_cross(a, b) {
                assert_eq!(v, Some(Verdict::Crossflash), "{label}");
                // A crossflash never crosses hardware: same catalog key.
                assert_eq!(cat_a.hardware, cat_b.hardware, "{label}");
                assert_eq!((a.family, a.banner), (b.family, b.banner), "{label}");
                crossed += 1;
            } else if decide_model(&b.product, &a.product).is_ok() {
                assert_eq!(v, Some(Verdict::SameModel), "{label}");
            } else {
                assert_eq!(v, None, "refused: {label}");
            }
            // Symmetry: a crossflash one way is a crossflash the other.
            assert_eq!(
                v == Some(Verdict::Crossflash),
                verdict(b, a) == Some(Verdict::Crossflash),
                "symmetry: {label}"
            );
        }
    }
    eprintln!("catalog stand-ins: {crossed} admitted crossflash pairs");
    assert_eq!(crossed, EXPECTED_CROSS, "admitted crossflash pairs");
}

/// The count admitted among the 69 embedded-catalog stand-ins: every ordered
/// pair that is one family and different models (INTM builds included). A
/// regression guard; see [`every_catalog_pair_crosses_exactly_within_one_family`].
const EXPECTED_CROSS: usize = 840;

/// The flash path itself (plan against a drive, then authorize on the backup)
/// agrees with [`decide`] on every pair of the JB8 family.
#[test]
fn the_flash_path_decides_every_jb8_pair_like_the_pure_gates() {
    use super::super::flash::authorize_bytes;
    use super::super::Mtk;
    use crate::backend::ReadDevice;
    use crate::platform::MockScsiDevice;
    let facts: Vec<_> = fixture::stand_ins()
        .into_iter()
        .filter(|(b, _)| b.family == JB8_FAMILY)
        .collect();
    assert_eq!(facts.len(), 20);
    let mut crossed = 0;
    for (_, drive_image) in &facts {
        let drive = Build::of_image(drive_image).unwrap();
        for (_, image) in &facts {
            let target = Build::of_image(image).unwrap();
            let mut dev = MockScsiDevice::new().with_firmware_image(drive_image.clone());
            let path = Mtk
                .validate_image(
                    &mut ReadDevice::without_unlocks(&mut dev),
                    image,
                    &drive.product,
                )
                .and_then(|(live, verdict)| {
                    // The backup of a catalog build is its OEM image.
                    authorize_bytes(&live, &drive.product, verdict, image, Some(drive_image))
                        .map(|a| (verdict, a.expect))
                });
            let pure = decide(&drive, &target).ok();
            let label = format!("{} onto {}", target.label(), drive.label());
            match (path, pure) {
                (Ok((verdict, expect)), Some(pure)) => {
                    assert_eq!(verdict, pure, "{label}");
                    if verdict == Verdict::Crossflash {
                        crossed += 1;
                        assert_eq!(expect.as_deref(), Some(target.product.as_str()));
                    } else {
                        assert_eq!(expect, None);
                    }
                }
                (Err(_), None) => {}
                (path, pure) => panic!("{label}: path {:?}, pure {pure:?}", path.map(|p| p.0)),
            }
        }
    }
    assert!(crossed > 0, "{crossed} crossflash pairs on the flash path");
}

// ---- architecture ------------------------------------------------------------

/// Nothing in the gate can be switched off: no function takes an allow, force
/// or override flag, or any `bool`; the gate reads no environment or flag.
#[test]
fn the_gate_takes_no_override_parameter() {
    let source = include_str!("crossflash.rs");
    let code = source.split("#[cfg(test)]\n#[path").next().unwrap();
    let mut signatures = 0;
    for (at, _) in code.match_indices("fn ") {
        let rest = &code[at..];
        let Some(open) = rest.find('(') else { continue };
        let close = rest[open..].find(')').map(|c| open + c).unwrap();
        let params = rest[open + 1..close].to_ascii_lowercase();
        signatures += 1;
        for word in ["allow", "force", "override", "bool", "unsafe", "skip"] {
            assert!(
                !params.contains(word),
                "crossflash.rs takes a {word:?} parameter: {}",
                &rest[..=close]
            );
        }
    }
    assert!(signatures >= 10, "{signatures} signatures scanned");
    for word in [
        "allow_crossflash",
        "--force",
        "FREEMKV_",
        "env::var",
        "CLASSES",
        "validated",
    ] {
        assert!(!code.contains(word), "crossflash.rs mentions {word:?}");
    }
}
