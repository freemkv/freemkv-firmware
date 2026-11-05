use super::*;
use pioneer_optical::envelope::{signature::SigningKey, Update};

fn archive(update: &Update, normal_only: bool) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("kernel.enc", update.kernel_transfer()),
        ("normal.enc", update.normal_transfer()),
    ] {
        if normal_only && name == "kernel.enc" {
            continue;
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes).unwrap();
    }
    tar.into_inner().unwrap()
}
fn startup(update: Update, value: u16, foreign: bool) -> Update {
    let mut normal = update.normal().image.clone();
    normal[0x600..0x614].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
        0x41, 7, 0x80,
    ]);
    normal[0x60a..0x60c].copy_from_slice(&value.to_be_bytes());
    normal[0x780..0x786].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    if foreign {
        normal[0x701] = 0x13;
    }
    normal[16..20].fill(0);
    let sum = normal.as_chunks::<4>().0.iter().fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(*word))
    });
    normal[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    let mut bytes = update.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    Update::load(update.kernel_transfer(), &bytes).unwrap()
}
fn outcome(
    result: Result<crate::crossflash::Evaluation>,
) -> std::result::Result<crate::crossflash::Evaluation, String> {
    result.map_err(|error| format!("{error:#}"))
}
#[test]
fn cached_packages_preserve_pair_gates_and_conditional_requirements() {
    let plain = prepared_tests::pair(false, 1);
    let old = prepared_tests::pair(false, 0);
    let barrier = prepared_tests::pair(true, 1);
    let source = startup(plain.clone(), 0xff01, false);
    let target = startup(old.clone(), 0xfe24, false);
    let foreign = startup(old.clone(), 0xfe24, true);
    for (source, target) in [
        (&plain, &old),
        (&barrier, &old),
        (&source, &target),
        (&source, &foreign),
    ] {
        let source = archive(source, false);
        let target = archive(target, false);
        let cached_source = OfflinePackage::load(&source).unwrap();
        let cached_target = OfflinePackage::load(&target).unwrap();
        assert_eq!(
            outcome(cached_source.routes_to(&cached_target)),
            outcome(offline_routes(&source, &target))
        );
    }
    let source = archive(&source, false);
    let normal = archive(&target, true);
    let invalid = b"invalid package";
    assert!(OfflinePackage::load(&normal).is_err());
    assert!(OfflinePackage::load(invalid).is_err());
    let packages: &[&[u8]] = &[&source, &normal, invalid];
    let routes =
        crate::crossflash::classified_routes(crate::crossflash::Platform::Pioneer, packages);
    let expected: Vec<_> = (0..packages.len())
        .flat_map(|i| {
            (0..packages.len())
                .filter(move |j| *j != i)
                .flat_map(move |j| {
                    crate::crossflash::decide(
                        crate::crossflash::Platform::Pioneer,
                        packages[i],
                        packages[j],
                    )
                    .routes
                    .into_iter()
                    .map(move |route| (i, j, route))
                })
        })
        .collect();
    assert_eq!(routes, expected);
}

#[test]
#[ignore = "requires one real retained package for focused cache timing"]
fn real_package_cache_retains_verdict_and_reuses_validation() {
    let bytes = std::fs::read(std::env::var("PIONEER_OFFLINE_CACHE_PACKAGE").unwrap()).unwrap();
    let package = OfflinePackage::load(&bytes).unwrap();
    let start = std::time::Instant::now();
    let ordinary = outcome(offline_routes(&bytes, &bytes));
    let ordinary_time = start.elapsed();
    let start = std::time::Instant::now();
    let cached = outcome(package.routes_to(&package));
    let cached_time = start.elapsed();
    assert_eq!(cached, ordinary);
    eprintln!("ordinary={ordinary_time:?} cached={cached_time:?}");
}
