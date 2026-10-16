//! Real-package proof that paired Normal is validated under its incoming Kernel.
//! Uses the real BDR-207M 1.60 <-> BDR-PR1ML 1.30 pair in both
//! directions (their receiver classes differ inside family `cee5c9016d0174c9`);
//! leave every same-model reflash and every same-receiver-class crossflash
//! admitted, including different receiver classes when the incoming pair matches.

use super::flash_plan::{
    check_receiver, receiver_class, receiver_evidence, receiver_gate, ReceiverClass,
};
use pioneer_optical::envelope::{self, header_info};
use pioneer_optical::ComponentKind;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

struct Pkg {
    name: String,
    model: String,
    sat: String,
    dest: String,
    family: String,
    class: ReceiverClass,
    kernel: Vec<u8>,
    normal: Vec<u8>,
}

fn components(tar_path: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    let bytes = std::fs::read(tar_path).ok()?;
    let mut archive = tar::Archive::new(bytes.as_slice());
    let (mut kernel, mut normal) = (None, None);
    for entry in archive.entries().ok()? {
        let mut entry = entry.ok()?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf).ok()?;
        match header_info(&buf).and_then(|h| h.kind) {
            Some(ComponentKind::Kernel) => kernel = Some(buf),
            Some(ComponentKind::Normal) => normal = Some(buf),
            _ => {}
        }
    }
    Some((kernel?, normal?))
}

fn load_hoard(root: &Path) -> Vec<Pkg> {
    let text = std::fs::read(root.join("index/packages.json")).expect("hoard index");
    let index: serde_json::Value = serde_json::from_slice(&text).expect("hoard index JSON");
    let field = |p: &serde_json::Value, k: &str| p[k].as_str().unwrap_or_default().to_string();
    let mut out = Vec::new();
    for p in index["packages"].as_array().expect("packages array") {
        if !p["kernel_sha256"].is_string() || !p["normal_sha256"].is_string() {
            continue;
        }
        let path = root.join(field(p, "path"));
        let Some((kernel, normal)) = components(&path) else {
            continue;
        };
        // Only packages the engine can actually pair (a recognized receiver
        // policy) participate; others are outside this gate's scope.
        let Some(class) = receiver_class(&kernel, &normal) else {
            continue;
        };
        // A pair the library itself rejects is not a flashable OEM pair (e.g. the
        // hoard's BDR-TD05 ID01 1.01 direct-match pairing); it is refused before
        // the receiver gate, so it is outside this test.
        let Ok(update) = envelope::Update::load(&kernel, &normal) else {
            continue;
        };
        let family = update.family().map(|f| f.to_string()).unwrap_or_default();
        out.push(Pkg {
            name: format!(
                "{} {} {}",
                field(p, "embedded_model"),
                field(p, "destination"),
                field(p, "revision")
            ),
            model: field(p, "embedded_model"),
            sat: field(p, "hardware"),
            dest: field(p, "destination"),
            family,
            class,
            kernel,
            normal,
        });
    }
    out
}

#[test]
fn hoard_paired_normal_uses_target_receiver() {
    let Ok(root) = std::env::var("FREEMKV_PIONEER_HOARD") else {
        eprintln!("FREEMKV_PIONEER_HOARD not set; real-package receiver-gate test skipped");
        return;
    };
    let pkgs = load_hoard(&PathBuf::from(root));
    assert!(
        pkgs.len() >= 2,
        "hoard must hold multiple Kernel+Normal packages"
    );

    let admits = |i: usize, j: usize| {
        check_receiver(
            Some(&pkgs[i].kernel),
            Some(&pkgs[j].kernel),
            &pkgs[j].normal,
        )
        .is_ok()
    };

    // 1. Every package's own Normal decodes under its own Kernel (the proof
    //    path, not the identical-Kernel shortcut).
    let mut self_admitted = 0usize;
    for p in &pkgs {
        assert!(
            receiver_gate(&receiver_evidence(Some(&p.kernel), &p.normal, &p.kernel)).is_ok(),
            "{}: own pair does not decode",
            p.name
        );
        self_admitted += 1;
    }

    // 2. Every same-model pair supplies Normal for its incoming Kernel.
    //    This checks Normal decoding; Kernel handoff is a separate gate.
    let mut by_model: HashMap<(&str, &str, &str), Vec<usize>> = HashMap::new();
    for (i, p) in pkgs.iter().enumerate() {
        by_model
            .entry((p.sat.as_str(), p.dest.as_str(), p.model.as_str()))
            .or_default()
            .push(i);
    }
    let mut same_model_pairs = 0usize;
    for group in by_model.values() {
        for &i in group {
            for &j in group {
                assert!(
                    admits(i, j),
                    "{} -> {}: same-model pair was refused",
                    pkgs[i].name,
                    pkgs[j].name
                );
                same_model_pairs += 1;
            }
        }
    }

    // 3. Paired cross-edition Normal is received by its incoming Kernel,
    //    including when its encoding differs from the installed Kernel.
    let (mut same_class_admit, mut cross_class_admit) = (0usize, 0usize);
    let mut violations: Vec<String> = Vec::new();
    for (i, a) in pkgs.iter().enumerate() {
        for (j, t) in pkgs.iter().enumerate() {
            if a.family != t.family || a.sat != t.sat || a.dest == t.dest {
                continue;
            }
            let same = a.class == t.class;
            if admits(i, j) {
                if same {
                    same_class_admit += 1;
                } else {
                    cross_class_admit += 1;
                }
            } else {
                violations.push(format!("{} -> {}: paired Normal refused", a.name, t.name));
            }
        }
    }
    assert!(violations.is_empty(), "{violations:#?}");

    // 4. The named real case, both directions, must preserve paired encoding.
    let find = |needle: &str| {
        pkgs.iter()
            .find(|p| p.name.starts_with(needle))
            .unwrap_or_else(|| panic!("hoard is missing {needle}"))
    };
    let a = find("BDR-207M ID43 1.60");
    let b = find("BDR-PR1ML ID88 1.30");
    assert_ne!(
        a.class, b.class,
        "the named case must straddle a class boundary"
    );
    assert_eq!(a.family, b.family, "the named case must share a family");
    assert!(
        check_receiver(Some(&a.kernel), Some(&b.kernel), &b.normal).is_ok(),
        "207M -> PR1ML must preserve paired encoding"
    );
    assert!(
        check_receiver(Some(&b.kernel), Some(&a.kernel), &a.normal).is_ok(),
        "PR1ML -> 207M must preserve paired encoding"
    );

    eprintln!(
        "receiver gate over {} packages: self-decode {self_admitted}, \
         same-model pairs {same_model_pairs} admitted; cross-edition same-class {same_class_admit} admitted, \
         different-contract {cross_class_admit} admitted; 207M<->PR1ML paired encoding admitted; 205<->206 encoding matches but handoff refuses",
        pkgs.len(),
    );

    // 5. BDR-205 (SAT 1014, the S05XLB) <-> BDR-206 (SAT 1030): one family, one
    //    receiver class, different SAT. Encoding equality is insufficient:
    //    the independent Kernel handoff check must refuse this transition.
    let k205 = pkgs
        .iter()
        .find(|p| p.model == "BDR-205" && p.sat == "1014")
        .expect("hoard is missing a BDR-205 SAT 1014 package");
    let k206 = pkgs
        .iter()
        .find(|p| p.model == "BDR-206" && p.sat == "1030")
        .expect("hoard is missing a BDR-206 SAT 1030 package");
    assert_eq!(k205.family, k206.family, "205 and 206 share a family");
    assert_eq!(k205.class, k206.class, "205 and 206 share a receiver class");
    assert!(check_receiver(Some(&k205.kernel), Some(&k206.kernel), &k206.normal).is_ok());
    assert!(check_receiver(Some(&k206.kernel), Some(&k205.kernel), &k205.normal).is_ok());
    let a = envelope::decode_envelope(&k205.kernel).unwrap();
    let b = envelope::decode_envelope(&k206.kernel).unwrap();
    assert!(pioneer_optical::image::check_kernel_handoff(&a.image, &b.image).is_err());
    assert!(pioneer_optical::image::check_kernel_handoff(&b.image, &a.image).is_err());
}
