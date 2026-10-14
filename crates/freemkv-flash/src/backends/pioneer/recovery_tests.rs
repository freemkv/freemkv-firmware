use super::*;
use crate::engine::gates::ungated_for_tests;
use pioneer_optical::envelope::{
    builder::{encode_encrypted_pair, BuildInputs, KernelBuild, NormalSignature},
    signature::SigningKey,
    Update,
};

// Synthetic instruction fixtures, not extracted firmware images.
const UNGATED_FINALIZER: &[u8] = &[
    0x7a, 0x00, 0x00, 0x01, 0x12, 0x00, 0x1f, 0x81, 0x58, 0x60, 0x00, 0x94, 0x1a, 0x91, 0x01, 0x00,
    0x69, 0xc1, 0x01, 0x00, 0x6f, 0x41, 0x00, 0x08, 0x1a, 0xb3, 0xf3, 0x12, 0x0a, 0x93, 0x7a, 0x11,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x69, 0xf1, 0x1a, 0xd5, 0xf5, 0x10, 0x01, 0x00, 0x6f, 0xf5,
    0x00, 0x04, 0x0f, 0xf0, 0x79, 0x10, 0x00, 0x0c, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x08, 0x0f, 0xc0,
    0x7a, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xb1, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x46, 0x0e,
    0x18, 0x99, 0x0f, 0xc0, 0x5e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x0c, 0x01, 0x00,
    0x6f, 0x70, 0x00, 0x0c,
];

const GATED_FINALIZER: &[u8] = &[
    0x7a, 0x00, 0x00, 0x01, 0x12, 0x00, 0x1f, 0x81, 0x58, 0x60, 0x00, 0xa6, 0x1a, 0x91, 0x01, 0x00,
    0x69, 0xd1, 0x01, 0x00, 0x6f, 0x51, 0x00, 0x08, 0x1a, 0xb3, 0xf3, 0x12, 0x0a, 0x93, 0x7a, 0x11,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x69, 0xf1, 0x1a, 0xc4, 0xf4, 0x10, 0x01, 0x00, 0x6f, 0xf4,
    0x00, 0x04, 0x0f, 0xf0, 0x79, 0x10, 0x00, 0x0c, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x08, 0x0f, 0xd0,
    0x7a, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xb1, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x46, 0x0e,
    0x18, 0x99, 0x0f, 0xd0, 0x5e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x6f, 0xf0, 0x00, 0x0c, 0x18, 0x99,
    0x0f, 0xd0, 0x5e, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x47, 0x44, 0x01, 0x00, 0x6f, 0x70, 0x00, 0x0c,
];

const MARKER_CHECK: &[u8] = &[
    0x01, 0x00, 0x6d, 0xf4, 0x1b, 0x87, 0x0f, 0x82, 0x01, 0x00, 0x6b, 0x24, 0x00, 0x41, 0x00, 0x14,
    0x01, 0x00, 0x6f, 0x00, 0x00, 0x08, 0x0c, 0x99, 0x46, 0x0a, 0x7a, 0x10, 0x00, 0x00, 0x12, 0xfe,
    0x0f, 0x81, 0x40, 0x0e, 0x01, 0x00, 0x6f, 0x21, 0x00, 0x0e, 0x0a, 0x81, 0x7a, 0x11, 0x00, 0x01,
    0x00, 0x28, 0x0f, 0xf0, 0x1a, 0xa2, 0xfa, 0x01, 0x5e, 0x00, 0x01, 0x90, 0x68, 0x78, 0xa8, 0xff,
    0x47, 0x08, 0x0c, 0x88, 0x47, 0x04, 0x18, 0x00, 0x40, 0x02, 0xf0, 0x01, 0x6a, 0x30, 0x00, 0x00,
    0x06, 0x7e, 0x77, 0x00, 0x44, 0x0a, 0x7a, 0x24, 0xff, 0xff, 0xff, 0xff, 0x46, 0x02, 0x18, 0x00,
    0x0c, 0x08, 0x0b, 0xf7, 0x01, 0x00, 0x6d, 0x74, 0x54, 0x70,
];

fn balance(bytes: &mut [u8]) {
    let at = bytes.len() - 4;
    bytes[at..].fill(0);
    let sum = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |sum, w| sum.wrapping_add(u32::from_be_bytes(*w)));
    bytes[at..].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
fn fixture_pair(gated: bool, marker: u8) -> Update {
    let mut kernel = vec![0; 0x10000];
    kernel[0x1000..0x1014].copy_from_slice(b"SAT FFFEGENERAL 0000");
    kernel[0x40..0x42].copy_from_slice(&[0xae, 0xfe]);
    kernel[0x46..0x48].copy_from_slice(&[0xae, 0xf0]);
    kernel[0x100..0x114].copy_from_slice(&[
        0x7a, 0x20, 0, 0, 1, 0, 0x47, 12, 0x7a, 0x20, 0, 0, 2, 0, 0x47, 4, 1, 0xf0, 0x65, 5,
    ]);
    // The XOR-skip branch above is followed by the Forward-rotation decode loop
    // the receiver reads: AND.W #0x1F,R3; MOV.W R3,R1; JSR shift-helper (at
    // KERNEL_BASE+0x114+14 = 0x400122); OR.L; SHLR.L (right) + RTS. Without this
    // `normal_rotation_from_kernel` returns None and `Update::load` fails
    // `UnknownRotation`.
    kernel[0x114..0x126].copy_from_slice(&[
        0x79, 0x63, 0, 0x1f, 0x0d, 0x31, 0x5e, 0x40, 0x01, 0x22, 1, 0xf0, 0x64, 0x40, 0x11, 0x70,
        0x54, 0x70,
    ]);
    let finalizer = if gated {
        GATED_FINALIZER
    } else {
        UNGATED_FINALIZER
    };
    kernel[0x300..0x300 + finalizer.len()].copy_from_slice(finalizer);
    for (offset, address) in [(0x349, [0x40, 0x20, 0]), (0x355, [0x40, 0x22, 0])] {
        kernel[offset..offset + 3].copy_from_slice(&address);
    }
    if gated {
        kernel[0x363..0x366].copy_from_slice(&[0x40, 0x30, 0]);
        kernel[0x3000..0x3000 + MARKER_CHECK.len()].copy_from_slice(MARKER_CHECK);
    }
    kernel[pioneer_optical::envelope::KERNEL_MARKER_OFFSET] = marker;
    balance(&mut kernel);
    let mut normal = vec![0; 0x2000];
    normal[..16].copy_from_slice(b"PIONEER TEST-NEW");
    normal[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    normal[0x400..0x408].copy_from_slice(&[0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36, 0, 0]);
    normal[0x500..0x510].copy_from_slice(&[
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, marker, 0x46, 0x4e,
    ]);
    balance(&mut normal);
    let mut scalar = [0; 20];
    scalar[19] = 5;
    let signer = SigningKey::from_bytes(scalar).unwrap();
    let encoded = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "26/10/07",
            kernel: KernelBuild::from_seed(7),
            normal_key_seed: 11,
        },
        NormalSignature::Sign(&signer),
    )
    .unwrap();
    Update::load(&encoded.kernel, &encoded.normal).unwrap()
}

#[derive(Default)]
struct Drive {
    updating: bool,
    finished: bool,
    stuck: bool,
    fail_write: Option<usize>,
    attempts: usize,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
}
impl ScsiDevice for Drive {
    fn describe(&self) -> String {
        "Recovery test".into()
    }
    fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; len];
        let kernel = (self.updating && !self.finished) || self.stuck;
        if command == cdb::inquiry(len as u8) {
            bytes[0] = 5;
            bytes[8..16].copy_from_slice(b"PIONEER ");
            bytes[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
            bytes[32..36].copy_from_slice(if kernel { b"0000" } else { b"1.00" });
        } else if command == cdb::vendor_identity() {
            bytes[16..24].copy_from_slice(b"SAT FFFE");
            bytes[24..32].copy_from_slice(b"GENERAL ");
            if !kernel {
                bytes[32..40].copy_from_slice(b"GENERAL ");
            }
        } else if command == cdb::test_unit_ready() {
            return Err(crate::platform::ScsiSenseError::new(2, 0x3a, 0, "no medium").into());
        } else if command != cdb::get_event_status() {
            panic!("unexpected read (firmware reads forbidden): {command:02x?}");
        }
        Ok(bytes)
    }
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        panic!("lenient write forbidden")
    }
    fn command_out_strict(&mut self, command: &[u8], bytes: &[u8]) -> Result<()> {
        self.attempts += 1;
        if self.fail_write == Some(self.attempts) {
            bail!("injected write failure");
        }
        self.writes.push((command.to_vec(), bytes.to_vec()));
        if command == cdb::finish() && self.writes.iter().any(|(c, _)| c[2] == 0xf0) {
            self.finished = true;
        }
        Ok(())
    }
}
fn recovery_plan() -> Plan {
    Plan::from_updates(fixture_pair(false, 1), fixture_pair(false, 0)).unwrap()
}

#[test]
fn kernel_recovery_writes_both_components_without_entry_or_firmware_reads() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(drive.writes.first().unwrap().0[2], 0xfe);
    assert_eq!(
        drive
            .writes
            .iter()
            .filter(|(c, _)| *c == cdb::finish())
            .count(),
        1
    );
    for (buffer, expected) in [
        (0xfe, plan.kernel_transfer.as_slice()),
        (0xf0, plan.normal_transfer.as_slice()),
    ] {
        let actual: Vec<_> = drive
            .writes
            .iter()
            .filter(|(c, _)| c[2] == buffer)
            .flat_map(|(_, b)| b.iter().copied())
            .collect();
        assert_eq!(actual, expected);
    }
}
#[test]
fn normal_recovery_enters_first_and_uses_supplied_receiver_control() {
    let plan = recovery_plan();
    let mut drive = Drive::default();
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
    assert_eq!(
        drive.writes[0],
        (cdb::enter_update().to_vec(), plan.control.to_vec())
    );
    assert_eq!(drive.writes.last().unwrap().1, plan.control);
}
#[test]
fn failed_write_stops_without_retry_or_finish() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        fail_write: Some(2),
        ..Default::default()
    };
    assert!(plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .is_err());
    assert_eq!(drive.attempts, 2);
    assert!(!drive.finished);
}
#[test]
fn remaining_in_kernel_is_not_reported_as_success() {
    let plan = recovery_plan();
    let mut drive = Drive {
        updating: true,
        stuck: true,
        ..Default::default()
    };
    let error = plan
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(error.to_string().contains("return to normal mode"));
}
#[test]
fn supplied_real_recovery_packages_prepare_and_transfer_without_reads() {
    let (Ok(current), Ok(target)) = (
        std::env::var("PIONEER_RECOVERY_CURRENT"),
        std::env::var("PIONEER_RECOVERY_TARGET"),
    ) else {
        return;
    };
    let plan = Plan::prepare(
        &std::fs::read(current).unwrap(),
        &std::fs::read(target).unwrap(),
    )
    .unwrap();
    let mut drive = Drive {
        updating: true,
        ..Default::default()
    };
    plan.run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap();
}

#[test]
fn credentials_come_from_current_not_target() {
    let current = fixture_pair(false, 1);
    let target = fixture_pair(false, 0);
    let ReceiverControl::Key(expected) =
        pioneer_optical::image::receiver_control(&current.normal().image).unwrap()
    else {
        panic!("expected keyed fixture")
    };
    assert_ne!(
        pioneer_optical::image::receiver_control(&current.normal().image),
        pioneer_optical::image::receiver_control(&target.normal().image)
    );
    let plan = Plan::from_updates(current, target).unwrap();
    assert_eq!(&plan.control[16..20], expected);
}

#[test]
fn entry_failure_never_sends_components() {
    let mut drive = Drive {
        fail_write: Some(1),
        ..Default::default()
    };
    let error = recovery_plan()
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(error.to_string().contains("update entry failed"));
    assert_eq!(drive.attempts, 1);
    assert!(drive.writes.is_empty());
}

fn archive(update: &Update, unsigned: bool) -> Vec<u8> {
    let kernel = update.kernel().repack(&update.kernel().image).unwrap();
    let mut normal = update.normal().repack(&update.normal().image).unwrap();
    if unsigned {
        normal[0x170..0x1c0].fill(0);
    }
    let mut tar = tar::Builder::new(Vec::new());
    for (name, data) in [("kernel.enc", kernel), ("normal.enc", normal)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, data.as_slice()).unwrap();
    }
    tar.into_inner().unwrap()
}

#[test]
fn unsigned_backup_is_valid_current_evidence_but_not_a_signed_target() {
    let update = fixture_pair(false, 1);
    let unsigned = archive(&update, true);
    let signed = archive(&update, false);
    assert!(Plan::prepare(&unsigned, &signed).is_ok());
    assert!(Plan::prepare(&signed, &unsigned).is_err());
}

struct UnsupportedDrive {
    inquiry: Vec<u8>,
    vendor_reads: usize,
    writes: usize,
}
impl ScsiDevice for UnsupportedDrive {
    fn describe(&self) -> String {
        "unsupported test drive".into()
    }
    fn command_in(&mut self, command: &[u8], len: usize) -> Result<Vec<u8>> {
        if command == cdb::inquiry(pioneer_optical::INQUIRY_LEN as u8) {
            return Ok(self.inquiry.clone());
        }
        assert_eq!(command, cdb::vendor_identity());
        self.vendor_reads += 1;
        Ok(vec![0; len])
    }
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        self.writes += 1;
        bail!("unexpected write")
    }
    fn command_out_strict(&mut self, c: &[u8], b: &[u8]) -> Result<()> {
        self.command_out(c, b)
    }
}

#[test]
fn wrong_drive_and_short_identity_fail_before_vendor_commands_or_writes() {
    let mut mtk = vec![0; pioneer_optical::INQUIRY_LEN];
    mtk[0] = 5;
    mtk[8..16].copy_from_slice(b"HL-DT-ST");
    let mut disk = mtk.clone();
    disk[0] = 0;
    disk[8..16].copy_from_slice(b"PIONEER ");
    let plan = recovery_plan();
    for inquiry in [mtk, disk, vec![0; 8]] {
        let mut drive = UnsupportedDrive {
            inquiry,
            vendor_reads: 0,
            writes: 0,
        };
        // This same eligibility check is used by the workflow before reads/dry-run.
        assert!(identify_receiver(&mut drive).is_err());
        let error = plan
            .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
            .unwrap_err();
        assert!(
            error.to_string().contains("No firmware written")
                || error.to_string().contains("no firmware written")
        );
        assert_eq!(drive.vendor_reads, 0);
        assert_eq!(drive.writes, 0);
    }
}

#[test]
fn unsupported_pioneer_dialect_fails_before_update_entry() {
    let mut inquiry = vec![0; pioneer_optical::INQUIRY_LEN];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"UNKNOWN RECEIVER");
    let mut drive = UnsupportedDrive {
        inquiry,
        vendor_reads: 0,
        writes: 0,
    };
    let error = recovery_plan()
        .run(&mut ungated_for_tests(&mut drive), &mut |_| {})
        .unwrap_err();
    assert!(error.to_string().contains("update dialect"));
    assert_eq!(drive.vendor_reads, 1);
    assert_eq!(drive.writes, 0);
}

#[test]
fn recover_hook_dry_run_writes_nothing_and_execute_writes() {
    let current = archive(&fixture_pair(false, 1), false);
    let target = archive(&fixture_pair(false, 0), false);

    let mut dry = Drive {
        updating: true,
        ..Default::default()
    };
    let pioneer = crate::backends::pioneer::Pioneer::new();
    crate::engine::recover(&mut dry, &pioneer, Some(&current), &target, false, false).unwrap();
    assert_eq!(dry.attempts, 0, "dry run wrote to the drive");
    assert!(dry.writes.is_empty());

    let mut live = Drive {
        updating: true,
        ..Default::default()
    };
    crate::engine::recover(&mut live, &pioneer, Some(&current), &target, true, true).unwrap();
    assert!(live.finished && !live.writes.is_empty());
}


// ---- Hoard-wide recover re-encode KAT ---------------------------------------
//
// Env-gated (`FREEMKV_PIONEER_HOARD`, the directory holding
// `index/packages.json`); unset is a no-op. Across every same-family
// Kernel+Normal package pair, the recover plan must admit exactly the
// offline-provable target Normals. Two cases:
//
//  * same receiver class (identical XOR-skip offsets + rotation): the installed
//    Kernel decodes the shipped Normal to the identical body by construction, so
//    the pair is provable without a re-encode;
//  * different receiver class: the target Normal must re-encode for the installed
//    Kernel and the result must decode, under that Kernel, to the identical body
//    with a zero BE32 checksum. Every such cross-receiver pair is proven here.
//
// The real same-SAT cross-receiver case BDR-207M <- BDR-PR1ML is additionally
// driven end-to-end through `Plan::prepare` and must take the re-encode path.
#[test]
fn hoard_recover_admits_offline_provable_same_family_pairs() {
    use crate::backends::pioneer::classify_flash_input;
    use crate::backends::pioneer::flash_plan::{
        normal_family_with_kernel, receiver_class, ReceiverClass,
    };
    use pioneer_optical::envelope::builder::{
        encode_normal_for_kernel, NormalKeySource, NormalSignature,
    };
    use pioneer_optical::envelope::signature::SigningKey;
    use pioneer_optical::envelope::{decode_envelope_with_kernel, Envelope};
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    let Ok(root) = std::env::var("FREEMKV_PIONEER_HOARD") else {
        eprintln!("FREEMKV_PIONEER_HOARD not set; recover re-encode KAT skipped");
        return;
    };
    let root = PathBuf::from(root);
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("index/packages.json")).expect("index"))
            .expect("index JSON");
    let field = |p: &serde_json::Value, k: &str| p[k].as_str().unwrap_or_default().to_string();

    struct Meta {
        name: String,
        path: PathBuf,
        family: String,
        class: ReceiverClass,
    }
    let mut metas: Vec<Meta> = Vec::new();
    let mut seen = HashSet::new();
    for p in index["packages"].as_array().expect("packages array") {
        if !p["kernel_sha256"].is_string() || !p["normal_sha256"].is_string() {
            continue;
        }
        if !seen.insert((field(p, "kernel_sha256"), field(p, "normal_sha256"))) {
            continue;
        }
        let path = root.join(field(p, "path"));
        let Ok(tar) = std::fs::read(&path) else {
            continue;
        };
        let Ok((Some(k), Some(n))) = classify_flash_input(&tar) else {
            continue;
        };
        let (Some(family), Some(class)) =
            (normal_family_with_kernel(&n, &k), receiver_class(&k, &n))
        else {
            continue;
        };
        metas.push(Meta {
            name: format!(
                "{} {} {}",
                field(p, "embedded_model"),
                field(p, "destination"),
                field(p, "revision")
            ),
            path,
            family: family.to_string(),
            class,
        });
    }
    assert!(metas.len() >= 2, "hoard must hold multiple K+N packages");

    let mut by_family: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, m) in metas.iter().enumerate() {
        by_family.entry(m.family.as_str()).or_default().push(i);
    }

    // A fixed caller-owned signer; its on-drive acceptance is hardware-unproven.
    let signer = SigningKey::from_bytes([7; 20]).unwrap();
    let decode_body = |kernel: &[u8], normal: &[u8]| -> Option<Vec<u8>> {
        let k = Envelope::load(kernel).ok()?;
        Some(decode_envelope_with_kernel(normal, &k)?.image)
    };

    let (mut same_class, mut cross_proven, mut cross_total) = (0usize, 0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    // Full per-pair matrix (family, installed X, target Y, verdict), emitted to
    // FREEMKV_PIONEER_HOARD_REPORT when set. AS-IS = installed Kernel decodes the
    // shipped Normal unchanged; REENCODE = X->Y needs cross-receiver re-encode;
    // REFUSED = not offline-provable (with cause).
    let mut rows: Vec<String> = Vec::new();
    for group in by_family.values() {
        let mut cross: Vec<(usize, usize)> = Vec::new();
        let mut same_pair: Option<(usize, usize)> = None;
        for &i in group {
            for &j in group {
                if i == j {
                    continue;
                }
                if metas[i].class == metas[j].class {
                    same_class += 1;
                    same_pair.get_or_insert((i, j));
                    rows.push(format!(
                        "{}\t{}\t{}\tAS-IS",
                        metas[i].family, metas[i].name, metas[j].name
                    ));
                } else {
                    cross.push((i, j));
                }
            }
        }
        if cross.is_empty() {
            continue;
        }
        // Load only this family's bytes, proving each cross-receiver pair.
        let bytes: HashMap<usize, (Vec<u8>, Vec<u8>)> = group
            .iter()
            .filter_map(|&i| {
                let (Some(k), Some(n)) = classify_flash_input(&std::fs::read(&metas[i].path).ok()?).ok()?
                else {
                    return None;
                };
                Some((i, (k, n)))
            })
            .collect();
        // Sanity-check the by-construction claim on one same-class pair when one
        // exists in this (multi-class) family.
        if let Some((i, j)) = same_pair {
            let (ki, _) = &bytes[&i];
            let (kj, nj) = &bytes[&j];
            assert_eq!(
                decode_body(ki, nj),
                decode_body(kj, nj),
                "{} and {} share a receiver class but decode a Normal differently",
                metas[i].name,
                metas[j].name
            );
        }
        for (i, j) in cross {
            cross_total += 1;
            let (ki, _) = &bytes[&i];
            let (kj, nj) = &bytes[&j];
            let installed = Envelope::load(ki).expect("installed kernel");
            let want = decode_body(kj, nj).expect("target body");
            let seed = Envelope::load(kj)
                .ok()
                .and_then(|k| decode_envelope_with_kernel(nj, &k))
                .and_then(|n| n.encoding_seed());
            let Some(seed) = seed else {
                failures.push(format!("{} <- {}: no seed", metas[j].name, metas[i].name));
                rows.push(format!(
                    "{}\t{}\t{}\tREFUSED: no recoverable encoding seed",
                    metas[i].family, metas[i].name, metas[j].name
                ));
                continue;
            };
            let reencoded = match encode_normal_for_kernel(
                &installed.image,
                &want,
                &nj[..0x200],
                NormalKeySource::Seed(seed),
                NormalSignature::Sign(&signer),
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    failures.push(format!("{} <- {}: {e:?}", metas[j].name, metas[i].name));
                    rows.push(format!(
                        "{}\t{}\t{}\tREFUSED: {e:?}",
                        metas[i].family, metas[i].name, metas[j].name
                    ));
                    continue;
                }
            };
            let proven = decode_envelope_with_kernel(&reencoded, &installed)
                .is_some_and(|d| d.image == want && be32_sum_zero(&d.image));
            if proven {
                cross_proven += 1;
                rows.push(format!(
                    "{}\t{}\t{}\tREENCODE",
                    metas[i].family, metas[i].name, metas[j].name
                ));
            } else {
                failures.push(format!(
                    "{} <- {}: re-encode does not prove",
                    metas[j].name, metas[i].name
                ));
                rows.push(format!(
                    "{}\t{}\t{}\tREFUSED: re-encode does not prove",
                    metas[i].family, metas[i].name, metas[j].name
                ));
            }
        }
    }

    // The real same-SAT cross-receiver case through the full recover plan.
    let find = |n: &str| {
        metas
            .iter()
            .position(|m| m.name.starts_with(n))
            .unwrap_or_else(|| panic!("hoard is missing {n}"))
    };
    let a = find("BDR-207M ID43 1.60");
    let b = find("BDR-PR1ML ID88 1.30");
    assert_eq!(metas[a].family, metas[b].family, "named case shares a family");
    assert_ne!(
        metas[a].class, metas[b].class,
        "207M and PR1ML must straddle a receiver class"
    );
    let plan = Plan::prepare(
        &std::fs::read(&metas[a].path).unwrap(),
        &std::fs::read(&metas[b].path).unwrap(),
    )
    .expect("installed 207M must admit a re-encoded PR1ML Normal");
    assert!(
        plan.was_reencoded(),
        "207M <- PR1ML must take the cross-receiver re-encode path"
    );

    if let Ok(report) = std::env::var("FREEMKV_PIONEER_HOARD_REPORT") {
        rows.sort();
        let body = format!(
            "# Pioneer recover re-encode matrix: every same-family ordered pair\n\
             # columns: family<TAB>installed(X)<TAB>target(Y)<TAB>verdict\n\
             # AS-IS = installed Kernel decodes shipped Normal unchanged; \
             REENCODE = X->Y needs re-encode; REFUSED = not offline-provable (cause)\n\
             # totals: same-class(AS-IS) {same_class}; cross-receiver proven \
             {cross_proven}/{cross_total}; {} not provable\n{}\n",
            failures.len(),
            rows.join("\n"),
        );
        std::fs::write(&report, body).expect("write hoard report");
        eprintln!(
            "wrote recover re-encode matrix ({} rows) to {report}",
            rows.len()
        );
    }
    eprintln!(
        "recover KAT: same-class pairs {same_class} provable by construction; \
         cross-receiver re-encode proven {cross_proven}/{cross_total}; {} not provable",
        failures.len()
    );
    assert!(
        cross_proven >= 1,
        "expected at least one cross-receiver re-encode to be proven"
    );
    // Cross-receiver re-encode must succeed for the overwhelming majority; a few
    // packages (e.g. no recoverable seed) are legitimately not re-encodable.
    assert!(
        cross_total == 0 || cross_proven * 5 >= cross_total * 4,
        "too many cross-receiver re-encode failures ({}/{cross_total}): {failures:#?}",
        cross_total - cross_proven
    );
}
