use super::*;
use anyhow::ensure;

/// A Kernel-only partial capture is validatable and named by the backup notice
/// (a Kernel-only tar is still not a flashable `Bundle::from_tar_bytes`).
#[test]
fn patched_oem_backup_preserves_body_and_original_receiver_when_configured() {
    let Ok(path) = std::env::var("PIONEER_PATCHED_KERNEL_FIXTURE") else {
        return;
    };
    let body = std::fs::read(path).unwrap();
    let env = build_kernel_envelope(&body, "PIONEER BD-RW   BDR-UD04").unwrap();
    let decoded = pioneer_optical::envelope::decode_envelope(&env).unwrap();
    assert_eq!(
        decoded.image, body,
        "backup must retain the actual patched body"
    );
    let header = pioneer_optical::envelope::header_info(&env).unwrap();
    assert_eq!(header.revision, "1.00");
    let tar = assemble_tar(&[env]).unwrap();
    let provenance = package_provenance(&tar);
    assert!(!provenance.kernel_oem);
    assert!(provenance.kernel_generation_patched);
    // The planner must not confuse our patched marker with a newer receiver.
    assert_eq!(
        crate::backends::pioneer::k::receiver_generation(&decoded.image),
        Some(false)
    );
}

#[test]
fn kernel_only_partial_backup_validates_and_is_reported_partial() {
    let mut body = vec![0u8; 0x10000];
    body[0xFE] = 0x01;
    body[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    body[0x1008..0x1010].copy_from_slice(b"ID58    ");
    body[0x1010..0x1014].copy_from_slice(b"ID5 ");
    body[0x2000..0x2008].copy_from_slice(&[0xae, 0xfe, 0, 0, 0, 0, 0xae, 0xf0]);
    let sum = body
        .chunks(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .fold(0u32, |a, w| a.wrapping_add(w));
    body[0x1020..0x1024].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    let env = build_kernel_envelope(&body, "PIONEER BD-RW   BDR-UD04").unwrap();
    let tar = assemble_tar(&[env]).unwrap();
    validate_envelope_package(&tar, "BD-RW BDR-UD04")
        .expect("a Kernel-only partial backup must validate");
    assert!(Bundle::from_tar_bytes(&tar).is_err());
    let roles = component_roles(&tar);
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].0, "kernel");
}

#[test]
fn read_access_probe_retries_only_short_reads_and_reknocks() {
    struct Access {
        responses: std::collections::VecDeque<Result<Vec<u8>>>,
        order: Vec<&'static str>,
    }
    impl ScsiDevice for Access {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            assert_eq!(cdb, [0x3c, 2, 0xb0, 0x40, 0, 0, 0, 0, 4, 0]);
            assert_eq!(len, 4);
            self.order.push("read");
            self.responses.pop_front().expect("unexpected probe retry")
        }
        fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
            assert_eq!(cdb, [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]);
            assert!(data.is_empty());
            self.order.push("knock");
            Ok(())
        }
        fn describe(&self) -> String {
            "read permission test".into()
        }
    }
    let sense = |key, asc, ascq| {
        Err(crate::platform::ScsiSenseError::new(key, asc, ascq, "test sense").into())
    };
    for (responses, ok) in [
        (vec![Ok(vec![0; 4])], true),
        (vec![sense(5, 0x24, 0)], false), // still locked after the knock
        (vec![sense(5, 0x20, 0)], false),
        (vec![sense(4, 0x44, 0)], false),
        (vec![Err(anyhow::anyhow!("transport disconnected"))], false),
        (vec![Ok(vec![]), Ok(vec![0; 2]), Ok(vec![0; 4])], true),
        (vec![Ok(vec![]), Ok(vec![]), Ok(vec![])], false),
        (vec![Ok(vec![0; 3]), sense(5, 0x24, 0)], false),
    ] {
        let attempts = responses.len();
        let mut dev = Access {
            responses: responses.into(),
            order: Vec::new(),
        };
        assert_eq!(prepare_firmware_read(&mut dev).is_ok(), ok);
        assert!(dev.responses.is_empty());
        assert_eq!(dev.order, ["knock", "read"].repeat(attempts));
    }
}

#[test]
fn deep_read_salvages_around_an_unreadable_span_and_reports_the_gap() {
    // A device that serves byte `off & 0xff` everywhere except a bad window
    // `[bad, bad+badlen)`, where every read intersecting it errors.
    struct Spotty {
        bad: usize,
        badlen: usize,
    }
    impl ScsiDevice for Spotty {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            let start = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
            if start < self.bad + self.badlen && start + len > self.bad {
                bail!("unreadable span");
            }
            Ok((0..len).map(|i| ((start + i) & 0xff) as u8).collect())
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "spotty".into()
        }
    }
    let len = 0x200usize;
    let bad = 0x100usize;
    let badlen = 0x10usize;
    let mut dev = Spotty { bad, badlen };
    let image = read_region_deep(&mut dev, 0, len).unwrap();
    assert_eq!(image.len(), len);
    // Readable bytes are their offset mod 256; the bad window is zero-filled.
    for (i, b) in image.iter().enumerate() {
        if (bad..bad + badlen).contains(&i) {
            assert_eq!(*b, 0, "byte {i:#x} should be a zero-filled gap");
        } else {
            assert_eq!(*b, (i & 0xff) as u8, "byte {i:#x} should be recovered");
        }
    }
    // A fully readable region salvages byte-for-byte with no gaps.
    let mut clean = Spotty {
        bad: len,
        badlen: 0,
    };
    let whole = read_region_deep(&mut clean, 0, len).unwrap();
    assert!(whole
        .iter()
        .enumerate()
        .all(|(i, b)| *b == (i & 0xff) as u8));
}

#[test]
fn deep_read_aborts_when_the_drive_drops_out_mid_region() {
    // Serves the first read, then every read (including the liveness probe)
    // fails: a dropped drive must not cost millions of retries.
    struct Dying {
        reads: usize,
    }
    impl ScsiDevice for Dying {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            self.reads += 1;
            let _ = cdb;
            if self.reads > 1 {
                bail!("drive gone");
            }
            Ok(vec![0u8; len])
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "dying".into()
        }
    }
    let mut dev = Dying { reads: 0 };
    let err = read_region_deep(&mut dev, 0, READ_CHUNK * 24).unwrap_err();
    assert!(format!("{err:#}").contains("stopped responding"), "{err:#}");
    assert!(
        dev.reads <= DEEP_RETRIES + 3,
        "too many retries: {}",
        dev.reads
    );
}

#[test]
fn push_gap_merges_contiguous_runs_and_separates_disjoint_ones() {
    let mut g = Vec::new();
    push_gap(&mut g, 0x100, 4);
    push_gap(&mut g, 0x104, 4); // contiguous with the previous → merged
    push_gap(&mut g, 0x200, 8); // disjoint → new entry
    assert_eq!(g, vec![(0x100, 8), (0x200, 8)]);
}

#[test]
fn deep_read_bails_when_the_whole_region_is_unreadable() {
    struct Dead;
    impl ScsiDevice for Dead {
        fn command_in(&mut self, _c: &[u8], _a: usize) -> Result<Vec<u8>> {
            bail!("dead drive")
        }
        fn command_out(&mut self, _c: &[u8], _d: &[u8]) -> Result<()> {
            bail!("dead drive")
        }
        fn describe(&self) -> String {
            "dead".into()
        }
    }
    let err = read_region_deep(&mut Dead, 0, 0x200).unwrap_err();
    assert!(format!("{err:#}").contains("entirely unreadable"));
}

/// Refuses any command after the two identity reads and records writes so the
/// unsupported-capture tests exercise production preflight without firmware I/O.
struct IdentityOnlyCapture {
    inquiry: Vec<u8>,
    f1: Vec<u8>,
    commands: usize,
    writes: usize,
}
impl ScsiDevice for IdentityOnlyCapture {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        self.commands += 1;
        match self.commands {
            1 => {
                assert_eq!(cdb, [0x12, 0, 0, 0, 36, 0]);
                assert_eq!(len, 36);
                Ok(self.inquiry.clone())
            }
            2 => {
                assert_eq!(cdb, [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0]);
                assert_eq!(len, 48);
                Ok(self.f1.clone())
            }
            _ => panic!("unsupported identity must not trigger firmware or service reads"),
        }
    }
    fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
        self.writes += 1;
        bail!("unsupported identity must not trigger service entry or writes")
    }
    fn command_out_strict(&mut self, cdb: &[u8], bytes: &[u8]) -> Result<()> {
        self.command_out(cdb, bytes)
    }
    fn describe(&self) -> String {
        "identity-only test transport".into()
    }
}

#[test]
fn unsupported_capture_identity_stops_before_service_entry_or_memory_reads() {
    let mut inquiry = vec![b' '; 36];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"BD-RW   BDR-TEST");
    inquiry[32..36].copy_from_slice(b"1.00");
    for hardware in [b"ATA 0009", b"SCSI0001", b"UNKNOWN "] {
        let mut f1 = vec![0; 48];
        f1[16..24].copy_from_slice(hardware);
        let mut dev = IdentityOnlyCapture {
            inquiry: inquiry.clone(),
            f1,
            commands: 0,
            writes: 0,
        };
        assert!(capture_signed_candidate(&mut dev)
            .unwrap_err()
            .to_string()
            .contains("H8/SAT hardware identity"));
        assert_eq!(dev.commands, 2);
        assert_eq!(dev.writes, 0);
    }
    for length in [0, 16, 23, 47, 49] {
        let mut dev = IdentityOnlyCapture {
            inquiry: inquiry.clone(),
            f1: vec![0; length],
            commands: 0,
            writes: 0,
        };
        assert!(capture_signed_candidate(&mut dev).is_err());
        assert_eq!(dev.commands, 2);
        assert_eq!(dev.writes, 0);
    }
}

#[test]
fn embedded_identity_preserves_spacing_and_rejects_model_prefixes() {
    let mut inquiry = [b' '; 36];
    inquiry[8..15].copy_from_slice(b"PIONEER");
    inquiry[16..30].copy_from_slice(b"BD-RW  BDR-212");
    assert!(embedded_envelope_id(&inquiry, b"PIONEER BD-RW   BDR-212M\0", b"").is_err());
    assert_eq!(
        embedded_envelope_id(&inquiry, b"PIONEER BD-RW   BDR-212\0", b"").unwrap(),
        "PIONEER BD-RW   BDR-212"
    );
}

#[test]
fn embedded_identity_accepts_model_only_product() {
    // Some OEM/engineering units (e.g. BDR-PR1MD2MCM) report the model with no
    // media-class token in INQUIRY product. The envelope id is recovered from
    // the embedded vendor+model string at the drive's own spacing.
    let mut inquiry = [b' '; 36];
    inquiry[8..15].copy_from_slice(b"PIONEER");
    inquiry[16..29].copy_from_slice(b"BDR-PR1MD2MCM");
    assert_eq!(
        embedded_envelope_id(&inquiry, b"\x00PIONEER BDR-PR1MD2MCM\x00", b"").unwrap(),
        "PIONEER BDR-PR1MD2MCM"
    );
    // A model that is a prefix of the embedded model must not match.
    let mut shorter = [b' '; 36];
    shorter[8..15].copy_from_slice(b"PIONEER");
    shorter[16..28].copy_from_slice(b"BDR-PR1MD2MC");
    assert!(embedded_envelope_id(&shorter, b"\x00PIONEER BDR-PR1MD2MCM\x00", b"").is_err());
}

/// Replay captured address-space bytes without opening a device. Reject
/// every command outside the bounded reference backup transaction.
struct CaptureReplay {
    dump: Vec<u8>,
    reads: usize,
    knocks: usize,
    corrupt_second_pass: bool,
}

impl ScsiDevice for CaptureReplay {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb == [0x12, 0, 0, 0, len as u8, 0] && matches!(len, 36 | 96) {
            if let Ok(path) = std::env::var("PIONEER_INQUIRY_FIXTURE") {
                let bytes = std::fs::read(path).unwrap();
                return Ok(bytes[..len].to_vec());
            }
            let mut data = vec![0; len];
            data[8..16].copy_from_slice(b"PIONEER ");
            data[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
            data[32..36].copy_from_slice(b"1.14");
            return Ok(data);
        }
        if cdb == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
            assert_eq!(len, 48);
            let mut data = vec![0; 48];
            data[16..24].copy_from_slice(b"SAT 8A10");
            return Ok(data);
        }
        if cdb == [0x3c, 0x06, 0, 0, 0x30, 0, 0, 0, 0x20, 0] {
            bail!("Pioneer does not implement the MTK identity buffer");
        }
        // Firmware reads are gated until the read-unlock knock; the crate
        // issues the knock itself before every read.
        if self.knocks == 0 {
            return Err(
                crate::platform::ScsiSenseError::new(5, 0x24, 0, "read access locked").into(),
            );
        }
        assert_eq!(cdb.len(), 10);
        assert_eq!(&cdb[..3], &[0x3c, 2, 0xb0]);
        // 24-bit length field: top byte is 0 for anything under 16 MiB; low two bytes carry the length.
        let cdb_len = ((cdb[6] as usize) << 16) | ((cdb[7] as usize) << 8) | cdb[8] as usize;
        assert_eq!(cdb_len, len);
        assert_eq!(cdb[9], 0);
        assert!((1..=READ_CHUNK).contains(&len));
        let offset = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
        if offset + len > self.dump.len() {
            return Err(crate::platform::ScsiSenseError::new(
                5,
                0x24,
                0,
                "outside saved address space",
            )
            .into());
        }
        let mut data = self.dump[offset..offset + len].to_vec();
        if self.corrupt_second_pass && offset == 0x400000 && self.reads > 0 {
            data[0] ^= 1;
        }
        self.reads += 1;
        Ok(data)
    }

    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        assert_eq!(cdb, [0x3b, 2, 0x41, 0xa5, 0xaa, 0xaa, 0, 0, 0, 0]);
        assert!(data.is_empty());
        self.knocks += 1;
        Ok(())
    }

    fn describe(&self) -> String {
        "saved capture replay; no hardware".into()
    }
}

#[test]
fn unknown_sat_receiver_stops_after_kernel_capture() {
    let mut dump = vec![0; NORMAL_IMAGE_BASE];
    dump[KERNEL_IMAGE_BASE + 0x1000..KERNEL_IMAGE_BASE + 0x1008].copy_from_slice(b"SAT 8A10");
    // The replay has no Normal bytes. Any read beyond the Kernel panics,
    // proving rejection occurs before guessing Normal geometry.
    let mut replay = CaptureReplay {
        dump,
        reads: 0,
        knocks: 0,
        corrupt_second_pass: false,
    };
    let error = read_h8_image_pair(&mut replay).unwrap_err();
    assert!(error.to_string().contains("receiver layout is unsupported"));
    assert!(replay.knocks >= 1, "the crate knocks before reading");
    assert!(replay.reads > 0);
}

#[test]
fn oem_pair_rebuilds_from_decoded_images_when_configured() {
    let Ok(path) = std::env::var("PIONEER_PAIR_KAT") else {
        return;
    };
    let source = Bundle::from_tar_bytes(&std::fs::read(path).unwrap()).unwrap();
    let kernel = source
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .unwrap();
    let normal = source
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .unwrap();
    let k = pioneer_optical::envelope::decode_envelope(&kernel.bytes).unwrap();
    let detected = pioneer_optical::envelope::builder::kernel_layout_from_image(&k.image).unwrap();
    let expected = match k.info().layout.as_str() {
        "kernel-front" => pioneer_optical::envelope::Layout::KernelFront,
        "kernel-derived" => pioneer_optical::envelope::Layout::KernelDerived,
        other => panic!("unsupported Kernel layout: {other}"),
    };
    assert_eq!(detected, expected);
    let n = pioneer_optical::envelope::decode_envelope_with_kernel(&normal.bytes, &k).unwrap();
    let h = pioneer_optical::envelope::header_info(&normal.bytes).unwrap();
    let output = construct_signed_candidate(&k.image, &n.image, &h.id, &h.revision).unwrap();
    validate_envelope_package(&output, &h.model).unwrap();
    let rebuilt = Bundle::from_tar_bytes(&output).unwrap();
    let rk = rebuilt
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .unwrap();
    let rn = rebuilt
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .unwrap();
    assert_eq!(&rn.bytes[..0x160], &normal.bytes[..0x160]);
    if h.destination == "GENERAL" || h.destination.starts_with("ID") {
        assert_eq!(&rn.bytes[0x1f0..0x200], &normal.bytes[0x1f0..0x200]);
    } else {
        assert!(rn.bytes[0x1f0..]
            .starts_with(format!("NORMAL.{}\0", h.revision.replace('.', "")).as_bytes()));
    }
    if pioneer_optical::envelope::builder::normal_authentication_from_kernel(&k.image)
        == Some(pioneer_optical::envelope::builder::NormalAuthentication::ScaledChecksumOnly)
    {
        assert!(
            pioneer_optical::envelope::builder::normal_authentication_valid(
                &normal.bytes,
                &k.image
            )
        );
        assert!(
            pioneer_optical::envelope::builder::normal_authentication_valid(&rn.bytes, &k.image)
        );
    } else {
        assert_eq!(
            pioneer_optical::envelope::signature::verify_normal_signature(&normal.bytes),
            pioneer_optical::envelope::signature::verify_normal_signature(&rn.bytes)
        );
    }
    let dk = pioneer_optical::envelope::decode_envelope(&rk.bytes).unwrap();
    let dn = pioneer_optical::envelope::decode_envelope_with_kernel(&rn.bytes, &dk).unwrap();
    assert_eq!(dk.image, k.image);
    assert_eq!(dn.image, n.image);
    // Provenance: an OEM-sourced pair rebuilds a byte-exact OEM kernel and,
    // when its decoded normal is in the OEM normal table, a byte-exact OEM
    // normal too. normal_oem must agree with the pioneer_n lookup.
    let prov = package_provenance(&output);
    assert!(
        prov.kernel_oem,
        "OEM kernel must be recognized as byte-exact"
    );
    let normal_in_table =
        crate::backends::pioneer::n::lookup(&format!("{:x}", Sha256::digest(&n.image))).is_some();
    assert_eq!(
        prov.normal_oem, normal_in_table,
        "normal_oem must reflect the pioneer_n table"
    );
    let mut damaged = rn.bytes.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(validate_envelope_pair(&rk.bytes, &damaged, &h.model).is_err());
    assert_eq!(
        unique_embedded_date(&n.image),
        Some(h.generated_date.as_str())
    );
}

#[test]
fn unparseable_package_has_no_oem_provenance() {
    let p = package_provenance(b"not a tar at all");
    assert!(!p.kernel_oem && !p.normal_oem);
}

#[test]
fn corpus_encoding_seeds_when_configured() {
    let Ok(root) = std::env::var("PIONEER_INSTALLER_CORPUS_KAT_ROOT") else {
        return;
    };
    let mut dirs = vec![std::path::PathBuf::from(root)];
    let mut seen = std::collections::HashSet::new();
    let mut groups = std::collections::BTreeMap::<String, std::collections::BTreeSet<u32>>::new();
    let mut seeds = std::collections::BTreeMap::<u32, usize>::new();
    let mut unknown = std::collections::BTreeMap::<String, usize>::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if !path.to_string_lossy().ends_with(".installer.tar") {
                continue;
            }
            let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(path).unwrap()) else {
                continue;
            };
            for component in bundle.components {
                if !seen.insert(Sha256::digest(&component.bytes).to_vec()) {
                    continue;
                }
                let Some(decoded) = pioneer_optical::envelope::decode_envelope(&component.bytes)
                else {
                    continue;
                };
                let h = pioneer_optical::envelope::header_info(&component.bytes).unwrap();
                let group = format!(
                    "{}/{}/{}/{}/{}",
                    h.model,
                    h.hardware_version,
                    h.destination,
                    h.kind.map_or("unknown", |t| t.as_str()),
                    decoded.info().layout.as_str()
                );
                if let Some(seed) = decoded.encoding_seed() {
                    *seeds.entry(seed).or_default() += 1;
                    groups.entry(group).or_default().insert(seed);
                } else {
                    *unknown.entry(group).or_default() += 1;
                }
            }
        }
    }
    eprintln!("Encoding seeds (hex, distinct envelopes): {seeds:x?}");
    eprintln!("Non-LCG decoded key tables: {unknown:?}");
    eprintln!(
        "Seed groups: {}; varying groups: {}",
        groups.len(),
        groups.values().filter(|s| s.len() > 1).count()
    );
    for (group, values) in groups.iter().filter(|(_, s)| s.len() > 1) {
        eprintln!("varying seeds: {group}: {values:x?}");
    }
    assert!(!groups.is_empty());
}

#[test]
fn embedded_build_date_preserves_formats_and_rejects_ambiguity() {
    assert_eq!(
        unique_embedded_date(b"model 1.10 Sep18,2008   "),
        Some("Sep18,2008")
    );
    assert_eq!(
        unique_embedded_date(b"model 1.14 20/06/15   "),
        Some("20/06/15")
    );
    assert_eq!(unique_embedded_date(b"Sep18,2008 20/06/15"), None);
    assert_eq!(unique_embedded_date(b"20/06/15 20/06/15"), Some("20/06/15"));
    assert_eq!(
        unique_embedded_date(b"Sep18,2008 Sep18,2008"),
        Some("Sep18,2008")
    );
    assert_eq!(unique_embedded_date(b"20/06/15 20/06/16"), None);
    assert_eq!(
        unique_embedded_date(b"20/00/15 20/13/15 20/06/00 20/06/32"),
        None
    );
    assert_eq!(unique_embedded_date(b"99/99/99 20/06/15"), Some("20/06/15"));
    assert_eq!(unique_embedded_date(b"Sep00,2008"), None);
    assert_eq!(unique_embedded_date(b"Bog18,2008"), None);
}

#[test]
fn scaled_image_capture_uses_receiver_length_when_configured() {
    let Ok(path) = std::env::var("PIONEER_SCALED_KERNEL_FIXTURE") else {
        return;
    };
    let kernel = pioneer_optical::envelope::decode_envelope(&std::fs::read(path).unwrap()).unwrap();
    let normal_bytes =
        std::fs::read(std::env::var("PIONEER_SCALED_NORMAL_FIXTURE").unwrap()).unwrap();
    let normal =
        pioneer_optical::envelope::decode_envelope_with_kernel(&normal_bytes, &kernel).unwrap();
    let h = pioneer_optical::envelope::header_info(&normal_bytes).unwrap();
    let (vendor, product) = h.id.split_once(' ').unwrap();
    let product = product.trim();
    assert!(vendor.len() <= 8 && product.len() <= 16 && h.revision.len() == 4);
    let mut inquiry = vec![b' '; 36];
    inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
    inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
    inquiry[32..36].copy_from_slice(h.revision.as_bytes());
    let mut dump = vec![0; 0x600000];
    dump[KERNEL_IMAGE_BASE..NORMAL_IMAGE_BASE].copy_from_slice(&kernel.image);
    dump[NORMAL_IMAGE_BASE..NORMAL_IMAGE_BASE + normal.image.len()].copy_from_slice(&normal.image);
    struct Replay {
        inner: CaptureReplay,
        inquiry: Vec<u8>,
        hardware: Vec<u8>,
    }
    impl ScsiDevice for Replay {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            if cdb == [0x12, 0, 0, 0, 36, 0] {
                return Ok(self.inquiry.clone());
            }
            if cdb == [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0] {
                let mut out = vec![0; 48];
                out[16..24].copy_from_slice(&self.hardware);
                return Ok(out);
            }
            self.inner.command_in(cdb, len)
        }
        fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
            self.inner.command_out(cdb, data)
        }
        fn describe(&self) -> String {
            "saved older image replay; no hardware".into()
        }
    }
    let mut replay = Replay {
        inner: CaptureReplay {
            dump,
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        },
        inquiry,
        hardware: kernel.image[0x1000..0x1008].to_vec(),
    };
    // The modern length field is executable code here, not the image size.
    assert_ne!(
        u32::from_be_bytes(normal.image[20..24].try_into().unwrap()) as usize,
        normal.image.len()
    );
    let (captured_kernel, captured_normal, revision, _) = read_h8_image_pair(&mut replay).unwrap();
    assert_eq!(captured_kernel, kernel.image);
    assert_eq!(captured_normal, normal.image);
    assert_eq!(revision, h.revision);
}

#[test]
fn corpus_kernel_sharing_by_catalog_model_when_configured() {
    let Ok(root) = std::env::var("PIONEER_KERNEL_SHARING_ROOT") else {
        return;
    };
    let mut dirs = vec![std::path::PathBuf::from(root)];
    let mut cache = std::collections::HashMap::<Vec<u8>, Option<String>>::new();
    let mut groups =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    let mut undecodable = std::collections::BTreeSet::new();
    let mut invalid_packages = 0;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if !path.to_string_lossy().ends_with(".installer.tar") {
                continue;
            }
            let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(&path).unwrap()) else {
                invalid_packages += 1;
                continue;
            };
            let Some(component) = bundle.components.iter().find(|c| c.role == Role::Kernel) else {
                continue;
            };
            let envelope_hash = Sha256::digest(&component.bytes).to_vec();
            let raw_hash = cache.entry(envelope_hash.clone()).or_insert_with(|| {
                pioneer_optical::envelope::decode_envelope(&component.bytes)
                    .map(|d| format!("{:x}", Sha256::digest(&d.image)))
            });
            let Some(raw_hash) = raw_hash else {
                undecodable.insert(envelope_hash);
                continue;
            };
            // Keep catalog models even when they use identical envelope bytes.
            let model = path
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            groups.entry(raw_hash.clone()).or_default().insert(model);
        }
    }
    assert!(!groups.is_empty(), "no decoded Kernels in corpus");
    let shared = groups.values().filter(|models| models.len() > 1).count();
    let models: std::collections::BTreeSet<_> = groups.values().flatten().collect();
    eprintln!(
        "Kernel sharing: {} decoded image hashes, {} catalog models, {shared} cross-model groups, {} undecodable envelope hashes, {invalid_packages} invalid packages",
        groups.len(),
        models.len(),
        undecodable.len()
    );
    for (hash, models) in groups.iter().filter(|(_, m)| m.len() > 1) {
        eprintln!("shared Kernel {hash}: {models:?}");
    }
}

#[test]
fn corpus_kernel_dispatcher_selects_recorded_wrapper_when_configured() {
    let Ok(root) = std::env::var("PIONEER_INSTALLER_CORPUS_KAT_ROOT") else {
        return;
    };
    let mut dirs = vec![std::path::PathBuf::from(root)];
    let mut seen = std::collections::HashSet::new();
    let mut front = 0;
    let mut derived = 0;
    let mut literal_id_in_kernel = 0;
    let mut missing_literal_ids = Vec::new();
    let mut unrecognized = Vec::new();
    let mut unsupported_kernels = std::collections::BTreeMap::<String, usize>::new();
    let mut unsupported_normals = std::collections::BTreeMap::<String, usize>::new();
    let mut raw_metadata =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    let mut kernel_revision_literals = 0;
    let mut kernel_date_literals = 0;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if !path.to_string_lossy().ends_with(".installer.tar") {
                continue;
            }
            let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(&path).unwrap()) else {
                continue;
            };
            let Some(component) = bundle.components.iter().find(|c| c.role == Role::Kernel) else {
                continue;
            };
            let digest = Sha256::digest(&component.bytes);
            if !seen.insert(digest.to_vec()) {
                continue;
            }
            let Some(decoded) = pioneer_optical::envelope::decode_envelope(&component.bytes) else {
                let hardware = pioneer_optical::envelope::header_info(&component.bytes)
                    .map(|h| h.hardware_version)
                    .unwrap_or_else(|| "invalid header".into());
                *unsupported_kernels.entry(hardware).or_default() += 1;
                continue;
            };
            if let Some(h) = pioneer_optical::envelope::header_info(&component.bytes) {
                kernel_revision_literals += usize::from(
                    !h.revision.is_empty()
                        && decoded
                            .image
                            .windows(h.revision.len())
                            .any(|w| w == h.revision.as_bytes()),
                );
                kernel_date_literals += usize::from(
                    !h.generated_date.is_empty()
                        && decoded
                            .image
                            .windows(h.generated_date.len())
                            .any(|w| w == h.generated_date.as_bytes()),
                );
                raw_metadata
                    .entry(format!("{:x}", Sha256::digest(&decoded.image)))
                    .or_default()
                    .insert(format!("{} {} {}", h.model, h.revision, h.generated_date));
            }
            if let Some(normal) = bundle.components.iter().find(|c| c.role == Role::Main) {
                if pioneer_optical::envelope::decode_envelope_with_kernel(&normal.bytes, &decoded)
                    .is_none()
                {
                    let hardware = pioneer_optical::envelope::header_info(&normal.bytes)
                        .map(|h| h.hardware_version)
                        .unwrap_or_else(|| "invalid header".into());
                    *unsupported_normals.entry(hardware).or_default() += 1;
                }
                if let Some(header) = pioneer_optical::envelope::header_info(&normal.bytes) {
                    if decoded
                        .image
                        .windows(header.id.len())
                        .any(|w| w == header.id.as_bytes())
                    {
                        literal_id_in_kernel += 1;
                    } else {
                        missing_literal_ids.push(path.display().to_string());
                    }
                }
            }
            let expected = match decoded.info().layout.as_str() {
                "kernel-front" => {
                    front += 1;
                    pioneer_optical::envelope::Layout::KernelFront
                }
                "kernel-derived" => {
                    derived += 1;
                    pioneer_optical::envelope::Layout::KernelDerived
                }
                _ => continue,
            };
            let detected =
                pioneer_optical::envelope::builder::kernel_layout_from_image(&decoded.image);
            if detected.is_none() {
                let signature = bundle
                    .components
                    .iter()
                    .find(|c| c.role == Role::Main)
                    .map(|c| {
                        pioneer_optical::envelope::signature::verify_normal_signature(&c.bytes)
                    });
                unrecognized.push(format!("{} signature={signature:?}", path.display()));
            } else {
                assert_eq!(detected, Some(expected), "{}", path.display());
            }
        }
    }
    assert!(front > 0 && derived > 0);
    eprintln!("Undecodable unique Kernels by hardware: {unsupported_kernels:?}");
    eprintln!("Undecodable receiver Normal per unique Kernel: {unsupported_normals:?}");
    eprintln!(
        "Kernel header revision/date literals in decoded image: {kernel_revision_literals}/{kernel_date_literals}"
    );
    for (hash, labels) in raw_metadata.iter().filter(|(_, labels)| labels.len() > 1) {
        eprintln!("identical raw Kernel {hash}, envelope labels: {labels:?}");
    }
    eprintln!(
        "Kernel dispatcher corpus: {front} front, {derived} derived unique envelopes; {} unrecognized",
        unrecognized.len()
    );
    eprintln!(
        "OEM ID literal in Kernel: {literal_id_in_kernel}; missing in {} cases",
        missing_literal_ids.len()
    );
    for path in missing_literal_ids.iter().take(12) {
        eprintln!("missing ID: {path}");
    }
    for path in &unrecognized {
        eprintln!("unrecognized: {path}");
    }
}

/// Replay the production capture with a declared identity and real decoded
/// image bytes. Only the read-unlock knock is permitted on the data-out path.
struct DeclaredIdentityCapture {
    inquiry: Vec<u8>,
    hardware: String,
    replay: CaptureReplay,
    firmware_writes: usize,
}
impl ScsiDevice for DeclaredIdentityCapture {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb == pioneer_optical::cdb::inquiry(36) {
            return Ok(self.inquiry.clone());
        }
        if cdb == pioneer_optical::cdb::vendor_identity() {
            let mut bytes = vec![b' '; len];
            bytes[16..24].copy_from_slice(self.hardware.as_bytes());
            return Ok(bytes);
        }
        self.replay.command_in(cdb, len)
    }
    fn command_out(&mut self, cdb: &[u8], bytes: &[u8]) -> Result<()> {
        if cdb != pioneer_optical::cdb::knock() || !bytes.is_empty() {
            self.firmware_writes += 1;
            bail!("identity mismatch must not issue firmware writes or service commands");
        }
        self.replay.command_out(cdb, bytes)
    }
    fn command_out_strict(&mut self, cdb: &[u8], bytes: &[u8]) -> Result<()> {
        self.command_out(cdb, bytes)
    }
    fn describe(&self) -> String {
        "declared identity / decoded-body capture replay".into()
    }
}

/// A relabeled envelope is not capture evidence for its declared model. Admit
/// this negative case only when another envelope pair has identical encoded
/// payloads and supplies a different ID independently found in decoded bytes.
fn prove_declared_identity_refusal(
    source_path: &std::path::Path,
    source_kernel: &[u8],
    source_normal: &[u8],
    inquiry: &[u8],
    kernel: &[u8],
    normal: &[u8],
    declared: &pioneer_optical::envelope::HeaderInfo,
) -> Result<()> {
    let mut authentic = None;
    for entry in std::fs::read_dir(source_path.parent().context("source has no directory")?)? {
        let path = entry?.path();
        if !path.to_string_lossy().ends_with(".installer.tar") {
            continue;
        }
        let bundle = Bundle::from_tar_bytes(&std::fs::read(path)?)?;
        let (Some(k), Some(n)) = (
            bundle.components.iter().find(|c| c.role == Role::Kernel),
            bundle.components.iter().find(|c| c.role == Role::Main),
        ) else {
            continue;
        };
        if k.bytes.get(512..) != source_kernel.get(512..)
            || n.bytes.get(512..) != source_normal.get(512..)
        {
            continue;
        }
        let candidate = pioneer_optical::envelope::header_info(&n.bytes)
            .context("matching-payload Normal has no parsed header")?;
        if candidate.model == declared.model {
            continue;
        }
        let (vendor, product) = candidate
            .id
            .split_once(' ')
            .context("alternate identity has no vendor/product")?;
        if pioneer_optical::ident::embedded_envelope_id(vendor, product, &[kernel, normal])
            .is_ok_and(|id| id == candidate.id)
        {
            ensure!(
                authentic.as_ref().is_none_or(
                    |prior: &pioneer_optical::envelope::HeaderInfo| prior.id == candidate.id
                ),
                "multiple alternate payload-bound identities are embedded in the decoded body"
            );
            authentic = Some(candidate);
        }
    }
    let authentic = authentic
        .context("no matching-payload header identity is independently proven in decoded bytes")?;
    ensure!(
        authentic.model != declared.model,
        "identity refusal is not a demonstrated header/body model disagreement"
    );
    ensure!(
        authentic.hardware_version == declared.hardware_version
            && authentic.kernel_version == declared.kernel_version,
        "identity refusal differs beyond the demonstrated model relabeling"
    );
    let (vendor, product) = authentic
        .id
        .split_once(' ')
        .context("OEM identity has no vendor/product")?;
    let body_id = pioneer_optical::ident::embedded_envelope_id(vendor, product, &[kernel, normal])
        .context("alternative OEM identity is absent from the actual decoded bytes")?;
    ensure!(
        body_id == authentic.id,
        "embedded body identity differs from the identical-payload envelope header"
    );
    let original_error = embedded_envelope_id(inquiry, kernel, normal).unwrap_err();
    ensure!(
        original_error.to_string() == "captured firmware has no envelope identity matching INQUIRY",
        "unexpected declared identity refusal: {original_error:#}"
    );
    ensure!(
        kernel.len() == NORMAL_IMAGE_BASE - KERNEL_IMAGE_BASE,
        "unsupported replay Kernel size"
    );
    let mut dump = vec![0; NORMAL_IMAGE_BASE + normal.len()];
    dump[KERNEL_IMAGE_BASE..NORMAL_IMAGE_BASE].copy_from_slice(kernel);
    dump[NORMAL_IMAGE_BASE..].copy_from_slice(normal);
    let mut dev = DeclaredIdentityCapture {
        inquiry: inquiry.to_vec(),
        hardware: declared.hardware_version.clone(),
        replay: CaptureReplay {
            dump,
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        },
        firmware_writes: 0,
    };
    let error = capture_signed_candidate(&mut dev).unwrap_err();
    ensure!(
        error.to_string() == original_error.to_string(),
        "production capture refused for another reason: {error:#}"
    );
    ensure!(
        dev.replay.reads > 0 && dev.replay.knocks > 0,
        "production capture did not inspect the decoded image bytes"
    );
    ensure!(
        dev.firmware_writes == 0,
        "production capture attempted firmware writes"
    );
    eprintln!(
        "declared model {:?} refused; decoded body proves {:?}; only read-unlock data-out allowed",
        declared.id, body_id
    );
    Ok(())
}

/// A checksum-invalid Normal cannot become a complete backup. The production
/// capture must retain only the independently valid Kernel, with no firmware
/// write or service command beyond its explicit read-unlock knock.
fn prove_checksum_invalid_normal_refusal(
    inquiry: &[u8],
    kernel: &[u8],
    normal: &[u8],
    hardware: &str,
    product: &str,
) -> Result<()> {
    use pioneer_optical::envelope::{Envelope, NormalLayout, NormalLayoutError};
    ensure!(
        zero_be32_sum(kernel),
        "negative checksum case has an invalid Kernel"
    );
    ensure!(
        !zero_be32_sum(normal),
        "negative checksum case has no checksum defect"
    );
    let layout = NormalLayout::from_kernel(kernel, KERNEL_IMAGE_BASE as u32)?;
    let region = layout.resolve(&normal[..24])?;
    ensure!(
        region.address() as usize == NORMAL_IMAGE_BASE && region.length() == normal.len(),
        "negative checksum case has unproven geometry"
    );
    ensure!(
        layout.validate(normal) == Err(NormalLayoutError::ImageChecksum),
        "negative checksum case has another structural defect"
    );
    ensure!(
        kernel.len() == NORMAL_IMAGE_BASE - KERNEL_IMAGE_BASE,
        "unsupported replay Kernel size"
    );
    let mut dump = vec![0; NORMAL_IMAGE_BASE + normal.len()];
    dump[KERNEL_IMAGE_BASE..NORMAL_IMAGE_BASE].copy_from_slice(kernel);
    dump[NORMAL_IMAGE_BASE..].copy_from_slice(normal);
    let mut dev = DeclaredIdentityCapture {
        inquiry: inquiry.to_vec(),
        hardware: hardware.to_owned(),
        replay: CaptureReplay {
            dump,
            reads: 0,
            knocks: 0,
            corrupt_second_pass: false,
        },
        firmware_writes: 0,
    };
    let output = capture_signed_candidate(&mut dev)?;
    validate_envelope_package(&output, product)?;
    let partial = Bundle::from_backup_tar_bytes(&output)?;
    ensure!(
        partial.components.len() == 1 && partial.components[0].role == Role::Kernel,
        "production capture retained checksum-invalid Normal"
    );
    let restored = Envelope::load(&partial.components[0].bytes)?;
    ensure!(
        restored.image == kernel,
        "production partial backup changed valid Kernel bytes"
    );
    ensure!(
        dev.replay.reads > 0 && dev.replay.knocks > 0,
        "production partial capture did not read firmware"
    );
    ensure!(
        dev.firmware_writes == 0,
        "production partial capture attempted firmware writes"
    );
    eprintln!(
        "checksum-invalid Normal refused; production capture retained exact valid Kernel only; only read-unlock data-out allowed"
    );
    Ok(())
}

#[test]
fn corpus_builder_reports_hardware_coverage_when_configured() {
    let Ok(root) = std::env::var("PIONEER_INSTALLER_CORPUS_KAT_ROOT") else {
        return;
    };
    let mut dirs = vec![std::path::PathBuf::from(root)];
    let mut seen_hardware = std::collections::HashSet::new();
    let all_pairs = std::env::var_os("PIONEER_ALL_PAIRS_KAT").is_some();
    let mut built = 0;
    let mut eligible_sat_pairs = 0;
    let mut refused_non_sat_pairs = 0;
    let mut refused_relabelled_sat_pairs = 0;
    let mut refused_checksum_sat_pairs = 0;
    let mut refused_identity_shapes = 0;
    let mut canonical_headers = 0;
    let mut canonical_names = 0;
    let mut unsigned_candidates = 0;
    let mut exact_text = 0;
    let mut exact_name = 0;
    let mut generated_name = 0;
    let mut signature_range_match = 0;
    let mut failures = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if !path.to_string_lossy().ends_with(".installer.tar") {
                continue;
            }
            let Ok(bundle) = Bundle::from_tar_bytes(&std::fs::read(&path).unwrap()) else {
                continue;
            };
            let (Some(kernel), Some(normal)) = (
                bundle.components.iter().find(|c| c.role == Role::Kernel),
                bundle.components.iter().find(|c| c.role == Role::Main),
            ) else {
                continue;
            };
            let Some(k) = pioneer_optical::envelope::decode_envelope(&kernel.bytes) else {
                continue;
            };
            let Some(n) = pioneer_optical::envelope::decode_envelope_with_kernel(&normal.bytes, &k)
            else {
                continue;
            };
            let Some(h) = pioneer_optical::envelope::header_info(&normal.bytes) else {
                continue;
            };
            let identity = if all_pairs {
                format!(
                    "{:x}:{:x}",
                    Sha256::digest(&kernel.bytes),
                    Sha256::digest(&normal.bytes)
                )
            } else {
                h.hardware_version.clone()
            };
            if !seen_hardware.insert(identity) {
                continue;
            }
            let words: Vec<_> = h.id.split_whitespace().collect();
            if words.len() < 2 {
                // The declared ID provides no separate vendor. Do not invent
                // whitespace or a vendor/product split to make a capture fit.
                assert_eq!(
                    pioneer_optical::ident::embedded_envelope_id("", &h.id, &[&k.image, &n.image]),
                    Err(pioneer_optical::ident::IdentError::IncompleteIdentity),
                    "{}: malformed declared identity was accepted",
                    path.display()
                );
                refused_identity_shapes += 1;
                eprintln!("declared identity parser refused missing vendor/product separation without I/O: {} ID={:?}",path.display(),h.id);
                continue;
            }
            let vendor = words[0];
            let product = words[1..].join(" ");
            if vendor.len() > 8 || product.len() > 16 {
                failures.push(format!(
                    "{}: OEM ID cannot form a SCSI INQUIRY",
                    h.hardware_version
                ));
                continue;
            }
            let mut inquiry = [b' '; 36];
            inquiry[0] = 5;
            inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
            inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
            assert!(
                h.revision.is_ascii() && h.revision.len() >= 4,
                "{}: unusable INQUIRY revision {:?}",
                path.display(),
                h.revision
            );
            inquiry[32..36].copy_from_slice(&h.revision.as_bytes()[..4]);
            // Match the production backup capability boundary exactly. Every
            // non-SAT pair must prove refusal using its usable identity before
            // any firmware access; every SAT pair keeps the reconstruction gate.
            if !h.hardware_version.as_bytes().starts_with(b"SAT ") {
                assert_eq!(
                    h.hardware_version.len(),
                    8,
                    "{}: unusable hardware identity",
                    path.display()
                );
                let mut f1 = vec![b' '; 48];
                f1[16..24].copy_from_slice(h.hardware_version.as_bytes());
                let mut dev = IdentityOnlyCapture {
                    inquiry: inquiry.to_vec(),
                    f1,
                    commands: 0,
                    writes: 0,
                };
                let error = capture_signed_candidate(&mut dev).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("H8/SAT hardware identity required"),
                    "{}: unsupported capture did not reach the hardware preflight refusal: {error:#}",
                    path.display()
                );
                assert_eq!(
                    dev.commands,
                    2,
                    "{}: capture went beyond identity reads",
                    path.display()
                );
                assert_eq!(
                    dev.writes,
                    0,
                    "{}: unsupported capture issued a write",
                    path.display()
                );
                refused_non_sat_pairs += 1;
                eprintln!(
                    "capture refused before firmware I/O: {} hardware={}",
                    path.display(),
                    h.hardware_version
                );
                continue;
            }
            eligible_sat_pairs += 1;
            let id = match embedded_envelope_id(&inquiry, &k.image, &n.image) {
                Ok(id) => id,
                Err(error) => {
                    prove_declared_identity_refusal(&path, &kernel.bytes, &normal.bytes, &inquiry, &k.image, &n.image, &h)
                        .unwrap_or_else(|proof_error| panic!("{}: unexpected identity failure: {error:#}; negative evidence failed: {proof_error:#}", path.display()));
                    refused_relabelled_sat_pairs += 1;
                    eprintln!(
                        "capture refused declared header/body disagreement: {}",
                        path.display()
                    );
                    continue;
                }
            };
            assert_eq!(id, h.id);
            match construct_signed_candidate(&k.image, &n.image, &id, &h.revision) {
                Ok(output) => {
                    validate_envelope_package(&output, &product).unwrap_or_else(|error| {
                        panic!(
                            "{}: hardware={} reconstructed package validation failed: {error:#}",
                            path.display(),
                            h.hardware_version
                        )
                    });
                    let rebuilt = Bundle::from_tar_bytes(&output).unwrap();
                    let rebuilt_normal = rebuilt
                        .components
                        .iter()
                        .find(|c| c.role == Role::Main)
                        .unwrap();
                    let rebuilt_kernel = rebuilt
                        .components
                        .iter()
                        .find(|c| c.role == Role::Kernel)
                        .unwrap();
                    let decoded_kernel =
                        pioneer_optical::envelope::Envelope::load(&rebuilt_kernel.bytes).unwrap();
                    let decoded_normal = pioneer_optical::envelope::Envelope::load_with_kernel(
                        &rebuilt_normal.bytes,
                        &decoded_kernel,
                    )
                    .unwrap();
                    assert_eq!(
                        decoded_kernel.image,
                        k.image,
                        "{}: restored Kernel bytes changed",
                        path.display()
                    );
                    assert_eq!(
                        decoded_normal.image,
                        n.image,
                        "{}: restored Normal bytes changed",
                        path.display()
                    );
                    let image_hash = format!("{:x}", Sha256::digest(&n.image));
                    let metadata = super::super::n::lookup(&image_hash);
                    let source_verification =
                        pioneer_optical::envelope::signature::verify_normal_signature(
                            &normal.bytes,
                        );
                    let rebuilt_verification =
                        pioneer_optical::envelope::signature::verify_normal_signature(
                            &rebuilt_normal.bytes,
                        );
                    let source_authentication =
                        pioneer_optical::envelope::builder::normal_authentication_valid(
                            &normal.bytes,
                            &k.image,
                        );
                    let rebuilt_authentication =
                        pioneer_optical::envelope::builder::normal_authentication_valid(
                            &rebuilt_normal.bytes,
                            &k.image,
                        );
                    let signature_matches = if pioneer_optical::envelope::builder::normal_authentication_from_kernel(&k.image) == Some(pioneer_optical::envelope::builder::NormalAuthentication::ScaledChecksumOnly) {
                        source_authentication && rebuilt_authentication
                    } else {
                        source_verification == rebuilt_verification
                    };
                    let rebuilt_header =
                        pioneer_optical::envelope::header_info(&rebuilt_normal.bytes).unwrap();
                    let actual_tag = std::str::from_utf8(&k.image[0x1008..0x1010])
                        .unwrap()
                        .trim_matches([' ', '\0']);
                    let raw_header_matches = rebuilt_normal.bytes[..0x160] == normal.bytes[..0x160];
                    let raw_name_matches =
                        rebuilt_normal.bytes[0x1f0..0x200] == normal.bytes[0x1f0..0x200];
                    if !raw_header_matches || !raw_name_matches {
                        let catalog_header = metadata
                            .and_then(|m| m.header.as_ref())
                            .expect("unexpected header drift without catalog evidence");
                        assert_ne!(
                            h.kernel_version,
                            actual_tag,
                            "{}: no declared/body Kernel tag discrepancy",
                            path.display()
                        );
                        assert_eq!(
                            rebuilt_header.kernel_version,
                            actual_tag,
                            "{}: restored Normal not bound to captured Kernel",
                            path.display()
                        );
                        assert_eq!(
                            &rebuilt_normal.bytes[..0x160],
                            &catalog_header[..0x160],
                            "{}: canonical OEM header differs",
                            path.display()
                        );
                        assert_eq!(
                            &rebuilt_normal.bytes[0x1f0..0x200],
                            &catalog_header[0x1f0..0x200],
                            "{}: canonical OEM filename differs",
                            path.display()
                        );
                        let mut expected = normal.bytes[..0x160].to_vec();
                        for label in [
                            b"Kernel Version : ".as_slice(),
                            b"Destination : ".as_slice(),
                        ] {
                            let at = expected
                                .windows(label.len())
                                .position(|w| w == label)
                                .unwrap()
                                + label.len();
                            assert_eq!(
                                &expected[at..at + h.kernel_version.len()],
                                h.kernel_version.as_bytes(),
                                "{}: unrelated header drift",
                                path.display()
                            );
                            assert_eq!(actual_tag.len(), h.kernel_version.len());
                            expected[at..at + actual_tag.len()]
                                .copy_from_slice(actual_tag.as_bytes());
                        }
                        assert_eq!(
                            &rebuilt_normal.bytes[..0x160],
                            expected,
                            "{}: header changed beyond actual captured Kernel tag",
                            path.display()
                        );
                        canonical_headers += usize::from(!raw_header_matches);
                        canonical_names += usize::from(!raw_name_matches);
                        eprintln!("canonical captured identity restored: {} declared_tag={} actual_body_tag={} (exact OEM catalog header/name and both decoded bodies)",path.display(),h.kernel_version,actual_tag);
                    }
                    if let Some(entry) = metadata {
                        assert_eq!(
                            &rebuilt_normal.bytes
                                [pioneer_optical::envelope::builder::NORMAL_SIGNATURE_RANGE],
                            entry.signature.as_slice(),
                            "{}: catalog OEM signature bytes changed",
                            path.display()
                        );
                        assert!(
                            signature_matches && rebuilt_authentication,
                            "{}: known OEM receiver authentication changed",
                            path.display()
                        );
                        assert!(
                            package_provenance(&output).normal_oem,
                            "{}: exact catalog body/signature lost OEM provenance",
                            path.display()
                        );
                        let update = pioneer_optical::envelope::Update::load(
                            &rebuilt_kernel.bytes,
                            &rebuilt_normal.bytes,
                        )
                        .unwrap_or_else(|e| {
                            panic!("{}: strict OEM pair refused: {e}", path.display())
                        });
                        if !raw_header_matches || !raw_name_matches {
                            pioneer_optical::receiver::Receiver::detect_with_kernel(
                                update.normal(),
                                update.kernel(),
                            )
                            .unwrap_or_else(|e| {
                                panic!(
                                    "{}: canonical captured receiver refused: {e}",
                                    path.display()
                                )
                            });
                        }
                    } else {
                        assert!(
                            rebuilt_normal.bytes
                                [pioneer_optical::envelope::builder::NORMAL_SIGNATURE_RANGE]
                                .iter()
                                .all(|&b| b == 0),
                            "{}: unknown image was not explicitly unsigned",
                            path.display()
                        );
                        assert!(
                            !package_provenance(&output).normal_oem,
                            "{}: unknown image falsely marked OEM",
                            path.display()
                        );
                        let signed = super::super::normal_prepare::pair(&rebuilt_kernel.bytes,&rebuilt_normal.bytes).unwrap_or_else(|e|panic!("{}: unsigned candidate cannot prepare for captured receiver: {e:#}",path.display()));
                        assert_eq!(
                            signed.kernel().image,
                            k.image,
                            "{}: signing preparation changed Kernel",
                            path.display()
                        );
                        assert_eq!(
                            signed.normal().image,
                            n.image,
                            "{}: signing preparation changed Normal",
                            path.display()
                        );
                        unsigned_candidates += 1;
                        eprintln!("unsigned candidate proved: {} body_sha256={image_hash} zero signature, false OEM provenance, exact decoded bodies, strict receiver-valid signing preparation",path.display());
                    }
                    built += 1;
                    exact_text +=
                        usize::from(rebuilt_normal.bytes[..0x160] == normal.bytes[..0x160]);
                    exact_name += usize::from(
                        rebuilt_normal.bytes[0x1f0..0x200] == normal.bytes[0x1f0..0x200],
                    );
                    if h.destination != "GENERAL" && !h.destination.starts_with("ID") {
                        let image_hash = format!("{:x}", Sha256::digest(&n.image));
                        let captured_name = &normal.bytes[0x1f0..0x200];
                        let rebuilt_name = &rebuilt_normal.bytes[0x1f0..0x200];
                        if let Some(header) = super::super::n::lookup(&image_hash)
                            .and_then(|entry| entry.header.as_ref())
                        {
                            // The baseline builder restores the hash-matched OEM header,
                            // including its original embedded filename.
                            assert_eq!(
                                rebuilt_name,
                                captured_name,
                                "{}: hardware={} Normal body SHA256={image_hash}: captured OEM filename changed",
                                path.display(),
                                h.hardware_version
                            );
                            assert_eq!(
                                rebuilt_name,
                                &header[0x1f0..0x200],
                                "{}: hardware={} Normal body SHA256={image_hash}: catalog OEM filename changed",
                                path.display(),
                                h.hardware_version
                            );
                        } else {
                            assert!(
                                rebuilt_name.starts_with(
                                    format!("NORMAL.{}\0", h.revision.replace('.', "")).as_bytes()
                                ),
                                "{}: hardware={} revision={} destination={:?} rebuilt embedded name={rebuilt_name:?}, original embedded name={captured_name:?}",
                                path.display(),
                                h.hardware_version,
                                h.revision,
                                h.destination
                            );
                            generated_name += usize::from(rebuilt_name != captured_name);
                        }
                    }
                    signature_range_match += usize::from(metadata.is_some() && signature_matches);
                }
                Err(error) => {
                    if !zero_be32_sum(&n.image)
                        && error.to_string()
                            == "images do not satisfy Pioneer H8/SAT image structure"
                    {
                        prove_checksum_invalid_normal_refusal(
                            &inquiry,
                            &k.image,
                            &n.image,
                            &h.hardware_version,
                            &product,
                        )
                        .unwrap_or_else(|proof| {
                            panic!(
                                "{}: checksum refusal proof failed: {proof:#}",
                                path.display()
                            )
                        });
                        refused_checksum_sat_pairs += 1;
                        eprintln!(
                            "capture refused checksum-invalid Normal: {}",
                            path.display()
                        );
                        continue;
                    }
                    eprintln!(
                        "structure diagnostic: {} kernel_len={} normal_len={} kernel_sum={} normal_sum={} kernel_hardware={:?} normal_descriptor={:?} normal_declared={} scaled={:?}",
                        path.display(),
                        k.image.len(),
                        n.image.len(),
                        zero_be32_sum(&k.image),
                        zero_be32_sum(&n.image),
                        &k.image[0x1000..0x1008],
                        &n.image[..16],
                        u32::from_be_bytes(n.image[20..24].try_into().unwrap()),
                        pioneer_optical::envelope::builder::scaled_normal_geometry_from_kernel(
                            &k.image
                        )
                    );
                    failures.push(format!(
                        "{}: hardware={}: {error:#}",
                        path.display(),
                        h.hardware_version
                    ));
                }
            }
        }
    }
    eprintln!(
        "capture capability: {eligible_sat_pairs} SAT pairs ({refused_relabelled_sat_pairs} relabeled headers refused after decoded-body proof; {refused_checksum_sat_pairs} checksum-invalid Normals excluded with exact Kernel-only capture); {refused_non_sat_pairs} non-SAT pairs refused before firmware I/O"
    );
    eprintln!(
        "builder corpus: {built} built, {} unsupported; {exact_text} exact textual headers, {exact_name} exact names, {signature_range_match} matching signature ranges",
        failures.len()
    );
    for failure in &failures {
        eprintln!("unsupported: {failure}");
    }
    assert!(
        failures.is_empty(),
        "decoded OEM pairs failed reconstruction: {failures:?}"
    );
    assert!(built > 0);
    assert_eq!(
        built + refused_relabelled_sat_pairs + refused_checksum_sat_pairs,
        eligible_sat_pairs,
        "SAT pairs lack reconstruction or explicit production refusal evidence"
    );
    assert_eq!(
        exact_text + canonical_headers,
        built,
        "unexplained textual header drift"
    );
    eprintln!("explicit generated Normal filenames: {generated_name}");
    assert_eq!(
        exact_name + generated_name + canonical_names,
        built,
        "unexplained embedded filename drift"
    );
    assert_eq!(
        signature_range_match + unsigned_candidates,
        built,
        "unexplained signature change"
    );
    assert_eq!(
        built
            + refused_relabelled_sat_pairs
            + refused_checksum_sat_pairs
            + refused_non_sat_pairs
            + refused_identity_shapes,
        seen_hardware.len(),
        "decoded pairs lack positive or explicit negative evidence"
    );
    eprintln!("final evidence: {built} reconstructed ({signature_range_match} OEM signatures, {unsigned_candidates} explicit unsigned candidates); {canonical_headers} canonical actual-body headers, {canonical_names} canonical filenames; {refused_non_sat_pairs} non-SAT preflight refusals, {refused_relabelled_sat_pairs} relabeled identity refusals, {refused_checksum_sat_pairs} invalid Normal checksums with Kernel-only preservation, {refused_identity_shapes} malformed declared identity parser refusals");
}

#[test]
#[ignore = "requires FREEMKV_HOARD OEM corpus"]
fn production_s12jx_105_backup_reproduces_both_oem_envelopes() {
    let root = std::path::PathBuf::from(std::env::var_os("FREEMKV_HOARD").unwrap())
        .join("images/pioneer/sat/8F01/ID72/1.05");
    let kernel = std::fs::read(
        root.join("kernel/2d8b2749bb35c787a2a216e777018443fe9582ae52988d93b32f26b8fdc58e72.enc"),
    )
    .unwrap();
    let normal = std::fs::read(
        root.join("normal/a44eacdd94bc91a1484e3ed7c1762df61c5cab71155deacc3da99e23e000b380.enc"),
    )
    .unwrap();
    let k = pioneer_optical::envelope::decode_envelope(&kernel).unwrap();
    let n = pioneer_optical::envelope::decode_envelope_with_kernel(&normal, &k).unwrap();
    let header = pioneer_optical::envelope::header_info(&normal).unwrap();
    let output =
        construct_signed_candidate(&k.image, &n.image, &header.id, &header.revision).unwrap();
    let rebuilt = Bundle::from_tar_bytes(&output).unwrap();
    assert_eq!(
        rebuilt
            .components
            .iter()
            .find(|c| c.role == Role::Kernel)
            .unwrap()
            .bytes,
        kernel
    );
    assert_eq!(
        rebuilt
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap()
            .bytes,
        normal
    );
    let provenance = package_provenance(&output);
    assert!(provenance.kernel_oem && provenance.normal_oem);
}

#[test]
#[ignore = "requires FREEMKV_OEM_AUDIT report.json from pioneer_oem_tables"]
fn production_every_audited_normal_rebuilds_through_backup() {
    use pioneer_optical::envelope::{decode_envelope, decode_envelope_with_kernel, header_info};
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var_os("FREEMKV_OEM_AUDIT").unwrap()).unwrap(),
    )
    .unwrap();
    let files = report["files"].as_array().unwrap();
    let kernels: Vec<_> = files
        .iter()
        .filter(|r| r["status"] == "kernel_byte_exact" || r["status"] == "kernel_not_byte_exact")
        .map(|r| {
            let bytes = std::fs::read(r["path"].as_str().unwrap()).unwrap();
            (
                header_info(&bytes).unwrap(),
                decode_envelope(&bytes).unwrap(),
            )
        })
        .collect();
    let mut rebuilt_hashes = std::collections::HashSet::new();
    for row in files.iter().filter(|r| r["status"] == "normal_byte_exact") {
        let bytes = std::fs::read(row["path"].as_str().unwrap()).unwrap();
        let h = header_info(&bytes).unwrap();
        let expected_hash = row["image_sha256"].as_str().unwrap();
        let (k, n) = kernels
            .iter()
            .filter(|(kh, _)| {
                kh.hardware_version == h.hardware_version
                    && kh.kernel_version == h.kernel_version
                    && kh.kernel_version2 == h.kernel_version2
            })
            .find_map(|(_, k)| {
                let n = decode_envelope_with_kernel(&bytes, k)?;
                (format!("{:x}", Sha256::digest(&n.image)) == expected_hash).then_some((k, n))
            })
            .unwrap_or_else(|| panic!("no audited Kernel for {}", row["path"]));
        let output = construct_signed_candidate(&k.image, &n.image, &h.id, &h.revision)
            .unwrap_or_else(|e| panic!("{}: {e:#}", row["path"]));
        validate_envelope_package(&output, &h.model)
            .unwrap_or_else(|e| panic!("backup validation {}: {e:#}", row["path"]));
        let bundle = Bundle::from_tar_bytes(&output).unwrap();
        let normal = &bundle
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap()
            .bytes;
        assert!(pioneer_optical::envelope::builder::normal_authentication_valid(normal, &k.image));
        let decoded = decode_envelope_with_kernel(normal, k).unwrap();
        assert_eq!(decoded.image, n.image, "{}", row["path"]);
        assert!(package_provenance(&output).normal_oem);
        rebuilt_hashes.insert(expected_hash.to_owned());
    }
    assert_eq!(
        rebuilt_hashes.len(),
        459,
        "full eligible corpus must be exercised"
    );
}

#[test]
fn self_signed_live_capture_is_a_verified_offline_candidate_when_configured() {
    let Ok(path) = std::env::var("PIONEER_LIVE_DUMP_FIXTURE") else {
        return;
    };
    let dump = std::fs::read(path).unwrap();
    assert_eq!(dump.len(), 0x600000);
    let mut replay = CaptureReplay {
        dump: dump.clone(),
        reads: 0,
        knocks: 0,
        corrupt_second_pass: false,
    };
    let candidate = capture_signed_candidate(&mut replay).unwrap();
    if let Ok(path) = std::env::var("PIONEER_SIGNED_BACKUP_KAT_OUTPUT") {
        std::fs::write(path, &candidate).unwrap();
    }
    assert!(replay.knocks >= 1, "the crate knocks before reading");
    validate_envelope_package(&candidate, "BD-RW BDR-UD04").unwrap();
    let bundle = Bundle::from_tar_bytes(&candidate).unwrap();
    let kernel = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .unwrap();
    let normal = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .unwrap();
    let candidate_steps =
        crate::backends::pioneer::offline_pair_data_out(&kernel.bytes, &normal.bytes).unwrap();
    if let Ok(path) = std::env::var("PIONEER_UD04_AUTOFLASHER_BUNDLE_FIXTURE") {
        let original_bytes = std::fs::read(path).unwrap();
        validate_envelope_package(&original_bytes, "BD-RW BDR-UD04").unwrap();
        let original = Bundle::from_tar_bytes(&original_bytes).unwrap();
        let original_kernel = original
            .components
            .iter()
            .find(|c| c.role == Role::Kernel)
            .unwrap();
        let original_normal = original
            .components
            .iter()
            .find(|c| c.role == Role::Main)
            .unwrap();
        assert_eq!(&normal.bytes[..0x160], &original_normal.bytes[..0x160]);
        assert_eq!(
            &normal.bytes[0x160..0x170],
            &original_normal.bytes[0x160..0x170]
        );
        assert_eq!(
            &normal.bytes[0x1c0..0x200],
            &original_normal.bytes[0x1c0..0x200]
        );
        assert_ne!(&normal.bytes[0x200..], &original_normal.bytes[0x200..]);
        let generated_kernel = pioneer_optical::envelope::decode_envelope(&kernel.bytes).unwrap();
        let supplied_kernel =
            pioneer_optical::envelope::decode_envelope(&original_kernel.bytes).unwrap();
        let generated_normal = pioneer_optical::envelope::decode_envelope_with_kernel(
            &normal.bytes,
            &generated_kernel,
        )
        .unwrap();
        let supplied_normal = pioneer_optical::envelope::decode_envelope_with_kernel(
            &original_normal.bytes,
            &supplied_kernel,
        )
        .unwrap();
        // UD04 is a known OEM kernel in pioneer_k.bin, so the whole kernel
        // envelope is reconstructed byte-for-byte (real revision/date + the
        // OEM raw front key).
        assert_eq!(kernel.bytes, original_kernel.bytes);
        // The Normal is still self-made with the obvious placeholder seed 0.
        assert_eq!(generated_normal.encoding_seed(), Some(0));
        assert_eq!(generated_kernel.image, supplied_kernel.image);
        assert_eq!(generated_normal.image, supplied_normal.image);
        assert_eq!(
            &normal.bytes[0x1f0..0x200],
            &original_normal.bytes[0x1f0..0x200]
        );
        let original_steps = crate::backends::pioneer::offline_pair_data_out(
            &original_kernel.bytes,
            &original_normal.bytes,
        )
        .unwrap();
        assert_eq!(candidate_steps.len(), original_steps.len());
        for (candidate, original) in candidate_steps.iter().zip(&original_steps) {
            assert_eq!(candidate.stage, original.stage);
            assert_eq!(candidate.cdb, original.cdb);
            assert_eq!(candidate.data.len(), original.data.len());
        }
    }
    let decoded_kernel = pioneer_optical::envelope::decode_envelope(&kernel.bytes).unwrap();
    let decoded_normal =
        pioneer_optical::envelope::decode_envelope_with_kernel(&normal.bytes, &decoded_kernel)
            .unwrap();
    assert_eq!(decoded_kernel.image, dump[0x400000..0x410000]);
    assert_eq!(decoded_normal.image, dump[0x410000..0x5d7500]);
    let output =
        std::env::temp_dir().join(format!("ud04-signed-candidate-{}.tar", std::process::id()));
    let _ = std::fs::remove_file(&output);
    let drive = crate::backends::pioneer::Pioneer::new();
    crate::backends::pioneer::file_info::plan_offline(
        &candidate,
        &crate::backends::pioneer::PACKAGE,
        "BD-RW BDR-UD04",
        false,
    )
    .unwrap();
    replay.knocks = 0;
    replay.reads = 0;
    crate::engine::backup(&mut replay, &drive, &output, false).unwrap();
    let saved = std::fs::read(&output).unwrap();
    validate_envelope_package(&saved, "BD-RW BDR-UD04").unwrap();
    std::fs::remove_file(&output).unwrap();
    replay.knocks = 0;
    replay.reads = 0;
    replay.corrupt_second_pass = true;
    assert!(capture_signed_candidate(&mut replay).is_err());
}

// Synthetic firmware with independent H8 fixtures; no proprietary bytes or
// corpus environment variables are required for this regression in CI.
fn bounded_backup_fixture() -> (Vec<u8>, Vec<u8>) {
    fn put(image: &mut [u8], offset: usize, hex: &str) {
        let bytes: Vec<_> = hex
            .split_whitespace()
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect();
        image[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }
    fn fix(image: &mut [u8]) {
        let end = image.len() - 4;
        image[end..].fill(0);
        let sum = image
            .as_chunks::<4>()
            .0
            .iter()
            .fold(0u32, |s, w| s.wrapping_add(u32::from_be_bytes(*w)));
        image[end..].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    }
    let mut kernel = vec![0; 0x10000];
    kernel[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    kernel[0x1008..0x1010].copy_from_slice(b"GENERAL ");
    kernel[0x1010..0x1014].copy_from_slice(b"0000");
    let id = b"PIONEER BD-RW   BDR-UD04";
    kernel[0x2000..0x2000 + id.len()].copy_from_slice(id);
    put(&mut kernel, 0x40, "ae fe 00 00 00 00 ae f0");
    put(
        &mut kernel,
        0x100,
        "7a 20 00 00 01 00 47 0c 7a 20 00 00 02 00 47 04 01 f0 65 05",
    );
    // Forward-rotation decode loop the receiver reads after the XOR-skip branch;
    // without it pioneer-optical 0.15.0 returns UnknownRotation from Update::load.
    put(
        &mut kernel,
        0x114,
        "79 63 00 1f 0d 31 5e 40 01 22 01 f0 64 40 11 70 54 70",
    );
    put(
        &mut kernel,
        0x200,
        "18 bb 1a 91 0c b9 78 10 6a 2a 00 41 00 00 78 10 6a 28 00 40 20 00 1c 8a 47 04 5e 40 10 20 0a 0b ab 10 45 de",
    );
    put(
        &mut kernel,
        0x400,
        "1a a2 7a 01 00 40 00 00 01 00 6b 23 00 41 00 14 7a 13 00 41 00 00 40 06 01 00 6d 10 0a 82 1f b1 46 f6",
    );
    fix(&mut kernel);
    let mut normal = vec![0; 0x2000];
    normal[..16].copy_from_slice(&id[..16]);
    normal[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    normal[24..32].copy_from_slice(b"GENERAL ");
    fix(&mut normal);
    (kernel, normal)
}

#[test]
fn reverse_rotation_backup_validates_without_relaxing_integrity() {
    use pioneer_optical::envelope::{builder, Layout};
    let (mut kernel, normal) = bounded_backup_fixture();
    // Change the independent receiver fixture's shift helper from right to left.
    assert_eq!(&kernel[0x122..0x124], &[0x11, 0x70]);
    kernel[0x122] = 0x10;
    let end = kernel.len() - 4;
    kernel[end..].fill(0);
    let sum = kernel
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |s, w| s.wrapping_add(u32::from_be_bytes(*w)));
    kernel[end..].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    assert_eq!(
        builder::normal_rotation_from_kernel(&kernel),
        Some(builder::NormalRotation::Reverse)
    );
    let archive =
        construct_signed_candidate(&kernel, &normal, "PIONEER BD-RW   BDR-UD04", "1.00").unwrap();
    validate_envelope_package(&archive, "BD-RW BDR-UD04").unwrap();
    let bundle = Bundle::from_tar_bytes(&archive).unwrap();
    let k = &bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .unwrap()
        .bytes;
    let n = &bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .unwrap()
        .bytes;
    let decoded_kernel = pioneer_optical::envelope::decode_envelope(k).unwrap();
    let decoded =
        pioneer_optical::envelope::decode_envelope_with_kernel(n, &decoded_kernel).unwrap();
    assert_eq!(decoded.info().layout, Layout::NormalReverse);
    assert_eq!(decoded.image, normal);
    let mut corrupted = n.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(validate_envelope_pair(k, &corrupted, "BD-RW BDR-UD04").is_err());
    let mut bad_signature = n.clone();
    bad_signature[0x170] = 1;
    let error = validate_envelope_pair(k, &bad_signature, "BD-RW BDR-UD04").unwrap_err();
    assert!(error.to_string().contains("Normal's signature"));
    assert!(error.to_string().contains("Use Dump"));
}

struct BoundedBackupReplay {
    inner: CaptureReplay,
    firmware_reads: Vec<(usize, usize)>,
    refused_reads: usize,
}
impl BoundedBackupReplay {
    fn new(kernel: &[u8], normal: &[u8]) -> Self {
        let mut dump = vec![0; NORMAL_IMAGE_BASE + normal.len()];
        dump[KERNEL_IMAGE_BASE..NORMAL_IMAGE_BASE].copy_from_slice(kernel);
        dump[NORMAL_IMAGE_BASE..].copy_from_slice(normal);
        Self {
            inner: CaptureReplay {
                dump,
                reads: 0,
                knocks: 0,
                corrupt_second_pass: false,
            },
            firmware_reads: Vec::new(),
            refused_reads: 0,
        }
    }
}
impl ScsiDevice for BoundedBackupReplay {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb.starts_with(&[0x3c, 2, 0xb0]) {
            let address = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
            // Reproduce the user's successful Kernel reads and 05/24/00 for
            // address zero / the upper probe, and reject every unrelated read.
            if address < KERNEL_IMAGE_BASE || address + len > self.inner.dump.len() {
                self.refused_reads += 1;
                return Err(
                    crate::platform::ScsiSenseError::new(5, 0x24, 0, "outside firmware").into(),
                );
            }
            self.firmware_reads.push((address, len));
        }
        self.inner.command_in(cdb, len)
    }
    fn command_out(&mut self, cdb: &[u8], data: &[u8]) -> Result<()> {
        self.inner.command_out(cdb, data)
    }
    fn describe(&self) -> String {
        "bounded firmware replay; no hardware".into()
    }
}

#[test]
fn backup_succeeds_without_probing_unrelated_or_address_zero_memory() {
    let (kernel, normal) = bounded_backup_fixture();
    let mut replay = BoundedBackupReplay::new(&kernel, &normal);
    let archive = capture_signed_candidate(&mut replay).unwrap();
    assert_eq!(replay.refused_reads, 0);
    assert_eq!(
        replay.firmware_reads,
        [
            (0x400000, 4),
            (0x400000, 0x8000),
            (0x408000, 0x8000),
            (0x400000, 0x8000),
            (0x408000, 0x8000),
            (0x410000, 24),
            (0x410000, 24),
            (0x410000, 0x2000),
            (0x410000, 0x2000),
        ]
    );
    let bundle = Bundle::from_backup_tar_bytes(&archive).unwrap();
    assert_eq!(bundle.components.len(), 2);
    let k = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .unwrap();
    let n = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .unwrap();
    validate_envelope_pair(&k.bytes, &n.bytes, "BD-RW BDR-UD04").unwrap();
    let decoded = pioneer_optical::envelope::decode_envelope(&k.bytes).unwrap();
    assert_eq!(decoded.image, kernel);
    let decoded_normal =
        pioneer_optical::envelope::decode_envelope_with_kernel(&n.bytes, &decoded).unwrap();
    assert_eq!(decoded_normal.image, normal);
    assert_eq!(decoded_normal.encoding_seed(), Some(0));
    assert!(
        n.bytes[pioneer_optical::envelope::builder::NORMAL_SIGNATURE_RANGE]
            .iter()
            .all(|b| *b == 0)
    );
    assert!(!package_provenance(&archive).normal_oem);
}

#[test]
fn unknown_kernel_geometry_stops_before_any_normal_read() {
    let (mut kernel, normal) = bounded_backup_fixture();
    // Preserve the checksum while removing the layout proof.
    kernel.swap(0x400, 0x404);
    let mut replay = BoundedBackupReplay::new(&kernel, &normal);
    let error = capture_signed_candidate(&mut replay).unwrap_err();
    assert!(format!("{error:#}").contains("pioneer.normal_layout.unsupported"));
    assert!(replay
        .firmware_reads
        .iter()
        .all(|(a, n)| a + n <= NORMAL_IMAGE_BASE));
    assert_eq!(replay.refused_reads, 0);
}

#[test]
fn invalid_normal_keeps_verified_kernel_but_cannot_be_full_rollback() {
    let (kernel, mut normal) = bounded_backup_fixture();
    let valid =
        construct_signed_candidate(&kernel, &normal, "PIONEER BD-RW   BDR-UD04", "1.14").unwrap();
    normal[0x100] ^= 1;
    let mut replay = BoundedBackupReplay::new(&kernel, &normal);
    let archive = capture_signed_candidate(&mut replay).unwrap();
    let bundle = Bundle::from_backup_tar_bytes(&archive).unwrap();
    assert_eq!(bundle.components.len(), 1);
    assert_eq!(bundle.components[0].role, Role::Kernel);
    assert!(crate::backends::pioneer::verify_preflash_backup(&archive, &valid).is_err());
    assert_eq!(replay.refused_reads, 0);
}

#[test]
fn xd06u_backup_normal_matches_oem_exactly_when_configured() {
    let Ok(root) = std::env::var("PIONEER_XD06_RECONSTRUCTION_FIXTURE") else {
        return;
    };
    let root = std::path::Path::new(&root);
    let backup_kernel = std::fs::read(root.join("backup-kernel.enc")).unwrap();
    let kernel = pioneer_optical::envelope::decode_envelope(&backup_kernel).unwrap();
    let normal = std::fs::read(root.join("backup.bin")).unwrap();
    let held = std::fs::read(root.join("held.enc")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&normal)),
        "7c1175169d33c37e296103569ba5ead98b492bd9d668e850a99cf1a44ed82679"
    );
    let header = pioneer_optical::envelope::header_info(&held).unwrap();
    let rebuilt =
        construct_signed_candidate(&kernel.image, &normal, &header.id, &header.revision).unwrap();
    let bundle = Bundle::from_backup_tar_bytes(&rebuilt).unwrap();
    let n = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Main)
        .unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&n.bytes)),
        "1a84f11ecb50a89b4f1a4b09eb4ccc4d69fea785149be78aa51c58cadae16b2a"
    );
    assert_eq!(n.bytes, held);
    let k = bundle
        .components
        .iter()
        .find(|c| c.role == Role::Kernel)
        .unwrap();
    let held_kernel = std::fs::read(root.join("held-kernel.enc")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&k.bytes)),
        "817b30930721c97b7b3da57d973d42e45f6630229c7c9efa87b22919b808e051"
    );
    assert_eq!(k.bytes, held_kernel);
    let provenance = package_provenance(&rebuilt);
    assert!(provenance.kernel_oem && provenance.normal_oem);
}
