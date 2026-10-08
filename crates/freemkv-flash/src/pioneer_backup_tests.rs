use super::*;

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
        crate::pioneer_k::receiver_generation(&decoded.image),
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

/// The drive's refusal of an address past its read end.
fn refused() -> anyhow::Error {
    anyhow::Error::new(crate::platform::ScsiSenseError::new(
        0x05,
        0x24,
        0x00,
        "address past the read end",
    ))
}

/// Serves B0 reads below `end`, refuses at or past it, and counts reads.
struct Ceiling {
    end: usize,
    reads: usize,
}

impl ScsiDevice for Ceiling {
    fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
        if cdb[2] != 0xb0 {
            return Ok(vec![0; len]);
        }
        self.reads += 1;
        let start = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
        if start >= self.end {
            return Err(refused());
        }
        Ok(vec![0x5A; len])
    }
    fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
        Ok(())
    }
    fn describe(&self) -> String {
        "ceiling".into()
    }
}

#[test]
fn read_end_is_the_first_refused_address() {
    for end in [0x88_0300, 0x60_0000, 0x7A_1235, 0x40_0001] {
        let mut dev = Ceiling { end, reads: 0 };
        assert_eq!(probe_read_end(&mut dev).unwrap(), end);
        assert!(dev.reads <= 26, "{end:#x}: {} reads", dev.reads);
    }
    let mut open = Ceiling {
        end: ADDRESS_LIMIT,
        reads: 0,
    };
    assert_eq!(probe_read_end(&mut open).unwrap(), ADDRESS_LIMIT);
}

#[test]
fn read_end_probe_fails_on_errors_other_than_a_refusal() {
    struct Broken;
    impl ScsiDevice for Broken {
        fn command_in(&mut self, _cdb: &[u8], _len: usize) -> Result<Vec<u8>> {
            bail!("bus reset")
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "broken".into()
        }
    }
    assert!(probe_read_end(&mut Broken).is_err());
}

#[test]
fn force_dump_with_unreadable_kernel_base_still_saves_a_zero_filled_image() {
    // Alive drive; only 0x400000..0x440000 (the Kernel base) is unreadable.
    struct BadKernelBase;
    impl ScsiDevice for BadKernelBase {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            if cdb[2] != 0xb0 {
                bail!("no identity");
            }
            let start = ((cdb[3] as usize) << 16) | ((cdb[4] as usize) << 8) | cdb[5] as usize;
            if start < 0x44_0000 && start + len > 0x40_0000 {
                bail!("unreadable kernel base");
            }
            if start >= pioneer_optical::cdb::READ_CEILING as usize {
                return Err(refused());
            }
            Ok(vec![0xAA; len])
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "bad kernel base".into()
        }
    }
    let image = capture_raw_dump(&mut BadKernelBase, true).expect("dump must complete");
    assert_eq!(image.len(), pioneer_optical::cdb::READ_CEILING as usize);
    assert!(image[0x40_0000..0x44_0000].iter().all(|b| *b == 0));
    assert!(image[..0x40_0000].iter().all(|b| *b == 0xAA));
    assert!(image[0x44_0000..].iter().all(|b| *b == 0xAA));
}

#[test]
fn gap_summary_is_loud_and_counts_bytes() {
    assert_eq!(gap_summary(&[]), None);
    let msg = gap_summary(&[(0x100, 8), (0x200, 0x18)]).unwrap();
    assert!(msg.contains("2 gap(s)"), "{msg}");
    assert!(msg.contains("32 byte(s)"), "{msg}");
    assert!(msg.to_lowercase().contains("zero"), "{msg}");
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

#[test]
fn unsupported_capture_identity_stops_before_service_entry_or_memory_reads() {
    struct IdentityOnly {
        f1: Vec<u8>,
        commands: usize,
    }
    impl ScsiDevice for IdentityOnly {
        fn command_in(&mut self, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
            self.commands += 1;
            match self.commands {
                1 => {
                    assert_eq!(cdb, [0x12, 0, 0, 0, 36, 0]);
                    assert_eq!(len, 36);
                    let mut inquiry = vec![b' '; 36];
                    inquiry[8..16].copy_from_slice(b"PIONEER ");
                    Ok(inquiry)
                }
                2 => {
                    assert_eq!(cdb, [0x3c, 2, 0xf1, 0, 0, 0, 0, 0, 48, 0]);
                    assert_eq!(len, 48);
                    Ok(self.f1.clone())
                }
                _ => panic!("unsupported identity must not trigger memory reads"),
            }
        }
        fn command_out(&mut self, _: &[u8], _: &[u8]) -> Result<()> {
            panic!("unsupported identity must not trigger service entry")
        }
        fn describe(&self) -> String {
            "identity-only test transport".into()
        }
    }
    for hardware in [b"ATA 0009", b"SCSI0001", b"UNKNOWN "] {
        let mut f1 = vec![0; 48];
        f1[16..24].copy_from_slice(hardware);
        let mut dev = IdentityOnly { f1, commands: 0 };
        assert!(read_h8_image_pair(&mut dev)
            .unwrap_err()
            .to_string()
            .contains("H8/SAT hardware identity"));
        assert_eq!(dev.commands, 2);
    }
    for length in [0, 16, 23, 47, 49] {
        let mut dev = IdentityOnly {
            f1: vec![0; length],
            commands: 0,
        };
        assert!(read_h8_image_pair(&mut dev).is_err());
        assert_eq!(dev.commands, 2);
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
        crate::pioneer_n::lookup(&format!("{:x}", Sha256::digest(&n.image))).is_some();
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
    eprintln!("Kernel sharing: {} decoded image hashes, {} catalog models, {shared} cross-model groups, {} undecodable envelope hashes, {invalid_packages} invalid packages", groups.len(), models.len(), undecodable.len());
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
    eprintln!("Kernel header revision/date literals in decoded image: {kernel_revision_literals}/{kernel_date_literals}");
    for (hash, labels) in raw_metadata.iter().filter(|(_, labels)| labels.len() > 1) {
        eprintln!("identical raw Kernel {hash}, envelope labels: {labels:?}");
    }
    eprintln!("Kernel dispatcher corpus: {front} front, {derived} derived unique envelopes; {} unrecognized", unrecognized.len());
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

#[test]
fn corpus_builder_reports_hardware_coverage_when_configured() {
    let Ok(root) = std::env::var("PIONEER_INSTALLER_CORPUS_KAT_ROOT") else {
        return;
    };
    let mut dirs = vec![std::path::PathBuf::from(root)];
    let mut seen_hardware = std::collections::HashSet::new();
    let all_pairs = std::env::var_os("PIONEER_ALL_PAIRS_KAT").is_some();
    let mut built = 0;
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
            if words.len() < 3 {
                failures.push(format!(
                    "{}: OEM ID has no vendor/media/model",
                    h.hardware_version
                ));
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
            inquiry[8..8 + vendor.len()].copy_from_slice(vendor.as_bytes());
            inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
            let id = embedded_envelope_id(&inquiry, &k.image, &n.image)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(id, h.id);
            match construct_signed_candidate(&k.image, &n.image, &id, &h.revision) {
                Ok(output) => {
                    validate_envelope_package(&output, &product).unwrap();
                    let rebuilt = Bundle::from_tar_bytes(&output).unwrap();
                    let rebuilt_normal = rebuilt
                        .components
                        .iter()
                        .find(|c| c.role == Role::Main)
                        .unwrap();
                    built += 1;
                    exact_text +=
                        usize::from(rebuilt_normal.bytes[..0x160] == normal.bytes[..0x160]);
                    exact_name += usize::from(
                        rebuilt_normal.bytes[0x1f0..0x200] == normal.bytes[0x1f0..0x200],
                    );
                    if h.destination != "GENERAL" && !h.destination.starts_with("ID") {
                        assert!(rebuilt_normal.bytes[0x1f0..].starts_with(
                            format!("NORMAL.{}\0", h.revision.replace('.', "")).as_bytes()
                        ));
                        generated_name += 1;
                    }
                    signature_range_match += usize::from(if pioneer_optical::envelope::builder::normal_authentication_from_kernel(&k.image) == Some(pioneer_optical::envelope::builder::NormalAuthentication::ScaledChecksumOnly) {
                            pioneer_optical::envelope::builder::normal_authentication_valid(&normal.bytes, &k.image)
                                && pioneer_optical::envelope::builder::normal_authentication_valid(&rebuilt_normal.bytes, &k.image)
                        } else {
                            pioneer_optical::envelope::signature::verify_normal_signature(
                                &rebuilt_normal.bytes,
                            ) == pioneer_optical::envelope::signature::verify_normal_signature(&normal.bytes)
                        });
                }
                Err(error) => failures.push(format!("{}: {error:#}", h.hardware_version)),
            }
        }
    }
    eprintln!("builder corpus: {built} built, {} unsupported; {exact_text} exact textual headers, {exact_name} exact names, {signature_range_match} matching signature ranges", failures.len());
    for failure in &failures {
        eprintln!("unsupported: {failure}");
    }
    assert!(
        failures.is_empty(),
        "decoded OEM pairs failed reconstruction: {failures:?}"
    );
    assert!(built > 0);
    assert_eq!(exact_text, built, "OEM textual header drift");
    eprintln!("explicit generated Normal filenames: {generated_name}");
    assert_eq!(
        exact_name + generated_name,
        built,
        "unexplained embedded filename drift"
    );
    assert_eq!(signature_range_match, built, "OEM signature range drift");
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
        crate::drive::pioneer::offline_pair_data_out(&kernel.bytes, &normal.bytes).unwrap();
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
        let original_steps = crate::drive::pioneer::offline_pair_data_out(
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
    let drive = crate::drive::pioneer::Pioneer::new();
    crate::engine::plan_pioneer_offline(
        &candidate,
        crate::drive::InputKind::PioneerBundle,
        "BD-RW BDR-UD04",
        false,
        false,
    )
    .unwrap();
    replay.knocks = 0;
    replay.reads = 0;
    crate::engine::backup(&mut replay, &drive, &output, false, false).unwrap();
    let saved = std::fs::read(&output).unwrap();
    validate_envelope_package(&saved, "BD-RW BDR-UD04").unwrap();
    std::fs::remove_file(&output).unwrap();
    replay.knocks = 0;
    replay.reads = 0;
    replay.corrupt_second_pass = true;
    assert!(capture_signed_candidate(&mut replay).is_err());
}

#[test]
fn backup_map_rejects_relocated_ambiguous_and_truncated_regions() {
    let kernel = vec![0; NORMAL_IMAGE_BASE - KERNEL_IMAGE_BASE];
    let mut image = vec![0; NORMAL_IMAGE_BASE + 0x2000];
    image[NORMAL_IMAGE_BASE..NORMAL_IMAGE_BASE + 8].copy_from_slice(b"PIONEER ");
    image[NORMAL_IMAGE_BASE + 20..NORMAL_IMAGE_BASE + 24].copy_from_slice(&0x2000u32.to_be_bytes());
    validate_backup_image_map(&image, &kernel).unwrap();
    assert!(validate_backup_image_map(&image[..image.len() - 1], &kernel).is_err());
    let mut bad_kernel = kernel.clone();
    bad_kernel[0] = 1;
    assert!(validate_backup_image_map(&image, &bad_kernel).is_err());
    image.resize(0x422000, 0);
    image[0x420000..0x420018].copy_from_slice(&{
        let mut header = [0; 24];
        header[..8].copy_from_slice(b"PIONEER ");
        header[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
        header
    });
    assert!(validate_backup_image_map(&image, &kernel).is_err());
    image[NORMAL_IMAGE_BASE..NORMAL_IMAGE_BASE + 24].fill(0);
    assert!(validate_backup_image_map(&image, &kernel).is_err());
}

#[test]
fn backup_map_does_not_mistake_inquiry_or_log_strings_for_firmware() {
    let kernel = vec![0; NORMAL_IMAGE_BASE - KERNEL_IMAGE_BASE];
    let mut image = vec![0; NORMAL_IMAGE_BASE + 0x2000];
    image[NORMAL_IMAGE_BASE..NORMAL_IMAGE_BASE + 8].copy_from_slice(b"PIONEER ");
    image[NORMAL_IMAGE_BASE + 20..NORMAL_IMAGE_BASE + 24].copy_from_slice(&0x2000u32.to_be_bytes());
    let inquiry = b"PIONEER BD-RW   SOMEMODEL ";
    image[0x100..0x100 + inquiry.len()].copy_from_slice(inquiry);
    image[0x200..0x208].copy_from_slice(b"PIONEER ");
    validate_backup_image_map(&image, &kernel).unwrap();
}
