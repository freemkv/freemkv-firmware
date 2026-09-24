use super::*;
use freemkv_flash::cmac;

/// An image whose integrity table exists but has **no active entry**. Auto
/// detection deliberately refuses it (`MtkCmac::detect` needs one live entry),
/// so every test that wants the "zero active regions" branch must force the
/// family — which is exactly the operator-supplied `--family mtk` path.
fn no_active_region_image() -> Vec<u8> {
    let mut img = vec![0u8; 0x20000];
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i * 11 + 5) as u8;
    }
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        for b in &mut img[off..off + cmac::ENTRY_SIZE] {
            *b = 0xFF;
        }
    }
    img
}

/// The committed OEM BU40N 1.00 fixture (third-party firmware kept in-tree for
/// interoperability testing — see `tests/fixtures/README.md`). The only image
/// in the repo a real `create` can be driven against.
fn bu40n_fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/BU40N_OEM_1.00.bin"
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("BU40N fixture must be present at {path}: {e}"))
}

/// A fresh, empty scratch directory unique to this process and `name`.
fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("freemkv-fw-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// [`ExitCode`] is opaque and implements neither `PartialEq` nor `Eq`, so tests
/// compare two codes through their `Debug` form — always against
/// `ExitCode::SUCCESS`/`FAILURE`, never against a hardcoded string, so this
/// stays portable across platforms.
fn exit_dbg(c: ExitCode) -> String {
    format!("{c:?}")
}

fn synthetic_image() -> Vec<u8> {
    let mut img = vec![0u8; 0x20000];
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    for i in 0..cmac::ENTRY_COUNT {
        let off = cmac::TABLE_OFFSET + i * cmac::ENTRY_SIZE;
        for b in &mut img[off..off + cmac::ENTRY_SIZE] {
            *b = 0xFF;
        }
    }
    let (start, end): (u32, u32) = (0x1000, 0x1FFF);
    let off = cmac::TABLE_OFFSET;
    img[off..off + 4].copy_from_slice(&cmac::ENABLED.to_le_bytes());
    img[off + 4..off + 8].copy_from_slice(&start.to_le_bytes());
    img[off + 8..off + 12].copy_from_slice(&end.to_le_bytes());
    let digest = cmac::compute_stored_digest(&img, start, end).unwrap();
    img[off + 12..off + 28].copy_from_slice(&digest);
    img
}

#[test]
fn verify_image_ok() {
    let img = synthetic_image();
    let (_, verdicts) = verify_image(&img, None).unwrap();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts.iter().all(|v| v.ok));
}

#[test]
fn sign_image_repairs_and_self_verifies() {
    let mut img = synthetic_image();
    img[0x1234] ^= 0xFF;
    let (_, signed, changes) = sign_image(&img, None).unwrap();
    assert_eq!(changes.len(), 1);
    let (_, verdicts) = verify_image(&signed, None).unwrap();
    assert!(verdicts.iter().all(|v| v.ok));
}

#[test]
fn unrecognized_image_is_clean_error() {
    let zeros = vec![0u8; 0x20000];
    assert!(verify_image(&zeros, None).is_err());
}

#[test]
fn default_signed_path_uses_stem() {
    let p = default_signed_path(Path::new("/tmp/fw.bin"));
    assert_eq!(p, PathBuf::from("/tmp/fw.signed.bin"));
}

#[test]
fn default_created_path_uses_stem() {
    let p = default_created_path(Path::new("/tmp/fw.bin"));
    assert_eq!(p, PathBuf::from("/tmp/fw.freemkv.bin"));
}

// -- verify's file-vs-device dispatch ------------------------------------

#[test]
fn classify_plain_path_is_file() {
    // Doesn't exist, doesn't look like a device path: treated as a file so
    // the ordinary "no such file" error still fires.
    assert_eq!(
        classify_verify_target(Path::new("/tmp/does-not-exist-freemkv-fw.bin")),
        VerifyTarget::File
    );
    assert_eq!(
        classify_verify_target(Path::new("firmware.bin")),
        VerifyTarget::File
    );
}

#[test]
fn classify_dev_prefixed_path_is_device() {
    // Purely path-based: doesn't need the node to actually exist, so this
    // runs the same on every host including CI.
    assert_eq!(
        classify_verify_target(Path::new("/dev/sg1")),
        VerifyTarget::Device
    );
    assert_eq!(
        classify_verify_target(Path::new("/dev/rdisk4")),
        VerifyTarget::Device
    );
}

#[test]
fn classify_existing_regular_file_is_file() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("freemkv-fw-classify-test-{}", std::process::id()));
    std::fs::write(&path, b"not a device").unwrap();
    assert_eq!(classify_verify_target(&path), VerifyTarget::File);
    let _ = std::fs::remove_file(&path);
}

/// Requires a real character/block special file (e.g. a real drive node)
/// to exercise the metadata branch on an actual device; not runnable in
/// CI. Gated out by default.
///
/// NOT KILLABLE IN CI: `classify_verify_target`'s
/// `is_char_device() || is_block_device()` is only reachable for a path that
/// is a special file yet does NOT start with `/dev/` (the earlier prefix test
/// returns first for every node under `/dev`). Creating such a node needs
/// `mknod` as root, and `symlink_metadata` deliberately does not follow a
/// symlink to one. So no host-independent test can distinguish `||` from `&&`
/// there — only this hardware-gated case can, run by hand against a drive.
#[test]
#[ignore = "requires real hardware: a live device node to probe"]
fn classify_real_device_node_is_device() {
    // Point this at a real device (e.g. `/dev/rdisk4` or `/dev/sg1`) when
    // running manually against attached hardware.
    let path = std::env::var("FREEMKV_FW_TEST_DEVICE").expect("set FREEMKV_FW_TEST_DEVICE");
    assert_eq!(
        classify_verify_target(Path::new(&path)),
        VerifyTarget::Device
    );
}

// -- mem_read: windowing, the fault fill, and the auto-stop threshold -----
//
// `mem_read` is the drive-dump engine: an off-by-one in its window walk or in
// its auto-stop bookkeeping silently truncates (or over-reads) a capture of a
// live drive, and the operator has no way to notice. Everything below pins the
// byte count, the byte *content* (which proves the address stepping), and the
// exact number of SCSI commands issued.

/// Mirrors `mem_read`'s private `STOP_AFTER`: the number of consecutive
/// unreadable windows that means "end of mapped memory". Deliberately restated
/// here so changing the production threshold has to be a conscious decision.
const EXPECT_STOP_AFTER: usize = 16;

/// A [`platform::ScsiDevice`] that answers `mem_read`'s memory-read CDBs with
/// deterministic address-derived bytes, and fails every window at or above
/// `fail_from` — the way a real drive reports the end of a mapped region.
struct WindowMem {
    fail_from: u32,
    /// Every window address requested, decoded from `cdb[5..9]`, in order.
    reads: Vec<u32>,
}

impl WindowMem {
    fn all_readable() -> Self {
        Self {
            fail_from: u32::MAX,
            reads: Vec::new(),
        }
    }

    fn failing_from(fail_from: u32) -> Self {
        Self {
            fail_from,
            reads: Vec::new(),
        }
    }

    /// The bytes this mock serves for the window at `addr` — derived from the
    /// address, so a test can prove which window landed where.
    fn window(addr: u32) -> Vec<u8> {
        (0..abi::MEMREAD_LEN)
            .map(|i| (addr as usize).wrapping_add(i) as u8)
            .collect()
    }

    /// The concatenation `mem_read` must return for `count` windows from `start`.
    fn expected(start: u32, count: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|w| Self::window(start + (w * abi::MEMREAD_LEN) as u32))
            .collect()
    }
}

impl platform::ScsiDevice for WindowMem {
    fn command_in(&mut self, cdb: &[u8], _alloc_len: usize) -> Result<Vec<u8>> {
        let addr = u32::from_be_bytes([cdb[5], cdb[6], cdb[7], cdb[8]]);
        self.reads.push(addr);
        if addr >= self.fail_from {
            bail!("mock: address 0x{addr:08x} is not mapped");
        }
        Ok(Self::window(addr))
    }

    fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
        unreachable!("mem_read must never write to the drive — it is a read-only dump path")
    }

    fn describe(&self) -> String {
        "mock://window-mem".to_string()
    }
}

#[test]
fn mem_read_walks_fixed_windows_and_returns_exactly_the_requested_length() {
    // Four consecutive MEMREAD_LEN windows from a non-zero base. The returned
    // bytes are address-derived, so asserting them proves the walk advanced by
    // exactly one window per command — a dump that silently shifts or repeats a
    // window yields a corrupt image that still looks the right size.
    let start = 0x1000u32;
    let windows = 4usize;
    let len = (windows * abi::MEMREAD_LEN) as u64;
    let mut dev = WindowMem::all_readable();

    let out = mem_read(&mut dev, start, len, false);

    assert_eq!(
        out.len(),
        len as usize,
        "a fully readable range must return exactly `len` bytes — short or long \
         means the dump is misaligned against the requested start address"
    );
    assert_eq!(
        out,
        WindowMem::expected(start, windows),
        "each window must land at its own offset, in order"
    );
    assert_eq!(
        dev.reads,
        vec![0x1000, 0x1040, 0x1080, 0x10c0],
        "the walk must issue one command per MEMREAD_LEN window, stepping by \
         exactly MEMREAD_LEN and never re-reading or skipping an address"
    );
}

#[test]
fn mem_read_of_a_zero_length_range_issues_no_commands_at_all() {
    // The loop bound is `addr < end`, not `<=`: a zero-length dump must not
    // poke the drive even once.
    let mut dev = WindowMem::all_readable();
    let out = mem_read(&mut dev, 0x1000, 0, false);
    assert!(out.is_empty(), "a zero-length dump must return no bytes");
    assert!(
        dev.reads.is_empty(),
        "a zero-length dump must issue no SCSI commands — an inclusive bound \
         here would read one window past the end of every requested range"
    );
}

#[test]
fn mem_read_auto_stop_drops_the_trailing_fault_fill_after_the_threshold() {
    // Eight readable windows then unmapped memory. Auto-stop must give back
    // exactly the readable bytes: the zero fill emitted while the fault run was
    // still inconclusive has to be truncated away, or every `--full` capture
    // ends with a block of fake zeros indistinguishable from real firmware.
    let start = 0x2000u32;
    let good = 8usize;
    let fail_from = start + (good * abi::MEMREAD_LEN) as u32;
    let mut dev = WindowMem::failing_from(fail_from);

    let out = mem_read(&mut dev, start, 0x1_0000, true);

    assert_eq!(
        out.len(),
        good * abi::MEMREAD_LEN,
        "auto-stop must return only the readable prefix — the STOP_AFTER-1 \
         zero-filled windows emitted before the run was conclusive are fill, \
         not drive contents"
    );
    assert_eq!(
        out,
        WindowMem::expected(start, good),
        "the retained bytes must be the real readable windows, unshifted"
    );
    assert_eq!(
        dev.reads.len(),
        good + EXPECT_STOP_AFTER,
        "auto-stop must fire on the STOP_AFTER-th consecutive fault: earlier \
         truncates a live region, later wastes commands past the end of memory"
    );
    assert_eq!(
        *dev.reads.last().expect("at least one read"),
        fail_from + ((EXPECT_STOP_AFTER - 1) * abi::MEMREAD_LEN) as u32,
        "the last command issued must be the STOP_AFTER-th faulting window"
    );
}

#[test]
fn mem_read_auto_stop_counts_only_consecutive_faults() {
    // A readable window between two fault runs resets the counter, so neither
    // run alone reaches the threshold and the whole requested range comes back
    // with the isolated faults zero-filled.
    struct Intermittent {
        readable: Vec<u32>,
        reads: usize,
    }
    impl platform::ScsiDevice for Intermittent {
        fn command_in(&mut self, cdb: &[u8], _alloc_len: usize) -> Result<Vec<u8>> {
            let addr = u32::from_be_bytes([cdb[5], cdb[6], cdb[7], cdb[8]]);
            self.reads += 1;
            if self.readable.contains(&addr) {
                Ok(WindowMem::window(addr))
            } else {
                bail!("mock: transient fault at 0x{addr:08x}")
            }
        }
        fn command_out(&mut self, _cdb: &[u8], _data: &[u8]) -> Result<()> {
            unreachable!("mem_read must never write to the drive")
        }
        fn describe(&self) -> String {
            "mock://intermittent".to_string()
        }
    }

    let start = 0x4000u32;
    let step = abi::MEMREAD_LEN as u32;
    let windows = 24usize;
    // A readable window every 10th: two fault runs of 9 < STOP_AFTER.
    let readable: Vec<u32> = (0..windows)
        .filter(|w| w % 10 == 0)
        .map(|w| start + w as u32 * step)
        .collect();
    let mut dev = Intermittent { readable, reads: 0 };

    let out = mem_read(&mut dev, start, (windows * abi::MEMREAD_LEN) as u64, true);

    assert_eq!(
        out.len(),
        windows * abi::MEMREAD_LEN,
        "a fault run shorter than STOP_AFTER must not end the read — only a \
         *consecutive* run means end-of-region, so the counter has to reset on \
         every successful window"
    );
    assert_eq!(
        dev.reads, windows,
        "every window in the range must still be attempted"
    );
    assert_eq!(
        &out[..abi::MEMREAD_LEN],
        &WindowMem::window(start)[..],
        "the readable windows must keep their own offsets"
    );
    assert!(
        out[abi::MEMREAD_LEN..10 * abi::MEMREAD_LEN]
            .iter()
            .all(|&b| b == 0),
        "faulting windows before the threshold must be zero-filled so every \
         later byte stays at its true offset from `start`"
    );
}

#[test]
fn mem_read_without_auto_stop_zero_fills_every_fault_and_reads_the_whole_range() {
    // `--dump --len` (auto_stop = false) is an explicit, operator-sized range:
    // it must come back at exactly the requested length no matter how many
    // windows fault, so file offsets line up with the addresses asked for.
    let start = 0x3000u32;
    let windows = 40usize; // far more than STOP_AFTER consecutive faults
    let mut dev = WindowMem::failing_from(start + abi::MEMREAD_LEN as u32);

    let out = mem_read(&mut dev, start, (windows * abi::MEMREAD_LEN) as u64, false);

    assert_eq!(
        out.len(),
        windows * abi::MEMREAD_LEN,
        "without auto-stop a fault run must never end the read early — the \
         caller asked for a specific range and indexes the result by offset"
    );
    assert_eq!(
        dev.reads.len(),
        windows,
        "every window of the requested range must be attempted"
    );
    assert_eq!(
        &out[..abi::MEMREAD_LEN],
        &WindowMem::window(start)[..],
        "the one readable window must be returned verbatim"
    );
    assert!(
        out[abi::MEMREAD_LEN..].iter().all(|&b| b == 0),
        "unreadable windows must be zero-filled, not dropped"
    );
}

// -- parse_u32: the address/length arguments for `info --dump` -----------

#[test]
fn parse_u32_accepts_both_hex_prefixes_and_plain_decimal() {
    // A misparsed `--dump`/`--len` points the memory read at the wrong address
    // or the wrong size, so every accepted spelling is pinned to its value.
    assert_eq!(parse_u32("0x1f80000").unwrap(), 0x01f8_0000);
    assert_eq!(parse_u32("0X10").unwrap(), 0x10);
    assert_eq!(
        parse_u32("  0x40  ").unwrap(),
        0x40,
        "surrounding whitespace must be trimmed, not treated as a parse error"
    );
    assert_eq!(
        parse_u32("4096").unwrap(),
        4096,
        "an unprefixed number is DECIMAL — reading it as hex would silently \
         dump the wrong range"
    );
    assert_eq!(parse_u32("0").unwrap(), 0);
    assert_eq!(parse_u32("1").unwrap(), 1);
}

#[test]
fn parse_u32_rejects_garbage_instead_of_defaulting() {
    for bad in ["", "0x", "0xzz", "-1", "12g", "0x1_0000"] {
        let err = parse_u32(bad).unwrap_err().to_string();
        assert!(
            err.contains("invalid number"),
            "a rejected number must be refused with a clear error (got {err:?} \
             for {bad:?}) — substituting a default address would dump the \
             wrong memory"
        );
    }
}

// -- short_hex: the digest preview in every report table -----------------

#[test]
fn short_hex_previews_exactly_the_first_four_digest_bytes() {
    let mut d = [0xAAu8; 16];
    d[0] = 0x00;
    d[1] = 0xab;
    d[2] = 0xff;
    d[3] = 0x10;
    assert_eq!(
        short_hex(&d),
        "00abff10",
        "the preview must be the first four bytes, lowercase and zero-padded — \
         it is what an operator eyeballs to tell a stored digest from a \
         computed one"
    );
}

// -- json_str: the hand-rolled escaper behind `--json` -------------------

#[test]
fn json_str_quotes_and_escapes_exactly_the_json_special_characters() {
    assert_eq!(json_str("ok"), "\"ok\"", "ordinary text is quoted verbatim");
    assert_eq!(json_str(""), "\"\"");
    assert_eq!(json_str("a\"b"), "\"a\\\"b\"");
    assert_eq!(json_str("a\\b"), "\"a\\\\b\"");
    assert_eq!(json_str("\n\r\t"), "\"\\n\\r\\t\"");
    assert_eq!(
        json_str("BD-RE BU40N"),
        "\"BD-RE BU40N\"",
        "SPACE (0x20) is NOT a control character — escaping it would mangle \
         every vendor/model string the publish pipeline reads"
    );
}

#[test]
fn json_str_escapes_control_characters_as_four_digit_unicode() {
    assert_eq!(
        json_str("\u{1}"),
        "\"\\u0001\"",
        "a raw control byte out of a drive descriptor must be escaped or the \
         report is not parseable JSON"
    );
    assert_eq!(json_str("\u{1f}"), "\"\\u001f\"");
    assert_eq!(
        json_str("\u{0}"),
        "\"\\u0000\"",
        "NUL padding is common in descriptor strings"
    );
}

// -- base_features / base_report_json: the STRICT `--base` publish gate --

#[test]
fn base_features_reports_all_six_firmware_flags_in_a_stable_order() {
    // The publish pipeline reads this list; a dropped, renamed or reordered
    // entry advertises a feature the firmware does not actually have.
    let outcome = api::create(&bu40n_fixture()).expect("create must succeed on the OEM base");
    let features = base_features(&outcome.report);

    let names: Vec<&str> = features.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        vec!["Speed", "Region", "UHD", "BD", "HRL", "Encryption"],
        "the six flag-table features must be reported in their fixed order — \
         consumers read this list positionally"
    );
    assert!(
        features.iter().all(|(_, ok)| *ok),
        "every gate resolves on the OEM BU40N base, so every feature must read \
         available: {features:?}"
    );
}

#[test]
fn base_features_tracks_the_resolved_stub_addresses_not_a_constant() {
    // Zero a feature's stub VA and it must flip to unavailable — the whole
    // point of the list is that it is derived from THIS image's facts.
    let outcome = api::create(&bu40n_fixture()).expect("create must succeed on the OEM base");
    let mut report = outcome.report.clone();
    report.uhd_stub_va = 0;
    report.hrl_stub_va = 0;
    let available: Vec<&str> = base_features(&report)
        .into_iter()
        .filter(|(_, ok)| *ok)
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        available,
        vec!["Speed", "Region", "BD", "Encryption"],
        "a feature whose detour stub was never emitted must be reported \
         unavailable — advertising it promises a capability the drive lacks"
    );
}

#[test]
fn base_report_json_emits_identity_grounded_facts_and_a_comma_separated_feature_array() {
    let outcome = api::create(&bu40n_fixture()).expect("create must succeed on the OEM base");
    let json = base_report_json(&outcome);
    let r = &outcome.report;

    assert!(
        json.starts_with("{\"base\":true,"),
        "the STRICT report must lead with the base flag: {json}"
    );
    assert!(
        json.ends_with("]}"),
        "the report must be a closed object: {json}"
    );
    assert!(
        json.contains("\"engine\":\"MT1959\","),
        "the engine that built the image must be named: {json}"
    );
    assert!(
        json.contains("\"vendor\":\"HL-DT-ST\",\"model\":\"BD-RE BU40N\",\"rev\":\"1.00\","),
        "the detected chip identity must round-trip into the report: {json}"
    );
    assert!(
        json.contains(&format!(
            "\"base_facts\":{{\"handler_va\":{},\"boot_stub_va\":{},\
             \"boot_init_site\":{},\"de_off\":{},",
            r.handler_va, r.boot_stub_va, r.boot_init_site, r.de_off
        )),
        "the grounded addresses that PROVE a real base must be this report's \
         own values, not a fixed string: {json}"
    );
    assert!(
        json.contains(&format!("\"hrl_sites\":{}}}", r.hrl_sites.len())),
        "hrl_sites is reported as a COUNT and closes the facts object: {json}"
    );
    assert!(
        json.contains(
            "\"features\":[{\"name\":\"Speed\",\"ok\":true},\
             {\"name\":\"Region\",\"ok\":true},\
             {\"name\":\"UHD\",\"ok\":true},\
             {\"name\":\"BD\",\"ok\":true},\
             {\"name\":\"HRL\",\"ok\":true},\
             {\"name\":\"Encryption\",\"ok\":true}]"
        ),
        "the feature array needs exactly one separating comma BETWEEN elements \
         — a leading, trailing or missing comma makes the publish pipeline's \
         JSON unparseable: {json}"
    );
}

// -- verify: what actually decides the process exit code -----------------

#[test]
fn cmd_verify_file_exits_zero_only_when_every_region_matches() {
    let dir = scratch_dir("verify-exit");
    let good = dir.join("good.bin");
    std::fs::write(&good, synthetic_image()).unwrap();
    assert_eq!(
        exit_dbg(cmd_verify_file(&good, None).unwrap()),
        exit_dbg(ExitCode::SUCCESS),
        "an image whose every active region matches must verify clean"
    );

    let bad = dir.join("bad.bin");
    let mut img = synthetic_image();
    img[0x1234] ^= 0xFF; // inside the single active region (0x1000..=0x1fff)
    std::fs::write(&bad, &img).unwrap();
    assert_eq!(
        exit_dbg(cmd_verify_file(&bad, None).unwrap()),
        exit_dbg(ExitCode::FAILURE),
        "a mismatching digest MUST exit non-zero — reporting a tampered or \
         corrupt image as verified is the failure class that bricks hardware"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cmd_verify_file_refuses_an_image_with_no_active_regions() {
    // Nothing verified is not the same as everything verified: an image with an
    // all-inactive table has proved nothing and must not exit zero.
    let dir = scratch_dir("verify-empty");
    let path = dir.join("inactive.bin");
    std::fs::write(&path, no_active_region_image()).unwrap();
    assert_eq!(
        exit_dbg(cmd_verify_file(&path, Some(Family::Mtk)).unwrap()),
        exit_dbg(ExitCode::FAILURE),
        "zero active regions must exit non-zero — an empty verdict list means \
         the integrity table proved nothing about the image"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cmd_verify_surfaces_a_missing_image_as_an_error_not_a_pass() {
    let missing = std::env::temp_dir().join("freemkv-fw-definitely-absent-image.bin");
    let _ = std::fs::remove_file(&missing);
    assert!(
        cmd_verify(&missing, None).is_err(),
        "a typo'd image path must fail loudly; returning success would let a \
         CI gate 'verify' a file that was never read"
    );
    assert!(cmd_verify_file(&missing, None).is_err());
}

#[test]
fn cmd_verify_device_surfaces_an_unopenable_device_as_an_error() {
    // Classified as a device by path, but no such node exists: opening must
    // fail, and that failure must reach the caller rather than being reported
    // as a successful probe.
    //
    // NOT TESTABLE WITHOUT HARDWARE: the DETECTED-vs-NOT-DETECTED decision in
    // `cmd_verify_device` (the `Ok(resp) if abi::verify_response(&resp)` match
    // guard) sits behind `platform::open`, which takes a path and returns a real
    // transport. Without a live drive — or a production seam that let a test
    // inject a `ScsiDevice` — a test cannot reach the guard at all. The guard's
    // own predicate IS covered: see `abi::tests::verify_response_matches_only_
    // the_magic_lead`.
    let path = Path::new("/dev/freemkv-fw-no-such-device");
    assert_eq!(classify_verify_target(path), VerifyTarget::Device);
    assert!(
        cmd_verify_device(path).is_err(),
        "a device that cannot even be opened is an error, not a clean \
         'not detected' answer"
    );
    assert!(cmd_verify(path, None).is_err());
}

// -- sign: the self-verify refusal and the overwrite guards --------------

#[test]
fn sign_image_refuses_an_image_with_no_active_regions() {
    // `sign` promises the bytes it hands back self-verify. An all-inactive
    // table verifies nothing, so there is nothing to stand behind.
    assert!(
        sign_image(&no_active_region_image(), Some(Family::Mtk)).is_err(),
        "re-signing must refuse when the produced image has zero active \
         regions — 'no regions checked' must never read as 'all regions OK'"
    );
}

#[test]
fn cmd_sign_writes_the_default_output_and_refuses_to_clobber_its_input() {
    let dir = scratch_dir("sign-guards");
    let input = dir.join("fw.bin");
    let mut img = synthetic_image();
    img[0x1500] ^= 0xFF; // force a real re-sign
    std::fs::write(&input, &img).unwrap();

    assert_eq!(
        exit_dbg(cmd_sign(&input, None, false, None).unwrap()),
        exit_dbg(ExitCode::SUCCESS)
    );
    let default_out = dir.join("fw.signed.bin");
    assert!(
        default_out.is_file(),
        "with no -o and no --in-place the re-signed image must be written to \
         <stem>.signed.bin"
    );
    assert_eq!(
        std::fs::read(&input).unwrap(),
        img,
        "the input must be left untouched unless --in-place was asked for"
    );

    assert!(
        cmd_sign(&input, Some(input.clone()), false, None).is_err(),
        "an -o equal to the input must be refused — silently overwriting the \
         only copy of an OEM image destroys it"
    );
    assert!(
        cmd_sign(&input, Some(default_out.clone()), true, None).is_err(),
        "--in-place and -o are mutually exclusive"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cmd_sign_surfaces_a_missing_image_as_an_error() {
    let missing = std::env::temp_dir().join("freemkv-fw-definitely-absent-sign.bin");
    let _ = std::fs::remove_file(&missing);
    assert!(cmd_sign(&missing, None, false, None).is_err());
}

// -- create: the build guards ("never write an image that does not verify") --
//
// UNREACHABLE BRANCH: the `verdicts.is_empty()` half of `cmd_create`'s
// post-build refusal (and of `api::create`'s) cannot be reached. A build only
// gets that far when `engine::detect` accepted the image and the engine
// re-signed it, which means the image has a live CMAC table — so
// `MtkCmac::verify` always returns at least one verdict. Turning that `||` into
// `&&` is therefore behaviourally equivalent for every input the engine
// accepts, and no test can distinguish it. The same guard IS exercised on the
// `sign` path (`sign_image_refuses_an_image_with_no_active_regions`), where a
// forced `--family` lets an all-inactive table through.

#[test]
fn cmd_create_builds_audits_and_writes_the_oem_base() {
    let dir = scratch_dir("create-ok");
    let input = dir.join("BU40N.bin");
    std::fs::write(&input, bu40n_fixture()).unwrap();

    // `--audit` proves every Applied lever's detour actually landed; it must
    // PASS on the OEM base, and a passing audit must not become a refusal.
    assert_eq!(
        exit_dbg(cmd_create(&input, None, false, false, false, true).unwrap()),
        exit_dbg(ExitCode::SUCCESS),
        "the MODIFY build plus structural audit must succeed on the OEM base"
    );
    let out = dir.join("BU40N.freemkv.bin");
    assert!(
        out.is_file(),
        "the built image must be written to <stem>.freemkv.bin"
    );
    assert_ne!(
        std::fs::read(&out).unwrap(),
        bu40n_fixture(),
        "the written image must actually differ from the OEM input"
    );

    // The STRICT base path is the publish gate; it must also succeed here.
    let base_out = dir.join("base.bin");
    assert_eq!(
        exit_dbg(cmd_create(&input, Some(base_out.clone()), false, true, true, false).unwrap()),
        exit_dbg(ExitCode::SUCCESS),
        "`create --base --json` must succeed on an image with a real freemkv BASE"
    );
    assert!(base_out.is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cmd_create_refuses_to_clobber_its_input_and_rejects_conflicting_flags() {
    let dir = scratch_dir("create-guards");
    let input = dir.join("BU40N.bin");
    std::fs::write(&input, bu40n_fixture()).unwrap();

    assert!(
        cmd_create(&input, Some(input.clone()), false, false, false, false).is_err(),
        "an output path equal to the input must be refused — the OEM image is \
         usually the operator's only copy"
    );
    assert!(
        cmd_create(&input, Some(dir.join("x.bin")), true, false, false, false).is_err(),
        "--in-place and an explicit output path are mutually exclusive"
    );
    assert_eq!(
        std::fs::read(&input).unwrap(),
        bu40n_fixture(),
        "a refused create must not have touched the input"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cmd_create_surfaces_a_missing_image_as_an_error() {
    let missing = std::env::temp_dir().join("freemkv-fw-definitely-absent-create.bin");
    let _ = std::fs::remove_file(&missing);
    assert!(cmd_create(&missing, None, false, false, false, false).is_err());
}

// -- info: the argument guards that run before any device is opened ------

#[test]
fn cmd_info_requires_the_output_and_length_arguments_before_touching_a_device() {
    // These refusals happen *before* `platform::open`, so they are the only
    // part of `info` testable without hardware — and they are exactly the
    // arguments whose absence would otherwise produce a discarded or
    // wrongly-addressed drive dump.
    let dev = Path::new("/dev/freemkv-fw-no-such-device");
    let err = cmd_info(dev, None, None, true, None)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("--full requires --out"),
        "`--full` with nowhere to write must refuse, not silently discard a \
         whole-drive capture: {err}"
    );

    let err = cmd_info(dev, Some("0x1000"), None, false, None)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("--dump requires --len"),
        "`--dump` with no length must refuse rather than dump nothing: {err}"
    );

    assert!(
        cmd_info(dev, Some("nonsense"), Some("0x40"), false, None).is_err(),
        "an unparseable --dump address must be refused, never defaulted"
    );
}
