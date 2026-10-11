//! Tripwires for the standard snapshot, typed report rows and the one file
//! recognizer (design findings R3, R4, R6, R7, R8, R12 and R13).

use super::*;
use crate::backend::registry;
use crate::report::{Row, Value};

/// One part (`text`, `events`, `scsi transcript`) of a v0.11.2 scenario.
fn baseline(file: &str, scenario: &str, part: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/v0.11.2")
        .join(file);
    let text = std::fs::read_to_string(path).unwrap();
    let (_, lines) = sections(&text)
        .into_iter()
        .find(|(t, _)| t == scenario)
        .unwrap_or_else(|| panic!("no {scenario:?} in {file}"));
    let header = format!("--- {part} (");
    lines
        .iter()
        .skip_while(|l| !l.starts_with(&header))
        .skip(1)
        .take_while(|l| !l.starts_with("--- "))
        .filter(|l| !l.is_empty())
        .cloned()
        .collect()
}

/// The Pioneer and backend-less `info` scenarios, which must equal v0.11.2.
fn pioneer_info_cases() -> Vec<(&'static str, &'static str, MockScsiDevice, bool)> {
    vec![
        (
            "info_pioneer.txt",
            "Pioneer info: MockScsiDevice::pioneer",
            MockScsiDevice::pioneer(),
            true,
        ),
        (
            "info_pioneer.txt",
            "Renesas info: MockScsiDevice::renesas (Pioneer backend)",
            MockScsiDevice::renesas(),
            true,
        ),
        (
            "classify_and_unknown_info.txt",
            "info with the Unknown handler on MockScsiDevice::pioneer",
            MockScsiDevice::pioneer(),
            false,
        ),
        (
            "classify_and_unknown_info.txt",
            "info with the Unknown handler on blank mock (matches no backend)",
            MockScsiDevice::new(),
            false,
        ),
    ]
}

fn backend(pioneer: bool) -> Option<&'static dyn Backend> {
    static PIONEER: Pioneer = Pioneer::new();
    pioneer.then_some(&PIONEER as &dyn Backend)
}

fn strip(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| normalize(l).trim_end_matches('\n').to_string())
        .collect()
}

/// A Pioneer drive whose INQUIRY and vendor identity carry `extra` and
/// `platform`, as Device::info parses them.
fn pioneer_with(extra: &[u8], serial: &[u8], platform: &[u8]) -> MockScsiDevice {
    let mut inq = vec![b' '; 96];
    inq[0] = 5;
    inq[4] = 91;
    inq[8..16].copy_from_slice(b"PIONEER ");
    inq[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
    inq[32..36].copy_from_slice(b"1.14");
    inq[36..36 + extra.len()].copy_from_slice(extra);
    let mut f1 = vec![b' '; 48];
    f1[..serial.len()].copy_from_slice(serial);
    f1[16..16 + platform.len()].copy_from_slice(platform);
    f1[24..28].copy_from_slice(b"ID58");
    f1[32..36].copy_from_slice(b"ID58");
    f1[40..44].copy_from_slice(b"0000");
    MockScsiDevice::new()
        .on(|cdb| cdb.first() == Some(&0x12), inq)
        .on(
            |cdb| cdb.first() == Some(&0x3C) && cdb.get(2) == Some(&0xF1),
            f1,
        )
}

fn keys(rows: &[Row]) -> Vec<&'static str> {
    rows.iter().map(|r| r.key).collect()
}

fn first(keys: &[&str], key: &str) -> usize {
    keys.iter()
        .position(|k| *k == key)
        .unwrap_or_else(|| panic!("no {key} in {keys:?}"))
}

// ---- R3: the standard snapshot ----------------------------------------------

#[test]
fn info_transcript_matches_0_11_2() {
    for (file, scenario, dev, pioneer) in pioneer_info_cases() {
        let (_, transcript) = drive_run(dev, |d| crate::engine::info(d, backend(pioneer)));
        assert_eq!(
            transcript,
            baseline(file, scenario, "scsi transcript"),
            "{scenario}"
        );
    }
    // The snapshot is read once even when the drive answers every field.
    let mut dev = Rec::new(pioneer_with(b"", b"SN1", b"SAT 8A10"));
    let before = crate::standard::reads();
    crate::engine::info_report(&mut dev, backend(true));
    assert_eq!(crate::standard::reads(), before + 1);
    let modes = dev
        .transcript()
        .iter()
        .filter(|l| l.contains("cdb=5a082a"))
        .count();
    assert_eq!(modes, 1);
}

#[test]
fn backup_flash_recover_send_no_standard_snapshot() {
    let dir = scratch("no-snapshot");
    let before = crate::standard::reads();
    let snapshot_free = |transcript: &[String]| {
        transcript
            .iter()
            .all(|l| !l.contains("cdb=5a082a") && !l.contains("cdb=a4"))
    };
    let (_, t) = drive_run(mtk_drive(), |d| {
        crate::engine::backup(d, &Mtk, &dir.join("mtk.bin"), false)
    });
    assert!(snapshot_free(&t));
    let (_, t) = drive_run(BackupReplay::new(), |d| {
        crate::engine::backup(d, &Pioneer::new(), &dir.join("pioneer.tar"), false)
    });
    assert!(snapshot_free(&t));
    let image = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    for req in [
        mtk_request(image.clone(), false, None),
        mtk_request(image, true, Some(dir.join("preflash.bin"))),
    ] {
        let dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
        let (outcome, t) = drive_run(dev, |d| engine_flash(d, &Mtk, &req));
        assert_eq!(outcome.result, "OK");
        assert!(snapshot_free(&t));
    }
    let current = archive(&prepared_pair(false, 1), false);
    let target = archive(&prepared_pair(false, 0), false);
    let (_, t) = drive_run(MockScsiDevice::pioneer(), |d| {
        recover_via(d, Some(&current), &target, false)
    });
    assert!(snapshot_free(&t));
    assert_eq!(crate::standard::reads(), before, "only info reads it");
    drive_run(MockScsiDevice::pioneer(), |d| {
        crate::engine::info(d, backend(true))
    });
    assert_eq!(crate::standard::reads(), before + 1);
}

// ---- R4: rows reproduce the CLI and the GUI ---------------------------------

#[test]
fn info_cli_stdout_matches_0_11_2() {
    for (file, scenario, dev, pioneer) in pioneer_info_cases() {
        let expected = baseline(file, scenario, "text");
        let mut rec = Rec::new(dev);
        let report = crate::engine::info_report(&mut rec, backend(pioneer)).report;
        assert_eq!(strip(&report.cli_lines()), expected, "{scenario}");
    }
    for (file, scenario, dev, pioneer) in pioneer_info_cases() {
        let (outcome, _) = drive_run(dev, |d| crate::engine::info(d, backend(pioneer)));
        let expected = baseline(file, scenario, "text");
        assert_eq!(strip(&outcome.text), expected, "{scenario}");
    }
}

#[test]
fn info_gui_events_match_0_11_2() {
    for (file, scenario, dev, pioneer) in pioneer_info_cases() {
        let (outcome, _) = drive_run(dev, |d| crate::engine::info(d, backend(pioneer)));
        let expected = baseline(file, scenario, "events");
        let events: Vec<String> = strip(&outcome.events)
            .into_iter()
            .map(|e| e.trim_end().to_string())
            .collect();
        let expected: Vec<String> = expected.iter().map(|e| e.trim_end().to_string()).collect();
        assert_eq!(events, expected, "{scenario}");
    }
}

#[test]
fn pioneer_rows_interleave_at_slots() {
    let mut dev = pioneer_with(b"", b"SN1", b"SAT 8A10");
    let report = crate::engine::info_report(&mut dev, backend(true)).report;
    let k = keys(&report.rows);
    let identity = first(&k, "hardware_type");
    assert!(first(&k, "interface") < identity, "{k:?}");
    assert!(first(&k, "product_origin") < first(&k, "media"), "{k:?}");
    let region = report
        .rows
        .iter()
        .rposition(|r| r.group == crate::report::Group::Region)
        .unwrap();
    assert_eq!(
        k[region + 1],
        "quiet_drive",
        "settings follow the region: {k:?}"
    );
    assert_eq!(
        report.rows[identity].gui_label.as_deref(),
        Some("Hardware type")
    );
    assert_eq!(
        report.rows[identity].cli_label.as_deref(),
        Some("Hardware type")
    );

    // MediaTek's chipset row comes after everything standard, before the
    // firmware lines, with a GUI and a CLI label of its own.
    let mut dev = mtk_drive();
    let report = crate::engine::info_report(&mut dev, Some(&Mtk)).report;
    let k = keys(&report.rows);
    let chipset = first(&k, "chipset");
    assert!(first(&k, "region") < chipset);
    assert_eq!(k[chipset + 1], "firmware");
    let row = &report.rows[chipset];
    assert_eq!(
        (row.gui_label.as_deref(), row.cli_label.as_deref()),
        (Some("Chipset"), Some("chipset"))
    );
}

// ---- R6: recovery is reachable without a probe match ------------------------

/// A Pioneer receiver whose vendor identity does not satisfy the protocol
/// probe (its platform field is not a SAT/ATA/SCSI code), e.g. mid-update.
fn unprobeable_receiver() -> MockScsiDevice {
    pioneer_with(b"", b"SN1", b"BDR 8A10")
}

#[test]
fn recovery_offered_for_unsupported_identified_drive() {
    let mut dev = unprobeable_receiver();
    let profile = crate::workflow::profile_on(&mut dev).expect("a profile, not an error");
    assert!(profile.backend.is_none(), "no protocol probe matched");
    assert_eq!(profile.capabilities, crate::backend::Capabilities::NONE);
    assert_eq!(
        profile.recovery.map(|d| d.id),
        Some(crate::backends::pioneer::DESCRIPTOR.id)
    );
    assert!(dev.writes.is_empty());

    // Unsupported and unidentified is still a profile.
    let mut blank = MockScsiDevice::new();
    let profile = crate::workflow::profile_on(&mut blank).unwrap();
    assert!(profile.backend.is_none() && profile.recovery.is_none());
    assert!(profile.flash_formats.is_empty() && profile.backup_format.is_none());

    // A supported Pioneer drive offers both.
    let profile = crate::workflow::profile_on(&mut pioneer_with(b"", b"SN1", b"SAT 8A10")).unwrap();
    assert!(profile.backend.is_some() && profile.recovery.is_some());
}

#[test]
fn recovery_identify_needs_no_probe() {
    let mut dev = Rec::new(unprobeable_receiver());
    assert!(registry::resolve(&mut dev).unwrap().is_none());
    let mut dev = Rec::new(unprobeable_receiver());
    let receiver = Pioneer::new()
        .recovery()
        .unwrap()
        .identify(&mut ReadDevice::new(&mut dev, &[]))
        .unwrap()
        .expect("identified without a probe match");
    assert_eq!(receiver.label, "BD-RW   BDR-UD04 1.14");
    assert_eq!(
        dev.transcript(),
        [
            "IN   cdb=120000002400 alloc=36 -> ok 96",
            "IN   cdb=3c02f100000000003000 alloc=48 -> ok 48",
        ]
    );
    // Another vendor's drive is simply not identified.
    let mut other = mtk_drive();
    let none = Pioneer::new()
        .recovery()
        .unwrap()
        .identify(&mut ReadDevice::new(&mut other, &[]))
        .unwrap();
    assert!(none.is_none());
}

// ---- R7: the phase-0 goldens cover the design's categories ------------------

#[test]
fn golden_coverage_is_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let required: &[(&str, &str, &[&str])] = &[
        (
            "info, Pioneer",
            "info_pioneer.txt",
            &["Pioneer info: MockScsiDevice::pioneer"],
        ),
        (
            "info, MediaTek",
            "info_mtk.txt",
            &["MTK info: mock exposing a drive-read firmware image"],
        ),
        (
            "info, Unknown",
            "classify_and_unknown_info.txt",
            &["info with the Unknown handler on blank mock (matches no backend)"],
        ),
        (
            "ambiguous probe",
            "classify_and_unknown_info.txt",
            &["classify ambiguous: MediaTek and Pioneer both match"],
        ),
        (
            "info <file>, every format",
            "info_file.txt",
            &[
                "info_file mtk_flashable.bin",
                "info_file mtk_drive_read_backup.bin",
                "info_file mtk_legacy_0_10_backup.tar",
                "info_file pioneer_bundle_signed_pair.tar",
                "info_file pioneer_signed_normal.enc",
                "info_file renesas_dump.bin",
                "info_file garbage.bin",
            ],
        ),
        (
            "check, every format",
            "check_file.txt",
            &[
                "check_file mtk_flashable.bin",
                "check_file mtk_drive_read_backup.bin",
                "check_file mtk_legacy_0_10_backup.tar",
                "check_file pioneer_bundle_signed_pair.tar",
                "check_file pioneer_signed_normal.enc",
                "check_file renesas_dump.bin",
                "check_file garbage.bin",
            ],
        ),
        (
            "backup and dump",
            "backup_capture.txt",
            &[
                "MTK backup: drive-read image",
                "MTK dump (recover): raw memory",
                "Pioneer backup: bounded replay of a UD04",
                "Pioneer dump (recover): bounded replay",
            ],
        ),
        (
            "flash dry run",
            "flash_dry_run.txt",
            &[
                "MTK dry run: .bin",
                "Pioneer dry run: signed Kernel+Normal bundle",
            ],
        ),
        (
            "flash execute",
            "flash_execute.txt",
            &[
                "MTK execute: .bin with pre-flash backup",
                "Pioneer flash_bundle: plain update (no kernel patch)",
                "Pioneer flash_bundle: update with kernel restoration pass",
            ],
        ),
        (
            "Pioneer prompt, TTY and non-TTY",
            "pioneer_confirm_prompt.txt",
            &[
                "Pioneer prompt: stdin is not a TTY",
                "Pioneer prompt: TTY answers y",
                "Pioneer prompt: TTY answers n",
            ],
        ),
        (
            "partial backup and coverage refusal",
            "pioneer_plan_and_gates.txt",
            &[
                "verify_preflash_backup: Kernel-only (partial) backup vs Kernel+Normal bundle",
                "backup_notice + validate_backup: Normal-only (partial) backup",
            ],
        ),
        (
            "Refused plan",
            "pioneer_plan_and_gates.txt",
            &["resolve_flash_plan: installed=other-family Normal, plain"],
        ),
        (
            "Kernel-tag mismatch",
            "pioneer_plan_and_gates.txt",
            &["validate_bundle: Kernel-tag mismatch"],
        ),
        (
            "tray refusal",
            "flash_execute.txt",
            &["MTK execute: disc loaded", "Pioneer execute: disc loaded"],
        ),
        (
            "recover dry run and execute",
            "pioneer_recover.txt",
            &[
                "Pioneer recover dry run: receiver in normal mode",
                "Pioneer recover execute: receiver in normal mode",
            ],
        ),
    ];
    let mut missing = Vec::new();
    for (category, file, titles) in required {
        let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
        let found = sections(&text);
        for title in *titles {
            let ok = found.iter().any(|(t, lines)| {
                t == title && lines.first().is_some_and(|l| l.starts_with("result: "))
            });
            if !ok {
                missing.push(format!("{category}: {file} :: {title}"));
            }
        }
    }
    // Device scenarios carry full transcripts, tray checks included.
    let execute = std::fs::read_to_string(root.join("flash_execute.txt")).unwrap();
    if !execute.contains("--- scsi transcript (") || !execute.contains("MEDIUM -> ClosedEmpty") {
        missing.push("full transcripts with medium_status".into());
    }
    assert!(
        missing.is_empty(),
        "golden coverage gaps:\n{}",
        missing.join("\n")
    );
}

// ---- R8: conformance ---------------------------------------------------------

/// A standards-compliant drive of no registered family: it reports a complete
/// MMC firmware-information feature (0x010C) but refuses vendor buffer reads.
fn unknown_mmc_drive() -> MockScsiDevice {
    let mut inq = vec![b' '; 96];
    inq[0] = 5;
    inq[4] = 91;
    inq[8..16].copy_from_slice(b"ASUS    ");
    inq[16..32].copy_from_slice(b"BW-16D1HT       ");
    inq[32..36].copy_from_slice(b"3.10");
    let mut feature = vec![0u8; 28];
    feature[3] = 24;
    feature[8..10].copy_from_slice(&[0x01, 0x0C]);
    feature[11] = 16;
    feature[12..28].copy_from_slice(b"2019102516300000");
    MockScsiDevice::new()
        .on(|cdb| cdb.first() == Some(&0x12), inq)
        .on(
            |cdb| cdb.first() == Some(&0x46) && cdb.get(2..4) == Some(&[0x01, 0x0C][..]),
            feature,
        )
        .on_fail(|cdb| cdb.first() == Some(&0x3C), "ILLEGAL REQUEST")
}

#[test]
fn conformance_probe_rejects_unknown_mmc_drive() {
    let own: &[(&str, fn() -> MockScsiDevice)] = &[
        ("mtk19xx", MockScsiDevice::mtk),
        ("pioneer-oem", MockScsiDevice::pioneer),
    ];
    for backend in registry::backends() {
        let id = backend.descriptor().id;
        let fixture = own
            .iter()
            .find(|(name, _)| *name == id.0)
            .unwrap_or_else(|| panic!("backend {id} has no conformance fixture"))
            .1;
        let probe = |dev: &mut MockScsiDevice| {
            let identity = crate::backend::read_identity(&mut ReadDevice::new(dev, &[]));
            let found = backend
                .probe(
                    &mut ReadDevice::new(dev, backend.allowed_data_out()),
                    &identity,
                )
                .unwrap();
            let undeclared = dev.writes.iter().any(|(cdb, data)| {
                !crate::backend::device::declared(backend.allowed_data_out(), cdb, data)
            });
            assert!(!undeclared, "{id}: probe sent undeclared data-out");
            found
        };
        assert_eq!(probe(&mut fixture()).map(|m| m.backend), Some(id), "{id}");
        assert_eq!(
            probe(&mut unknown_mmc_drive()),
            None,
            "{id} claimed an unknown MMC drive"
        );
        assert_eq!(
            probe(&mut MockScsiDevice::new()),
            None,
            "{id} claimed the empty mock"
        );
    }
    let mut dev = unknown_mmc_drive();
    assert!(registry::resolve(&mut dev).unwrap().is_none());
}

#[test]
fn details_reuse_probe_data_without_repeat_reads() {
    // Info reads the identity and the standard snapshot once each; the vendor
    // identity (F1) is read only inside the snapshot.
    let mut dev = Rec::new(pioneer_with(b"", b"SN1", b"SAT 8A10"));
    let report = crate::engine::info_report(&mut dev, backend(true)).report;
    let t = dev.transcript();
    let count = |prefix: &str| t.iter().filter(|l| l.contains(prefix)).count();
    assert_eq!(count("cdb=120000006000"), 2, "{t:#?}");
    assert_eq!(count("cdb=3c02f1"), 1, "{t:#?}");
    assert!(report.rows.iter().any(|r| r.key == "hardware_type"));

    // The backend's own rows issue only their own reads.
    let mut snapshot_dev = pioneer_with(b"", b"SN1", b"SAT 8A10");
    let standard = crate::standard::read(&mut snapshot_dev);
    let read = crate::backend::InfoSoFar {
        standard: &standard,
        settings: None,
    };
    let mut dev = Rec::new(pioneer_with(b"", b"SN1", b"SAT 8A10"));
    let rows = Pioneer::new().details().unwrap().rows(
        &mut ReadDevice::new(&mut dev, &[]),
        &read,
        crate::report::Slot::AfterInterface,
    );
    assert_eq!(rows[0].value, Value::text("SAT 8A10"));
    assert!(
        dev.transcript()
            .iter()
            .all(|l| !l.contains("cdb=12") && !l.contains("cdb=3c02f1")),
        "{:#?}",
        dev.transcript()
    );
}

// ---- R12: sanitizing ---------------------------------------------------------

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

#[test]
fn every_drive_string_is_clean() {
    let dev = pioneer_with(b"2017\x1b[2J\x07", b"SN\x1b]0;x\x07", b"SAT \x1b[31m");
    let (outcome, _) = drive_run(dev, |d| crate::engine::info(d, backend(true)));
    assert_eq!(outcome.result, "OK");
    for line in outcome.text.iter().chain(&outcome.events) {
        assert!(
            !has_control(line),
            "control bytes reached a front-end: {line:?}"
        );
    }
    let replaced = |label: &str| {
        outcome
            .events
            .iter()
            .any(|e| e.starts_with(&format!("FIELD    {label} = ")) && e.contains('\u{fffd}'))
    };
    assert!(replaced("Extra information"));
    assert!(replaced("Serial number"));
    assert!(replaced("Hardware type"));
    let mut dev = pioneer_with(b"2017\x1b[2J", b"SN", b"SAT \x1b[31m");
    for row in crate::engine::info_report(&mut dev, backend(true))
        .report
        .rows
    {
        assert!(!has_control(&row.value.plain()), "{row:?}");
        assert!(
            !has_control(&row.value.cli().replace("\x1b[", "")),
            "{row:?}"
        );
    }
    assert_eq!(
        crate::report::Clean::new("a\x1bb\n").as_str(),
        "a\u{fffd}b\u{fffd}"
    );
}

#[test]
fn paths_and_hex_render_unmangled() {
    let path = PathBuf::from("dir/back\tup é.tar");
    assert_eq!(Value::Path(path.clone()).plain(), "dir/back\tup é.tar");
    assert_eq!(Value::Path(path).cli(), "dir/back\tup é.tar");
    assert_eq!(Value::Hex("00ffab".into()).cli(), "00ffab");

    // A saved backup's path reaches the GUI exactly, and the sha256 line is raw hex.
    let out = scratch("unmangled").join("back\tup é.tar");
    let (outcome, _) = drive_run(BackupReplay::new(), |d| {
        crate::engine::backup(d, &Pioneer::new(), &out, false)
    });
    assert_eq!(outcome.result, "OK");
    assert!(
        outcome
            .events
            .contains(&format!("FIELD    Saved to = {}", out.display())),
        "{:#?}",
        outcome.events
    );
    let sha = format!("{:x}", Sha256::digest(std::fs::read(&out).unwrap()));
    assert!(outcome.text.contains(&format!("candidate sha256: {sha}")));
}

// ---- R13: one recognizer -----------------------------------------------------

#[test]
fn one_recognizer_serves_flash_check_and_inspect() {
    let dir = scratch("one-recognizer");
    let legacy = legacy_mtk_tar();
    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "pioneer.tar",
            archive(&pioneer_pair(false, 0), false),
            "pioneer-oem",
            "pioneer-package",
        ),
        (
            "mixed.tar",
            pioneer_bundle_with_mtek_tag(),
            "pioneer-oem",
            "pioneer-package",
        ),
        ("legacy.tar", legacy, "mtk19xx", "mtk-legacy-tar"),
        ("image.bin", backup_firmware(), "mtk19xx", "mtk-image"),
    ];
    for (name, bytes, backend_id, format) in cases {
        let (b, r) = registry::recognize(&bytes).unwrap().expect(name);
        assert_eq!(
            (b.descriptor().id.0, r.format.id),
            (backend_id, format),
            "{name}"
        );
        let path = dir.join(name);
        std::fs::write(&path, &bytes).unwrap();
        // Flash input: the recognized format, whichever drive is attached.
        for drive in registry::backends() {
            let flash = registry::flash_input_format(drive, &path, &bytes).unwrap();
            assert_eq!(
                flash.map(|f| f.id),
                Some(format),
                "{name} to {}",
                drive.descriptor().id
            );
        }
        // Inspection: the recognized backend's inspector, or none.
        let inspected = crate::inspection::inspect(
            &crate::inspection::Source::File(path.clone()),
            &crate::inspection::Control::default(),
        );
        match (backend_id, format, inspected) {
            ("pioneer-oem", _, inspected) => {
                assert!(inspected.is_ok(), "{name}: {:?}", inspected.err())
            }
            (_, "mtk-image", Ok(inspection)) => {
                let chip = inspection.components[0]
                    .fields
                    .iter()
                    .any(|f| f.label == "Chip");
                assert!(chip, "{name} reached the wrong inspector: {inspection:?}");
            }
            (_, "mtk-image", Err(e)) => panic!("{name}: {e:#}"),
            (_, _, Ok(_)) => {}
            (_, _, Err(e)) => {
                let error = format!("{e:#}");
                assert!(
                    !error.contains("firmware package"),
                    "{name} reached the Pioneer inspector: {error}"
                );
            }
        }
    }
    // check / info <file>: the recognized backend describes the file.
    let path = dir.join("legacy.tar");
    let outcome = run(|| crate::engine::info_file(&path));
    assert!(
        outcome
            .text
            .iter()
            .any(|l| l.starts_with("chipset: MediaTek")),
        "{:#?}",
        outcome.text
    );
    let path = dir.join("mixed.tar");
    let outcome = run(|| crate::engine::info_file(&path));
    assert!(
        outcome.text.contains(&"family: Pioneer".to_string()),
        "{:#?}",
        outcome.text
    );
}

#[test]
fn ambiguous_file_is_an_error() {
    use crate::backend::{Confidence, Descriptor, FileFacet, Identity, Match, Recognized};
    struct Claims(&'static Descriptor, Confidence);
    impl Backend for Claims {
        fn descriptor(&self) -> &'static Descriptor {
            self.0
        }
        fn probe(&self, _: &mut ReadDevice<'_>, _: &Identity) -> Result<Option<Match>> {
            Ok(None)
        }
        fn files(&self) -> Option<&dyn FileFacet> {
            Some(self)
        }
    }
    impl FileFacet for Claims {
        fn recognize(&self, _: &[u8]) -> Option<Recognized> {
            Some(Recognized {
                format: &self.0.formats[0],
                confidence: self.1,
            })
        }
        fn describe(&self, _: &[u8], _: &Recognized) -> Option<Result<()>> {
            None
        }
        fn classify_input(&self, _: &Path, _: &[u8]) -> &'static FileFormat {
            &self.0.formats[0]
        }
    }
    static A: Descriptor = Descriptor {
        id: BackendId("a"),
        display_name: "A",
        flash_summary: None,
        formats: &[PIONEER_PACKAGE],
    };
    static B: Descriptor = Descriptor {
        id: BackendId("b"),
        display_name: "B",
        flash_summary: None,
        formats: &[MTK_IMAGE],
    };
    use Confidence::{Heuristic, Structural};
    static SA: Claims = Claims(&A, Structural);
    static SB: Claims = Claims(&B, Structural);
    static HA: Claims = Claims(&A, Heuristic);
    static HB: Claims = Claims(&B, Heuristic);
    let pick = |list: [&'static Claims; 2]| registry::recognize_among(list, b"x");
    for pair in [[&SA, &SB], [&HA, &HB]] {
        let error = pick(pair).err().expect("ambiguous");
        assert!(error.to_string().starts_with("ambiguous file"), "{error}");
    }
    // Structural beats heuristic in either order.
    for pair in [[&SA, &HB], [&HB, &SA]] {
        let (b, _) = pick(pair).unwrap().unwrap();
        assert_eq!(b.0.id.0, "a");
    }
    // The real backends never tie: a Pioneer package with a MediaTek tag inside
    // is the package.
    let (b, r) = registry::recognize(&pioneer_bundle_with_mtek_tag())
        .unwrap()
        .unwrap();
    assert_eq!(
        (b.descriptor().id.0, r.confidence),
        ("pioneer-oem", Structural)
    );
}

#[test]
fn settings_are_read_only() {
    let facet = Pioneer::new();
    let facet = facet.settings().expect("Pioneer exposes its settings");
    // Through a read-only device that permits no data-out at all.
    let mut dev = Rec::new(pioneer_with(b"", b"SN1", b"SAT 8A10"));
    let _ = facet.read(&mut ReadDevice::new(&mut dev, &[]));
    let t = dev.transcript();
    assert!(!t.is_empty());
    assert!(t.iter().all(|l| l.starts_with("IN ")), "{t:#?}");

    // The contract has a read and nothing else: no setter exists to call.
    let src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/backend/mod.rs"))
            .unwrap();
    let start = src.find("pub trait SettingsFacet").unwrap();
    let body = &src[start..start + src[start..].find("\n}").unwrap()];
    assert_eq!(body.matches("fn ").count(), 1, "{body}");
    assert!(
        body.contains("fn read(&self, dev: &mut ReadDevice<'_>)"),
        "{body}"
    );
}
