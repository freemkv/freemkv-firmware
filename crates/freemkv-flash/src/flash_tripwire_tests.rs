//! Tripwires for the two-stage flash (design findings R1, R2 and R5): `plan`
//! needs no backup, `authorize` runs the installed-firmware gates after it,
//! `execute` writes only through a grant that requires the saved backup, and
//! the behaviours the old single-stage flow had are kept.

use super::*;
use crate::backend::{AuthorizedPlan, Confirm, FlashPlan, PlanLine, SavedBackup, WriteDevice};

/// The (installed backup, target package) pair the Pioneer executor goldens
/// use: a plain update, or one that needs the Kernel restoration pass.
fn pioneer_update(restore: bool) -> (Vec<u8>, Vec<u8>) {
    (
        archive(&prepared_pair(restore, 1), false),
        archive(&prepared_pair(false, 0), false),
    )
}

fn pioneer_plan(target: Vec<u8>) -> FlashPlan {
    let req = pioneer_request(target, &PIONEER_PACKAGE, true);
    let mut dev = MockScsiDevice::new();
    Pioneer::new()
        .plan(&mut ReadDevice::new(&mut dev, &[]), &req)
        .expect("a package plans without its drive")
}

fn authorize(plan: FlashPlan, installed: Vec<u8>) -> Result<AuthorizedPlan> {
    let mut dev = MockScsiDevice::new();
    let saved = crate::engine::gates::saved_for_tests(installed);
    let result = Pioneer::new().authorize(&mut ReadDevice::new(&mut dev, &[]), plan, &saved);
    assert!(dev.reads.is_empty() && dev.writes.is_empty());
    result
}

/// A front-end that records what it was asked and declines.
#[derive(Default)]
struct Decline(Vec<Option<String>>);

impl Confirm for Decline {
    fn confirm(&mut self, plan: &AuthorizedPlan) -> Result<bool> {
        self.0.push(plan.confirmation.clone());
        Ok(false)
    }
}

fn text_index(outcome: &Outcome, needle: &str) -> usize {
    outcome
        .text
        .iter()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no {needle:?} in {:#?}", outcome.text))
}

#[test]
fn flash_plan_needs_no_backup() {
    // MediaTek: an execute plan with no backup destination reads only the chip
    // identity; the firmware is never read.
    let image = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    let req = mtk_request(image.clone(), true, None);
    let mut dev = Rec::new(mtk_drive());
    let plan = Mtk
        .plan(&mut ReadDevice::new(&mut dev, &[]), &req)
        .expect("plan without a backup");
    assert!(plan.after_backup.contains(&PlanLine::Backup));
    assert_eq!(
        dev.transcript(),
        ["IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256"]
    );

    // Pioneer: planned from the package alone, against a drive that is not a
    // Pioneer, with nothing installed known.
    let (_, target) = pioneer_update(false);
    let req = pioneer_request(target, &PIONEER_PACKAGE, true);
    let mut dev = Rec::new(MockScsiDevice::new());
    Pioneer::new()
        .plan(&mut ReadDevice::new(&mut dev, &[]), &req)
        .expect("plan without a backup");
    assert!(dev.transcript().is_empty());

    // The engine's first stage alone: the tray, then the plan; nothing saved.
    let (outcome, transcript) = drive_run(mtk_drive(), |d| {
        crate::engine::plan_flash(d, &Mtk, &mtk_request(image, true, None)).map(drop)
    });
    assert_eq!(outcome.result, "OK");
    assert_eq!(
        transcript,
        [
            "MEDIUM -> ClosedEmpty",
            "IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256"
        ]
    );
}

#[test]
fn flash_authorize_runs_pioneer_installed_gates_after_backup() {
    // One plan, made before any backup; what authorize decides depends only
    // on the installed firmware in the saved backup.
    let (plain, target) = pioneer_update(false);
    let (barrier, _) = pioneer_update(true);
    let authorized = authorize(pioneer_plan(target.clone()), plain).expect("plain update");
    assert!(authorized.warnings.is_empty());

    let authorized = authorize(pioneer_plan(target.clone()), barrier).expect("barrier update");
    assert_eq!(
        authorized.warnings.len(),
        1,
        "the generation barrier is a property of the installed Kernel"
    );
    assert!(authorized.warnings[0].contains("generation barrier"));

    // An installed backup without a Kernel cannot establish the receiver.
    let pair = prepared_pair(true, 1);
    let normal_only = tar_of(&[(
        "normal.enc",
        &pair.normal().repack(&pair.normal().image).unwrap(),
    )]);
    let error = authorize(pioneer_plan(target), normal_only).err().unwrap();
    assert!(
        format!("{error:#}").contains("unknown_installed_kernel"),
        "{error:#}"
    );
}

#[test]
fn pioneer_confirmation_text_is_returned_not_prompted() {
    let (installed, target) = pioneer_update(false);
    let plan = pioneer_plan(target);
    let mut authorized = None;
    let outcome = run(|| {
        authorized = Some(authorize(plan, installed)?);
        Ok(())
    });
    assert_eq!(outcome.result, "OK");
    assert!(
        outcome.events.is_empty(),
        "authorize printed or prompted: {:#?}",
        outcome.events
    );
    assert_eq!(
        authorized.unwrap().confirmation.as_deref(),
        Some("This will flash: KERNEL (rev 0000) + NORMAL (rev 1.00)")
    );

    // The engine shows the text and asks the front-end; a decline writes nothing.
    let mut front_end = Decline::default();
    let (outcome, transcript) = drive_run(MockScsiDevice::echoing(), |d| {
        crate::engine::flash(d, &Confirming, &confirming_request(), &mut front_end)
    });
    assert_eq!(outcome.result, "ERR flash aborted at confirmation prompt");
    assert_eq!(front_end.0, [Some(CONFIRM_TEXT.to_string())]);
    assert!(outcome.text.iter().any(|l| l == CONFIRM_TEXT));
    assert!(
        transcript.iter().all(|l| !l.starts_with("OUT")),
        "{transcript:#?}"
    );
}

#[test]
fn flash_never_writes_without_saved_backup() {
    // A failed backup read stops both backends before any data-out.
    let image = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    let dir = scratch("never-without-backup");
    let unreadable = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on_fail(
            |cdb| cdb.first() == Some(&0x3c) && cdb.get(3..6) == Some(&[0x10, 0, 0][..]),
            "unreadable main",
        );
    let req = mtk_request(image, true, Some(dir.join("mtk.bin")));
    let (outcome, transcript) = drive_run(unreadable, |d| engine_flash(d, &Mtk, &req));
    assert!(
        outcome.result.contains("pre-flash backup failed"),
        "{}",
        outcome.result
    );
    assert!(
        transcript.iter().all(|l| !l.starts_with("OUT")),
        "{transcript:#?}"
    );
    assert!(!dir.join("mtk.bin").exists());

    let (_, target) = pioneer_update(false);
    let mut req = pioneer_request(target, &PIONEER_PACKAGE, true);
    req.predump_out = Some(dir.join("pioneer.tar"));
    let (outcome, transcript) = drive_run(MockScsiDevice::pioneer(), |d| {
        engine_flash(d, &Pioneer::new(), &req)
    });
    assert!(
        outcome.result.contains("pre-flash backup failed"),
        "{}",
        outcome.result
    );
    assert!(
        transcript.iter().all(|l| !l.starts_with("OUT")),
        "{transcript:#?}"
    );

    // A backend whose backup fails is never handed a write grant.
    let mut dev = MockScsiDevice::echoing();
    let mut req = confirming_request();
    req.predump_out = Some(dir.join("fails.bin"));
    let error =
        crate::engine::flash(&mut dev, &FailingBackup, &req, &mut Decline::default()).unwrap_err();
    assert!(format!("{error:#}").contains("no capture"), "{error:#}");
    assert!(dev.writes.is_empty());
}

#[test]
fn post_flash_identity_check_fails_unconfirmed_flash() {
    // The image streams and reads back cleanly, but the rebooted drive's
    // firmware identity cannot be read: the flash is not confirmed.
    let dir = scratch("unconfirmed");
    let image = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    let dev = MockScsiDevice::echoing()
        .with_firmware_image(backup_firmware())
        .on_fail_after_stream(
            |cdb| cdb == crate::backends::mtk::cdb::read_memory(0x3000, 32).as_slice(),
            "drive still re-enumerating",
        );
    let req = mtk_request(image, true, Some(dir.join("rollback.bin")));
    let (outcome, transcript) = drive_run(dev, |d| engine_flash(d, &Mtk, &req));
    assert!(
        outcome
            .result
            .contains("firmware-identity read-back errored"),
        "{}",
        outcome.result
    );
    assert!(
        transcript.iter().any(|l| l.starts_with("OUT")),
        "the image was written"
    );
    assert!(outcome.text.iter().any(|l| l.contains("flash complete .")));
    assert!(!outcome.text.iter().any(|l| l.starts_with("firmware now")));
}

#[test]
fn backup_candidate_infix_and_sha_line_kept() {
    let identity = crate::backend::Identity {
        product: "BD-RW   BDR-UD04".into(),
        revision: "1.14".into(),
        ..Default::default()
    };
    let pioneer = Pioneer::new().backup().unwrap().format();
    assert_eq!(
        crate::workflow::default_backup_name(&identity, Some(pioneer), false).unwrap(),
        PathBuf::from("BD-RW___BDR-UD04_1.14.candidate.tar")
    );
    let mtk = Mtk.backup().unwrap().format();
    assert_eq!(
        crate::workflow::default_backup_name(&identity, Some(mtk), false).unwrap(),
        PathBuf::from("BD-RW___BDR-UD04_1.14.backup.bin")
    );

    let out = scratch("candidate").join("pioneer.tar");
    let (outcome, _) = drive_run(BackupReplay::new(), |d| {
        crate::engine::backup(d, &Pioneer::new(), &out, false)
    });
    assert_eq!(outcome.result, "OK");
    let sha = format!("{:x}", Sha256::digest(std::fs::read(&out).unwrap()));
    assert!(outcome.text.contains(&format!("candidate sha256: {sha}")));
    assert!(outcome
        .events
        .contains(&format!("FIELD    Saved to = {}", out.display())));
}

#[test]
fn raw_dump_name_and_line_kept() {
    let identity = crate::backend::Identity {
        product: "BD-RW   BDR-UD04".into(),
        revision: "1.14".into(),
        ..Default::default()
    };
    let format = Pioneer::new().backup().unwrap().format();
    assert_eq!(
        crate::workflow::default_backup_name(&identity, Some(format), true).unwrap(),
        PathBuf::from("BD-RW___BDR-UD04_1.14.dump.bin")
    );
    assert_eq!(
        crate::workflow::default_backup_name(&identity, None, true).unwrap(),
        PathBuf::from("BD-RW___BDR-UD04_1.14.dump.bin")
    );

    let out = scratch("raw-dump").join("pioneer.dump.bin");
    let (outcome, _) = drive_run(BackupReplay::new(), |d| {
        crate::engine::backup(d, &Pioneer::new(), &out, true)
    });
    assert_eq!(outcome.result, "OK");
    assert_eq!(
        outcome.text.last().map(String::as_str),
        Some("RAW DUMP: device memory and diagnostic sections; NOT a flashable backup.")
    );
    assert!(outcome
        .events
        .contains(&"FIELD    Artifact = Raw memory dump — not a flashable backup".to_string()));
}

#[test]
fn saved_backup_kept_when_authorize_refuses() {
    // The replayed UD04 backs up completely, then authorize refuses this
    // package against the installed firmware it found.
    let dir = scratch("authorize-refuses");
    let out = dir.join("preflash.tar");
    let (_, target) = pioneer_update(false);
    let mut req = pioneer_request(target, &PIONEER_PACKAGE, true);
    req.predump_out = Some(out.clone());
    let mut front_end = Decline::default();
    let (outcome, transcript) = drive_run(BackupReplay::new(), |d| {
        crate::engine::flash(d, &Pioneer::new(), &req, &mut front_end)
    });
    assert!(outcome.result.starts_with("ERR "), "{}", outcome.result);
    assert!(
        !outcome.result.contains("confirmation"),
        "{}",
        outcome.result
    );
    assert!(
        front_end.0.is_empty(),
        "authorize refused before the confirmation"
    );
    let saved = std::fs::read(&out).expect("the backup is kept");
    BackupFacet::validate(&Pioneer::new(), &saved, "BD-RW   BDR-UD04").unwrap();
    let line = text_index(&outcome, &format!("backup: saved {}", out.display()));
    assert_eq!(
        line,
        outcome.text.len() - 1,
        "the backup line is the last output"
    );
    let knock = "OUT  cdb=3b0241a5aaaa00000000";
    assert!(
        transcript
            .iter()
            .filter(|l| l.starts_with("OUT"))
            .all(|l| l.starts_with(knock)),
        "{transcript:#?}"
    );
}

#[test]
fn dry_run_keeps_tray_warning_and_mtk_preflight() {
    let image = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    let req = mtk_request(image, false, None);
    let (outcome, transcript) = drive_run(mtk_drive().with_medium_loaded(), |d| {
        engine_flash(d, &Mtk, &req)
    });
    assert_eq!(outcome.result, "OK");
    assert_eq!(
        outcome.text[0],
        "WARNING: a disc is loaded. An actual flash requires a closed, empty tray."
    );
    assert!(text_index(&outcome, "preflight ....") > text_index(&outcome, "== flash plan =="));
    assert!(outcome
        .text
        .last()
        .unwrap()
        .starts_with("DRY RUN: no firmware writes"));
    assert_eq!(
        transcript,
        [
            "MEDIUM -> DiscPresent",
            "IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256",
            "IN   cdb=3c06001ec000000100000000 alloc=256 -> ok 256",
            "IN   cdb=000000000000000000000000 alloc=0 -> ok 0",
        ]
    );

    // Pioneer's dry run plans from the file: no tray check, no I/O at all.
    let (_, target) = pioneer_update(false);
    let req = pioneer_request(target, &PIONEER_PACKAGE, false);
    let (outcome, transcript) = drive_run(MockScsiDevice::pioneer().with_medium_loaded(), |d| {
        engine_flash(d, &Pioneer::new(), &req)
    });
    assert_eq!(outcome.result, "OK");
    assert!(transcript.is_empty(), "{transcript:#?}");
    assert_eq!(
        outcome.text.last().unwrap(),
        "DRY RUN: no device I/O or writes."
    );
}

#[test]
fn mtk_execute_prints_plan_after_backup_summary() {
    let dir = scratch("plan-after-backup");
    let out = dir.join("rollback.bin");
    let image = make_flashable(vec![0x11u8; IMAGE_SIZE], "BD-RE BU40N");
    let req = mtk_request(image, true, Some(out.clone()));
    let dev = MockScsiDevice::echoing().with_firmware_image(backup_firmware());
    let (outcome, _) = drive_run(dev, |d| engine_flash(d, &Mtk, &req));
    assert_eq!(outcome.result, "OK");
    let last_backup_read = outcome
        .text
        .iter()
        .rposition(|l| l.starts_with("reading drive memory"))
        .expect("backup progress");
    let header = text_index(&outcome, "== flash plan ==");
    let backup = text_index(&outcome, "backup: saved ");
    assert!(last_backup_read < header && header < backup);
    assert!(outcome.text[backup].contains(&out.display().to_string()));
    assert!(backup < text_index(&outcome, "EXECUTING flash"));
}

// ---- the CLI prompt, recorded against v0.11.2 --------------------------------

/// The confirmation text the prompt goldens show (a Pioneer package summary).
const CONFIRM_TEXT: &str = "This will flash: KERNEL (rev 0000) + NORMAL (rev 1.00)";

/// The CLI's prompt core with the terminal check and input scripted.
struct Scripted {
    is_tty: bool,
    input: &'static str,
}

impl Confirm for Scripted {
    fn confirm(&mut self, _plan: &AuthorizedPlan) -> Result<bool> {
        let mut reader = self.input.as_bytes();
        crate::output::confirm_with(self.is_tty, &mut reader)
    }
}

/// The engine showing a confirmation and the CLI answering it, TTY and not.
#[test]
fn golden_pioneer_confirm_prompt() {
    let mut g = Golden::default();
    for (title, is_tty, input) in [
        ("Pioneer prompt: stdin is not a TTY", false, ""),
        ("Pioneer prompt: TTY answers y", true, "y\n"),
        ("Pioneer prompt: TTY answers yes", true, "YES\n"),
        ("Pioneer prompt: TTY answers n", true, "n\n"),
        ("Pioneer prompt: TTY input ends", true, ""),
    ] {
        let mut dev = MockScsiDevice::echoing();
        let mut cli = Scripted { is_tty, input };
        let outcome =
            run(|| crate::engine::flash(&mut dev, &Confirming, &confirming_request(), &mut cli));
        g.case(title, &outcome, None);
    }
    check("pioneer_confirm_prompt", g);
}

// ---- a minimal backend for engine-order checks ------------------------------

fn confirming_request() -> FlashRequest {
    let mut req = mtk_request(vec![1], true, None);
    req.predump_out = Some(scratch("confirming").join("backup.bin"));
    req
}

/// A backend whose backup always saves and whose authorize asks a question.
struct Confirming;

/// A backend whose backup capture always fails.
struct FailingBackup;

static TEST_FORMATS: &[FileFormat] = &[];
static CONFIRMING: crate::backend::Descriptor = crate::backend::Descriptor {
    id: BackendId("test-confirming"),
    display_name: "Test",
    flash_summary: None,
    formats: TEST_FORMATS,
};

macro_rules! test_backend {
    ($ty:ty, $capture:expr) => {
        impl Backend for $ty {
            fn descriptor(&self) -> &'static crate::backend::Descriptor {
                &CONFIRMING
            }
            fn probe(
                &self,
                _: &mut ReadDevice<'_>,
                _: &crate::backend::Identity,
            ) -> Result<Option<crate::backend::Match>> {
                Ok(None)
            }
            fn backup(&self) -> Option<&dyn BackupFacet> {
                Some(self)
            }
            fn flash(&self) -> Option<&dyn FlashFacet> {
                Some(self)
            }
        }
        impl BackupFacet for $ty {
            fn format(&self) -> crate::backend::BackupFormat {
                crate::backend::BackupFormat {
                    extension: "bin",
                    infix: "backup",
                }
            }
            fn capture(&self, _: &mut ReadDevice<'_>) -> Result<Vec<u8>> {
                $capture
            }
            fn notice(&self, _: &[u8]) -> crate::backend::BackupNotice {
                crate::backend::BackupNotice::None
            }
            fn validate(&self, bytes: &[u8], _: &str) -> Result<Vec<u8>> {
                Ok(bytes.to_vec())
            }
        }
        impl FlashFacet for $ty {
            fn plan(&self, _: &mut ReadDevice<'_>, _: &FlashRequest) -> Result<FlashPlan> {
                Ok(FlashPlan::new(()))
            }
            fn authorize(
                &self,
                _: &mut ReadDevice<'_>,
                plan: FlashPlan,
                _: &SavedBackup,
            ) -> Result<AuthorizedPlan> {
                let mut authorized = AuthorizedPlan::new(plan, ());
                authorized.confirmation = Some(CONFIRM_TEXT.into());
                Ok(authorized)
            }
            fn execute(&self, dev: &mut WriteDevice<'_>, _: &AuthorizedPlan) -> Result<()> {
                dev.command_out(&[0x3b, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0])
            }
        }
    };
}

test_backend!(Confirming, Ok(vec![0xAA; 16]));
test_backend!(FailingBackup, bail!("no capture"));
