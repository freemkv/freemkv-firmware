//! freemkv-flash command-line interface.
//!
//! Firmware backup and flash commands; `info` is the default:
//! * `freemkv-flash <dev|file>` / `info <dev|file>` — identify + classify a
//!   live drive or a firmware image `.bin` (same family key the flash gate uses).
//! * `freemkv-flash backup <dev> [-o backup.tar]` — firmware package capture.
//! * `freemkv-flash flash <dev> -i <file> [flags]` — backed-up write path.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use freemkv_flash::drive::{self, Family, FlashRequest, InputKind};
use freemkv_flash::engine;
use freemkv_flash::manifest::FlashMode;
use freemkv_flash::platform;
use freemkv_flash::style;

/// freemkv standalone optical-drive firmware backup and flasher.
#[derive(Parser, Debug)]
#[command(
    name = "freemkv-flash",
    version,
    about,
    long_about = None,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    after_help = "\
EXAMPLES:
  # Identify the drive (read-only, safe):
  freemkv-flash info /dev/sg0

  # Save a supported backup before flashing:
  freemkv-flash backup /dev/sg0 -o backup.tar

  # Dry-run a flash — prints the plan, issues NO writes:
  freemkv-flash flash /dev/sg0 -i firmware.bin

  # Flash for real (risk of permanent failure). EJECT ANY DISC FIRST — an empty, closed
  # tray is required; flashing with a disc loaded can wedge the drive:
  freemkv-flash flash /dev/sg0 -i firmware.bin \\
      --backup backup-preflash.tar --execute --i-understand-risk

Run `freemkv-flash flash --help` for the full flash workflow and all flags."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Device (e.g. /dev/sg0) or firmware image file for the default `info` action.
    device: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List optical drives and the selector to pass to info/backup/flash. Works
    /// with an empty tray (a disc-less macOS drive has no /dev/diskN node).
    List,
    /// Identify + classify a drive OR a firmware image file (read-only; never aborts).
    Info {
        /// Drive selector (a `list` number, a /dev path, or an `ioreg:` id) or a
        /// firmware image file. Omit to auto-pick the only connected drive.
        device: Option<String>,
    },
    /// Capture firmware. Pioneer output is byte-exact OEM where recognized, else a
    /// clearly-labeled non-OEM candidate (zeroed signature).
    Backup {
        /// Drive selector (a `list` number, a /dev path, or an `ioreg:` id).
        /// Omit to auto-pick the only connected drive.
        device: Option<String>,
        /// Output .tar path (Pioneer defaults to `<model>_<rev>.candidate.tar`).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Salvage read: dump the drive's ENTIRE flash (0x000000..0x600000) as ONE raw file, even
    /// if degraded (Pioneer: a single contiguous verbatim `.bin`). A
    /// best-effort, unverified capture — NOT a flashable backup. Read-only; never
    /// uses vendor kernel mode. `--force` stops trusting what the drive reports.
    Dump {
        /// Drive selector (a `list` number, a /dev path, or an `ioreg:` id).
        /// Omit to auto-pick the only connected drive.
        device: Option<String>,
        /// Output path (defaults to `<model>_<rev>.<infix>.<ext>`).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Trust nothing the drive reports: identity/layout failures become
        /// warnings and the read proceeds anyway (degraded/soft-bricked drives).
        /// Still read-only; no kernel mode.
        #[arg(long)]
        force: bool,
    },
    /// Flash firmware or roll back firmware from a supported backup (WRITE).
    Flash(FlashArgs),
}

/// Flash a firmware image (.bin) or roll back firmware from a backup .tar.
/// Per-unit data in the archive is retained as reference, not auto-written.
///
/// Without `--execute` this is a DRY RUN: it prints the full plan and a read-only
/// readiness handshake but issues no writes. Add `--execute --i-understand-risk`
/// to actually program the flash; a failed flash can permanently disable the drive.
///
/// EJECT ANY DISC FIRST: the flash requires an empty, closed tray. Reprogramming
/// while the drive is servicing a medium can wedge the controller mid-program.
#[derive(Parser, Debug)]
#[command(after_help = "\
FLASH WORKFLOW:
  1. freemkv-flash info  /dev/sg0                      # confirm the drive + family
  2. freemkv-flash backup /dev/sg0 -o backup.tar       # save a backup first
  3. EJECT any disc so the tray is empty and closed
  4. freemkv-flash flash /dev/sg0 -i firmware.bin      # DRY RUN — review the plan
  5. freemkv-flash flash /dev/sg0 -i firmware.bin \\
         --backup backup-preflash.tar --execute --i-understand-risk   # for real

Do not power off or disconnect the drive during step 5.")]
struct FlashArgs {
    /// Drive selector (a `list` number, a /dev path, or an `ioreg:` id).
    /// Omit to auto-pick the only connected drive.
    device: Option<String>,
    /// Input: MTK image (.bin), complete backup (.tar), Pioneer .enc, or a Pioneer envelope tar.
    /// A backup .tar rolls back firmware; per-unit reference data is not auto-written.
    /// Pioneer inputs are dry-run by default; live writes need --execute --i-understand-risk and a pre-flash backup.
    #[arg(short, long)]
    input: PathBuf,
    /// Where to save the mandatory pre-flash backup.
    #[arg(short, long)]
    backup: Option<PathBuf>,
    /// Skip the mandatory pre-flash backup. DANGEROUS: no rollback if the write
    /// fails. Without this, a failed backup aborts the flash.
    #[arg(long)]
    skip_backup: bool,
    /// Streaming mode: `main` or `full`. NOTE: on the currently-supported
    /// MediaTek family this is informational only — the full 2 MiB image is
    /// always streamed and the commit handshake is always sent regardless of
    /// which mode is selected.
    #[arg(long, value_enum, default_value_t = ModeArg::Full)]
    mode: ModeArg,
    /// Actually issue SCSI writes (otherwise dry-run only).
    #[arg(long)]
    execute: bool,
    /// Acknowledge that flashing can permanently brick the drive.
    #[arg(long)]
    i_understand_risk: bool,
    /// EXPERIMENTAL: crossflash a DIFFERENT same-chipset model's firmware (e.g. a
    /// UHD-friendly crossflash). Waives the model match but NEVER the chipset-family
    /// gate (MT1959->MT1959 only). Hardware-unvalidated — high brick risk.
    #[arg(long)]
    allow_crossflash: bool,
    /// RECOVER a degraded/soft-bricked drive: re-push the given (same or
    /// known-good) firmware through the ordinary OEM-update route. Waives the
    /// pre-flash backup, the post-entry identity gate and the older/downgrade
    /// refusals; the firmware-family match still applies unless --force. Needs
    /// --execute --i-understand-risk. EXPERIMENTAL, hardware-unvalidated.
    #[arg(long)]
    recover: bool,
    /// Ignore the firmware-family match (Pioneer). By default a flash proceeds
    /// only when the installed and target firmware profile to the SAME family;
    /// --force skips that check. DANGEROUS: flashing another family can brick the
    /// drive.
    #[arg(long)]
    force: bool,
    /// Show the raw SCSI CDB sequence in the plan (default: clean summary).
    #[arg(short = 'v', long)]
    verbose: bool,
    /// Hidden expert override: force the enc envelope on.
    #[arg(long, hide = true)]
    enc: bool,
    /// Hidden expert override: force the enc envelope off (plaintext).
    #[arg(long, hide = true, conflicts_with = "enc")]
    no_enc: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ModeArg {
    Main,
    Full,
}

impl From<ModeArg> for FlashMode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Main => FlashMode::Main,
            ModeArg::Full => FlashMode::Full,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::List) => cmd_list(),
        Some(Command::Info { device }) => cmd_info(device.as_deref()),
        Some(Command::Backup { device, out }) => cmd_backup(device.as_deref(), out, false, false),
        Some(Command::Dump { device, out, force }) => {
            cmd_backup(device.as_deref(), out, true, force)
        }
        Some(Command::Flash(args)) => cmd_flash(args),
        None => cmd_info(cli.device.as_deref()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e:#}", style::red("error:"));
            ExitCode::FAILURE
        }
    }
}

fn cmd_info(target: Option<&str>) -> Result<()> {
    // A regular file is a firmware image → classify the FILE (no drive needed);
    // anything else (a selector, a /dev node, or nothing) → probe the DRIVE.
    if let Some(t) = target {
        if is_firmware_file(t) {
            return engine::info_file(Path::new(t));
        }
    }
    let selector = resolve_device(target)?;
    let mut dev = platform::open(&selector, false)?;
    let family = resolved_family(dev.as_mut())?;
    let handler = drive::for_family(family);
    engine::info(dev.as_mut(), handler.as_ref())
}

/// Turn an optional user selector into a concrete device selector.
/// - a bare integer `N` → the Nth drive from `list` (1-based)
/// - any other string → used verbatim (a `/dev` path or an `ioreg:` id)
/// - `None` → the only connected drive, or an error listing the choices
fn resolve_device(arg: Option<&str>) -> Result<String> {
    if let Some(a) = arg {
        if let Ok(n) = a.parse::<usize>() {
            let drives = platform::list_drives();
            let d = n
                .checked_sub(1)
                .and_then(|i| drives.get(i))
                .with_context(|| format!("no drive #{a}; run `freemkv-flash list`"))?;
            return Ok(d.path.clone());
        }
        return Ok(a.to_string());
    }
    let drives = platform::list_drives();
    match drives.as_slice() {
        [] => bail!("no optical drive found (is one connected and powered on?)"),
        [only] => Ok(only.path.clone()),
        many => {
            let mut msg =
                String::from("multiple drives found — pass a number or path (or run `list`):\n");
            for (i, d) in many.iter().enumerate() {
                msg.push_str(&format!(
                    "  {}  {}  {} {}\n",
                    i + 1,
                    d.path,
                    style::printable(&d.vendor),
                    style::printable(&d.model)
                ));
            }
            bail!(msg)
        }
    }
}

/// Route the `info` argument: a path that exists as a **regular file** is a
/// firmware image (file info); a SCSI **device node** (`/dev/sg*`, a char/block
/// device) or a nonexistent path is a live drive to probe. Firmware images are
/// regular files and device nodes are not, so the two split cleanly with no flag.
fn is_firmware_file(target: &str) -> bool {
    std::fs::metadata(target)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Resolve the backend registry while preserving probe and ambiguity errors.
fn resolved_family(dev: &mut dyn platform::ScsiDevice) -> Result<Family> {
    Ok(drive::resolve_backend(dev)?
        .map(|matched| matched.evidence.family)
        .unwrap_or(Family::Unknown))
}

/// Resolve a protocol with an executable flash implementation.
fn classify_gated(dev: &mut dyn platform::ScsiDevice) -> Result<Family> {
    let family = resolved_family(dev)?;
    if !drive::for_family(family).capabilities().flash {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(family)
}

/// Classify a drive for a backend's backup path.
fn classify_for_backup(dev: &mut dyn platform::ScsiDevice) -> Result<Family> {
    let family = resolved_family(dev)?;
    if !drive::for_family(family).capabilities().backup {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(family)
}

fn cmd_list() -> Result<()> {
    let drives = platform::list_drives();
    if drives.is_empty() {
        println!("{}", style::kv("drives", "none found"));
        return Ok(());
    }
    // `path` is the selector to pass to info/backup/flash — a /dev node when a
    // disc is present, or an `ioreg:<id>` for an empty macOS drive.
    for d in &drives {
        println!(
            "{}",
            style::kv(
                &d.path,
                &format!(
                    "{} {} (rev {})",
                    style::printable(&d.vendor),
                    style::printable(&d.model),
                    style::printable(&d.firmware)
                )
            )
        );
    }
    Ok(())
}

fn cmd_backup(
    device: Option<&str>,
    out: Option<PathBuf>,
    recover: bool,
    force: bool,
) -> Result<()> {
    // backup/dump are read-only (no kernel mode), so the device is opened
    // read-only.
    let selector = resolve_device(device)?;
    let mut dev = platform::open(&selector, false)?;
    let family = classify_for_backup(dev.as_mut())?;
    let handler = drive::for_family(family);
    if recover && !handler.capabilities().recover {
        // No distinct deeper recover for this family: a normal backup already
        // captures a complete image, so fall through and run one.
        eprintln!(
            "note: {} has no deeper recover; running a normal backup",
            handler.backend_name()
        );
    }
    let out = match out {
        Some(o) => o,
        None => {
            let id = handler.identity(dev.as_mut());
            let s: String = format!("{}_{}", id.product, id.revision)
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let extension = handler
                .backup_extension()
                .context("backend has no backup format")?;
            if recover && handler.dump_is_raw() {
                // A raw dump is a single flat memory image, not a backup archive.
                PathBuf::from(format!("{s}.dump.bin"))
            } else {
                // Filename infix (`backup` / `candidate`) comes from the backend,
                // so the CLI names no chipset.
                PathBuf::from(format!("{s}.{}.{extension}", handler.backup_kind().infix))
            }
        }
    };
    engine::backup(dev.as_mut(), handler.as_ref(), &out, recover, force)
}

fn cmd_flash(args: FlashArgs) -> Result<()> {
    let input = read_capped(&args.input)
        .with_context(|| format!("reading input {}", args.input.display()))?;
    let selector = resolve_device(args.device.as_deref())?;
    let mut dev = platform::open(&selector, args.execute)?;
    let family = classify_gated(dev.as_mut())?;
    let handler = drive::for_family(family);
    let input_kind = if family == Family::Pioneer {
        if freemkv_flash::pioneer_bundle::Bundle::from_tar_bytes(&input).is_ok() {
            InputKind::PioneerBundle
        } else if args.input.extension().is_some_and(|ext| ext == "tar") {
            // Preserve the specific package-parse error in the Pioneer path.
            InputKind::PioneerBundle
        } else {
            InputKind::Bin
        }
    } else {
        handler.classify_input(&args.input)
    };

    let drive_model = handler.identity(dev.as_mut()).product;
    let enc_override = if args.enc {
        Some(true)
    } else if args.no_enc {
        Some(false)
    } else {
        None
    };
    // Recovery waives the mandatory pre-flash backup (a degraded drive may not be
    // readable, and recovery is the last resort anyway).
    let predump_out = if args.recover {
        None
    } else {
        args.backup.clone().or_else(|| {
            handler
                .backup_extension()
                .and_then(|ext| default_backup_path(&args.input, ext))
        })
    };

    let req = FlashRequest {
        input,
        input_kind,
        mode: args.mode.into(),
        execute: args.execute,
        acknowledged_risk: args.i_understand_risk,
        enc_override,
        drive_model,
        verbose: args.verbose,
        predump_out,
        allow_crossflash: args.allow_crossflash,
        skip_backup: args.skip_backup || args.recover,
        recover: args.recover,
        force: args.force,
    };
    engine::flash(dev.as_mut(), handler.as_ref(), &req)
}

/// Read a firmware input file with a hard size cap, so a huge file or an endless
/// source (e.g. `/dev/zero`, a FIFO) cannot exhaust memory before the per-family
/// size validation runs. The cap is far above any real firmware/backup artifact
/// (largest Pioneer envelope is ~4.5 MiB; an MTK image 2 MiB).
fn read_capped(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    const MAX_INPUT: u64 = 64 * 1024 * 1024;
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(MAX_INPUT + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_INPUT {
        bail!(
            "input {} exceeds the {} MiB cap for a firmware file; refusing to load",
            path.display(),
            MAX_INPUT / (1024 * 1024)
        );
    }
    Ok(buf)
}

/// Default pre-flash backup path: `<input>.preflash.backup.<backend-extension>`.
fn default_backup_path(input: &Path, extension: &str) -> Option<PathBuf> {
    let name = input.file_name()?.to_string_lossy();
    Some(input.with_file_name(format!("{name}.preflash.backup.{extension}")))
}

#[cfg(test)]
mod tests {
    use super::{is_firmware_file, Cli, Command};
    use clap::Parser;

    #[test]
    fn backup_dump_and_flash_recover_parse() {
        // backup = the trusted capture.
        assert!(matches!(
            Cli::try_parse_from(["freemkv-flash", "backup", "/dev/sg0"])
                .expect("backup")
                .command,
            Some(Command::Backup { .. })
        ));
        // dump = salvage read; --force trusts nothing the drive reports.
        assert!(matches!(
            Cli::try_parse_from(["freemkv-flash", "dump", "/dev/sg0"])
                .expect("dump")
                .command,
            Some(Command::Dump { force: false, .. })
        ));
        assert!(matches!(
            Cli::try_parse_from(["freemkv-flash", "dump", "/dev/sg0", "--force"])
                .expect("dump --force")
                .command,
            Some(Command::Dump { force: true, .. })
        ));
        // The old `recover` command is gone (it moved onto `flash`).
        assert!(Cli::try_parse_from(["freemkv-flash", "recover", "/dev/sg0"]).is_err());
        // flash --recover parses and sets the recover flag.
        match Cli::try_parse_from([
            "freemkv-flash",
            "flash",
            "/dev/sg0",
            "-i",
            "fw.bin",
            "--recover",
        ])
        .expect("flash --recover")
        .command
        {
            Some(Command::Flash(a)) => assert!(a.recover && !a.force),
            other => panic!("expected flash, got {other:?}"),
        }
        // flash --force parses and sets the family-bypass flag.
        match Cli::try_parse_from([
            "freemkv-flash",
            "flash",
            "/dev/sg0",
            "-i",
            "fw.bin",
            "--force",
        ])
        .expect("flash --force")
        .command
        {
            Some(Command::Flash(a)) => assert!(a.force && !a.recover),
            other => panic!("expected flash, got {other:?}"),
        }
    }

    #[test]
    fn regular_file_routes_to_file_info() {
        let p = std::env::temp_dir().join(format!("fmkv_info_dispatch_{}.bin", std::process::id()));
        std::fs::write(&p, b"a regular file, contents irrelevant to dispatch").unwrap();
        assert!(is_firmware_file(p.to_str().unwrap()));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn device_node_routes_to_drive() {
        // /dev/null exists but is a char device, not a regular file → drive path.
        assert!(!is_firmware_file("/dev/null"));
    }

    #[test]
    fn nonexistent_path_routes_to_drive() {
        assert!(!is_firmware_file("/dev/sg-does-not-exist-42"));
    }
}
