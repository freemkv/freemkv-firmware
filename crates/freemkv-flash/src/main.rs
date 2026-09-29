//! freemkv-flash command-line interface.
//!
//! Firmware backup and flash commands; `info` is the default:
//! * `freemkv-flash <dev|file>` / `info <dev|file>` — identify + classify a
//!   live drive or a firmware image `.bin` (same family key the flash gate uses).
//! * `freemkv-flash backup <dev> [-o backup.tar]` — firmware package capture.
//! * `freemkv-flash flash <dev> -i <file> [flags]` — backed-up write path.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
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
    /// Identify + classify a drive OR a firmware image file (read-only; never aborts).
    Info {
        /// SCSI device path (e.g. /dev/sg0) or a firmware image file (.bin).
        device: String,
    },
    /// Save a firmware backup; current Pioneer profile is BDR-UD04 1.14.
    Backup {
        /// SCSI device path (e.g. /dev/sg0).
        device: String,
        /// Output .tar path (default: `<product>_<rev>.backup.tar`).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Matching signed OEM Kernel+Normal tar (currently UD04 1.14 only).
        #[arg(long)]
        template: Option<PathBuf>,
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
  2. freemkv-flash backup /dev/sg0 -o backup.tar       # save a restorable backup
  3. EJECT any disc so the tray is empty and closed
  4. freemkv-flash flash /dev/sg0 -i firmware.bin      # DRY RUN — review the plan
  5. freemkv-flash flash /dev/sg0 -i firmware.bin \\
         --backup backup-preflash.tar --execute --i-understand-risk   # for real

Do not power off or disconnect the drive during step 5.")]
struct FlashArgs {
    /// SCSI device path (e.g. /dev/sg0).
    device: String,
    /// Input: MTK image (.bin), complete backup (.tar), Pioneer .enc, or a Pioneer envelope tar.
    /// A backup .tar rolls back firmware; per-unit reference data is not auto-written.
    /// Pioneer inputs can be dry-run; live writes remain blocked pending a restorable backup.
    #[arg(short, long)]
    input: PathBuf,
    /// Where to save the mandatory pre-flash backup.
    #[arg(short, long)]
    backup: Option<PathBuf>,
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
        Some(Command::Info { device }) => cmd_info(&device),
        Some(Command::Backup {
            device,
            out,
            template,
        }) => cmd_backup(&device, out, template),
        Some(Command::Flash(args)) => cmd_flash(args),
        None => match cli.device {
            Some(device) => cmd_info(&device),
            None => {
                eprintln!(
                    "{} a device is required (try `freemkv-flash info <dev>` or --help)",
                    style::red("error:")
                );
                return ExitCode::FAILURE;
            }
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e:#}", style::red("error:"));
            ExitCode::FAILURE
        }
    }
}

fn cmd_info(target: &str) -> Result<()> {
    // A regular file is a firmware image → classify the FILE (no drive needed);
    // anything else (a /dev/sg* node, or a nonexistent path) → probe the DRIVE.
    if is_firmware_file(target) {
        return engine::info_file(Path::new(target));
    }
    let mut dev = platform::open(target, false)?;
    let family = resolved_family(dev.as_mut())?;
    let handler = drive::for_family(family);
    engine::info(dev.as_mut(), handler.as_ref())
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
    if !drive::for_family(family).is_supported() {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(family)
}

/// Classify a drive for a backend's bounded backup path.
fn classify_for_backup(dev: &mut dyn platform::ScsiDevice) -> Result<Family> {
    let family = resolved_family(dev)?;
    if drive::for_family(family).backup_extension().is_none() {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(family)
}

fn cmd_backup(device: &str, out: Option<PathBuf>, template: Option<PathBuf>) -> Result<()> {
    let template = template
        .map(std::fs::read)
        .transpose()
        .context("reading backup template")?;
    let mut dev = platform::open(device, false)?;
    let family = classify_for_backup(dev.as_mut())?;
    let handler = drive::for_family(family);
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
                .context("backend has no restorable backup format")?;
            PathBuf::from(format!("{s}.backup.{extension}"))
        }
    };
    engine::backup_with_template(dev.as_mut(), handler.as_ref(), &out, template.as_deref())
}

fn cmd_flash(args: FlashArgs) -> Result<()> {
    let input = std::fs::read(&args.input)
        .with_context(|| format!("reading input {}", args.input.display()))?;
    let mut dev = platform::open(&args.device, args.execute)?;
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
    let predump_out = args.backup.clone().or_else(|| {
        handler
            .backup_extension()
            .and_then(|ext| default_backup_path(&args.input, ext))
    });

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
    };
    engine::flash(dev.as_mut(), handler.as_ref(), &req)
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
    fn backup_is_the_only_public_backup_command() {
        let parsed =
            Cli::try_parse_from(["freemkv-flash", "backup", "/dev/sg0"]).expect("backup command");
        assert!(matches!(parsed.command, Some(Command::Backup { .. })));
        assert!(Cli::try_parse_from(["freemkv-flash", "dump", "/dev/sg0"]).is_err());
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
