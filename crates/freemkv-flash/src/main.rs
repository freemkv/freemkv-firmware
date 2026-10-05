//! freemkv-flash command-line interface.
//!
//! Firmware backup and flash commands; `info` is the default:
//! * `freemkv-flash <dev|file>` / `info <dev|file>` — identify + classify a
//!   live drive or a firmware image `.bin` (same family key the flash gate uses).
//! * `freemkv-flash backup <dev> [-o backup.tar]` — firmware package capture.
//! * `freemkv-flash flash <dev> -i <file> [flags]` — backed-up write path.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use freemkv_flash::manifest::FlashMode;
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
        Some(Command::List) => freemkv_flash::workflow::list(),
        Some(Command::Info { device }) => freemkv_flash::workflow::info(device.as_deref()),
        Some(Command::Backup { device, out }) => {
            freemkv_flash::workflow::backup(device.as_deref(), out, false, false)
        }
        Some(Command::Dump { device, out, force }) => {
            freemkv_flash::workflow::backup(device.as_deref(), out, true, force)
        }
        Some(Command::Flash(args)) => freemkv_flash::workflow::flash(args.into()),
        None => freemkv_flash::workflow::info(cli.device.as_deref()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e:#}", style::red("error:"));
            ExitCode::FAILURE
        }
    }
}

impl From<FlashArgs> for freemkv_flash::workflow::FlashOptions {
    fn from(a: FlashArgs) -> Self {
        Self {
            device: a.device,
            input: a.input,
            backup: a.backup,
            skip_backup: a.skip_backup,
            mode: a.mode.into(),
            execute: a.execute,
            acknowledged_risk: a.i_understand_risk,
            allow_crossflash: a.allow_crossflash,
            recover: a.recover,
            force: a.force,
            verbose: a.verbose,
            enc: a.enc,
            no_enc: a.no_enc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
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
}
