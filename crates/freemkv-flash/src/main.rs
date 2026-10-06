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
    /// Capture all accessible drive memory as a raw dump (read-only).
    Dump {
        /// Drive selector; omitted when only one drive is connected.
        device: Option<String>,
        /// Output raw .bin path.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Inspect a firmware file without opening a drive.
    Check {
        /// Firmware or backup file to inspect.
        input: PathBuf,
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
    /// Actually issue firmware writes (otherwise preview the plan).
    #[arg(long)]
    execute: bool,
    /// Acknowledge that flashing can permanently disable the drive.
    #[arg(long)]
    i_understand_risk: bool,
    /// Override compatibility/recovery checks and permit flashing without a backup.
    /// The input must still have a valid format for the drive's write protocol.
    #[arg(long)]
    force: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::List) => freemkv_flash::workflow::list(),
        Some(Command::Info { device }) => freemkv_flash::workflow::info(device.as_deref()),
        Some(Command::Backup { device, out }) => {
            freemkv_flash::workflow::backup(device.as_deref(), out, false)
        }
        Some(Command::Dump { device, out }) => {
            freemkv_flash::workflow::backup(device.as_deref(), out, true)
        }
        Some(Command::Check { input }) => freemkv_flash::workflow::check_file(&input),
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
            execute: a.execute,
            acknowledged_risk: a.i_understand_risk,
            force: a.force,
        }
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
