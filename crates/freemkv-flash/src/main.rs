//! freemkv-flash command-line interface.
//!
//! Firmware backup and flash commands; `info` is the default:
//! * `freemkv-flash <dev|file>` / `info <dev|file>` — identify + classify a
//!   live drive or a firmware image `.bin` (same family key the flash gate uses).
//! * `freemkv-flash backup <dev> [-o backup.bin]` — firmware package capture.
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
  freemkv-flash backup /dev/sg0 -o backup.bin

  # Dry-run a flash — prints the plan, issues NO writes:
  freemkv-flash flash /dev/sg0 -i firmware.bin

  # Flash for real (risk of permanent failure). EJECT ANY DISC FIRST — an empty, closed
  # tray is required; flashing with a disc loaded can wedge the drive:
  freemkv-flash flash /dev/sg0 -i firmware.bin \\
      --backup backup-preflash.bin --execute --i-understand-risk

Run `freemkv-flash flash --help` for the full flash workflow and all flags."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Drive name or id from `list`, or a firmware image file, for the default `info` action.
    device: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List optical drives by the name or id to pass to info/backup/flash. Works
    /// with an empty tray (a disc-less macOS drive has no /dev/diskN node).
    List,
    /// Identify + classify a drive OR a firmware image file (read-only).
    Info {
        /// Drive name or id from `list` (e.g. `E:` or `\\.\CdRom1`) or a
        /// firmware image file. Omit to auto-pick the only connected drive.
        device: Option<String>,
    },
    /// Capture firmware. Pioneer output is byte-exact OEM where recognized, else a
    /// clearly-labeled non-OEM candidate (zeroed signature).
    Backup {
        /// Drive name or id from `list` (e.g. `E:` or `\\.\CdRom1`).
        /// Omit to auto-pick the only connected drive.
        device: Option<String>,
        /// Output path (MediaTek `.bin`; Pioneer defaults to `<model>_<rev>.candidate.tar`).
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
    /// Recover a Pioneer drive using Current firmware or an explicit drive read.
    Recover(RecoveryArgs),
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
  2. freemkv-flash backup /dev/sg0 -o backup.bin       # save a backup first
  3. EJECT any disc so the tray is empty and closed
  4. freemkv-flash flash /dev/sg0 -i firmware.bin      # DRY RUN — review the plan
  5. freemkv-flash flash /dev/sg0 -i firmware.bin \\
         --backup backup-preflash.bin --execute --i-understand-risk   # for real

Do not power off or disconnect the drive during step 5.")]
struct FlashArgs {
    /// Drive name or id from `list` (e.g. `E:` or `\\.\CdRom1`).
    /// Omit to auto-pick the only connected drive.
    device: Option<String>,
    /// Input: MTK image or backup (.bin), 0.10.x MTK backup (.tar), Pioneer .enc, or a Pioneer envelope tar.
    /// Pioneer inputs are dry-run by default; live writes need --execute --i-understand-risk and a pre-flash backup.
    #[arg(short, long)]
    input: PathBuf,
    /// Where to save the required pre-flash backup (otherwise chosen automatically).
    #[arg(short, long)]
    backup: Option<PathBuf>,
    /// Actually issue firmware writes (otherwise preview the plan).
    #[arg(long)]
    execute: bool,
    /// Acknowledge that flashing can permanently disable the drive.
    #[arg(long)]
    i_understand_risk: bool,
}

#[derive(clap::Args, Debug)]
struct RecoveryArgs {
    /// Drive name or id from list; omitted when only one drive is connected.
    device: Option<String>,
    /// Target package containing Kernel and Normal.
    #[arg(short, long)]
    input: PathBuf,
    /// Copy of the firmware currently running on the drive.
    #[arg(
        long,
        required_unless_present = "read_from_drive",
        conflicts_with = "read_from_drive"
    )]
    current: Option<PathBuf>,
    /// Explicitly read Current firmware instead of supplying a file.
    #[arg(long)]
    read_from_drive: bool,
    /// Actually write firmware; otherwise preview without firmware writes.
    #[arg(long)]
    execute: bool,
    /// Acknowledge that recovery can permanently disable the drive.
    #[arg(long)]
    i_understand_risk: bool,
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
        Some(Command::Recover(args)) => {
            freemkv_flash::workflow::recover(freemkv_flash::workflow::RecoveryOptions {
                device: args.device,
                input: args.input,
                current: match args.current {
                    Some(path) => freemkv_flash::workflow::CurrentFirmware::File(path),
                    None => freemkv_flash::workflow::CurrentFirmware::ReadFromDrive,
                },
                execute: args.execute,
                acknowledged_risk: args.i_understand_risk,
            })
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
            execute: a.execute,
            acknowledged_risk: a.i_understand_risk,
            force: false,
        }
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
