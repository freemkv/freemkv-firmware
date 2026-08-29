//! freemkv-flash command-line interface.
//!
//! Exactly three commands; `info` is the default:
//! * `freemkv-flash <dev>` / `info <dev>` — identify + classify (read-only).
//! * `freemkv-flash dump <dev> [-o out.tar]` — per-unit backup (read-only).
//! * `freemkv-flash flash <dev> -i <file> [flags]` — write, then read-back verify.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use freemkv_flash::drive::{self, Family, FlashRequest};
use freemkv_flash::engine;
use freemkv_flash::manifest::FlashMode;
use freemkv_flash::platform;

/// freemkv standalone optical-drive firmware flasher / dumper.
#[derive(Parser, Debug)]
#[command(
    name = "freemkv-flash",
    version,
    about,
    long_about = None,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Device for the default `info` action (e.g. /dev/sg0).
    device: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Identify + classify the drive (read-only; never aborts).
    Info {
        /// SCSI device path (e.g. /dev/sg0).
        device: String,
    },
    /// Back up the per-unit regions to an interoperable .tar (read-only).
    Dump {
        /// SCSI device path (e.g. /dev/sg0).
        device: String,
        /// Output .tar path.
        #[arg(short, long, default_value = "dump.tar")]
        out: PathBuf,
    },
    /// Flash a firmware image or restore a per-unit .tar (WRITE).
    Flash(FlashArgs),
}

#[derive(Parser, Debug)]
struct FlashArgs {
    /// SCSI device path (e.g. /dev/sg0).
    device: String,
    /// Input firmware image (.bin) or per-unit dump (.tar).
    #[arg(short, long)]
    input: PathBuf,
    /// Where to save the mandatory pre-flash backup dump.
    #[arg(short, long)]
    backup: Option<PathBuf>,
    /// Streaming mode: `main` or `full` (full sets the commit flag). NOTE: on
    /// the currently-supported MediaTek family this is informational only —
    /// the full 2 MiB image is always streamed and the commit handshake is
    /// always sent regardless of which mode is selected.
    #[arg(long, value_enum, default_value_t = ModeArg::Full)]
    mode: ModeArg,
    /// Actually issue SCSI writes (otherwise dry-run only).
    #[arg(long)]
    execute: bool,
    /// Acknowledge that flashing can permanently brick the drive.
    #[arg(long)]
    i_understand_risk: bool,
    /// Permit flashing firmware whose model differs from the drive.
    #[arg(long)]
    allow_cross_flash: bool,
    /// Flash without a successful pre-flash backup (rescue a dead drive only).
    #[arg(long)]
    rescue_no_dump: bool,
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
        Some(Command::Dump { device, out }) => cmd_dump(&device, &out),
        Some(Command::Flash(args)) => cmd_flash(args),
        None => match cli.device {
            Some(device) => cmd_info(&device),
            None => {
                eprintln!("error: a device is required (try `freemkv-flash info <dev>` or --help)");
                return ExitCode::FAILURE;
            }
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_info(device: &str) -> Result<()> {
    let mut dev = platform::open(device)?;
    let family = drive::classify(dev.as_mut());
    let handler = drive::for_family(family);
    engine::info(dev.as_mut(), handler.as_ref())
}

/// Classify and enforce the MTK-gate: only MediaTek drives may dump/flash.
fn classify_gated(dev: &mut dyn platform::ScsiDevice) -> Result<Family> {
    let family = drive::classify(dev);
    if family != Family::Mtk {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(family)
}

fn cmd_dump(device: &str, out: &Path) -> Result<()> {
    let mut dev = platform::open(device)?;
    let family = classify_gated(dev.as_mut())?;
    let handler = drive::for_family(family);
    engine::dump(dev.as_mut(), handler.as_ref(), out)
}

fn cmd_flash(args: FlashArgs) -> Result<()> {
    let input = std::fs::read(&args.input)
        .with_context(|| format!("reading input {}", args.input.display()))?;
    let input_kind = drive::sniff_input(&args.input);

    let mut dev = platform::open(&args.device)?;
    let family = classify_gated(dev.as_mut())?;
    let handler = drive::for_family(family);

    let drive_model = handler.identity(dev.as_mut()).product;
    let enc_override = if args.enc {
        Some(true)
    } else if args.no_enc {
        Some(false)
    } else {
        None
    };
    let predump_out = args
        .backup
        .clone()
        .or_else(|| default_backup_path(&args.input));

    let req = FlashRequest {
        input,
        input_kind,
        mode: args.mode.into(),
        execute: args.execute,
        rescue_no_dump: args.rescue_no_dump,
        allow_cross_flash: args.allow_cross_flash,
        acknowledged_risk: args.i_understand_risk,
        enc_override,
        drive_model,
        firmware_model: String::new(),
        predump_out,
    };
    engine::flash(dev.as_mut(), handler.as_ref(), &req)
}

/// Default pre-flash backup path: `<input>.predump.tar` next to the input.
fn default_backup_path(input: &Path) -> Option<PathBuf> {
    let name = input.file_name()?.to_string_lossy();
    Some(input.with_file_name(format!("{name}.predump.tar")))
}
