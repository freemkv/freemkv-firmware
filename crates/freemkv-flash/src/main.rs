//! freemkv-flash command-line interface.
//!
//! Reading commands (read-only) + `flash` (write); `info` is the default:
//! * `freemkv-flash <dev|file>` / `info <dev|file>` — identify + classify a
//!   live drive or a firmware image `.bin` (same family key the flash gate uses).
//! * `freemkv-flash dump <dev> [-o fw.bin]` — full 2 MiB image (`--tar` = per-unit backup).
//! * `freemkv-flash map  <dev>` — read-surface map → `<base>.map.{json,md}`.
//! * `freemkv-flash flash <dev> -i <file> [flags]` — write, then read-back verify.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use freemkv_flash::drive::{self, Family, FlashRequest};
use freemkv_flash::engine;
use freemkv_flash::manifest::FlashMode;
use freemkv_flash::platform;
use freemkv_flash::style;

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
    /// Dump EVERYTHING readable to one .tar: full image + per-unit regions + map (read-only).
    Dump {
        /// SCSI device path (e.g. /dev/sg0).
        device: String,
        /// Output .tar path (default: `<product>_<rev>.dump.tar`).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Flash a firmware image or restore a per-unit .tar (WRITE).
    Flash(FlashArgs),
    /// EXPERIMENTAL read-only probe: find which READ BUFFER channel dumps the
    /// full 2 MiB flash (issues only 0x3C — never a write).
    #[command(hide = true)]
    ReadProbe {
        /// SCSI device path (e.g. /dev/sg0).
        device: String,
        /// Save the full image here if the sweep succeeds.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// EXPERIMENTAL read-only map: sweep the full READ BUFFER (mode x buf x
    /// offset) surface and report what each reads (0x3C only — never a write).
    #[command(hide = true)]
    ReadMap {
        /// SCSI device path (e.g. /dev/sg0).
        device: String,
        /// Save the map text here.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// EXPERIMENTAL read-only raw READ BUFFER via explicit mode/buf/offset/len,
    /// or --dump to sweep the whole 2 MiB via that channel (0x3C only).
    #[command(hide = true)]
    ReadRaw {
        /// SCSI device path (e.g. /dev/sg0).
        device: String,
        /// READ BUFFER mode (e.g. 2, 6). Accepts 0x-prefixed hex.
        #[arg(short = 'm', long)]
        mode: String,
        /// Buffer-ID (e.g. 0, 0x80). Accepts 0x-prefixed hex.
        #[arg(short = 'b', long)]
        buf: String,
        /// Byte offset. Accepts 0x-prefixed hex.
        #[arg(short = 'O', long, default_value = "0")]
        offset: String,
        /// Read length. Accepts 0x-prefixed hex.
        #[arg(short = 'L', long, default_value = "0x40")]
        len: String,
        /// Sweep the whole 2 MiB via this channel and save here (uses --len as chunk).
        #[arg(long)]
        dump: Option<PathBuf>,
    },
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
    /// Flash without a successful pre-flash backup (rescue a dead drive only).
    #[arg(long)]
    rescue_no_dump: bool,
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
        Some(Command::Dump { device, out }) => cmd_dump(&device, out),
        Some(Command::Flash(args)) => cmd_flash(args),
        Some(Command::ReadProbe { device, out }) => cmd_read_probe(&device, out.as_deref()),
        Some(Command::ReadMap { device, out }) => cmd_read_map(&device, out.as_deref()),
        Some(Command::ReadRaw {
            device,
            mode,
            buf,
            offset,
            len,
            dump,
        }) => cmd_read_raw(&device, &mode, &buf, &offset, &len, dump.as_deref()),
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
    let family = drive::classify(dev.as_mut());
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

/// Classify and enforce the flash/probe gate: only MediaTek drives may flash or
/// run the (MTK-specific) read probes.
fn classify_gated(dev: &mut dyn platform::ScsiDevice) -> Result<Family> {
    let family = drive::classify(dev);
    if family != Family::Mtk {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(family)
}

/// Classify and gate the read-only DUMP path: any family whose dump is
/// implemented may proceed (MediaTek and Pioneer/Renesas today). Flash stays
/// gated separately by [`classify_gated`], so a Pioneer/Renesas drive can be
/// dumped but never flashed.
fn classify_for_dump(dev: &mut dyn platform::ScsiDevice) -> Result<Family> {
    let family = drive::classify(dev);
    if !drive::for_family(family).dump_supported() {
        return Err(drive::unsupported_family_error(family));
    }
    Ok(family)
}

fn cmd_dump(device: &str, out: Option<PathBuf>) -> Result<()> {
    let mut dev = platform::open(device, false)?;
    let family = classify_for_dump(dev.as_mut())?;
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
            PathBuf::from(format!("{s}.dump.tar"))
        }
    };
    engine::dump_everything(dev.as_mut(), handler.as_ref(), &out)
}

fn cmd_read_probe(device: &str, out: Option<&Path>) -> Result<()> {
    let mut dev = platform::open(device, false)?;
    let _family = classify_gated(dev.as_mut())?;
    freemkv_flash::probe::read_probe(dev.as_mut(), out)
}

fn cmd_read_map(device: &str, out: Option<&Path>) -> Result<()> {
    let mut dev = platform::open(device, false)?;
    let _family = classify_gated(dev.as_mut())?;
    freemkv_flash::probe::read_map(dev.as_mut(), out)
}

/// Parse a `u32` that may be decimal or `0x`-prefixed hex.
fn parse_num(s: &str) -> Result<u32> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    };
    v.with_context(|| format!("invalid number '{s}'"))
}

#[allow(clippy::too_many_arguments)]
fn cmd_read_raw(
    device: &str,
    mode: &str,
    buf: &str,
    offset: &str,
    len: &str,
    dump: Option<&Path>,
) -> Result<()> {
    let mode = parse_num(mode)? as u8;
    let buf = parse_num(buf)? as u8;
    let offset = parse_num(offset)?;
    let len = parse_num(len)?;
    let mut dev = platform::open(device, false)?;
    let _family = classify_gated(dev.as_mut())?;
    freemkv_flash::probe::read_raw(dev.as_mut(), mode, buf, offset, len, dump)
}

fn cmd_flash(args: FlashArgs) -> Result<()> {
    let input = std::fs::read(&args.input)
        .with_context(|| format!("reading input {}", args.input.display()))?;
    let input_kind = drive::sniff_input(&args.input);

    let mut dev = platform::open(&args.device, true)?;
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
        acknowledged_risk: args.i_understand_risk,
        enc_override,
        drive_model,
        verbose: args.verbose,
        predump_out,
    };
    engine::flash(dev.as_mut(), handler.as_ref(), &req)
}

/// Default pre-flash backup path: `<input>.predump.tar` next to the input.
fn default_backup_path(input: &Path) -> Option<PathBuf> {
    let name = input.file_name()?.to_string_lossy();
    Some(input.with_file_name(format!("{name}.predump.tar")))
}

#[cfg(test)]
mod tests {
    use super::is_firmware_file;

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
