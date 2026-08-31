//! freemkv-fw command-line interface.
//!
//! A firmware *authoring* tool: it verifies and re-signs the integrity
//! structures embedded in optical-drive firmware images, and can probe a live
//! drive over SCSI to check whether it is already running freemkv firmware.
//! Everything except `verify <device>` only reads and rewrites `.bin` images
//! on disk — it never touches a device.
//!
//! * `freemkv-fw create <input.bin> [output.bin]` — build freemkv firmware from
//!   an MTK image (inject the built mods and re-sign).
//! * `freemkv-fw verify <path>` — dual mode: a regular file gets the on-disk
//!   integrity-region verify (below); a device node (`/dev/...`, or a
//!   character/block special file) gets a live IDENTITY probe instead.
//! * `freemkv-fw sign <image> [-o <out>] [--in-place]` — recompute every
//!   active region's digest, write back, and self-verify the result.
//!
//! The tool is chipset-agnostic: it auto-selects an [`IntegrityScheme`] for the
//! image (or accepts `--family` to force one). Only the MediaTek MT19xx AES-CMAC
//! scheme is implemented today; the CLI layer hardcodes no chipset.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

// The authoring engine and its integrity schemes now live in the `freemkv_fw`
// *library* (see `src/lib.rs`), so this CLI and the desktop GUI share one code
// path and cannot drift.
use freemkv_flash::{platform, style};
use freemkv_fw::scheme::{
    select_scheme, Family, IntegrityScheme, MtkCmac, RegionChange, RegionVerdict,
};
use freemkv_fw::{abi, engine, family};

/// freemkv firmware authoring tool (create / verify / re-sign).
#[derive(Parser, Debug)]
#[command(name = "freemkv-fw", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create freemkv firmware from an OEM image: hijack the `READ BUFFER`
    /// (`0x3C`) handler via the platform engine and re-sign.
    Create {
        /// Source OEM firmware image (.bin).
        input: PathBuf,
        /// Output path (default: `<input-stem>.freemkv.bin`).
        output: Option<PathBuf>,
        /// Rewrite the input image in place.
        #[arg(long)]
        in_place: bool,
    },
    /// Verify a firmware image (file) or probe a live drive (device) for
    /// freemkv firmware.
    ///
    /// A regular file gets the read-only on-disk integrity-region verify
    /// (per-region match/mismatch table). A device node (a path starting
    /// with `/dev/`, or one that is a character/block special file) instead
    /// gets a live IDENTITY probe over SCSI: no data is written.
    Verify {
        /// Firmware image (.bin) to verify, or a device node (e.g. `/dev/sg1`)
        /// to probe.
        path: PathBuf,
        /// Force a chipset family instead of auto-detecting (file mode only).
        #[arg(long, value_enum)]
        family: Option<Family>,
    },
    /// Probe a live freemkv drive over the vendor command (`3C 0E C0 DE`):
    /// identity, or a memory read via [`abi::SubFn::DumpAll`] (subfn 07).
    ///
    /// With no dump flags: prints the drive's freemkv identity.
    /// `--dump <hex-addr> --len <hex-len> --out <file>`: read an explicit range.
    /// `--full --out <prefix>`: capture the entire decrypted image (flash + RAM
    /// banks) with auto-stop at the end of each readable region — one file per
    /// captured region, named `<prefix>-<startVA>.bin`.
    Info {
        /// Device node, e.g. `/dev/sg0`.
        device: PathBuf,
        /// Memory-read start address (hex, e.g. `0x1f80000`).
        #[arg(long)]
        dump: Option<String>,
        /// Memory-read length (hex). Required with `--dump`.
        #[arg(long)]
        len: Option<String>,
        /// Capture the entire decrypted image (flash + RAM banks), auto-stop.
        #[arg(long)]
        full: bool,
        /// Output file (with `--dump`) or filename prefix (with `--full`).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Recompute and write back every active region's digest.
    Sign {
        /// Firmware image (.bin) to re-sign.
        image: PathBuf,
        /// Output path (default: `<stem>.signed.bin`).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Rewrite the input image in place.
        #[arg(long)]
        in_place: bool,
        /// Force a chipset family instead of auto-detecting.
        #[arg(long, value_enum)]
        family: Option<Family>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Create {
            input,
            output,
            in_place,
        } => cmd_create(&input, output, in_place),
        Command::Verify { path, family } => cmd_verify(&path, family),
        Command::Info {
            device,
            dump,
            len,
            full,
            out,
        } => cmd_info(
            &device,
            dump.as_deref(),
            len.as_deref(),
            full,
            out.as_deref(),
        ),
        Command::Sign {
            image,
            out,
            in_place,
            family,
        } => cmd_sign(&image, out, in_place, family),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {e:#}", style::red("error:"));
            ExitCode::FAILURE
        }
    }
}

/// Short hex preview of a digest (first 4 bytes) for compact tables.
fn short_hex(d: &[u8; 16]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// Pure core: select a scheme and verify. Returns the scheme name + verdicts.
fn verify_image(
    image: &[u8],
    family: Option<Family>,
) -> Result<(&'static str, Vec<RegionVerdict>)> {
    let scheme = select_scheme(image, family)?;
    let verdicts = scheme.verify(image)?;
    Ok((scheme.name(), verdicts))
}

/// What kind of target `verify`'s argument names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyTarget {
    /// A regular firmware image on disk — verify its integrity table(s).
    File,
    /// A live device node — probe it over SCSI for freemkv firmware.
    Device,
}

/// Classify `path` for `verify`'s dual-mode dispatch.
///
/// A path is treated as a device if it looks like a device path (starts with
/// `/dev/`, which also covers `/dev/sg*`) or — when it already exists on
/// disk — its filesystem metadata says it is a character or block special
/// file. Anything else, including a plain path that doesn't exist yet, is
/// treated as a file, so the ordinary "no such file" error still fires for a
/// typo'd image path instead of being swallowed by device-probe logic.
fn classify_verify_target(path: &Path) -> VerifyTarget {
    if path.starts_with("/dev/") {
        return VerifyTarget::Device;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            let ft = meta.file_type();
            if ft.is_char_device() || ft.is_block_device() {
                return VerifyTarget::Device;
            }
        }
    }
    VerifyTarget::File
}

fn cmd_verify(path: &Path, family: Option<Family>) -> Result<ExitCode> {
    match classify_verify_target(path) {
        VerifyTarget::Device => cmd_verify_device(path),
        VerifyTarget::File => cmd_verify_file(path, family),
    }
}

fn cmd_verify_file(path: &Path, family: Option<Family>) -> Result<ExitCode> {
    let image = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (scheme_name, verdicts) = verify_image(&image, family)?;

    println!("{}", style::kv("scheme", scheme_name));
    print_verdicts(&verdicts);

    let mismatches = verdicts.iter().filter(|v| !v.ok).count();
    if verdicts.is_empty() {
        println!(
            "{}",
            style::status_line("summary", "no active regions", style::Status::Warn)
        );
        Ok(ExitCode::FAILURE)
    } else if mismatches == 0 {
        println!(
            "{}",
            style::status_line(
                "summary",
                &format!("{} region(s) OK", verdicts.len()),
                style::Status::Ok
            )
        );
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "{}",
            style::status_line(
                "summary",
                &format!("{mismatches} of {} region(s) MISMATCH", verdicts.len()),
                style::Status::Fail
            )
        );
        Ok(ExitCode::FAILURE)
    }
}

// ---------------------------------------------------------------------------
// verify (live drive)
// ---------------------------------------------------------------------------

/// Probe a live drive for freemkv firmware by sending the Identity command
/// (`3C 0E C0 DE 01 …`) built by [`abi::build_cdb`].
///
/// Opens the device read-only (never writes anything) via [`platform::open`].
///
/// NOTE (detection gap): the current firmware Identity handler raises a vendor
/// *sense* ([`abi::SENSE_IDENTITY`] = `09/F0`), not a data reply, so the
/// authoritative live check is a CHECK CONDITION carrying that sense. This
/// data-path check (looking for [`abi::RESP_MAGIC`]) only detects a future
/// *data-returning* Identity; against the sense-based handler a freemkv drive
/// currently reads as "not detected" here. Until the sense-aware probe lands,
/// confirm on hardware with `sg_raw` and inspect the returned sense
/// (`09/F0` = freemkv, OEM returns `05/24`). Either way this never writes and
/// never crashes.
fn cmd_verify_device(path: &Path) -> Result<ExitCode> {
    let path_str = path.to_string_lossy();
    let mut dev =
        platform::open(&path_str, false).with_context(|| format!("opening {path_str}"))?;

    const ALLOC_LEN: usize = 96;
    let cdb = abi::build_cdb(abi::SubFn::Identity, None, ALLOC_LEN as u16);

    match dev.command_in(&cdb, ALLOC_LEN) {
        Ok(resp) if abi::verify_response(&resp) => {
            let detail = match resp.get(abi::RESP_MAGIC.len()) {
                Some(&v) => format!(
                    "DETECTED on {path_str} {}",
                    style::dim(&format!("(version 0x{v:02x})"))
                ),
                None => format!("DETECTED on {path_str}"),
            };
            println!(
                "{}",
                style::status_line("freemkv firmware", &detail, style::Status::Ok)
            );
            Ok(ExitCode::SUCCESS)
        }
        // Either a well-formed non-freemkv response (e.g. a plain INQUIRY
        // reply on stock firmware) or a SCSI-level error from a drive that
        // doesn't recognize the knock at all — both mean "not freemkv".
        Ok(_) | Err(_) => {
            println!(
                "{}",
                style::status_line(
                    "freemkv firmware",
                    &format!(
                        "NOT DETECTED on {path_str} {}",
                        style::dim("(stock/OEM or other firmware)")
                    ),
                    style::Status::Warn
                )
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

// ---------------------------------------------------------------------------
// info (live drive: identity + subfn-07 memory read)
// ---------------------------------------------------------------------------

/// Parse a hex (or decimal) integer that may carry a `0x` prefix.
fn parse_u32(s: &str) -> Result<u32> {
    let t = s.trim();
    let v = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .map(|h| u32::from_str_radix(h, 16))
        .unwrap_or_else(|| t.parse::<u32>())
        .with_context(|| format!("invalid number: {s}"))?;
    Ok(v)
}

/// Read `len` bytes starting at `start` via [`abi::SubFn::DumpAll`], in
/// [`abi::MEMREAD_LEN`]-byte windows. When `auto_stop`, a run of consecutive
/// unreadable windows (transport/sense error) ends the read early — the natural
/// "end of mapped memory" signal. Unreadable windows before the run are
/// zero-filled to keep byte offsets aligned to `start`. Returns the bytes read.
fn mem_read(dev: &mut dyn platform::ScsiDevice, start: u32, len: u64, auto_stop: bool) -> Vec<u8> {
    const STOP_AFTER: u32 = 16; // consecutive faults = end of region
    let mut out = Vec::with_capacity(len as usize);
    let mut faults = 0u32;
    let mut addr = start as u64;
    let end = start as u64 + len;
    while addr < end {
        let cdb = abi::build_memread_cdb(addr as u32);
        match dev.command_in(&cdb, abi::MEMREAD_LEN) {
            Ok(mut d) => {
                faults = 0;
                d.resize(abi::MEMREAD_LEN, 0);
                out.extend_from_slice(&d);
            }
            Err(_) => {
                faults += 1;
                if auto_stop && faults >= STOP_AFTER {
                    // drop the trailing all-fault fill and stop
                    out.truncate(
                        out.len()
                            .saturating_sub(((faults - 1) as usize) * abi::MEMREAD_LEN),
                    );
                    break;
                }
                out.extend_from_slice(&[0u8; abi::MEMREAD_LEN]);
            }
        }
        addr += abi::MEMREAD_LEN as u64;
    }
    out
}

/// The decrypted-image regions captured by `--full`: flash + the RAM banks the
/// runtime (boot block, OTFAD overlay, resident lib, SRAM state) decrypts into.
/// Each is read with auto-stop, so the caps are generous upper bounds.
const FULL_REGIONS: &[(u32, u64)] = &[
    (0x0000_0000, 0x0020_0000), // flash (plaintext + in-place-decrypted boot block)
    (0x01c0_0000, 0x0044_0000), // firmware RAM: data bank, overlay, resident lib, SRAM
];

fn cmd_info(
    device: &Path,
    dump: Option<&str>,
    len: Option<&str>,
    full: bool,
    out: Option<&Path>,
) -> Result<ExitCode> {
    let path_str = device.to_string_lossy();

    if full {
        let prefix = out.ok_or_else(|| anyhow::anyhow!("--full requires --out <prefix>"))?;
        let mut dev =
            platform::open(&path_str, false).with_context(|| format!("opening {path_str}"))?;
        for &(start, cap) in FULL_REGIONS {
            eprintln!(
                "{}",
                style::status_line(
                    "capture",
                    &format!("region 0x{start:08x} (cap 0x{cap:x}) …"),
                    style::Status::Ok
                )
            );
            let data = mem_read(dev.as_mut(), start, cap, true);
            let file = prefix.with_file_name(format!(
                "{}-{start:08x}.bin",
                prefix
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("dump")
            ));
            std::fs::write(&file, &data).with_context(|| format!("writing {}", file.display()))?;
            println!(
                "{}",
                style::status_line(
                    "captured",
                    &format!(
                        "0x{start:08x}..0x{:08x} ({} bytes) -> {}",
                        start as u64 + data.len() as u64,
                        data.len(),
                        file.display()
                    ),
                    style::Status::Ok
                )
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(d) = dump {
        let start = parse_u32(d)?;
        let length =
            parse_u32(len.ok_or_else(|| anyhow::anyhow!("--dump requires --len"))?)? as u64;
        let mut dev =
            platform::open(&path_str, false).with_context(|| format!("opening {path_str}"))?;
        let data = mem_read(dev.as_mut(), start, length, false);
        match out {
            Some(o) => {
                std::fs::write(o, &data).with_context(|| format!("writing {}", o.display()))?;
                println!(
                    "{}",
                    style::status_line(
                        "dump",
                        &format!(
                            "0x{start:08x} +0x{length:x} -> {} ({} bytes)",
                            o.display(),
                            data.len()
                        ),
                        style::Status::Ok
                    )
                );
            }
            None => {
                for (i, chunk) in data.chunks(16).enumerate() {
                    let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
                    println!("{:08x}  {hex}", start as usize + i * 16);
                }
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    // No dump flags: identity probe (reuse the verify-device path).
    cmd_verify_device(device)
}

/// Print the per-region verdict table.
fn print_verdicts(verdicts: &[RegionVerdict]) {
    if verdicts.is_empty() {
        return;
    }
    println!(
        "{}",
        style::dim(&format!(
            "{:>3}  {:<21}  {:>9}  {:<8}  {:<8}  {:<8}",
            "idx", "range", "size", "status", "stored", "computed"
        ))
    );
    for v in verdicts {
        let size = (v.end as u64).saturating_sub(v.start as u64) + 1;
        let status_plain = if v.ok { "MATCH   " } else { "MISMATCH" };
        let status = if v.ok {
            style::green(status_plain)
        } else {
            style::red(status_plain)
        };
        println!(
            "{:>3}  {}  {}  {}  {}  {}",
            v.index,
            style::dim(&format!("{:<21}", format!("0x{:x}-0x{:x}", v.start, v.end))),
            style::dim(&format!("{:>9}", format!("0x{size:x}"))),
            status,
            style::dim(&short_hex(&v.stored)),
            style::dim(&short_hex(&v.computed)),
        );
    }
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

/// Pure core: select a scheme, re-sign, and self-verify the produced image.
///
/// Returns the scheme name, the new image bytes, and the list of changed
/// regions. Errors if the produced image fails to self-verify.
fn sign_image(
    image: &[u8],
    family: Option<Family>,
) -> Result<(&'static str, Vec<u8>, Vec<RegionChange>)> {
    let scheme = select_scheme(image, family)?;
    let (signed, changes) = scheme.sign(image)?;

    // Refuse to hand back an image that does not verify under its own scheme.
    let verdicts = scheme.verify(&signed)?;
    if verdicts.is_empty() || verdicts.iter().any(|v| !v.ok) {
        bail!("internal error: re-signed image does not self-verify");
    }
    Ok((scheme.name(), signed, changes))
}

fn cmd_sign(
    path: &Path,
    out: Option<PathBuf>,
    in_place: bool,
    family: Option<Family>,
) -> Result<ExitCode> {
    let image = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    // Resolve the output path before doing work so we fail fast on conflicts.
    let out_path = if in_place {
        if out.is_some() {
            bail!("--in-place conflicts with -o/--out");
        }
        path.to_path_buf()
    } else {
        let dest = out.unwrap_or_else(|| default_signed_path(path));
        if dest == path {
            bail!(
                "refusing to overwrite the input ({}); pass --in-place or a different -o",
                path.display()
            );
        }
        dest
    };

    let (scheme_name, signed, changes) = sign_image(&image, family)?;

    println!("scheme: {scheme_name}");
    if changes.is_empty() {
        println!("image already valid — 0 regions re-signed");
    } else {
        println!("re-signed {} region(s):", changes.len());
        for c in &changes {
            println!(
                "  [{:>2}] 0x{:x}-0x{:x}  {} -> {}",
                c.index,
                c.start,
                c.end,
                short_hex(&c.before),
                short_hex(&c.after),
            );
        }
    }

    std::fs::write(&out_path, &signed)
        .with_context(|| format!("writing {}", out_path.display()))?;
    println!("wrote {} ({} bytes)", out_path.display(), signed.len());
    Ok(ExitCode::SUCCESS)
}

/// Default signed-output path: `<stem>.signed.bin` next to the input.
fn default_signed_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".to_string());
    input.with_file_name(format!("{stem}.signed.bin"))
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

/// Default freemkv-output path: `<stem>.freemkv.bin` next to the input.
fn default_created_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".to_string());
    input.with_file_name(format!("{stem}.freemkv.bin"))
}

fn cmd_create(path: &Path, out: Option<PathBuf>, in_place: bool) -> Result<ExitCode> {
    let image = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    // Resolve the output path up front so we fail fast on conflicts.
    let out_path = if in_place {
        if out.is_some() {
            bail!("--in-place conflicts with an explicit output path");
        }
        path.to_path_buf()
    } else {
        let dest = out.unwrap_or_else(|| default_created_path(path));
        if dest == path {
            bail!(
                "refusing to overwrite the input ({}); pass --in-place or a different output path",
                path.display()
            );
        }
        dest
    };

    // Pick the platform engine (a clean refusal on an unsupported/unidentified
    // controller), then build. Every address the engine uses is derived from the
    // drive's own code — the grounded find fails loudly rather than guessing.
    let engine = engine::detect(&image).context("selecting a platform engine for this image")?;
    let chip = family::detect_chip(&image).ok();
    let report = engine.create(&image).context("building freemkv firmware")?;

    // Never write an image that does not re-verify.
    let verdicts = MtkCmac.verify(&report.image)?;
    if verdicts.is_empty() || verdicts.iter().any(|v| !v.ok) {
        bail!("internal error: modified image does not re-verify");
    }

    match &chip {
        Some(c) => println!(
            "\n{} — {} · {} {} · rev {}",
            style::header(&format!("freemkv-fw {}", env!("CARGO_PKG_VERSION"))),
            engine.name(),
            c.vendor,
            c.model,
            c.rev,
        ),
        None => println!(
            "\n{} — {}",
            style::header(&format!("freemkv-fw {}", env!("CARGO_PKG_VERSION"))),
            engine.name(),
        ),
    }
    println!();
    print_command_table(&report);
    println!();

    for v in &verdicts {
        println!(
            "Re-signing {} integrity table {} ... {}",
            MtkCmac.name(),
            style::dim(&format!("@ 0x{:x}", v.start)),
            style::green("ok"),
        );
    }

    std::fs::write(&out_path, &report.image)
        .with_context(|| format!("writing {}", out_path.display()))?;
    println!(
        "Wrote {} {}",
        out_path.display(),
        style::dim(&format!(
            "({} bytes, {} CMAC region(s) OK)",
            report.image.len(),
            verdicts.len()
        )),
    );

    print_create_details(engine.name(), &report);
    Ok(ExitCode::SUCCESS)
}

/// Whether a capability is actually present in THIS build. Derived from the
/// real [`engine::CreateReport`], never a hardcoded claim — so the summary can
/// never drift from what the handler truly emits.
enum FeatureStatus {
    /// Emitted into this build's handler and active.
    Wired,
    /// Not emitted in this build.
    NotWired,
    /// The engine located the hook point, but the runtime patch is not yet
    /// wired (pending the RAM-flag work) — honestly neither "added" nor absent.
    HookLocated,
}

/// Print the capability table with each row's status DERIVED from `report`
/// (the actual build), so a build always describes itself truthfully.
///
/// `Identity` (0x01), `Volume ID` (0x03) and `Diagnostic Dump` (0x07) are
/// emitted by `build_handler` on every successful create — and VID is further
/// confirmed by the report carrying its resolved producer + gate-setter.
/// `Speed` (0x02) and `Region-free` (0x05) are not emitted yet. `Bus
/// Encryption` (0x04) has only its `SetDiscMode` hook located, not a wired
/// runtime patch.
fn print_command_table(report: &engine::CreateReport) {
    let vid = if report.vid_producer != 0 && report.vid_gate_setter != 0 {
        FeatureStatus::Wired
    } else {
        FeatureStatus::NotWired
    };
    let bus = if report.setdiscmode != 0 {
        FeatureStatus::HookLocated
    } else {
        FeatureStatus::NotWired
    };
    let speed = if report.speed_stub_va != 0 {
        FeatureStatus::Wired
    } else {
        FeatureStatus::NotWired
    };
    let region = if report.region_stub_va != 0 {
        FeatureStatus::Wired
    } else {
        FeatureStatus::NotWired
    };
    // One capability row: label, status, and two (state, description) detail pairs.
    type FeatureRow = (
        &'static str,
        FeatureStatus,
        [(&'static str, &'static str); 2],
    );
    let rows: [FeatureRow; 6] = [
        (
            "Identity",
            FeatureStatus::Wired,
            [("On", "answers freemkv"), ("Off", "stock")],
        ),
        (
            "Speed",
            speed,
            [("On", "full speed"), ("Off", "OEM throttle")],
        ),
        (
            "Volume ID (VID)",
            vid,
            [("On", "returns the disc VID"), ("Off", "OEM")],
        ),
        (
            "Bus Encryption",
            bus,
            [("Off", "clear reads"), ("On", "OEM bus encryption")],
        ),
        (
            "Region-free",
            region,
            [("On", "any region"), ("Off", "OEM region lock")],
        ),
        (
            "Diagnostic Dump",
            FeatureStatus::Wired,
            [("addr", "64-byte RAM read"), ("", "diagnostic")],
        ),
    ];
    for (label, status, detail) in rows {
        let (word, sty) = match status {
            FeatureStatus::Wired => ("added", style::Status::Ok),
            FeatureStatus::NotWired => ("skipped", style::Status::Warn),
            FeatureStatus::HookLocated => ("hook located", style::Status::Warn),
        };
        println!("{}", style::status_line(label, word, sty));
        let [(s1, d1), (s2, d2)] = detail;
        println!(
            "{}",
            style::dim_line(&format!("    {s1:<3} → {d1:<28}{s2:<3} → {d2}"))
        );
        match status {
            FeatureStatus::NotWired => println!(
                "{}",
                style::dim_line("      (not yet implemented in this build)")
            ),
            FeatureStatus::HookLocated => println!(
                "{}",
                style::dim_line("      (hook located; runtime patch not yet wired)")
            ),
            FeatureStatus::Wired => {}
        }
    }
}

/// The grounded facts the build used — every address derived from the image, so
/// this block is the audit trail for how the firmware was made.
fn print_create_details(engine_name: &str, report: &engine::CreateReport) {
    println!();
    println!("{}", style::dim("details:"));
    println!(
        "{}",
        style::dim(&format!(
            "  command: 3C {:02X} {:02X} {:02X}  (READ BUFFER hijack, OEM-unused mode + knock)",
            abi::KNOCK_MODE,
            abi::KNOCK[0],
            abi::KNOCK[1],
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  engine ({engine_name}): scanner @ 0x{:x} · CDB base @ 0x{:x} · sense-setter @ 0x{:x}",
            report.scanner_entry, report.cdb_base, report.sense_setter,
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  hijack: 0x{:02X} record @ 0x{:x}  handler 0x{:x} -> 0x{:x}  (flags 0x{:02X} preserved)",
            report.record.opcode, report.record.off, report.record.handler,
            report.handler_va | 1, report.record.flags,
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  handler: {} bytes injected at 0x{:x}",
            report.handler_bytes.len(),
            report.handler_va,
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  vid (0x03): producer @ 0x{:x} · scratch @ 0x{:x} · gate-setter @ 0x{:x}",
            report.vid_producer, report.vid_out_buf, report.vid_gate_setter,
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  speed (0x02): gate @ 0x{:x} -> stub 0x{:x}  (flag-gated, ramp untouched)",
            report.speed_gate, report.speed_stub_va,
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  region-free (0x05): emitter @ 0x{:x} -> stub 0x{:x}  (flag-gated RPC-1)",
            report.region_emitter, report.region_stub_va,
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  bus encryption (0x04): SetDiscMode @ 0x{:x}  (hook located; not yet wired — see notes)",
            report.setdiscmode,
        ))
    );
    println!(
        "{}",
        style::dim(&format!(
            "  flags: table @ 0x{:x} (validated free SRAM, unreferenced this image) · DE byte @ 0x{:x}",
            report.flag_base, report.de_off,
        ))
    );
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
