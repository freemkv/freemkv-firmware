//! freemkv-firmware command-line interface.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use freemkv_firmware::detect::{self, ChipClass};
use freemkv_firmware::flash::{self, FlashPlan, SafetyContext};
use freemkv_firmware::manifest::{FlashMode, Manifest};
use freemkv_firmware::{cmac, crc32, scsi};

/// freemkv optical-drive firmware flasher + firmware-build pipeline.
#[derive(Parser, Debug)]
#[command(name = "freemkv-firmware", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Identify and classify the connected optical drive.
    Detect {
        /// SCSI device path (e.g. /dev/sr0).
        #[arg(short, long, default_value = "/dev/sr0")]
        device: String,
    },
    /// List available firmware images from a manifest.
    List {
        /// Path to a TOML manifest.
        #[arg(short, long)]
        manifest: PathBuf,
    },
    /// Flash a firmware image to a drive (dry-run unless --execute).
    Flash(FlashArgs),
    /// Verify a firmware image's AES-CMAC integrity table.
    Verify {
        /// Path to a firmware .bin.
        image: PathBuf,
    },
    /// Re-sign a firmware image's AES-CMAC table, writing a new .bin.
    Resign {
        /// Input firmware .bin.
        image: PathBuf,
        /// Output path for the re-signed image.
        #[arg(short, long)]
        out: PathBuf,
    },
}

#[derive(Parser, Debug)]
struct FlashArgs {
    /// SCSI device path (e.g. /dev/sr0).
    #[arg(short, long, default_value = "/dev/sr0")]
    device: String,
    /// Manifest describing available images.
    #[arg(short, long)]
    manifest: PathBuf,
    /// Firmware model to select from the manifest.
    #[arg(long)]
    model: String,
    /// Firmware version to select from the manifest.
    #[arg(long)]
    version: String,
    /// Override the manifest flash mode.
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
    /// Acknowledge that flashing can permanently brick the drive.
    #[arg(long)]
    i_understand_risk: bool,
    /// Permit flashing firmware whose model differs from the drive.
    #[arg(long)]
    allow_cross_flash: bool,
    /// Actually issue SCSI writes (otherwise dry-run only).
    #[arg(long)]
    execute: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ModeArg {
    Main,
    Full,
    Enc,
}

impl From<ModeArg> for FlashMode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Main => FlashMode::Main,
            ModeArg::Full => FlashMode::Full,
            ModeArg::Enc => FlashMode::Enc,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Detect { device } => cmd_detect(&device),
        Command::List { manifest } => cmd_list(&manifest),
        Command::Flash(args) => cmd_flash(args),
        Command::Verify { image } => cmd_verify(&image),
        Command::Resign { image, out } => cmd_resign(&image, &out),
    }
}

fn cmd_detect(device: &str) -> Result<()> {
    let mut dev = scsi::open(device)?;
    println!("device: {}", dev.describe());
    let p = detect::probe(dev.as_mut());
    if let Some(inq) = &p.inquiry {
        println!(
            "inquiry: vendor='{}' product='{}' rev='{}'",
            inq.vendor, inq.product, inq.revision
        );
    } else {
        println!("inquiry: <unavailable>");
    }
    println!("chip-id: {}", p.chip_id.as_deref().unwrap_or("<none>"));
    println!(
        "boot-banner: {}",
        p.boot_banner.as_deref().unwrap_or("<none>")
    );
    println!("pioneer-vendor-probe: {}", p.pioneer_vendor);
    let class = detect::classify(&p);
    println!("classification: {class}");
    if class == ChipClass::Unknown {
        println!("(fail-safe: Unknown drives are never flashed)");
    }
    Ok(())
}

fn cmd_list(manifest_path: &std::path::Path) -> Result<()> {
    let manifest = Manifest::load(manifest_path)?;
    if manifest.images.is_empty() {
        println!("(manifest has no images)");
        return Ok(());
    }
    for ((model, kind), images) in manifest.grouped() {
        println!("{model}  [{kind:?}]");
        for img in images {
            println!(
                "  - v{:<12} chip={:?} mode={:?} downgrade={} crc32={:08x}  {}",
                img.version, img.chip, img.flash_mode, img.downgrade_enable, img.crc32, img.path
            );
        }
    }
    Ok(())
}

fn cmd_flash(args: FlashArgs) -> Result<()> {
    let manifest = Manifest::load(&args.manifest)?;
    let selected = manifest
        .images
        .iter()
        .find(|i| i.model == args.model && i.version == args.version)
        .with_context(|| {
            format!(
                "no manifest image matches model='{}' version='{}'",
                args.model, args.version
            )
        })?;

    // Resolve the image path relative to the manifest directory if needed.
    let img_path = {
        let p = PathBuf::from(&selected.path);
        if p.is_absolute() {
            p
        } else {
            args.manifest
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(p)
        }
    };
    let image = std::fs::read(&img_path)
        .with_context(|| format!("reading firmware image {}", img_path.display()))?;

    let actual_crc = crc32(&image);
    if actual_crc != selected.crc32 {
        bail!(
            "image CRC32 mismatch: manifest says {:08x}, file is {:08x} — refusing to flash",
            selected.crc32,
            actual_crc
        );
    }

    let flash_mode: FlashMode = args.mode.map(Into::into).unwrap_or(selected.flash_mode);

    // Probe the drive so we can gate on the real model.
    let mut dev = scsi::open(&args.device)?;
    let probe = detect::probe(dev.as_mut());
    let drive_model = probe
        .inquiry
        .as_ref()
        .map(|i| i.product.clone())
        .unwrap_or_default();
    let class = detect::classify(&probe);

    println!("== flash plan ==");
    println!("device:         {}", dev.describe());
    println!(
        "drive model:    {}",
        if drive_model.is_empty() {
            "<unknown>"
        } else {
            &drive_model
        }
    );
    println!("drive class:    {class}");
    println!(
        "firmware:       {} v{} [{:?}]",
        selected.model, selected.version, selected.kind
    );
    println!("flash mode:     {flash_mode:?}");
    println!(
        "image:          {} ({} bytes, crc32={:08x})",
        img_path.display(),
        image.len(),
        actual_crc
    );

    // Safety gate.
    let ctx = SafetyContext {
        drive_model: &drive_model,
        firmware_model: &selected.model,
        acknowledged_risk: args.i_understand_risk,
        allow_cross_flash: args.allow_cross_flash,
    };
    if let Err(block) = flash::check_safety(&ctx) {
        bail!("SAFETY GATE: {}", block.0);
    }
    if class == ChipClass::Unknown {
        bail!("SAFETY GATE: drive silicon classified as Unknown — refusing to flash");
    }

    let plan = FlashPlan::prepare(&image, flash_mode)?;
    println!(
        "payload:        {} bytes in {} chunk(s) of {} B{}",
        plan.payload.len(),
        plan.chunk_count(),
        plan.chunk,
        if flash_mode == FlashMode::Enc {
            " (AES-128-ECB enc-wrapped)"
        } else {
            ""
        }
    );

    if !args.execute {
        println!("\nDRY RUN: no SCSI writes issued. Re-run with --execute to flash.");
        return Ok(());
    }

    println!("\nEXECUTING flash — do not power off or disconnect the drive...");
    plan.execute(dev.as_mut())?;
    println!("flash complete: {} bytes written.", plan.payload.len());
    Ok(())
}

fn cmd_verify(image_path: &std::path::Path) -> Result<()> {
    let image =
        std::fs::read(image_path).with_context(|| format!("reading {}", image_path.display()))?;
    let verdicts = cmac::verify_detailed(&image)?;
    if verdicts.is_empty() {
        bail!("no active CMAC entries found (not an MT1959 image?)");
    }
    let mut all_ok = true;
    for v in &verdicts {
        let mark = if v.matches { "MATCH" } else { "MISMATCH" };
        all_ok &= v.matches;
        println!(
            "[{:>2}] 0x{:06x}-0x{:06x}  {}  {}",
            v.entry.index,
            v.entry.start,
            v.entry.end,
            hex16(&v.entry.stored),
            mark
        );
    }
    if all_ok {
        println!("CMAC: all {} active entries verified.", verdicts.len());
        Ok(())
    } else {
        bail!("CMAC verification failed")
    }
}

fn cmd_resign(image_path: &std::path::Path, out_path: &std::path::Path) -> Result<()> {
    let image =
        std::fs::read(image_path).with_context(|| format!("reading {}", image_path.display()))?;
    let resigned = cmac::resign(&image)?;
    std::fs::write(out_path, &resigned)
        .with_context(|| format!("writing {}", out_path.display()))?;
    println!(
        "re-signed {} -> {} ({} bytes)",
        image_path.display(),
        out_path.display(),
        resigned.len()
    );
    if cmac::verify(&resigned) {
        println!("verification of re-signed image: OK");
    } else {
        bail!("re-signed image failed self-verification");
    }
    Ok(())
}

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
