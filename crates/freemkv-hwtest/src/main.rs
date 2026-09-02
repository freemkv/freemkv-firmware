//! freemkv firmware hardware-test harness.
//!
//! A data-driven replacement for `scripts/fw_hwtest.sh`. Every test step is
//! issued through ONE call primitive ([`call::call_cdb`]) over libfreemkv's real
//! SCSI transport, so the test data-phase framing is byte-identical to
//! production — the class of bug (a knock sent with no data-in phase desyncs the
//! transfer and wedges the drive) that motivated the rewrite cannot recur.
//!
//! See `tests.yaml` for the script schema and `README.md` for how to run
//! against real hardware.

mod call;
mod cdb;
#[cfg(test)]
mod mock;
mod runner;
mod script;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use runner::{RunOutcome, Runner, StepReport};
use script::Script;

/// Print one step's result LIVE (and flush) as it completes, so a `ssh -tt` run
/// shows real-time progress instead of a buffered black box.
fn print_step_report(step: &StepReport) {
    use std::io::Write;
    if step.wedged {
        println!("  ABORT {}", step.name);
        if let Some(at) = &step.wedge_at {
            println!(
                "    drive wedged (DID_BAD_TARGET / timeout) at {at} — power-cycle to recover"
            );
        }
    } else {
        let phase = match step.phase {
            script::Phase::Discless => "discless",
            script::Phase::Disc => "disc",
        };
        if step.skipped {
            println!("  SKIP [{phase}] {}", step.name);
            if let Some(reason) = &step.skip_reason {
                println!("       -- {reason}");
            }
        } else {
            println!(
                "  {} [{phase}] {}",
                if step.passed() { "PASS" } else { "FAIL" },
                step.name
            );
            for c in &step.checks {
                println!("       {} {}", if c.pass { "ok " } else { "BAD" }, c.detail);
            }
        }
    }
    let _ = std::io::stdout().flush();
}

/// The default script shipped with the crate.
const DEFAULT_SCRIPT: &str = include_str!("../tests.yaml");

#[derive(Parser, Debug)]
#[command(
    name = "freemkv-hwtest",
    about = "freemkv firmware hardware-test harness (single-framing, YAML-driven)",
    version
)]
struct Cli {
    /// Path to a YAML test script (defaults to the built-in `tests.yaml`).
    #[arg(long)]
    script: Option<PathBuf>,

    /// SCSI generic device to test (e.g. /dev/sg0). Omit to load & validate the
    /// script only (a dry parse — no hardware touched).
    #[arg(long)]
    dev: Option<String>,

    /// Run ONLY the disc-less phases (skip disc-phase steps). This is the default
    /// unless `--disc` is given; the flag is accepted for parity with the shell.
    #[arg(long)]
    discless: bool,

    /// Include the disc-phase steps (a disc must be loaded).
    #[arg(long)]
    disc: bool,

    /// Expected identity version string (overrides the script's `expect_version`).
    #[arg(long)]
    expect_version: Option<String>,

    /// Don't pause to prompt for a disc between the disc-less and disc phases
    /// (run straight through — for automation / when a disc is already loaded).
    #[arg(long)]
    no_pause: bool,

    /// Inter-command delay in ms (rapid-fire is a known wedge trigger). Overrides
    /// the script / `HWTEST_DELAY_MS`. Use 0 to disable pacing.
    #[arg(long)]
    delay_ms: Option<u32>,

    /// Extra settle in ms after a flag-toggle knock (02/03/04) before the next
    /// read. Overrides the script / `HWTEST_SETTLE_MS`.
    #[arg(long)]
    settle_ms: Option<u32>,

    /// TEST UNIT READY polls before a disc read (0 disables). Overrides the
    /// script / `HWTEST_TUR_RETRIES`.
    #[arg(long)]
    tur_retries: Option<u32>,

    /// Base backoff in ms between TEST UNIT READY polls. Overrides the script /
    /// `HWTEST_TUR_BACKOFF_MS`.
    #[arg(long)]
    tur_backoff_ms: Option<u32>,

    /// Run every step's FULL declared iteration count (the 20x reliability soak).
    /// Without this, iterations are capped (see `--max-iters`) for a fast pass.
    #[arg(long)]
    soak: bool,

    /// Cap each step's `iterations` at this many for a fast run (default 3).
    /// Ignored when `--soak` is given (full count runs).
    #[arg(long, default_value_t = 3)]
    max_iters: usize,

    /// Kill an `exec` cert-AKE helper after this many ms so a hung helper (e.g. a
    /// 1.0 cert against a 2.0 disc) can't stall the run. 0 disables.
    #[arg(long, default_value_t = 25000)]
    exec_timeout_ms: u32,
}

/// A `u32` env var, if set and parseable.
fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

/// A non-empty env var, if set.
fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    let text = match &cli.script {
        Some(p) => {
            std::fs::read_to_string(p).with_context(|| format!("reading script {}", p.display()))?
        }
        None => DEFAULT_SCRIPT.to_string(),
    };
    let script = Script::from_yaml(&text).context("parsing test script")?;

    let version = cli
        .expect_version
        .clone()
        .or_else(|| script.expect_version.clone());
    let run_disc = cli.disc && !cli.discless;

    // No device → validate-only dry run (host-independent; used in CI smoke).
    let Some(dev) = &cli.dev else {
        println!(
            "script OK: {} step(s) parsed (no --dev; nothing issued)",
            script.steps.len()
        );
        println!(
            "  flag_base=0x{:08x}  timeout={}ms",
            script.flag_base(),
            script.timeout_ms()
        );
        if let Some(v) = &version {
            println!("  expected version: {v:?}");
        }
        return Ok(ExitCode::from(0));
    };

    let mut transport = libfreemkv::scsi::open(std::path::Path::new(dev))
        .map_err(|e| anyhow::anyhow!("opening {dev}: {e}"))?;

    // Resolve pacing: CLI > env > script > default.
    let base = script.pacing();
    let pacing = script::Pacing {
        delay_ms: cli
            .delay_ms
            .or_else(|| env_u32("HWTEST_DELAY_MS"))
            .unwrap_or(base.delay_ms),
        settle_ms: cli
            .settle_ms
            .or_else(|| env_u32("HWTEST_SETTLE_MS"))
            .unwrap_or(base.settle_ms),
        tur_retries: cli
            .tur_retries
            .or_else(|| env_u32("HWTEST_TUR_RETRIES"))
            .unwrap_or(base.tur_retries),
        tur_backoff_ms: cli
            .tur_backoff_ms
            .or_else(|| env_u32("HWTEST_TUR_BACKOFF_MS"))
            .unwrap_or(base.tur_backoff_ms),
    };

    // Resolve AKE config: script `ake:` block overlaid by env, dev from --dev.
    let mut ake = script.ake.clone().unwrap_or_default();
    ake.helper = env_str("AKE_HELPER").or(ake.helper);
    ake.valid_cert = env_str("VALID_CERT").or(ake.valid_cert);
    ake.valid_key = env_str("VALID_KEY").or(ake.valid_key);
    ake.revoked_cert = env_str("REVOKED_CERT").or(ake.revoked_cert);
    ake.revoked_key = env_str("REVOKED_KEY").or(ake.revoked_key);
    ake.dev = Some(dev.clone());

    // Fast by default (cap iterations); `--soak` runs each step's full count.
    let max_iters = if cli.soak {
        None
    } else {
        Some(cli.max_iters.max(1))
    };

    println!("freemkv firmware hardware test — {dev}");
    if let Some(v) = &version {
        println!("  expect identity: {v:?}");
    }
    println!(
        "  mode: {}   flag_base=0x{:08x}  timeout={}ms",
        if run_disc {
            "disc + disc-less"
        } else {
            "disc-less only"
        },
        script.flag_base(),
        script.timeout_ms()
    );
    println!(
        "  pacing: delay={}ms settle={}ms tur={}x@{}ms   AKE_HELPER={}\n",
        pacing.delay_ms,
        pacing.settle_ms,
        pacing.tur_retries,
        pacing.tur_backoff_ms,
        ake.helper.as_deref().unwrap_or("(unset — cert steps skip)")
    );
    println!(
        "  iterations: {}\n",
        match &max_iters {
            None => "full (soak)".to_string(),
            Some(m) => format!("fast (capped at {m}; use --soak for full)"),
        }
    );

    let mut r = Runner::new(transport.as_mut(), script.flag_base(), script.timeout_ms())
        .with_pacing(pacing)
        .with_ake(ake)
        .with_max_iters(max_iters)
        .with_disc_precheck(true)
        .with_exec_timeout(cli.exec_timeout_ms);
    // Stream each step's result LIVE (flushed) as it runs, and pause between the
    // disc-less and disc phases so the operator can insert a disc.
    let no_pause = cli.no_pause;
    let result = r.run_live(
        &script,
        run_disc,
        version.as_deref(),
        print_step_report,
        || {
            if no_pause {
                return;
            }
            use std::io::Write;
            print!(
                "\n>>> disc-less phases complete. Insert a disc, then press Enter to run the \
                 disc phases (Ctrl-C to stop)... "
            );
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            println!();
        },
    );

    // Steps were already printed live; here we only tally.
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skip = 0usize;
    for step in &result.steps {
        if step.wedged {
            continue;
        }
        if step.skipped {
            skip += 1;
        } else if step.passed() {
            pass += 1;
        } else {
            fail += 1;
        }
    }

    println!("\nPASS={pass} FAIL={fail} SKIP={skip}");
    match result.outcome {
        RunOutcome::Wedged => println!("RESULT: WEDGED"),
        RunOutcome::Failure => println!("RESULT: FAIL"),
        RunOutcome::AllPass => println!("RESULT: PASS"),
    }
    Ok(ExitCode::from(result.outcome.exit_code() as u8))
}
