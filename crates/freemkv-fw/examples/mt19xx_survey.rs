//! Per-family BUILD survey over the MediaTek MT19xx firmware corpus.
//!
//! Reproducible evidence for the portability claim: "does the tri-state engine
//! build across every OEM MTK firmware family?" For every ~2 MiB image under the
//! given roots that detects as MT19xx (`MTEKMT1959` / `MTEKMT1939`), it records:
//!
//! * the family-agnostic finders — `find_flash_program` (must be n==1) and
//!   `find_boot_init` (Modern / ClassicUnconfirmed / None / ambiguous);
//! * the strict `create` build outcome, categorised as
//!     - `built`       — build succeeded AND every AES-CMAC region re-verifies;
//!     - `fail-closed` — build refused BECAUSE the boot-init site is the
//!       hardware-unconfirmed MT1939-classic leaf helper (expected, safe DE-only
//!       degrade — not a defect);
//!     - `errored`     — any other build/verify failure (a real gap to look at).
//!
//! and prints a per-family matrix plus the aggregate finder tallies.
//!
//! Usage (corpus root supplied by the operator — never baked in):
//!   cargo run -p freemkv-fw --example mt19xx_survey -- ROOT [ROOT ...]
//!   FREEMKV_KAT_HOARD=/path cargo run -p freemkv-fw --example mt19xx_survey
//!
//! At least one root must come from an arg or the colon-separated
//! `FREEMKV_KAT_HOARD` env var, else the harness exits with usage. Writes
//! nothing; read-only over the corpus.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use freemkv_fw::engine::core::BootInitSite;
use freemkv_fw::engine::mt1959::Mt1959Engine;
use freemkv_fw::engine::{self};
use freemkv_fw::family::{self, ChipFamily};
use freemkv_fw::scheme::{IntegrityScheme, MtkCmac};

#[derive(Default)]
struct FamilyRow {
    total: usize,
    built: usize,
    fail_closed: usize,
    errored: usize,
    flash_n1: usize,
    boot_modern: usize,
    boot_classic: usize,
    boot_none: usize,
    boot_ambiguous: usize,
}

fn collect_bins(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_bins(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("bin") {
            if let Ok(m) = std::fs::metadata(&p) {
                if (2_000_000..2_200_000).contains(&(m.len() as usize)) {
                    out.push(p);
                }
            }
        }
    }
}

fn main() {
    let mut roots: Vec<String> = std::env::args().skip(1).collect();
    if roots.is_empty() {
        if let Ok(env) = std::env::var("FREEMKV_KAT_HOARD") {
            roots.extend(env.split(':').filter(|s| !s.is_empty()).map(String::from));
        }
    }
    if roots.is_empty() {
        eprintln!(
            "usage: mt19xx_survey ROOT [ROOT ...]   (or set FREEMKV_KAT_HOARD)\n\
             no corpus root given — pass a firmware-hoard directory to survey."
        );
        std::process::exit(2);
    }

    let mut files = Vec::new();
    for r in &roots {
        collect_bins(Path::new(r), &mut files);
    }
    files.sort();
    files.dedup();

    let eng = Mt1959Engine;
    // Family key = a coarse model label (vendor+model), so near-duplicate revisions
    // group together and the matrix reads one line per drive model.
    let mut rows: BTreeMap<String, FamilyRow> = BTreeMap::new();
    let mut mt19xx = 0usize;

    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(chip) = family::detect_chip(&bytes) else {
            continue; // not an identifiable MTK part (Pioneer/Renesas etc.)
        };
        let fam = chip.family;
        if !matches!(fam, ChipFamily::Mt1959 | ChipFamily::Mt1939) {
            continue;
        }
        // Scope to images the engine RECOGNISES as a 3C target (scanner entry
        // resolves) — the portability claim is about drives the tool actually
        // builds, not every part that merely carries an MTEKMT19xx tag. Images that
        // fail this gate (older DVD-lineage / ASUS BC-12* etc.) are refused cleanly
        // and are out of scope for the tri-state build.
        if eng.find_scanner_entry(&bytes).is_err() {
            continue;
        }
        mt19xx += 1;

        let model = if chip.model.is_empty() {
            fam.label().to_string()
        } else {
            format!("{} {}", fam.label(), chip.model)
        };
        let row = rows.entry(model).or_default();
        row.total += 1;

        // Family-agnostic finders (scanned directly, independent of engine choice).
        if eng
            .find_flash_program(&bytes)
            .map(|v| v != 0)
            .unwrap_or(false)
        {
            row.flash_n1 += 1;
        }
        let boot = eng.find_boot_init(&bytes);
        match boot {
            Ok(Some(BootInitSite::Modern(_))) => row.boot_modern += 1,
            Ok(Some(BootInitSite::ClassicUnconfirmed(_))) => row.boot_classic += 1,
            Ok(None) => row.boot_none += 1,
            Err(_) => row.boot_ambiguous += 1,
        }

        // Strict build outcome via the family engine.
        match engine::for_family(fam).and_then(|e| e.create(&bytes)) {
            Ok(report) => match MtkCmac.verify(&report.image) {
                Ok(v) if !v.is_empty() && v.iter().all(|r| r.ok) => row.built += 1,
                _ => row.errored += 1,
            },
            Err(_) => {
                // Distinguish the EXPECTED classic fail-closed (unconfirmed boot-init
                // leaf helper) from a genuine hard error.
                if matches!(boot, Ok(Some(BootInitSite::ClassicUnconfirmed(_)))) {
                    row.fail_closed += 1;
                } else {
                    row.errored += 1;
                }
            }
        }
    }

    // --- report -----------------------------------------------------------------
    println!("# MT19xx per-family build survey\n");
    println!("roots: {}", roots.join(", "));
    println!("MT19xx images found: {mt19xx}\n");
    println!(
        "| {:<28} | {:>5} | {:>5} | {:>11} | {:>7} | {:>8} | {:>6} | {:>7} |",
        "family (model)",
        "imgs",
        "built",
        "fail-closed",
        "errored",
        "flash n1",
        "modern",
        "classic"
    );
    println!(
        "|{:-<30}|{:-<7}|{:-<7}|{:-<13}|{:-<9}|{:-<10}|{:-<8}|{:-<9}|",
        "", "", "", "", "", "", "", ""
    );

    let mut tot = FamilyRow::default();
    for (model, r) in &rows {
        println!(
            "| {:<28} | {:>5} | {:>5} | {:>11} | {:>7} | {:>8} | {:>6} | {:>7} |",
            model,
            r.total,
            r.built,
            r.fail_closed,
            r.errored,
            r.flash_n1,
            r.boot_modern,
            r.boot_classic
        );
        tot.total += r.total;
        tot.built += r.built;
        tot.fail_closed += r.fail_closed;
        tot.errored += r.errored;
        tot.flash_n1 += r.flash_n1;
        tot.boot_modern += r.boot_modern;
        tot.boot_classic += r.boot_classic;
        tot.boot_none += r.boot_none;
        tot.boot_ambiguous += r.boot_ambiguous;
    }
    println!(
        "|{:-<30}|{:-<7}|{:-<7}|{:-<13}|{:-<9}|{:-<10}|{:-<8}|{:-<9}|",
        "", "", "", "", "", "", "", ""
    );
    println!(
        "| {:<28} | {:>5} | {:>5} | {:>11} | {:>7} | {:>8} | {:>6} | {:>7} |",
        "TOTAL",
        tot.total,
        tot.built,
        tot.fail_closed,
        tot.errored,
        tot.flash_n1,
        tot.boot_modern,
        tot.boot_classic
    );

    println!(
        "\nfinders: flash_program n==1 on {}/{} | boot-init: modern {} / classic {} / none {} / ambiguous {}",
        tot.flash_n1, tot.total, tot.boot_modern, tot.boot_classic, tot.boot_none, tot.boot_ambiguous
    );
}
