//! qa's GUI gate: what each native shell checks about itself when a debug build runs with
//! `FREEMKV_FLASH_GATE=<dir>`.
//!
//! The shell starts on a synthetic drive whose profile offers every task (`fixture`), walks
//! every tab through real `Input`s, opens the flash confirmation over a synthetic authorized
//! plan (`open_flash_sheet`), reads its Confirm control from the native widget, and captures
//! itself. The model is `inert` throughout: no job, profile read or drive scan can start, so
//! the gate never reaches a device. The pixel arithmetic and the verdict live here,
//! toolkit-free and tested on every host. Debug builds only (`main.rs`).

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use freemkv_flash::workflow::{DriveChoice, FlashOptions, FlashSheet};

use crate::ui::{App, Input, Pending, Pick, Profile, ProfileState, Sheet, Target, Task};

/// Set to a directory, it turns the gate on; the report and captures go there.
pub const ENV: &str = "FREEMKV_FLASH_GATE";
/// The tabs the gate walks, in order.
pub const TABS: [Task; 7] = [
    Task::Info,
    Task::Backup,
    Task::Dump,
    Task::Flash,
    Task::Recovery,
    Task::Inspect,
    Task::Compare,
];
/// A gate still running after this has hung: the watchdog fails it.
pub const DEADLINE: Duration = Duration::from_secs(90);
/// The synthetic drive's id; no platform backend knows it.
pub const DRIVE: &str = "freemkv-flash-gate:synthetic";

/// The gate's directory, when the gate is on.
pub fn dir() -> Option<PathBuf> {
    std::env::var_os(ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The model a shell starts with: under the gate, the armed `fixture` and the gate's
/// directory; otherwise `real()`, which the gate never calls (it scans the drives).
pub fn model_or(real: impl FnOnce() -> App) -> (App, Option<PathBuf>) {
    match dir() {
        Some(dir) => {
            arm(&dir);
            (fixture(), Some(dir))
        }
        None => (real(), None),
    }
}

/// Create `dir`, leave any panic's message in `panic.txt` there, and fail the run if the
/// gate has not finished by `DEADLINE`, so no window outlives a hung gate.
pub fn arm(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let panic_txt = dir.join("panic.txt");
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let _ = std::fs::write(&panic_txt, format!("{info}\n{bt}"));
        previous(info);
    }));
    let report = dir.join("gate.txt");
    std::thread::spawn(move || {
        std::thread::sleep(DEADLINE);
        let mut g = Gate::default();
        g.check(
            "watchdog",
            false,
            format!("the gate did not finish within {} s", DEADLINE.as_secs()),
        );
        let _ = std::fs::write(report, g.report());
        std::process::exit(1);
    });
}

/// The model the gate drives: one synthetic drive, its profile answered with every task,
/// and a file chosen for every slot, so each tab shows its full form. Inert: nothing it is
/// asked to do can start a worker.
pub fn fixture() -> App {
    let mut app = App::with_drives(vec![DriveChoice {
        path: DRIVE.into(),
        name: "GATE".into(),
        label: "Synthetic drive 1.00 (no hardware)".into(),
    }]);
    app.inert = true;
    app.profile = ProfileState::Ready(Profile {
        chips: ["Synthetic", "Backup", "Dump", "Flash", "Recovery"]
            .map(String::from)
            .to_vec(),
        tasks: vec![Task::Backup, Task::Dump, Task::Flash, Task::Recovery],
        inspect: true,
        backup_name: Some("GATE_1.00.backup.bin".into()),
        dump_name: Some("GATE_1.00.dump.bin".into()),
        flash_extensions: vec!["bin"],
        notes: Vec::new(),
    });
    for (pick, file) in [
        (Pick::FlashFirmware, "gate-firmware.bin"),
        (Pick::RecoveryCurrent, "gate-current.bin"),
        (Pick::RecoveryInput, "gate-recovery.bin"),
        (Pick::AnalysisFile(0), "gate-a.bin"),
        (Pick::AnalysisFile(1), "gate-b.bin"),
    ] {
        app.dispatch(Input::Chosen(pick, PathBuf::from(file)));
    }
    app
}

/// Ask the flash confirmation over a synthetic authorized plan, as a passed backup and
/// authorization would. No worker waits on the answer: its receiver is already gone.
pub fn open_flash_sheet(app: &mut App) {
    let (reply, _) = mpsc::channel();
    let input = app.flash_input.clone().unwrap_or_default();
    app.risk_ack = false;
    app.pending = Some(Pending {
        target: Target {
            device: app.device.clone(),
            label: app.device_label(),
            options: FlashOptions {
                input,
                execute: true,
                ..Default::default()
            },
        },
        sheet: Sheet::Flash {
            sheet: FlashSheet {
                plan: vec![
                    "GUI gate: a synthetic plan; nothing is written.".into(),
                    "backup: gate.backup.bin".into(),
                ],
                warnings: vec!["GUI gate: a synthetic warning.".into()],
                confirmation: Some("Write the synthetic image?".into()),
            },
            reply,
        },
    });
}

/// The model is still the gate's: inert, its profile answered, and no worker or profile
/// read running.
pub fn inert(app: &App) -> bool {
    app.inert
        && !app.running()
        && app.profile_rx.is_none()
        && matches!(app.profile, ProfileState::Ready(_))
}

/// A tab's name in a capture's file name.
pub fn tab_name(task: Task) -> String {
    task.title().to_lowercase().replace(' ', "-")
}

// ── captures ──────────────────────────────────────────────────────────────

/// A rectangle of a capture, in top-down pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Region {
    /// A rectangle given in points from the bottom-left of a view `height` points tall (an
    /// AppKit frame), in the pixels of a capture taken at `scale` pixels per point.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn from_bottom_left(x: f64, y: f64, w: f64, h: f64, height: f64, scale: f64) -> Self {
        let px = |v: f64| (v * scale).round() as i32;
        Self {
            x: px(x),
            y: px(height - y - h),
            w: px(w),
            h: px(h),
        }
    }
}

/// How a capture's four bytes per pixel are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Windows and GTK; AppKit captures are RGBA.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Bgra,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Rgba,
}

/// A 32-bit capture of a window, rows tightly packed.
#[derive(Debug, Clone)]
pub struct Capture {
    pub width: i32,
    pub height: i32,
    pub px: Vec<u8>,
    pub order: Order,
    /// Rows run bottom to top, as in a Windows DIB.
    pub bottom_up: bool,
}

impl Capture {
    pub fn full(&self) -> Region {
        Region {
            x: 0,
            y: 0,
            w: self.width,
            h: self.height,
        }
    }

    /// Whether `r` holds more than one colour: text or a rule on its background, not a blank
    /// fill. A region outside the capture, or a capture shorter than its size, has no ink.
    pub fn has_ink(&self, r: Region) -> bool {
        let (x0, y0) = (r.x.max(0), r.y.max(0));
        let (x1, y1) = ((r.x + r.w).min(self.width), (r.y + r.h).min(self.height));
        let mut first: Option<&[u8]> = None;
        for y in y0..y1 {
            let row = if self.bottom_up {
                self.height - 1 - y
            } else {
                y
            };
            for x in x0..x1 {
                let i = (row as usize * self.width as usize + x as usize) * 4;
                let Some(p) = self.px.get(i..i + 3) else {
                    return false;
                };
                match first {
                    None => first = Some(p),
                    Some(f) if f != p => return true,
                    Some(_) => {}
                }
            }
        }
        false
    }

    /// Composite a capture with alpha onto an opaque `bg`, so text drawn on a transparent
    /// window background stays visible whichever appearance (light or dark) drew it.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn flatten(&mut self, bg: [u8; 3], premultiplied: bool) {
        for p in self.px.as_chunks_mut::<4>().0 {
            let a = u16::from(p[3]);
            for (c, b) in p[..3].iter_mut().zip(bg) {
                let ink = if premultiplied {
                    u16::from(*c)
                } else {
                    u16::from(*c) * a / 255
                };
                *c = (ink + u16::from(b) * (255 - a) / 255).min(255) as u8;
            }
            p[3] = 255;
        }
    }

    /// Top-down RGBA rows, opaque: what a PNG of the capture holds.
    pub fn rgba(&self) -> Vec<u8> {
        let stride = self.width.max(0) as usize * 4;
        let mut out = Vec::with_capacity(self.px.len());
        for y in 0..self.height.max(0) as usize {
            let row = if self.bottom_up {
                self.height as usize - 1 - y
            } else {
                y
            };
            let Some(line) = self.px.get(row * stride..(row + 1) * stride) else {
                break;
            };
            for p in line.as_chunks::<4>().0 {
                let (r, b) = match self.order {
                    Order::Bgra => (p[2], p[0]),
                    Order::Rgba => (p[0], p[2]),
                };
                out.extend_from_slice(&[r, p[1], b, 255]);
            }
        }
        out
    }

    pub fn save_png(&self, path: &Path) -> Result<(), String> {
        let (w, h) = (self.width.max(0) as u32, self.height.max(0) as u32);
        image::save_buffer_with_format(
            path,
            &self.rgba(),
            w,
            h,
            image::ExtendedColorType::Rgba8,
            image::ImageFormat::Png,
        )
        .map_err(|e| e.to_string())
    }
}

// ── the checks ────────────────────────────────────────────────────────────

/// The gate's findings, in order.
#[derive(Debug, Default)]
pub struct Gate {
    checks: Vec<(bool, String)>,
}

impl Gate {
    /// Record a check. A failure is also printed at once, so it shows even when the app
    /// dies before it writes the report.
    pub fn check(&mut self, name: &str, ok: bool, detail: impl AsRef<str>) {
        let line = format!("{name} — {}", detail.as_ref());
        if !ok {
            eprintln!("GATE FAIL {line}");
        }
        self.checks.push((ok, line));
    }

    /// Whether every check passed; a gate that checked nothing has not passed.
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|(ok, _)| *ok)
    }

    /// One `GATE PASS …` / `GATE FAIL …` line per check, then the verdict.
    pub fn report(&self) -> String {
        let mut out: String = self
            .checks
            .iter()
            .map(|(ok, line)| format!("GATE {} {line}\n", if *ok { "PASS" } else { "FAIL" }))
            .collect();
        let failed = self.checks.iter().filter(|(ok, _)| !ok).count();
        out.push_str(&if self.passed() {
            format!("GATE OK: {} checks\n", self.checks.len())
        } else {
            format!("GATE FAILED: {failed} of {} checks\n", self.checks.len())
        });
        out
    }

    /// Write `gate.txt` to `dir`; the process's exit code: 0 only if every check passed and
    /// the report was written.
    pub fn finish(&self, dir: &Path) -> i32 {
        let written = std::fs::write(dir.join("gate.txt"), self.report()).is_ok();
        i32::from(!(written && self.passed()))
    }

    /// Save `capture` as `<dir>/<name>.png`, and check that it was taken and saved.
    pub fn save(&mut self, dir: &Path, name: &str, capture: Option<&Capture>) {
        let path = dir.join(format!("{name}.png"));
        let saved = match capture {
            Some(c) => c.save_png(&path),
            None => Err("the window could not be captured".into()),
        };
        let detail = match &saved {
            Ok(()) => path.display().to_string(),
            Err(e) => format!("{}: {e}", path.display()),
        };
        self.check("capture", saved.is_ok(), detail);
    }

    /// The model still could not reach a device.
    pub fn no_drive_io(&mut self, when: &str, app: &App) {
        let detail = format!(
            "{when}: inert {}, worker {}, profile read {}",
            app.inert,
            app.running(),
            app.profile_rx.is_some()
        );
        self.check("no-drive-io", inert(app), detail);
    }
}

/// What a shell saw of one tab.
#[derive(Debug, Clone)]
pub struct TabRun {
    pub task: Task,
    /// The model shows the task, its tab enabled.
    pub model: bool,
    /// The native tab control shows the task selected; `None` when it could not be read.
    pub widget: Option<bool>,
    /// The task form's area of a capture has ink; `None` when there was no capture.
    pub ink: Option<bool>,
}

pub fn tab_checks(g: &mut Gate, t: &TabRun) {
    let name = t.task.title();
    g.check("tab-in-model", t.model, name);
    g.check(
        "tab-selected-in-widget",
        t.widget == Some(true),
        format!("{name}: {}", seen(t.widget, "selected", "not selected")),
    );
    g.check(
        "tab-form-has-ink",
        t.ink == Some(true),
        format!("{name}: {}", seen(t.ink, "drawn", "blank")),
    );
}

/// What a shell saw of one opening of the flash confirmation, read from its native widgets.
#[derive(Debug, Clone, Default)]
pub struct SheetRun {
    /// The native sheet or dialog came up.
    pub opened: bool,
    /// The risk box was unticked on opening; `None` when the box could not be found.
    pub unticked: Option<bool>,
    /// The Confirm control was enabled on opening; `None` when it could not be found.
    pub confirm_before: Option<bool>,
    /// After ticking the risk box through its widget's click path: the model's
    /// acknowledgement and whether the Confirm control was enabled. `None` when the box was
    /// not ticked.
    pub ticked: Option<(bool, Option<bool>)>,
    /// After that tick, made the way a user makes it (AppKit `performClick:`, GTK's
    /// `activate` signal, the task dialog's `TDM_CLICK_VERIFICATION`), the box's state as
    /// the shell reads it back from the toolkit (on Windows, as the task dialog reported
    /// it). `None` when not ticked or unreadable.
    pub box_reads_ticked: Option<bool>,
    /// After Cancel through its widget, the model withdrew the request and the sheet closed.
    pub closed: bool,
}

/// Whether a task dialog's verification box is unticked: its creation flags leave it
/// unticked, the dialog has reported no tick since it was created (it reports every change,
/// however caused, and offers no query), and the model holds no acknowledgement.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn task_dialog_unticked(flag_checked: bool, reported_checked: bool, acked: bool) -> bool {
    !flag_checked && !reported_checked && !acked
}

/// The confirmation's checks: opened unticked with Confirm disabled, Confirm enabled by the
/// tick and only then, closed by Cancel, and reopened unticked and disabled again.
pub fn sheet_checks(g: &mut Gate, first: &SheetRun, reopened: &SheetRun) {
    let state = |v: Option<bool>| seen(v, "enabled", "disabled");
    g.check("sheet-opens", first.opened, "the flash confirmation");
    g.check(
        "sheet-opens-unticked",
        first.unticked == Some(true),
        seen(first.unticked, "unticked", "ticked"),
    );
    g.check(
        "confirm-disabled-before-tick",
        first.confirm_before == Some(false),
        state(first.confirm_before),
    );
    let (acked, after) = first.ticked.unwrap_or((false, None));
    g.check(
        "tick-reaches-model",
        first.ticked.is_some() && acked,
        match first.ticked {
            None => "the risk box was not ticked",
            Some((true, _)) => "acknowledged",
            Some((false, _)) => "not acknowledged",
        },
    );
    g.check(
        "confirm-enabled-after-tick",
        after == Some(true),
        state(after),
    );
    g.check(
        "clicked-box-reads-ticked",
        first.box_reads_ticked == Some(true),
        format!(
            "after a click through the toolkit the box reads {}",
            seen(first.box_reads_ticked, "ticked", "unticked")
        ),
    );
    g.check("sheet-closes-on-cancel", first.closed, "first opening");
    g.check("sheet-reopens", reopened.opened, "after Cancel");
    g.check(
        "reopened-sheet-unticked",
        reopened.unticked == Some(true),
        seen(reopened.unticked, "unticked", "ticked"),
    );
    g.check(
        "confirm-disabled-after-reopen",
        reopened.confirm_before == Some(false),
        state(reopened.confirm_before),
    );
    g.check("sheet-closes-on-cancel", reopened.closed, "reopened");
}

fn seen(v: Option<bool>, yes: &str, no: &str) -> String {
    match v {
        Some(true) => yes.into(),
        Some(false) => no.into(),
        None => "not found".into(),
    }
}

#[cfg(test)]
#[path = "gui_gate_tests.rs"]
mod tests;
