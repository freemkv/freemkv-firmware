//! DPI-aware geometry for the Windows shell: pure arithmetic, no Win32.
//!
//! As in freemkv, every length here is at the 96-DPI baseline and `Scale::px` converts it
//! for a monitor; `Column`/`Line` stack rectangles top-down and left-to-right. Also the
//! control-pool sizes: winsafe cannot create a control once its window exists, so the shell
//! builds fixed pools up front and `panel_needs` says what a task form takes from them.
//!
//! Not `cfg(windows)`: it holds no Win32 types, so its tests run on every host.

use crate::ui::Item;

/// Windows' baseline: 100% scaling is 96 DPI, 150% is 144, 200% is 192.
pub const BASE_DPI: u32 = 96;

/// Default and minimum client size (the macOS shell's proportions).
pub const W: i32 = 900;
pub const H: i32 = 760;
pub const MIN_W: i32 = 760;
pub const MIN_H: i32 = 640;
/// Window margin and the gap between stacked rows.
pub const PAD: i32 = 16;
pub const GAP: i32 = 8;
/// A push button, combo box or tab strip row.
pub const ROW_H: i32 = 26;
/// One line of label text, and a checkbox row.
pub const LINE_H: i32 = 18;
pub const CHECK_H: i32 = 20;
pub const PROGRESS_H: i32 = 16;
/// The drive label, the Refresh button and the label leading a row of buttons.
pub const DRIVE_LABEL_W: i32 = 96;
pub const REFRESH_W: i32 = 90;
pub const LEAD_W: i32 = 80;
/// Button widths: text plus padding, never narrower than these.
pub const BUTTON_PAD: i32 = 28;
pub const BUTTON_MIN_W: i32 = 96;
pub const PRIMARY_MIN_W: i32 = 150;
/// The activity log pane, and the least the results list is given.
pub const LOG_H: i32 = 110;
pub const RESULTS_MIN_H: i32 = 80;
/// The results list's label column.
pub const FIELD_COL_W: i32 = 220;
/// The diagnostics and analysis windows' default sizes.
pub const DIAG_W: i32 = 680;
pub const DIAG_H: i32 = 460;
pub const ANALYSIS_W: i32 = 1000;
pub const ANALYSIS_H: i32 = 720;

/// Wrapping labels, single-line (path / row lead) labels, push buttons and checkboxes in
/// the task-form pools.
pub const POOL_TEXT: usize = 8;
pub const POOL_LINE: usize = 4;
pub const POOL_BUTTONS: usize = 8;
pub const POOL_CHECKS: usize = 2;
/// Action buttons in the diagnostics and analysis windows.
pub const DIAG_BUTTONS: usize = 4;
pub const ANALYSIS_BUTTONS: usize = 6;

/// A DPI and the one operation the layout needs from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scale {
    dpi: u32,
}

impl Scale {
    /// `GetDpiForWindow` answers 0 before a window exists; clamp to the baseline.
    #[must_use]
    pub fn new(dpi: u32) -> Self {
        Self {
            dpi: dpi.clamp(BASE_DPI, 960),
        }
    }

    #[must_use]
    pub const fn dpi(self) -> u32 {
        self.dpi
    }

    /// A baseline length in physical pixels, rounded half away from zero like `MulDiv`.
    #[must_use]
    pub fn px(self, v: i32) -> i32 {
        let n = i64::from(v) * i64::from(self.dpi);
        let d = i64::from(BASE_DPI);
        let r = if n >= 0 {
            (n + d / 2) / d
        } else {
            (n - d / 2) / d
        };
        r as i32
    }
}

/// One control's rectangle in physical client pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    #[must_use]
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }
}

/// Rows stacked down a fixed-width column, `gap` apart.
#[derive(Debug, Clone, Copy)]
pub struct Column {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub gap: i32,
}

impl Column {
    #[must_use]
    pub const fn new(x: i32, y: i32, w: i32, gap: i32) -> Self {
        Self { x, y, w, gap }
    }

    /// The next full-width row of height `h`.
    pub fn take(&mut self, h: i32) -> Rect {
        let r = Rect::new(self.x, self.y, self.w, h.max(0));
        self.y += h.max(0) + self.gap;
        r
    }

    /// The next row, to be divided left to right.
    pub fn line(&mut self, h: i32) -> Line {
        let r = self.take(h);
        Line {
            x: r.x,
            right: r.x + r.w,
            y: r.y,
            h: r.h,
            gap: self.gap,
        }
    }

    pub fn space(&mut self, h: i32) {
        self.y += h;
    }
}

/// One row divided into cells: from the left with `take`, from the right with
/// `take_right`, the remainder with `rest`.
#[derive(Debug, Clone, Copy)]
pub struct Line {
    pub x: i32,
    pub right: i32,
    pub y: i32,
    pub h: i32,
    pub gap: i32,
}

impl Line {
    pub fn take(&mut self, w: i32) -> Rect {
        let w = w.clamp(0, (self.right - self.x).max(0));
        let r = Rect::new(self.x, self.y, w, self.h);
        self.x += w + self.gap;
        r
    }

    pub fn take_right(&mut self, w: i32) -> Rect {
        let w = w.clamp(0, (self.right - self.x).max(0));
        self.right -= w;
        let r = Rect::new(self.right, self.y, w, self.h);
        self.right -= self.gap;
        r
    }

    pub fn rest(&mut self) -> Rect {
        let r = Rect::new(self.x, self.y, (self.right - self.x).max(0), self.h);
        self.x = self.right;
        r
    }

    /// A cell of height `h` centred vertically in this row.
    #[must_use]
    pub fn centre(r: Rect, h: i32) -> Rect {
        Rect::new(r.x, r.y + (r.h - h) / 2, r.w, h)
    }
}

/// Default and minimum client sizes at a DPI.
#[must_use]
pub fn default_size(dpi: u32) -> (i32, i32) {
    let s = Scale::new(dpi);
    (s.px(W), s.px(H))
}

#[must_use]
pub fn min_size(dpi: u32) -> (i32, i32) {
    let s = Scale::new(dpi);
    (s.px(MIN_W), s.px(MIN_H))
}

/// A push button's width for text `text_w` pixels wide.
#[must_use]
pub fn button_width(s: Scale, text_w: i32, primary: bool) -> i32 {
    let min = if primary { PRIMARY_MIN_W } else { BUTTON_MIN_W };
    (text_w + s.px(BUTTON_PAD)).max(s.px(min))
}

/// What one task form takes from the control pools.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Needs {
    pub text: usize,
    pub line: usize,
    pub buttons: usize,
    pub checks: usize,
}

impl Needs {
    /// Whether the pools hold it all.
    #[must_use]
    pub const fn fits(self) -> bool {
        self.text <= POOL_TEXT
            && self.line <= POOL_LINE
            && self.buttons <= POOL_BUTTONS
            && self.checks <= POOL_CHECKS
    }
}

#[must_use]
pub fn panel_needs(items: &[Item]) -> Needs {
    let mut n = Needs::default();
    for item in items {
        match item {
            Item::Text(_) | Item::Heading(_) | Item::Note(_) | Item::Warning(_) => n.text += 1,
            Item::Check { .. } => n.checks += 1,
            Item::Path { path, .. } => {
                n.buttons += 1;
                n.line += usize::from(path.is_some());
            }
            Item::Buttons { label, buttons } => {
                n.line += usize::from(label.is_some());
                n.buttons += buttons.len();
            }
        }
    }
    n
}

#[cfg(test)]
#[path = "win_layout_tests.rs"]
mod tests;
