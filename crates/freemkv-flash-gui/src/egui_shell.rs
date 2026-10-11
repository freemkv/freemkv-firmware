//! egui shell — draws `ui::App::view()` and forwards input to `App::dispatch`.
//!
//! The fallback for every OS without a native shell yet. It decides nothing: enabled states,
//! wording, grouping and gates all come from the view. Layout (sizes, columns) is its own.

use std::sync::Arc;

use eframe::egui;

use crate::ui::{
    AnalysisView, Button, ButtonStyle, Card, CardBody, Confirm, Diagnostics, Effect, Input, Item,
    MediaRow, Node, NodeKind, Results, Status, Task, Tri, View,
};

const CAUTION: egui::Color32 = egui::Color32::from_rgb(160, 70, 0);
const DANGER: egui::Color32 = egui::Color32::from_rgb(220, 80, 80);
const ERROR: egui::Color32 = egui::Color32::from_rgb(160, 45, 35);

/// Run the egui window until it closes.
pub fn run() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title(format!(
            "freemkv Firmware Utility {}",
            env!("CARGO_PKG_VERSION")
        ))
        .with_inner_size([900.0, 760.0])
        .with_min_inner_size([720.0, 610.0])
        .with_resizable(true);
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(Arc::new(icon));
    }
    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "freemkv-flash",
        native_options,
        Box::new(|cc| {
            configure_style(&cc.egui_ctx);
            Ok(Box::new(Shell::new(crate::ui::App::new(), &cc.egui_ctx)))
        }),
    )
}

/// Decode the bundled freemkv PNG into an egui window icon.
fn load_icon() -> Option<egui::IconData> {
    let bytes = include_bytes!("../assets/freemkv.png");
    let img = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

/// One shared appearance on every OS; tests use this same setup.
pub(crate) fn configure_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Light);
    ctx.style_mut_of(egui::Theme::Light, |style| {
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    });
}

/// The shell: the model plus nothing it could disagree with.
pub struct Shell {
    pub(crate) app: crate::ui::App,
}

impl Shell {
    pub fn new(mut app: crate::ui::App, ctx: &egui::Context) -> Self {
        let waker = ctx.clone();
        app.set_waker(Arc::new(move || waker.request_repaint()));
        let effects = app.start();
        let mut shell = Self { app };
        shell.perform(ctx, effects);
        shell
    }

    fn send(&mut self, ctx: &egui::Context, input: Input) {
        let effects = self.app.dispatch(input);
        self.perform(ctx, effects);
    }

    fn perform(&mut self, ctx: &egui::Context, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::OpenFile { pick, filter } => {
                    let mut dialog = rfd::FileDialog::new();
                    if let Some(f) = filter {
                        dialog = dialog.add_filter(f.name, f.extensions);
                    }
                    if let Some(path) = dialog.pick_file() {
                        self.send(ctx, Input::Chosen(pick, path));
                    }
                }
                Effect::SaveFile { pick, file_name } => {
                    if let Some(path) = rfd::FileDialog::new().set_file_name(file_name).save_file()
                    {
                        self.send(ctx, Input::Chosen(pick, path));
                    }
                }
                Effect::CopyText(text) => ctx.copy_text(text),
                // egui repaints on the worker's waker and on the running-job timer below.
                Effect::StartTicking | Effect::StopTicking => {}
            }
        }
    }

    pub(crate) fn render(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let effects = self.app.poll();
        self.perform(&ctx, effects);
        let view = self.app.view();
        if !view.can_close && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        if view.status.as_ref().is_some_and(|s| s.running) || !view.can_close {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        let mut out = Vec::new();
        main_panel(ui, &view, &mut out);
        if let Some(confirm) = &view.confirm {
            confirm_window(&ctx, confirm, &mut out);
        }
        if let Some(diag) = &view.diagnostics {
            diagnostics_window(&ctx, diag, &mut out);
        }
        if let Some(window) = &view.analysis {
            analysis_window(&ctx, &window.tree, window.notice.as_deref(), &mut out);
        }
        for input in out {
            self.send(&ctx, input);
        }
    }
}

impl eframe::App for Shell {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

fn main_panel(ui: &mut egui::Ui, view: &View, out: &mut Vec<Input>) {
    egui::Frame::new().inner_margin(16.0).show(ui, |ui| {
        ui.set_max_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.heading("freemkv");
            ui.label("Firmware Utility");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(env!("CARGO_PKG_VERSION"));
            });
        });
        ui.add_space(18.0);
        // The diagnostics window overlays the main panel, so it is modal here.
        let enabled = view.controls_enabled && view.diagnostics.is_none();
        ui.add_enabled_ui(enabled, |ui| {
            drive_bar(ui, view, out);
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                for tab in &view.tabs {
                    let r = ui.add_enabled(
                        tab.enabled,
                        egui::Button::selectable(view.task == tab.task, tab.title),
                    );
                    if r.clicked() && view.task != tab.task {
                        out.push(Input::SelectTask(tab.task));
                    }
                }
            });
            ui.separator();
            ui.add_space(6.0);
            let (max, min) = match view.task {
                Task::Info => (60.0, 60.0),
                Task::Inspect | Task::Compare => (180.0, 0.0),
                Task::Backup | Task::Dump => (110.0, 110.0),
                Task::Flash => (200.0, 200.0),
                Task::Recovery => (280.0, 280.0),
            };
            egui::ScrollArea::vertical()
                .id_salt(("task_content", view.task as u8))
                .max_height(max)
                .min_scrolled_height(min)
                .auto_shrink([false, matches!(view.task, Task::Inspect | Task::Compare)])
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    for item in &view.panel {
                        panel_item(ui, item, out);
                    }
                });
        });
        let (Some(status), Some(results)) = (&view.status, &view.results) else {
            return;
        };
        ui.add_space(8.0);
        ui.separator();
        status_ui(ui, status, out);
        egui::ScrollArea::vertical()
            .id_salt("result_panel")
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .max_height(ui.available_height().max(1.0))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                results_ui(ui, results, out);
                egui::CollapsingHeader::new(crate::ui::LOG_TITLE)
                    .default_open(false)
                    .show(ui, |ui| {
                        for line in &view.log {
                            ui.add(egui::Label::new(egui::RichText::new(line).small()).wrap());
                        }
                    });
            });
    });
}

fn drive_bar(ui: &mut egui::Ui, view: &View, out: &mut Vec<Input>) {
    let bar = &view.drives;
    egui::Frame::group(ui.style())
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.label(egui::RichText::new(bar.label).strong());
            ui.horizontal(|ui| {
                let shown = bar
                    .selected
                    .and_then(|i| bar.items.get(i))
                    .map_or(bar.placeholder, |d| d.text.as_str());
                egui::ComboBox::from_id_salt("device_combo")
                    .selected_text(shown)
                    .width((ui.available_width() - 88.0).max(180.0))
                    .show_ui(ui, |ui| {
                        for (i, drive) in bar.items.iter().enumerate() {
                            let r = ui
                                .selectable_label(bar.selected == Some(i), &drive.text)
                                .on_hover_text(&drive.tooltip);
                            if r.clicked() && bar.selected != Some(i) {
                                out.push(Input::SelectDrive(i));
                            }
                        }
                    });
                button(ui, &bar.refresh, out);
            });
            if !bar.chips.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for chip in &bar.chips {
                        egui::Frame::new()
                            .fill(ui.visuals().faint_bg_color)
                            .corner_radius(8.0)
                            .inner_margin(egui::Margin::symmetric(8, 2))
                            .show(ui, |ui| ui.small(chip));
                    }
                });
            }
        });
}

fn button(ui: &mut egui::Ui, b: &Button, out: &mut Vec<Input>) {
    let clicked = match b.style {
        ButtonStyle::Primary => ui
            .add_enabled(
                b.enabled,
                egui::Button::new(egui::RichText::new(&b.text).color(egui::Color32::WHITE))
                    .fill(egui::Color32::from_rgb(30, 95, 165))
                    .min_size(egui::vec2(170.0, 34.0)),
            )
            .clicked(),
        ButtonStyle::Normal => ui
            .add_enabled(b.enabled, egui::Button::new(&b.text))
            .clicked(),
        ButtonStyle::Link => ui
            .add_enabled(b.enabled, egui::Link::new(&b.text))
            .clicked(),
    };
    if clicked {
        out.push(b.input.clone());
    }
}

fn panel_item(ui: &mut egui::Ui, item: &Item, out: &mut Vec<Input>) {
    match item {
        Item::Text(t) => {
            ui.label(t);
        }
        Item::Heading(t) => {
            ui.label(egui::RichText::new(t).strong());
        }
        Item::Note(t) => {
            ui.small(t);
        }
        Item::Warning(t) => {
            ui.colored_label(CAUTION, t);
        }
        Item::Check {
            id,
            text,
            checked,
            enabled,
        } => {
            let mut on = *checked;
            if ui
                .add_enabled(*enabled, egui::Checkbox::new(&mut on, text))
                .changed()
            {
                out.push(Input::SetCheck(*id, on));
            }
        }
        Item::Path { button: b, path } => {
            ui.horizontal(|ui| {
                button(ui, b, out);
                if let Some(p) = path {
                    ui.add(egui::Label::new(&p.name).truncate())
                        .on_hover_text(&p.full);
                }
            });
        }
        Item::Buttons { label, buttons } => {
            ui.horizontal(|ui| {
                if let Some(l) = label {
                    ui.label(l);
                }
                for b in buttons {
                    button(ui, b, out);
                }
            });
        }
    }
}

fn status_ui(ui: &mut egui::Ui, status: &Status, out: &mut Vec<Input>) {
    ui.horizontal(|ui| {
        if status.running {
            ui.spinner();
        }
        ui.label(egui::RichText::new(&status.text).strong());
    });
    if let Some(cancel) = &status.cancel {
        button(ui, cancel, out);
    }
    if let Some(p) = &status.progress {
        match p.fraction {
            Some(f) => {
                ui.label(&p.label);
                ui.add(egui::ProgressBar::new(f).show_percentage());
            }
            None => {
                ui.add(egui::ProgressBar::new(0.0).animate(true).text(&p.label));
            }
        }
    }
    if let Some(note) = status.note {
        ui.small(note);
    }
}

fn results_ui(ui: &mut egui::Ui, results: &Results, out: &mut Vec<Input>) {
    if let Some(open) = &results.open_results {
        button(ui, open, out);
    }
    if !results.cards.is_empty() {
        info_cards(ui, &results.cards);
    } else if !results.fields.is_empty() {
        egui::Grid::new("operation_results")
            .num_columns(2)
            .spacing([24.0, 8.0])
            .max_col_width((ui.available_width() - 24.0) / 2.0)
            .show(ui, |ui| {
                for (label, value) in &results.fields {
                    ui.label(label);
                    ui.add(egui::Label::new(value).wrap());
                    ui.end_row();
                }
            });
    }
    if let Some(failure) = &results.failure {
        ui.colored_label(ERROR, &failure.text);
        button(ui, &failure.save_log, out);
    }
    if let Some(notice) = &results.notice {
        ui.label(notice);
    }
    ui.add_space(6.0);
    button(ui, &results.view_log, out);
}

// ── drive information cards ───────────────────────────────────────────────

pub(crate) fn info_cards(ui: &mut egui::Ui, cards: &[Card]) {
    if ui.available_width() >= 760.0 {
        ui.columns(2, |cols| {
            for card in cards {
                card_ui(&mut cols[card.column.min(1)], card);
            }
        });
    } else {
        for card in cards {
            card_ui(ui, card);
        }
    }
}

fn card_ui(ui: &mut egui::Ui, card: &Card) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.visuals_mut().disabled_alpha = 0.8;
        ui.strong(card.title);
        if let Some(sub) = card.subtitle {
            ui.small(sub);
        }
        match &card.body {
            CardBody::Rows(rows) => {
                ui.add_space(8.0);
                egui::Grid::new(("drive_information", card.title))
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .max_col_width((ui.available_width() - 16.0) / 2.0)
                    .show(ui, |ui| {
                        for (label, value) in rows {
                            ui.label(label);
                            ui.add(egui::Label::new(value).wrap().selectable(true));
                            ui.end_row();
                        }
                    });
            }
            CardBody::Media { left, right } => {
                ui.add_space(8.0);
                if ui.available_width() >= 350.0 && !left.is_empty() && !right.is_empty() {
                    ui.columns(2, |cols| {
                        media_column(&mut cols[0], left.iter(), 0);
                        media_column(&mut cols[1], right.iter(), 1);
                    });
                } else {
                    media_column(ui, left.iter().chain(right), 0);
                }
            }
        }
    });
    ui.add_space(8.0);
}

fn media_column<'a>(ui: &mut egui::Ui, rows: impl Iterator<Item = &'a MediaRow>, id: usize) {
    egui::Grid::new(("media_capabilities", id))
        .num_columns(2)
        .spacing([8.0, 2.0])
        .show(ui, |ui| {
            ui.label("");
            ui.strong(crate::ui::MEDIA_HEADER)
                .on_hover_text(crate::ui::MEDIA_HINT);
            ui.end_row();
            for row in rows {
                ui.label(&row.label);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 1.0;
                    tick(ui, row.read);
                    if let Some(w) = row.write {
                        tick(ui, w);
                    }
                });
                ui.end_row();
            }
        });
}

fn tick(ui: &mut egui::Ui, state: Tri) {
    match state {
        Tri::Yes | Tri::No => {
            let mut checked = state == Tri::Yes;
            ui.add_enabled(false, egui::Checkbox::without_text(&mut checked));
        }
        Tri::Unknown => {
            let s = ui.spacing().interact_size.y;
            ui.allocate_space(egui::vec2(s, s));
        }
    }
}

// ── windows ───────────────────────────────────────────────────────────────

fn confirm_window(ctx: &egui::Context, c: &Confirm, out: &mut Vec<Input>) {
    let mut open = true;
    egui::Window::new(c.title)
        .default_width(480.0)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .open(&mut open)
        .show(ctx, |ui| {
            let (drive_image, current) = c.details.split_at(c.details.len().min(2));
            for line in drive_image {
                ui.label(line);
            }
            ui.colored_label(DANGER, c.danger);
            for line in current {
                ui.label(line);
            }
            if let Some(w) = c.warning {
                ui.colored_label(CAUTION, w);
            }
            if let Some(n) = c.note {
                ui.label(n);
            }
            ui.add_space(12.0);
            let mut ack = c.ack_checked;
            if ui.checkbox(&mut ack, c.ack_text).changed() {
                out.push(Input::SetCheck(crate::ui::CheckId::RiskAck, ack));
            }
            ui.horizontal(|ui| {
                button(ui, &c.cancel, out);
                let b = Button {
                    style: ButtonStyle::Normal,
                    ..c.confirm.clone()
                };
                button(ui, &b, out);
            });
        });
    if !open {
        out.push(Input::CancelConfirm);
    }
}

fn diagnostics_window(ctx: &egui::Context, d: &Diagnostics, out: &mut Vec<Input>) {
    let mut open = true;
    egui::Window::new(d.title)
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .fixed_size(egui::vec2(620.0, 400.0))
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                for b in &d.buttons {
                    button(ui, b, out);
                }
            });
            ui.label(d.hint);
            if let Some(path) = &d.path {
                ui.add(
                    egui::Label::new(egui::RichText::new(path).small())
                        .wrap()
                        .selectable(true),
                );
            }
            if let Some(notice) = &d.notice {
                ui.label(notice);
            }
            ui.separator();
            egui::ScrollArea::both()
                .id_salt("diagnostic_text")
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .max_height(310.0)
                .auto_shrink([false, false])
                .show_rows(ui, 14.0, d.lines.len(), |ui, rows| {
                    for line in &d.lines[rows] {
                        ui.add(
                            egui::Label::new(egui::RichText::new(line).monospace().size(12.0))
                                .extend(),
                        );
                    }
                });
        });
    if !open {
        out.push(Input::CloseDiagnostics);
    }
}

fn analysis_window(
    ctx: &egui::Context,
    tree: &AnalysisView,
    notice: Option<&str>,
    out: &mut Vec<Input>,
) {
    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("firmware_analysis_results"),
        egui::ViewportBuilder::default()
            .with_title(tree.title)
            .with_inner_size([1100.0, 800.0])
            .with_min_inner_size([720.0, 500.0]),
        |ctx, _| {
            if ctx.input(|i| i.viewport().close_requested()) {
                out.push(Input::CloseResults);
            }
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("analysis_window_content")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            for b in &tree.actions {
                                button(ui, b, out);
                            }
                        });
                        if let Some(n) = notice {
                            ui.label(n);
                        }
                        ui.heading(&tree.heading);
                        nodes_ui(ui, &tree.nodes, out);
                    });
            });
        },
    );
}

fn nodes_ui(ui: &mut egui::Ui, nodes: &[Node], out: &mut Vec<Input>) {
    let mut i = 0;
    while i < nodes.len() {
        // Consecutive fields share one aligned grid.
        let run = nodes[i..]
            .iter()
            .take_while(|n| matches!(n.kind, NodeKind::Field { .. }))
            .count();
        if run > 0 {
            egui::Grid::new(ui.next_auto_id())
                .num_columns(2)
                .spacing([24.0, 8.0])
                .max_col_width((ui.available_width() - 180.0).max(120.0))
                .show(ui, |ui| {
                    for n in &nodes[i..i + run] {
                        if let NodeKind::Field { label, value } = &n.kind {
                            ui.strong(label);
                            ui.add(egui::Label::new(value).wrap());
                            ui.end_row();
                        }
                    }
                });
            i += run;
            continue;
        }
        let node = &nodes[i];
        ui.push_id(i, |ui| node_ui(ui, node, out));
        i += 1;
    }
}

fn node_ui(ui: &mut egui::Ui, node: &Node, out: &mut Vec<Input>) {
    match &node.kind {
        NodeKind::Section(name) => {
            egui::CollapsingHeader::new(name)
                .default_open(node.open)
                .show(ui, |ui| {
                    let mono = node
                        .children
                        .iter()
                        .all(|c| matches!(c.kind, NodeKind::Mono(_)));
                    if mono && !node.children.is_empty() {
                        let h = ui.text_style_height(&egui::TextStyle::Body);
                        egui::ScrollArea::vertical().max_height(240.0).show_rows(
                            ui,
                            h,
                            node.children.len(),
                            |ui, range| {
                                for c in &node.children[range] {
                                    if let NodeKind::Mono(t) = &c.kind {
                                        ui.monospace(t);
                                    }
                                }
                            },
                        );
                    } else {
                        nodes_ui(ui, &node.children, out);
                    }
                });
        }
        NodeKind::Field { .. } => nodes_ui(ui, std::slice::from_ref(node), out),
        NodeKind::Text(t) => {
            ui.label(t);
        }
        NodeKind::Note(t) => {
            ui.small(t);
        }
        NodeKind::Mono(t) => {
            ui.monospace(t);
        }
        NodeKind::Buttons(buttons) => {
            ui.horizontal(|ui| {
                for b in buttons {
                    button(ui, b, out);
                }
            });
        }
        NodeKind::Table { header, rows } => {
            egui::Grid::new(ui.next_auto_id())
                .num_columns(header.len())
                .spacing([24.0, 8.0])
                .show(ui, |ui| {
                    for h in header {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for row in rows {
                        for cell in row {
                            ui.label(cell);
                        }
                        ui.end_row();
                    }
                });
        }
    }
}

#[cfg(test)]
#[path = "egui_shell_tests.rs"]
mod tests;
