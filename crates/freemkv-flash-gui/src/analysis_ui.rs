//! Generic Inspect and Compare views. No firmware decoding or vendor decisions.
use eframe::egui;
use freemkv_flash::inspection::{self, ComparisonReport, Control, Inspection, Source};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone)]
pub enum Request {
    Inspect(Source),
    Compare(Source, Source),
}
#[derive(Debug)]
pub enum ResultView {
    Inspect(Arc<Inspection>),
    Compare(ComparisonReport),
}
pub fn execute(request: &Request, control: &Control) -> anyhow::Result<ResultView> {
    match request {
        Request::Inspect(source) => inspection::inspect(source, control).map(ResultView::Inspect),
        Request::Compare(a, b) => inspection::compare(a, b, control).map(ResultView::Compare),
    }
}
#[derive(Default)]
pub struct Panel {
    sources: [Option<Source>; 2],
    pub result: Option<ResultView>,
    pub control: Control,
    notice: Option<String>,
    pub window_open: bool,
}
impl Panel {
    pub fn inputs(&mut self, ui: &mut egui::Ui, compare: bool, device: &str) -> Option<Request> {
        let mut changed = false;
        for i in 0..if compare { 2 } else { 1 } {
            ui.horizontal(|ui| {
                ui.label(if compare {
                    if i == 0 {
                        "Source A"
                    } else {
                        "Source B"
                    }
                } else {
                    "Source"
                });
                if ui.button("Firmware file…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Firmware", &["tar", "bin", "enc"])
                        .pick_file()
                    {
                        self.sources[i] = Some(Source::File(path));
                        changed = true;
                    }
                }
                let other_live =
                    compare && matches!(&self.sources[1 - i], Some(Source::Drive { .. }));
                if ui
                    .add_enabled(
                        !device.is_empty() && !other_live,
                        egui::Button::new("Selected drive…"),
                    )
                    .clicked()
                {
                    if let Some(capture) = rfd::FileDialog::new()
                        .set_file_name("inspection.backup.tar")
                        .save_file()
                    {
                        self.sources[i] = Some(Source::Drive {
                            device: device.into(),
                            capture,
                        });
                        changed = true;
                    }
                }
            });
            match &self.sources[i] {
                Some(Source::File(p)) => {
                    ui.small(p.display().to_string());
                }
                Some(Source::Drive { device, capture }) => {
                    ui.small(format!("{device} → capture {}", capture.display()));
                }
                Some(Source::Analyzed(a)) => {
                    ui.small(format!("Retained analysis: {}", a.source));
                }
                None => {
                    ui.small("Choose a firmware file or drive.");
                }
            }
        }
        if changed {
            self.result = None;
            self.notice = None;
        }
        let mut request = None;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.sources[0].is_some() && (!compare || self.sources[1].is_some()),
                    egui::Button::new(if compare { "Compare" } else { "Inspect" }),
                )
                .clicked()
            {
                self.control = Control::default();
                self.result = None;
                self.notice = None;
                request = Some(if compare {
                    Request::Compare(
                        self.sources[0].clone().unwrap(),
                        self.sources[1].clone().unwrap(),
                    )
                } else {
                    Request::Inspect(self.sources[0].clone().unwrap())
                });
            }
        });
        request
    }
    /// Return true to switch to Inspect, false to switch to Compare.
    pub fn results(&mut self, ui: &mut egui::Ui) -> Option<bool> {
        self.result.as_ref()?;
        if ui.button("Open results…").clicked() {
            self.window_open = true;
        }
        if !self.window_open {
            return None;
        }
        let mut navigate = None;
        let ctx = ui.ctx().clone();
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("firmware_analysis_results"),
            egui::ViewportBuilder::default()
                .with_title("Firmware analysis")
                .with_inner_size([1100.0, 800.0])
                .with_min_inner_size([720.0, 500.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.window_open = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("analysis_window_content")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            navigate = self.render_results(ui);
                        });
                });
            },
        );
        navigate
    }

    fn render_results(&mut self, ui: &mut egui::Ui) -> Option<bool> {
        let mut navigate = None;
        let Some(result) = &self.result else {
            return None;
        };
        let text = || match result {
            ResultView::Inspect(r) => r.text(),
            ResultView::Compare(r) => r.text(),
        };
        let json = || match result {
            ResultView::Inspect(r) => r.json(),
            ResultView::Compare(r) => r.json(),
        };
        ui.horizontal(|ui| {
            if ui.button("Copy report").clicked() {
                ui.ctx().copy_text(text());
            }
            if ui.button("Save text…").clicked() {
                self.notice = save("firmware-report.txt", Ok(text()));
            }
            if ui.button("Save JSON…").clicked() {
                self.notice = save("firmware-report.json", json());
            }
        });
        if let Some(notice) = &self.notice {
            ui.label(notice);
        }
        match result {
            ResultView::Inspect(report) => {
                ui.heading(format!(
                    "Hardware family: {}",
                    report.family.as_ref().map_or("Unknown", |f| f.id.as_str())
                ));
                ui.label(&report.source);
                if let Some(live) = &report.live {
                    ui.label(format!(
                        "Drive state captured at {} (Unix seconds)",
                        live.captured_at
                    ));
                    fields(ui, &live.fields);
                    for d in &live.diagnostics {
                        ui.label(d);
                    }
                } else {
                    ui.small("DVD region and change counters are available only from a live drive capture.");
                }
                for name in &report.missing_components {
                    ui.horizontal(|ui| {
                        ui.strong(format!("{name}:"));
                        ui.label("Not included in this source.");
                    });
                }
                for (ci, c) in report.components.iter().enumerate() {
                    ui.push_id(ci, |ui| {
                        egui::CollapsingHeader::new(&c.name)
                            .default_open(true)
                            .show(ui, |ui| {
                                fields(ui, &c.fields);
                                for d in &c.diagnostics {
                                    if !d.contains("pioneer.analysis.semantic_coverage") {
                                        ui.label(d);
                                    }
                                }
                                for r in &c.regions {
                                    egui::CollapsingHeader::new(&r.name).id_salt(r.id).show(
                                        ui,
                                        |ui| {
                                            fields(ui, &r.fields);
                                            for (ti, t) in r.tables.iter().enumerate() {
                                                ui.push_id(ti, |ui| {
                                                    egui::CollapsingHeader::new(format!(
                                                        "{} — {} records",
                                                        t.format,
                                                        t.records.len()
                                                    ))
                                                    .show(ui, |ui| {
                                                        let records = &t.records;
                                                        egui::ScrollArea::vertical()
                                                            .max_height(240.0)
                                                            .show_rows(
                                                                ui,
                                                                ui.text_style_height(
                                                                    &egui::TextStyle::Body,
                                                                ),
                                                                records.len(),
                                                                |ui, range| {
                                                                    for index in range {
                                                                        let record =
                                                                            &records[index];
                                                                        ui.monospace(format!(
                                                                            "{} @ {:#x}: {}",
                                                                            record.index,
                                                                            record.range.start,
                                                                            record
                                                                                .fields
                                                                                .iter()
                                                                                .map(|f| format!(
                                                                                    "{}: {}",
                                                                                    f.label,
                                                                                    f.value
                                                                                ))
                                                                                .collect::<Vec<_>>()
                                                                                .join("; ")
                                                                        ));
                                                                    }
                                                                },
                                                            );
                                                    });
                                                });
                                            }
                                        },
                                    );
                                }
                            });
                    });
                }
            }
            ResultView::Compare(report) => {
                ui.heading(format!("Hardware family: {:?}", report.family));
                ui.label(format!(
                    "A: {} — {}",
                    report.left.source,
                    report
                        .left_family
                        .as_ref()
                        .map_or("Unknown", |f| f.id.as_str())
                ));
                ui.label(format!(
                    "B: {} — {}",
                    report.right.source,
                    report
                        .right_family
                        .as_ref()
                        .map_or("Unknown", |f| f.id.as_str())
                ));
                let mut inspect = None;
                ui.horizontal(|ui| {
                    if ui.button("Inspect A").clicked() {
                        inspect = Some(report.left.clone());
                    }
                    if ui.button("Inspect B").clicked() {
                        inspect = Some(report.right.clone());
                    }
                });
                for (i, s) in report.sections.iter().enumerate() {
                    egui::CollapsingHeader::new(&s.name)
                        .id_salt(i)
                        .default_open(true)
                        .show(ui, |ui| {
                            for finding in &s.summary {
                                ui.label(finding);
                            }
                            egui::CollapsingHeader::new("Changes by region").default_open(true).show(ui, |ui| {
                                egui::Grid::new(("region_summary", i))
                                    .num_columns(4)
                                    .spacing([24.0, 8.0])
                                    .show(ui, |ui| {
                                        ui.strong("Region");
                                        ui.strong("Changed in A");
                                        ui.strong("Changed in B");
                                        ui.strong("Different");
                                        ui.end_row();
                                        for region in &s.regions {
                                            ui.label(&region.name);
                                            ui.label(byte_count(region.left_changed));
                                            ui.label(byte_count(region.right_changed));
                                            ui.label(if region.unresolved {
                                                "Partially compared".into()
                                            } else {
                                                region.difference_percent.map_or("Not available".into(), |p| format!("{p:.2}%"))
                                            });
                                            ui.end_row();
                                        }
                                    });
                            });
                            egui::CollapsingHeader::new("Technical details").show(ui, |ui| {
                                ui.label("Percentages use decoded and expanded bytes across both sources. Metadata and verified address relocations do not count as differences.");
                                fields(ui, &s.fields);
                                ui.label(format!(
                                    "{} address-relocation or metadata changes excluded.",
                                    s.relocations.len()
                                ));
                                egui::CollapsingHeader::new("Excluded changes").show(ui, |ui| {
                                    detail_rows(ui, "excluded", &s.relocations);
                                });
                                detail_rows(ui, "changes", &s.details);
                            });
                        });
                }
                if let Some(source) = inspect {
                    self.sources[0] = Some(Source::Analyzed(source.clone()));
                    self.result = Some(ResultView::Inspect(source));
                    navigate = Some(true);
                }
            }
        }
        navigate
    }
}
fn fields(ui: &mut egui::Ui, fields: &[inspection::Field]) {
    egui::Grid::new(ui.next_auto_id())
        .num_columns(2)
        .spacing([24.0, 8.0])
        .max_col_width((ui.available_width() - 180.0).max(120.0))
        .show(ui, |ui| {
            for f in fields {
                if matches!(f.label.as_str(), "Codec" | "Logical bytes") {
                    continue;
                }
                ui.strong(format!("{}:", f.label));
                ui.add(egui::Label::new(&f.value).wrap());
                ui.end_row();
            }
        });
}

fn save(name: &str, data: anyhow::Result<String>) -> Option<String> {
    let path: PathBuf = rfd::FileDialog::new().set_file_name(name).save_file()?;
    Some(
        match data.and_then(|data| std::fs::write(&path, data).map_err(Into::into)) {
            Ok(()) => format!("Saved {}", path.display()),
            Err(e) => format!("Could not save report: {e}"),
        },
    )
}

fn byte_count(bytes: usize) -> String {
    if bytes == 0 {
        "Unchanged".into()
    } else if bytes < 1024 {
        format!("{bytes} bytes")
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

fn detail_rows(ui: &mut egui::Ui, id: &str, rows: &[String]) {
    egui::ScrollArea::both()
        .id_salt(id)
        .max_height(500.0)
        .min_scrolled_height(250.0)
        .show_rows(
            ui,
            ui.text_style_height(&egui::TextStyle::Body),
            rows.len(),
            |ui, range| {
                for index in range {
                    ui.add(egui::Label::new(&rows[index]).extend());
                }
            },
        );
}
