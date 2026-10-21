//! Widget builders for the GTK shell: labels, text panes, the extra windows, the drive
//! information cards and the analysis tree. Each draws a piece of the view as given.

use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::ui::{self, ButtonStyle, Card, CardBody, MediaRow, Node, NodeKind, Tri};

/// A left-aligned, wrapping label with libadwaita style classes.
pub fn label(text: &str, classes: &[&str]) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.set_wrap(true);
    l.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    l.set_xalign(0.0);
    l.set_halign(gtk::Align::Fill);
    for c in classes {
        l.add_css_class(c);
    }
    l
}

/// A read-only monospace text view in a scrolled window, for logs.
pub fn text_pane() -> (gtk::ScrolledWindow, gtk::TextView) {
    let tv = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::None)
        .build();
    let scroll = gtk::ScrolledWindow::builder().child(&tv).build();
    scroll.add_css_class("card");
    (scroll, tv)
}

/// Replace a text view's contents and scroll to the end.
pub fn set_text(tv: &gtk::TextView, text: &str) {
    let buf = tv.buffer();
    buf.set_text(text);
    let mark = buf.create_mark(None, &buf.end_iter(), false);
    tv.scroll_mark_onscreen(&mark);
    buf.delete_mark(&mark);
}

pub fn clear(b: &gtk::Box) {
    while let Some(child) = b.first_child() {
        b.remove(&child);
    }
}

/// Show a model button's text, enabled state and style on a GTK button.
pub fn bind(btn: &gtk::Button, b: &ui::Button) {
    btn.set_label(&b.text);
    btn.set_sensitive(b.enabled);
    for (style, class) in [
        (ButtonStyle::Primary, "suggested-action"),
        (ButtonStyle::Link, "flat"),
    ] {
        if b.style == style {
            btn.add_css_class(class);
        } else {
            btn.remove_css_class(class);
        }
    }
}

/// A secondary window (diagnostics, analysis): header bar, then a padded vertical box.
/// Closing hides it, so the shell can show it again when the model asks.
pub fn window(
    parent: &adw::ApplicationWindow,
    w: i32,
    h: i32,
) -> (adw::Window, adw::WindowTitle, gtk::Box) {
    let window = adw::Window::builder()
        .transient_for(parent)
        .default_width(w)
        .default_height(h)
        .hide_on_close(true)
        .build();
    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    let title = adw::WindowTitle::new("", "");
    header.set_title_widget(Some(&title));
    toolbar.add_top_bar(&header);
    let root = gtk::Box::new(gtk::Orientation::Vertical, 8);
    root.set_margin_top(12);
    root.set_margin_bottom(16);
    root.set_margin_start(16);
    root.set_margin_end(16);
    toolbar.set_content(Some(&root));
    window.set_content(Some(&toolbar));
    (window, title, root)
}

/// A libadwaita property row: the label small above the value, the value selectable.
fn property(label: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(label)
        .subtitle(value)
        .use_markup(false)
        .subtitle_selectable(true)
        .build();
    row.add_css_class("property");
    row
}

/// The drive information cards in their two columns.
pub fn cards(cards: &[Card], language: crate::localization::Language) -> gtk::Widget {
    let cols = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    cols.set_homogeneous(true);
    let columns = [
        gtk::Box::new(gtk::Orientation::Vertical, 12),
        gtk::Box::new(gtk::Orientation::Vertical, 12),
    ];
    for card in cards {
        columns[card.column.min(1)].append(&card_group(card, language));
    }
    for c in &columns {
        c.set_valign(gtk::Align::Start);
        cols.append(c);
    }
    cols.upcast()
}

fn card_group(card: &Card, language: crate::localization::Language) -> adw::PreferencesGroup {
    let g = adw::PreferencesGroup::builder().title(&card.title).build();
    if let Some(sub) = card.subtitle.as_deref() {
        g.set_description(Some(sub));
    }
    match &card.body {
        CardBody::Rows(rows) => {
            for (l, v) in rows {
                g.add(&property(l, v));
            }
        }
        CardBody::Media { left, right } => {
            let header = gtk::Label::new(Some(crate::localization::get(language, "media.header")));
            header.add_css_class("caption-heading");
            header.set_tooltip_text(Some(crate::localization::get(language, "media.hint")));
            g.set_header_suffix(Some(&header));
            for r in left.iter().chain(right) {
                g.add(&media_row(r));
            }
        }
    }
    g
}

/// Read-only ticks never change, so a tick is an insensitive check button; a capability
/// the drive did not report is an empty slot of the same width.
fn tick(text: Option<&str>, state: Tri) -> gtk::Widget {
    match state {
        Tri::Unknown => {
            let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
            spacer.set_width_request(20);
            spacer.upcast()
        }
        Tri::Yes | Tri::No => {
            let c = gtk::CheckButton::new();
            if let Some(t) = text {
                c.set_label(Some(t));
            }
            c.set_active(state == Tri::Yes);
            c.set_sensitive(false);
            c.set_valign(gtk::Align::Center);
            c.upcast()
        }
    }
}

fn media_row(r: &MediaRow) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(r.label.as_str())
        .use_markup(false)
        .build();
    row.add_suffix(&tick(None, r.read));
    if let Some(wr) = r.write {
        row.add_suffix(&tick(None, wr));
    }
    row
}

/// Any other operation's labelled results, as one group of property rows.
pub fn fields(fields: &[(String, String)]) -> gtk::Widget {
    let g = adw::PreferencesGroup::new();
    for (l, v) in fields {
        g.add(&property(l, v));
    }
    g.upcast()
}

/// Append the analysis tree under `parent`: sections as expanders, consecutive fields in one
/// aligned grid, a run of monospace records as one text view. `top` skips the top-level
/// button rows, which the window shows with its actions.
pub fn nodes(
    parent: &gtk::Box,
    list: &[Node],
    button: &dyn Fn(&ui::Button) -> gtk::Button,
    top: bool,
) {
    let mut i = 0;
    while i < list.len() {
        let run = list[i..]
            .iter()
            .take_while(|n| matches!(n.kind, NodeKind::Field { .. }))
            .count();
        if run > 0 {
            let grid = gtk::Grid::builder()
                .column_spacing(24)
                .row_spacing(6)
                .build();
            for (r, n) in list[i..i + run].iter().enumerate() {
                if let NodeKind::Field { label: l, value } = &n.kind {
                    let name = gtk::Label::new(Some(l));
                    name.set_xalign(0.0);
                    name.set_valign(gtk::Align::Start);
                    name.add_css_class("heading");
                    let v = label(value, &[]);
                    v.set_selectable(true);
                    v.set_hexpand(true);
                    grid.attach(&name, 0, r as i32, 1, 1);
                    grid.attach(&v, 1, r as i32, 1, 1);
                }
            }
            parent.append(&grid);
            i += run;
            continue;
        }
        let n = &list[i];
        i += 1;
        match &n.kind {
            NodeKind::Section(name) => {
                let inner = gtk::Box::new(gtk::Orientation::Vertical, 6);
                inner.set_margin_start(18);
                inner.set_margin_top(4);
                let mono = !n.children.is_empty()
                    && n.children
                        .iter()
                        .all(|c| matches!(c.kind, NodeKind::Mono(_)));
                if mono {
                    let lines: Vec<&str> = n
                        .children
                        .iter()
                        .filter_map(|c| match &c.kind {
                            NodeKind::Mono(t) => Some(t.as_str()),
                            _ => None,
                        })
                        .collect();
                    let (scroll, tv) = text_pane();
                    tv.buffer().set_text(&lines.join("\n"));
                    scroll.set_min_content_height(80);
                    scroll.set_max_content_height(240);
                    scroll.set_propagate_natural_height(true);
                    inner.append(&scroll);
                } else {
                    nodes(&inner, &n.children, button, false);
                }
                let header = gtk::Label::new(Some(name));
                header.add_css_class("heading");
                let e = gtk::Expander::builder()
                    .label_widget(&header)
                    .expanded(n.open)
                    .child(&inner)
                    .build();
                parent.append(&e);
            }
            NodeKind::Field { .. } => {}
            NodeKind::Text(t) => parent.append(&label(t, &[])),
            NodeKind::Note(t) => parent.append(&label(t, &["caption", "dim-label"])),
            NodeKind::Mono(t) => parent.append(&label(t, &["monospace"])),
            NodeKind::Buttons(bs) if !top => {
                let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                for b in bs {
                    row.append(&button(b));
                }
                parent.append(&row);
            }
            NodeKind::Buttons(_) => {}
            NodeKind::Table { header, rows } => {
                let grid = gtk::Grid::builder()
                    .column_spacing(24)
                    .row_spacing(6)
                    .build();
                for (c, h) in header.iter().enumerate() {
                    let l = gtk::Label::new(Some(h));
                    l.set_xalign(0.0);
                    l.add_css_class("heading");
                    grid.attach(&l, c as i32, 0, 1, 1);
                }
                for (r, line) in rows.iter().enumerate() {
                    for (c, cell) in line.iter().enumerate() {
                        let l = gtk::Label::new(Some(cell));
                        l.set_xalign(0.0);
                        l.set_selectable(true);
                        grid.attach(&l, c as i32, r as i32 + 1, 1, 1);
                    }
                }
                parent.append(&grid);
            }
        }
    }
}
