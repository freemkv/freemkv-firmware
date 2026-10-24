//! macOS AppKit shell — draws `ui::App::view()` with native controls and forwards input to
//! `App::dispatch`, after freemkv's `mac.rs`.
//!
//! One window: a drive bar (popup + Refresh), a segmented task switcher, the task form, the
//! status and progress, the results (grouped cards in a scroll view) and the activity log.
//! Confirmation is an `NSAlert` sheet; diagnostics and analysis results get their own windows.
//!
//! The controller holds the model and nothing else of its own: every handler goes through
//! `send`, which dispatches, performs the returned effects and repaints. `render` is the only
//! place controls are written, and it computes nothing — it compares the new view with what
//! it last drew and rebuilds only the parts that changed.

// qa's GUI gate (`FREEMKV_FLASH_GATE`), a debug-build hook.
#[cfg(debug_assertions)]
mod gate;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly, Message};
use objc2_app_kit::{
    NSAlert, NSAlertStyle, NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate,
    NSApplicationTerminateReply, NSBackingStoreType, NSBox, NSBoxType, NSButton, NSColor,
    NSControlTextEditingDelegate, NSFont, NSFontWeightRegular, NSGridCell, NSGridView,
    NSLayoutAttribute, NSLayoutConstraintOrientation, NSLineBreakMode, NSMenu, NSMenuItem,
    NSOpenPanel, NSOutlineView, NSOutlineViewDataSource, NSOutlineViewDelegate, NSPasteboard,
    NSPasteboardTypeString, NSPopUpButton, NSProgressIndicator, NSProgressIndicatorStyle,
    NSSavePanel, NSScrollView, NSSegmentSwitchTracking, NSSegmentedControl,
    NSStackViewDistribution, NSTableColumn, NSTextField, NSTextFieldDelegate, NSTextView,
    NSUserInterfaceLayoutOrientation, NSView, NSWindow, NSWindowDelegate, NSWindowStyleMask,
    NSWindowTabbingMode,
};
use objc2_foundation::{
    MainThreadMarker, NSArray, NSEdgeInsets, NSNotification, NSNumber, NSPoint, NSRange, NSRect,
    NSSize, NSString, NSTimer,
};

use crate::ui::{
    self, AnalysisView, Button, ButtonStyle, Card, CardBody, CheckId, Confirm, Diagnostics,
    DriveItem, Effect, Input, Item, MediaRow, Node, NodeKind, Results, Status, Task, Tri, View,
};

const W: f64 = 900.0;
const H: f64 = 760.0;
const PAD: f64 = 20.0;
/// Reserved action tags for controls built once (the rest are allocated per rebuild).
const TAG_REFRESH: isize = 1;
const TAG_CANCEL: isize = 2;
const TAG_FIRST_DYNAMIC: isize = 100;
const NS_MODAL_OK: isize = 1;
const NS_ALERT_FIRST: isize = 1000;

fn ns(s: &str) -> Retained<NSString> {
    NSString::from_str(s)
}

fn rect(x: f64, y: f64, w: f64, h: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(w, h))
}

fn view_of(v: &impl AsRef<NSView>) -> Retained<NSView> {
    v.as_ref().retain()
}

fn label(mtm: MainThreadMarker, text: &str) -> Retained<NSTextField> {
    NSTextField::labelWithString(&ns(text), mtm)
}

fn wrapping(mtm: MainThreadMarker, text: &str, width: f64) -> Retained<NSTextField> {
    let l = NSTextField::wrappingLabelWithString(&ns(text), mtm);
    l.setPreferredMaxLayoutWidth(width);
    l
}

fn small(mtm: MainThreadMarker, text: &str, width: f64) -> Retained<NSTextField> {
    let l = wrapping(mtm, text, width);
    l.setFont(Some(&NSFont::systemFontOfSize(
        NSFont::smallSystemFontSize(),
    )));
    l.setTextColor(Some(&NSColor::secondaryLabelColor()));
    l
}

fn bold(mtm: MainThreadMarker, text: &str) -> Retained<NSTextField> {
    let l = label(mtm, text);
    l.setFont(Some(
        &NSFont::boldSystemFontOfSize(NSFont::systemFontSize()),
    ));
    l
}

fn mono_font() -> Retained<NSFont> {
    NSFont::monospacedSystemFontOfSize_weight(11.0, unsafe { NSFontWeightRegular })
}

fn stack(
    mtm: MainThreadMarker,
    vertical: bool,
    spacing: f64,
) -> Retained<objc2_app_kit::NSStackView> {
    let s = objc2_app_kit::NSStackView::new(mtm);
    s.setOrientation(if vertical {
        NSUserInterfaceLayoutOrientation::Vertical
    } else {
        NSUserInterfaceLayoutOrientation::Horizontal
    });
    s.setAlignment(if vertical {
        NSLayoutAttribute::Leading
    } else {
        NSLayoutAttribute::CenterY
    });
    s.setSpacing(spacing);
    s.setDetachesHiddenViews(true);
    s
}

type Stack = objc2_app_kit::NSStackView;

fn clear(s: &Stack) {
    for v in s.arrangedSubviews().iter() {
        s.removeArrangedSubview(&v);
        v.removeFromSuperview();
    }
}

/// Make `child` (arranged in `parent`) span the parent's width less `inset`.
fn fill(parent: &NSView, child: &NSView, inset: f64) {
    child
        .widthAnchor()
        .constraintEqualToAnchor_constant(&parent.widthAnchor(), -inset)
        .setActive(true);
}

/// Pin `child` to all edges of `parent`, inset by `m`.
fn pin(parent: &NSView, child: &NSView, m: f64) {
    child.setTranslatesAutoresizingMaskIntoConstraints(false);
    child
        .leadingAnchor()
        .constraintEqualToAnchor_constant(&parent.leadingAnchor(), m)
        .setActive(true);
    child
        .trailingAnchor()
        .constraintEqualToAnchor_constant(&parent.trailingAnchor(), -m)
        .setActive(true);
    child
        .topAnchor()
        .constraintEqualToAnchor_constant(&parent.topAnchor(), m)
        .setActive(true);
    child
        .bottomAnchor()
        .constraintEqualToAnchor_constant(&parent.bottomAnchor(), -m)
        .setActive(true);
}

fn new_window(mtm: MainThreadMarker, title: &str, w: f64, h: f64) -> Retained<NSWindow> {
    let style = NSWindowStyleMask::Titled
        | NSWindowStyleMask::Closable
        | NSWindowStyleMask::Miniaturizable
        | NSWindowStyleMask::Resizable;
    let window = unsafe {
        NSWindow::initWithContentRect_styleMask_backing_defer(
            NSWindow::alloc(mtm),
            rect(0.0, 0.0, w, h),
            style,
            NSBackingStoreType::Buffered,
            false,
        )
    };
    // Owned through `Retained`; AppKit must not also release it on close.
    unsafe { window.setReleasedWhenClosed(false) };
    window.setTitle(&ns(title));
    window.setTabbingMode(NSWindowTabbingMode::Disallowed);
    window
}

/// A vertical scroll view whose flipped document view holds `content` from the top.
fn scrolling(mtm: MainThreadMarker, content: &NSView) -> Retained<NSScrollView> {
    let scroll = NSScrollView::new(mtm);
    scroll.setHasVerticalScroller(true);
    scroll.setDrawsBackground(false);
    let doc = FlippedView::new(mtm);
    doc.setTranslatesAutoresizingMaskIntoConstraints(false);
    scroll.setDocumentView(Some(&doc));
    let clip = scroll.contentView();
    for (a, b) in [
        (doc.leadingAnchor(), clip.leadingAnchor()),
        (doc.trailingAnchor(), clip.trailingAnchor()),
    ] {
        a.constraintEqualToAnchor(&b).setActive(true);
    }
    doc.topAnchor()
        .constraintEqualToAnchor(&clip.topAnchor())
        .setActive(true);
    doc.addSubview(content);
    pin(&doc, content, 0.0);
    scroll
}

/// A read-only text view in a scroll view, for logs.
fn text_pane(mtm: MainThreadMarker) -> (Retained<NSScrollView>, Retained<NSTextView>) {
    let scroll = NSTextView::scrollableTextView(mtm);
    let tv: Retained<NSTextView> = scroll
        .documentView()
        .and_then(|v| v.downcast::<NSTextView>().ok())
        .expect("scrollableTextView holds a text view");
    tv.setEditable(false);
    tv.setFont(Some(&mono_font()));
    (scroll, tv)
}

fn set_text(tv: &NSTextView, text: &str) {
    tv.setString(&ns(text));
    let len = tv.string().length();
    tv.scrollRangeToVisible(NSRange::new(len, 0));
}

fn tick(mtm: MainThreadMarker, state: Tri) -> Retained<NSView> {
    match state {
        Tri::Unknown => NSGridCell::emptyContentView(mtm),
        Tri::Yes | Tri::No => {
            let b = unsafe { NSButton::checkboxWithTitle_target_action(&ns(""), None, None, mtm) };
            b.setState(isize::from(state == Tri::Yes));
            b.setEnabled(false);
            view_of(&b)
        }
    }
}

fn grid(mtm: MainThreadMarker) -> Retained<NSGridView> {
    let g = NSGridView::gridViewWithViews(&NSArray::new(), mtm);
    g.setRowSpacing(4.0);
    g.setColumnSpacing(12.0);
    g
}

fn grid_row(g: &NSGridView, views: &[Retained<NSView>]) {
    g.addRowWithViews(&NSArray::from_retained_slice(views));
}

// ── classes ───────────────────────────────────────────────────────────────

define_class!(
    // A document view that lays out from the top, as a scroll view's content should.
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[name = "FmkFlashFlippedView"]
    struct FlippedView;

    impl FlippedView {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }
    }
);

impl FlippedView {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(());
        unsafe { msg_send![super(this), init] }
    }
}

/// One flattened analysis row: two cells, a style, and its children.
#[derive(Default)]
struct TreeRow {
    item: String,
    value: String,
    strong: bool,
    mono: bool,
    open: bool,
    kids: Vec<usize>,
}

#[derive(Default)]
struct TreeIvars {
    rows: RefCell<Vec<TreeRow>>,
    roots: RefCell<Vec<usize>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "FmkFlashTreeSource"]
    #[ivars = TreeIvars]
    struct TreeSource;

    unsafe impl NSObjectProtocol for TreeSource {}

    unsafe impl NSOutlineViewDataSource for TreeSource {
        #[unsafe(method(outlineView:numberOfChildrenOfItem:))]
        fn n_children(&self, _ov: &NSOutlineView, item: Option<&AnyObject>) -> isize {
            match idx(item) {
                None => self.ivars().roots.borrow().len() as isize,
                Some(i) => self.ivars().rows.borrow()[i].kids.len() as isize,
            }
        }

        #[unsafe(method(outlineView:isItemExpandable:))]
        fn expandable(&self, _ov: &NSOutlineView, item: Option<&AnyObject>) -> bool {
            match idx(item) {
                None => true,
                Some(i) => !self.ivars().rows.borrow()[i].kids.is_empty(),
            }
        }

        #[unsafe(method_id(outlineView:child:ofItem:))]
        fn child(
            &self,
            _ov: &NSOutlineView,
            n: isize,
            item: Option<&AnyObject>,
        ) -> Retained<AnyObject> {
            let id = match idx(item) {
                None => self.ivars().roots.borrow()[n as usize],
                Some(i) => self.ivars().rows.borrow()[i].kids[n as usize],
            };
            // Small NSNumbers are tagged pointers: stable identity without retention.
            unsafe { Retained::cast_unchecked(NSNumber::new_usize(id)) }
        }
    }

    unsafe impl NSControlTextEditingDelegate for TreeSource {}

    unsafe impl NSOutlineViewDelegate for TreeSource {
        #[unsafe(method_id(outlineView:viewForTableColumn:item:))]
        fn view_for(
            &self,
            _ov: &NSOutlineView,
            col: Option<&NSTableColumn>,
            item: Option<&AnyObject>,
        ) -> Option<Retained<NSView>> {
            self.cell_for(col, item)
        }
    }
);

fn idx(item: Option<&AnyObject>) -> Option<usize> {
    let n: &NSNumber = unsafe { &*(item? as *const AnyObject as *const NSNumber) };
    Some(n.as_usize())
}

impl TreeSource {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(TreeIvars::default());
        unsafe { msg_send![super(this), init] }
    }

    /// Build one cell; outside `define_class!` so it can use `?`.
    fn cell_for(
        &self,
        col: Option<&NSTableColumn>,
        item: Option<&AnyObject>,
    ) -> Option<Retained<NSView>> {
        let mtm = MainThreadMarker::new().unwrap();
        let i = idx(item)?;
        let rows = self.ivars().rows.borrow();
        let row = rows.get(i)?;
        let value_col = col.is_some_and(|c| c.identifier().to_string() == "value");
        let text = if value_col { &row.value } else { &row.item };
        let l = label(mtm, text);
        l.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
        l.setToolTip(Some(&ns(text)));
        if row.mono {
            l.setFont(Some(&mono_font()));
        } else if row.strong && !value_col {
            l.setFont(Some(
                &NSFont::boldSystemFontOfSize(NSFont::systemFontSize()),
            ));
        }
        Some(view_of(&l))
    }

    /// Flatten the model's tree; top-level button rows are returned for the toolbar row.
    fn load(&self, nodes: &[Node]) -> Vec<Button> {
        let mut rows = Vec::new();
        let mut buttons = Vec::new();
        let mut roots = Vec::new();
        for n in nodes {
            if let NodeKind::Buttons(b) = &n.kind {
                buttons.extend(b.iter().cloned());
            } else {
                roots.extend(flatten(n, &mut rows));
            }
        }
        *self.ivars().rows.borrow_mut() = rows;
        *self.ivars().roots.borrow_mut() = roots;
        buttons
    }

    /// Expand the sections the model marks open, parents before children.
    fn expand(&self, ov: &NSOutlineView) {
        fn walk(src: &TreeSource, ov: &NSOutlineView, ids: &[usize]) {
            for &i in ids {
                let (open, kids) = {
                    let rows = src.ivars().rows.borrow();
                    (rows[i].open, rows[i].kids.clone())
                };
                if open && !kids.is_empty() {
                    let item = NSNumber::new_usize(i);
                    unsafe { ov.expandItem(Some(&item)) };
                    walk(src, ov, &kids);
                }
            }
        }
        let roots = self.ivars().roots.borrow().clone();
        walk(self, ov, &roots);
    }
}

/// Append `node` (and its subtree) to `rows`; returns the row ids it contributes at its level.
fn flatten(node: &Node, rows: &mut Vec<TreeRow>) -> Vec<usize> {
    let mut push = |row: TreeRow| {
        rows.push(row);
        vec![rows.len() - 1]
    };
    match &node.kind {
        NodeKind::Section(name) => {
            let me = rows.len();
            rows.push(TreeRow {
                item: name.clone(),
                strong: true,
                open: node.open,
                ..Default::default()
            });
            let kids: Vec<usize> = node
                .children
                .iter()
                .flat_map(|c| flatten(c, rows))
                .collect();
            rows[me].kids = kids;
            vec![me]
        }
        NodeKind::Field { label, value } => push(TreeRow {
            item: label.clone(),
            value: value.clone(),
            ..Default::default()
        }),
        NodeKind::Text(t) | NodeKind::Note(t) => push(TreeRow {
            item: t.clone(),
            ..Default::default()
        }),
        NodeKind::Mono(t) => push(TreeRow {
            item: t.clone(),
            mono: true,
            ..Default::default()
        }),
        NodeKind::Buttons(b) => push(TreeRow {
            item: b
                .iter()
                .map(|b| b.text.as_str())
                .collect::<Vec<_>>()
                .join(" · "),
            ..Default::default()
        }),
        // A table becomes one row per line: its first cell, then the rest labelled.
        NodeKind::Table {
            header,
            rows: lines,
        } => lines
            .iter()
            .map(|line| {
                let value = header
                    .iter()
                    .zip(line)
                    .skip(1)
                    .map(|(h, c)| format!("{h}: {c}"))
                    .collect::<Vec<_>>()
                    .join("   ·   ");
                rows.push(TreeRow {
                    item: line.first().cloned().unwrap_or_default(),
                    value,
                    ..Default::default()
                });
                rows.len() - 1
            })
            .collect(),
    }
}

// ── the controller ────────────────────────────────────────────────────────

#[derive(Default)]
struct Ivars {
    /// The single source of truth. The shell holds no state of its own.
    app: RefCell<Option<ui::App>>,
    window: RefCell<Option<Retained<NSWindow>>>,
    drive_label: RefCell<Option<Retained<NSTextField>>>,
    drive_popup: RefCell<Option<Retained<NSPopUpButton>>>,
    drive_chips: RefCell<Option<Retained<NSTextField>>>,
    refresh: RefCell<Option<Retained<NSButton>>>,
    tabs: RefCell<Option<Retained<NSSegmentedControl>>>,
    panel: RefCell<Option<Retained<Stack>>>,
    status_box: RefCell<Option<Retained<Stack>>>,
    status_label: RefCell<Option<Retained<NSTextField>>>,
    progress: RefCell<Option<Retained<NSProgressIndicator>>>,
    progress_label: RefCell<Option<Retained<NSTextField>>>,
    note_label: RefCell<Option<Retained<NSTextField>>>,
    cancel: RefCell<Option<Retained<NSButton>>>,
    results: RefCell<Option<Retained<Stack>>>,
    log: RefCell<Option<Retained<NSTextView>>>,
    // What each part last drew, so render rebuilds only what changed.
    drives_shown: RefCell<Option<Vec<DriveItem>>>,
    panel_shown: RefCell<Option<(Task, Vec<Item>)>>,
    results_shown: RefCell<Option<Option<Results>>>,
    log_shown: RefCell<Vec<String>>,
    language_shown: Cell<Option<crate::localization::Language>>,
    /// Button tag → the input it forwards; checkbox tag → the check it reports.
    actions: RefCell<HashMap<isize, Input>>,
    checks: RefCell<HashMap<isize, CheckId>>,
    next_tag: Cell<isize>,
    alert: RefCell<Option<Retained<NSAlert>>>,
    report_alert: RefCell<Option<Retained<NSAlert>>>,
    alert_details: RefCell<Option<(Retained<NSButton>, Retained<NSScrollView>)>>,
    alert_ack: RefCell<Option<Retained<NSButton>>>,
    alert_confirm: RefCell<Option<Retained<NSButton>>>,
    diag_win: RefCell<Option<Retained<NSWindow>>>,
    diag_text: RefCell<Option<Retained<NSTextView>>>,
    diag_buttons: RefCell<Option<Retained<Stack>>>,
    diag_hint: RefCell<Option<Retained<NSTextField>>>,
    diag_path: RefCell<Option<Retained<NSTextField>>>,
    diag_notice: RefCell<Option<Retained<NSTextField>>>,
    diag_shown: RefCell<Option<Arc<Vec<String>>>>,
    an_win: RefCell<Option<Retained<NSWindow>>>,
    an_source: RefCell<Option<Retained<TreeSource>>>,
    an_outline: RefCell<Option<Retained<NSOutlineView>>>,
    an_heading: RefCell<Option<Retained<NSTextField>>>,
    an_notice: RefCell<Option<Retained<NSTextField>>>,
    an_actions: RefCell<Option<Retained<Stack>>>,
    an_shown: RefCell<Option<Arc<AnalysisView>>>,
    timer: RefCell<Option<Retained<NSTimer>>>,
    /// The GUI gate's directory, when a debug build runs the gate.
    #[cfg(debug_assertions)]
    gate: RefCell<Option<std::path::PathBuf>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "FmkFlashController"]
    #[ivars = Ivars]
    struct Controller;

    unsafe impl NSObjectProtocol for Controller {}

    unsafe impl NSControlTextEditingDelegate for Controller {
        #[unsafe(method(controlTextDidChange:))]
        fn code_changed(&self, notification: &NSNotification) {
            if let Some(field) = notification.object().and_then(|o| o.downcast::<NSTextField>().ok()) {
                self.send(Input::FamilyOverrideCode(field.stringValue().to_string()));
            }
        }
    }
    unsafe impl NSTextFieldDelegate for Controller {}

    unsafe impl NSApplicationDelegate for Controller {
        #[unsafe(method(applicationShouldTerminate:))]
        fn should_terminate(&self, _app: &NSApplication) -> NSApplicationTerminateReply {
            if self.may_close() {
                NSApplicationTerminateReply::TerminateNow
            } else {
                NSApplicationTerminateReply::TerminateCancel
            }
        }
    }

    unsafe impl NSWindowDelegate for Controller {
        #[unsafe(method(windowShouldClose:))]
        fn window_should_close(&self, sender: &NSWindow) -> bool {
            !self.is_main(sender) || self.may_close()
        }

        #[unsafe(method(windowWillClose:))]
        fn window_will_close(&self, n: &NSNotification) {
            let Some(w) = n.object().and_then(|o| o.downcast::<NSWindow>().ok()) else {
                return;
            };
            if self.is_main(&w) {
                NSApplication::sharedApplication(self.mtm()).terminate(None);
            } else if same(&self.ivars().diag_win, &w) {
                self.send(Input::CloseDiagnostics);
            } else if same(&self.ivars().an_win, &w) {
                self.send(Input::CloseResults);
            }
        }
    }

    impl Controller {
        #[unsafe(method(onButton:))]
        fn on_button(&self, sender: Option<&AnyObject>) {
            let Some(s) = sender else { return };
            let tag: isize = unsafe { msg_send![s, tag] };
            let input = self.ivars().actions.borrow().get(&tag).cloned();
            if let Some(input) = input {
                self.send(input);
            }
        }

        #[unsafe(method(onCheck:))]
        fn on_check(&self, sender: Option<&AnyObject>) {
            let Some(s) = sender.and_then(|s| s.downcast_ref::<NSButton>()) else {
                return;
            };
            let id = self.ivars().checks.borrow().get(&s.tag()).copied();
            if let Some(id) = id {
                self.send(Input::SetCheck(id, s.state() != 0));
            }
        }

        #[unsafe(method(onDetails:))]
        fn on_details(&self, sender: Option<&AnyObject>) {
            let Some(sender) = sender.and_then(|s| s.downcast_ref::<NSButton>()) else { return };
            let details = self.ivars().alert_details.borrow().clone();
            let alert = self.ivars().alert.borrow().clone();
            let (Some((button, scroll)), Some(alert)) = (details, alert) else { return };
            // Ignore a delayed action from a dismissed sheet.
            if !std::ptr::eq(&*button, sender) { return; }
            scroll.setHidden(!scroll.isHidden());
            let title = button.title();
            button.setTitle(&button.alternateTitle());
            button.setAlternateTitle(&title);
            if let Some(accessory) = alert.accessoryView() {
                accessory.layoutSubtreeIfNeeded();
                let size = accessory.fittingSize();
                accessory.setFrame(rect(0.0, 0.0, size.width, size.height));
                alert.layout();
                if !scroll.isHidden() {
                    let clip = scroll.contentView();
                    clip.scrollToPoint(NSPoint::new(0.0, 0.0));
                    scroll.reflectScrolledClipView(&clip);
                }
            }
            // Relayout must not make the destructive action a keyboard default.
            alert.window().setDefaultButtonCell(None);
            let buttons = alert.buttons();
            buttons.objectAtIndex(0).setKeyEquivalent(&ns(""));
            buttons.objectAtIndex(1).setKeyEquivalent(&ns("\r"));
        }

        #[unsafe(method(onDrive:))]
        fn on_drive(&self, sender: Option<&AnyObject>) {
            let Some(p) = sender.and_then(|s| s.downcast_ref::<NSPopUpButton>()) else {
                return;
            };
            let i = p.indexOfSelectedItem();
            if i >= 0 && !self.ivars().drives_shown.borrow().as_ref().is_none_or(Vec::is_empty) {
                self.send(Input::SelectDrive(i as usize));
            }
        }

        #[unsafe(method(onLanguage:))]
        fn on_language(&self, sender: Option<&AnyObject>) {
            let Some(item) = sender.and_then(|s| s.downcast_ref::<NSMenuItem>()) else {
                return;
            };
            if let Some(language) = crate::localization::Language::ALL
                .get(item.tag() as usize)
                .copied()
            {
                self.send(Input::SetLanguage(language));
            }
        }

        #[unsafe(method(onTab:))]
        fn on_tab(&self, sender: Option<&AnyObject>) {
            let Some(s) = sender.and_then(|s| s.downcast_ref::<NSSegmentedControl>()) else {
                return;
            };
            if let Some(task) = usize::try_from(s.selectedSegment()).ok().and_then(|i| Task::ALL.get(i)) {
                self.send(Input::SelectTask(*task));
            }
        }

        #[unsafe(method(onTick:))]
        fn on_tick(&self, _s: Option<&AnyObject>) {
            let fx = self.with_app(|a| a.poll());
            self.perform(fx);
        }

        #[cfg(debug_assertions)]
        #[unsafe(method(onGate:))]
        fn on_gate(&self, _s: Option<&AnyObject>) {
            let dir = self.ivars().gate.borrow().clone();
            if let Some(dir) = dir {
                gate::run(self, &dir);
            }
        }
    }
);

fn same(slot: &RefCell<Option<Retained<NSWindow>>>, w: &NSWindow) -> bool {
    slot.borrow()
        .as_ref()
        .is_some_and(|x| std::ptr::eq(&**x, w))
}

impl Controller {
    fn new(mtm: MainThreadMarker, app: ui::App) -> Retained<Self> {
        let iv = Ivars {
            app: RefCell::new(Some(app)),
            next_tag: Cell::new(TAG_FIRST_DYNAMIC),
            ..Default::default()
        };
        let this = Self::alloc(mtm).set_ivars(iv);
        unsafe { msg_send![super(this), init] }
    }

    fn with_app<R>(&self, f: impl FnOnce(&mut ui::App) -> R) -> R {
        f(self.ivars().app.borrow_mut().as_mut().expect("model"))
    }

    fn view(&self) -> View {
        self.with_app(|a| a.view())
    }

    fn is_main(&self, w: &NSWindow) -> bool {
        same(&self.ivars().window, w)
    }

    /// The model decides whether closing would orphan a job; the shell only says so.
    fn may_close(&self) -> bool {
        if self.view().can_close {
            return true;
        }
        let alert = NSAlert::new(self.mtm());
        alert.setMessageText(&ns(&crate::localization::render(
            self.view().language,
            ui::CLOSE_BLOCKED,
        )));
        alert.runModal();
        false
    }

    /// The single choke-point: dispatch, perform the effects, repaint.
    fn send(&self, input: Input) {
        let fx = self.with_app(|a| a.dispatch(input));
        self.perform(fx);
    }

    fn perform(&self, effects: Vec<Effect>) {
        let mtm = self.mtm();
        for e in effects {
            match e {
                Effect::ReportPrompt {
                    summary,
                    description,
                } => {
                    self.present_report(&summary, &description);
                }
                Effect::OpenFile { pick, filter } => {
                    let panel = NSOpenPanel::openPanel(mtm);
                    panel.setCanChooseFiles(true);
                    panel.setCanChooseDirectories(false);
                    panel.setAllowsMultipleSelection(false);
                    if let Some(f) = filter.and_then(ui::FileFilter::validated) {
                        panel.setMessage(Some(&ns(f.name)));
                        let types: Vec<_> = f.extensions.iter().map(|e| ns(e)).collect();
                        // `allowedContentTypes` needs UTType; the deprecated call still filters.
                        #[allow(deprecated)]
                        panel.setAllowedFileTypes(Some(&NSArray::from_retained_slice(&types)));
                    }
                    self.run_panel(&panel, pick);
                }
                Effect::SaveFile { pick, file_name } => {
                    let panel = NSSavePanel::savePanel(mtm);
                    panel.setNameFieldStringValue(&ns(&file_name));
                    panel.setCanCreateDirectories(true);
                    self.run_panel(&panel, pick);
                }
                Effect::CopyText(text) => {
                    let pb = NSPasteboard::generalPasteboard();
                    pb.clearContents();
                    pb.setString_forType(&ns(&text), unsafe { NSPasteboardTypeString });
                }
                Effect::OpenPath(path) => {
                    if let Err(error) = crate::external::open_path(&path) {
                        self.send(Input::ShellFailed(
                            crate::ui::ShellFailure::OpenLog,
                            format!("{error:#}"),
                        ));
                    }
                }
                Effect::StartTicking => self.start_tick(),
                Effect::StopTicking => {
                    if let Some(t) = self.ivars().timer.borrow_mut().take() {
                        t.invalidate();
                    }
                }
            }
        }
        self.render();
    }

    /// Show a file panel as a sheet on the main window; a choice comes back as `Chosen`.
    fn run_panel(&self, panel: &NSSavePanel, pick: ui::Pick) {
        let Some(window) = self.ivars().window.borrow().clone() else {
            return;
        };
        let me = self.retain();
        let held = panel.retain();
        let handler = RcBlock::new(move |response: isize| {
            if response != NS_MODAL_OK {
                return;
            }
            if let Some(path) = held.URL().and_then(|u| u.path()) {
                me.send(Input::Chosen(pick, path.to_string().into()));
            } else {
                me.send(Input::DialogFailed(
                    pick,
                    "Accepted file panel returned no local path".into(),
                ));
            }
        });
        panel.beginSheetModalForWindow_completionHandler(&window, &handler);
    }

    /// A separate report sheet; the model and language are snapshotted before AppKit
    /// can process events. Its completion reads the editor once, without trimming.
    fn present_report(&self, summary: &str, description: &str) {
        let mtm = self.mtm();
        let language = self.view().language;
        let Some(window) = self.ivars().window.borrow().clone() else {
            self.send(Input::DismissReport(description.to_owned()));
            return;
        };
        let text = |id| crate::localization::get(language, id);
        let alert = NSAlert::new(mtm);
        alert.setMessageText(&ns(text("report.prompt_title")));
        alert.setInformativeText(&ns(&crate::localization::render(language, summary)));
        let send = alert.addButtonWithTitle(&ns(text("report.send")));
        send.setKeyEquivalent(&ns(""));
        alert
            .addButtonWithTitle(&ns(text("ui.cancel")))
            .setKeyEquivalent(&ns("\u{1b}"));
        let accessory = stack(mtm, true, 8.0);
        accessory.addArrangedSubview(&label(mtm, text("report.description_label")));
        let scroll = NSTextView::scrollableTextView(mtm);
        let editor = scroll
            .documentView()
            .and_then(|v| v.downcast::<NSTextView>().ok())
            .expect("scrollableTextView holds a text view");
        editor.setRichText(false);
        editor.setEditable(true);
        editor.setFont(Some(&NSFont::systemFontOfSize(NSFont::systemFontSize())));
        editor.setAutomaticQuoteSubstitutionEnabled(false);
        editor.setAutomaticDashSubstitutionEnabled(false);
        editor.setAutomaticTextReplacementEnabled(false);
        editor.setAutomaticSpellingCorrectionEnabled(false);
        editor.setString(&ns(description));
        scroll.setHasVerticalScroller(true);
        scroll
            .widthAnchor()
            .constraintEqualToConstant(420.0)
            .setActive(true);
        scroll
            .heightAnchor()
            .constraintEqualToConstant(180.0)
            .setActive(true);
        accessory.addArrangedSubview(&scroll);
        accessory.layoutSubtreeIfNeeded();
        accessory.setFrame(rect(0.0, 0.0, 420.0, accessory.fittingSize().height));
        alert.setAccessoryView(Some(&accessory));
        *self.ivars().report_alert.borrow_mut() = Some(alert.clone());
        let me = self.retain();
        let input_editor = editor.clone();
        let handler = RcBlock::new(move |response: isize| {
            if me.ivars().report_alert.borrow_mut().take().is_none() {
                return;
            }
            let description = input_editor.string().to_string();
            me.send(if response == NS_ALERT_FIRST {
                Input::SendReport(description)
            } else {
                Input::DismissReport(description)
            });
        });
        alert.beginSheetModalForWindow_completionHandler(&window, Some(&handler));
        alert.window().setDefaultButtonCell(None);
        send.setKeyEquivalent(&ns(""));
        alert.window().makeFirstResponder(Some(&editor));
    }

    fn start_tick(&self) {
        if self.ivars().timer.borrow().is_some() {
            return;
        }
        let t = unsafe {
            NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                0.2,
                self,
                sel!(onTick:),
                None,
                true,
            )
        };
        *self.ivars().timer.borrow_mut() = Some(t);
    }

    /// A tag for a control built from the view; `input` is what clicking it forwards.
    fn tag_for(&self, input: &Input) -> isize {
        let tag = self.ivars().next_tag.get();
        self.ivars().next_tag.set(tag + 1);
        self.ivars().actions.borrow_mut().insert(tag, input.clone());
        tag
    }

    fn button(&self, b: &Button) -> Retained<NSButton> {
        let mtm = self.mtm();
        let btn = unsafe {
            NSButton::buttonWithTitle_target_action(
                &ns(&b.text),
                Some(self),
                Some(sel!(onButton:)),
                mtm,
            )
        };
        btn.setTag(self.tag_for(&b.input));
        btn.setEnabled(b.enabled);
        match b.style {
            ButtonStyle::Primary if b.enabled => {
                btn.setBezelColor(Some(&NSColor::controlAccentColor()))
            }
            ButtonStyle::Primary | ButtonStyle::Normal => {}
            ButtonStyle::Link => {
                btn.setBordered(false);
                btn.setContentTintColor(Some(&NSColor::linkColor()));
            }
        }
        btn
    }

    fn checkbox(
        &self,
        id: CheckId,
        text: &str,
        checked: bool,
        enabled: bool,
    ) -> Retained<NSButton> {
        let b = unsafe {
            NSButton::checkboxWithTitle_target_action(
                &ns(text),
                Some(self),
                Some(sel!(onCheck:)),
                self.mtm(),
            )
        };
        let tag = self.ivars().next_tag.get();
        self.ivars().next_tag.set(tag + 1);
        self.ivars().checks.borrow_mut().insert(tag, id);
        b.setTag(tag);
        b.setState(isize::from(checked));
        b.setEnabled(enabled);
        b
    }

    fn button_row(&self, buttons: &[Button]) -> Retained<Stack> {
        let row = stack(self.mtm(), false, 8.0);
        for b in buttons {
            row.addArrangedSubview(&self.button(b));
        }
        row
    }

    // ── building ──────────────────────────────────────────────────────────

    fn build(&self, window: &NSWindow) {
        let mtm = self.mtm();
        let content = window.contentView().expect("content view");
        let root = stack(mtm, true, 12.0);
        root.setEdgeInsets(NSEdgeInsets {
            top: PAD,
            left: PAD,
            bottom: PAD,
            right: PAD,
        });
        content.addSubview(&root);
        pin(&content, &root, 0.0);

        // Drive bar.
        let bar = stack(mtm, false, 8.0);
        let v = self.view();
        let drive_label = label(mtm, &v.drives.label);
        bar.addArrangedSubview(&drive_label);
        let popup = NSPopUpButton::new(mtm);
        unsafe {
            popup.setTarget(Some(self));
            popup.setAction(Some(sel!(onDrive:)));
        }
        popup.setContentHuggingPriority_forOrientation(
            1.0,
            NSLayoutConstraintOrientation::Horizontal,
        );
        bar.addArrangedSubview(&popup);
        let refresh = self.button(&v.drives.refresh);
        refresh.setTag(TAG_REFRESH);
        self.ivars()
            .actions
            .borrow_mut()
            .insert(TAG_REFRESH, Input::Refresh);
        bar.addArrangedSubview(&refresh);
        root.addArrangedSubview(&bar);
        fill(&root, &bar, 2.0 * PAD);
        let chips = small(mtm, "", 600.0);
        root.addArrangedSubview(&chips);

        // Task switcher.
        let titles: Vec<_> = v.tabs.iter().map(|t| ns(&t.title)).collect();
        let tabs = unsafe {
            NSSegmentedControl::segmentedControlWithLabels_trackingMode_target_action(
                &NSArray::from_retained_slice(&titles),
                NSSegmentSwitchTracking::SelectOne,
                Some(self),
                Some(sel!(onTab:)),
                mtm,
            )
        };
        root.addArrangedSubview(&tabs);
        root.setCustomSpacing_afterView(16.0, &tabs);

        // Task form.
        let panel = stack(mtm, true, 10.0);
        root.addArrangedSubview(&panel);
        fill(&root, &panel, 2.0 * PAD);
        let sep = NSBox::new(mtm);
        sep.setBoxType(NSBoxType::Separator);
        root.addArrangedSubview(&sep);
        fill(&root, &sep, 2.0 * PAD);

        // Status and progress.
        let status = stack(mtm, true, 6.0);
        let status_label = bold(mtm, "");
        status.addArrangedSubview(&status_label);
        let progress_label = small(mtm, "", 600.0);
        status.addArrangedSubview(&progress_label);
        let progress = NSProgressIndicator::new(mtm);
        progress.setStyle(NSProgressIndicatorStyle::Bar);
        progress.setMaxValue(100.0);
        status.addArrangedSubview(&progress);
        fill(&status, &progress, 0.0);
        let note = small(mtm, "", 600.0);
        status.addArrangedSubview(&note);
        let cancel = unsafe {
            NSButton::buttonWithTitle_target_action(&ns(""), Some(self), Some(sel!(onButton:)), mtm)
        };
        cancel.setTag(TAG_CANCEL);
        status.addArrangedSubview(&cancel);
        root.addArrangedSubview(&status);
        fill(&root, &status, 2.0 * PAD);

        // Results.
        let results = stack(mtm, true, 10.0);
        let results_scroll = scrolling(mtm, &results);
        results_scroll
            .setContentHuggingPriority_forOrientation(1.0, NSLayoutConstraintOrientation::Vertical);
        results_scroll
            .heightAnchor()
            .constraintGreaterThanOrEqualToConstant(120.0)
            .setActive(true);
        root.addArrangedSubview(&results_scroll);
        fill(&root, &results_scroll, 2.0 * PAD);

        // Activity log.
        let log_title = small(
            mtm,
            &crate::localization::render(self.view().language, ui::LOG_TITLE),
            400.0,
        );
        log_title.setHidden(true);
        let (log_scroll, log) = text_pane(mtm);
        log_scroll
            .heightAnchor()
            .constraintEqualToConstant(110.0)
            .setActive(true);
        log_scroll.setHidden(true);

        let iv = self.ivars();
        *iv.drive_label.borrow_mut() = Some(drive_label);
        *iv.drive_popup.borrow_mut() = Some(popup);
        *iv.drive_chips.borrow_mut() = Some(chips);
        *iv.refresh.borrow_mut() = Some(refresh);
        *iv.tabs.borrow_mut() = Some(tabs);
        *iv.panel.borrow_mut() = Some(panel);
        *iv.status_box.borrow_mut() = Some(status);
        *iv.status_label.borrow_mut() = Some(status_label);
        *iv.progress.borrow_mut() = Some(progress);
        *iv.progress_label.borrow_mut() = Some(progress_label);
        *iv.note_label.borrow_mut() = Some(note);
        *iv.cancel.borrow_mut() = Some(cancel);
        *iv.results.borrow_mut() = Some(results);
        *iv.log.borrow_mut() = Some(log);
    }

    fn panel_item(&self, panel: &Stack, item: &Item) {
        let mtm = self.mtm();
        let width = 820.0;
        let view: Retained<NSView> = match item {
            Item::Origin(origin) => {
                let text = crate::localization::render(
                    self.ivars().app.borrow().as_ref().unwrap().language,
                    origin.label_id(),
                );
                let l = bold(mtm, &text);
                let color = match origin {
                    crate::ui::FileOrigin::OemLikely => NSColor::systemGreenColor(),
                    crate::ui::FileOrigin::UserBackupLikely => NSColor::systemOrangeColor(),
                    crate::ui::FileOrigin::Unknown => NSColor::secondaryLabelColor(),
                };
                l.setTextColor(Some(&color));
                view_of(&l)
            }
            Item::Text(t) => view_of(&wrapping(mtm, t, width)),
            Item::Heading(t) => view_of(&bold(mtm, t)),
            Item::Note(t) => view_of(&small(mtm, t, width)),
            Item::Warning(t) => {
                let l = wrapping(mtm, t, width);
                l.setTextColor(Some(&NSColor::systemOrangeColor()));
                view_of(&l)
            }
            Item::Check {
                id,
                text,
                checked,
                enabled,
            } => view_of(&self.checkbox(*id, text, *checked, *enabled)),
            Item::Path { button, path } => {
                let row = stack(mtm, false, 10.0);
                row.addArrangedSubview(&self.button(button));
                if let Some(p) = path {
                    let l = label(mtm, &p.name);
                    l.setToolTip(Some(&ns(&p.full)));
                    l.setLineBreakMode(NSLineBreakMode::ByTruncatingMiddle);
                    row.addArrangedSubview(&l);
                }
                view_of(&row)
            }
            Item::Buttons {
                label: lead,
                buttons,
            } => {
                let row = self.button_row(buttons);
                if let Some(l) = lead {
                    let l = label(mtm, l);
                    l.widthAnchor()
                        .constraintEqualToConstant(80.0)
                        .setActive(true);
                    row.insertArrangedSubview_atIndex(&l, 0);
                }
                view_of(&row)
            }
        };
        panel.addArrangedSubview(&view);
    }

    fn card(&self, card: &Card) -> Retained<NSBox> {
        let mtm = self.mtm();
        let b = NSBox::new(mtm);
        b.setTitle(&ns(&card.title));
        let inner = stack(mtm, true, 6.0);
        if let Some(sub) = &card.subtitle {
            inner.addArrangedSubview(&small(mtm, sub, 360.0));
        }
        match &card.body {
            CardBody::Rows(rows) => {
                let g = grid(mtm);
                for (l, v) in rows {
                    let name = label(mtm, l);
                    name.setTextColor(Some(&NSColor::secondaryLabelColor()));
                    let value = wrapping(mtm, v, 220.0);
                    value.setSelectable(true);
                    grid_row(&g, &[view_of(&name), view_of(&value)]);
                }
                inner.addArrangedSubview(&g);
            }
            CardBody::Media { left, right } => {
                let cols = stack(mtm, false, 24.0);
                cols.setAlignment(NSLayoutAttribute::Top);
                for side in [left, right] {
                    if !side.is_empty() {
                        cols.addArrangedSubview(&media_grid(mtm, side, self.view().language));
                    }
                }
                inner.addArrangedSubview(&cols);
            }
        }
        if let Some(cv) = b.contentView() {
            cv.addSubview(&inner);
            pin(&cv, &inner, 8.0);
        }
        b
    }

    fn fill_results(&self, results: &Stack, r: &Results) {
        let mtm = self.mtm();
        if let Some(open) = &r.open_results {
            results.addArrangedSubview(&self.button(open));
        }
        if !r.cards.is_empty() {
            let cols = stack(mtm, false, 12.0);
            cols.setAlignment(NSLayoutAttribute::Top);
            cols.setDistribution(NSStackViewDistribution::FillEqually);
            let columns = [stack(mtm, true, 12.0), stack(mtm, true, 12.0)];
            for card in &r.cards {
                let col = &columns[card.column.min(1)];
                let b = self.card(card);
                col.addArrangedSubview(&b);
                fill(col, &b, 0.0);
            }
            for col in &columns {
                cols.addArrangedSubview(col);
            }
            results.addArrangedSubview(&cols);
            fill(results, &cols, 0.0);
        } else if !r.fields.is_empty() {
            let g = grid(mtm);
            for (l, v) in &r.fields {
                let name = label(mtm, l);
                name.setTextColor(Some(&NSColor::secondaryLabelColor()));
                let value = wrapping(mtm, v, 560.0);
                value.setSelectable(true);
                grid_row(&g, &[view_of(&name), view_of(&value)]);
            }
            results.addArrangedSubview(&g);
        }
        if let Some(f) = &r.failure {
            let l = wrapping(mtm, &f.text, 820.0);
            l.setTextColor(Some(&NSColor::systemRedColor()));
            l.setSelectable(true);
            results.addArrangedSubview(&l);
        }
        if let Some(n) = &r.notice {
            results.addArrangedSubview(&small(mtm, n, 820.0));
        }
        let actions = stack(mtm, false, 8.0);
        actions.addArrangedSubview(&self.button(&r.view_log));
        if let Some(f) = &r.failure {
            actions.addArrangedSubview(&self.button(&f.save_log));
        }
        actions.addArrangedSubview(&self.button(&r.submit_report));
        results.addArrangedSubview(&actions);
    }

    // ── rendering ─────────────────────────────────────────────────────────

    /// Apply a fully-decided `View` to the widgets. The only place controls are written.
    fn render(&self) {
        let v = self.view();
        let iv = self.ivars();
        if iv.language_shown.replace(Some(v.language)) != Some(v.language) {
            *iv.drives_shown.borrow_mut() = None;
            *iv.results_shown.borrow_mut() = None;
            *iv.diag_shown.borrow_mut() = None;
            let app = NSApplication::sharedApplication(self.mtm());
            build_menus(self.mtm(), &app, self, v.language);
        }
        if let Some(w) = iv.window.borrow().as_ref() {
            w.setTitle(&ns(&v.title));
        }
        self.render_drives(&v);
        if let Some(tabs) = iv.tabs.borrow().as_ref() {
            for (i, tab) in v.tabs.iter().enumerate() {
                tabs.setLabel_forSegment(&ns(&tab.title), i as isize);
                tabs.setEnabled_forSegment(tab.enabled, i as isize);
                if tab.task == v.task {
                    tabs.setSelectedSegment(i as isize);
                }
            }
        }
        let panel_key = (v.task, v.panel.clone());
        if iv.panel_shown.borrow().as_ref() != Some(&panel_key) {
            if let Some(panel) = iv.panel.borrow().as_ref() {
                clear(panel);
                for item in &v.panel {
                    self.panel_item(panel, item);
                }
            }
            *iv.panel_shown.borrow_mut() = Some(panel_key);
        }
        self.render_status(v.status.as_ref());
        if iv.results_shown.borrow().as_ref() != Some(&v.results) {
            if let Some(results) = iv.results.borrow().as_ref() {
                clear(results);
                if let Some(r) = &v.results {
                    self.fill_results(results, r);
                }
            }
            *iv.results_shown.borrow_mut() = Some(v.results.clone());
        }
        if *iv.log_shown.borrow() != v.log {
            if let Some(tv) = iv.log.borrow().as_ref() {
                set_text(tv, &v.log.join("\n"));
            }
            *iv.log_shown.borrow_mut() = v.log.clone();
        }
        self.render_confirm(v.confirm.as_ref());
        self.render_diagnostics(v.diagnostics.as_ref());
        self.render_analysis(&v);
    }

    fn render_drives(&self, v: &View) {
        let iv = self.ivars();
        let Some(popup) = iv.drive_popup.borrow().clone() else {
            return;
        };
        let bar = &v.drives;
        if let Some(label) = iv.drive_label.borrow().as_ref() {
            label.setStringValue(&ns(&bar.label));
        }
        if let Some(chips) = iv.drive_chips.borrow().as_ref() {
            chips.setStringValue(&ns(&bar.chips.join("  ·  ")));
            chips.setHidden(bar.chips.is_empty());
        }
        if iv.drives_shown.borrow().as_ref() != Some(&bar.items) {
            // Items go in through the menu: `addItemWithTitle` would merge equal titles.
            popup.removeAllItems();
            let menu = popup.menu().expect("popup menu");
            let entries: Vec<(String, String)> = if bar.items.is_empty() {
                vec![(bar.placeholder.to_string(), String::new())]
            } else {
                bar.items
                    .iter()
                    .map(|d| (d.text.clone(), d.tooltip.clone()))
                    .collect()
            };
            for (text, tip) in entries {
                let item = unsafe {
                    NSMenuItem::initWithTitle_action_keyEquivalent(
                        NSMenuItem::alloc(self.mtm()),
                        &ns(&text),
                        None,
                        &ns(""),
                    )
                };
                if !tip.is_empty() {
                    item.setToolTip(Some(&ns(&tip)));
                }
                menu.addItem(&item);
            }
            *iv.drives_shown.borrow_mut() = Some(bar.items.clone());
        }
        popup.selectItemAtIndex(bar.selected.map_or(0, |i| i as isize));
        popup.setEnabled(v.controls_enabled && !bar.items.is_empty());
        if let Some(r) = iv.refresh.borrow().as_ref() {
            r.setTitle(&ns(&bar.refresh.text));
            r.setEnabled(bar.refresh.enabled);
        }
    }

    fn render_status(&self, status: Option<&Status>) {
        let iv = self.ivars();
        let (Some(bx), Some(text), Some(bar), Some(plabel), Some(note), Some(cancel)) = (
            iv.status_box.borrow().clone(),
            iv.status_label.borrow().clone(),
            iv.progress.borrow().clone(),
            iv.progress_label.borrow().clone(),
            iv.note_label.borrow().clone(),
            iv.cancel.borrow().clone(),
        ) else {
            return;
        };
        let Some(s) = status else {
            bx.setHidden(true);
            return;
        };
        bx.setHidden(false);
        text.setStringValue(&ns(&s.text));
        match &s.progress {
            Some(p) => {
                bar.setHidden(false);
                plabel.setHidden(false);
                plabel.setStringValue(&ns(&p.label));
                match p.fraction {
                    Some(f) => {
                        bar.setIndeterminate(false);
                        bar.setDoubleValue(f64::from(f) * 100.0);
                    }
                    None => {
                        bar.setIndeterminate(true);
                        unsafe { bar.startAnimation(None) };
                    }
                }
            }
            None => {
                unsafe { bar.stopAnimation(None) };
                bar.setHidden(true);
                plabel.setHidden(true);
            }
        }
        note.setHidden(s.note.is_none());
        note.setStringValue(&ns(s.note.as_deref().unwrap_or("")));
        match &s.cancel {
            Some(b) => {
                cancel.setHidden(false);
                cancel.setTitle(&ns(&b.text));
                cancel.setEnabled(b.enabled);
                iv.actions.borrow_mut().insert(TAG_CANCEL, b.input.clone());
            }
            None => cancel.setHidden(true),
        }
    }

    fn render_confirm(&self, confirm: Option<&Confirm>) {
        let iv = self.ivars();
        let showing = iv.alert.borrow().clone();
        match (confirm, showing) {
            (Some(c), Some(_)) => {
                if let Some(ack) = iv.alert_ack.borrow().as_ref() {
                    ack.setState(isize::from(c.ack_checked));
                }
                if let Some(b) = iv.alert_confirm.borrow().as_ref() {
                    b.setEnabled(c.confirm.enabled);
                }
            }
            (Some(c), None) => self.present_confirm(c),
            (None, Some(alert)) => {
                // The model withdrew the request; drop the sheet without answering it.
                *iv.alert.borrow_mut() = None;
                *iv.alert_details.borrow_mut() = None;
                if let Some(w) = iv.window.borrow().as_ref() {
                    w.endSheet(&alert.window());
                }
            }
            (None, None) => {}
        }
    }

    fn present_confirm(&self, c: &Confirm) {
        let mtm = self.mtm();
        let Some(window) = self.ivars().window.borrow().clone() else {
            return;
        };
        let alert = NSAlert::new(mtm);
        alert.setAlertStyle(NSAlertStyle::Critical);
        alert.setMessageText(&ns(&c.title));
        alert.setInformativeText(&ns(&c.details.join("\n")));
        let confirm = alert.addButtonWithTitle(&ns(&c.confirm.text));
        // Never on Return: the dangerous button needs a deliberate click.
        confirm.setKeyEquivalent(&ns(""));
        confirm.setEnabled(c.confirm.enabled);
        let cancel = alert.addButtonWithTitle(&ns(&c.cancel.text));
        cancel.setKeyEquivalent(&ns("\r"));

        let width = 380.0;
        let acc = stack(mtm, true, 10.0);
        let danger = wrapping(mtm, &c.danger, width);
        danger.setTextColor(Some(&NSColor::systemRedColor()));
        acc.addArrangedSubview(&danger);
        for w in &c.warnings {
            let l = wrapping(mtm, w, width);
            l.setTextColor(Some(&NSColor::systemOrangeColor()));
            acc.addArrangedSubview(&l);
        }
        if let Some(p) = &c.prompt {
            let l = wrapping(mtm, p, width);
            l.setFont(Some(
                &NSFont::boldSystemFontOfSize(NSFont::systemFontSize()),
            ));
            acc.addArrangedSubview(&l);
        }
        if let Some(n) = &c.note {
            acc.addArrangedSubview(&wrapping(mtm, n, width));
        }
        if let Some(value) = &c.code_entry {
            let entry = NSTextField::new(mtm);
            entry.setStringValue(&ns(value));
            entry.setEditable(true);
            entry.setSelectable(true);
            // The controller outlives its alert and all accessory controls.
            unsafe { entry.setDelegate(Some(ProtocolObject::from_ref(self))) };
            entry
                .widthAnchor()
                .constraintEqualToConstant(width)
                .setActive(true);
            acc.addArrangedSubview(&entry);
        }
        if !c.technical_details.is_empty() {
            let disclosure = unsafe {
                NSButton::buttonWithTitle_target_action(
                    &ns(&c.details_label),
                    Some(self),
                    Some(sel!(onDetails:)),
                    mtm,
                )
            };
            disclosure.setAlternateTitle(&ns(&c.hide_details_label));
            let text = wrapping(mtm, &c.technical_details.join("\n\n"), width - 16.0);
            text.setFont(Some(&mono_font()));
            text.setSelectable(true);
            let scroll = scrolling(mtm, &text);
            scroll
                .widthAnchor()
                .constraintEqualToConstant(width)
                .setActive(true);
            scroll
                .heightAnchor()
                .constraintEqualToConstant(160.0)
                .setActive(true);
            scroll.setHidden(true);
            acc.addArrangedSubview(&disclosure);
            acc.addArrangedSubview(&scroll);
            *self.ivars().alert_details.borrow_mut() = Some((disclosure, scroll));
        }
        let ack = self.checkbox(CheckId::RiskAck, &c.ack_text, c.ack_checked, true);
        ack.setHidden(c.ack_text.is_empty());
        acc.addArrangedSubview(&ack);
        acc.widthAnchor()
            .constraintEqualToConstant(width)
            .setActive(true);
        acc.layoutSubtreeIfNeeded();
        let size = acc.fittingSize();
        acc.setFrame(rect(0.0, 0.0, width, size.height));
        alert.setAccessoryView(Some(&acc));

        let iv = self.ivars();
        *iv.alert.borrow_mut() = Some(alert.clone());
        *iv.alert_ack.borrow_mut() = Some(ack);
        *iv.alert_confirm.borrow_mut() = Some(confirm);
        let me = self.retain();
        let handler = RcBlock::new(move |response: isize| {
            // Answer only a sheet the model still wants answered.
            if me.ivars().alert.borrow_mut().take().is_none() {
                return;
            }
            *me.ivars().alert_details.borrow_mut() = None;
            *me.ivars().alert_ack.borrow_mut() = None;
            *me.ivars().alert_confirm.borrow_mut() = None;
            me.send(if response == NS_ALERT_FIRST {
                Input::Confirm
            } else {
                Input::CancelConfirm
            });
        });
        alert.beginSheetModalForWindow_completionHandler(&window, Some(&handler));
        // AppKit assigns a default while presenting. Clear that assignment after
        // presentation so Return always selects the safe response.
        alert.window().setDefaultButtonCell(None);
        let buttons = alert.buttons();
        buttons.objectAtIndex(0).setKeyEquivalent(&ns(""));
        buttons.objectAtIndex(1).setKeyEquivalent(&ns("\r"));
    }

    fn render_diagnostics(&self, d: Option<&Diagnostics>) {
        let iv = self.ivars();
        let Some(d) = d else {
            if let Some(w) = iv.diag_win.borrow().as_ref() {
                w.orderOut(None);
            }
            *iv.diag_shown.borrow_mut() = None;
            return;
        };
        if iv.diag_win.borrow().is_none() {
            self.build_diagnostics(d);
        }
        if let Some(w) = iv.diag_win.borrow().as_ref() {
            w.setTitle(&ns(&d.title));
        }
        if let Some(hint) = iv.diag_hint.borrow().as_ref() {
            hint.setStringValue(&ns(&d.hint));
        }
        if let Some(buttons) = iv.diag_buttons.borrow().as_ref() {
            let labels: Vec<_> = buttons
                .arrangedSubviews()
                .iter()
                .filter_map(|v| v.downcast_ref::<NSButton>().map(|b| b.title().to_string()))
                .collect();
            if labels != d.buttons.iter().map(|b| b.text.clone()).collect::<Vec<_>>() {
                clear(buttons);
                for button in &d.buttons {
                    buttons.addArrangedSubview(&self.button(button));
                }
            }
        }
        if let Some(p) = iv.diag_path.borrow().as_ref() {
            p.setStringValue(&ns(d.path.as_deref().unwrap_or("")));
        }
        if let Some(n) = iv.diag_notice.borrow().as_ref() {
            n.setStringValue(&ns(d.notice.as_deref().unwrap_or("")));
            n.setHidden(d.notice.is_none());
        }
        let fresh = iv
            .diag_shown
            .borrow()
            .as_ref()
            .is_none_or(|s| !Arc::ptr_eq(s, &d.lines));
        if fresh {
            if let Some(tv) = iv.diag_text.borrow().as_ref() {
                set_text(tv, &d.lines.join("\n"));
            }
            *iv.diag_shown.borrow_mut() = Some(d.lines.clone());
            if let Some(w) = iv.diag_win.borrow().as_ref() {
                if !w.isVisible() {
                    w.center();
                    w.makeKeyAndOrderFront(None);
                }
            }
        }
    }

    fn build_diagnostics(&self, d: &Diagnostics) {
        let mtm = self.mtm();
        let w = new_window(mtm, &d.title, 680.0, 460.0);
        w.setDelegate(Some(ProtocolObject::from_ref(self)));
        let content = w.contentView().expect("content view");
        let root = stack(mtm, true, 8.0);
        root.setEdgeInsets(NSEdgeInsets {
            top: 16.0,
            left: 16.0,
            bottom: 16.0,
            right: 16.0,
        });
        content.addSubview(&root);
        pin(&content, &root, 0.0);
        let buttons = self.button_row(&d.buttons);
        root.addArrangedSubview(&buttons);
        let hint = label(mtm, &d.hint);
        root.addArrangedSubview(&hint);
        let path = small(mtm, "", 640.0);
        path.setSelectable(true);
        root.addArrangedSubview(&path);
        let notice = small(mtm, "", 640.0);
        root.addArrangedSubview(&notice);
        let (scroll, tv) = text_pane(mtm);
        scroll
            .setContentHuggingPriority_forOrientation(1.0, NSLayoutConstraintOrientation::Vertical);
        root.addArrangedSubview(&scroll);
        fill(&root, &scroll, 32.0);
        let iv = self.ivars();
        *iv.diag_win.borrow_mut() = Some(w);
        *iv.diag_text.borrow_mut() = Some(tv);
        *iv.diag_buttons.borrow_mut() = Some(buttons);
        *iv.diag_hint.borrow_mut() = Some(hint);
        *iv.diag_path.borrow_mut() = Some(path);
        *iv.diag_notice.borrow_mut() = Some(notice);
    }

    fn render_analysis(&self, v: &View) {
        let iv = self.ivars();
        let Some(a) = &v.analysis else {
            if let Some(w) = iv.an_win.borrow().as_ref() {
                w.orderOut(None);
            }
            *iv.an_shown.borrow_mut() = None;
            return;
        };
        if iv.an_win.borrow().is_none() {
            self.build_analysis(&a.tree);
        }
        if let Some(w) = iv.an_win.borrow().as_ref() {
            w.setTitle(&ns(&a.tree.title));
        }
        if let Some(n) = iv.an_notice.borrow().as_ref() {
            n.setStringValue(&ns(a.notice.as_deref().unwrap_or("")));
            n.setHidden(a.notice.is_none());
        }
        if let Some(outline) = iv.an_outline.borrow().as_ref() {
            for (index, id) in ["field.item", "field.value"].iter().enumerate() {
                outline
                    .tableColumns()
                    .objectAtIndex(index)
                    .setTitle(&ns(crate::localization::get(v.language, id)));
            }
        }
        let fresh = iv
            .an_shown
            .borrow()
            .as_ref()
            .is_none_or(|s| !Arc::ptr_eq(s, &a.tree));
        if !fresh {
            return;
        }
        let (Some(src), Some(ov), Some(actions)) = (
            iv.an_source.borrow().clone(),
            iv.an_outline.borrow().clone(),
            iv.an_actions.borrow().clone(),
        ) else {
            return;
        };
        let extra = src.load(&a.tree.nodes);
        clear(&actions);
        for b in a.tree.actions.iter().chain(&extra) {
            actions.addArrangedSubview(&self.button(b));
        }
        if let Some(h) = iv.an_heading.borrow().as_ref() {
            h.setStringValue(&ns(&a.tree.heading));
        }
        ov.reloadData();
        src.expand(&ov);
        *iv.an_shown.borrow_mut() = Some(a.tree.clone());
        if let Some(w) = iv.an_win.borrow().as_ref() {
            w.makeKeyAndOrderFront(None);
        }
    }

    fn build_analysis(&self, tree: &AnalysisView) {
        let mtm = self.mtm();
        let w = new_window(mtm, &tree.title, 1000.0, 720.0);
        w.setDelegate(Some(ProtocolObject::from_ref(self)));
        w.center();
        let content = w.contentView().expect("content view");
        let root = stack(mtm, true, 8.0);
        root.setEdgeInsets(NSEdgeInsets {
            top: 16.0,
            left: 16.0,
            bottom: 16.0,
            right: 16.0,
        });
        content.addSubview(&root);
        pin(&content, &root, 0.0);
        let actions = stack(mtm, false, 8.0);
        root.addArrangedSubview(&actions);
        let notice = small(mtm, "", 900.0);
        root.addArrangedSubview(&notice);
        let heading = label(mtm, "");
        heading.setFont(Some(&NSFont::boldSystemFontOfSize(17.0)));
        root.addArrangedSubview(&heading);

        let src = TreeSource::new(mtm);
        let ov = NSOutlineView::new(mtm);
        for (id, title, width) in [
            (
                "item",
                crate::localization::get(self.view().language, "field.item"),
                560.0,
            ),
            (
                "value",
                crate::localization::get(self.view().language, "field.value"),
                380.0,
            ),
        ] {
            let col = NSTableColumn::initWithIdentifier(NSTableColumn::alloc(mtm), &ns(id));
            col.setTitle(&ns(title));
            col.setWidth(width);
            ov.addTableColumn(&col);
            if id == "item" {
                unsafe { ov.setOutlineTableColumn(Some(&col)) };
            }
        }
        ov.setUsesAlternatingRowBackgroundColors(true);
        ov.setRowHeight(20.0);
        unsafe {
            ov.setDataSource(Some(ProtocolObject::from_ref(&*src)));
            ov.setDelegate(Some(ProtocolObject::from_ref(&*src)));
        }
        let scroll = NSScrollView::new(mtm);
        scroll.setHasVerticalScroller(true);
        scroll.setHasHorizontalScroller(true);
        scroll.setDocumentView(Some(&ov));
        scroll
            .setContentHuggingPriority_forOrientation(1.0, NSLayoutConstraintOrientation::Vertical);
        root.addArrangedSubview(&scroll);
        fill(&root, &scroll, 32.0);
        let iv = self.ivars();
        *iv.an_win.borrow_mut() = Some(w);
        *iv.an_source.borrow_mut() = Some(src);
        *iv.an_outline.borrow_mut() = Some(ov);
        *iv.an_heading.borrow_mut() = Some(heading);
        *iv.an_notice.borrow_mut() = Some(notice);
        *iv.an_actions.borrow_mut() = Some(actions);
    }
}

fn media_grid(
    mtm: MainThreadMarker,
    rows: &[MediaRow],
    language: crate::localization::Language,
) -> Retained<NSGridView> {
    let g = grid(mtm);
    g.setRowSpacing(2.0);
    let header = label(mtm, crate::localization::get(language, "media.header"));
    header.setFont(Some(&NSFont::boldSystemFontOfSize(
        NSFont::smallSystemFontSize(),
    )));
    header.setToolTip(Some(&ns(crate::localization::get(language, "media.hint"))));
    grid_row(&g, &[NSGridCell::emptyContentView(mtm), view_of(&header)]);
    for r in rows {
        let ticks = stack(mtm, false, 2.0);
        ticks.addArrangedSubview(&tick(mtm, r.read));
        if let Some(w) = r.write {
            ticks.addArrangedSubview(&tick(mtm, w));
        }
        grid_row(&g, &[view_of(&label(mtm, &r.label)), view_of(&ticks)]);
    }
    g
}

fn menu_item(
    mtm: MainThreadMarker,
    title: &str,
    action: Option<Sel>,
    key: &str,
) -> Retained<NSMenuItem> {
    unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &ns(title),
            action,
            &ns(key),
        )
    }
}

/// A menu command: title, action, key equivalent.
type MenuEntry = (&'static str, Sel, &'static str);

/// The standard menus plus a language picker owned by the shared UI model.
fn build_menus(
    mtm: MainThreadMarker,
    app: &NSApplication,
    controller: &Controller,
    language: crate::localization::Language,
) {
    let main = NSMenu::new(mtm);
    let groups: [(&str, Vec<MenuEntry>); 3] = [
        ("freemkv Flash", vec![("menu.quit", sel!(terminate:), "q")]),
        (
            "menu.edit",
            vec![
                ("menu.copy", sel!(copy:), "c"),
                ("menu.select_all", sel!(selectAll:), "a"),
            ],
        ),
        (
            "menu.window",
            vec![
                ("menu.minimize", sel!(performMiniaturize:), "m"),
                ("menu.close", sel!(performClose:), "w"),
            ],
        ),
    ];
    for (title, items) in groups {
        let localized_title = if crate::localization::is_message(title) {
            crate::localization::get(language, title)
        } else {
            title
        };
        let top = menu_item(mtm, localized_title, None, "");
        let sub = NSMenu::initWithTitle(NSMenu::alloc(mtm), &ns(localized_title));
        for (t, action, key) in items {
            sub.addItem(&menu_item(
                mtm,
                crate::localization::get(language, t),
                Some(action),
                key,
            ));
        }
        if title == "freemkv Flash" {
            let language_item = menu_item(
                mtm,
                &crate::localization::text(language, "settings.language"),
                None,
                "",
            );
            let language_menu = NSMenu::new(mtm);
            for (index, choice) in crate::localization::Language::ALL.iter().enumerate() {
                let item = menu_item(mtm, choice.native_name(), Some(sel!(onLanguage:)), "");
                // SAFETY: `controller` is a live Objective-C target retained for the
                // application lifetime, and the selector is implemented on Controller.
                unsafe { item.setTarget(Some(controller)) };
                item.setTag(index as isize);
                item.setState(isize::from(*choice == language));
                language_menu.addItem(&item);
            }
            language_item.setSubmenu(Some(&language_menu));
            sub.addItem(&language_item);
        }
        top.setSubmenu(Some(&sub));
        main.addItem(&top);
    }
    app.setMainMenu(Some(&main));
}

/// Bring the app forward: `activate` where it exists (macOS 14+), else the older call.
fn activate_app(app: &NSApplication) {
    if app.respondsToSelector(sel!(activate)) {
        app.activate();
    } else {
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);
    }
}

/// Run the AppKit shell until the window closes.
pub fn run() {
    let mtm = MainThreadMarker::new().expect("the AppKit shell runs on the main thread");
    #[cfg(debug_assertions)]
    let (model, gate) = crate::gui_gate::model_or(ui::App::new);
    #[cfg(not(debug_assertions))]
    let (model, gate) = (ui::App::new(), None::<std::path::PathBuf>);
    let app = NSApplication::sharedApplication(mtm);
    // The gate runs unattended: no Dock icon, and it never takes focus.
    app.setActivationPolicy(if gate.is_some() {
        NSApplicationActivationPolicy::Accessory
    } else {
        NSApplicationActivationPolicy::Regular
    });
    let window = new_window(mtm, &model.view().title, W, H);
    window.setContentMinSize(NSSize::new(760.0, 640.0));
    let c = Controller::new(mtm, model);
    build_menus(mtm, &app, &c, c.view().language);
    *c.ivars().window.borrow_mut() = Some(window.clone());
    app.setDelegate(Some(ProtocolObject::from_ref(&*c)));
    window.setDelegate(Some(ProtocolObject::from_ref(&*c)));
    c.build(&window);
    let fx = c.with_app(|a| a.start());
    c.perform(fx);

    window.center();
    if gate.is_none() {
        window.makeKeyAndOrderFront(None);
        activate_app(&app);
    } else {
        window.orderFront(None);
    }
    #[cfg(debug_assertions)]
    if gate.is_some() {
        *c.ivars().gate.borrow_mut() = gate;
        // Once the run loop is up and the window has drawn.
        let _: () = unsafe {
            msg_send![&*c, performSelector: sel!(onGate:), withObject: None::<&AnyObject>, afterDelay: 0.5f64]
        };
    }
    app.run();
}
