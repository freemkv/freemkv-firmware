//! Scoped copies of firmware inputs consumed by an operation, for reproducible reports.
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug)]
/// Exact selected container bytes and the selection needed to reproduce an operation.
pub struct FirmwareInput {
    /// Input purpose: target, selected Current, or pre-update capture.
    pub role: &'static str,
    /// Original input filename, retained for the reproduction manifest.
    pub filename: PathBuf,
    /// Explicit component selection inside a multi-image container.
    pub member: Option<String>,
    /// Immutable bytes read by the workflow, before any target transformation.
    pub bytes: Arc<[u8]>,
}
type Sink = Box<dyn FnMut(FirmwareInput)>;
thread_local! { static SINK: RefCell<Option<Sink>> = RefCell::new(None); }

/// Restore a previous collector even when validation or execution unwinds.
pub fn capture_firmware_inputs<R>(
    sink: impl FnMut(FirmwareInput) + 'static,
    operation: impl FnOnce() -> R,
) -> R {
    struct Restore(Option<Sink>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SINK.with(|s| *s.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(SINK.with(|s| s.replace(Some(Box::new(sink)))));
    operation()
}
pub(crate) fn retain(role: &'static str, path: &Path, member: Option<&str>, bytes: &[u8]) {
    SINK.with(|s| {
        if let Some(sink) = s.borrow_mut().as_mut() {
            sink(FirmwareInput {
                role,
                filename: path.to_owned(),
                member: member.map(str::to_owned),
                bytes: Arc::from(bytes),
            });
        }
    });
}
