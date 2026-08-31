//! freemkv-fw as a library: the firmware-authoring engine plus thin, typed
//! wrappers over its three file operations (`create` / `verify` / `sign`).
//!
//! The `freemkv-fw` CLI (`src/main.rs`) and the `freemkv-fw-gui` desktop app
//! both build on this crate, so neither shells out and the two front-ends can
//! never drift. The wrappers in [`api`] return *typed outcomes* — the scheme
//! name, per-region verdicts, the produced image bytes, the create report — so a
//! GUI can render results without parsing log strings.

pub mod abi;
pub mod engine;
pub mod family;
pub mod scheme;
// The generic Thumb toolkit. Parts are wired into the apply path; the rest is
// the platform-neutral API the engines are migrating onto — kept public so the
// migration can land without churn.
pub mod thumb;

pub mod api;
