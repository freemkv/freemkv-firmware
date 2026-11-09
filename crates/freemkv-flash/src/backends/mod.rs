//! Protocol backends, one directory each. Core code reaches them only through
//! the registry in [`crate::backend::registry`].

pub mod mtk;
pub mod pioneer;

/// Offline historical catalog; never participates in protocol detection.
pub mod catalog;
