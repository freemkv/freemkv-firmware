//! Shared firmware UI localization.
pub use freemkv_flash::localization::*;

#[cfg(test)]
use std::fs;
#[cfg(test)]
#[path = "localization_tests.rs"]
mod tests;
