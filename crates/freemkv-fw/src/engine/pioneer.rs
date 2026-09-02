//! Pioneer / Renesas engine — placeholder.
//!
//! Pioneer/Renesas optical controllers are a different platform (different SRAM
//! map, hook points, and integrity scheme). When support lands, this becomes a
//! real [`crate::engine::Engine`] impl composing the same [`crate::thumb`] verbs — no new
//! patching logic, only new platform facts. Until then it is intentionally
//! empty so the extension point is visible.
//!
//! (freemkv-flash classifies Pioneer/Renesas drives but does not flash them; the
//! authoring side mirrors that: recognized, not yet supported.)
