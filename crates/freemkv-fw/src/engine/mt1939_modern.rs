//! MediaTek **MT1939-modern** (JB8 / JBP6 / JBC6) lineage.
//!
//! These parts carry an `"MT1959 Boot …"` banner and are MT1959-lineage silicon:
//! the scanner / CDB-base / dispatch-table / VID / AKE / Speed / Region signatures
//! **transfer unchanged**, so MT1939-modern images build through the shared modern
//! path in [`super::mt1959`] ([`Mt1959Engine::build_report`] /
//! [`Mt1959Engine::build_modify`]) verbatim — only the family label differs (applied
//! by [`super::mt1939::Mt1939Engine`]). There is no separate MT1939-modern builder:
//! everything it needs is either the shared [`super::core`] or the modern builder in
//! [`super::mt1959`]. This module exists to name the lineage in the tree; if a
//! JBC6-specific finder or window ever has to diverge from MT1959, it lands here.
//!
//! [`Mt1959Engine::build_report`]: super::mt1959::Mt1959Engine
//! [`Mt1959Engine::build_modify`]: super::mt1959::Mt1959Engine
