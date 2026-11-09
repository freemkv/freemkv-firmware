# B0: component-tagged immutable same-length composition core

Status: IMPLEMENTED AND TARGETED-TESTED; root inspected the patch. This is a used internal composition primitive, not admission of Kernel changes or extension. Existing Normal-only runner behavior remains authoritative. Baseline PO f16f0e9e381df138aa8d6f3ab97b9ee42b58a73b. Root provides a separate scratch source checkout; frozen sources remain untouched.

## Purpose and bounded contract

The current runner contains a Normal-specific byte merge. Extract that existing mechanism into a component-tagged, original-basis-checked primitive and immediately use it for existing Normal composition. This provides a concrete reusable foundation for later paired output while refusing cross-component or wrong-basis effects. It does not implement missing native Kernel/extension certificates, full final-pair verification, codecs or receiver migration.

Own only PO `src/filters.rs` (private module declaration), `src/filters/runner.rs` (existing compose adapter and narrow regression), and new `src/filters/composition.rs` (primitive and targeted unit tests). No owner/native recipe files. `crate::Role::{Normal,Kernel}` already represents the permitted two components; reuse it.

## Exact internal API

In private `filters::composition`, define crate-visible or parent-visible:

```
struct ComponentEffect<'a> {
    component: crate::Role,
    basis: &'a [u8],
    image: &'a [u8],
}
fn compose_component<F>(
    component: crate::Role,
    original: &[u8],
    effects: &[ComponentEffect<'_>],
    integrity_fields: &[core::ops::Range<usize>],
    repair: F,
) -> Result<Vec<u8>, crate::compatibility::Error>
where F: FnOnce(&[u8]) -> Result<Vec<u8>, crate::compatibility::Error>;
```

Use alloc/core and existing Error; keep no_std+alloc compatibility and no new dependency. The component discriminator is mandatory even for equal Normal/Kernel bytes. Basis is exact byte equality, not a hash, address or lossy projection. Callers remain responsible for original authority, native integrity agreement and all semantic/resource proofs.

Algorithm, before calling repair:
1. Reject no effects as Unsupported. Reject any effect with a different component or basis bytes unequal to original as ComponentMismatch. Reject any output whose length differs from original as Representation. Validate every effect before applying edits or invoking repair.
2. Build checksum mask using exactly the existing rules: every field must be nonempty, within original bounds and disjoint from all other fields. Invalid/overlapping fields return Representation. Empty field list remains allowed, as in current code; it authorizes no repair-byte changes.
3. Start from an owned original copy. For each effect, compare each byte with the immutable original. Ignore unchanged bytes and bytes inside integrity fields. For each other changed byte, reject a second claimant as Unsupported even if both propose the same value. Otherwise copy that effect's byte. Never use a previously merged result as another effect's basis.
4. Invoke repair exactly once on the completely merged image. Propagate its error. Reject repaired length mismatch or any modification outside the integrity mask as VerificationFailed. Return only the final repaired vector. No partial result escapes on any failure.

Existing `runner::compose` retains its current checks that every output has nonempty matching integrity id and identical integrity fields. It builds Normal-tagged effects with `basis=context.target.normal`, delegates the byte merge, and passes a closure invoking the existing selected `(integrity.repair)(context,image)`. Keep the legacy single output without integrity path and all Plan admission/final verification exactly as they are. No Operation or public API change. The existing runner length precheck may remain; the primitive independently validates lengths so future component callers cannot truncate via zip.

## Targeted acceptance

Tests in new module must cover: disjoint edits against immutable basis compose; equal overlapping writes refuse; Normal effect cannot enter Kernel composition even with identical bytes; wrong same-length basis refuses; short and long output refuse before repair; malformed/overlapping checksum fields refuse; repair invoked once after both edits; changed checksum bytes from owner outputs do not bypass central repair; repair outside authorized fields or length change refuses; repair error propagates. Use synthetic byte arrays, not invented native Kernel checksum claims. At least one valid Kernel-tagged synthetic case confirms tag symmetry, without exposing any Kernel admission path.

Run fmt/clippy + targeted tests only; CI runs full suites. CARGO_TARGET_DIR under implementation scratch directory. Commands:
- `cargo test --features envelope,drive --lib filters::composition::tests::`
- `cargo test --features envelope,drive --lib disjoint_owners_compose_atomically_and_repair_one_shared_checksum`
- `cargo test --features envelope,drive --lib composition_requires_same_proved_integrity_and_repair_cannot_edit_code`
- `cargo fmt --all -- --check`
- `cargo clippy --features envelope,drive --lib -- -D warnings`
- `cargo check --features alloc --lib` only if alloc is an actual declared feature; otherwise use the existing default/no_std feature set that includes filters. Do not run a feature matrix.

Worker may adjust private Rust visibility/import syntax only, not the semantic contract. Report exact diff/tests, source pin and baseline constraints. No commit/push/merge/device/Desktop action. Estimate 10–25 minutes on a warm compiler cache, with compile time reported separately. This is independent of C0 FW files. B1 later owns complete-pair result/native certificates/final-pair verifier and receiver/stages.rs; B0 does not claim those are implemented.

Implementation: `/Users/matthew/Developer/tmp/filter-implementation-0180/b0-evidence/B0.patch`, SHA256 `17185317cd49755943e2ad66974135d053458bf8f959582ee70bf290c5944ed6`. Eleven primitive tests and two runner regressions pass, along with fmt/clippy/image check/diff check. No alloc feature exists; image is the narrowest declared set including filters. Root apply-check passed against the frozen baseline without applying it. Source remains uncommitted in `po-components`; disposable target removed. Cargo compilation/check time27.24 seconds, command wall time29.388 seconds. No new gate or route.
