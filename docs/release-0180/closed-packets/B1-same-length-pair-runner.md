# B1: same-length complete-pair preparation and verification in the filter runner

Status: IMPLEMENTED AND TARGETED-TESTED; root inspected the exact patch. This is runner plumbing with synthetic mechanism tests; it does not add a native Kernel correction, change identity, authorize growth or migrate receiver encoding. Root owns the implementation checkout and integration. Baseline PO f16f0e9e381df138aa8d6f3ab97b9ee42b58a73b plus the inspected B0 patch17185317cd49755943e2ad66974135d053458bf8f959582ee70bf290c5944ed6. Use that retained isolated checkout, never frozen proof sources.

## Ownership and deliberate scope

One SOL worker owns `src/filters.rs`, `src/filters/runner.rs` and a new narrow runner pair-test module if useful. B0 composition primitive is reused; change it only if an actual contract defect is found and report that first. No native owner, compatibility codec, receiver, application or registry edits. Source/compiler feedback may refine private plumbing, not the semantic rules below.

The existing public Normal-only runner entry points remain checked wrappers. They must never silently discard a Kernel effect. Hardware string, Kernel presence and both decoded lengths remain exactly original. Final native identity mapping, absent-Kernel authority, extensions, foreign services and resources remain later packets. Their absence is not permission to bypass them.

## Concrete public types and trait additions

Add in filters.rs:

```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComponentOutputs {
    pub normal: Option<Vec<u8>>,
    pub kernel: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedComponents {
    pub normal: Vec<u8>,
    pub kernel: Option<Vec<u8>>,
}
```

ComponentOutputs None means preservation of that original component, not removal. PreparedComponents owns the complete final decoded pair, not independently authenticated envelopes. Do not imply it is executable/transfer-approved. Prefer a small borrowed `firmware(&self, hardware: &str)` helper only if useful; identity authority stays with original Preparation in this slice.

Keep existing Operation required `prepare` and `verify` methods unchanged for current implementors. Add defaults:
- `prepare_components(&self, context: &Preparation<'_>) -> Result<ComponentOutputs, Error>` delegates exactly once to legacy prepare; returned Normal goes into normal, kernel is None.
- `component_integrity(&self, component: crate::Role) -> Option<Integrity>` delegates Normal to legacy integrity and returns None for Kernel.
- `verify_components(&self, context: &Preparation<'_>, final_pair: Firmware<'_>) -> Result<(), Error>` first requires final hardware and Kernel bytes/presence equal context.target; otherwise VerificationFailed. Then delegates to legacy verify with final Normal.

The default verifier intentionally cannot certify a changed Kernel, including a Kernel change from another owner. A future owner must explicitly override complete-pair verification with its own full contract. New pair-only synthetic operations implement required legacy methods as Unsupported and override the new methods; they must not return a misleading legacy no-op. Existing production owners need no changes and gain no new support.

## Runner APIs and algorithm

Add Plan methods matching existing registry/default patterns:
- `prepare_components(&Preparation) -> Result<Option<PreparedComponents>, Error>`
- `prepare_components_with(&Preparation, &[&dyn Filter]) -> Result<Option<PreparedComponents>, Error>`
- `verify_components(&Preparation, Firmware<'_>) -> Result<(), Error>`
- `verify_components_with(&Preparation, Firmware<'_>, &[&dyn Filter]) -> Result<(), Error>`

Preparation:
1. Retain `admit`, exact original `matches_components` and exact registry checks before invoking any owner. Every owner receives the same immutable original Preparation; call its new preparation method once. Collect outputs and per-component integrity without altering originals.
2. Reject any emitted Normal length change. Reject any emitted Kernel when original Kernel is absent, or any emitted Kernel length change. Use ComponentMismatch for absence/basis mismatch and Representation for length. Validate all outputs before any checksum repair. An emitted byte-identical component is still an effect for integrity/ownership validation; only final result equality controls no-op return.
3. Compose each component independently using B0 `compose_component`. For effects in that component require matching nonempty integrity IDs and identical field ranges, as current Normal composition does. Each callback receives the original Preparation and the merged bytes of the selected component. Kernel ALWAYS requires integrity, even for one output. Preserve the current Normal-only exception: exactly one Normal output with no integrity is used directly. This exception never applies to Kernel. Multiple Normal effects with any missing integrity refuse.
4. A component with no effects is an exact clone of its original (or None for absent Kernel). If either component repair/composition fails, discard the entire pair; no partial result escapes. Both repairs, when needed, occur once, after their complete disjoint merge.
5. Build final Firmware using original hardware string and both final decoded components. Run complete-pair verification below. Only then return Some(PreparedComponents) if either decoded component differs from its original, else None. Required-word/prerequisite-only operations remain in the Plan and are still verified; this slice does not alter executor enforcement.

Complete-pair verification:
- Retain admission, original Preparation identity/file guards and registry checks.
- Require final hardware equal original, unchanged Normal length, same Kernel presence and unchanged Kernel length. Reject mismatches before inspecting owners.
- Construct ONE after Context from actual final Normal AND actual final Kernel. For every selected operation call its `verify_components` with that same final pair. For each untouched owner retain current known/not-applicable comparison and unresolved-hardware refusal rules, but run inspect on this actual final Context. Never rebuild after Context with original Kernel.
- Selected owner identity/role checks remain exactly current.

Legacy wrappers:
- `Plan::prepare/prepare_with` call new complete-pair preparation. If it returns a pair with Kernel bytes/presence different from the original, return Unsupported rather than dropping Kernel. Otherwise return its Normal through the existing Option<Vec<u8>> behavior. No output means None. Existing native owners therefore behave as before.
- `Plan::verify/verify_with` wrap the supplied Normal plus original Kernel/hardware into borrowed Firmware and call complete-pair verification. Do not allocate image clones solely to invoke a verifier.
- No changes to CorrectionPlan, PreparedCorrection or receiver at this step; their existing Normal path uses the checked wrapper and cannot acquire Kernel mutation support implicitly.

## Focused acceptance

Use small synthetic images/filters/operations, no invented native feasibility fixtures. Required tests:
1. Existing Normal composition regressions continue passing through new defaults/wrappers.
2. An explicitly pair-aware synthetic owner changes a present Kernel with a valid synthetic integrity callback; new pair API returns the actual final Kernel and unchanged Normal. Legacy preparation returns Unsupported for the same Plan.
3. Final selected verifier and untouched observing owner receive the actual edited Kernel. Mutate a protected Kernel byte and require final verification failure; do not let an original-Kernel Context hide it.
4. A legacy Normal owner combined with a Kernel effect refuses via its default verifier, unless its test implementation explicitly supplies a complete-pair verifier.
5. Separate disjoint Normal/Kernel effects compose; original Preparation seen by both is byte-identical regardless of owner order; a late verifier/repair failure exposes no pair.
6. Absent Kernel creation, Kernel/Normal growth/shrink, hardware change and missing Kernel integrity refuse. Same-valued overlapping Kernel writes refuse through B0. No-effect/prerequisite-only Plan still invokes verifiers and returns None.
7. Two Kernel owners with different integrity IDs/field ranges refuse; repair is once per affected component. Existing Normal single-no-integrity behavior remains.

Run fmt/clippy and directly targeted tests only; CI runs full suites. CARGO_TARGET_DIR stays under implementation scratch. Suggested commands: new runner pair-test module filter, the two B0 runner regression names, `cargo test --features envelope,drive --lib filters::composition::tests::`, fmt check, `cargo clippy --features envelope,drive --lib -- -D warnings`, and one `cargo check --features image --lib` for the declared non-envelope compilation path. No full test suite/feature matrix. If an existing narrow test directly covers legacy prepare/verify/required_words, include it by exact test filter.

Report exact diff, final source/patch hashes, targeted outcomes and any concrete integration defect. No commit/push/merge/device/Desktop action. Root retains the combined B0+B1 checkout and exact delta patch/receipts; remove disposable build target after reviewable results. Estimate15–35 minutes with warm compiler cache, explicitly separate compile time. B2 will later migrate compatibility/representation/receiver including receiver/stages.rs under complete native identity/codec contracts; B1 does not claim B2 readiness or whole48 completion.

Receipt: `/Users/matthew/Developer/tmp/filter-implementation-0180/b1-evidence/receipt.json`. Exact B1 delta SHA256 `b890fb27d3dfb10b31ee948868a5613d2bb9a1d97b0652e0aadc6eb46e229cc4`; combined B0+B1 SHA256 `cda212c2dd844b41fe64d92a921f27bdf22fb72679afd833cdd108db4b2b874c`. Thirteen pair tests, eleven B0 tests and five legacy regressions pass. fmt/clippy/image check pass; both patches reproduced final source in disposable apply checks. Root inspected; source retained uncommitted, build scratch removed. No native route or whole gate credit.
