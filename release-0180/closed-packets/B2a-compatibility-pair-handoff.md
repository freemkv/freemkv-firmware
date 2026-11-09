# B2a: preserve complete decoded pairs through compatibility planning

Status: implemented and targeted-tested in isolated po-components; root inspected the final diff and exact patch/source hashes. Scope is decoded compatibility handoff only. No new codec, native correction, receiver stage or route. Frozen source remains untouched. Receipt: `${EVIDENCE_ROOT}/filter-implementation-0180/b2a-evidence/receipt.json`. Delta SHA256 `e0d76fe988cd95e5350907ce65e512039a8bf5d823a1fbbf741855252e8ec327`; combined B0/B1/B2a `0175ebac1bfc7564816fbade415227d401b6b7296048baf27fad9df035c71c4e`.

Own only `src/compatibility.rs` and a dedicated narrow compatibility test module if useful. Do not edit B0/B1, native owners, representation.rs, receiver or firmware application. Baseline is frozen f16f0e9 plus inspected combined B0-B1 patch cda212c2dd844b41fe64d92a921f27bdf22fb72679afd833cdd108db4b2b874c.

## Contract and exact APIs

The runner now returns and verifies actual Normal+Kernel. CorrectionPlan still carries only Normal and performs its final strict discovery with original Kernel. Add:

- envelope-gated `CorrectionPlan::prepare_components(&self, normal: &Envelope, kernel: Option<&Envelope>) -> Result<Option<filters::PreparedComponents>, Error>`;
- raw `CorrectionPlan::prepare_decoded_components(&self) -> Result<Option<filters::PreparedComponents>, Error>`.

Both return owned decoded components, not an authenticated or executable Update. Envelope authentication/live prerequisites remain independent receiver gates, as on the existing decoded preparation path.

Envelope method retains all current prepare_image guards exactly: matching_components, exact Normal image, exact Kernel image/presence, exact hardware. It constructs original Preparation with the same envelope references and calls runner.prepare_components once. Raw method constructs the existing raw Preparation with no envelopes and also calls runner.prepare_components once. No missing codec/source authority is invented; an owner needing it still refuses.

For Some(result), strict final identity discovery receives `self.target.hardware`, `result.normal` and `result.kernel.as_deref()`. For None it receives the exact original pair. When expected is Some, require discovered after.as_is == expected, as today; when expected is None retain existing explicit-policy behavior and the runner's mandatory owner verification. This slice allows no hardware-string, length or Kernel-presence mapping; B1 already enforces those exact invariants. Introduce a private borrowed-pair identity verifier rather than cloning image buffers for verification. Preserve original `verify_image` as a small wrapper if existing narrow tests use it.

Existing Normal-only wrappers must call these new methods and reject Some(result) whose Kernel bytes/presence differ from self.target.kernel with Unsupported. Return only Normal when Kernel is unchanged. In particular:
- prepare_image delegates to envelope prepare_components;
- prepare_normal delegates to raw prepare_decoded_components;
- prepare_file remains unchanged in shape and uses checked prepare_image then existing rebuild_normal; it cannot silently encode only Normal from a changed pair.

Existing required_words, corrections and filters reporting are unchanged. No new authentication claim, identity mapping, checksum algorithm, callback, source mutation or drive I/O. Error or strict identity failure yields no partial result. No-op and prerequisite-only results preserve current None behavior while retaining required_words.

## Directly targeted evidence

Use small synthetic Filter/Operation registries through public runner planning in compatibility module tests; construct CorrectionPlan in its own module as existing tests do. Cover:
1. Raw complete-pair method returns a Kernel effect from an explicit pair-aware synthetic owner; raw Normal wrapper returns Unsupported for the same plan.
2. Envelope method refuses wrong original Normal/Kernel/hardware as before; a same-length synthetic Kernel effect is carried as a complete pair where fixture authority permits it, while prepare_image/prepare_file refuse dropping it.
3. Existing Normal-only correction and no-op behavior is unchanged; prerequisite-only operation still retains required_words.
4. Final strict identity uses final pair. Prefer an existing Kernel-dependent discovery fixture; mutate its relevant Kernel contribution and require rejection against the unchanged expected Key. Do not fabricate a native support claim from a synthetic effect. If no existing narrow fixture can exercise discovery, report the exact missing fixture instead of inventing a domain, and retain actual-final-pair verification tests from B1 plus direct code evidence for argument binding.
5. A late owner/final identity failure returns error without exposing either component.

Run fmt/clippy + targeted tests only; CI runs full suites. Use a task-specific CARGO_TARGET_DIR under scratch. Run the new module/filter, exact existing compatibility tests covering prepare_normal/verify_image, B1 pair tests if a change directly touches that handoff, fmt check, clippy with envelope,drive, and one image-only check. No feature matrix or full tests. Identify actual test names before commands.

Retain exact B2a delta against pre-B2a source, combined baseline patch and targeted receipts; report source hashes and compile time. No commit/push/merge/device/Desktop action. Root performs ordinary diff inspection and bookkeeping. Estimate10–20 minutes on warm cache. Pair envelope rebuilding/receiver propagation is B2b/B3 and remains outside this slice.

## Implementation evidence boundary

22 focused tests passed (7 new, 2 native regressions, 13 B1), plus fmt/clippy/image check. The synthetic registry cannot pass the public mandatory global-registry guard. Private FnOnce preparation helpers therefore share the production final-pair validation and checked extraction, while production wrappers still invoke the global runner exactly once. Synthetic changed-Kernel cases prove this helper path only. No complete registered-Key Kernel-dependent discovery fixture was found; the declared fallback retains B1 actual-final-Kernel tests and direct final-pair argument binding. No registry relaxation, native correction admission or additional gate credit follows. B0/B1 source hashes are unchanged.
