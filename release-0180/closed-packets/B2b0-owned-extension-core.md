# B2b0 — one explicitly owned component extension in the composition core

Status: IMPLEMENTED AND TARGETED-TESTED; root inspected the exact local change. This is an independently specified mechanism slice. It does not enable native growth, change final identity, or close B2b receiver/codec work. Parent owns dispatch and the retained isolated checkout.

Use `${EVIDENCE_ROOT}/filter-implementation-0180/po-components` after the accepted B0/B1/B2a changes. One gpt-6.1-sol worker owns only `src/filters/composition.rs`, including its narrow tests. No native owner, runner, public trait, compatibility, representation, receiver, registry, or identity edit. Keep frozen proof sources unchanged. No commit, push, merge, device or Desktop action. fmt/clippy plus targeted tests only; CI runs full suites. Build output remains under implementation scratch and is removed after a retained receipt.

The concrete need is the already retained Host recipe's appended Normal plus independent Phase prefix edits. B1 currently rejects length changes. The byte-composition semantics below can be completed independently of Host's unresolved resources and of the separate final-identity/codec design. The old same-length entry remains the only production caller in this slice, so no native route gains growth permission.

## Exact private API and algorithm

Keep `ComponentEffect { component, basis, image }` and existing `compose_component` signature/behavior. Add a private module-level function `compose_component_with_extent` with the same parameters plus `final_len: usize` immediately after `original`. The existing function delegates to it with `final_len = original.len()`. Visibility may be `pub(super)` like the existing primitive; no public API is introduced.

1. Require nonempty effects. Reject `final_len < original.len()` with Representation. Validate every component tag and exact immutable basis before merging, retaining ComponentMismatch for these errors. Every output length must equal either original length or final length. For unchanged final length, preserve the previous same-length rules exactly.
2. If final length grows, exactly one effect must have that final length. That effect owns the entire new interval `[original.len(), final_len)`, including zero-valued bytes and padding. Reject zero or multiple growers with Representation, even if multiple growers contain equal tail bytes. Do not relocate, concatenate or infer shared ownership. Original-length effects can change only the prefix. A mismatch in a later effect must still be found before any overlap merge or repair.
3. Validate nonempty, nonreversed, disjoint integrity ranges against the final length. Existing integrity rules remain unchanged. This primitive does not choose native fields, checksum coverage, declared-length words or an algorithm; its caller supplies those contracts.
4. Start with original prefix and a zero-initialized tail. Merge prefix differences against the immutable original, ignoring integrity bytes exactly as before. Equal overlapping prefix edits still refuse Unsupported. Copy the single grower's complete non-integrity tail, even where its byte is zero. No other effect owns a tail byte. Integrity bytes start from original prefix values or zero in the tail and are repaired once after composition.
5. Invoke repair exactly once after all validation and merge. Require returned length equal final length and require every byte outside the declared integrity fields, including tail bytes, to equal the merged input. Refuse VerificationFailed otherwise. Do not expose partial results.

There is no native extension certificate in this layer. A later caller may select an enlarged extent only after its exact owner/transfer/placement/identity contracts are implemented. Missing Kernel creation, original component authority, final pair identity and codec support remain outside this pure byte primitive. The existing wrapper continues to reject every length change.

## Focused acceptance

Retain all B0 primitive tests and the existing B1 pair regressions unchanged. Add small synthetic tests covering:

- One grower plus one disjoint prefix editor, both owner orders, for Normal and synthetic Kernel; immutable originals and exactly one repair.
- Tail containing zero bytes is retained as owned data; two equal growers still refuse before repair.
- Growth with no grower, shrink, output length between original/final or beyond final, wrong component/basis, and a late invalid effect all refuse before repair.
- Same-valued overlapping prefix edits between the grower and another effect refuse.
- Integrity field wholly in the tail and a field straddling the old end work only through the supplied synthetic repair; malformed/overlapping/out-of-final fields refuse.
- Repair that changes an unowned prefix or tail byte, or changes final length, refuses.
- Existing `compose_component` continues refusing growth; the new function's unchanged-length path reproduces all previous acceptance/refusal behavior.

Run only `filters::composition::tests::`, the existing 13 B1 pair tests by their module filter, fmt, clippy `--features envelope,drive --lib -- -D warnings`, and the already declared narrow `cargo check --features image --lib`. No full suite or feature matrix. Preserve B1/B2a source hashes except this intended composition-core change. Capture an exact delta from the accepted B0/B1/B2a checkout and the combined baseline patch, source hashes, commands/results and limitations. Expected effort 10–20 minutes with the warm cache; not a whole-B2b estimate.

The next B2b decision remains separate: final hardware identity (the Host recipe maps SAT8231 to truthful installed SAT8511), extension-aware native integrity, Phase's explicit complete-pair postcondition, original/final envelope authority and every actual receiver stage. This packet deliberately does not leave those central decisions to its coding worker.

Receipt: `${EVIDENCE_ROOT}/filter-implementation-0180/b2b0-evidence/receipt.json`. Only composition.rs changed (SHA25653438e217ffe5b1e50602da563268514a2d623665af7f3daa40d410974528715). Delta03d75ecb5a6bb4e0ffdf1a000612e0e0fe669aa8b6938efd4b1b032e5c1b0819; combinedc1bcdac081f7f676311c7973243958613b0f8a2502c99baeff3f81782c1c4e9c.21 composition tests and13 unchangedB1 pair tests pass; fmt/clippy/narrowimage check pass. No native growth/identity/codec/receiver admission. Source and receipts retained; disposable targets removed.
