# R1A — generic filter feasibility survives family override

Status: IMPLEMENTED, targeted-tested and root-accepted. Receipt: /Users/matthew/Developer/tmp/filter-implementation-0180/r1a-evidence/receipt.json. All six non-XD08 directional-policy cases now refuse; control passes; four XD08 cases remain explicitly open. No directed membership table. This is the first enforcement slice. It fixes the three permissive FamilyOverride mismatch cases; it does not close the separate missing Controller observation that permits XD08 under both policies.

## Owner instruction and behavior

Arbitrary old/new firmware → registered native filter observations → each owner's transition/correction decision → aggregate admission. Every owner.plan failure is mandatory under every policy. FamilyOverride bypasses the broad domain/family gate only; it cannot make an uncorrectable or unresolved native filter correctable. Supported correction operations and their requirements/verification remain enforced. This intentionally supersedes the existing behavior that waived a Hardware owner's Incompatible or UnresolvedIdentity error.

No model/version/digest/direction list is allowed. The five original directions are regression fixtures only. Do not introduce a replacement lookup behind an owner hook or alter native findings to make a test pass.

## Exact code and algorithm

Use retained po-components with accepted B0/B1/B2a/B2b0 edits. Exclusive production file src/filters/runner.rs, including its directly affected tests and policy/Decision documentation. No other production edit is authorized by this packet.

In evaluate_with, keep registry validation, inspection, compare, operation-ID checks and owner.plan invocation. Remove the FamilyOverride guarded Err arm that clears the owner's failure and sets waived=true. Every Err(error) sets blocked=Some(error), regardless of role or policy. Preserve the original actual comparison. Every newly built Decision has waived=false; retain the public field for compatibility, documenting that individual owner failures are no longer waivable. No correction is selected on failure.

Plan::admit retains its current policy-specific domain gate: Strict requires the domain comparison, FamilyOverride may bypass that gate. Both policies then enforce every owner failure and selected-operation prerequisite. Existing public preparation paths continue to call admit before operations and no-change returns. Do not change error variants or precedence in this slice: current Incompatible/UnresolvedIdentity/Unsupported remain truthful mandatory refusals, and Decision identifies the owner and native findings.

Leave component matching, complete-pair verification, immutable composition, registry binding, integrity repair and codecs unchanged. Existing final verification conditions may retain the public waived field branch, but this evaluator never creates a waived owner. Do not broaden scope to redesign reports or remove public API fields.

## Targeted acceptance

Red evidence already exists in run-20261108/release-negative-refusal-check: original171→184,352→199,352→399 under FamilyOverride currently pass; all originals authenticate. Replay those actual fixtures through the same public compatibility plan/preparation API after the change. They must refuse at planning with the existing owner failure, produce no decoded/encoded output, and remain refused under Strict.441→441 must keep observed no-change success.441↔444 are expected still permissive in this slice and must be reported as the separate Controller enforcement gap, never silently relabeled pass.

Replace the old test that expected an uncorrectable Hardware waiver with refusal under both policies, including reporting evaluate().decisions(): comparison remainsDifferent, blocked remainsIncompatible, waived=false. Likewise unresolved Hardware evidence staysUnresolvedIdentity under FamilyOverride. Retain a positive broad-domain override test where the test owner genuinely matches/supports the transition, proving the policy still has its intended independent scope. Retain supported Phase/ordinary correction, conflicting prerequisite and selected-proof-error cases. Keep the directly affected B1 pair tests. Add a no-operation plan target Normal/Kernel/hardware substitution check only if no existing directly targeted case covers it; no broad feature matrix.

Do not weaken a failing test's requirement merely because it previously encoded the superseded owner-waiver behavior; rewrite that exact policy assertion to the new contract and preserve unrelated verification coverage. In the former extra-write test, keep the mutation/postcondition rejection using an actually admitted registry (for example the untouched other owner matches), not a now-forbidden uncorrectable transition.

Explicit gpt-6.1-sol; fmt/clippy/build plus targeted tests only, CI full suites. Scratch/targets under /Users/matthew/Developer/tmp/. No commits/push/devices. Preserve original source snapshot and emit delta plus combined baseline patch with receipts. Expected10–20minutes including original-fixture replay. Root owns dispatch. Stop on an actual semantic contradiction; do not add a pair-specific exception.
