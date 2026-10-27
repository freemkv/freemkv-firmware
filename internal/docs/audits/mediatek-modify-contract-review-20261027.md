# MediaTek Modify contract review — 2026-10-27

Status: in progress on dev. This is not a firmware release or hardware-validation report.

## Scope and completion accounting

The held corpus baseline contains 1,085 unique MediaTek inputs. The published eligible group
contains 108 images. Earlier corpus runs predate the current contract changes and are not final
sign-off. At this checkpoint, final personally reviewed per-input end-to-end sign-off is **0/108**.
The 197 held inputs in the native base-role inventory all resolve the owned command/response
contracts. That is a component result, not full Modify or hardware validation.

## Findings and fixes with direct evidence

- Command table selection now follows native registration, the array consumer, scanner and
  linked tables. Disconnected coherent tables and table cycles are refused.
- Native response caller/argument evidence corrects 14 previously selected response writers.
  Buffer pointer, DMA source/count, normalization guards and saved return frames are checked.
- Compiler byte-switch calls preserve different registers from an ordinary call. A regression
  retains a native R0 stack alias across that switch and catches a later saved-frame overwrite.
- The modern boot detour restored R3 and then overwrote it with the native init target. The
  corrected detour uses scratch R12, restores R4 before native entry and keeps an aligned
  two-word return frame. Independent CPU execution fails on the previous generated BIN's R3
  and passes on the corrected BIN: R0-R3, R4-R11, SP, native return value and return NZCV.
- The SRAM walker previously invented long copy/clear extents when its pointer-seeded walk
  did not know the literal count. Bounded native word copies, word clears and byte clears
  now use the validated pre-test/count/stride/control-flow grammar. Zero-count loops do not
  write memory. Tests fail with these models disabled and pass when restored.
- A raw word equal to a code address is not by itself a branch. In WH16NS58 1.V9, the word
  0x4343 at 0x7a200 is loaded at 0x79ee6 and added to a masked MMIO value stored at [R4+28].
  Direct-entry analysis therefore uses decoded references rather than treating every matching
  literal as a control-flow edge. Arbitrary indirect entries remain outside this proof.
- Candidate SRAM placement now reserves four-byte guards plus the complete flag/scratch
  footprint and stays below the conservative placement ceiling. Classic emission performs
  the overlap checks as well. Underflow/overflow and a wholly occupied mapped range refuse.

## Assurance limits still being closed

Observed SRAM references and absence of a reference do not establish runtime ownership.
The BU40N capture does not prove every classic/modern model's RAM layout or every workload.
Classic storage ownership remains open. The older feature finders, overwritten-span incoming
edges, sibling API consistency and complete generated workflows remain part of this audit.
No final 100% claim follows from component recognition, signing or structural success alone.

## Verification evidence at this checkpoint

- Library: 189 passed, 3 ignored before the direct-entry indexing optimization; rerun in progress.
- Independent CPU: 1,040 modern/classic authentication and BD cases passed, plus three native
  boot ABI/return-flag cases. Native peripheral operations are not physical drive execution.
- App: 215/216 passed in the latest completed full run; remaining KAT candidate expectation
  corrected and its individual test passed. A complete updated run is in progress.
- Library Clippy and no-default/image/analysis feature checks passed before indexing; rerun needed.

Final corpus artifacts must retain actual modified BINs, full Modify JSON and Flash admission
results. A successful automated row must not be labelled personally reviewed until inspected.

## Final-producer checkpoint

Producer SHA-256: `64574b63546623261aebfb741903a5893aee1fa82dab4be6665845ecd3120bae`.
Offline Flash gate SHA-256: `57ab4d927ec6438b21161204e009d2a79a347f7b42ae7fe805f8ee640002723d`.
The final full-corpus run completed 1,085/1,085 with zero runner failures:
193 supported builds, all 193 admitted; 890 unsupported; one unchanged; one
known incomplete input rejected before capability JSON. Of the unsupported
inputs, three refuse for safe-code-space exhaustion; the other 887 refuse
as unsupported firmware (including the three raw readbacks).

The root library tests passed 217/217. The MediaTek library passed 193 with
three ignored opt-in corpus tests; release all-target/all-feature Clippy passed.
The final producer passed 1,040 independent auth/BD CPU cases and eight CDB
runtime/reset/reload cases. Native writer/committer CPU execution passed all
197 contracts (6,304 byte writes, 2,364 queue cases). The four pinned CI native
fixtures independently passed 128 writes and 48 queue cases.

The 108-image all-settings run remains in progress at this checkpoint. Personal
per-output sign-off remains incomplete; the completed automated corpus is not
being presented as that sign-off.

The three raw readbacks are research captures, not corrupt updater extractions.
Publication already requires Flash admission of the packaged bytes. fwext's
classification must demote raw MediaTek readbacks from OEM to dump using the
shared library detector. The WH16NS60 1.00 source is a raw archive; no OEM updater
is recorded for that hash. Original captures are retained, not withdrawn merely
because they require reconstruction before flashing.

## Completed corpus/settings/CPU checkpoint

- All 108 publication-group images passed every advertised settings choice,
  reopened verification, integrity checks and offline Flash admission.
- The other 85 supported held inputs passed the support-aware settings matrix
  (932 advertised choice executions). These manifests are disjoint, covering
  all 193 supported held inputs, including partial-support/base-only outputs.
- All 178 emitted authentication hooks passed per-input execution against native
  continuations, live registers, SP and CMP flags: 34,432 CPU cases.
- All 24 classic inputs passed 118,656 routing comparisons, 345,648 DI-entry
  cases, and 23,040 native speed selector/tail comparisons.
- The final output ledger binds all 193 retained outputs to exact input/output
  SHA-256 and admission records. Its placement metadata has been inspected;
  this is separate from final per-output logical sign-off, which remains open.
- Three remaining code-space refusals are two MK inputs and one Omni input.
  No publication-group image refuses for allocation.
- The raw WH16NS60 readback now resides under dump after canonical rebuild.
  It has an existing stored-form component match outside drive-written regions.

The 87a7f28 dev CI run caught a synthetic CLI fixture whose boot and mirror pages
were identical. The fixture now represents a stored image; the CLI suite passes
35 tests with one opt-in ignored. No runtime guard was relaxed.

During report triage, new Pioneer SXLT captures exposed OEM-brand assumptions
in descriptor recognition, fixed-width inquiry spelling, and native receiver
policy. Fixes live in pioneer-optical dev; host backup replay and error-message
regressions exercise the ordinary workflow. These do not alter MediaTek outputs.


## Current dev checkpoint after diagnostic imports

Dev commit `5d4b5163324816026795e5f6f93b4b27a78e1de6` passed the full
[CI workflow](https://github.com/freemkv/freemkv-firmware/actions/runs/40582181198)
and the comment, identity, leak and documentation guards. The native response
corpus paths are absolute so Cargo's crate working directory cannot change their
meaning. The same Cargo invocation and independent CPU checks passed locally.

The latest 1,085-input parity run uses Modify producer SHA-256
`3d126e958692d7f88b0f4554b2c30a687a7a8011a8d4d2826cb2c1e1d3885fd8`.
All statuses and retained output hashes match the preceding complete run. The
readback detector now requires the exact two-MiB geometry; three legitimate
512-KiB Optorite OEM inputs remain OEM. This corrects classification without
relaxing the guard for the three full raw MediaTek captures.

Both new Epson-family Kernel/Normal pairs are locally approved Community
imports. The SXLT source is retained as a raw capture; its Kernel-derived envelope
reconstruction is explicitly recorded rather than presented as an OEM original.
The shared Pioneer fix passes ordinary backup replay and offline Flash admission.
The specific unsupported-layout error no longer advises checking the connection.
These imports are staged only and require the fixed Flash app before deployment.
Extractor commit `378e574a` remains local on dev, with no remote push.

This checkpoint closes CI and diagnostic-import work. It does not close the
remaining personal per-output logical review or the assurance limits above.


## Combined classic-continuation regression found during final review

The decoded detour inventory covered 2,318 candidate installs across all 193
retained supported outputs. Twenty-four original branch references enter the
second half of another detoured instruction pair. Their original source branches
are themselves replaced, but the reverse-selector stubs retained those interior
addresses as literal continuations. Consequently, the earlier isolated component
CPU tests did not establish correctness of the combined output.

A new source-fixture regression fails before the fix. Emission now follows a
consecutive native branch only when it has the same already-taken condition;
no flag-changing instruction is skipped. Cycles refuse. The source-bound SDK
continues to report the actual original native edge, while the emitter resolves
its safe continuation. Both arithmetic selectors are installed together by the
CPU harness using thumb-asm-generated branch bytes. Recreating the old literal
continuation produces an invalid-instruction CPU failure; the corrected pair
passes 320 calculation cases on the pinned fixture. All 24 inputs passed the
first updated component matrix; the stricter final-rejection matrix and refreshed
normal-Modify outputs are being regenerated.

The 24 previous classic outputs are superseded audit artifacts, not final
sign-off. The broader logical review remains open. This issue was found before
any release of the conversion code.
