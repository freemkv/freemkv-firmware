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
