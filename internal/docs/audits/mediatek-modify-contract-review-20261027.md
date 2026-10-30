# MediaTek Modify software audit — 2026-10-27

Software review and local verification are complete. Final dev CI is required
before handoff. No firmware release or website capability deployment is authorized.

## Scope and result

All 1,085 held MediaTek inputs were queried through the real Modify planner.
There are 193 accepted input variants, producing 186 distinct default output hashes.
Input variants that normalize to the same output remain separate provenance records.

- 178 inputs expose all five public control groups: Unrestricted, HRL,
  Encryption, Speed and Region. This includes 154 MT1959 and 24 MT1939 images.
- 11 expose Speed only; four receive base/DE changes without editable controls.
- Every one of the 108 publication-group inputs has all five control groups.
- All 193 accepted inputs pass actual build, preview/output hash equality,
  structural audit, signing/integrity, reopened settings and offline Flash admission.
- All 2,336 advertised setting choices were exercised on the final outputs.

The remaining outcomes are explicit: 884 unsupported boot generations/layouts,
three raw readbacks, three modified MK/Omni inputs without safe code space,
one unchanged DE-enabled input, and one incomplete 80-KiB MK BU40N input rejected
before capability reporting. Unsupported does not mean corrupt or wrongly extracted.
The raw captures are retained; the WH16NS60 readback is classified as dump.

The machine-readable [per-input ledger](mediatek-modify-results-20261027.json)
binds each result/refusal to its input hash, and each generated result to its
output hash, placements, settings and execution receipts. The final review inspected
each generated entry and its native-control/placement evidence. This is review of
the changed code and contracts, not disassembly of every unchanged ROM instruction.

## Bugs found and corrected

1. Boot initialization restored R3 and then overwrote it with the native target.
   The trampoline now preserves R0-R3/R4, aligned SP, native return value and NZCV.
2. Native response selection chose the wrong writer on 14 inputs. Selection now
   binds registered command consumers, caller operands, buffer normalization,
   writer/committer cells and balanced saved frames.
3. SRAM loop analysis invented copy/clear lengths and treated data literals as
   code entries. Count/stride/pre-test semantics, zero-length loops and decoded
   reference ownership correct those false refusals. Guarded storage covers all
   flag/scratch bytes and stays below the conservative placement ceiling.
4. A classic reverse selector returned into the second half of the forward
   selector's new BL. Emission resolves the already-taken native conditional
   chain; combined-selector execution reproduces the old invalid instruction
   and passes with the corrected continuation on all 24 classic inputs.
5. HRL rejection restored R3 and then overwrote it with the branch target. Both
   continuations now preserve it. Every clean continuation replaces the lookup
   result before use; execution follows that native path, not only the detour.
6. Explicit BD/UHD Off compared against reserved class 0xFF and could compare
   equal. It now compares the known-zero Off flag with one. Both gates refuse
   every class byte, without enlarging their stubs.
7. VID Gate-A used live writer source/count registers as scratch. It now saves
   and restores all R0-R12 arguments around the reset and both continuations,
   retains the displaced CMP flags, balances SP and preserves its saved return.
   The stricter regression fails on the prior output and passes on all 178 images.

The known-answer snapshots were updated only for these reviewed emitted-code
changes. The independent handler-byte, changed-region, integrity and CPU assertions
remain enabled. No hand-encoded Thumb instructions were introduced.

## Final execution and workflow coverage

| Check | Inputs | Executions/comparisons |
| --- | ---: | ---: |
| Advertised settings, reopen, sign and Flash admission | 193 | 2,336 choices |
| Installed authentication hooks, registers/SP/CMP flags | 178 | 34,432 |
| Explicit native BD and UHD controls, all byte classes | 53 | 325,632 |
| HRL continuations and native clean behavior | 178 | 5,680 |
| Region FIFO bytes and complete native return frame | 178 | 42,720 |
| AKE/VID/deny arguments, return addresses and reset ABI | 178 | 44,760 |
| Native writer/committer contracts | 197 | 6,304 writes; 2,364 queues |
| Classic routing | 24 | 118,656 |
| Classic Disc Information entry | 24 | 345,648 |
| Classic native speed selector/tail | 24 | 23,040 |

Modern speed review covers 165 inputs: 146 R2-index and 19 R0-index layouts.
Their native continuations replace the scratch index before consuming it, or
return with it dead under the native ABI; the R2 cleanup callee replaces it before
use. Source-bound traces and the final detour inventory were inspected. No new
literal pointer enters the interior of an overwritten instruction pair.

The final complete Rust suite, Clippy, pinned independent CPU tests and dev CI
are recorded with the handoff. The held-input settings test now runs in bounded
independent shards, retaining the same assertions and exact input/output hashes.
CI and QA include pinned modern/classic HRL, Region and encryption workflow tests.

## Placement and limits

Code allocation requires erased space inside native integrity coverage and outside
boot, mirror, descriptor, integrity-table, signature and drive-written storage.
Coverage extension must match the independently recovered native programming span;
unused records cannot become code. Re-signing and Flash admission check the final
bytes. SRAM placement uses decoded references, native loop semantics, guards and
boot ordering. These are static/software checks; they do not measure every runtime
heap/interrupt workload on hardware. Hardware reset primitives in CPU tests are
ABI simulations. No drive was accessed or flashed during this audit.

The BH16NS48 1.02 test output is built through normal Modify with Unrestricted On
and other controls at OEM defaults. It is ready for the requested physical test;
this report does not claim physical MT1939 UHD reading has already been demonstrated.

Historical checkpoints and red/green findings are retained in the
[audit journal](mediatek-modify-contract-review-20261027-journal.md).
