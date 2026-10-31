# MediaTek 0.16.0 implementation review

Scope: the 123 retained OEM inputs (82 newer MT1959, 12 older MT1959,
29 classic MT1939) in `mediatek-oem-only-123-retained-20261031.json`.
Baseline: `5651c2334ddf30a86ce3b0bf5743c7ca43969c8c`, with pre-existing documentation
cleanup preserved separately. No dependency revision change was needed.

## Prioritized findings and disposition

1. **Acceptance membership was stale.** `scripts/firmware_execution/scope.py`
   required 126 inputs, 85 newer rows and three raw-readback refusals. It could
   not validate the retained inventory. It now requires exactly 123 distinct
   inputs, the 82/12/29 groups, zero refusals, and a digest of the exact reviewed
   `(input SHA-256, group)` membership. Counts alone cannot admit a replacement
   input or a group swap. This digest is solely an evidence-membership guard;
   it is never consulted by production recognition. Six regression tests cover
   substitutions, swaps, omissions, duplicates, modified inputs and native-only
   evidence. Historical receipts remain immutable.
2. **The base builders repeated expensive native analysis.** The scanner,
   command table, response writer/committer and SRAM references were repeatedly
   reconstructed from the same immutable input. Create and modify now retain
   one existing library `ImageAnalysis` per build, use its connected command
   scanner and dispatch facts, and pass that object into handler emission.
   `SramPlacement` owns one `RamReferences` result and borrows its set for the
   existing placement and guard algorithms. It does not clone that set.
   No global cache, hash-based recognition, weakened guard or dependency fork
   was introduced.
3. **Dead experiments and stale boot assumptions obscured current behavior.**
   Removed the always-true `CLASSIC_BOOT_BLESSED` branch, the unused HRL-wipe
   template, its false enable flag, unused private state constant and no-op glue.
   The real classic unique-caller guard remains. Replaced a stale, hoard-gated
   test that expected classic emission to fail with a committed-fixture test:
   qualified resolution succeeds, and missing/duplicate callers refuse. Removed
   contradictory reboot explanations and corrected default initialization and
   hardware-evidence claims. One obsolete template-only test was removed;
   the library suite now contains 237 tests.
4. **Similar matcher and helper implementations have different contracts.**
   They were inventoried, not mechanically merged. The classic mask matcher
   normalizes both operands, the core matcher expects a pre-masked value, and
   `thumb_asm::find_one_in` counts non-overlapping matches. The engine's
   variant scanner permits overlaps and rejects ambiguity across variants.
   Conflating these changes acceptance. Two short selector/tail implementations
   also differ in C7 continuation and optional relocated literal replay.
   Their small common instruction sequences do not justify replacing clear
   layout-specific emission with a generic rule engine in this change.

## Ownership and data flow

Paths in this section refer to the final source snapshot. Dependency paths are
relative to the pinned dependency root; the snapshot and receipt retain its
exact source bytes and file hashes.

| Stage | Owner and evidence | Boundary |
| --- | --- | --- |
| Input recognition and native facts | `mediatek-optical/src/image/analysis/{image.rs:76,command.rs:7,dispatch.rs:110,response.rs:175,ram.rs:12,uhd.rs:392}` | Immutable source, typed ambiguity/absence/contract errors, decoded operands and connected native control flow. |
| Family/lineage dispatch | `engine/mt1939.rs:119`, `engine/profile.rs:89`, `api.rs:286` | Family selects a builder; it does not substitute for structural role qualification. Raw-readback refusal is retained. |
| Settings policy | `boot.rs:232`, `boot.rs:247`, `api.rs:286` | Advertised support comes from installed facts, including narrower Unrestricted choices when refusal is unavailable. Invalid requested choices fail validation. |
| Build orchestration | `engine/mt1959.rs:120,359`, `engine/mt1939_classic.rs:249,536` | One source analysis per base; native saved-LR handler guard remains in `core.rs:721`. |
| Patch planning | `engine/mt1939_uhd.rs:24`, `engine/mt1959_uhd.rs:64` | Source-bound complete groups, exact displaced instructions, distinct classic and later layouts. |
| Allocation | `engine/code_space.rs:227`, `engine/sram.rs:7` | Flash reservations, authenticated extents and deterministic placement; conservative SRAM ceiling and four-byte guards. |
| Emission | `core.rs:1511`, `mt1939_uhd.rs`, `mt1959_uhd*.rs`; `thumb-asm` | freemkv settings and injected behavior belong here; generic assembly, branch encoding and instruction decoding belong in thumb-asm. |
| Structural verification | `install_guard.rs`, `engine/audit.rs:206`, plan `verify`, CMAC and boot metadata validation | Exact emitted bytes/branches, source spans, register/continuation contracts and integrity. Internal regeneration is not an independent functional oracle. |
| Execution evidence | `examples/firmware_execution_evidence.rs`, `scripts/firmware_execution/{corpus,scope,stages,native,conversion,cpu}.py` | Actual production API and CLI outputs, independently encoded expected behavior, native-versus-patched CPU traces and mutation sensitivity. |

The sibling Pioneer reference (`pioneer-optical/src/analysis/mod.rs:1`) also
keeps read-only source decomposition in the library and comparison/policy in its
consumer. MediaTek's already-existing lazy `ImageAnalysis` follows that model;
reusing it is preferable to introducing another recognition abstraction.
Native flash/boot/HRL/region/AKE recognition still partly lives in `core.rs`.
Moving that public finder surface into mediatek-optical would be a separate API
migration; this change does not pretend that layering cleanup is complete.

## Scans, signatures and layouts

The inventory contains **146 literal mask declarations, 144 unique normalized
patterns**: 20 declarations in freemkv-fw and 126 in mediatek-optical. The two
exact duplicate groups are two-instruction checks at `legacy_di.rs:188,192`
(the two native failure blocks) and `uhd_keys.rs:87,143` (different diagnostic
contexts). Neither is a duplicate whole-image scan or an unused experiment.

The accompanying `mediatek-review-20261031-signatures.json` records literal
halfword-mask arrays with file/line, normalized masks, source hashes, and every
matching retained input hash plus match count. It includes inline masks and UHD
layout definitions. These are **candidate pattern counts**, not a count of
fully qualified contracts: decoded instruction grammars (notably the connected
scanner), dynamic patterns, and receiver analysis are explicitly outside that
literal-array count. `mediatek-review-20261031-scan-sites.json` inventories
remaining call sites; static call-site counts are not runtime scan totals.

Examples demonstrating necessary semantic qualification:

- `core.rs:107` flash-program prefix: two raw matches in each of 123 inputs;
  `find_flash_program` additionally binds mailbox/controller/descriptor literals.
- `core.rs:138,167`: modern boot shape matches 96 retained images, classic leaf
  shape 112. Their corpus overlap is real. Modern-first fallback and decoded
  convergence/initializer binding must remain; broadening one merged pattern
  would manufacture ambiguity or select the wrong boot site.
- `core.rs:260,279`: read-ramp register variants match 84 and 10 inputs. The
  classic selector has separate native RMAX/consumer evidence; it is not a
  modern ramp with a different model label.
- `core.rs:297,320,351` and `mt1939_classic.rs:48`: AKE layouts differ in AGID
  register, reject-site placement, shared setter join and saved return frame.
  Prefix match counts overlap; operand and continuation qualification selects
  the role. The cross-variant ambiguity and setter-ABI mutation tests remain.
- The inventory's native role variants include 41 classic forward/reverse
  selections and 82 modern ones. DI has classic, register, stack and U-flag
  layouts; control and parameter roles separately vary. A lineage label alone
  cannot safely merge their instruction/data layouts.

The final exports contain seven observed combinations of the six media-role
layouts, nine including hardware-default variants, and five installed-helper
bundles (including the 82 native-UHD images that need none). These are observed
corpus combinations, not a Cartesian product of independent feature choices.

Base-stage native analysis counts, determined from the before/after call graph:

| Entry point | Connected scanner before → after | Response contract before → after | RAM-reference analyses before → after |
| --- | --- | --- | --- |
| Modern create | 5 → 1 | 1 → 1 | 3 → 1 |
| Modern modify | 5 → 1 | 1 → 1 | 2 → 1 |
| Classic create | 7 → 1 | 3 → 1 | 2 → 1 |
| Classic modify | 6 → 1 | 3 → 1 | 2 → 1 |

These counts cover base preparation and handler construction, not later feature
finders, evidence export, allocation retry, or repeated complete API calls.
The original call sites are at baseline `mt1959.rs:145,384`,
`mt1939_classic.rs:269,577`, and `core.rs:1593`. The final shared analysis is at
`mt1959.rs:145,377`, `mt1939_classic.rs:260,553`, and `core.rs:1511`.

Other duplication reviewed and retained deliberately:

- `mt1939.rs:129` and `core.rs:481,494,525` matchers have the normalization,
  alignment/overlap and error differences described above; `thumb-asm/src/lib.rs:316`
  advances by the entire pattern length. No shortcut removes the cross-variant
  uniqueness check in `core.rs:552`.
- `mt1939_uhd.rs:825,845,893` and `mt1959_uhd.rs:473,532,574` duplicate tail/CV
  instruction sequences but retain different C7 destinations and relocation
  needs. Emission remains Thumb-1 where required; ISA mutation tests remain.
- `mt1939_uhd.rs:35,60,83` regenerates prepared patches during verification and
  repeats source digests in component accessors. This is redundant host work,
  but preserves the public source-binding and verify contracts. No expectation
  was derived from patched output to eliminate that work.
- `mt1959.rs` re-inspects some AuthCell and conversion roles; `code_space.rs`
  scans progressively written output for each allocation. Those scans see
  different policy/verification contexts or mutated output. Extending caching
  to them requires an explicit invalidation contract, so it was not inferred
  from byte equality on this finite corpus.
- G07/G08 diagnostics have actual audit-example and test consumers
  (`examples/mt1959_conversion_audit.rs:56`, `mt1959_uhd.rs:116,760`); they are
  not dead code and still cannot authorize or block G01–G06 conversion. No
  abandoned authentication conversion work was revived.

## Validation and measurement

Final machine-readable results and exact hashes are recorded in
`mediatek-review-20261031-signoff.json`. The defined software-contract scope
passed for **123/123 newly rebuilt and executed outputs**, all five settings
available, zero production refusals and no input membership changes.

- 2,019 installed stages: 5,249,574 passing CPU cases.
- 492 native stages: 839,024 passing CPU cases. The lower native total versus
  the historical receipt excludes the three withdrawn native-only inputs.
- 237 Rust library tests passed; 13 integration tests passed. The extra
  seven-published-package integration test remains explicitly ignored because
  its optional `FREEMKV_BU40N_PACKAGES` fixture is not supplied. The required
  retained production scope is independently executed in full. Integration
  flash roundtrips use mock transport, not physical hardware.
- 45 Python tests ran: 43 passed and two fixture-inapplicable skips: classic AKE Off
  invokes its setter directly and has no modern reset prefix. A separate
  newer-firmware AKE run passed all seven tests with zero skips, covering
  both reset-prefix checks.
- All 282 reset-continuation mutants were detected on 94 actual outputs.
  Source/signature ambiguity, Thumb ISA, continuation, live-register, native
  setter, DI routing, native arithmetic and explicit-memory mutations remain.
- `cargo fmt --all -- --check`, `cargo clippy -p freemkv-fw --all-targets --
  -D warnings` and `git diff --check` passed. The build, dependency, binary
  and post-native source-freeze checks all passed.

The pre-change production run reconstructed all 123 retained outputs and matched
all 123 historical canonical/output hashes. Its CPU stages were deliberately
not requested; it is a byte/performance baseline, not new execution coverage.
The post-change run rebuilds from the final sources and executes every installed
stage and relevant native role, with byte equality against that fresh baseline
required by the scope acceptance gate.

Timing covers the production API's combined analysis/build path, including
planning, emission, CMAC and boot metadata. The paired measurement alternates
before/after process order across all 123 inputs. It is not a decoder-only
microbenchmark and says nothing about injected firmware execution speed.
Across all 123 paired builds, summed production API time fell from **249.70 s
to 156.49 s (37.33% less time)**. Reductions by group were 38.58% classic,
39.13% newer native and 26.57% older conversion. This is one sequential paired
round on this host, with normal timing variance; the full per-input values and
executable hashes are in `mediatek-review-20261031-performance.json`.

Installed handler and conversion-helper lengths/hashes are compared separately.
All 123 output BINs are byte-identical. The measured 123 handlers total 93,002
bytes; 906 installed conversion helpers total 190,000 bytes. Every compared
helper length/hash is unchanged, for a zero-byte size delta.

The historical 97/98 website model/revision coverage is retained because input
membership and supported settings are preserved. BP50NB40 1.00 remains excluded.
Hardware validation remains **0/123**. Finite source-bound software contracts do
not prove every RAM state, resident service, insertion ordering, optical
acquisition, controller/MMIO behavior, physical reading or AACS completion.

## Requested hardware-test image

`BH16NS48_1.02_UHD_ON_ENC_OFF.bin` was produced from retained input
`43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3`.
The CLI used `--default unrestricted=on --default encryption=off --audit`;
HRL, speed and region remain OEM. Encryption is the consolidated AKE/content
setting. The structural audit passed, and all 35 installed helper contracts
were rerun against the customized bytes: 150,318 passing CPU cases. Its exact
output digest, settings and bounded results are in `mediatek-review-20261031-bh16ns48.json`.
The Desktop receives only this BIN; no hardware flashing was performed.

## Reproduction

Create a private Python environment from `scripts/firmware_execution/requirements.txt`.
Run the Rust library tests first and retain their log, then run:

```sh
python scripts/firmware_execution/scope.py --build \
  --inventory internal/docs/audits/mediatek-oem-only-123-retained-20261031.json \
  --hoard /opt/review-home/Developer/firmware-extractor/hoard \
  --builder target/release/examples/firmware_execution_evidence \
  --fw target/release/freemkv-fw --output /tmp/freemkv-review-reproduction \
  --workers 6 --dependency-commit 9456d3a9154e10f60ad8745c81a6e2c4c4eec0c8 \
  --handler-rust-test-log /path/to/final-source-rust-tests.log \
  --baseline-receipt internal/docs/audits/mediatek-review-20261031-baseline-receipt.json.gz
```

The saved benchmark, inventory and deny-mutation scripts record their run-local
paths explicitly. Repoint those paths when reproducing elsewhere. The baseline
and final source snapshots bind the exact sources; their saved receipts bind
binary digests, inputs, outputs and CPU trace digests. Raw run directories and
trace files remain under `/tmp/freemkv-review-{baseline,clean-final}` locally; temporary
paths are not a promise of permanent raw-trace storage.
