# Pioneer 0.17.3 settings regression evidence

**Current status:** generated native migration tests and the exact-archive receiver workflow pass. Final immutable dependency pin, dev CI, full-hoard comparison and release QA remain pending.

The early host-only bypass experiments below are historical evidence. The final policy retains bank compatibility checks and supports the audited pair through an actual record migration. Synthetic partial firmware cannot authorize that migration. The original unchanged-bank startup failure is retained as an unconditional negative control; positive tests execute the generated migration and then the target guard.

Final dependency pin: `241b614773ec5c044e3af73601f486387be19a24` (production conversion commit `63a287d`, followed by two read-error tests).

Final implementation saves full raw banks before startup-word changes, retains an authenticated temporary-firmware archive, verifies that bridge and the unchanged Kernel, saves fresh banks, and binds the final update command to those records. Generated H8 code verifies live bank hashes before mutation, preserves a complete source bank, verifies programmed pages and publishes validity magic last. BNK0 restoration and BNK1 migration are distinct validated controls. Unsupported bank conversions remain refused even with family override.

Validation completed before the pin: nine unconditional native-payload tests, both real PreparedUpdate→native H8→target-guard capacity cases, six receiver integration tests with 22 faults, two additional pointer-read failures, exact customer provenance, and the UD02/UD04 corpus matrix. Latest measured receiver line coverage was 333/350 (95.14%) before the two additional read-error cases; no blanket 100% or measured branch-coverage claim. Remaining unmeasured lines include private immutable-plan invariants. Final pinned-source CI and full-hoard QA are still required.

## Earlier investigation and reproducible evidence

The customer report used 0.17.2 and explicit family override: BDR-212U 1.01 (SAT8F01/ID83) to BDR-213U 1.02 (SAT9201/ID58). Preparation failed with `pioneer.startup.bank_conversion_required` before firmware writes.

The exact retained source archive is `276c667ac1383c3aac110cbb433bd8627e49d626ac7c2136b1fa9dd29ecd11a7.installer.tar`; target is `967c3e42c65ae54802d9b6e1480e3fdf5f70b5de0d875da65731ab8567065415.installer.tar`. Their names are their SHA256 hashes. The corpus regression verifies both complete archive hashes and all 62 memory-read hashes from the customer log before exercising the application recovery preparation path.

`pioneer-212u-213u-bank-contracts.json` retains small native fragments at their original offsets: complete bank validator, capacity address calculation, reject helper and binding call sites. Synthetic surrounding firmware supplies existing test receiver/signature fixtures. The exact-corpus test verifies every fragment against decoded OEM code and verifies the full decoded Normal hashes. This avoids distributing full OEM images and does not claim that the synthetic surrounding image is OEM firmware.

Two tests failed against the original 0.17.2 dependency (`5051f06025b74e4e840a236951a7a3461a1dc98b`), each with the actual bank-conversion refusal, then passed with the explicit-policy fix candidate:

- `customer_212u_101_to_213u_102_recovery_prepares_without_bank_conversion_refusal`: exact customer source/target, actual application preparation. RED `/tmp/fmkv-pioneer-0173-red.log`, GREEN `/tmp/fmkv-pioneer-0173-green.log`.
- `pioneer_212u_213u_bank_contract_regression`: unconditional native-code-fragment KAT plus mocked recovery execution. RED `/tmp/fmkv-pioneer-0173-minimal-red.log`, GREEN `/tmp/fmkv-pioneer-0173-minimal-green.log`.

The fixed answers retain distinct FEDC4321 and FEDC4322 bank contracts, ordinary non-bypass refusal, startup parameter 009F=FFFF (implicit), no hardware adaptation and no 028F requirement. The mock executes transfer, restart and Kernel verification; this is software protocol evidence, not physical drive signoff.

`pioneer_crossflash_transition_routing_known_answers` provides unconditional literal forward, reverse, unsupported and malformed factory-product routing answers. The separate retained UD02/UD04 corpus KAT checks the actual transformed Normal SHA256 `ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815`, adaptation `pioneer.ud02-to-ud04-1.14` and required hardware parameter 028F=0001. Full image hash guards remain intact; sparse fixtures do not impersonate a certified full image.

Mandatory local corpus invocation (missing corpus fails, never silently skips):

```sh
export PIONEER_SETTINGS_HOARD=/Users/matthew/Developer/firmware-extractor/hoard
cargo test -p freemkv-flash --lib customer_212u_101_to_213u_102_recovery_prepares_without_bank_conversion_refusal -- --ignored
cargo test -p freemkv-flash --lib held_ud02_ud04_settings_are_prepared_by_the_normal_live_authorization_path -- --ignored
```

Release signoff must additionally execute both corpus tests explicitly; the mandatory CI gate below checks the unconditional tests independently of corpus availability.

The four unconditional `bypass_transaction_tests` now cover 14 startup-word transaction scenarios with compatible bank contracts and an explicit native startup requirement. The initial host-only experiment used differing bank contracts; that escape was removed after native execution proved conversion necessary. All four failed on released dependency `5051f06` at `Startup(Banks(ConversionRequired))`; all four passed on the candidate (0 failures, 0 ignored). Evidence logs are `/tmp/fmkv-pioneer-0173-transaction-red.log` and `/tmp/fmkv-pioneer-0173-transaction-green.log`.

- Successful change: literal `009F` read/write/read precedes update entry; FF01 becomes FE24.
- Already-correct FE24: read only, no settings write.
- Seven failures before firmware: initial read error or short read, rejected write, accepted write with lost acknowledgement, verification read error, short read or mismatch. Initial read failures write nothing; subsequent failures restore FF01 and verify it. No update command is attempted.
- Five failures after the first update attempt: entry, Kernel transfer, Normal transfer, finish or Kernel readback. FE24 remains in place, rollback is forbidden, and the error explicitly reports retained startup settings.

The tests use fixed CDB bytes and fixed startup/rollback values, assert exact parameter event sequences, and reject unrelated A0 settings access. They preserve ordinary preparation refusal and require no adaptation or hardware-setting requirements.

CI explicitly runs all six unconditional Rust KATs and the explicit native-startup release blocker through `.github/scripts/test_pioneer_settings_kats.py`, in addition to the existing test suite. Each exact test must report one pass and zero ignored tests; a renamed, missing or unexecuted test fails the gate. The ignored `backends::pioneer::prepared_tests::native_startup_tests::native_212u_to_213u_populated_banks_must_boot` is explicitly invoked with `--ignored`; its current failure blocks QA/release. No local OEM corpus or environment variables are needed for this mandatory gate.

## Native startup release blocker

`native_startup_tests.rs` fetches and steps the exact 146-byte OEM target bank guard fixture, starting after its stack allocation at CPU address 5509F4 and stopping at the normal epilogue, native write call 550E04 or native rejection call 4AFA7C. Unknown opcodes and exhausted instruction budgets fail. The full-corpus test compares the binary fixture with target decoded Normal bytes at 1409E8..140A7A. This is bounded native guard execution; it does not simulate the whole boot, native flash writer or arbitrary bank-record migration.

Fixed-answer controls cover both capacity geometries:

- Compact source headers FEDC4321 at 5EFFFA/5FFFFA: target reads 5F3FFA/5FFFFA and calls rejection. The second marker overlaps, so even an otherwise erased payload fails.
- Extended source headers at 7DFFFA/7EFFFA with erased interior bytes: target reads 7DBFFA/7E7FFA and reaches its initialization call. This does not establish safe migration or successful initialization.
- Representative occupied source payload at the target marker addresses: rejection in both geometries. Source headers and sequence words are preserved. This is a constructed counterexample, not a captured customer payload.
- Either target-native FEDC4322 marker: guard accepts in both geometries.

The desired compact crossflash boot test is **RED**, exit 101, because native execution reaches `Reject(0x4AFA7C)` instead of `Accepted`. Evidence: `/tmp/fmkv-pioneer-0173-native-boot-red.log`. It is explicitly ignored in routine tests to retain a reviewable failing test, **not** to waive release. Mandatory release gate:

```sh
cargo test -p freemkv-flash --lib native_212u_to_213u_populated_banks_must_boot -- --ignored --nocapture
```

No safe persistent-record converter is demonstrated. Do not release a host-only refusal bypass as a working 212U→213U fix while this gate fails.

Validation order is compile/test first, corpus QA second. Dev CI compiles and tests the Rust examples (`cargo test --locked --examples`), executes the exact Rust KATs, and runs the normal test suite. Python only invokes Cargo and checks that each named Rust KAT actually ran; firmware answers and transaction assertions remain in Rust. QA's fixture-corpus job depends on both exact-tree dev proof and successful release compilation/tests on all three operating systems.

Hosted QA currently provisions only the committed OEM fixtures. It has no private full-hoard download or self-hosted runner mechanism. Full local Pioneer corpus comparison uses the existing Rust test `golden_corpus_tests::pioneer_corpus_full`, with all three variables `FREEMKV_PIONEER_CORPUS`, `FREEMKV_PIONEER_CORPUS_OUT`, and `FREEMKV_PIONEER_CORPUS_BASELINE` set. The baseline is mandatory: missing environment/path/family files, an empty eligible corpus, or output aliasing the baseline now fails before executing the full corpus. Do not start this full-hoard phase until compilation, Rust examples and KATs pass; the two explicit pair/cross-flash tests above remain additional focused checks rather than substitutes for the full family comparison.

Validation order after adding the native guard fixture: compile the Rust application test target, execute `native_213u_guard_known_answers` (1 passed), then execute only the two-archive customer provenance test (1 passed, including the 146-byte fixture comparison), then explicitly execute the desired native-boot gate (failed, exit 101). Logs: `/tmp/fmkv-pioneer-0173-native-kat.log`, `/tmp/fmkv-pioneer-0173-native-fixture-provenance.log`, `/tmp/fmkv-pioneer-0173-native-boot-red.log`. No full-hoard QA was started in this phase.


Local inventory on 2026-11-01: hoard `/Users/matthew/Developer/firmware-extractor/hoard` contains all 723 indexed package paths (668 branded PIONEER). Index SHA256 is `b89a2e24618f4ba04b78b192c2308a27d32b59078fa6d29e27a741e0ae30197a`. This is availability evidence, not a firmware test pass or archive-content hash verification. No full family transcript baseline was found in the inspected repository, temporary or freemkv cache locations. The `v0.11.2` tag does not contain this corpus harness; its documented historical baseline required an adapted harness. A separately established baseline must be restored or generated with independently pinned old code before local full-hoard signoff. Candidate-generated output must never supply its own baseline.

After compilation and all mandatory Rust KATs pass, and an independent baseline is available, the full local comparison command is:

```sh
FREEMKV_PIONEER_CORPUS=/Users/matthew/Developer/firmware-extractor/hoard \
FREEMKV_PIONEER_CORPUS_BASELINE=/absolute/path/to/independently-established-baseline \
FREEMKV_PIONEER_CORPUS_OUT=/absolute/path/to/new-candidate-transcripts \
cargo test --release --locked -p freemkv-flash --lib \
  golden_corpus_tests::pioneer_corpus_full -- --exact --ignored
```

The placeholder baseline is intentionally not a claimed available artifact. No full-hoard run was started while the native startup KAT remained failing. Private firmware stays local; a later QA receipt can retain source/dependency revisions, input index and baseline hashes, tested/skipped family counts and result hashes without uploading firmware.

## Reproducible released-code baseline preparation

The regression baseline is now **released 0.17.2**, not the historical 0.11.2 comparison. An isolated checkout exists at `/Users/matthew/Developer/freemkv/.worktrees/pioneer-baseline-0172`, detached at `96f222cf85bded408d83622477676e54f37c5fa4`. Its only modification is the test-only patch `.github/scripts/pioneer_0172_baseline_capture.patch`; Cargo.lock and production code remain the released versions, including Pioneer dependency `5051f06025b74e4e840a236951a7a3461a1dc98b`. The patch creates the distinct ignored Rust capture test `golden_corpus_tests::pioneer_0172_baseline_capture`. It never uses candidate code to generate expected output.

Recreate that harness from the candidate checkout with:

```sh
git worktree add --detach ../.worktrees/pioneer-baseline-0172 96f222cf85bded408d83622477676e54f37c5fa4
git -C ../.worktrees/pioneer-baseline-0172 apply "$PWD/.github/scripts/pioneer_0172_baseline_capture.patch"
```

Compilation only passed with `CARGO_TARGET_DIR=/tmp/fmkv-pioneer-0173-target cargo test --locked -p freemkv-flash --lib pioneer_0172_baseline_capture --no-run` in that checkout. Log: `/tmp/fmkv-pioneer-0172-baseline-compile.log`. No full-hoard capture has run. Compile warnings concern comparison helpers unused by the capture-only test; production code was not changed.

**Only after candidate compilation, examples and every mandatory KAT pass**, execute this in the released-code checkout, reserving the shared target first:

```sh
FREEMKV_PIONEER_CORPUS=/Users/matthew/Developer/firmware-extractor/hoard \
FREEMKV_PIONEER_CORPUS_OUT=/tmp/fmkv-pioneer-0172-baseline \
CARGO_TARGET_DIR=/tmp/fmkv-pioneer-0173-target \
cargo test --locked -p freemkv-flash --lib \
  golden_corpus_tests::pioneer_0172_baseline_capture -- --exact --ignored
```

The destination must not exist. Capture pins the index hash listed above, checks package hashes through the existing corpus loader, and writes `_baseline_provenance.json` with the released source/dependency identities, compiled lockfile/harness hashes, inventory hash, package/family/skip counts, and each transcript hash. The proposed `/tmp/fmkv-pioneer-0172-baseline` is an output destination, **not yet an available baseline**.

Then run the candidate comparison with that directory as `FREEMKV_PIONEER_CORPUS_BASELINE` and a new `FREEMKV_PIONEER_CORPUS_OUT`. It verifies baseline source/dependency provenance, the same inventory and every transcript hash before executing the corpus. Every difference from 0.17.2 fails; historical difference classifications are diagnostic only. Changed expected output requires explicit review, not automatic acceptance. The native startup KAT independently checks the newly required behavior that the released baseline did not support.

## Decoding representation and fixture identity

The full decoded source Normal SHA256 is `014868226d2b9ef07685fb612d0060e4aeee6552dc48aa53371bd2631462d09b`; the full decoded target Normal SHA256 is `4c57a8f1a43367489a24ed591ba3bcd0e87267a07b58d290a8f658d2cc200025`. These are produced from the hash-locked OEM archive components with `Envelope::load(kernel)` then `Envelope::load_with_kernel(normal, &kernel)`. `Update::load` likewise supplies the decoded Kernel when loading Normal.

Standalone `Envelope::load(normal)` is a different, incomplete decoding representation: it omits the Kernel-derived receiver XOR exceptions at offsets 16900 and 77300. Each exception covers one four-byte word; exactly eight bytes differ. The correct source words are `6f40000c` and `f8015e4e`; target words are `80e80f82` and `7920ffff`. This is the proven receiver codec policy, not a firmware patch. The source representation matches all 62 customer memory-read hashes.

`98e93c149c1b3433545fef38976c957687f4f701b4ad70c497e485017e174df0` is solely the SHA256 of the **146-byte native target guard fixture**, not the full target image. Its bytes are compared directly with the correctly decoded target. Do not whitelist that fixture digest as a complete firmware identity.

Independent read-only review confirmed the programmer recognizer's 154-byte constructor and 652-byte copied-code excerpts match the exact correctly decoded source OEM image. Converter ordinary-mode parameter region mapping and bitmap/latest-record scan were compared with native disassembly at source 54E1DC/54E0B8 and target 550144/550020. The alternate reader mode and whole-device behavior are outside those view KATs.

The final two-archive application test additionally binds `programmer::discover` against the exact decoded source and checks the literal erase/program entries 04F0/053C, sector size 10000, runtime interval 04BE..074A and exact copied code. It binds `conversion::LayoutPair` to the same exact source/target, converts representative populated source records with maintenance state 8765 and sequences 7/8, checks the literal selected footer `8765 FEDC4322 0008`, and supplies the actual immutable converter output to the byte-driven target guard for both capacity bases. This completed-record guard check passes; it is not a live conversion, physical programming, interruption recovery, post-guard maintenance or whole-boot proof. Final ordered compile/KAT and two-archive tests pass; log `/tmp/fmkv-pioneer-0173-converted-native-guard.log`. The unchanged-source native release-blocker remains RED.

## Host durability and current local gates

The host implements the dependency's optional `persist_bank_backup` callback. It uses the existing validated, exclusive backup publisher, syncs the file, verifies the published bytes, syncs directory ancestors on Unix, and only then returns the opaque receipt. Storage is the persistent user data directory under `freemkv/drive-backups`; it never falls back to temporary storage. Backup files are created with owner-only permissions on Unix. Diagnostics retain the path and digest, not raw drive data.

The exact two-archive test constructs an immutable full-bank capture, saves and verifies it, rejects overwriting that backup, checks a missing-directory failure produces no receipt, and checks Unix file permissions. This passes in `/tmp/fmkv-0173-durable-bank-backup.log`. The existing publisher's three filesystem tests also pass. The callback is not yet invoked by a live conversion: wiring it into a proven bridge remains required.

Workspace Clippy with all targets/features and warnings denied passes against the local candidate (`/tmp/fmkv-0173-clippy.log`). The Flash library suite previously passed 728 tests before later additions; the remaining workspace packages passed separately. These are incremental local checks, not a claim of final pinned-source dev CI, full-hoard QA, or a release. Final exact-source gates must be rerun after integration.

The workspace `cargo test --examples` does **not** cover dependency-owned examples. CI therefore additionally runs `.github/scripts/test_pioneer_dependency_examples.py`. It resolves the application's locked `pioneer-optical` manifest through Cargo metadata, requires a full immutable git revision matching the resolved commit, verifies that both named example targets exist, then tests and runs `pioneer_startup_checks` and `bank_transaction_contract` from that exact dependency checkout. Eight exact Rust KAT names must each execute and pass; both example binaries must exit successfully. Missing targets, zero test matches, ignored tests, local path patches and mutable branch references fail this gate. These examples remain analysis/transaction-model evidence; they cannot replace the independently required native boot KAT or establish physical flash atomicity. Local orchestration checks and workflow lint passed; actual execution through this new gate awaits the final immutable dependency pin.

## Native SHA-256 helper execution

`pioneer-optical/tests/native_sha256.rs` executes the exact source OEM H8 SHA code through a bounded instruction executor, with no host hashing shortcut: init 4B7030, update 4B70C2 (ER0 pointer, ER1 length), final 4B7396 (ER0 output). Fixtures retain code 4B6418..4B7670, constants 59BE6E..59BF6E and native shift helpers 57EC28..57EC5A / 57ECC8..57ECFA. Unsupported instructions fail. `sha2` is used only as the independent expected-result oracle; empty and abc also have literal standard digests.

Passing vectors include empty, abc, lengths 55/56/63/64/65/127/128 with word-aligned intermediate chunks; 49152, 65536 and 131072-byte patterned storage with both one whole update and 64-byte incremental updates. The bank-length KAT executes up to 45,367,797 H8 instructions per case and completed all six cases in 39.97 seconds. Logs: `/tmp/native-sha-short.log`, `/tmp/native-sha-banks.log`.

The tests assert update/final preserve ER3..ER6 and SP and that writes stay within the 294-byte global SHA context 13C2..14E8, the test stack and 32-byte output. A callback using these helpers must preserve that global context or establish reset/exclusive ownership; interrupt masking alone is not proof of logical context ownership. Repeated unaligned intermediate updates currently fail a separate ignored diagnostic in the executor; that result remains subject to independent opcode/ABI review. The bridge contract validated here uses a whole bank call or 64-byte chunks, not arbitrary streaming chunks.

The pinned-dependency gate additionally requires the native SHA integration KATs `native_sha256_empty_abc_and_block_boundaries` and `native_sha256_source_and_target_bank_lengths`, the CCR instruction control `ccr_capture_mask_restore_preserves_incoming_interrupt_state`, and these three actual generated-payload unit tests under `startup::bank::bridge::execution_tests`:

- `native_payload_preserves_all_geometry_and_active_bank_cases`
- `native_payload_stops_after_partial_erase_program_and_footer`
- `native_payload_clone_failure_retains_valid_source_and_runtime_pointer`

These execute the generated instructions with native SHA and native erase/program wrappers; the emulator models the NOR hardware/task boundary. Host SHA is the independent answer oracle, not a replacement for the executed OEM hash loop. The mandatory dependency gate now invokes 14 exact Rust KATs and two example binaries, with an estimated native runtime around eight minutes. The unaligned incremental SHA diagnostic and full OEM archive provenance remain separate local tests. Actual payload test results must be recorded after their owning agent finishes validation; adding their CI invocation is not itself a pass.

The final pinned-dependency gate includes all nine footer-hardened generated-payload KATs (20 exact Rust KATs plus two example binaries overall). The added payload cases cover installation independent of fresh bank capture, restore/unknown tags, changed runtime vectors, extended-geometry failures, post-clone competing-header mapping, and tampered footer refusal. The payload owner reports the final nine-test suite passing in 129.90 seconds and local exact-archive provenance/public binding passing separately in 30.18 seconds. These results supersede the earlier three-case runtime estimate; the immutable dependency CI gate must still execute the pinned final source.
