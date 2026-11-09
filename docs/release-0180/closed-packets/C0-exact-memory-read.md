# C0: explicit partial and exact firmware-read contracts

Status: IMPLEMENTED AND TARGETED-TESTED in isolated local checkout; root inspected the patch. This component supplies future live-condition consumers; it does not close a whole filter gate or admit a correction.

Baseline: firmware 4e80beb252125f9a4606bc4804cc945a1c817d9c; Pioneer f16f0e9e381df138aa8d6f3ab97b9ee42b58a73b. Root creates a separate implementation checkout under /Users/matthew/Developer/tmp/. Never edit frozen fw-integrate/po-integrate or proof inputs. Preserve other work.

## Problem and invariant

`crates/freemkv-flash/src/transport.rs:260` calls a count-returning protocol read, truncates and returns success even on a short response, despite its `read_memory_exact` name/documentation. Two current callers exist. Backup `read_chunk` independently rejects incomplete data. Backup `prepare_firmware_read` deliberately retries successful short responses up to three reads but stops on explicit transport/protocol errors. A global conversion of short success into error without adapting the probe breaks that behavior.

A successful exact read must contain exactly the requested bytes. A partial read must return the actual response bytes without invented zero padding. Both APIs perform exactly one underlying protocol read with its normal preceding unlock knock and introduce no retries. Original transport/protocol errors propagate through existing `flash_err` conversion. Oversized SCSI responses are already rejected by `ScsiTransport` and remain errors. Zero-length behavior remains the underlying protocol behavior; a successful zero-length response satisfies the exact contract.

## Owned files and algorithm

One SOL worker owns only:
- `crates/freemkv-flash/src/transport.rs`
- `crates/freemkv-flash/src/transport_tests.rs`
- `crates/freemkv-flash/src/backends/pioneer/backup.rs`
- `crates/freemkv-flash/src/backends/pioneer/backup_tests.rs` only if extending the existing targeted regression is needed.

1. Move the existing helper body, unchanged, to `pub fn read_memory_partial(dev: &mut dyn ScsiDevice, off: u32, len: u32) -> Result<Vec<u8>>`. Document one read returning at most len bytes and no retry.
2. Keep the original public signature `read_memory_exact`. Call `read_memory_partial` exactly once, then reject `data.len() != len as usize` with an anyhow error naming address, actual length and requested length. Return the original bytes only on equality. No padding, concatenation, re-unlock/retry or conversion of transport errors into a length error.
3. Switch ONLY the probe in `prepare_firmware_read` to `read_memory_partial`. Preserve its three-attempt budget, 100ms gaps, re-knock each attempt, immediate explicit-error exit and diagnostics. Keep `read_chunk` on the exact helper; its redundant length guard may remain to minimize unrelated changes.
4. No protocol-crate edit, CDB literals in production, new dependency, route/registry/identity changes, device access or correction admission.

## Targeted evidence and commands

Use existing `MockScsiDevice` or a small scripted ScsiDevice test double in transport_tests. Test exact success returns identical bytes; short (including zero-byte) success rejects with actual/requested/address; partial success preserves actual short bytes; explicit error remains error without another request; oversized response remains rejected (existing regression); zero-length successful exact response is empty if underlying protocol permits it. Assert one knock/read sequence for each one-shot wrapper; do not accept an implementation that retries internally. Keep the existing `read_access_probe_retries_only_short_reads_and_reknocks` regression: it covers short-short-full, three shorts, short-then-sense and first explicit error.

Run fmt/clippy + directly targeted tests only; CI runs full suites. Set CARGO_TARGET_DIR under the implementation scratch directory. From implementation checkout:
- `cargo fmt --all -- --check` (format owned edits first as needed; do not sweep unrelated files)
- `cargo test -p freemkv-flash --lib transport::tests::`
- `cargo test -p freemkv-flash --lib read_access_probe_retries_only_short_reads_and_reknocks`
- `cargo clippy -p freemkv-flash --lib --tests -- -D warnings` if baseline supports it; report unrelated baseline failures without broad repair.

Report source revision, patch/diff, exact test results and any baseline dependency constraint. No commit, push, merge, physical device operation or Desktop publication. Retain only source patch and necessary targeted results; clean disposable build output after use. Estimate 20–40 minutes including compilation, one worker. Root owns checkout and integration decision. This packet can run concurrently with all native feasibility analysis because it touches no frozen input or semantic proof record.

Implementation receipt: `/Users/matthew/Developer/tmp/filter-implementation-0180/c0-evidence/C0.patch`, SHA256 `3097df958a37bfbe055dfc230c2c2e6d557c694c50ce308d41776602c4f748f0`. Source checkout `fw-read-contract` retains uncommitted changes in transport.rs, transport_tests.rs and backup.rs. Eight transport tests plus the existing probe regression pass; fmt, clippy, library build and diff check pass. Build target removed. No gate credit or route change. Warm compilation made the original 20–40 minute estimate conservative; actual root-reported coding/test interval was approximately three minutes before final checks.
