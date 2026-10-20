# Pioneer Normal startup investigation (0.13.2)

## Current implementation status

The chronological investigation below contains superseded intermediate safety
decisions. Normal Flash now derives the target word from a recognized startup
comparison, otherwise selects the user-approved neutral 9F/FFFF policy. It
requires a recognized installed native A0 surface, reads/changes/verifies before
update entry, and restores only before any firmware command has been attempted.
SJ/WX supplied-package mock tests cover both directions and failure boundaries.
Recovery from WX 0000 to the original S12JX uses firmware transfer without A0;
physical recovery and the subsequent WX flash remain the user's validation.
No raw persistent-memory fallback is implemented.

The user moved this investigation to 0.13.2. The already QA-green 0.13.1
candidate is released separately without these experimental changes.

## Persistent startup prerequisite: stronger WX1DM evidence

The original S12JX dump SHA-256 is
`e8a851710285f8e7f6a8f1501eba19579ea119860a00941a2d61073d1f6638bb`.
The later WX1DM dump SHA-256 is
`2afdc55c3bd6559c94c11a51bdb3a9c64252cb6b324507052d483b5a84eeec3c`.
The copies subsequently provided in `Anonymous+folder (2)` are identical.

WX1DM Normal startup at `0x45faf8` reads persistent parameter `0x9f` through
`0x54e0a2`, then compares it to `0xfe24` at `0x45fb00`. A mismatch calls
`0x458314(1)` to set bit 7 of RAM `0x144` through the Kernel service table,
then `0x4af3f6(0)` to re-enter the Kernel at `0x400100`. Its startup at
`0x4001ac..0x4001ba` sees that flag and enters the loader at `0x40026a`,
ultimately running the command loop `0x405e1e`. The loader's INQUIRY handler
uses the literal `0000` identity template at `0x406b2a`; Normal's template
contains revision `1.01` and date `23/10/27`.

The parameter reader selects key `0x9984`, unit `0x140`, area `0x1928` and
40 bytes of two-byte slot log. The original dump has valid bank markers
`fedc4321` in both `0x5e0000` and `0x5f0000`. Their sequence numbers are
`0x27` and `0x26`, selecting the first bank. Its slot log selects slot zero;
parameter `0x9f` is at CPU `0x5e9aea`, bytes `ff ff`, so the reader returns
`0xffff`, not `0xfe24`. The earlier S12JX startup has no corresponding check
at the analogous point after initialization.

The opt-in integration witness `pioneer_startup_witness.rs` checks capture
coverage (never placeholder zeros), binds the parser constants and return
branch to the actual WX1DM instructions, selects the active original bank,
and reproduces the mismatch. It passed on the supplied files. It is a traced
prerequisite evaluation, not whole-machine emulation or proof of the later
drive's current persistent bytes. The later Kernel dump cannot read CPU
`0x5e0000..0x600000`, so it does not directly observe their post-flash state.
The order of power cycling and later recovery attempts remains unknown.

This provides a persistent explanation even with complete, correctly paired
firmware in flash. Do not equate it with the separate polling candidate below.
Do not automatically patch the Normal boot check or write `fe24` to persistent
data: the meaning of that requirement and a supported migration/restoration
path need to be established first.

Reproduce with `PIONEER_STARTUP_ORIGINAL_DUMP` and
`PIONEER_STARTUP_TARGET_DUMP` pointing to the two supplied dumps, then run
`cargo test -p freemkv-flash --test pioneer_startup_witness -- --ignored --nocapture`.
The current experimental branch additionally needs the local Pioneer dependency
patch described below; do not publish that absolute path.

## Evidence, 2026-10-19

The WX1DM `0000` dump contains a complete decoded WX1DM 1.01 pair:

- Kernel at CPU `0x400000`, length `0x10000`, SHA-256
  `0394fcc7387c2eefa6f4d7fcb4b7c0d51a60d65a0fee3310f11fab62ab141b90`.
- Normal at CPU `0x410000`, length `0x1bb600`, SHA-256
  `b3602d195a28226f6221f33878a06b9fd00fc294579c5f4bb2a8555e60b5e3f1`.

Both match the held decoded OEM images byte-for-byte and have zero BE32
additive checksums. The boot descriptor, variant tag, length and markers match.
This rules out a missing/partial target image in the readable flash regions at
the time of that dump, not every possible hardware/startup failure. Low RAM
containing the programming flags was unavailable: its state cannot be inferred
from the dump's placeholder bytes. The subsequent S11JX Kernel-write failure
occurred after the dump and is not covered by these comparisons.

## Resident Kernel dispatch

WX1DM 1.01:

- `0x405406` reports whether RAM `0x14d` (programming counter) is nonzero.
- `0x402b00..0x402b26` rejects commands while that counter is nonzero, except
  opcode `03` (REQUEST SENSE). The busy branch skips command completion's
  restart check, returning through `0x402b8c`.
- The RAM programming routine (flash source `0x4013e0`) increments the counter
  at `0x401502..0x401506`. On completion it clears bit 7 of RAM `0x144` at
  `0x401554`, without clearing the counter.
- Allowed commands reach `0x402b72`, calling `0x405418`: bit 6 set and bit 7
  clear means programming has completed. `0x405442` resets the counter and
  jumps to startup at `0x400100`.

PR1ML 1.75 has the same mechanism at different addresses:

- Busy predicate `0x405360`; guard `0x402b2c..0x402b52`.
- Completion predicate `0x405372`; completion check `0x402b9e`.
- Restart routine `0x40539c`; programming completion clears bit 7 at `0x40152e`.

The supplied PR1ML 0.13.0 log contains no explicit REQUEST SENSE requests after
finish, only GET EVENT STATUS and TEST UNIT READY, repeatedly returning
`02/04/02`. When the counter is set, those commands take the busy early return
in these Kernels; the logged code itself is not proof that guard was active.
Transport-level automatic sense handling is not proof that an explicit opcode
03 passed through this dispatcher. We do not have a live observation of the
flags proving this was the only cause of either user's failure.

## PR1ML independent startup check

Decoded PR1ML 1.75 Normal SHA-256
`bdaae2e8f10b6c7cb399fd905d4b4281b1e0bc8195b0830711447eb678d12a2b`
has an analogous check with a different ABI and required value. Entry
`0x412000 -> 0x53abc6`, main `0x5f4cd4 -> 0x48c87a`, reaches
`0x48c964`: R1=parameter `0x9f`, call `0x5f05a8`, compare result with
`0xff01` at `0x48c96c`. Mismatch sets loader bit through
`0x482a54 -> 0x400a1a -> 0x400478`, then calls `0x53acf0(0)`;
its exit reaches `0x53acd2 -> 0x482a36 -> 0x400a04 -> 0x400100`.
The getter resolves a persistent address via `0x5f14b0` and reads low byte
then high byte at `0x5f0610..0x5f0622`. Its lookup for indices <= `0x9f`
uses key `0x7f0000`, not the WX1DM record key. No persistent-state dump
identified as belonging to the failing PR1ML session has been established.
Never write WX1DM's value to PR1ML.

Additional local captured-state evidence found during the corpus survey:

- `BD-RW_BDR-PR1M_1.75.dump.bin`, SHA-256
  `c82506d3e20ef0abc99c999988162503b09a5106c95615b717aeb827ce64e575`:
  captured INQUIRY revision `1.75`; captured 2048-byte A0 response has
  bytes `ff 01` at offset `0x13e` (parameter `0x9f`).
- `BDR-PR1AME_1.05.dump.bin`, SHA-256
  `534abba6eb7a4689a2a91f0cb98c2215cd5b7d14cc347ae895507006ea4d4176`:
  captured INQUIRY revision `1.05`; captured A0 word is `ff09`.
- Original S12JX capture's A0 word is `ffff`, agreeing with the independently
  traced CPU persistent-record lookup. UD04's separate 2048-byte parameter
  capture also contains `ffff` at `0x13e`; its standalone file has no dump
  coverage or identity record and is therefore weaker evidence.

This supports model-specific required values in working captures. It does not
prove all firmware without a detected comparison expects `ffff`, or prove a
marker-only update is a complete migration. The user's final policy is
target-driven in both directions, with no saved setting history. Keep the
original word only in RAM during the current attempt so pre-transfer failure
can restore it. A known S12JX return target should use its proven neutral
value, not retain WX1DM's marker or depend on a historical backup record.

## Attempt-local transaction implementation

`pioneer_optical::startup::migration::execute` implements read, conditional
change, readback verification, then one flash callback. It uses bounded A0
word constructors from `cdb` and never retries writes. Parameter index/value
are supplied by verified target/source analysis; it does not infer FFFF from
no-match. Original value exists in RAM/error context only, not a history file.
Change verification failure prevents the flash callback. Pre-transfer callback
failure attempts one verified restoration. A strict transport wrapper marks
the first attempted non-A0 vendor write, including entry conservatively;
subsequent errors retain the target word and explicitly prohibit blind rollback.
This avoids treating a rejected chunk or timeout as proof firmware is unchanged.
The caller must not bypass the wrapper with another device adapter.

Transaction tests cover forward/reverse target values, unchanged/no-rewrite,
pre-transfer restoration, rejected first firmware write/no restoration,
failed parameter verification/no flash, and invalid index/no commands.
The transaction is now available around the real shared prepared executor as
`PreparedUpdate::flash_with_parameter`, covering both passes/readbacks. Host
preflight runs before changing the parameter, and descriptor validation failure
inside the callback restores it before entry. Integration tests exercise both
real prepared passes, failed binding/restoration, and policy refusal/no writes.
Automatic target selection and app Recovery wiring remain unfinished. Current
firmware write admission and the default-value derivation still require proof;
do not interpret library primitives/tests as a completed working-drive fix.

## WX1DM native parameter command investigation (not enabled)

### Other consumers of parameter 9f (ongoing audit)

The only direct constant-index 9f read through `0x54e0a2` found in the
decoded WX1DM 1.01 Normal is its startup comparison at `0x45faf8`.
Generic indexed access remains: A0 response, diagnostic parameter readers,
and persistent-settings infrastructure can expose/read/write the same word.
These must not be counted as additional model-specific functional uses.

Cache initialization `0x54e14a..0x54e17c` reads parameters 60..9f inclusive
and stores their high byte then low byte in RAM at `0xa0add0 + 2*(index-60)`.
Thus 9f is cached at `0xa0ae4e/0xa0ae4f` (indices 7e/7f). Native writes
update that mirror through `0x54ea9a..0x54eb0e`. Cached byte getter is
`0x54e1e8`. No direct absolute access to ae4e/ae4f was found.
The inspected cached-reader paths use 70..7d for other fields, not 7e/7f;
the three-entry table at `0x595e3e` contains 74,72,70. This strengthens the
startup model-marker interpretation but does not prove absence of all
indirect/table-driven consumers. No calibration/power/laser/media consumer
of this word has been identified so far. Do not describe a completed
whole-program dataflow audit or OEM intent on this partial evidence.

Follow-up inspected the remaining literal function-pointer references to
cached getter `0x54e1e8`: the indirect paths at eb2a/eb58/eb80 read indices
70..7d; ebb4/ec24 read 11..19; ecc2/ecfa read 55..58. Direct wrappers at
ec5a..ecb8 use 28..31 and 53..54; ee4c uses 59. The table consumer
`0x53ec0a` is reached with selector 0..2 in `0x53e814..0x53e838`, selecting
74/72/70, each followed by the next byte. None selects 7e/7f.
The inspected indexed multiword readers at `0x576fd8`, `0x5776ca`, and
`0x57ab2a` have immediate caller indices in 12c..18f and 210..241, not 9f.
The cache loop and table are now bound to captured instructions in the
supplied-dump witness. Remaining generic parameter APIs can accept external
indices; this is a scoped static audit, not proof against arbitrary dynamic
execution or unidentified aliases.

### Hoard survey

The read-only scan examined 678 Normal envelopes: 643 decoded, 35 reported
unsupported layout. Broad comparison-pattern matches were narrowed by requiring
a mismatch-branch call to a wrapper of Kernel service `0x400a1a` (loader flag).
21 images matched; all use parameter 9f, with required values fe04, fe08,
fe0a, fe0b, fe12, fe13, fe14, fe15, fe1e, fe24, ff01, ff09.
Other decoded images are **no detected pattern**, not proven absent checks.
Legacy raw main ROMs and Plane images are outside this Normal-envelope scan.
Raw audit rows are `/tmp/pioneer-startup-corpus.tsv`; narrowed rows are
`/tmp/pioneer-startup-corpus-loader.tsv`; scanner source is
`/tmp/wx1dm-auth.xQR2bB/src/bin/startup_corpus.rs`.

The experimental `pioneer-optical::startup::discover` now exposes the observed
comparison read-only, with an explicit ambiguity error and unknown/no-match
result. It is not a migration authorization or proof of absent checks.
Three synthetic unit tests cover both argument conventions, malformed/truncated
code and conflicting matches. Both supplied-firmware integration witnesses
pass through this API; a separate cross-check reproduces all 21 narrowed
hoard matches. No persistent-setting write or default-FFFF policy is enabled.

The reproducible audit now lives in pioneer-optical's `startup_corpus` example
(`--features envelope --example startup_corpus -- HOARD/images/pioneer`).
The corrected complete run reported every one of 1195 inventoried images:
393 decoded Kernels, 34 unresolved raw main ROMs, 90 decoded Planes, and
678 Normals (35 unsupported envelopes, 21 recognized loader-flag comparisons,
622 no recognized comparison). Its R0-index native read/write switch shape
matched 372 Normals; those are candidates, not proven admission/side-effect
contracts. Per-image file hashes and unresolved safety status are retained in
`/tmp/pioneer-complete-startup-audit-verified.tsv`. Inventory coverage is not
whole-program consumer/write-safety coverage, which remains unfinished.

Recognized requirements are also exposed through the existing
`Envelope::analyze` / `FirmwareAnalysis.startup_requirement` contract, with
ambiguous recognition retained as a diagnostic. `None` remains unknown, not
evidence for a default-FFFF write. Flash/Recovery must share the library's
eventual migration executor, not duplicate model-specific app logic.

Writer comparison pass (`/tmp/pioneer-writer-shapes.tsv`) decoded all 372
candidate writer extents with the shared H8 decoder. Getter-minus-setter
sizes are 374 (39), 376 (245), and 378 (88) hex bytes. Erasing direct call
addresses and pointer-valued MOV immediates produces 84 review fingerprints;
these are not semantic-equivalence proofs (callee behavior is erased and
some remaining differences may still be relocations). WX1DM 1.01 and 1.02
share a fingerprint; 1.00 differs. This explicitly rules out treating one
traced writer as a certificate for every candidate. Example tests validate
switch offsets, truncation, relocation clustering, and retained scalar values.

WX1DM Normal WRITE BUFFER handler `0x44ce78` routes selector `A0` through
`0x44d7c0` to generic record access `0x43fd6a`, group 2, write flag 1.
The group uses word indices (byte offset divided by two). Its write branch
`0x43fea0` reads a payload word using `0x43f902`, then calls the native
persistent writer `0x54dd2c` with R0=index and E0=value. The input leaf
`0x4b2f2c` explicitly places the first payload byte in R0H and the second
in R0L: command payload words are big-endian, although the persistent
record getter assembles little-endian storage. Read output `0x4b2fba`
also emits high byte first. These byte orders must not be conflated.

The source S12JX lookup constants at `0x551e38`, `0x551d02`, and `0x551d58`
match the target's key `0x9984`, unit `0x140`, and area `0x1928`.
The supplied-dump witness binds both sets of constants to captured bytes.

The source S12JX has the same native A0 write surface: WRITE BUFFER handler
`0x44bd70`, selector A0 comparison `0x44be00 -> 0x44cb7c`, group 2 with
write flag 1 at `0x44cb90`, generic access `0x43f148`. Descriptor at
`0x59de0c` is `8002 0800` (word indexing, 0x800-byte bound); offset/2
at `0x43f190..0x43f194` makes byte offset 13e select word 9f. Data input
`0x43f292 -> 0x43ecc0 -> 0x4b4766` supplies the requested word, and
`0x43f29a` calls native persistent writer `0x5510f0` (R0=index,E0=value).
This establishes source handler equivalence. Outer command admission and
native writer failure/rollover behavior remain separate verification work.

This is a candidate supported command path, not authorization to initialize
the field. Still required: outer command permission/mode gates,
full native writer rollover/error behavior, and the
meaning of the target prerequisite. Do not send a guessed A0 write, overwrite
an entire parameter bank, or bypass the startup check on this evidence.

## Candidate correction and verification requirements

The user subsequently confirmed a power cycle. If `0000` persists after full
drive power removal, a volatile post-programming counter cannot explain the
whole failure. The polling change is therefore not established as the WX1DM
cold-start fix. Continue tracing boot checks and Normal-to-loader fallbacks;
do not publish this as a complete resolution of that report.

Also distinguish exact sense codes: the WX1DM busy-guard table entry is
`02/04/12`, whereas the PR1ML log reports `02/04/02`. The earlier shorthand
that the logged code directly identified the busy guard was too strong.
The shared command-dispatch mechanism is real, but that log code alone does
not prove it was active.

Poll REQUEST SENSE before event/readiness commands after finish, in both the
shared Pioneer Flash executor and app Recovery. Do not retry firmware writes,
force a reset, patch the firmware, or accept a sense response as recovery
success. Recovery must still observe usable readiness and a non-0000 identity
with a Normal tag. Preserve/log the returned sense bytes or command error.

A stateful regression holds the drive in update mode until REQUEST SENSE
reaches command completion. The pre-fix shared executor times out; the amended
executor and Recovery pass. Negative tests retain timeout when sense fails or
the drive remains in Kernel mode. This validates host behavior against the
traced receiver mechanism; it is not a physical-drive validation claim.

The CDB constructor and shared executor change belong in `pioneer-optical`.
Local integration uses an explicit Cargo patch to its release worktree;
shipping requires a released dependency containing that change, not an
absolute-path Cargo patch in this repository.

## Additional 0.13.2 verification findings

WX Kernel selector 70 is not a general execution or settings bridge:
`0x4034dc` calls `0x4054e2`, which only sets receiver-object byte +0x0c
to 1. The traced Kernel dispatch has no Normal A0 parameter interface.
Consequently the pre-flash A0 transaction cannot repair an already-0000
drive by simply issuing that same command in loader mode. A verified staged
return through usable Normal firmware or another independently established
access path is still required.

WX blank-bank initialization at `0x54f25c` recognizes both bank markers
as FFFFFFFF and programs only sequence 1 at bank+FFFE and FEDC4321 at
bank+FFFA. This is evidence for erased record contents remaining FF at
this initialization stage, not a universal certificate that an unmatched
target should receive FFFF. Subsequent initialization and per-generation
semantics still require verification. The bookkeeping call through
`0x54f720 -> 0x54d378` uses record key 9784, distinct from parameter key
9984; its other callees have not all been certified here.

Instruction-level comparison of the S12JX and WX native writer extents
found 253 instructions in each. After normalizing direct call destinations
and pointer-valued MOV immediates, the only two remaining differences are
indexed scratch RAM addresses (A0AF52 versus A0AB10). This supports shared
writer structure but does not establish equivalence of their callees or
authorize all 372 candidate command surfaces.

The library now provides an explicit `PreparedUpdate::flash_with_parameter`
transaction entry point. It checks initial runtime policy before touching
settings and wraps both prepared passes with the attempt-local write guard.
Integration tests cover two-pass completion, a changed receiver binding
restoring the original setting before entry, and initial policy refusal
without any setting writes. Automatic target selection and app wiring are
not implemented; the caller must independently establish the parameter
contract. These changes are experimental and are not a dev-green release.

PR1ML 1.75 requires an additional command-binding trace, not merely the R0
writer pattern used by WX/S12. Its Normal READ BUFFER handler at 4685F2
compares A0 at 46866C and branches to 468E38. That selects group 2,
direction flag 0, and calls 460280 at 468E56. WRITE BUFFER at 4704A0
compares A0 at 47050A, branches to 470DC4, selects the same group with
direction flag 1, and calls 460280 at 470DDC. The descriptor at 62FAA4 is 8002 0800,
but this generation's generic access does not directly call the persistent
getter/setter: it constructs command C7 at RAM 25AC, group/write-direction
flags at 25AE, index at 25AF/25B0, and exchanges data through 25A2 and
25B1/25B2. 5F4A22 yields through the scheduler (60DABC); it is not itself
the native setter. The persistent writer is 5F0176 (ER0 object, R1 index,
E1 value); the startup getter is 5F05A8. Connecting the mailbox consumer
to those functions remains necessary before applying the A0 transaction
generically to this generation. Matching the descriptor alone is insufficient.

Independent read-side binding is now established for the supplied working
PR1M 1.75 capture (SHA256 c82506d3e20ef0abc99c999988162503b09a5106c95615b717aeb827ce64e575).
Its startup comparison is at 48C8AC, getter 5EFF0C, requiring FF01.
Lookup 5F0E14 selects key 7F0000 for indices through 9F; unit 140 at
5F0CCE and area 3250 at 5F0D20 imply a 50-byte log. Three used entries
select record 7F02D0 and word 9F at 7F040E (stored 01 FF, little-endian).
Every one of the 160 native words matches the captured A0 response after
byte-order conversion, including response bytes FF 01 at offset 13E.
The opt-in working-PR1M witness checks input hash, capture coverage, traced
instruction constants, log selection, and all 160 comparisons. This is not
the failed PR1ML session or a write-side certification.

Latest local verification: library all-feature unit suite 388 passed, zero
failed; strict library/app clippy passed; both opt-in supplied-firmware
witnesses passed, including captured blank-bank initializer instructions.
The full app unit suite was still running at this checkpoint (session 67758,
log /tmp/freemkv-0132-lib-qa.log); no full app/dev-green claim follows.

Follow-up verification and hardening:

- The first full app run finished with 542 passed, one historical parity-ledger
  failure, and 11 ignored. P7 now explicitly records the REQUEST SENSE read
  and exact transcript-count changes in `INTENDED_CHANGES.md`; the parity
  gate passes after that correction. A full rerun is session 99807, logging
  to /tmp/freemkv-0132-final-app-qa.log.
- `PreparedNormal::flash_with_parameter` now supports the same attempt-local
  transaction without writing a Kernel, needed for a staged Normal restore.
  Tests exercise success, pre-entry rollback, uncertain-entry no-rollback,
  initial policy refusal, and initial descriptor refusal.
- Both prepared migration entry points bind the live descriptor twice before
  reading/changing settings. They bind again before update entry; a change
  between those boundaries triggers the pre-transfer restoration path.
  A mismatched initial descriptor causes no setting write at all.
- Startup mismatch tails are instruction-decoded, not searched at arbitrary
  even offsets. A JSR-looking immediate is rejected and the flag wrapper must
  include its RTS. All 21 previously recognized hoard comparisons still match
  (/tmp/pioneer-0132-boundary-crosscheck.log). This improves recognition
  integrity, not absence/default inference or write authorization.
