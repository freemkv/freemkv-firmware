# WH14NS40 MT1939 UHD investigation

This is an open code investigation, not a UHD capability declaration. The
production classic Modify path still reports Unrestricted unavailable. The
candidate emitter can be exercised through the read-only example; it does not
save a firmware image or change website capability records.

## Inputs

| Role | Revision | Full source SHA-256 | Boot banner |
|---|---|---|---|
| Classic example | 1.02 | `40eb760e23f100d55e86e9c061c73428d4087ef712294e4dbfcefa3093837a1a` | `MT1939 Boot Code` |
| Comparison | 1.02 | `648a16d024eea31ef4901f3ac2180cbfffeda1161d70f9096335d8a6097445bc` | `MT1959 Boot JB8` |

The same model/revision string is insufficient to select a chipset or code
layout. The existing boot/identity parser distinguishes these inputs.

## Grounded paths in the classic image

The coherent command tables contain multiple handlers for opcode AD. The
handler at `0x15538a` checks a packed byte shifted right six against 1. It is
not sufficient to inspect that handler and assume every structure request goes
through it. Another AD handler at `0xb67da` explicitly tests the request's media
field for 1 for formats below 0x80. Its format-0x80 branch reaches the shared
VID producer through `bl 0x17f4d6` at `0xb68ea`.

The classic producer uses the already supported TwoRound VID address grammar;
a separate per-model or Classic VID grammar was unnecessary. The auth==6 gate
at `0x17f532` precedes a preparation call and a checked success branch to
`0x17f586`. Following that success block reaches the state check at
`0x17f5ac`, not an arbitrary ranked CMP match elsewhere in the image.

| Item | Native code | Current evidence |
|---|---|---|
| State byte | literal at `0x17f728` resolves to `0x01ff9dd3` | Read through r1; shifted into r0 |
| First state path | `cmp r0,#0xc; bne 0x17f626` | C proceeds at `0x17f5b0` |
| Alternate path | `ldrb r0,[r1]; lsrs r0,#4; cmp r0,#4` | 4 proceeds at `0x17f62e`; other nibbles exit at `0x17f65e` |
| Layer gate | `0xb6804` onwards | 0 accepted; 1 requires a flag; 2+ rejected |
| Layer normalization | `0xb6816` onwards | Accepted requests have their layer field reset to zero |
| Dense-disc lead | `BDXLSpotCal` string at `0x6943c` | Code loads its address at `0x6945a`/`0x69468`, calls logging around `bl 0x1154a0` at `0x69462` |

The MT1959 comparison handler at `0xb0640` normalizes the request layer field
without the same preceding 0/1-only check. This is a concrete compiler/behavior
difference, not yet proof that bypassing the classic check permits physical
reads of a third layer.

The older Descriptor candidate around `0x15516e` has a close newer counterpart
at `0x11bebe`; it is reached from another structure-response path. It must not
be assigned a BD/UHD role merely because a signature or a 6F refusal matches.
Its semantic role and any existing feature claims require the ongoing audit.
The unproven descriptor detour is now refused by the emitter; a red/green
regression demonstrates the prior acceptance and the corrected refusal.

## Executed tests

`scripts/test-mtk-classic-dispatch.py` executes the original source excerpts on
Unicorn. All 256 state-byte values and 128 media/format/layer/flag combinations
reach their expected native continuations.

The shared emitter generates a research state-gate detour from the positively
selected contract. A red test caught the overly broad original On override:
it would replace the existing nibble-4 implementation with the C path. The
classic candidate bounds On to nibble values C..F and keeps other original
paths. The revised Off branch uses the separately validated native failure
block for that same band; nibble 4 and every lower band retain OEM behavior.
All 1,024 packed-byte/setting cases pass for the excerpt, including unchanged
r0-r12, the live r1 fallback pointer, SP and original CMP flags. The same test
passes 24,576 comparisons over all 24 full originals. This checks emission
behavior; it does not establish that D/E/F are UHD types.

The code-layout library adds one register/continuation form,
`R0StateR1Alternate`, while reusing the existing TwoRound VID form and the
shared state-gate generator. Small source excerpts retain the relevant literal
pools and PC alignment; their full-source and excerpt hashes are recorded.

## Type assignment comparison

In the classic image, the caller at `0x1098d6` invokes `0x1080cc` and stores
its returned byte into `0x01ff9dd3` at `0x1098dc`. The classification block at
`0x10822c` tests `(state & 0xCC) == 0xC4`, a status value and a helper result.
The corresponding MT1959 block at `0xde7b4` has the same comparisons, constants
and helper arguments:

| Branch | Low-result outcome | High-result/status-2 outcome | Threshold |
|---|---|---|---|
| Masked state C4 | C4 | F4 | 0x3000 |
| Other state | C0 | F0 | 0x3800 |

The CPU test replays both original blocks for 126 state/status/helper-result
combinations, including threshold boundaries and the unchanged-state status-1
path. All outputs match, and both call their respective helper with arguments
`(0x76, 0, 7, 1)`. Helper results are supplied by the test; hardware accesses
are emulated. This does not identify the physical meaning of the helper value
or prove that F4/F0 represent UHD. It establishes that these particular
classification rules are shared, so changing the classic thresholds based only
on age would be unsupported.

## Remaining proof obligations

### Receiver boundary evidence

The read-only `mtk_receiver_evidence IMAGE receiver-plan` query now uses the
library's complete envelope, identity, installed-firmware and receiver APIs.
For the MT1939 source above it selects receiver `0xa36d0`, with plaintext
header/body encoding. For the OEM UH12NS40 1.03 allocation case
`eeb1c948f1ed98245b7d21d03fe5e333a3349d28453690e2a60b4a8dc01765ba`
it selects receiver `0xa7688`, with encrypted header/body encoding. Both
currently return `None` for programmed and preserved ranges. This means the
library has not established those boundaries; it does not mean the entire
image is programmed or that erased gaps outside authenticated ranges are safe.
The query does not modify either input.

The updated release CLI/example passed the 64 WH instruction cases, eight
runtime settings cases and all 574 classic/comparison cases described above.
These remain CPU routing and preservation checks, not physical read tests.

1. Trace the assignments to the packed type byte and determine which values
   describe physical medium/density, rather than assuming a UHD enum exists.
2. Trace disc-information version/layer recognition and the data-read path;
   getting a structure/VID response alone is insufficient.
3. Establish whether normalizing a layer-2 structure request is the correct
   behavior, or whether a distinct layer response is required.
4. Validate the complete hook group and OEM behavior, including the alternate
   implementation, before enabling a classic capability in Modify or the finder.
5. Sole current scope: get UHD working for the 24 published classic MT1939
   images. Other feature buckets and website changes are out of scope.

## 24-image authentication contract and native read-entry comparison

The published 6/6 group contains 84 MT1959 hashes and no MT1939 hashes. All 24
published 5/6 hashes are MT1939. Every one of those 24 independently selects
`R0StateR1Alternate` through the same shared VID/authentication analyzer; all
research candidate source hashes match their full original. The adjacent
`mt1939-24-auth-candidates-20261026.json` records the exact per-image sites and
candidate bytes. This is research evidence, not a capability enablement.

The native READ(10/12) dispatch records select `0xb4814` in the classic example
and `0xae73c` in the MT1959 comparison. Both first check the same native ready
state at `0x01ff9b2b`. Their next decision also has the same semantics:

| Role | MT1939 | MT1959 |
| --- | --- | --- |
| availability byte | `0x02000ddc` | `0x02000c20` |
| packed media-state byte | `0x01ff9dd3` | `0x01ff9e00` |
| native status byte | `0x01ff9b29` | `0x01ff9b29` |
| accept continuation | `0xb484c` | `0xae76e` |
| reject continuation | `0xb4844` | `0xae766` |

Both reject only when availability is zero, the packed high nibble is F, and
native status differs from 0x82. Both report native medium-error 03/31/00 on
that branch. Independent execution of both original entry blocks passes 1,024
paired combinations covering every packed state byte, both availability values
and both native status outcomes. This gate is not evidence of a classic-only
UHD restriction, and it is not patched. F must not be renamed UHD based solely
on this comparison.

The added small original excerpts and checks run in the existing independent
CPU script. The next target remains the disc-information/density recognition
path leading to those state/availability values, followed by the physical data
read path. Authentication widening alone does not establish UHD reading.

## Native classification metric

A later source trace reaches a native packed-input classifier at `0x134c16`,
called from `0x1094d6` when the packed state is F0 or F4. The corresponding
MT1959 function is `0xfc71e`. Both read a signed mantissa byte and unsigned
exponent byte, calculate `abs(mantissa) * 2^exponent / 128` using native ARM
soft-float helpers, and compare the ROM/R classes against the same single-
precision constants `0x3f2147ae` and `0x3f428f5c` (approximately 0.63 and 0.76).
Below threshold, the original state is normalized to C0/C4; otherwise it is
retained. The code also handles other state bands, but their physical meaning
is not established by these comparisons.

The independent CPU test executes the actual Thumb functions and their actual
ARM float helpers. It checks 216 paired cases covering the thresholds, signed
mantissas and exponents, including callee-saved registers and stack balance.
Only diagnostic logging is skipped. Both generations produce identical state,
metric and threshold results for these ROM/R cases. No threshold is patched.
The two functions and math helpers are retained as small hashed original
excerpts for CI. A decompiler's inferred condition flags across soft-float calls
are not used as proof; native execution supplies that check.

## Isolated, signed research candidates

`mt1939_uhd_candidate_tests` creates experimental outputs only under the Rust
test configuration. Ordinary CLI, GUI, capability queries and website builds
have no entry into this path. The builder uses the existing engine, SRAM role,
auth emitter, covered free-space allocator, boot-record serializer, signer,
metadata checks and structural audit. It requires the complete classic base and
boot contracts, an original MT1939 input, the selected alternate auth contract,
and an unclaimed original hook site. Another chipset or already-modified input
is rejected. No guessed raw-ROM offsets or per-model/hash selectors are used.

All 24 original hashes build with each of OEM/On/Off, giving 72 signed outputs.
All 72 pass structural/integrity audits and offline Flash admission against
their respective original. Source hashes remain unchanged. The adjacent
`mt1939-uhd-candidate-builds-20261026.json` records every output checksum and
admission result. Research output files are held separately under
`Developer/tmp/mt1939-uhd-research-20261026`, never in approved
hoard inputs or the website catalog.

To reproduce from the workspace root, use absolute source/output paths:

```sh
FREEMKV_MT1939_UHD_SOURCES="$PWD/internal/docs/audits/mt1939-24-auth-candidates-20261026.json" \
FREEMKV_MT1939_UHD_HOARD=/path/to/hoard \
FREEMKV_MT1939_UHD_OUTPUT=/path/to/research-output \
cargo test -p freemkv-fw --lib \
  mt1939_uhd_candidate_tests::classic_uhd_research_corpus_builds_without_changing_originals -- --exact
```

The regular Modify path still reports the 24 images at 5/6, and a regression
checks that the research builder does not promote ordinary support. A signed,
admitted candidate is not a physical UHD conversion result. No optical drives
were found on this Mac during read-only enumeration; a suitable MT1939 drive
and UHD disc are needed for the physical check. No live flash has been attempted.
