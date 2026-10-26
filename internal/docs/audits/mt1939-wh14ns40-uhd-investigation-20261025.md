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
classic candidate now bounds its override to nibble values C..F and keeps
other original paths. All 64 nibble/setting cases pass, including unchanged
r0-r12, the live r1 fallback pointer, SP and original CMP flags. This checks
emission behavior; it does not establish that D/E/F are valid UHD types.

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
5. Continue with the agreed allocation, five-feature, unsupported-input and
   zero-configurable-feature audits; keep work on dev and pause after green QA.
