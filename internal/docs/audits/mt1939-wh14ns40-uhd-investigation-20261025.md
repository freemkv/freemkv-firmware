# WH14NS40 MT1939 UHD investigation

Latest finding: the native disc-information parser, before VID/authentication,
has a concrete generation difference. MT1959 explicitly recognizes identifier
`BDU` in addition to `BDO`/`BDR`/`BDW`; the reviewed MT1939 parser rejects it.
The new path produces high-nibble-C states, so experimental C..F authentication
widening does not address that earlier refusal. See the native DI parser section
below. This supersedes treating authentication widening as the likely complete
UHD conversion; neither physical conversion nor a complete patch is proven.

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

## Native DI parser comparison

The source copy loops bind the reviewed inputs to DI bytes 8..13, rather than
arbitrary internal enum values. MT1939 copies bytes 8/9 at `0x10a14e` onwards
and bytes 10..13 at `0x10a172` onwards; the corresponding MT1959 loops start
at `0xe080a` and `0xe082e`. Both then test bytes 8/9 for ASCII `B`/`D`.

| Role | MT1939 | MT1959 |
| --- | --- | --- |
| Reviewed parser start | `0x10a4aa` | `0xe08f0` |
| `BDW` branch | `0x10a502` | `0xe0968` |
| `BDR` branch | `0x10a524` | `0xe0988` |
| `BDO` branch | `0x10a546` | `0xe09d0` |
| Additional `BDU` branch | none in this reviewed dispatch | `0xe09ac` |
| Layer-field assignment | `0x10a5be` | `0xe0a3c` |

The MT1959 U branch requires DI byte 13 equal to 5 for the assignments below.
It reads the high nibble of DI byte 12: value 2 assigns `0xc7`, while value 3
assigns `0xc8`. The subsequent layer assignment deliberately preserves `0xc7`
for value 2; the generic classic layer assignment has no such exception.
Other U combinations must not be assumed valid merely because they reach a
continuation without assigning a new state.

Independent CPU execution supplies exactly those copied bytes to the two
original parsers. With U/5 and field values 2 or 3, the classic parser explicitly
clears its state and takes its diagnostic refusal path; the modern parser
continues with C7 or C8. This holds for provisional input states C0/C4/F0/F4.
The test also compares the common O/R/W paths and their layer-bit assignments.
Both original ARM inline-switch helpers execute; only diagnostic logging is
skipped. The hashed source excerpts and helpers are in `mt1939-research` and
run through `scripts/test-mtk-classic-dispatch.py`.

This establishes actual native input/output semantics and an earlier parser
obstacle. It does not by itself identify every physical format field, prove that
a real disc reaches the parser on MT1939, or prove its optical decoder can read
the content. Do not label D/E/F as UHD states: the reviewed modern U path stays
in C, which the original classic authentication comparison already accepts.

Next work is to bind equivalent parser roles across the 24 originals, trace C7
and C8 consumers in both generations, and identify which additional parser,
layer or read-path behavior is required. A generic adaptation must retain the
OEM O/R/W branches and use proven source/continuation contracts. No production
capability has been enabled by this comparison.

## Native C7/C8 downstream comparison (2026-10-26)

Compared the two exact WH14NS40 source hashes above. These are native input
states, not guessed C/D/E/F authentication classes. C7 and C8 both remain in
high-nibble C, but are not interchangeable downstream.

| Consumer | MT1939 address | MT1959 address | Observed difference |
|---|---|---|---|
| Hardware control bit | 36472 | 26706 | Bit 31 of MMIO 0420903C is set for `(state & C8)==C8` in classic; modern also sets it for C7. Other bits survive. |
| Hardware control field | 32140 | 32E6A | In the BD band, classic clears bits 4..7 for the C8 mask, otherwise selects 30; modern also clears them for C7. Caller supplies the live register base. |
| Default speed values | 678C4 | 6875A | With native restriction flag clear, classic C7 selects 8 and C8 selects 12; modern selects 6 for both. With flag bit 0 set both select 4. These are native stored values, not a claim about achieved physical speed. |
| Forward calculation | FD15A | D8E64 | Modern extends the C8-mask calculation branch to C7; classic C7 takes the fallback. The shared branch has additional CC-mask coefficient selection. |
| Reverse calculation | FD1D2 | D8EE0 | Modern includes C7, with a further flag-dependent branch. This is not an unconditional C7-to-C8 alias. |
| Parameter nibble | FD4CC | D9424 | Modern extends a C8-mask plus flag-bit-5 condition to C7, selecting low nibble 2 at 0420B1B8; classic C7 follows the lookup path. |
| Profile dispatch | A44A2 | 9FF06 | Both route C7 and C8 to the ROM profile branch; no new profile split at this point. |

The first three rows now execute original hashed instruction excerpts in
`scripts/test-mtk-classic-dispatch.py`. Hardware bit tests cover every state
byte and three initial register values; hardware-field tests cover every
BD-band state and those initial values; speed tests cover every C-band state
and both restriction flag values. The calculation/nibble rows are disassembly
comparisons, not yet equivalent CPU or physical tests. Existing READ-entry and
VID tests remain separate; their passing does not prove these other paths.

A literal-reference scan found 35 distinct modern C7 comparisons near direct
state loads. This is a work list, not an exhaustive count of state consumers
or a claim that 35 patches are required: indirect/aliased state access and
runtime ROM code need separate tracing. Some modern veneers enter runtime
01F9xxxx code whose mapping is not established from the file; do not invent a
file-offset alias to fill that gap.

Consequence: adding BDU recognition is necessary for this reviewed parser,
but not sufficient. C7 needs selected downstream branches and parameters;
C8 already has classic handling, yet modern defaults also differ for C8.
A global state substitution or broad authentication bypass cannot stand in
for this comparison. No production capability is enabled by these tests.

## Cross-corpus comparison: distinguish routing from hardware tuning

The follow-up inventory is reproducible with:

```sh
python scripts/audit-mtk-native-uhd-areas.py \
  --hoard /path/to/firmware-extractor/hoard \
  --output internal/docs/audits/mtk-native-uhd-area-inventory-20261026.json
```

It selects the 24 classic candidate hashes and all 171 native-banner-confirmed
MT1959 images from the full corpus manifest. The latter includes 97 OEM/dump
images and 74 MK/Omni images; those counts are kept separate. These are corpus
images, not deduplicated website download counts.

Each area is located independently. Reference patterns retain register operands,
non-address immediates, and branch conditions, allowing literal/call/branch
relocations. Decoded instruction shapes must also match. The report retains
resolved literal values and local branch layout; forward/reverse calculations
additionally follow the CC-mask path to bind its actual add/subtract continuation,
including branches across literal-pool islands. The old R-to-O recognizer shape
must have a preceding R-failure branch that targets the O block directly.

This is a research locator and inventory, not the production feature matcher or
an assertion of whole-function equivalence. Matching a partial region does not
prove all callers, external continuations, tables, or physical behavior. Missing
or ambiguous matches remain explicit rather than becoming guessed variants.

The 24 classic images share the reviewed control-bit, control-field, forward and
reverse calculation, and parameter-nibble shapes. Their O recognizer differs
only in register use in one image. They do not all share identical hardware
defaults: BH40N uses a different default from the other 23.

MT1959 is not one universal comparison implementation. Across the six non-speed
areas, five observed combinations occur. In particular, 24 MT1959 images retain
the old forward/reverse calculation selection and lack the U branch in the
reviewed DI recognizer. The other 147 have the C7-aware calculation selection;
their U recognizers include a plain variant and variants that additionally set a
flag and accept format 1 as C0. The modern generation therefore cannot itself
serve as a UHD capability test or as an instruction to copy every newer branch.

Native calculation CPU tests now execute the original Thumb routines and real
ARM divide helpers: 720 executions covering forward/reverse, C7/C8/CC and other
C-band states, three flag values, and ten u16 inputs including boundaries.
The shared coefficients are already present in classic code. The modern
reverse selection sometimes chooses `base5 - 9*(value/10)` where the other
path uses `base7 - 12*(value/10)`; there is also a shared
`0x51B1 +/- 23*(value/20)` CC-mask path. These tests establish the calculation,
not the physical meaning of its input or the origin of the selecting flag.

### Hardware-sensitive defaults: preserve, do not copy

The following C7/C8 cases execute original code in tests:

| Native source | Flag clear | Flag bit 0 set |
|---|---|---|
| Classic WH14NS40 reference | C7=8, C8=12 | both 4 |
| Classic BH40N | both 8 | both 4 |
| Modern BU40N reference | both 6 | both 6 |
| Modern WH16NS60 reference | both 8 | both 4 |
| Modern WH14NS40 reference | both 6 | both 4 |

Thus, even native C7-aware MT1959 implementations have different default values.
These are stored firmware values, not measured physical speeds. No speed-default
change is justified merely by the parser/generation comparison. The reviewed
13-byte parameter lookup prefix likewise differs between generations: all 24
classic images use `06 06 06 05 05 05 05 05 05 04 04 04 04`, while all 171 modern
images use `04 04 04 03 03 03 03 03 03 02 02 02 02`. Preserve each image's table;
a change to the C7 selection condition does not require replacing that table.

The conversion work should isolate DI recognition and C7-dependent routing,
trace the selecting flags back to their producers, and bind each continuation.
Hardware tuning is a separate decision that needs evidence of a blocking role.
No production patch, capability declaration, website update, or physical UHD
claim is introduced by this inventory.

Final selected-area inventory: 195 inputs × seven areas = 1,365 unique bindings,
with zero unresolved/ambiguous area matches in this snapshot. This does not mean
all 35 previously found C7 comparison sites, indirect consumers, or ROM routines
have been audited; the matrix covers the seven named areas only.

| Selected area | MT1939 (24) | MT1959 (171) | MT1959 OEM/dump subset (97) |
|---|---|---|---|
| U-identifier recognizer | 24 without U branch | 147 U-aware; 24 without U branch | 84 U-aware; 13 without U branch |
| Forward calculation gate | 24 old gate | 147 C7 extension; 24 old gate | 84 extension; 13 old gate |
| Reverse calculation gate | 24 old gate | 147 C7 extension; 24 old gate | 84 extension; 13 old gate |
| Hardware-control bit gate | 24 old gate | 147 C7 extension; 24 old gate | 84 extension; 13 old gate |
| Hardware-control field gate | 24 old gate | 170 C7-aware; 1 old gate | 96 C7-aware; 1 old gate |
| Parameter-nibble gate | 24 old gate | 147 C7 extension; 24 old gate | 84 extension; 13 old gate |
| Default selection | 2 code shapes | 6 code shapes | Same 6 shapes represented |

For the specific C7/C8 plus restriction-bit cases reviewed above, the six modern
default-selection code shapes resolve to three native policies: both values 6
with restricted value 4 (94 images); both values 6 even with the bit set
(65 images); both values 8 with restricted value 4 (12 images). Other states and
additional conditions must not be inferred from this narrow policy comparison.

The five non-speed combinations contain 94, 41, 12, 23, and 1 images respectively
(OEM/dump subset: 55, 22, 7, 12, and 1). They are combinations of the selected
area shapes, not five proven complete firmware families or five ready patches.

## Component implementation and first hardware target

`mediatek-optical::image::analysis::UhdAreas` now selects the seven areas
independently and exposes typed native handling and selector contracts. The
library owns replay opcodes, hook spans and both native continuations. Modify's
`engine::mtk_uhd::UhdConversionPlan` consumes those contracts, preserves hardware
policy, binds the source hash, and emits research components through the
read-only `mtk_receiver_evidence IMAGE uhd-conversion` mode. Ordinary classic
Modify records the outstanding conversion contracts and installs none of these
partial components.

Implemented research emission: four selection extensions (forward calculation,
hardware bit, hardware field, parameter selection), a DI identifier helper and
a layer-state helper. Selection stubs replay OEM operations for Off/OEM/unknown
settings, preserve registers/SP and native comparison flags, and extend C7 only
for On. BICS stubs preserve incoming C/V using Thumb-1 branches/arithmetic;
no Thumb-2 MRS dependency is introduced. These are component bytes, not a
complete signed conversion firmware.

Independent CPU execution passes 16,384 native-versus-emitted routing cases and
6,624 DI helper cases on the committed classic fixture. The 24-input sweep adds
18,432 routing comparisons (12 state values, four setting values, four C/V
combinations, four candidate selectors). This explicitly does not settle caller
LR lifetimes, DI format prevalidation, selecting-flag producers or the remaining
indirect/layer consumers. Full conversion remains refused until those contracts
are implemented and checked.

First user hardware target: **BD-RE BH16NS48 1.02**, native MT1939, variant
`N0002A0`. The selected OEM source is:

- SHA-256: `43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3`
- MD5: `7ac1e89afc1a4033db5288f63f9bbca5`
- Hoard: `oem/mediatek/MT1939/HL-DT-ST_BH16NS48_MT1939_Code_JB7/GENERAL/1.02/main/43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3.bin`

The user will send the eventual signed candidate to the tester. No candidate has
been declared ready or sent. Build/check/hash the completed candidate before
handoff, retain the original and normal Flash compatibility checks, and keep the
website tied to released Modify capabilities.
