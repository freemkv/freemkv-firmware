# Older 24 MT1959: G01-G06 media audit

OEM UHD is defined here as complete G01-G06 media behavior. G07/G08 are internal diagnostics only and generate no patches. These are source-image findings, not a physical read test. All 24 full source hashes were rechecked.

| Present | Images | Missing |
| --- | --- | --- |
| 1/6 | 23 | G01, G02, G04, G05, G06 |
| 0/6 | 1 | G01-G06: earliest BP50NB40 1.00 |

The contract already matching in the 23 is G03. No member of this older group has 2/6 through 6/6. Provenance: 10 OEM, 11 MK, 3 dumps.

| Gap | Source behavior versus reference | Implementation assessment |
| --- | --- | --- |
| G01 | Tested U/5 DI does not assign C7/C8. | Two coordinated admission/layer helpers prepared for all 24 layouts, including the earliest BP50 1.00. |
| G02 | C7 clears the control bit that the reference sets. | Source-bound selector helper prepared for all 24. |
| G03 | Earliest BP50 1.00 selects field3 versus reference field0. The other23 match. | Source-bound selector helper prepared for the one affected image. |
| G04 | C7 skips the forward numerical worker. | Selector helper prepared for all24; actual native numerical worker checks passed, including boundary vectors. |
| G05 | C7 skips the reverse worker; the newer native mode-byte/calibration relationship is not bound here. | Source-bound mode-aware arithmetic prepared for 23 images; earliest mode binding and mode/lifecycle qualification remain unresolved. No mode constant or donor orchestration is installed. |
| G06 | With native flag bit5 set, C7 uses the lookup table instead of reference nibble2. | Source-bound selector helper prepared for all24, retaining other states and flag behavior. |

All five common gap types now have prepared helpers for 23 images; G01 downstream identity effects and G05 lifecycle qualification still prevent a complete group. Nothing in this table authorizes partial media conversion or copying hardware defaults. Prepared helpers were exercised in the historical candidate CPU receipt; current plans exclude G07/G08 helpers.

The newer reference reverse calculations use low16(R7 -12*floor(input/10)) in mode0 and low16(R5 -9*floor(input/10)) in nonzero mode. Both native arithmetic branches exist in the older sample studied, but their UHD admission and mode-production/calibration contracts do not match. The remaining work is the producer/consumer relationship, not inventing division code. The matching newer calibration sequence was not found by the exact grammar checked in these24; that is not proof every equivalent implementation is absent.

## Per-image results

| Source | Model / revision | SHA prefix | Present | Missing media contracts |
| --- | --- | --- | --- | --- |
| oem | HL-DT-ST BP50NB40 MT1959 BUP1/BU1 / 1.00 | `c88a69013d55` | 0/6 | G01,G02,G03,G04,G05,G06 |
| oem | HL-DT-ST BP50NB40 NB50 / 1.01 | `961acab180c9` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST BP50NB40 NB50 / 1.03 | `3cdbdacace5c` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST BP50NB40 NB50 / INTM | `92bb22b2c899` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST BP55EB40 NB50 / 1.01 | `e60a4ce02a58` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST BU40N MT1959 BU5/BU3 / BN11 | `5c01c1fda59f` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST BU40N MT1959 BU5/BU3 / BN12 | `3d3badd67d47` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST BU40N MT1959 BU5/BU3 / CB04 | `78f75561d474` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST WP50NB40 NB50 / 1.01 | `bea3a823370a` | 1/6 | G01,G02,G04,G05,G06 |
| oem | HL-DT-ST WP50NB40 NB50 / 1.03 | `263994abefb0` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BP50NB40 NB50 / 1.01 | `148d89cc6ea4` | 1/6 | G01,G02,G04,G05,G06 |
| dump | HL-DT-ST BP50NB40 NB50 / 1.02 | `a344e289e0b1` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BP50NB40 NB50 / 1.02 | `cc7182ac0e56` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BP50NB40 NB50 / 1.03 | `e04aaf44157f` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BP55EB40 NB50 / 1.01 | `4ed5cdc974eb` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BP55EB40 NB50 / 1.02 | `88761a31edd5` | 1/6 | G01,G02,G04,G05,G06 |
| dump | HL-DT-ST BP55EB40 NB50 / 1.02 | `e64c4ca52445` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BP55EB40 NB50 / 1.03 | `0f7b3d34cbf5` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BU40N MT1959 BU5/BU3 / BN11 | `c0b346b0e2a7` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BU40N MT1959 BU5/BU3 / BN12 | `3559077e3c03` | 1/6 | G01,G02,G04,G05,G06 |
| dump | HL-DT-ST BU40N MT1959 BU5/BU3 / BN12 | `c4d995f031fe` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST BU40N MT1959 BU5/BU3 / U100 | `de24b0003fb0` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST WP50NB40 NB50 / 1.01 | `ed8f1c8414fa` | 1/6 | G01,G02,G04,G05,G06 |
| mk | HL-DT-ST WP50NB40 NB50 / 1.03 | `592e8d22d98a` | 1/6 | G01,G02,G04,G05,G06 |

Full hashes, exact paths and source observations are in the adjacent JSON and the full corpus CSV/JSON. Underlying DI, consumer, numerical and candidate receipts are retained in this directory.

## Bound operation-stage transition

A further ARM926 survey passed 8,775 cases in 65 positively bound layouts:
41 newer images select a mode-entry or mode-exit routine based on media state,
a structure coordinate and a phase byte; all24older images instead call the
native driver directly at that corresponding stage. The41newer bindings tie
those routines to the same mode byte read by the reverse numerical worker.
The threshold is112192 in these bound examples. Its physical units and the
full caller's field production are not established by this stage test.

The other106newer compiler layouts are unresolved by this particular grammar,
not missing the transition. Execution supplies R5/R7 inputs and stops before
the chosen callee, so no calibration/device result is fabricated. The receipt
is `mt1959-uhd-mode-transition-receipts-20261030.json`.

## Mode primitive execution follow-up

All 24 older images contain the same relevant coefficient and parameter primitives as the native BU40N 1.02 reference. A signature-bound audit executes the actual routines, lookup tables, ARM switch dispatcher and division worker without substituting function results. It compares all signed high-byte encodings for the native mode-entry scale -3 / option 0, with four low-byte values: 25,600 coefficient executions across the reference and 24 images.

The same audit executes parameters 0x10 and 0x11 through native get/set/get for all high bytes, three low nibbles and two initial register patterns: 76,800 round trips (230,400 native function calls). Getter results, exact register writes and full final register-page hashes agree with the reference. SP and callee-saved registers are checked, with writes confined to stack and the independently bound register page. These are passive MMIO memory tests; hardware side effects are not simulated.

The earliest BP50 1.00 uses an inline scale operation where the other images use a wrapper; both signature grammars execute identically. This narrows G05: these primitives can be reused, but mode-entry/exit orchestration, mode consumers and the caller's frame fields remain unresolved. It does not install or qualify a complete G05 conversion. Receipts: `mt1959-uhd-mode-arithmetic-receipts-20261030.json`; harness: `scripts/audit-mtk-uhd-mode-arithmetic.py`.

## Operation-frame and mode-byte identity

The enclosing operation caller now binds its R5 base from native instructions. A local CFG traversal follows both conditional edges, checks all reaching definitions of R5 and records the callee-saved-R5 assumption across calls. All 24 older direct-driver layouts and 41 newer transition layouts bind the caller and downstream requested/returned coordinate comparison.

For all 41 native transition layouts, caller-base + phase offset equals the independently bound mode byte written by the enter/leave routines and read by the reverse calculation. The phase is not a separate input field. The older requested-coordinate offset is independently derived as 0x3C in 23 images and 0x34 in the earliest BP50 1.00. Both use a returned-coordinate field four bytes later. These fields must be derived per image. The later adversarial audit below supersedes the initial new-storage hypothesis: 23 images already contain the semantic mode at an independently bound older field. Reuse that role; never infer it from numeric adjacency. Earliest-image field semantics remain different and unqualified.

The original 8,775 operation-stage Unicorn cases still pass across 65 bound layouts. This is additional static dataflow binding, not execution of the native mode-entry hardware sequence, and does not complete G05. The other 106 full MT1959 compiler layouts remain outside this particular stage grammar, as recorded explicitly; they are not classified as lacking transitions.

## Earliest DI caller and current helper execution

The earliest BP50 1.00 DI parser was already supported, but its saved-link proof stopped at an arbitrary 0x1200-byte window. Native conditional edge 0xE3D8E reaches 0xE3DC8 beyond that window, executes an alternate tail and returns through 0xE3D82/0xE3D84. The proof now bounds graph states, stack depth and image extents instead, retaining saved-slot alias and balanced-return checks. The library regression accepts a long caller and rejects saved-LR overwrite and an unbalanced return. All 194 library tests pass (three pre-existing ignored tests).

All 24 plans now prepare their G01 helpers. The current 121 candidate helpers pass 103,776 ARM926 selector cases, including OEM/Off behavior and other-state preservation. Every plan remains blocked solely by G05; none installs a partial conversion. These tests enter isolated helpers and stop at native continuations; they do not execute complete disc acquisition or physical hardware.

## Source-owned default restoration

A positive instruction grammar now binds the six native default-loading blocks (parameters 0x00/0x10/0x20 and 0x01/0x11/0x21) in every older image. The native UHD reference has two such groups: ordinary initialization and mode exit. Its operation-stage leave target independently selects the mode-exit group, avoiding an arbitrary match. Each older image has one matching initialization group. The parameter setter is independently bound before these call sites are accepted; each default address is loaded from that image and validated as RAM.

The actual six blocks and native setters pass 12,000 ARM926 executions across the reference plus all24older images. Boundary high/low coefficient bytes, two initial register-page patterns, and two upper scratch-word patterns produce identical exact register writes and full passive MMIO-page hashes. SP and callee-saved registers remain unchanged, and scratch-byte effects are checked. Fifty corrupted argument-load/call mutations are rejected. This establishes a usable source-owned restoration primitive; it does not install or qualify G05 orchestration, per-disc reset or additional mode consumers. The source values are supplied as explicit test inputs, not evidence of physical calibration correctness. Harness/receipt: `audit-mtk-uhd-mode-restoration.py` / `mt1959-uhd-mode-restoration-receipts-20261030.json`.

## Adversarial audit correction and implementation checkpoint

Independent Astra, Sol and Terra reviews found concrete defects in the earlier local tests and two helpers. G01 now follows the native prior-state-dependent attribute predicate, rather than unconditional attributes 0/3. The earliest G03 group now covers its later bit-10 selector as well as the nibble: actual owner execution with both prepared helpers matches two hash-bound native references across complete MMIO write sequences for the tested C7 context. Removing either helper fails the downstream oracle.

G05 now binds an existing old mode field through independent zero/one consumers and state-pointer domination, and reuses the source ARM division and R6 normalization path. The semantic mapping in 23 images is old B19 to newer B1A; old B1A is unrelated. This is not a numeric-offset rule. The earliest image uses packed configuration with no established equivalent reverse-mode binding and remains refused. No new mode RAM or newer orchestration was transplanted.

There are now 145 prepared helpers: G01 48, G02 24, G03 2, G04 24, G05 23, G06 24. The combined bounded CPU suite passes 196,748 candidate contract cases plus a separate 80-case stock parser oracle. Every helper is hash-bound and accounted for; grouped G03/G05 tests are mandatory, and the old nibble-only G03 oracle has been removed. Library tests pass (firmware 227, analysis dependency 198; three pre-existing dependency tests ignored). These are private CPU patches and bounded stages, not installed full-BIN or QA qualification.

All24older plans remain unqualified and install no partial conversion: G01 controller/resident-worker policy and G05 lifecycle/caller context require a scoped qualification decision, with the earliest mode grammar additionally unsupported. Native U-marker B19 has speed/control consumers and can choose resident code outside the held image; copying that byte onto old B19 would corrupt the established mode role. Some marker effects are provably redundant in tested contexts; others are not yet closed.

G07/G08 remain diagnostics in the implementation. The new audit rejects the blanket claim that AKE/encryption overrides replace class-3 routing or extended certificate/backend responses. Their exclusion must be tied to a qualified media/raw-read workflow; it is not a factory AACS2 playback claim. The unified design and adversarial G01–G08 reports document exact findings, remaining source/resident boundaries and required tests.
