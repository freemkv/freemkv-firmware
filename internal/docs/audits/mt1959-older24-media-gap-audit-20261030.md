# Older 24 MT1959: G01-G06 media audit

OEM UHD is defined here as complete G01-G06 media behavior. G07/G08 are internal diagnostics only and generate no patches. These are source-image findings, not a physical read test. All 24 full source hashes were rechecked.

| Present | Images | Missing |
| --- | --- | --- |
| 1/6 | 23 | G01, G02, G04, G05, G06 |
| 0/6 | 1 | G01-G06: earliest BP50NB40 1.00 |

The contract already matching in the 23 is G03. No member of this older group has 2/6 through 6/6. Provenance: 10 OEM, 11 MK, 3 dumps.

| Gap | Source behavior versus reference | Implementation assessment |
| --- | --- | --- |
| G01 | Tested U/5 DI does not assign C7/C8. | Two coordinated admission/layer helpers prepared for 23 layouts; earliest BP50 1.00 uses a distinct early DI parser not covered by that helper binding. |
| G02 | C7 clears the control bit that the reference sets. | Source-bound selector helper prepared for all 24. |
| G03 | Earliest BP50 1.00 selects field3 versus reference field0. The other23 match. | Source-bound selector helper prepared for the one affected image. |
| G04 | C7 skips the forward numerical worker. | Selector helper prepared for all24; actual native numerical worker checks passed, including boundary vectors. |
| G05 | C7 skips the reverse worker; the newer native mode-byte/calibration relationship is not bound here. | Main unresolved gap. A mode constant or bare branch change would not establish both reference behaviors. |
| G06 | With native flag bit5 set, C7 uses the lookup table instead of reference nibble2. | Source-bound selector helper prepared for all24, retaining other states and flag behavior. |

Four of the five common gap types have prototype helpers; G05 prevents a complete group. Earliest BP50 additionally lacks a complete G01 helper binding for its distinct parser. Nothing in this table authorizes partial media conversion or copying hardware defaults. Prepared helpers were exercised in the historical candidate CPU receipt; current plans exclude G07/G08 helpers.

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
