# Detection milestone and retained BU40N experiment

User reaffirmed that physical disc detection is milestone one; reading and
triple-layer/100GB behavior come later. The full conversion is research, not a
proven required patch set for detection. Do not send it as the next tester image.

The latest tester result for detection-only image `8a7ffc47...` remains:
it attempts detection but fails. No diagnostic state from that attempt has been
received. The CPU parser tests supply DI and cannot establish optical acquisition.

## Signature-based patch policy

Conversion locators in `mediatek-optical::image::analysis` inspect instruction
grammars, bind live RAM literals and native continuations, and reject missing or
ambiguous layouts. `ClassicDi` binds its prefix validation, prevalidation, format
switch, layer store and parent frame. The firmware engine emits Thumb code from
these contracts. It does not select hook addresses by BH16NS48 name or hash.
The exact-image hashes in research builders and CPU scripts pin test inputs;
addresses in receipts are results, not production selection rules.

This policy supports independently recognized layouts, not an unconditional
claim that every MT1939 image works. Native hardware routines and tables remain
source-specific. The read-only probe deliberately uses exact-image fingerprints
and is not a generic firmware patch locator.

## BU40N comparison retained for later

Ported BU40N's state-dependent DI attribute validation into a cfg(test)-only
recognizer. It accepts formats 1 and 5 using classic native format/layer handlers.
The 200-byte installed recognizer matches native BU40N OEM 1.00 parser outcomes
in 4096 cases (256 initial states, four attribute classes, two formats and two/
three layers); 12291 classic OEM/Off/unknown-flag/prefix preservation cases pass.
The separate BU40N U flag and its consumers are not ported by this change.

The full-group research BIN remains at:
`/tmp/BH16NS48_1.02_freemkv_0.15.4-dev-bu40n-parity.bin`.
SHA-256: `011ecbea0f9d8bb20ec7aa68d07fbe6fabfd1d3279ff720d9affdb5d4f137410`.
It has not been delivered or hardware-tested. The unit fixture build, 6400 full
installed-parser cases and eight early abort/ready boundaries pass. Previously
defined installed/read checks also pass on this new BIN: 28 stubs, 108 linked
scenarios, 48 capacity responses, 1536 read handoffs and 384 range refusals.
These are bounded software checks, not physical detection or reading.

Measured conversion footprint: 28 routing/position/calibration stubs total 6008
bytes and displace 124 bytes, plus the 200-byte DI recognizer and auth-cell hook.
Many 280-byte selector stubs duplicate four C/V-preservation cases; this is
defensive emission overhead, not 6KB of optical reading implementation. No size
optimization is performed here, because the active milestone is detection.

## Pioneer comparison corrected

Read the retained branches without checking them out or modifying them:
`research/ud02-ud04-pickup` holds UD02 mechanism settings, while
`archive/ud02-ud04-investigation-20261024` retains the original conversion plan.
The archived README describes a two-instruction-byte calibration-getter change
plus checksum adjustment on already-UHD UD04 firmware. Later settings include
broader mechanism adaptations. This is adapting UHD firmware for different
hardware, not evidence that original UD02 or MT1939 firmware gains all UHD
behavior from a tiny media-gate change. The user confirmed this distinction.

## Next tester action: read-only capture, no flash

Desktop package: `BH16NS48-Detection-Diagnostics.zip`.
Use the existing failed detection-1-5 image. After the same UHD fails detection,
leave it inserted, run `Capture.cmd` as administrator and return the timestamped
JSON. The Windows x64 static-CRT tool verifies firmware samples and records the
native DI-ready bit, media state, initialization/abort status, mode and capacity
state before standard capacity/configuration commands. It issues no writes,
flag changes, reset, tray commands or sector reads. Four mock tests pass, as do
the example build, Clippy and formatting checks. Checksums are in the adjacent
JSON and the package's SHA256SUMS.txt.

This snapshot may be partial or reflect cleared state after retries. It cannot
alone prove historical control flow. It is the available next evidence for
choosing a small acquisition/admission fix. Do not force readiness without valid
DI, and do not claim the currently inaccessible BU40N acquisition implementation
at runtime `0x01f95086` has been translated from the 2MB firmware file.
