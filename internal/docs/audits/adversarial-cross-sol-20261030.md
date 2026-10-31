# Independent Sol comparison of older and newer MT1959 media paths

Reviewed source at firmware worktree f5b7f12 and dependency 66c4b1c. This review independently inspected the implementation, positive signature grammars, and actual Thumb instructions from the hoard; it did not consume other review agents' reports. No firmware edits, hardware operations, commits, or new agents.

## Finding

The six contracts form a useful parity inventory, but the statement that all six are individually necessary for UHD reading is stronger than the current evidence. Local source-bound C7 behavior is established; a complete acquisition-to-consumer UHD execution trace is not. In particular G03 already works in 23 old images, G04's numerical worker already exists, G05's two numerical workers already exist, and G06 has concrete input classes with identical old/new output. Preserve the pending G05 installation boundary, but describe it as an unresolved mode/control binding rather than missing UHD arithmetic.

Reference source SHA256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396` (BU40N general 1.02); older counterpart `5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95` (BN11); earliest `c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306` (BP50NB40 1.00). Addresses below are file offsets, not presumed live load addresses.

## Per-contract necessity challenge

* **G01:** Strongest direct admission evidence. New `0xe0c74` compares identifier U; density5 with high nibble2 produces C7, nibble3 C8, and stores through `0xe0cb2`. BN11 `0xdfaf6` instead compares O, reaches its error route at `0xdfb0e` for U, clears state at `0xdfb16`, and selects error14. Thus this particular native parser rejects the relevant input. Whether every actual UHD load necessarily traverses this parser remains a separate caller/acquisition question. Retain the source-bound format handler, density/layer handling and subsequent native stores; a U-byte substitution is insufficient.
* **G02:** Real C7-dependent MMIO difference. BN11 `0x28f4c` BICS C8,C7 is nonzero and clears bit31 through `0x28f64..68`; new `0x28f6c..70` explicitly admits C7 to the bit-set arm at `0x28f72`. This establishes a changed control setting when this routine runs; absent hardware semantics/caller evidence it does not prove bit31 is individually required for reading UHD. Other states already share the native high-density arm.
* **G03:** No patch is necessary in BN11: explicit C7 compare `0x35432` reaches the same field-clearing arm as new `0x35456`. Earliest BP50 has no compare at `0x33a14..24`. This is a one-image remaining local parity gap, not a 24-image UHD requirement.
* **G04:** BN11 already contains divide-by10 then multiply12 and addR7 at `0xd7dca..da`; new has corresponding worker `0xd8756..66`. The change is routing C7 into existing shared arithmetic. New explicit C7 edge is `0xd8752..54`; BN11 rejects through `0xd7da0 -> 0xd7e96 -> 0xd8054`. Importing another firmware's worker is unnecessary. Still unresolved: which real acquisition/control conditions lead to this arm, and whether returned arithmetic controls acquisition, calibration, or another operation. The nearby save/control-call/restore sequence (`0xd86b0..d6` new, `0xd7d28..50` old) argues against describing these isolated workers as demonstrated sector-address conversion.
* **G05:** New reverse C7 gate `0xd885c..66` reads mode through R1. Its mode pointer is literally `0x02000b1a` from `0xd880e`; the state pointer is `0x01ff9e04` from `0xd8804`. Zero mode reaches `0xd8868` divide10/multiply12/subtract fromR7; nonzero reaches `0xd884a` divide10/multiply9 then `0xd891a` subtract fromR5. BN11 already owns 12/subR7 at `0xd7eb0..c0` and 9/subR5 at `0xd7ea0..ac`. Crucially the latter then branches to `0xd7e76`, while the former exits through `0xd7f2e`; their entry/exit context differs. A direct C7-to-one-worker detour cannot prove mode production, correct base register, or continuation equivalence. The missing knowledge is the mode producer and surrounding state/control contract; byte emission is routine once those are bound.
* **G06:** Conditional difference with a concrete counterexample. New `0xd8d50..66` admits C7 to the bit5 test and writes low nibble2 only if bit5 is set. BN11 `0xd839c` bypasses that test for C7 and looks up its table. Both actual tables are identical: new `0x14da2f`, old `0x14c4eb`, bytes `[4,4,4,3,3,3,3,3,3,2,2,2,2]`. Therefore C7 with bit5 clear already matches at every index. With bit5 set, indices9..12 also already write2. Only indices0..8 with bit5 set change output (4/3 becomes2). Reachability of those differing combinations during UHD use must be established before calling the change indispensable. Keep native lookup for ordinary states and flag-clear cases.

## What the current tests do and do not prove

The engine's `selects_c7()==Some(false)` classification marks a matched local grammar as a conversion gap; it does not compute actual caller reachability or necessity. Dependency documentation correctly says matched regions are not complete functions. The engine unconditionally leaves G05 pending when recognized legacy, even though both arithmetic primitives already exist; this accurately prevents incomplete installation but obscures the narrower unresolved boundary.

Isolated ARM926 execution can establish flag/register restoration, exact arithmetic, and selected MMIO writes under supplied initial state. Passive MMIO and preseeded mode bytes cannot show optical acquisition generates those values, that a command reaches each arm, or that the physical device observes the required timing/control response. The reported 103776 cases should remain evidence of those local properties, not necessity of all six edits or physical success.

## Minimal next work

1. Trace writers and reset lifetime of new mode byte `0x02000b1a` to the controlling function and real C7 input path; bind the analogous old state only if a semantic producer exists. Do not borrow a same-offset old byte by appearance.
2. Execute the enclosing native routine with its actual entry contract and controlled return values from the hardware worker, comparing control writes, base-register production, restoration and both mode outcomes. Separate a hardware response assumption from verified behavior.
3. Run selective conversion variants: G01 only, then each proven reached consumer. Capture first divergence between old and new under the same logical input. For G06 specifically exercise bit5 clear, indices9..12, then the differing indices0..8.
4. Keep the distinction between classification parity and reading necessity in reports/API descriptions. No evidence here justifies adding G07/G08 authentication changes or hardware-default replacement.

Reproduction artifacts: `/tmp/freemkv-cross-sol-inspect.py`, `/tmp/freemkv-cross-sol-detail.py`, `/tmp/freemkv-cross-sol-disassembly.txt`; scripts use the supplied Python/Capstone environment and source corpus paths. These are disassembly observations, not a fresh complete acquisition emulation.

## Follow-up: G05 downstream value and old-consumer compatibility

Independently traced the reverse result through the enclosing routine, rather than assuming that its numerical worker returns a sector address. The reverse arithmetic produces **internal R6**, narrowed to low16 at new `0xd88e4..e6`. It branches into the common suffix at `0xd8a0a`; BN11 corresponding common result is `0xd7f2e` and suffix eventually `0xd8054`. The enclosing function ultimately returns **R5**, not this raw reverse coefficient.

The suffix restores a saved halfword and a flag bit, then calls new `0xdb838` (old counterpart bound by its call at `0xd806a`, rather than by fixed displacement). The new helper polls MMIO status and reads halfword `0x04205084`; its normal return at `0xdb8d6..dc` is `(halfword & 0x7ffc) >> 2`. Timeout returns `0xffff` at `0xdb8d2`. The caller handles zero denominator before the division path, returning0 or E6 according to a flag. Thus passive MMIO tests with a supplied nonzero denominator deliberately exclude this acquisition/status boundary.

On the nonzero path, new `0xd8a38..56` and old `0xd8082..a0` read `s=(MMIO[0x04000028]>>4)&7`, set R7 to originalR6 shifted by s, then compute two quotients using the native unsigned division worker: R6=originalR6/d, R5=low16((originalR6<<s)/d). For C7 the `state>>6==3` arm doubles both modulo65536 (`0xd8a6a..70`, old `0xd80b4..ba`). Subsequent code checks policy, flags and a small bounded stack table. Threshold scanning increments its index only through4; entries0..4 select a hardware shift setting. The reverse output is compared against thresholds; it is not used as an unbounded table index.

The principal sink calls new `0x27e2c` / old `0x27e1c` with low16(R6<<currentSelector). Their actual instruction bodies match up to relocated calls. A zero argument returns immediately. Otherwise they select K from `[0x15180,0x2a300,0x54600,0xa8c00]` according to bits4..5 of MMIO `0x0420c07e`, calculate `((K/input)-256)<<4`, apply native bounds (0x1800..0xf000, with a special flag-dependent0x2000 boundary), and store a halfword at `0x01ffa104`. The called helper new `0x27e08` / old `0x27df8` translates the upper nibble into bits4..5 of MMIO `0x04207508`. The selector helper new `0x2a5c6` / old `0x2a5a6` writes selector&7 into bits4..6 of MMIO `0x04000028`, then invokes another native helper. The enclosing routine finally persists R6 at `0x01ff9e74` (new `0xd8cf2`, old `0xd8340`) and moves R5 into return R0.

**Software meaning supported by these instructions:** a normalized rate/timing coefficient, with a companion scaled quotient, consumed by reciprocal timing conversion and hardware shift selection. Specific physical units, spindle/channel nomenclature, and optical meaning require hardware documentation or stronger control-flow context; calling it LBA/sector conversion is unsupported here.

### Reproducible counterfactual check

`/tmp/freemkv-cross-sol-counterfactual.py` executes both native common suffixes in Unicorn, starting new `0xd8a38` and old `0xd8082`. Result `/tmp/freemkv-cross-sol-counterfactual.json`: **1370 cases, zero differences** in normalized external helper calls/arguments and persisted R6. Values include the full16-bit domain on a257-step grid plus explicit near-zero, threshold, high-bit and wrap boundaries. Environments include (denominator,selector,policy) `(1,0,0),(2,1,0),(8,3,0),(1,0,2),(2,1,2)` with stateC7.

Assumptions are explicit: initial reverse R6 and nonzero hardware denominator are supplied; stack thresholds are controlled; hardware is passive except selector writes modeled at the intercepted selector helper; external helpers are recorded/skipped; division calls use unsigned quotient hooks. Consequently this proves sampled compatibility of the **actual old software consumer** with any supplied new result in those cases. It does not prove the native producer generates a particular sample, the skipped helpers have equivalent real hardware effects, or timing/optical success. No case suppresses an observed old C7 rejection in the suffix: the old code already admits C7 via class bits.

The minimal candidate boundary is therefore the old producer's C7/mode routing plus any demonstrated base/flag preparation required by that producer. Retain the old common suffix, bounded tables, reciprocal timing sink, final persistent store and existing hardware helpers. Blindly copying the complete new orchestration is unnecessary for downstream acceptance based on this evidence. The remaining ROM/hardware boundary is the actual worker's measured/status return and effect of control/MMIO settings; importing more executable bytes does not establish that response.

Additional disassembly scripts: `/tmp/freemkv-cross-sol-consumer.py`, `/tmp/freemkv-cross-sol-sinks.py`, `/tmp/freemkv-cross-sol-selector.py`, `/tmp/freemkv-cross-sol-tail.py`. Their linear output may display literal pools as instructions; all conclusions above follow explicit branch targets and literal loads, not those pool decodes.

### Correction to mode binding: old B19 is the relevant analogue

A fresh literal-load scan (`/tmp/freemkv-cross-sol-flags.py`, output `/tmp/freemkv-cross-sol-flags.txt`) independently supports reusing the older mode cell **0x02000b19**, not the same numerical address as the newer0x02000b1a. This is anchored in three distinct paired consumer grammars:

| Consumer | BN11 pointer load / mode cell | BU40N1.02 pointer load / mode cell | Shared operation |
| --- | --- | --- | --- |
| Hardware control | 0x291ae / B19 | 0x291ce / B1A | mode==0 selects same bit masks and constants0x13<<9,3<<9 |
| Table family A | 0x7884c / B19 | 0x78c6c / B1A | explicit C7 admission followed by mode==0 |
| Table family B | 0x78946 / B19 | 0x78d66 / B1A | explicit C7 admission followed by mode==1 |
| Table family C | 0x78dde / B19 | 0x791fe / B1A | same register binding and later C7/mode test at old78eb4/new792d4 |

Old B1A at `0xcac7e` belongs to a different class4 branch and must not be imported as the reverse-mode analogue merely because its address matches. Reset code clears oldB19 at `0x81b16`; newer code separately clears B19 and B1A at `0x82192,0x82196`. New B19 also receives the DI U marker at `0xe0c7c`, which demonstrates that address identity is particularly misleading here.

The direct-literal scan sees newB1A stores at `0x7af5e` (valueR6), `0x7b02c` (zero), `0xfc358` (zero), plus reset. For oldB19, this scan establishes the reset and many reads; it does not establish a nonzero writer. This scan deliberately does not claim completeness for indirect/derived-address writes or overlapping stores. Semantic identity is strongly supported for **existing consumers**, while mode-producer lifetime remains an independent obligation. A new reverse gate should bind the oldB19 cell by these consumer grammars, with the matched originals retained; it should not install another firmware's complete calibration routine just to manufacture an address-aligned flag.

The old common suffix's denominator helper is concretely `0xdadfc`, called at `0xd806a`; the earlier general description intentionally bound it by call rather than an assumed displacement.
