# Independent old/new review of the six-gap necessity claim

2026-10-30. This review was conducted without reading the parallel agents' reports. It inspected the implementation, the corpus inventory as an address locator, and actual SHA-256-checked binaries. It did not modify firmware or run hardware. Local experiments are `/tmp/freemkv-cross-astra-{inspect,detail,mode,run}.py`; outputs have matching `.txt` or `.json` suffixes. The report name identifies the assigned review lane, not additional evidence.

## Conclusion

G01–G06 are a useful inventory of six reference behaviors, but are **not an established necessary-and-sufficient UHD capability specification**. G01 is a recognizable input-admission gate. G02–G06 are genuine state-dependent differences in shared processing, with different evidentiary strength and activation conditions. Nothing inspected justifies discarding their differences as cosmetic. Equally, neither correlation with stock UHD firmware nor six isolated passing contracts proves that all six changes are physically necessary, that they are sufficient, or that six is the complete list.

The G05 extension to **two numerical alternatives plus their selector** is justified if the objective is reference behavior. Extending G05 into a transplant of the entire modern mode/calibration/control subsystem is not yet justified as the minimal UHD change. The dependency investigation is justified; assuming its result in advance is not. A constant-zero substitute is also not justified as full reference parity.

The minimal complete physical-UHD patch set remains unknown. The minimal changes that can presently be defended are a bounded semantic conversion hypothesis, not an established physical-capability result.

## Binary evidence

Reviewed images:

- BU40N 1.02: `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`.
- BU40N BN11: `5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95`.
- BP50NB40 1.00: `c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306`.

The 24-image inventory independently counted as 24 legacy G01/G02/G04/G05/G06, 23 explicit G03, one legacy G03. That count is inventory evidence, not fresh execution across all 24. Actual disassembly and the execution experiment below are focused on the named binaries.

| Role | Observed distinction | What this establishes |
| --- | --- | --- |
| G01 | New `0xe0c74` admits identifier `0x55`; format 5 and layer nibble 2/3 select C7/C8. BN11 `0xdfaf6` tests `0x4f`, with other identifiers reaching an error/zero-state path. | A concrete rejection for the U-format input on this reached path. Closest of the six to a direct UHD admission requirement. It still needs input/caller reachability. |
| G02 | New `0x28f6e` tests C7 and sets bit 31; old takes the clearing path. | A real MMIO policy change, not a demonstrated hardware density/decoder meaning. |
| G03 | New `0x35456` tests C7 before the zero-field path. BN11 `0x3541e` already has the corresponding explicit selector. Earliest `0x33a14` differs. | The change is already present in 23 old images without U admission. It is neither a standalone capability marker nor a change needed in those 23. This does not prove its absence harmless on the earliest image. |
| G04 | New `0xd8752` admits C7 to `12*q + r7`; BN11 `0xd7da0` bypasses that final override. BN11 already contains the arithmetic at `0xd7dca`. | A missing dispatch edge into shared arithmetic, not a missing arithmetic implementation. |
| G05 | New `0xd885c` admits C7 and reads mode byte `0x02000b1a`; zero selects `r7−12*q`, nonzero `r5−9*q`. BN11 `0xd7e82` bypasses the override. Both arithmetic forms exist in BN11. | Selector semantics are larger than one C7 gate, but the numerical substrate is not new. |
| G06 | New `0xd8d52` extends the existing flag-bit-5/fixed-nibble-2 branch to C7; BN11 `0xd839c` routes C7 to a table lookup. | Conditional parameter difference. No difference when the flag is clear; even when set, table entries can make outcomes coincide. Physical need is unproven. |

The labels “forward” and “reverse” are mathematical directions here, not established physical units or mechanisms. `q` denotes the result of the existing divide helper for the observed arguments. No interpretation as physical radius, sector addressing, density, or servo behavior is asserted.

## G05 execution counterexample

A new independent Unicorn ARM926 experiment executes original image code and the original division helper. It seeds state C7, input halfword 100, `r5=0x3fd2`, `r7=0x5534`, and prior result `r0=0x1234`; starts at the native reverse selector; and stops after the result continuation. It uses artificial entry state, so it is **not** a whole-function or hardware test.

| Mode byte | BU40N 1.02 | BN11 stock | BN11 with experimental gate-only branch |
| --- | ---: | ---: | ---: |
| 0 | 21692 | 4660 | 21692 |
| 1 | 16248 | 4660 | 21692 |
| 2 | 16248 | 4660 | 21692 |

The experimental branch changes only emulator memory to route the selected C7 case into existing BN11 `r7−12*q`; it is not a production patch. This is a concrete disproof of “opening the C7 gate always gives the reference result.” It does not prove modes 1 or 2 are physically reachable for C7, or that their reference results are required for reading. Mode 2 also shows the C7 condition is **nonzero**, not “exactly 1”; the nearby C8 path uses a different equality condition.

The preceding arithmetic/calibration wrapper is substantially shared between BN11 `0xd7ce6` onward and new `0xd866e` onward: same input halfword address, temporary stores to `0x02000b40`/`0x02000b3c`, save/restore shape, threshold `0x20000`, and loaded constants `0x5534`, `0x3fd2`, `0x3b6f`. Reusing source-native arithmetic therefore has stronger evidence than importing a modern function wholesale. This structural comparison does not establish equal called-helper or hardware behavior.

## Why expanding G05 is both reasonable and dangerous

A direct PC-relative-literal scan for modern mode address `0x02000b1a` found 14 candidate references in the new image and two in BN11. New references include reads in control/MMIO selection (`0x291ce`, `0xdde48`), table-dependent paths (`0x78c6c`, `0x78d66`), reverse arithmetic (`0xd880e`), and stores/reset paths (`0x7af5c`, `0x7b028`, `0x82194`, `0xfc354`). BN11 references occur at `0x80df6` and `0xcac7e`, without a reverse-selector read. These are literal-pattern candidates manually sampled, not an exhaustive data-flow proof; base-plus-offset and indirect accesses are omitted.

This establishes that the modern mode is shared state, not a private G05 argument. It **does not** establish that BN11's same numerical RAM address has the same meaning. Copying the address or setting it opportunistically risks conflating unrelated state. Nor does importing the modern producer alone guarantee that its other consumers, resets, and table context are consistent. The safe research question is which source-native state can express the required predicate, and whether a modern-only mode is actually reached for the target C7 paths.

An acceptable reduction would be a proof that C7 always reaches reverse calculation with mode zero in the intended supported conditions. Then the second numerical alternative is unnecessary within that explicitly bounded scope. No such proof was obtained. An acceptable expansion would identify a reachable nonzero C7 trace, its producer, its required consumers, and the source-native equivalent or narrowly bounded new state. Neither case follows from isolated mode primitive tests.

## Hidden assumptions and counterexamples to the framework

1. **Circular classification.** `OEM UHD = 100% of G01–G06` defines the answer being used as evidence. Correlation between that label and six passes cannot establish necessity. Keep “matches six reviewed media behaviors” distinct from manufacturer-backed UHD product provenance and demonstrated physical reads.
2. **State-specific differences are not universal disc requirements.** U/5 with layer nibble 3 is admitted as C8; the five consumer changes primarily add C7 handling. Therefore those five differences cannot simply be described as five additional gates every UHD disc must pass. Existing C8 processing and mode behavior need their own trace.
3. **Shared arithmetic already computes a fallback.** Old code does not uniformly fail when C7 misses the final G04/G05 override; it preserves an earlier result. The preliminary result can depend on other selectors. A bypass is a numerical-policy difference, not automatically a hard read refusal.
4. **Explicit C7 recognition is a syntactic property.** A behavior can be correct through an inclusive mask or general default without an explicit C7 comparison. Conversely an explicit comparison does not validate all downstream values or consumers. Current signatures must not be promoted into a general capability oracle.
5. **G03 presence before G01** is a real counterexample to treating the set as an indivisible feature introduced all at once. It is not proof G03 is unnecessary in a complete C7 pipeline.
6. **Finite emulation coverage has a boundary.** Many isolated test cases can prove exact wrappers against specified seeds, while proving nothing about reachability, genuine MMIO response, producer/consumer ordering, initialization and reset, or omitted state consumers. A helper count is not evidence proportional to completeness.
7. **Transplantation substitutes one unknown for another.** Swapping code can reproduce local outputs while silently importing assumptions about tables, state ownership, hardware revision, and lifecycle. Source-native continuation binding is preferable where its inputs and side effects are understood; it still requires compositional tests.

## Concrete next steps

1. Preserve the six roles as comparison contracts, but stop presenting their conjunction as an independently proved UHD necessity/sufficiency theorem. Keep existing provenance/physical-validation qualifiers prominent.
2. Build a bounded C7/C8 data-flow map from DI output through the actual arithmetic caller, including entry state, preliminary result, input halfword transformations, mode producer, result consumers, and reset paths. Record edges as proven, sampled, or unknown.
3. Compare G05 at the whole containing-function boundary using matched **reachable** states. Run the actual division and calibration helpers wherever possible. Separate passive-memory equivalence from modeled hardware effects. Test original source and proposed source-native dispatch, not just a copied reference helper.
4. Resolve the nonzero C7 mode question before expanding production patch scope. If unreachable under a defensible support contract, document that constraint. If reachable, bind its native meaning and all required lifecycle effects. Do not reuse the modern mode address merely because it is RAM in the old image.
5. Establish G02/G03/G06 ordering and observable consumers before assigning physical necessity. The register writes are real; the physical interpretation remains unknown.
6. Once a candidate exists, use staged omission/ablation comparisons to find which edits are required for the chosen observable pipeline outcomes. Ultimately distinguish a bounded emulated conversion from DL/TL physical-read validation. No permission loop is needed for this read-only analytical work.

No candidate patches, firmware outputs, commits, resets, or hardware writes were produced by this review.

## Follow-up: G03 downstream investigation and a missing adjacent contract

This follow-up investigated the downstream reader identified by the other review lane, then independently scanned binary aliases and executed the actual existing G03 candidate. The initial review above remains independent; this follow-up explicitly uses the supplied `0x31b34` lead.

**Actionable defect in the reference-parity contract:** G03 currently captures only bits 7:4 of `0x04208270`, but the same containing function immediately performs a second state-dependent update to **bit 10**. Earliest BP50NB40 sets bit 10 for C7. BN11 and the stock UHD reference clear it. Therefore the actual existing candidate does not match even the containing function's register result. This is a proven missing reference behavior, not a new claim about physical UHD necessity.

Exact paths:

- Earliest: nibble store `0x33afc`; C8-mask-only test `0x33b08–0x33b14`; C7 follows `ORR` at `0x33b1c`, then store `0x33b1e`.
- BU40N 1.02: nibble store `0x35538`; additional family/C7 checks `0x35552–0x3555e`; C7 follows clear/store at `0x35562/0x35564`.
- BN11: nibble store `0x35514`; C7 follows clear/store at `0x3553e/0x35540`. Thus both the nibble and bit-10 changes predate the missing U-admission behavior in BN11.

The independent experiment `/tmp/freemkv-cross-astra-g03-candidate.py` installs the **actual** G03 bytes from `mt1959-uhd-conversion-plan-receipts-20261030.json` into emulator memory at `0x1e0000`, installs a Thumb BL at the recorded `0x33a1a`, verifies original source bytes, and enables feature byte `0x02000e43=1`. No disk firmware is emitted. It runs through both register writes, not merely to the selector continuation.

A second experiment, `/tmp/freemkv-cross-astra-g03-owner.py`, starts at the containing function's actual entry (including the literal load before PUSH): earliest `0x3392c`, reference `0x3535a`, BN11 `0x35336`. It seeds C7, function argument zero, zeroed other RAM/MMIO, and register word `0xffffffff`; executes the original prefix; and stops at the shared continuation after both writes (`0x33ba0`, `0x355ee`, `0x355ca`). It does not claim a full return-boundary or caller-to-hardware test.

| Image/candidate | Word after original prefix and both writes | Word masked by `0x4f0` |
| --- | --- | --- |
| Earliest stock | `0xfeffff3f` | `0x430` |
| Earliest actual G03 candidate | `0xfeffff0f` | `0x400` |
| BU40N 1.02 stock | `0xfefffb0f` | `0x000` |
| BN11 stock | `0xfefffb0f` | `0x000` |

The original prefix independently clears bit 24, explaining the `0xfe...` outputs. The candidate/reference mismatch is exactly bit 10. Output receipts are `/tmp/freemkv-cross-astra-g03-owner.json` and the suffix-started `/tmp/freemkv-cross-astra-g03-candidate.json`.

### What the supposed downstream reader actually does

The routine at earliest `0x31b34` has matching-prologue counterparts in BU40N 1.02 at `0x3353c` and BN11 at `0x33518`. It saves the entire `0x04208270` word at `0x31b42`, but **does not extract the incoming G03 nibble to calculate a CPU result**. Before the sample loop, it overwrites the whole register at `0x31bb8` with `0x01000000`: the supposedly mysterious `r5 << 17` is deterministic because r5 was set to `0x04208080` at `0x31b94/0x31b98`, and ABI-preserved through the intervening call. This clears both the nibble and bit 10 for the measurement interval, regardless of their saved values.

The routine then selects 0/3/6/9 in bits 28:24 of `0x04208210`, reads signed low-byte samples from `0x04208844` 128 times per selection, computes differences of accumulated sums, and restores the entire saved word at `0x31ca4`. Its return combines two signed difference results. Hence this routine is evidence for a **temporary hardware sampling configuration and preservation**, not a CPU consumer that decodes the original G03 field. The original value can affect hardware before or after the interval, but that is a different claim. No direct Thumb call or exact aligned/unaligned pointer to this routine was found in the inspected earliest image; this is not proof of dead code because indirect/relocated/constructed references remain possible.

### Alias scan and actual setter callers

`/tmp/freemkv-cross-astra-g03-alias.py` follows PC-relative register-base loads, immediate arithmetic, register copies, and both conditional successors for up to 180 instructions per seed. It detects accesses through `0x04208240+0x30`, `0x04208280−0x40+0x30`, `0x042082c0−0x80+0x30`, and related bases. It found 59 target-word accesses in earliest, 61 in the reference, and 60 in BN11. This is a bounded static candidate inventory, not an exhaustive disassembly theorem: it omits caller-supplied pointers, arbitrary computed addresses, ARM code, and hidden aliases.

Inspection of the earliest accesses found read-modify-write preservation, direct field replacement, and the whole-word save/restore above; no CPU extraction/branch/arithmetic using the old nibble was identified. Specific independent field setters include zero at `0x21150`, three at `0x273e4`, and twelve at `0x27bd8`. The G03 owner also clears the nibble on its nonzero-argument branch at `0x33b7a`. Thus the field is a mode-dependent hardware configuration shared with other paths, not a unique C7 tag in RAM.

The G03 setter's real entry is **`0x3392c`, not its PUSH at `0x3392e`**. Searching the actual entry finds direct calls at:

- `0x33e0e`: argument is bit 11 of r4 (`LSL #20; LSR #31`), after a separate configuration call at `0x33e06`. This call is gated by bit 15 of `0x04208018` and exclusions for r5 equal to `0x40` or `0x50`.
- `0x34246`: argument is bit 6 of RAM byte `0x02000b6c`, after changes to `0x04208140` and `0x042082c8`; then control rejoins `0x3413a`.

These are useful concrete caller timing constraints: reaching the function does not imply reaching the zero-argument G03 branch, and it may reconfigure the field more than once. The direct-caller search must include literal loads before PUSH; using PUSH as a universal function boundary misses real edges.

### Source check and consequence

An explicit web search for MT1959 register documentation and the address found the manufacturer's [MT1959 product page](https://www.mediatek.com/products/smart-home/optical-disc-drives/mt1959), which describes the optical SoC but supplies no register definition for this field. No authoritative field name or datasheet definition was obtained. Do not label it a density selector, clock selector, equalizer setting, or decoder mode without additional evidence.

The immediate implementation consequence is to widen the **reference-comparison** G03 contract to include the adjacent bit-10 selector and test through both stores. The research consequence is to trace the two actual setter callers, their r4/r5 inputs, and the lifetime between configuration writes. CPU-only observations currently support “shared hardware configuration with preserved neighboring fields”; they do not identify the hardware's internal use of the nibble. The found sampling routine cannot fill that gap because it replaces the setting before sampling.

## Follow-up: G01 controller-policy closure using source-native machinery

This follow-up read `mt1959-resident-worker-qualification-20261030.md` as requested, then independently resolved the old worker, inspected the captured 1.03 helper, scanned old register/state consumers, and executed paired original code slices. No private binary or donor implementation was copied into the repository. No production patch was made.

### A concrete local-fallback mismatch does not require resident transplantation

BN11 `DB0E0` is **ARM**, not Thumb. Its veneer branches to `148454`, which loads Thumb pointer `DB801`; the actual old local worker is `DB800`. Selector 4 chooses index 1, updates selected-speed byte `02000B0B` through its own table, and writes `02000B01=2` at `DB844`.

There is a missing C7/C8 policy in this old local worker independently of the resident mode. BN11 `DB9F8–DB9FE` loads a halfword from its own table `14F89A`, indexed by twice the selected index, and calls its own controller-target routine `DAC00`. The four table values are `[2100, 3400, 5000, 6500]`.

Stock BU40N 1.02 local fallback `DC6DE–DC6FA` and BU40N 1.03 local fallback `DC8C6–DC8E2` select **a second table for `(state >> 2)==0x32` or state C7**, otherwise selecting the original-value table. Both newer versions' second table is `[1860, 2547, 3745, 4869]`. Its address is `150DE6` in 1.02 and `150FDA` in 1.03. The original-value table remains `[2100, 3400, 5000, 6500]`. This comparison does not assume resident addresses or bodies are equal between versions.

The target consumer is structurally present in BN11: `DAC00` saves the chosen halfword to `01FF9EDC` at `DAC26`, obtains a native measured value through `D8FC6`, compares the signed difference against an approximately ±150 band, and otherwise calls its own control calculation `D9444` before updating further native state. New 1.03 `DB834` has the corresponding store at `DB85A` and the same comparison shape. This establishes **table producer → desired target → native controller comparison**, without assigning a physical unit to the number.

The experiment `/tmp/freemkv-cross-astra-policy-cpu.py` executes the old suffix from `DB8CA` and 1.03 suffix from `DC808`, with index 1, the corresponding doubled index 2, explicit media state, and zero MMIO. It stops on entry to the actual controller-target routine, rather than stubbing that routine and pretending hardware convergence. Results:

| State | BN11 argument to its native target routine | 1.03 argument to its native target routine |
| --- | ---: | ---: |
| C0 | 3400 | 3400 |
| C7 | 3400 | 2547 |
| C8 | 3400 | 2547 |

The inspected register writes preceding this call match in these slices. This is an actionable missing density-class dispatch **even if the resident path were deliberately excluded**. It is not merely the U-marker flag itself, and it affects C8 as well as C7.

A minimal new **reference contract** can therefore bind the old selector/index computation, source-native desired-target call, target-state store, and the C7/C8 class predicate. It can author a narrow value selection at the old call boundary while retaining `DAC00`, all old control primitives, old lifecycle, and normal-media values. It must not globally replace the normal table, because the reference keeps it for other states. No new mode orchestration or donor NV is required to express this particular behavior. The newer target values are immutable firmware policy evidence, not recovered per-drive NV; their suitability across all 24 old hardware variants still needs per-source qualification rather than automatic transplantation. No contiguous equivalent four-entry table was found in BN11, so do not claim its existing table alone already contains the new target mapping.

### Resident marker policy is more than the local table

Independently executing the 1.03 resident helper from `01FBB02E` through its tail predicate confirms the previously reported marker differences. This run maps the captured runtime region plus the stock 1.03 flash and stops at the logger veneer `01FE77F8`; it does not replace the predicate with a guessed return. The real `01FE8D2C` veneer points to stock Thumb predicate `66832`. For argument 4 the predicate returns zero, so the BCE threshold survives the subsequent conditional overwrite. Thus the earlier stop at `01FBB14E` did not hide an overwrite in these cases.

| C7/C8, selector 4 | Marker 0 | Marker 1 |
| --- | --- | --- |
| `0420502C` masked configuration | `8` | `8` |
| `04205030` in zeroed MMIO fixture | `03000000` | `03000000` |
| `04205034` low 11 bits | `285` | `295` |
| `04205040` bits 11:8 | `C` | `C` |
| `04205044` low nibble | `D` | `A` |
| `02000BCE`, C7 | `0E` | `04` |
| `02000BCE`, C8 | `11` | `04` |

The **marker-specific** register deltas are `04205034` and `04205044`, plus BCE. The shared writes are mode setup, not additional U-marker effects. Marker 1 with C0 produces BCE 9, so BCE 4 additionally depends on the C7/C8-class predicate; simply copying one marker-specific constant without its media predicate would broaden behavior.

The local fallback does not implement these same outputs by choosing another existing speed-table entry. Both old `DB9CE–DB9D4` and new local `DC89A–DC8A0` clear the low nibble of `04205044` with shifts and no table input. Their bounded suffixes leave `04205034` unchanged. Their selector-4 table result for `04205040` is `A87` in zeroed MMIO, not resident `C00`. Consequently a table-only edit cannot make the local mode equal the resident mode: the zero nibble is hard-coded. That does not mean local mode must be made equal to resident mode; the two are distinct policies already present in the reference.

### Existing old BCE production and consumption: not a harmless label

BN11 already uses `02000BCE` in a broad controller threshold role. Its own function `F30B6` selects policies for numeric arguments 4/6/8 and writes the same controller region. For argument 4, existing state and byte `01FF9E08` select constants for `04205034`, `04205040`, and `04205044`, then the native state predicate chooses BCE 5 or 6. This path is not equivalent to the resident U policy: the observed constants differ. Its existence does establish that the old firmware already has native machinery owning these registers and threshold state; inventing a new RAM state merely to reproduce the captured helper is unnecessary.

Concrete old consumers include:

- `D9CCE–D9CD6`: compares byte 2 of `02000B3C` with BCE and conditionally enters further control calculation.
- `E33FE–E3418`: the same comparison selects a multiple of selected-speed byte `02000B0B` (14 versus 8), influencing subsequent arithmetic.
- `F325E–F3276`: under additional flags and bounds, a below-BCE result sets a flag in `02000B15` and writes halfword 500 to `02000B2C`. That halfword is an actual input used by the previously reviewed G04/G05 arithmetic wrapper.
- `E1BF0` and `E2EE4`: comparisons can invoke the exported speed interface again.

This closes a meaningful software dependency: changing BCE changes old control decisions and can change the later arithmetic input. It does **not** prove that all these consumers occur on the intended raw-read command path. Assigning the modern threshold without its producer/lifetime predicate can therefore alter established old behavior rather than merely fill an unused field.

### Source/version qualification

The flash slices used during discovery were checked byte-for-byte against the unpatched corpus BU40N 1.03 image `64688690a2878c792833d9af8731004411f86d7a64ceb522a82368584d84282a`. The complete local worker range `DC6DE..DC922`, associated table range `150F78..151006`, and predicate `66832..6686C` match that stock image. The final experiment uses that stock flash directly. The resident bytes retain the documented provenance limitation: they come from the held live 1.03MK capture, with a positively bound OEM-style worker path; no identity with 1.02's resident address/body is asserted. Capture bytes remain outside this repository.

### Concrete next contract and remaining decision

The next narrow implementable contract is **source-native C7/C8 desired-target selection at the existing local worker's controller call**, covering all four speed indices and retaining normal-state values. This is a newly demonstrated reference mismatch on a path the older firmware already executes, and does not require importing resident machinery.

Separately, qualify the resident-mode policy at a full transition boundary: determine whether the intended old raw-read path selects the policy equivalent to the reference U/selector-4 resident mode, trace all three marker-specific values to their next consumers, and verify the source-native reset/reconfiguration rules. If that policy is required, its contract must include both MMIO settings and BCE lifetime; adjusting one old density table cannot express it. If the intended supported path stays in the local policy, the reference's local density-target difference remains relevant while the extra resident mode may be unnecessary for that bounded path. There is not yet evidence to call it an optional optimization or a universal UHD prerequisite.

This advances beyond an undifferentiated “unknown”: the local density-target selector is independently actionable, the resident mode has a precise three-value observable delta, the old threshold consumers are located, and a table-only resident equivalence hypothesis is disproved. Physical read necessity and full raw-read transition reachability remain to be established.
