# Adversarial G01 audit — 2026-10-30

Verdict: **conditionally needed** for U/5 identification through the inspected parser; **unproven** as a complete physical detection/read requirement. This is a real identifier admission difference, not merely a shared BDXL calculation difference. G01 alone does not prove that C7/C8 is the only workable read strategy.

Inspected immutable stock payloads in hoard/originals (addresses are payload offsets / native mapped code addresses):

- BU40N BN11: SHA256 `5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95`.
- BU40N 1.02: SHA256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`. The leading `1` matters; `bbeb535...` supplied in assignment is not the full hash.
- BP50NB40 1.00: SHA256 `c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306`.

## Exact local paths

BN11 caller starts `0xDF8E6` (push saved link, subtract 0x4c). Its actual instruction `0xDF8F0` loads R7 from literal `0xDFC14`, value `0x01FF9E04`. Thus state identity is tied to real caller code, not an emulator-supplied R7. The caller copies raw buffer data into SP+0x44 (BD prefix) and SP+0x48 (identifier/attributes/layers/density) at `0xDF998–0xDF9DA`, using source base `[0x02000C78]` and offset `[0x01FFA38C]`. This establishes input provenance within the function; it does not establish that optical acquisition produced these bytes.

Prefix check at `0xDFA82` requires BD. Attribute bits 5:4 must be 0 or 1 at `0xDFA98–0xDFAA6`. W and R cases precede the O-only ROM case. At `0xDFAF2–0xDFAF8`, identifier U fails CMP #0x4f and branches to `0xDFB0E`. The diagnostic path calls `0xCA99C`, clears `[R7]` at `0xDFB16`, and returns status 0x0e through `0xDF96A`. U therefore does not merely retain a usable generic BD state on this path. O densities 0/1/2 assign C0; generic layer normalization then makes 2L C4 and 3L C8 (`0xDFB56–0xDFB8A`). **C8 is already shared with generic three-layer ROM; treating all C8 behavior as UHD-specific is unjustified.**

Earliest BP50 repeats the rejection at `0xE30A8–0xE30AE`, diagnostics `0xE30C6`, clear state `0xE30CC–0xE30D0`, status0x0e. Its real state pointer is loaded per store: e.g. `0xE30C0` resolves literal `0xE327C` to `0x01FF9DEF`.

Reference BU40N1.02 reloads actual state pointer at `0xE0BD2` from literal `0xE0F80` = `0x01FF9E04`. Its U branch at `0xE0C74` accepts density1 as generic C0 and density5 with layer2 -> C7 (`0xE0C98`), layer3 -> C8 (`0xE0C90`), shared store `0xE0CB2`. Density5/2L is specifically distinguished from generic O/2L C4. Layer normalization explicitly preserves C7 at `0xE0D1C–0xE0D20`; C8 naturally survives three-layer normalization.

## Counterexamples / limits of prepared helper equivalence

1. Reference attribute validation is **prior-state dependent**, `0xE0BD2–0xE0C28`; it is not simply a universal attr0/3 predicate. For an ordinary initial state0, attr1 passes the final gate, whereas helper `di_candidates` in `crates/freemkv-fw/src/engine/mt1959_uhd.rs` requires attr0/3 for its U/5 detour. This is an input-level counterexample to universal reference equivalence, not proof that attr1 occurs on valid UHD media.
2. Reference U handling stores **a separate U marker** `0x02000B19=1` at `0xE0C78–0xE0C7C` (literal `0xE0F88`), before checking density. Prepared helper skips directly to native density-format handling and does not reproduce this store. The native density classification byte is instead `0x02000B6D` (reference literal `0xE0F90`, BN11 literal `0xDFC64`). They must not be conflated.
3. Reference marker has real consumers: `0x666EE`, `0xA3C86`, `0xA3DCC`, `0xA42B8`, `0xA444C`, `0xA457E`, `0xCACF4`, `0xD9AAC`, `0xDA724`, `0xDA8CE`, `0xDBB8E`, `0xDCA40`, `0xE0426`, `0xE05D6`, `0xE297E`, `0x136A98`, `0x13F258`, `0x140A06`. For example `0xE05D6` selects 0x86 versus0x80 from it. These are unresolved functionality, not automatically additional required patches. BN11's numeric address0x02000B19 also has references, but RAM address coincidence does not establish matching semantics across versions.
4. The helper recognizes only U/density5/layers2or3. Reference also admits U/density1. That is deliberately narrower scope, not full reference DI behavior.

Existing native DI receipts expressly start after assumed prefix/attribute validation and stop at state store/outgoing edge. They cannot prove full parser outcome, physical acquisition, ready state, or reads. The rejection clear/status path above follows the actual stock instructions beyond their stopping boundary.

## Reproduction and next action

Disassemble the above original .bin ranges with Capstone ARM/Thumb (installed `/tmp/mt1939-recognition-venv/bin/python`). An owned static cross-reference script `/tmp/freemkv-g01-xrefs.py` enumerates aligned literal values0x02000B19 and Thumb LDR literal references in both stock images; no firmware changes or hardware operations occurred.

Next: trace the U marker consumers to their caller/operation identities and compare equivalent BN11 behavior; execute the full parser from its raw-buffer copy with real state definitions and matched initial-state matrix, including attr0/1/3. Then establish the optical acquisition caller path or capture real DI input. Until that is done, label G01 a proven parser admission gap and conditional read prerequisite, and avoid claiming the two detours are complete OEM G01 equivalence.

## Follow-up: fuller parser execution and correction (2026-10-30)

**Correction to the earlier static attr1 example:** initial-state0 accepts only attr0 in native1.02. The earlier paragraph saying attr1 passes for state0 was incorrect. Native execution resolves the conditional shifts precisely.

Owned reproducible experiment: `/tmp/freemkv-g01-parser.py`; results `/tmp/freemkv-g01-parser-results.json` (128 cases), `/tmp/freemkv-g01-parser-extra.json` (8 cases). Uses Unicorn ARM/Thumb and executes real stock prologues from BN11 `0xDF8E6` / native `0xE0970`, real state-pointer definitions, actual raw-buffer copy loops, prefix/attribute/identifier/density logic, actual ARM switch function (`0x137C34` / `0x138F88`), and complete layer normalization. Native stops at `0xE0D42`; rejection stops at the status0x0e return epilogue. BN11 stops at normalization `0xDFB8C` or its status return epilogue. It explicitly bypasses hardware acquisition by jumping from BN11 `0xDF910` to `0xDF998`, native `0xE099A` to `0xE0A30`; the diagnostic logger returns immediately. Raw input source is mapped at0x02100000, native source pointers are seeded, caller SP starts0x0200E000, other RAM starts zero. **No R7 is seeded.** Initial media state is an explicit matrix input, not claimed to arise from hardware.

For U/density5, layers2 and3:

| Initial state | Native accepted attribute bits5:4 | Output when accepted |
| --- | --- | --- |
| 00,C0,C4,E0 | 0 | C7 for2L, C8 for3L |
| C7,C8 | 0,3 | same |
| E8,F8 | 1 | same |
| CC,D8 | 0,1,2,3 | same |

All accepted native cases set U marker1 and density classification0x20. All rejected cases clear actual state and return0x0e. BN11 rejects every U case in the128-case matrix, including otherwise permitted old attributes0/1. No emulation errors occurred.

The exact native attribute predicate, extracted from `0xE0BD2–0xE0C28`, is:

```
if state == C7 || state >> 2 == 32h: attr in {0,3}
else if state >> 3 in {1Dh,1Fh}: attr == 1
else: (state & C8h) == C8h || attr == 0
```

This predicate is evaluated before U classification; it does not establish which prior states actually occur for an inserted UHD disc. The current helper's unconditional attr0/3 both over-admits (state00/attr3) and under-admits (stateE8/attr1). A source-bound minimal correction must consult the bound `di.state` byte and reproduce this predicate for its U/5 detour, or explicitly document a narrower proven prestate invariant. Retain original replay on rejected cases. Test state00, C7, C8, E8, F8, CC, D8 × all four attrs × layers2/3, plus feature-off/non-U/wrong-density and invalid-layer conservation. Do not silently substitute old attr0/1 semantics either.

### Separate marker resolved: old address collision

**Do not write1 to old0x02000B19.** Matched native consumer `0x792D4` to old `0x78EB4`: both compare media stateC7 and branch on `[R7]`, but the real pointer definitions differ:

- BN11 `0x78DDE`: R7=0x02000B19.
- Native1.02 `0x791FE`: R7=0x02000B1A.

The reset routine independently confirms this structural insertion: old `0x81B14–0x81B16` clears existingB19; native `0x82190–0x82196` clears new UmarkerB19 **and** existing flagB1A. Native also inserts clear of0x02000C12 immediately before those. Thus oldB19 corresponds to nativeB1A in at least this source-bound consumer; a naive native-marker store corrupts a different existing control flag. This is stronger than mere address ambiguity.

Native's U marker genuinely selects paths/parameters beyond DI, e.g. `0xE05D6` selects0x86 versus0x80; `0xDA724` / `0xDA8CE` select different table pointers; `0xA3C86` gates state-dependent handling. Their hardware/read necessity and corresponding old consumer mappings remain unproven. A private marker without consumer changes cannot reproduce these behaviors. A G01 helper should honestly claim U/5 parser admission and final state normalization, **not complete native DI side-effect equivalence or complete OEM read support**. Native marker translation must be a separately source-bound undertaking before asserting that larger claim.

Recommended immediate production change after overall review: fix the helper attribute predicate as above; add matrix/conservation tests; preserve actual source-derived state and density stores; do not add a native-address Umarker write. Keep marker/consumer work recorded as unresolved rather than treating the six labels as exhaustive proof of OEM behavior.

## Implemented bounded correction

Updated only G01 `di_candidates` attribute handling to load the source-bound state byte and implement the exact prior-state predicate above for both detours. Scratch R1/R2 remain within the existing saved register set; emitted code remains Thumb1. Rejected cases replay the displaced original instructions. No U-marker write was added.

Extended `scripts/test-mt1959-conversion-candidates.py` with a SHA-pinned stock BU40N1.02 raw-buffer parser oracle:80 actual native parser cases, rather than a Python predicate copy. Added all four attrs, both valid layer counts, both incoming V flags and nine additional prior states to each old-image G01 detour test, retaining the broad feature-off/non-U/density/layer conservation checks. Oracle bypasses acquisition and stubs diagnostics exactly as documented above; it validates classification, not native marker side-effect equivalence or physical reading.

Validation so far: all five `engine::mt1959_uhd::tests` pass; the80-case native parser oracle passes; `git diff --check` passes. Complete all24 regenerated candidate CPU run follows separately.

Final bounded-correction verification: regenerated every old24 source plan, extracted exactly48 G01 detours (maximum180bytes), and ran **76,032 ARM926 selector/conservation cases across all24 images**, including earliest BP50, against the80-case actual native parser oracle. PASS. Receipts: `/tmp/freemkv-g01-corrected-plans.json`, `/tmp/freemkv-g01-only-corrected-plans.json`, `/tmp/freemkv-g01-corrected-cpu.json`. This focused G01 run intentionally excludes concurrently changing G03/G05 helpers; final integrated regeneration/testing remains the parent task's responsibility. Production installation remains blocked by unresolved G05 until separately validated.

## Bounded new-U-marker consumer audit

Verdict: **media-related, necessity still unproven**. The marker is not exclusively reporting/authentication. It participates in speed selection, servo targets, transition timing and a different hardware-worker dispatch. However, several apparent differences are redundant for U/5 states, and a new flag is not justified merely by those references. Do not port unrelated native changes or write the old mode flag.

Direct-reference inventory in SHA256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`:18 reads, plus set at `0xE0C7C` and reset at `0x82192`, from20 Thumb literal loads. No ARM LDR-literal reference to the exact marker address was found. This bounds direct literal references; it is not a proof excluding aliases formed from a neighboring address. Producer set occurs for identifierU before the density check, so marker also describes U/density1 and is not synonymous with stateC7/C8. Reset shares the actual initializer context with adjacent per-disc fields.

| Native marker read | Observed branch/output and downstream | Source-bound old counterpart |
| --- | --- | --- |
| `666EE` | Input4 returns0; C7/C8 already return0 for inputs>=6 and fallback returns0 below6. Marker change is redundant for tested U/5 cases. | `664CE` function lacks marker branch. |
| `A3C86` | Selects speed cap6 for C7/C8,4 for other U states; returns min(requested cap, selected cap). Calls from `9FD30`, `A3F6C`, `A425C`. | `A3506`; fallback begins `A3522`. |
| `A3DCC` | Skips update of target speed byteB0C and timersC92/C96 when marker set. | Old `A3636–A3642` performs update without marker guard. |
| `A42B8` | With statusBD42==2 allows target-speed transition before the D2E>0x32 threshold; flows through `A426C`. | Old transition block `A3AF2` onward; no marker early-transition clause. |
| `A444C` | Skips B0C target update and transition counters when marker set. | Old `A3CAE–A3CB8` falls directly into update. |
| `A457E` | Skips timer reset / call through ARM wrapperD9964 / B0C update when marker set. | Old `A3DDA–A3DE6` lacks guard. |
| `CACF4` | With predicate6EABA true, selects parameter77h instead ofA8h; flows through `CAD44` to `135466`, which packs parameter into command20h and invokes `CA564` (direct MMIO04011040/04000000). This is an internal hardware command, not a proven AACS dispatch. | Old analogous switch at `CA444–CA456`: C7/C8 choosesDCh; other statesA8h; common continuation `CA49A`. |
| `D9AAC` | If marker and halfword9EDC>3000, calls61612 / delay5EBBE and sets bit7 of9DEB before MMIO04205000 polling. | Old `D90B8–D90C2` goes directly to poll without clause. |
| `DA724` | For C7 at speed4 selects target5000 instead of4200. C8 already5000 independent of marker due earlier state check. Target flows throughD9994 table conversion andD99B2 MMIO measurement/control. **These are scalar targets, correcting earlier report shorthand calling them table pointers.** | Old `D9CEE–D9D32`: C7 at speed4=4200; C8=3225. The C8 change is an additional state branch, not caused by marker. |
| `DA8CE` | Second target-control path with same marker override to5000; comparison againstD99B2 measurement then control calls. | Old `D9EA0–D9EE8`, no marker clause. |
| `DBB8E` | Marker+speed4+modebits7 selects table index5 instead of3, then MMIO04207580/+8/+10. **But indices3 and5 contain equal bytes in both relevant tables; tested writes are identical.** | Old function `DB0EC`, selection `DB0F6–DB10E`, same table bytes at14F87A versus native150DBE. |
| `DCA40` | For dispatch argument4 and predicate6EABA true, chooses worker149874 instead ofDBB78. Worker149874 branches to **ROM01FBAA34**, outside the2MiB payload. FallbackDBB78->14985C loads local flashDC4F7. | Old dispatcher `DBC78`: argument4 atDBCA4 always callsDB0E0, its local-worker analogue. |
| `E0426` | Boolean marker OR stateC7/C8; redundant marker for U/5 states. Callers52144,527FE,6C966,6C9AA,E051C,E0548. | Old exact standalone counterpart not uniquely bound; not labeled absent merely from this search. |
| `E05D6` | In MMIO04205020/04205000 status path, selects threshold134 instead of128 for halfwordBEA; then may set6CF and log. Native also independently selects194 for speed6. | Old `DF51E–DF548`: threshold128; no marker branch. |
| `E297E` | Maps input4 to output6 through `[R1]` and logs, whereas marker0 fallback maps to2. C7/C8 input6 already maps6 before marker test. | Old exact function not uniquely bound; do not label missing or required yet. |
| `136A98` | Same77h/A8h hardware parameter switch asCACF4; flows through136AEA to135466. | Old analogous switch ends at135360; marker clause absent. |
| `13F258` | Changes target-speed adjustment threshold from2 to6 for C7/C8; writes desired targetB0C at13F2EE. Called13F5DA/13FE1E. | Old exact function entry not uniquely bound in this bounded scan; not labeled absent. |
| `140A06` | With marker+statusBD42==2 skips D2E threshold / timer checks into target-speed comparison at140A36. | Old `13F644–13F64E` proceeds directly to threshold/timer block. |

### Independent counterfactual execution

Owned scripts/results:

- `/tmp/freemkv-g01-xrefs.py` and `/tmp/freemkv-g01-marker-xrefs.txt`: direct references.
- `/tmp/freemkv-g01-marker-detail.py`, `...-marker-detail.txt`, `...-old-detail.py`, `...-old-detail.txt`: literal-resolved native/old blocks.
- `/tmp/freemkv-g01-marker-match.py` and variants: source-byte normalized matching; a candidate match alone was not accepted as semantic identity.
- `/tmp/freemkv-g01-marker-cpu.py`, `...-marker-cpu-results.json`, `...-marker-old-cpu-results.json`, `...-marker-cap-results.json`, `...-marker-actual-mode-predicate.json`: local stock execution, explicit state/speed/mode inputs; no optical acquisition or readiness claim.

For C7/C8, speed4, modebits7, native marker0 and1 and old stock produce the **same five MMIO writes**, including final04207580=0x5140,04207588=0x2407,04207590=0x51400024. Native150DBE and old14F87A table bytes are identical; indices3/5 both55h and40h. Existing mode predicate calls were stubbed to the same0 result in this table comparison. This refutes the claim that this marker read necessarily introduces a new hardware value.

Native filter666D2 produced identical marker0/1 return values for inputs0..8 in C7 state. Native target selectionDA6FA->DA750 produced C7 marker0=4200, marker1=5000; C8 both5000. Old analogous block produced C7=4200,C8=3225. These are actual instruction outcomes, not inferred function names.

Native speed-cap functionA3C6A with max8: policy0 returns8 with marker0 and6 with marker1; policy82h returns4 with marker0 and6 with marker1. OldA3506 returns8/4 respectively. Thus marker affects speed policy in both directions; it cannot be summarized as an unconditional reading-admission prerequisite.

Native dispatchDCA08 argument4, C7, B01=0x0E: marker0 reachesDCA72 fallback; marker1 reachesDCA6A ROM dispatch. This was repeated with the **actual**6EABA predicate executing: it returns whether `(B01>>1)&3 == 3`. No assumed predicate result is needed for this dispatch difference. The pointed ROM worker was not available in the inspected flash, so its numerical/physical behavior remains unresolved.

### Minimal next action

Do not add a U flag now. For the scoped U/5 conversion, source-bound C7/C8 predicates can represent identification in any consumer that is independently shown necessary; native marker's U/density1 role is outside that scope and cannot be reproduced by this substitution. First resolve ROM01FBAA34 and its call chain versus old local worker for argument4, then trace whether the C7 target5000 and hardware-command77h changes are needed for valid raw reads or only native speed/calibration policy. Until then, retain the implemented parser-admission correction and the explicit **native media-side-effect equivalence unproven** qualifier. This evidence does not support declaring the missing marker purely authentication-related, nor does it justify porting all18 consumers.
