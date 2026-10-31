# Adversarial G05 necessity and boundaries — 2026-10-30

Scope: audit of necessity, not authorization to transplant newer firmware. Reviewed engine `mt1959_uhd.rs`, calculation/mode audit scripts and receipts, and native BU40N 1.02 bytes SHA-256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`. No firmware edits, flashes, or hardware results.

## Finding

Media admission alone does not establish UHD reading: the reference explicitly distinguishes C7 in downstream numerical code. Conversely, reference parity alone does not establish that every associated mode transition is necessary to read UHD. G05 currently bundles a demonstrated C7 numerical distinction with a shared mode-acquisition subsystem whose necessity and full command reachability remain unproven. Treat these as separate proof obligations.

| Part | Evidence | Defensible boundary |
| --- | --- | --- |
| C7 reverse selection and arithmetic | Native `D885C–D8876` selects C7 and reads a mode byte. Zero gives `low16(R7 - 12 * floor(input/10))`; nonzero gives `low16(R5 - 9 * floor(input/10))`. Existing numerical execution audit tests these with native division. | A simple extension to a C8 selector cannot claim all native C7 behavior. Bounded arithmetic implementation is justified for reference parity, but physical reading necessity is still not established by isolated execution. |
| Mode-sensitive existing BD behavior | `D883C–D8848` explicitly routes states C8..CB through the nine-times branch when mode equals 1. C7 uses any nonzero mode instead. | Mode logic is shared, not UHD-exclusive. Preserve all non-C7 paths. Do not globally replace C8 behavior, and do not equate C7's nonzero test with C8's equals-one test. |
| Stage transition selection | `6D86E–6D89A` admits C7 or `(state >> 2)==0x32`, compares requested coordinate with `0x1B640`, enters below threshold with phase 0 and leaves at/above threshold with phase 1. Frame phase aliases the reverse mode byte. | This is concrete producer/consumer linkage in a shared operation stage. It is not proof that a normal admitted UHD read reaches that stage or requires transition. Coordinate physical units are unknown. |
| Mode entry and exit | Entry `7AED4` is a multi-stage state machine. It calls driver veneer `148E04` at `7AF24`, retries status B0 up to five times, invokes other routines, writes mode at `7AF5E`, adjusts parameters 10/11, and performs further operations. | Not a flag-setting helper. Copying only a store, arithmetic helper, or coefficient transform is not proven equivalent. Whole orchestration port is not presently justified by necessity evidence. |
| Coefficient and restoration audits | Native helper executions and passive-register roundtrips establish local software equivalence; restoration blocks establish their local effects. Scripts explicitly disclaim physical behavior and acquisition. | Useful prerequisites if orchestration is eventually required, not evidence that it is required or safe as a complete controller sequence. |

## Reachability countercheck

An independent raw-file direct-edge survey is reproducible with `/tmp/freemkv-g05-callers.py`; results are `/tmp/freemkv-g05-callers.json`. It scans aligned Thumb B/BL/BLX candidates and ARM branch candidates and searches exact entry-address pointer words. The only discovered direct source-offset caller of operation entry `6D6DC` is `64768`, preceded by `MOVS R0,#1` at `64766`. At `6D808–6D818`, operation argument 1 branches to `6D8F8`; the audited mode stage is on the argument-0 branch through `6D836`. Thus **the observed direct caller does not prove mode-stage reachability**. Only direct mode-enter/leave callers found were `6D88C` and `6D896`.

This is not an absence proof: executable RAM aliases, relocation, computed dispatch, indirect callers, alternate entries and unscanned code can invalidate a raw source-offset caller inventory. The driver at `148E04` is an ARM `LDR PC,[PC,#-4]` veneer containing `0x01F83785`, so mapping that executable address is an explicit next step. Do not assume the driver implementation is missing simply because the pointer is outside raw file offsets. Likewise do not confuse the entry argument in R7 with its later media-state-pointer value.

## Strongest falsification and next action

The most useful next experiment is not another coefficient cross-product. Establish the executable-address mapping and trace a real read-command path, preserving actual state-cell provenance, into the operation with argument 0 and onward into reverse calculation. Record whether an admitted C7 medium can reach either reverse branch and whether the phase can become nonzero under existing older firmware behavior. This can falsify the claim that a reverse selector alone suffices, or support a smaller default-mode implementation if the alternate state is provably unreachable for the intended operation. Whole-pipeline emulation still needs an honest boundary around hardware results; supplied success values cannot establish acquisition.

A narrowly staged implementation can prepare a C7-only arithmetic detour and its invariants independently, but must not install it as a completed G05 while mode lifecycle remains unresolved. Keep existing non-C7 and feature-off behavior exact. Do not transplant modern threshold, calibration constants, retry policy, restoration sequences or mode state machine merely because helper equivalence tests pass. If full UHD behavior ultimately needs mode transitions, bind the complete lifecycle and its hardware dependencies first, then implement only that demonstrated dependency chain.

The existing all-or-nothing installation policy may legitimately remain blocked as a conservative product policy. Its block is not evidence that the bundled subsystem has been proven physically necessary. The accurate answer to “should BD reading suffice after admission?” is: admission is insufficient evidence; downstream C7 differences are real, while the minimum changes needed for successful reading remain unproven.

## Follow-up: complete operation-entry execution and upstream boundary

`/tmp/freemkv-g05-entry.py` and `/tmp/freemkv-g05-entry.json` execute the **actual operation entry**, not the isolated stage, on ARM926. They initialize source-bound state `0x01FF9E04=C7`, frame `0x02000B00` status to B0, and frame+0x11 bit 1 to 1; other RAM is zero except requested coordinate and phase. These conditions take native branches that bypass earlier helper calls. The harness stops at the **first call instruction**: it never fabricates a callee return or acquisition result.

Eight executions passed:

| Entry argument | Coordinate | Phase | First call reached |
| --- | --- | --- | --- |
| 0 | 0 or 0x1B63F | 0 | `6D88C -> 7AED4` (enter) |
| 0 | 0x1B640 | 1 | `6D896 -> 7AFE0` (leave) |
| 0 | 0x1B640 | 0 | `6D89C -> 148E04` (driver) |
| 1 | same four combinations | same | `6D990 -> 148DFC` (different driver) |

In every argument-0 case, actual R7 at the first call is `0x01FF9E04`, produced by the native R6/R1/R7 chain. This establishes a feasible complete entry-to-mode-stage path and state provenance without calls being intercepted as successes. It does **not** prove that normal admission produces those prerequisite RAM values or that an upstream caller supplies argument 0.

The direct-edge survey was expanded to the whole function interval `6D6DC..6DAB8`, considering external Thumb conditional/unconditional branches and calls and ARM branch encodings. No new plausible Thumb entry was found. Two ARM-pattern hits (`5B920 -> 6D9F8`, `6D258 -> 6DA60`) occur inside coherent Thumb instruction streams (`LDR R0,[PC,#D0]; LDR R3,[SP]` and `LSLS R0,#8; LSRS R0,#8`), so they are not established ARM callers. Raw unaligned-looking pointer candidates likewise do not establish executable dispatch.

The argument-1 C7 route itself is bounded: `6D986..6D994` selects a resident driver through veneer `148DFC`, then branches to the common status store/return `6D948`. It does not locally loop back into the argument-0 mode stage. The driver veneer targets are `148DFC -> 0x01F84483` and `148E04 -> 0x01F83785` (Thumb bit included). Neither target body is in the 2 MiB source image. Repository layout documentation says flash load address equals file offset, and the existing resident-acquisition audit warns that subtracting an invented base is invalid; no evidence located here establishes an alias for these two targets. Earlier scatter-table conclusions concern other resident targets and must not be silently promoted to a fresh proof for these exact addresses.

Concrete remaining boundary: an upstream argument-0 invocation is unbound, and the known argument-1 route enters resident code at `0x01F84482`. That resident code could potentially invoke operation 0 or modify shared state, but its bytes/mapping are unavailable in the inspected artifact. Therefore source-file direct-call absence cannot justify deleting mode logic, nor does the internally feasible argument-0 path justify claiming it is reached by normal UHD reading. Obtaining the relevant resident mapping/body or an actual command trace is the smallest missing evidence for this reachability question. Compatibility of newly admitted fields with older downstream consumers must be demonstrated separately; these eight executions claim no such compatibility.

## Correction: older mode field exists at B19, not B1A

Independent follow-up confirms the parent's field-layout correction: the older mode field is `0x02000B19`, while the native field is `0x02000B1A`. Absence of older B1A references was not valid evidence for absence of an older mode lifecycle. Native B19 has a newly inserted marker role. This materially reduces the presumptive port scope: reuse the source-bound older semantic field if its lifecycle is established; never allocate a new flag merely from the earlier address survey.

A pointer-flow survey, `/tmp/freemkv-g05-oldflag.py`, tracks PC-literal seeds in the neighboring RAM region through local branches, register moves and additions/subtractions, and treats calls as clobbering R0–R3. It finds older B19 reads at `291B0`, `7884E`, `78948`, `78EBA`, `78FAA`, plus **frame-relative `6AF1C`**, and a reset store at `81B16`. This bounded survey is not a whole-program writer absence proof; indirect argument-derived stores and resident routines remain unresolved.

The frame-relative consumer independently establishes semantic alignment, not just adjacency:

- Older `6AF10..6AF76` and native `6B17C..6B1E8` copy frame+0x40 to frame+0x3C and conditionally transform the coordinate according to frame+3.
- Older `6AF1C` reads `[R4,#0x19]`; native `6B18E` reads `[R4,#0x1A]`, with the same zero-mode guard and corresponding coordinate transformation bodies.
- Native additionally accepts explicit C7 at `6B188..6B18C`; older `6AF14..6AF1A` has only the C8-mask condition. This is a concrete downstream C7 difference, not a reason to transplant the entire routine. The transformed coordinate's required semantics for C7 still need validation.
- Older coefficient selectors already explicitly accept C7 and branch on this same field: `78846..78852` checks mode zero; `78940..7894C` checks mode one. The table consumer at `78EBA` also reads this field. Thus older code already supports both values in relevant shared consumers.

Both coordinate-processing routines subsequently invoke their resident driver directly (native `6B1F6 -> 148E04`; older corresponding path uses `1479F4`). Older driver veneer literal is `0x01F83719`; native is `0x01F83785`. This provides another operation path to the driver that does not pass through the audited mode-transition insertion. It reinforces that which path executes is load-bearing; proving an argument-0 call to one wrapper alone would not prove all reads require that wrapper's mode orchestration.

Revised implementation boundary: source-bind older B19 and its existing consumers first. Determine its nonzero producer/lifecycle, including the resident driver boundary. A C7 reverse arithmetic patch can potentially consume the existing field; new mode storage and wholesale lifecycle replacement are unjustified until that inquiry is resolved. Keep the newly identified C7 coordinate-selector difference separate from mode production, and validate its exact downstream behavior rather than inferring necessity from reference similarity.

## Earliest c88a6901: no justified mode binding yet

Examined BP50NB40 1.00 SHA-256 `c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306` separately. Do not extend the 23-image B19 binding by address:

- Existing source-bound operation frame is still B00, but its requested/returned coordinate fields are +0x34/+0x38, rather than +0x3C/+0x40. Structure-layout assumptions already differ.
- The bounded pointer-flow survey `/tmp/freemkv-g05-earliestflag.py` finds earliest B19 bitfield reads/writes at `6F4F2..6F574` and `CB820..CBA98`, plus reset `81D30`. For example, `6F4D6` loads B00, `6F4DA` adds 0x19, and `6F4F2..6F4F6` tests bit 2 of the byte. This is not evidence for a zero/one calibration-mode field.
- A structurally related coefficient-selection family is at `7A7FC..7AD86` with different register allocation. At `7A84A` it binds media state `0x01FF9DEF`; `7A850` binds B01, `7A852` binds speed field B0B, and `7A858` binds profile byte `0x01FF9E0E`. Its BD selection path uses B01 bits 1..2 and a bits 1..4 comparison, not a C8/C7-specific binary mode test. The branch paths load halfword/byte coefficients and six-byte records using the selected profile.
- `/tmp/freemkv-g05-earliest-calibration.py` and JSON execute 36 ARM926 cases from `7A84A` to the first actual native logging call: states C7/C8/CC × proposed B19 values 0/1/255 × B01 packed configurations 0..3. No callee result is manufactured. B19 does not change selection in this bounded BD path. Configurations 0 or 2 reach `7A926`, configuration 1 reaches `7A972`, and configuration 3 reaches `7A952`; these are distinct native coefficient-profile continuations.

This does not establish a whole-program absence of a mode flag, nor prove that the selected coefficient family is the only relevant one. It does falsify treating earliest B19 as the 23-image semantic mode on address/layout similarity alone. B01's multivalued configuration must not be relabeled as that mode without a causal producer/consumer mapping. No positive C8-only mode-zero/mode-one grammar was established in this pass, so the earliest image should continue to refuse the 23-image recognizer rather than receive a guessed field or new RAM allocation. The remaining search is a separate compiler/layout contract, with positive semantic evidence required before emitting its reverse-mode detour.
