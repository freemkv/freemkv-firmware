# Adversarial audit: G02 control bit31

Verdict: **plausible C7-specific reference behavior, not proven necessary for UHD reading**. G02 cannot be described as a universally required UHD change: the observed U/5 three-layer route produces C8, for which the old selector already sets the same bit. This does not establish that G02 is unnecessary for two-layer UHD, or that the old drive can read three-layer UHD.

## Sources and exact binding

Read-only source trees: freemkv-firmware f5b7f12 and mediatek-optical 66c4b1c. Source firmware in hoard:

- Native OEM BU40N 1.02 SHA-256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`.
- Older OEM BU40N BN11 SHA-256 `5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95`.

Offsets below are image offsets, also used as execution addresses in the harness. Both source selectors read byte `0x01ff9e04`. Both write word `0x0420903c`; this is derived from actual literal `0x04209040`, subtract `0x40`, then offset `0x3c`. Its hardware meaning is unknown. Calling it laser power, density control, or a particular decoder mode would exceed this evidence.

Native selector `0x28f5c..0x28f84`, store at `0x28f82`: sets bit31 iff `(state & 0xc8) == 0xc8 || state == 0xc7`; otherwise clears bit31. Old selector `0x28f4c..0x28f6a`, store at `0x28f68`: sets bit31 iff `(state & 0xc8) == 0xc8`; otherwise clears it. All other word bits survive either route. Across all byte states the only difference is C7. The preexisting mask is broader than literal C8 and selects 32 possible byte values; do not treat all those values as real supported media states.

## DI, caller, and execution evidence

Native DI function entry `0xe0970`; direct BL references at `0x69b74` and `0x69ef0`. Native `0xe0bd2` binds r7 to the same state cell `0x01ff9e04`. At `0xe0c6e`, the parser takes DI byte8=0x55 ('U'), byte11=5, byte10 high nibble2 to `mov r0,#0xc7` at `0xe0c98`, then state store `0xe0cb2`. High nibble3 takes C8 at `0xe0c90`. Subsequent two-layer adjustment explicitly preserves C7 (`0xe0d1e..0xe0d20`); three-layer adjustment preserves the C8 layer encoding.

The native writer's containing function starts `0x28d92` and returns `0x28fb0`. A direct call at `0xdf020` targets it. A caller-level Unicorn ARM926 experiment entered the actual BL at `0xdf020`, executed the containing function, observed the exact word store at `0x28f82`, and returned to `0xdf024`. C4 produced `0x12345678`; C7 and C8 produced `0x92345678`. Five external subroutine calls were stubbed: `0x28df8 -> 0x5ba84`, `0x28e16/0x28e32 -> 0x5bb66`, `0x28e38 -> 0x5ba5a`, `0x28e46 -> 0x5ba34`. Other memory began zero; those stubs return r0=0. This proves local caller reachability under the stated simulated conditions, not real acquisition or MMIO behavior.

A separate experiment executed actual native DI instructions through the state store for U/5 layer counts2 and3, retained the resulting memory, then explicitly jumped to the selector. It observed C7/C8 respectively, both setting bit31. **The jump is imposed by the harness, not a demonstrated firmware call chain.** No continuous real acquisition/DI-to-`0xdf020` execution was established. Therefore this audit does not close the critical scheduling/reachability gap.

Exhaustive selector execution used Unicorn2.1.4 ARM926, all256 state bytes and initial words `0x12345678`/`0x92345678` on each of the two source images:1024 executions, all matched the predicates above. This is exact selector semantics, not evidence that the bit is required for sector reading.

Reproduction artifacts: `/tmp/freemkv-g02-execute.py`, `/tmp/freemkv-g02-execution.json`, `/tmp/freemkv-g02-caller-run.py`, `/tmp/freemkv-g02-caller-execution.json`; disassembly and caller inspection scripts under the same owned prefix.

## Counterexamples and confounders

1. U/5 three-layer C8 is a concrete counterexample to the assertion that adding C7 to this selector changes every UHD route. The old and native G02 paths are identical for that state. Other gaps may still prevent acquisition/readout.
2. This is an extension of a shared preexisting state mask, not a UHD-only register writer. Ordinary and other high-layer states already use the writer. The C7 branch itself is specific to the new state in this pair; its hardware necessity cannot be inferred from the writer's existence.
3. Independently filtering the existing corpus by explicit DI recognition, rather than its circular 'OEM UHD' label, yields149 entries, all with explicit C7 control-bit recognition and no recognized legacy control-bit counterexample. The corpus contains patched/duplicate sources, and the recognition grammars themselves constrain what is recognized. This correlation supports deliberate reference behavior, not necessity. It is not an independent sector-read outcome dataset.
4. The old BN11 lacks U DI admission. Injecting C7 into it measures a hypothetical state introduced by other patches; it cannot establish a real original failing-UHD path.
5. No downstream software test of this exact bit, register specification, hardware side effect, or successful/failed sector read with the bit selectively toggled was established. The bit could matter only in a particular stage, or another stage might rewrite it. Neither possibility is excluded.

## Recommendation

Label G02 **C7 control-bit reference divergence; UHD necessity unproven**, not a proven missing UHD requirement. Retain a conservative reference-parity requirement if the engineering policy demands matching the known source behavior, but explicitly distinguish that policy from demonstrated necessity. Do not remove G02 solely because the necessity claim is unproven. Keep the atomic G05 block; these experiments justify no partial installation.

To advance beyond plausible: establish an actual acquisition trace carrying U/5 two-layer DI into `0xdf020`, track every write to `0x0420903c` through the subsequent read stage, and obtain either the register semantics or a controlled read outcome with only this C7 behavior changed. Include U/5 three-layer C8 and ordinary C4/C8-class media as controls. Without that, a six-of-six reference-role score must not be presented as physical UHD completeness.

## Follow-up: downstream acceptance, other writers, and actual candidate

The value is a word written to the peripheral-address region `0x0420903c`. It is not a computed sector address passed to a software worker. The first direct acceptance boundary is the store itself. The code proves delivery of the changed bit to that address; it does **not** prove that physical hardware accepts it, latches it, or behaves differently in a way required for UHD. Unicorn maps this region as RAM and cannot answer those hardware questions.

A bounded Thumb literal/constant-address CFG search enumerated 246 native and245 old literal seeds in `0x04208f00..0x04209200`. It propagates constant register aliases, additions/subtractions, follows immediate branches, and stops at calls/returns or1000 instructions. It found19 native and18 old exact-word accesses. These include the G02 RMW and the following eight other RMWs in six regions:

| Native read → write | Old read → write | Word transformation | Bit31 |
|---|---|---|---|
| `0x2a2c6 → 0x2a2cc` | `0x2a2b4 → 0x2a2ba` | clear `0x2000` | preserved |
| `0x83582 → 0x8358c` | `0x82eda → 0x82ee4` | clear `0x77000000` | preserved |
| `0xde52e → 0xde536` | `0xdd598 → 0xdd5a0` | clear `0x30000` | preserved |
| `0xde540 → 0xde546` | `0xdd5aa → 0xdd5b0` | set `0x10` | preserved |
| `0xdec96 → 0xdeca8` | `0xddb8c → 0xddb9e` | `(word & 0x88ccffef) + 0x30000`, then OR `0x33000000` | preserved; addition cannot carry into bit31 because its destination bits were cleared |
| `0xf0422 → 0xf042a` | `0xeed72 → 0xeed7a` | clear `0x2000` | preserved |
| `0xf045c → 0xf0462` | `0xeedac → 0xeedb2` | set `0x10` | preserved |
| `0xf723c → 0xf7246` | `0xf5b8c → 0xf5b96` | clear `0x10`, set `0x30000` | preserved |

Native and old actual instruction snippets for these16 RMWs were executed with words `0x12345678`, `0x92345678`, `0x7fffffff`, and `0xffffffff`:64 runs, all preserved bit31. Thus, for the found accesses under ordinary read/write-register semantics, these updates do not erase the G02 difference. These are independently entered snippets, not an asserted chronological hardware-stage trace. Within the G02 containing function, the write is retained through its return; no subsequent exact-word store occurs before that return.

No found readback branches or calculations use bit31 to select software behavior. The found reads simply preserve bit31 while editing other fields. G02 itself can clear it on a later invocation when the state no longer satisfies its predicate. No evidence determines when such a subsequent invocation occurs relative to media readout.

This search resolves software addressing aliases such as literal `0x04209040 - 0x40 + 0x3c` and `0x04209000 + 0x3c`. It does **not** establish completeness: ARM-mode code, register values crossing calls, dynamically constructed addresses, byte/halfword accesses to `0x0420903f`, DMA, reset behavior, and hardware mirror aliases are outside its proof. No hardware register map was available to resolve physical aliases. In particular, absence of a found bit31-clearing RMW elsewhere is not proof that the bit stays latched. Source artifacts: `/tmp/freemkv-g02-mmio.py`, `...-mmio.json`, `...-mmio-context.py`, `...-old-context.txt`, `...-rmw.py`, `...-rmw-results.json`.

The shared-media interpretation is stronger than code similarity alone: the old DI path admits identifier O with density byte0/1/2, initially writes C0, then its three-layer adjustment creates C8; W/5 initially produces F8 and the three-layer adjustment retains F8. Both C8 and F8 already satisfy the old G02 mask. These are code-produced non-U states, not a claim that every syntactically admitted combination represents supported physical media. C7 is the sole new byte-state behavior.

### Actual proposed helper, containing-function comparison

The actual72-byte G02 candidate from `mt1959-uhd-conversion-plan-receipts-20261030.json` for BN11 was installed **only in emulated memory**, with its detour at `0x28f58`, replacing original bytes `00 29 c1 6b 02 d1`. It ran from the original containing function entry `0x28d82` through its real return. Both original and candidate used the same external-call stubs and peripheral RAM model. All256 states × feature values0/1/255 × two initial word patterns =1536 paired containing-function comparisons passed:

- r0–r12, SP, and NZCV matched at return.
- Every non-stack memory write matched, except the intended bit31 set in the exact word for stateC7 and feature1.
- Other31 word bits survived; feature0/255 and all other states matched original behavior.
- Stack scratch writes are allowed and excluded from the memory comparison. LR is a caller-clobbered register and excluded; the actual saved return address restored control to the same sentinel return PC. This does not claim every scratch stack byte is restored.

Reproducer `/tmp/freemkv-g02-candidate.py`, results `/tmp/freemkv-g02-candidate-results.json`. The simulator did not emit a firmware image. This closes the local helper/caller-preservation question for this source and test domain, but cannot show the downstream hardware function of bit31. **Final acceptance status remains unknown at the hardware boundary; UHD necessity remains unproven.**
