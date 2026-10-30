# Normal MediaTek Modify integration and robustness audit

Only normal Modify authors firmware. The former test-only MT1939 assembler has
been removed; fixture and corpus tests call the same API as the CLI and app.

All 108 eligible published hashes build with six reported feature labels: 84
MT1959 and 24 MT1939. Every advertised setting can be changed on the resulting
image through normal Modify, reinspected, verified for integrity and admitted by
the offline flash check. The other six published hashes remain one speed-only
and five base/DE-only images. These counts describe software implementation,
not physical UHD read results.

The full 1,085-input capability sweep retains every prior input status: 181
held images now report all six labels, 11 report speed only, five have base/DE
only, 887 are unsupported and one is malformed. One of the 197 buildable inputs
is already unchanged. No unsupported input was promoted by a model-name rule.

The MT1939 group requires source-bound DI, routing, auxiliary controllers,
completion, position/setup/ranges, parameter and calibration contracts together.
It checks original bytes, allocates within integrity coverage, verifies emitted
branches and bytes, and commits on a working copy. Actual Gate-A and AKE facts
are mandatory. Editable capability facts are emitted only after full installation.
OEM/On preserve native class-C authentication; Off uses the proven class-C
refusal, preserving every other native class. Hardware UHD reading is unproven.

Robustness regressions cover competing VID/AKE/Speed variants, final-window
matches, recovery-register clobbers and bypassed definitions, register writeback,
truncated producers and real AGID operand binding. WH16NS58 1.V9 reads through
r5 at SRAM 0x02000cf4; the old r7 heuristic selected unrelated 0x02000c22.
BU40N 1.00 remains bound to 0x02000d38. The independent CPU suite executes
1,040 authentication/BD combinations, including 768 classic class/setting cases.

The fresh independent reviewer rechecked installation atomicity, prerequisites,
metadata, operand liveness and settings updates after fixes; no blocker remained.
See the adjacent JSON for per-input output hashes and checks. Historical files
with experimental/probe descriptions record earlier research, not current paths.
