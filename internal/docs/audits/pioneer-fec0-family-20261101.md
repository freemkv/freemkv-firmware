# Pioneer FEC0 family matching — 2026-11-01

Pioneer dependency commit: `2769dd0ae03d35c7dbd60391a9bc0266ab9608b1`.
Family scheme: `pioneer.hardware.v5`.

Exclude only FEC0 bit 6 (`0x40`) from the family key. PR1ML and 211M SAT 8801
initialize FEC0 to C7 and 87 in both Kernel and Normal; their other family
evidence matches. A feature/mode bit is a hypothesis, not an established
physical function. FE94, the remaining FEC0 bits, ASIC setup, board markers and
servo coefficients remain compared. No register value in firmware is changed.

`FamilyFingerprint::raw_pins` preserves unmasked FE94/FEC0 writes for analysis.
Existing exact-image settings profiles and unresolved-issue bindings use their
derived v5 identifiers; firmware hashes and parameter guards are unchanged.

The retained 723-package corpus has 531 fingerprinted packages. Comparing the
same decoded inputs yields exactly three pairs of merged v4 families (24 to
21 families), with identical raw register, ASIC, board and servo evidence.
PR1ML and 211M SAT 8801 match; the separate 211M SAT 8800 board/servo evidence
remains distinct. Library tests cover all 256 FEC0 byte values: bit 6 equality,
other-bit inequality, raw preservation and duplicate normalization.

Research backlog: all eight bits of FE8F, FE94, FE9D, FE9F and FEC0. Trace OEM
initialization/reset and runtime reads/writes, indirect access, hardware status,
reserved-bit semantics and behavior correlations before designing bit-flip
experiments. FE8F/FE9D/FE9F were excluded in v4 as host-interface setup evidence;
that did not establish individual feature switches. FE94 remains in the key.

Full notes: [Pioneer register analysis](https://github.com/MattJackson/pioneer-optical/blob/2769dd0ae03d35c7dbd60391a9bc0266ab9608b1/docs/pioneer-register-analysis-20261101.md).
Raw OEM binaries, probe disassembly, corpus reports and hashes are retained in
private research evidence; no bit-flip experiments or physical tests occurred.
