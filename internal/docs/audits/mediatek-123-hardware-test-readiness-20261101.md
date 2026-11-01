# MediaTek 123 hardware-test assessment

Scope: the 123 OEM inputs in `mediatek-oem-only-123-retained-20261031.json`.
The assessment is readiness for hardware testing, not proof of physical UHD reads.
Final dev integration checks and candidate hashes are recorded in the accompanying
machine-readable sign-off after validation.

| Group | Count | UHD modification strategy |
|---|---:|---|
| Newer MT1959 | 82 | Keep native UHD recognition, geometry and calculations; existing acceptance/authentication controls only |
| Older MT1959 | 12 | Source-bound admission, controller, arithmetic and parameter repairs; preserve the already UHD-aware control field |
| Classic MT1939 | 29 | Source-bound recognition/routing repairs plus DI record lifetime and geometry/capacity repairs |

The working BU40N minimal-gate configuration is a user-reported hardware precedent
also recorded in historical source. It is a baseline, not physical qualification
of every image. All 82 newer images preserve seven inspected native role spans.
The classic defects were demonstrated using independent saved disc-information
and capacity pairs; merely copying a third record did not fix their geometry.

All patches must be selected using validated shared instruction signatures and
source relationships. No firmware/model/hash-to-address production lookup table
is permitted. Hashes identify evidence and reject stale prepared plans. Geometry
and DI repairs install together on a private working image before integrity is
recomputed; failure cannot leave a partially installed conversion group.

Software acceptance covers exact API/CLI output equality, integrity, installed
helper behavior, native-role preservation, advertised settings, reset/default
and selected interaction cases, encryption transitions, Speed/Region host command
values, HRL native searches, and corruption/omission negatives. Finite tests do
not cover every generated handler instruction or every possible interaction.

Nine newer and all 29 classic images have bound captured-disc stages. The other
73 newer and12 older images retain an explicit resident-code test boundary.
No unavailable routine is replaced by an invented successful return. Physical
optical acquisition, readiness completion and actual sector transfer remain for
hardware testing. These boundaries alone do not justify additional patches.

Candidates default Unrestricted to On. Speed, Region, Encryption and HRL default
to OEM and must be selected explicitly when testing those modifications. Use
only the choices advertised for the exact output. Region-free is a DVD RPC
response behavior, not a claim of Blu-ray region forcing or playback bypass.

Hardware testers should identify the exact input/output hashes, check ordinary
BD preservation, then read known two-layer and three-layer UHDs. Check capacity,
real reads at the beginning/end and layer transitions, and sector hashes where
an independent reference exists. Exercise individual settings, reset/power-cycle
persistence and relevant combinations, retaining exact disc identities and logs.

## Final local sign-off

All 123 candidates pass production integrity verification and exact API/CLI byte
comparison. Final lint-clean outputs are byte-identical to the fresh full-corpus
outputs: 5,286,124 CPU cases, 2115 passed stages, zero failed stages and 85 explicitly
unqualified resident-dependent stages. Native-role checks add 839,024 cases on 82
exact final outputs. Classic source locators match all 29 reviewed operand sets.

The complete workspace suite passed 1,315 tests with zero failures. Formatting and
all-target/all-feature Clippy checks pass. Eleven CI CPU-check scripts and the
native-response writer/committer checks pass; the captured-disc mutation suite
passes 9 tests. Exact-output feature reruns pass 21,648 Encryption/settings cases,
17,204 HRL sequences with 4,301 actual native searches, and 5,994 Speed/Region host
command cases. Missing native services remain boundaries as described above.

The [machine-readable sign-off](mediatek-123-hardware-test-signoff-20261101.json)
records every input/output hash, group, supported/default settings and bounded
per-image test counts. Private capture/ISO inputs, raw trace archives and candidate
BIN files remain in the local hardware-test handoff, not in this public repository.
The matching host ABI correction is in the companion freemkv-unlock change.
