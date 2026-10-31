# MT1959 UHD media implementation checkpoint

**Current definition: OEM UHD = 100% of G01-G06.** G07/G08 are known internal
authentication differences only. They do not authorize patches, block a media
plan or affect the OEM UHD classification. Existing freemkv AKE/encryption
bypasses are retained. Physical disc testing is tracked separately.

## Active scope and result

All 147 newer-media-layout payloads already contain the six reviewed media
contracts. Thus **147/147 (100%) are OEM UHD under the agreed G01-G06 definition**.
No new media conversion edits are needed for this group. This result does not
claim 147 independent drives were physically tested or establish licensed
playback/authentication behavior. The 24 older-layout MT1959 images and MT1939
are the next implementation groups in the 0.16.0 UHD goal.

The whole corpus has 171 full payloads, 26 incomplete sources and two archive
aliases. Nine manufacturer-backed stock images remain the comparison references;
manufacturer provenance is separate from the current six-contract definition.

## Installer and diagnostics

The source-bound planner treats only G01-G06 as required media gaps. G07/G08
are reported through separate immutable diagnostic accessors. Failure to bind
an authentication diagnostic does not block a valid media plan. No class-3
routing stub is generated, allocated or installed.

For deferred older layouts the existing G01/G02/G03/G04/G06 prototypes remain
blocked by unresolved G05 mode/calibration contracts (one also has an unresolved
early DI caller). None of those incomplete groups is installed. The installer
checks source identity, exact displaced bytes, saved-LR contracts, erased-space
coverage, branch encoding and complete-group verification before committing a
private buffer. The audit rejects partial media groups. Stub validation rejects
wide and narrow Thumb-2-only instructions.

## Validation

All 227 firmware library tests pass after removing authentication patch generation.
The fresh 171-image planner audit has 147 native media plans and 24 blocked
media plans, with zero G07/G08 candidates or requirements. All 119 remaining
media helper candidates passed 100,896 ARM926 cases (OEM/Off and other states
preserved). The bound mode-transition stage passed a further 8,775 cases.
Clippy with warnings denied, formatting and the five planner regression tests pass.
The tests cover diagnostic-only G07/G08, unresolved auth bindings, no-edit native
media plans, rejection of partial media edits and rollback after a late failure.

## Numerical evidence

The forward survey passed 17,082 cases across all 171 full payloads, executing
native division workers. The reverse survey passed 36,270 cases. In the 147
newer layouts, the C7 reverse result is the low 16 bits of
`R7 - 12 * floor(input / 10)` when the bound mode byte is zero, or
`R5 - 9 * floor(input / 10)` when it is nonzero. Distinct R5 and R7 values were
tested. Mode production/calibration remains unresolved for the older 24.

The earlier 455-candidate / 358,944-case CPU receipt is historical and includes
G07 prototypes which have now been removed. Its exact input plan is preserved
as `mt1959-uhd-conversion-plan-before-auth-scope-20261030.json`; do not count
those authentication candidates as current patches.

## Internal authentication evidence

Within the active group, 94 have reviewed G07/G08 differences and 53 do not.
The 53 extended services bind to four distinct protected backend payloads.
None of those exact payloads or their first 256 bytes was found in the 94
other images. This is an exact-byte comparison, not proof that every equivalent
implementation is absent. It is not a detection/read requirement and produces
no firmware edits. The source-bound backend/service receipts retain the evidence.

## Reproduction

```sh
cargo test -p freemkv-fw --lib
cargo clippy -p freemkv-fw --lib --examples -- -D warnings
cargo run -p freemkv-fw --example mt1959_conversion_audit -- SCAN.json /path/to/hoard /tmp/plans.json
python scripts/test-mt1959-conversion-candidates.py --scan SCAN.json --candidates /tmp/plans.json --hoard /path/to/hoard --output /tmp/cpu.json
python scripts/audit-mtk-uhd-calculation-values.py --scan SCAN.json --plans /tmp/plans.json --hoard /path/to/hoard --direction forward --output /tmp/forward.json
python scripts/audit-mtk-uhd-calculation-values.py --scan SCAN.json --plans /tmp/plans.json --hoard /path/to/hoard --direction reverse --output /tmp/reverse.json
```
