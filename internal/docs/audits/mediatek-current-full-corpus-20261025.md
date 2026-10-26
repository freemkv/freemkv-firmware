# Current full MediaTek Modify corpus result

Every one of the 1,085 baseline held hashes was queried with the same executable.
All 196 supported outputs were actually built with a structural audit, matched
their preview output hashes, and preserved the input hash. The flasher admits
193; three held raw-readback-shaped inputs are refused. These are software
checks, not physical drive validation.

| Planner result | Held hashes |
| --- | ---: |
| Supported, including partial feature sets | 196 |
| Unchanged | 1 |
| Unsupported | 887 |
| Artifact parser rejection (known malformed 81,920-byte MK input) | 1 |

The unsupported total comprises the original 884 noncanonical/unrecognized
inputs and three remaining handler-allocation refusals. The malformed artifact
rejection is recorded separately with its actual CLI exit and message; no
capability record was invented for a command that failed before JSON output.

## Published inventory

The exact-image website generator processed all 98 model/revision pairs and
114 final BIN hashes: 113 changed outputs build, audit and pass the flasher gate;
one is unchanged. No published hash was silently omitted.

| Actual controls | Published hashes |
| --- | ---: |
| All five controls, including Unrestricted OEM/On/Off | 84 |
| HRL, Encryption, Region | 24 |
| Speed only | 1 |
| None | 5 |

Five controls map to the seven existing website feature labels. A successful
build is not a claim that every control exists. The raw per-image report retains
missing-hook reasons. Missing native UHD/BD discriminators are not silently
counted as hooks: the supported combined control can instead use the positively
validated auth decision. Classic UHD remains unproven and unavailable.

## Measured selected sub-hook contracts

These counts come from applied sub-hook reports in the held corpus. They count
selected instruction/register contracts, not model categories or unique custom
implementations. Missing reports do not establish an extra variant. Classic
emitters also retain their per-lever addresses and failure reasons in each full
report; this table is the explicitly typed sub-hook portion.

| Hook | Applied contract | Images |
| --- | --- | ---: |
| ake | reject-tail-call | 54 |
| ake | shared-call | 103 |
| auth-cell | R0StateR0 | 23 |
| auth-cell | R0StateR4 | 7 |
| auth-cell | R0StateR5 | 1 |
| auth-cell | R1StateR1 | 66 |
| auth-cell | R1StateR4 | 60 |
| bd-native | Explicit | 54 |
| deny-reset | light-reset | 157 |
| hrl | shared-revoke | 157 |
| uhd-native | explicit-class | 54 |
| vid | Direct | 74 |
| vid | Notebook | 17 |
| vid | TwoRound | 66 |

The five auth contracts reuse one emitter parameterized for r0/r1. The two
recognized native programming-loop forms remain shared. The additional OEM
WH16NS60 1.03 loop does not match either complete form, so its allocation retry
remains unavailable. This is an unproven layout, not proof of exhausted bytes.

The native BD hook now reads the shared Unrestricted slot, so runtime changes
cannot disagree with the auth/UHD hooks when the retired BD slot differs. An
independent CPU test failed for Unrestricted Off / retired slot On / BD class 2
before this correction; 272 auth/BD combinations now pass. Existing partial
boot records still retain their original restricted choices.

Producer binary SHA-256: `4511bde8f567fa25870908303366146dc8b5e2410c6dfed00a86fc6876132ed0`.
Flasher binary SHA-256: `1e0d63bcc4c227863453e03d176d593fa84cc560720cb9adf7688462b6b9beab`.

The adjacent JSON is the authoritative current complete result. Earlier
allocation/five-feature/base-only JSON files are investigation checkpoints.
Remaining work includes the unproven layouts, final publication/QA integration,
and user review; no new support has been released to production.
