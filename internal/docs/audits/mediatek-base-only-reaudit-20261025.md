# Current re-audit of the 32 baseline base-only inputs

The current planner reports 31 supported builds and one unchanged result. All 31
actual output builds pass the structural audit, match preview hashes, preserve
source hashes and pass the flasher admission gate. Exact per-image evidence and
unavailable reasons are in the adjacent JSON. This is not hardware validation.

| Actual configurable controls | Inputs | Current result |
| --- | ---: | --- |
| HRL, Encryption, Region | 24 | Classic hooks were already emitted; now reported |
| Speed only | 3 | Region/RawRead allocation failures remain |
| None | 4 | DE applied; classic Identity base unavailable |
| None | 1 | Unchanged; DE already present, classic Identity base unavailable |

The three Speed-only objects are WH16NS60 1.03 OEM `f1cd257b8c4b...`, its MK
comparison `3d9011427337...`, and BH16NS60 1.02 MK `dc6579b6880c...`. Their partial
allocation failures were outside the original 18 hard-allocation-refusal set.
Region requests 107 bytes; RawRead requests 60. The OEM case still needs the
same evidence-driven allocation investigation; it is not counted as resolved.

The five without controls are BE14NU40 1.01 `2f02308413c8...`, BW-16D1HT 1.01
`3f436c31124f...` (unchanged), WH16NS48 1.D3 `46b41f15e053...`, and UH12NS30
1.01/1.02 `84fecc2930d6...` / `d98c2e11f400...`. The full reasons distinguish
missing classic Identity plumbing, missing VID/AKE anchors, and the unsupported
classic speed-control shape. These require further work; an Applied DE change
does not imply complete modification support.

The 24 improved reports still lack classic Speed and Unrestricted controls.
Classic UHD and the new three-way modern auth hook must not be conflated.
