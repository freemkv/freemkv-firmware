# Current breakdown of the 884 baseline unsupported inputs

All 884 were queried individually through the current exact-image Modify planner.
Every query returns unsupported before selecting hooks: no MT1959/MT1939 boot
banner is recognized at the canonical `0x3000` position. All input hashes remain
unchanged. Per-input paths, hashes and actual reasons are in the adjacent JSON.

844 inputs are not 2 MiB; 40 are 2 MiB but still lack the supported canonical
banner. Size alone never proves a valid firmware image. The index labels span
older silicon, unknown chips and supported-chip fragments/containers. These
labels do not authorize an engine selection.

An observational ASCII scan finds supported boot-banner text elsewhere in 86
objects, and none in 798. This scan is only a diagnostic locator, not an input
parser or format selector. Existing typed hoard metadata identifies 24 MT1959
fragments, 60 MT1939 objects with noncanonical framing, and two MT1959 objects
with extra framing. The remaining 798 still need detailed format classification;
absence of a string does not prove encryption or an unsupported processor.

The two extra-framed objects have a complete candidate image beginning at 0x600:

| Original hash | Embedded candidate hash | Result |
| --- | --- | --- |
| `7d5aa8bc43f3...` BE16NU50 1.01 | `d286c5a7ea4a...` | Exact existing held dump |
| `f79ccf0bc90e...` BW-16D1HT 3.01 | `40118f8171da...` | Exact existing held dump |

The candidate hashes match existing complete held objects byte for byte. Their
Modify builds work, but the flasher refuses their raw-readback boot shape, as
recorded by the 97-image audit. This is not authorization to strip arbitrary
headers or to override that gate. Original-container provenance remains separate
from canonical image suitability.

Supporting fragments requires the missing components and a positively parsed
assembly contract. Supporting framed inputs requires an actual format parser,
then normal exact-image integrity/receiver checks. Older silicon needs its own
proven implementation. None should be fixed by selecting from a folder/model
label or guessing padding. These are explicit unresolved input-format cases,
not 884 demonstrated failures of the new hook matcher.

Index SHA-256 for the metadata observations: `b4a64b87366aa3e3f41d7fcca3baa789f214740efae4d719240a2f9184d8dfde`.
