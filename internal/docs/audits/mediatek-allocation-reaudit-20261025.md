# MediaTek allocation re-audit — 2026-10-25

The original 18 allocation refusals were re-queried against the current modifier. Four still fail the initial handler allocation. Fourteen produce partial outputs with Speed. The handler now shares its identical default-restoration body, saving 28 bytes; before that change eight had no configurable features and six had Speed only. These fourteen are **not fully resolved allocation cases**; Region and RawRead still report allocation failures.

The machine-readable adjacent JSON records every source hash, eligible original-image hole, active integrity coverage and current modifier result. Hole measurements independently intersect erased bytes with active CMAC coverage and exclude current reserved regions; they do not certify code reachability or unused data.

| Model | Revision | Hash | Current result | Largest candidate | Total candidate bytes |
|---|---|---|---|---:|---:|
| BD-RE BP55EB40 | 1.03 | `0f7b3d34cbf5` | partial: speed | 864 | 943 |
| BD-RE BP60NB10 | 1.02 | `1227f133eb1c` | partial: speed | 864 | 916 |
| BDDVDRW UH12NS40 | 1.03 | `243a7b0bb237` | handler allocation refused | 42 | 87 |
| BD-RE WP50NB40 | 1.03 | `263994abefb0` | partial: speed | 864 | 963 |
| BD-RE  WH14NS40 | 1.05 | `38a70ac234a1` | partial: speed | 908 | 987 |
| BD-RE BP50NB40 | 1.03 | `3cdbdacace5c` | partial: speed | 864 | 939 |
| BD-RE WP50NB40 | 1.03 | `592e8d22d98a` | partial: speed | 864 | 963 |
| BD-RE  WH14NS40 | 1.05 | `60a66592d501` | partial: speed | 908 | 987 |
| BW-16D1HT | 3.10 | `66f277bcad34` | handler allocation refused | 0 | 0 |
| BD-RE BU40N | A103 | `7d7f2465feaf` | partial: speed | 864 | 943 |
| BD-RE  BE16NU50 | 1.04 | `7dcc99d27600` | partial: speed | 908 | 987 |
| BDDVDRW CH12NS40 | 1.03 | `b3892226d89d` | handler allocation refused | 42 | 87 |
| BD-RE BP60NB10 | 1.02 | `cd10fc7396a2` | partial: speed | 864 | 916 |
| BD-RE  BE16NU50 | 1.04 | `d59b5da7424e` | partial: speed | 908 | 987 |
| BD-RE BP50NB40 | 1.03 | `e04aaf44157f` | partial: speed | 864 | 939 |
| BDDVDRW UH12NS40 | 1.03 | `eeb1c948f1ed` | handler allocation refused | 42 | 87 |
| BD-RE  WH16NS40 | 1.05 | `f37fc1b8f61c` | partial: speed | 908 | 987 |
| BD-RE  WH16NS40 | 1.05 | `ffde0e55aed6` | partial: speed | 908 | 987 |

The remaining initial refusals comprise two MK objects and their OEM UH12NS40 counterpart (87 bytes total in eligible erased fragments, largest 42 bytes), plus an Omni image with no eligible erased bytes under its deliberately restricted active integrity ranges. The initial handler currently requests 758 contiguous bytes. Splitting alone cannot fit 758 bytes into 87; investigate other proven storage opportunities or reduced-purpose handlers without changing integrity descriptors blindly.

Next: account for all non-erased padding, alternate authenticated ranges, and handler size/placement constraints before concluding impossibility. No source image was changed.


Implemented allocation corrections:

- Finalized byte arrays request their exact size. Their literal pools and branch encodings are already emitted, so another 16 bytes cannot be justified as assembly expansion space. Subsequent allocations still enforce their own capacity and alignment.
- Shared reset-defaults code saves 28 bytes while retaining all CDB commands. New v3 settings records describe two unique instruction runs; v1/v2 readers and updates remain supported. The erased-NV fallback branch into the shared body is positively checked when attaching the record.
- Four exact-capacity/short-capacity Rust tests cover the handler and feature groups, plus a separate boot-stub boundary test. Independent ARM execution covers eight reset/default/saved-state combinations, including updating a generated image's defaults.

This remains an open allocation audit: all fourteen partial outputs still lack Region and RawRead groups. Splitting routines, reducing repeated code further, and investigating other provably unused storage remain candidates; passing the base build does not close those missing groups.

## Native integrity-routing evidence

`scripts/test-mtk-integrity-routing.py` replays hashed excerpts from the OEM
UH12NS40 source `eeb1c948...`. It executes the original application range walker
at `0x17c298` and boot-check wrapper at `0x17c27a`. Cryptography, setup and logging
helpers are stubbed; the test proves argument routing and return behavior only.

Seven cases cover the four stock mask-one ranges, changing the second inclusive
endpoint from `0x1806f` to `0x183ff`, skipping an out-of-bounds endpoint, stopping
on a failed cryptographic result, an empty mask, and boot success/failure. The
boot wrapper passes `0x1000..0xffef` with stored digest at `0xfff0`. This corrects
the earlier unverified concern that its range might include the application
integrity table.

The expanded endpoint reaches the helper, but the malformed endpoint also gets
skipped while the walker returns success. Therefore, a native success result
does not establish complete validity. This is not authorization to modify
integrity metadata: the receiver's programmed ranges remain unproven for this
input, and unchanged boot/runtime behavior still needs independent evidence.
No production allocation policy or input image is changed by this experiment.

### Programming-loop evidence

Following the same OEM application's selected range cells reaches the mode-three
programming wrapper at `0x17c44e`, which stores source offset, destination and
remaining length, then calls `0x17000`. The original loop uses 64 KiB and 4 KiB
program calls and skips `0x1d0000..0x1ec000` and `0x1f0000..0x200000`.

`scripts/test-mtk-program-routing.py` executes that original loop with ready
hardware status, stubbing the page helper and setup/logging completion. Starting
at zero yields 33 page-helper calls; starting at `0x10000` yields 32. Every
source offset, destination and length is asserted, including the preserved
skips and final zero remaining length. The proposed `0x18074..0x18400` gap is
inside a programmed span in this replay.

Four further cases execute the native page helper through its staging-to-buffer
copy for offsets `0x18000`, `0x18100`, `0x18200`, `0x18300`. All 256 bytes of each
nonconstant test page reach the hardware buffer unchanged. These stop before
the actual hardware program/verify sequence; they do not establish physical
acceptance or write completion.

The loop is the existing library's compact programming form with relocated RAM
literal operands: 11 bytes differ across eight literal words in its 2016-byte
signature. This suggests a shared operand-bound contract, not another
model-selected implementation. Literal roles are now checked by the shared
analysis below. Binding it to this application's selection and wrapper, and
exposing the resulting ranges through the receiver API remain work to do
before any allocation policy change.

### Shared-loop recognition across the held hash set

The library now exposes read-only `programming::inspect_program_loop` evidence
for the two existing complete instruction forms. Five aligned, distinct RAM
pointer cells and three distinct status addresses may relocate within their
validated memory regions. Instructions, branches, hardware literals, skip
constants and the raw page-copy body remain exact matches. Mutating every
non-relocatable halfword, truncating either form, aliasing cells or substituting
the wrong memory region is rejected by library tests.

All 18 original allocation cases contain one matched loop: **10 compact and
8 wide**. The native wide-loop replay additionally verifies its `0x1c8000`
first skip boundary and 4 KiB writes approaching that boundary. Its full-image
and boot-preserving routes make 40 and 39 page-helper calls respectively,
compared with 33 and 32 for the compact form. Both forms' raw staging copy is
executed on four nonconstant pages. Hardware completion remains simulated.

Scanning every aligned address of all **1085 held input hashes** finds one
complete candidate in **116**: **72 compact and 44 wide**. The other **969**
do not match either complete form; that is a loop-evidence result, not a new
Modify unsupported classification. Sources and the producer binary are hashed
before and after querying. Exact per-input results are saved in
`mediatek-hoard-program-loops-20261025.json`; the 18-case subset is in
`mediatek-allocation-program-loops-20261025.json`.

Reproduce with `scripts/audit-mtk-program-loops.py --hoard HOARD --example
target/release/examples/mtk_receiver_evidence --inputs INPUTS.json --output
OUTPUT.json`. Inputs have an `images` array of unique `sha256`/`path` records.
Candidate discovery scans the image and does not assume a fixed boot offset.

This API deliberately returns **loop evidence**, not executable receiver
authorization. Application selection, wrapper argument binding and integrity
semantics must still be connected before exposing programmed ranges in a
transfer plan or extending allocation coverage. These results do not resolve
the 18 allocation cases by themselves.
