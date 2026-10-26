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
