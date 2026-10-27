# Native MediaTek speed policy — 2026-10-26

Speed-only audit. Preserve each image's native hardware policy; no firmware speed
constant, public UHD capability, recovery path or website data changed.

## Coverage and result

The source-hash manifest in `mtk-speed-policy-20261026.json` covers all 24 classic
MT1939 conversion candidates and 171 held canonical MT1959 images. This is broader
than the requested 88 MT1959 comparisons. The current finder catalog contains 85
unique final MT1959 hashes and six distinct intermediate hashes; all 91 are covered,
with zero missing. Catalog, inventory, script and builder hashes are recorded.

| Native C7 default | MT1939 | MT1959, all held | MT1959, catalog finals |
|---|---:|---:|---:|
| 6 | 0 | 141 | 74 |
| 8 | 24 | 30 | 11 |

Both policies occur in native MT1959 code. A blanket replacement of classic 8 with
6 would discard legitimate image-specific policy. All 24 classic images retain
their native hardware-conditioned lower limit of 4. Modern lower-limit paths vary
between 4 and 6. C7 and C8 are tested separately: classic code selects 8 for
C7 and 12 for C8 in 23 images; one native default-8 variant selects 8 for
both. Modern examples select equal C7/C8 defaults. These are native policy
differences, not interchangeable media classes.

The read-only `mediatek-optical::image::analysis::NativeSpeedPolicy` binds the
existing default-writer grammar's media, maximum, optimum and hardware cells.
An independent requested-rate clamp must read that same maximum cell and preserve
its incoming request when it is already within the maximum. Register/address flow
handles compiler variants without model, filename, hash or generation dispatch.
Unknown or ambiguous contracts are refused.

## Execution evidence

- 1,560 native-default executions: C7/C8 and hardware-policy bytes 0, 1, 2, 255
  across all 195 images, through the actual maximum and optimum stores.
- 83,200 requested-rate clamp cases: every byte request (0–255), for each observed
  C7 hardware maximum. Result equals `min(request, maximum)`; maximum is unchanged.
- 23,040 production classic Speed selector/tail comparisons across all 24 inputs,
  including C7/C8, all settings (OEM/On/Off/invalid), boundary maximum values and
  native RAM modes. OEM/Off preserve native results, live registers and flags;
  On uses only the validated native maximum.
- 18 source-hash-bound excerpt witnesses cover eight default-writer grammars and
  15 observed request-clamp instruction encodings. CI executes these independently
  with Unicorn. Rust tests bind all witnesses and reject changed clamp branch,
  fallback destination and maximum-cell linkage.

These are CPU/code-policy tests, not physical drive-speed measurements. They close
this speed-policy question without proving the whole MT1939 UHD conversion on
hardware. Preserve OEM limits; no additional speed patch is justified by this set.

## Reproduce

Build `mtk_receiver_evidence` with the pinned dev dependency, then:

```sh
python scripts/audit-mtk-speed-policy.py --builder target/debug/examples/mtk_receiver_evidence
python scripts/test-mtk-classic-speed.py --builder target/debug/examples/mtk_receiver_evidence
python scripts/audit-mtk-speed-policy.py \
  --builder target/debug/examples/mtk_receiver_evidence \
  --inventory internal/docs/audits/mtk-native-uhd-area-inventory-20261026.json \
  --hoard /path/to/hoard --catalog /path/to/finder-catalog.json \
  --output /tmp/mtk-speed-policy.json
```

For the complete classic selector run, pass `--sources` a list of the MT1939
`sha256`/`path` records from the committed report and `--hoard /path/to/hoard`.
The scripts hash-check originals and never write to them. Excerpt gaps are synthetic
analysis-only padding; the fixtures are not firmware files for flashing.
