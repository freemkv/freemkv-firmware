# MediaTek UHD code evidence survey

The current manufacturer-qualified inventory and per-image gap results are in
[the MT1959 gap table](mt1959-uhd-gap-table-20261030.md). Historical "native" and
"positive" labels below mean reviewed code evidence only, never OEM UHD.

This is a research instrument on the MT1939 branch, not a production hardware
capability flag. It answers which reviewed instruction paths are present and
what our own modifier changes. It does not establish physical detection,
complete initialization, AACS access, capacity or readable sectors.

## Scanner

`crates/freemkv-fw/examples/mtk_uhd_scan.rs` applies the pinned library's
source-bound `UhdAreas` contracts to each distinct input image. It scans DI
identifier recognition, control-bit and control-field selection, forward and
reverse calculations, parameter selection and read-only hardware defaults.
The classification is based on the actual code, never model/chip/hash dispatch:

- Native: all six media roles explicitly recognize U/C7 and the hardware policy
  role and shared state binding also match.
- Legacy: all six roles match reviewed legacy implementations.
- Mixed: known roles disagree on explicit versus legacy handling.
- Unknown/partial: any missing, ambiguous or inconsistent contract.

Identification banners and catalogue metadata label evidence only. All supplied
BINs are scanned even if identification fails or reports an older chipset. This
matters for fragments and unidentified layouts; neither is proof of absence.
SHA-256 deduplicates/proves inputs; it does not choose a signature.

Run without writing to a drive:

```sh
cargo run -p freemkv-fw --example mtk_uhd_scan -- evidence.json ROOT ...
cargo run -p freemkv-fw --example mtk_uhd_scan -- pairs.json --modify-pairs SOURCE.bin ...
```

The second command builds our unrestricted-On modification in memory and records
hook outcomes and byte preservation in each reviewed original region. A refused
build is retained as a refusal. Modified code that no longer matches an OEM
grammar is unknown in its independent scan, not automatically unsupported.
No BIN is exported and no hardware operation occurs.

## Five stock source samples and paired builds

These are five distinct marketed drive families, not five independent hardware
designs. Their hoard sidecars classify them as OEM/unpatched and retain updater
or OEM-package extraction provenance; none is an MK reference.

| Source | SHA-256 prefix | Stock media roles | All seven regions after our modification |
| --- | --- | --- | --- |
| ASUS BW-16D1HT 3.02 | 784e017fbacd | Six explicit U/C7 roles | Unchanged |
| LG BH16NS55 1.03 | 0bfdd3009ed1 | Six explicit U/C7 roles | Unchanged |
| LG BU40N 1.02 | 97bee5c51fbe | Six explicit U/C7 roles | Unchanged |
| LG BU50N 1.00 | 20425a8ade6b | Six explicit U/C7 roles | Unchanged |
| LG WH16NS60 1.01 | aea98763cad7 | Six explicit U/C7 roles | Unchanged |

All five offline modifications build. BU40N, BU50N and WH16NS60 emit the explicit
native UHD class-gate hook. ASUS and BH16NS55 have no role-validated instance of
that particular class gate; their report retains that unavailability while
applying independently established key/authentication hooks. Do not erase this
difference or infer physical success from the overall build result.

The media-aware code across all five is consistent at the reviewed semantic
roles, despite register and instruction variants. Hardware defaults differ:
BU40N/BU50N match the slim fixed-six policy, WH16NS60 a desktop default-eight
policy, and ASUS/BH16NS55 another modern policy. Our modifier leaves all of
these original hardware-policy regions intact. This supports treating shared
media routing and hardware defaults separately, not copying hardware values.

The five positive pairs show that our current MT1959 unlock preserves existing
UHD media logic. They do not demonstrate adding that logic to firmware missing
it. The corpus' legacy/mixed MT1959 cases are therefore a separate negative
comparison set and must be examined before making that stronger claim.

## Validation

The scanner's native and legacy fixture checks pass, and unrecognized bytes
remain unknown. Clippy with warnings denied passes. The unfiltered inventory
scanned all 1,085 distinct BINs under the held OEM, dump, MK and OmniDrive
MediaTek roots: 149 native, 28 legacy, 23 mixed and 885 partial/unknown. The
last category includes other chip generations, fragments and unknown layouts;
it is not an unsupported-UHD verdict. Full per-image evidence is retained in
`mediatek-uhd-corpus-20261030.json`; five stock/modified pairs are retained in
`mediatek-uhd-five-pairs-20261030.json`.

The first inventory of 200 positively identified MT19xx images found 147 native,
28 legacy, 23 mixed and two partial/unknown. Removing the identification gate
additionally found reviewed native code in two unidentified inputs catalogued
as ASUS BW-16D1HT 3.01 and BE16NU50 1.01. This is why identification is now a
report label and never a condition for running the code scan.
Of that initial subset, 24 MT1959 images have legacy/mixed media roles and are
compared with their own modified output independently of the five OEM positive
examples. Twenty-one builds succeed and preserve all seven reviewed regions;
three MK inputs refuse unrestricted-On. None of these builds converts its
reviewed legacy/mixed media handling into the positive native pattern. These
are authoring results, not physical success/failure tests. MK images remain
explicitly categorized in the broad scan.

## MT1959 comparison before implementation

The user prioritizes actual MT1959 UHD operation before further MT1939 trials.
The OEM-only MT1959 inventory has 69 full-sized source images and 24 fragments.
The full-sized sources have 59 native reviewed media implementations and ten
legacy/mixed implementations. The 24 unknown/partial entries are fragments,
not another 24 unknown complete firmwares. These are code-evidence counts.

`mt1959-uhd-reference-lock-20261030.json` pins WH16NS60 1.01/1.03, BU40N
1.02/1.04, BP60NB10 1.00 and Buffalo BU40N BU11. They represent six firmware
images across four marketed products, not six independent hardware designs.
The product references have manufacturer UHD support and stock provenance;
none has been physically tested in this investigation. BU50N and Verbatim
43888 remain separately qualified candidates where product-to-image or primary
manufacturer evidence is incomplete. Never rewrite this lock as six local
100%-working hardware tests.

WH16NS58 1.V9 (97b28707) is a separate comparison target. Its U/5 parser
assigns C7 for two layers and C8 for three; its own modified build preserves all
seven reviewed regions. The modifier emits key/authentication and reset-path
hooks, but no independently matched `uhd-native` class-gate hook. Earlier media
admission and readiness still need tracing before stock operational behavior
can be classified.

Native CPU execution of the matched DI identifier gates now supplies a narrow
behavioral check: 36 cases across the five initial positive examples and BH16,
and 60 cases across the ten OEM legacy/mixed MT1959 sources. U/5 assigns C7/C8
in the positive gates but exits the legacy gates without a media-state store.
Only the matched gate and its direct state-store join execute. Prefix and
attribute validation are assumed complete; acquisition/readiness are not run.

The existing classic conversion contracts do not cover the ten modern legacy
implementations completely: position binds in all ten, setup in one, while DI,
auxiliary selectors, read-position, parameters, calibration and completion
remain unbound. Do not reuse the complete MT1939 helper set or label this gap
a few already-proven branch patches. Extend and validate each modern contract
before attempting a coherent conversion.

The BP50NB40 1.00 negative user report at
https://forum.makemkv.com/forum/viewtopic.php?f=16&t=29614 describes an original
MT1959 NB40 drive that does not detect UHD even with LibreDrive enabled.
This is useful external behavior evidence, but it does not hash-bind our exact
sample or establish convertibility of that older hardware. Prefer a properly
identified NB50/BP60 comparison for hardware-matched investigation. There is
no local optical drive available; tester availability/model/SVC is requested.
