# MT1939 experimental UHD software completion

Follow-up: [native UHD recognition comparison, 2026-10-30](mt1939-recognition-comparison-20261030.md)
demonstrates a U/format-1 recognition path in WH16NS60 firmware that the earlier
comparison did not cover. The completion claim below concerns the previously
enumerated software contracts, not all native-UHD behavior or physical success.

The known software-contract group is complete for all 24 held classic conversion
candidates. Production Modify still installs none of the experimental conversion
group. No tester BIN was saved, website changed, or release promoted. Physical UHD
recognition and reading remain unproven.

## Recovery/controller findings

Reference source hashes:

- Classic: `40eb760e23f100d55e86e9c061c73428d4087ef712294e4dbfcefa3093837a1a`.
- Modern comparison: `648a16d024eea31ef4901f3ac2180cbfffeda1161d70f9096335d8a6097445bc`.

Addresses below document those inputs only. Runtime selection searches instruction
roles and binds operands, state cells, native joins and saved frames.

| Role | Classic reference | Modern comparison | Experimental action |
|---|---|---|---|
| Paired controller timing fields | `366e2` | `26984` / `26a44` | C7/On selects existing native C8 field writes |
| Controller mode field | `3672c` | `26a8e` | C7/On selects existing native C8 field write |
| Read-completion boundary reflection | `197b1e` | `143318` | C7/On selects existing native C8 boundary body |
| ROM read/recovery entry | `6bf9c..6bfde` | `6dffc..6e072` | Preserve native classic dispatch |

The first timing selector writes the same native `0x2600` and `0x0600` fields in
both generations, instead of the other branch's `0x1400` / `0x0700` fields. The
second clears the native mode field rather than setting its alternative bit.
Newer hardware can additionally consult a calibration flag; that newer flag and
its producer are not transplanted into classic firmware.

The completion boundary body recognizes boundary+1 and applies the source's
native `3<<26`, `1<<27`, `1<<26` reflection formulas. This is a separate consumer
from the earlier read-boundary helper. Leaving it unchanged would send C7 around
the reflection body even after DI recognition succeeded.

Native classic recovery first dispatches on the upper two state bits, then
separates the upper-three-bit value seven. C7 and C8 both take the existing ROM
branch and call the same native read-entry implementation. Controlled return
statuses 0, 1, 0x20 and 0xb0 have identical C7/C8 call arguments, stored status,
request flag and success/failure continuation. No replacement recovery strategy
or newer hardware calibration policy is needed for this dispatch.

A branch veneer moves one completion body; another compiler form uses different
saved state/request registers and a different opaque flag register. The matcher
binds these instruction/data-flow differences without model, revision or hash
selection. OEM/Off/invalid settings replay native behavior. The common emitter
and native bodies remain shared.

## Completion gate and validation

`UhdConversionPlan` now checks every named software prerequisite: DI recognition,
core routing, auxiliary selectors, position/scaling/setup, parameter lookup,
startup calibration, read-position/ranges, controller/completion/recovery, and
native speed defaults/request clamp. A missing contract is named explicitly;
changing a controller body or recovery branch refuses completion. An empty pending
list represents this software-contract set, not a hardware capability claim.

Per-source results are committed alongside this note:

- `mt1939-complete-uhd-cpu-20261026.json`: all 24 inputs; source hashes, exact
  selected native callers, 118,656 routing comparisons, 345,648 DI cases, 9,216
  completion cases and 768 native recovery comparisons, plus the previous
  arithmetic/parameter/position/calibration/OEM-preservation suites.
- `mt1939-complete-uhd-builds-20261026.json`: all 24 complete experimental outputs
  built and signed in memory; exact input/output hashes, installed branches/stubs,
  integrity, base structural audit and offline Flash admission. Eighteen require
  29 components; six retain their state-independent parameter/calibration paths
  and require 27. Public capability remains disabled in every case.

Native function calls/controller completions intercepted by the CPU tests are
explicit test inputs. These establish the tested code paths and preservation
contracts; actual controller/optical behavior requires the hardware test.

The [speed audit](mtk-speed-policy-20261026.md) remains unchanged: preserve native
per-image limits rather than impose a universal modern rate.

## Reproduce

Use the pinned dev dependency and a Python environment containing Unicorn 2.1.4:

```sh
cargo build --release -p freemkv-fw --example mtk_receiver_evidence
python scripts/test-mtk-uhd-conversion.py \
  --builder target/release/examples/mtk_receiver_evidence \
  --corpus internal/docs/audits/mtk-speed-policy-20261026.json \
  --hoard /path/to/hoard --output /tmp/classic-cpu.json
FREEMKV_MT1939_COMPLETE_CORPUS=/absolute/path/to/mtk-speed-policy-20261026.json \
FREEMKV_MT1939_COMPLETE_HOARD=/path/to/hoard \
FREEMKV_MT1939_COMPLETE_OUTPUT=/tmp/classic-builds.json \
cargo test -p freemkv-fw --lib \
  complete_classic_corpus_builds_signs_and_admits_without_public_promotion -- --nocapture
```

The bulk build test saves the audit JSON only. It does not save firmware for a
user to flash. Preparing the selected BH16NS48 1.02 test BIN is the next separate
step after the requested pause.
