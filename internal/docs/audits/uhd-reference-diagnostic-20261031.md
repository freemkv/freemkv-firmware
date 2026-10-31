# UHD reference diagnosis — 2026-10-31

Diagnosis only. No firmware source, patch policy, boot defaults or Desktop BIN
changed. Source commit: 7933f6f559ef40b3f897299d41ed00fb7228b4f1.

## Finding

The present success classification is narrower than complete UHD reading.
It can report a complete G01–G06 media plan while G07/G08 differ from advertised
UHD reference models. That is intentional in the implementation, but makes
“UHD supported” an unsafe unqualified description. WH16NS58 1.V9 is a concrete
counterexample to equating native media-role recognition with complete parity.
No diagnosis here establishes that modified 1.V9 can or cannot physically read.

## Commercial reference evidence

- WH16NS60: LG explicitly advertises Ultra HD Blu-ray playback:
  https://www.lg.com/us/burners-drives/lg-wh16ns60-internal-blu-ray-dvd-drive
- BU40N: HLDS specification, dated 2016, labels the model a UHD writer and
  specifies UHD reading. Distributor-hosted manufacturer document:
  https://www.digikey.bg/htmldatasheets/production/2467481/0/0/1/BU40N-Specifications.pdf
- BH16NS60: commercial listing attributed to Hitachi-LG Data Storage Korea
  advertises UHD BD-ROM reading at 8x. This is lower-confidence provenance than
  the manufacturer-hosted WH16NS60 page:
  https://globaltradeplaza.com/product/super-multi-uhd-bd-writer-bh16ns60-2

These establish model-level commercial claims, not certification of every
firmware revision, OEM branch or transplanted firmware/hardware combination.
Manufacturer Buffalo also advertises BRUHD-PU3-BK UHD playback, but its enclosure
claim is not independently bound here to a particular hoard BIN:
https://www.buffalo.jp/press/detail/20170405-02.html

## Actual image comparison

Fresh read-only `mt1959_conversion_audit` was executed on all 123 retained actual
inputs, checking their SHA-256, plus separately on the excluded BP50NB40 1.00.
The companion JSON records all 124 rows, input identities, emitted-hook reports,
media-helper roles, G07/G08 findings and diagnostic provenance. Existing
production reports are compared; no new CPU or physical execution is claimed.

| Actual OEM images | G01–G06 media additions needed | G07/G08 differences recognized |
| --- | --- | --- |
| BU40N general 1.00/1.01/1.02/1.03 | None | Neither |
| WH16NS60 1.00/1.01/1.02/1.03 | None | Neither |
| BH16NS60 1.00 and INTM | None | Neither |
| WH16NS58 1.V1/1.V2/1.V5/1.V7/1.V9 | None | Both |

The user reports successful UHD reading with modified BU40N. The exact tested
revision, BIN hash, settings and client command profile have been requested;
the inspected BU40N rows must not silently stand in for that exact hardware
experiment. Its physical success remains the practical anchor once bound.

## What is and is not being changed

G01–G06 cover DI admission, control bit/field, forward/reverse calculations and
conditional parameters, with additional source-qualified downstream classic
roles. For native-media images these generate no conversion helpers.

G07 is REPORT/SEND KEY class-3 routing. G08 is the extended authentication
mode/certificate/session/backend path. The current Plan records both as
`authentication_differences` and never generates their patches. Their absence
from the required media-plan set is explicit in `mt1959_uhd.rs:1–6,115–121` and
the `UhdKeyPath::inspect` block. The pinned library binds registered A3/A4
wrappers, legacy class selectors and the worker mode/allocation grammar;
this is more than comparing model names, but does not prove session completion.

Independent freemkv AKE, VID/reset, auth-cell and HRL hooks alter particular
acceptance paths. On 1.V9 they are installed, but they do not manufacture G07
routing or G08 producers/session/backend compatibility. Encryption Off is a
specific bypass profile, not authenticated OEM parity. With Encryption OEM,
that bypass is not selected.

Correction to the preceding conversation: BU40N's `uhd-native` and `bd-native`
hooks are forced-refusal controls. `build_uhd_gate_stub` in `core.rs` preserves
OEM comparison for On/OEM and forces refusal for Off. Their absence on 1.V9
therefore does NOT establish an omitted unlock. The unavailable report is also
not proof of a hidden blocker. Hook-count comparison alone was misleading.

## Where the omitted authentication work occurs

| Retained group | Both G07/G08 differ and remain unpatched | Neither difference recognized |
| --- | ---: | ---: |
| Newer native-media | 53 | 29 |
| Older conversion | 9 | 3 |
| Classic conversion | 29 | 0 |
| Total | **91** | **32** |

All 123 authentication diagnostics resolved; no diagnostic error was silently
counted as parity. “Neither difference” still means the inspected contracts,
not an exhaustive equality proof. The additional excluded BP50NB40 1.00 has
G07/G08 differences and unresolved G01 identity/density and G05 reverse contracts.
It remains excluded and was not authored or flashed.

## Consequences and next diagnostic priorities

1. Stop interpreting the 123/123 software receipt as full authenticated UHD or
   universal sector-reading capability. Its existing finite-contract evidence
   remains valid within its stated scope. Capability wording is the first
   reporting defect; firmware need is profile-dependent.
2. Bind the exact successful BU40N experiment: input/output hash, settings,
   client commands and observed sector results. Reproduce that command/state
   sequence on 1.V9 in software through the actual native READ path. Determine
   whether missing authentication paths are bypassed, required, or encountered
   during capability probing, insertion, failure and reset/rearm.
3. For 1.V9, trace DI/acquisition state to readiness and registered READ(10/12)
   dispatch/controller boundaries, alongside class-3 A3/A4 routes. Current
   local helper tests do not establish all those connections. Do not insert
   successful service stubs to close that gap.
4. Repeat the resulting requirements across the row groups, not a model allowlist.
   For authenticated parity, G07/G08 differences are actual unresolved work.
   For the working bypass profile, prove irrelevance by reachable command/state
   traces before treating those differences as optional.
5. Investigate G01–G06 producer/lifetime, runtime calibration and controller
   dependencies separately; passing six labels cannot establish their complete
   execution environment. Do not copy donor hardware tables merely to match bytes.

No evidence presently justifies either “1.V9 OEM reads UHD” or “one missing
native UHD hook is the cause.” The concrete result is that 1.V9 differs from the
commercial-reference group in G07/G08, and those differences are not repaired.
Whether they prevent the user's successful bypass workflow is the next bounded
question, requiring the exact hardware anchor and native read-state tracing.
