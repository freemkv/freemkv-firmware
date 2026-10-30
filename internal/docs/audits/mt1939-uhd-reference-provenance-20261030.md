# UHD reference provenance and BU40N modification comparison

The BH16NS48 1.02 MT1939 image (`43c484dc...`) remains the build base.
Modern images below are behavioral references, not crossflash targets or sources
of hardware defaults to transplant. No new BH16NS48 candidate was built here.

## Verified reference images

Downloaded the [MakeMKV developer firmware archive](https://www.makemkv.com/download/mk-firmware-pack-20200720.zip)
linked by the [developer's MK explanation](https://forum.makemkv.com/forum/viewtopic.php?f=19&t=19113).
Archive SHA-256: `5c03087d4ad1df1d4f638d1a047a9addf11abf86284997fc891e174667797ab5`.
The [UHD guide](https://forum.makemkv.com/forum/viewtopic.php?t=19634) recommends
these model/version combinations. Each image was extracted by matching its full
SHA-256; full paths, hashes, archive members and inspection records are in the
adjacent JSON. This establishes provenance and documented UHD use, not a fresh
physical test of each individual image in this session.

| Reference | SHA-256 prefix | Native DI recognition site |
|---|---|---|
| BU40N 1.03 MK | `64900e8d69212f5d` | `0xe0e56` |
| WH16NS60 1.02 MK | `c5e351d25f647599` | `0xe25fa` |
| ASUS BW-16D1HT 3.10 MK | `e04ed8f38ce9e858` | `0xe037c` |

All three independently match explicit C7 recognition and selection grammars in
DiscInformation, ControlBit, ControlField, ForwardCalculation,
ReverseCalculation and ParameterNibble. An unmatched grammar would mean unknown,
not absent support. HardwareDefaults are inventoried only as comparison evidence.

## What our working BU40N modification actually changes

Built the committed BU40N OEM 1.00 fixture through `freemkv-fw modify --audit --json`.
Input SHA-256: `221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4`.
The command and structural audit succeeded. The modification report is retained
in the scratch reference directory and its lever facts are copied to the JSON.

The output leaves all seven inventoried native code regions byte-identical.
It also leaves the complete U-identifier/format decision at `0xe0e22..0xe0e6a`
byte-identical. That OEM code already stores its U flag at `0x02000b19`, accepts
U/1 through the ordinary C0/layer path, and maps U/5 to C7 for two layers or C8
for three layers. The native DI, controller and calculation roles therefore
predate our modification; the modification does not implement recognition.

Relevant modification sites on this exact fixture:

| Site | Role |
|---|---|
| `0x1365a0` | AKE reject-tail detour, preserving LR |
| `0x1367ae` | VID producer gate |
| `0x1367f8` | Deny-path reset detour |
| `0x1365c2` | Native UHD class gate in REPORT KEY |
| `0x136826` | Auth-cell acceptance widening |

The native UHD class stub replays OEM acceptance for Unrestricted On or OEM;
Off forces refusal. The auth-cell hook changes a later acceptance decision.
Neither is the early optical/DI acquisition implementation. Speed, region,
boot settings, HRL and vendor-command hooks are separate changes.

## Implication for MT1939

BH16NS48 OEM has legacy selections in the six roles above. Its conversion must
add behavior already native in BU40N; copying only BU40N's unlock hooks cannot
establish parity. The previous WH14NS40 MT1959 reference remains useful but was
insufficient alone: it lacks the native U/1 branch present in BU40N and WH16NS60.

The U/1+U/5 detection-only candidate still failed on the tester's drive. That
does not prove whether recognition was reached. Valid DI acquisition and its
earlier abort paths remain unobserved hardware boundaries; see the recognition
comparison and read-only state-capture tool. Do not force the ready bit or
claim that static branch equivalence proves physical UHD detection.

Validation: native inspection on all three archive references, BU40N OEM and
BH16NS48 OEM; audited BU40N modify; byte comparisons of seven native regions
and the complete U-format branch; example build, Clippy and formatting checks.
