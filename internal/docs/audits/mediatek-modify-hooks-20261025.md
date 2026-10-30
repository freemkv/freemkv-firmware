# MediaTek Modify hook diagnosis after 0.15.3

This is a static corpus and source audit, performed by the primary agent. It is
not a hardware sign-off and does not change any firmware hook or enable a profile.
The released 0.15.3 CLI was used, with hashes checked against the hoard index.

## Measured scope

Every unique image under MediaTek identities was examined: **1,085** hashes,
comprising 919 OEM, 86 dump, 63 MK and 17 Omni images. MK/Omni are comparison
material only; this audit does not approve them for website publication.

`modify INPUT --dry-run --json` accepted 182 images. All 182 also passed
`modify INPUT --dry-run --json --audit`. The remaining results were 884
unsupported inputs, 18 insufficient-safe-space refusals and one invalid input.
The invalid input is an 81,920-byte MK-category object, not a complete image.
These are input/build results, not flash attempts. No drive was accessed and no
firmware output was saved.

The [complete hash-bound inventory](mediatek-modify-hook-inventory-20261025.csv)
records every input, its category, result, emitted addresses and boot capability
booleans. It includes unapproved material deliberately, and is not a website
allowlist. The CLI's structural audit proves reported detours landed and image
integrity verifies; it does not prove the OEM function has the intended meaning
or that all disc paths reach it.

## OEM and dump results

119 accepted images are held in OEM/dump: 90 use the MT1959 engine and 29 the
MT1939 engine. These are all held inputs, not just the approved published subset.

| Emitted hook evidence | Images |
| --- | ---: |
| Boot initializer | 90 |
| Speed | 89 |
| Region | 113 |
| AKE | 112 |
| VID/Gate-A | 112 |
| Deny reset | 89 |
| HRL | 113 |
| BD media gate | 89 |
| UHD media gate | 30 |
| Auth-cell widening | 1 |

Missing hooks require a reason per layout. A classic implementation need not
contain the modern deny-reset hook, for example. Several accepted images contain
only a subset of modifications; success alone must not grant every feature.
Classic region/HRL hooks can exist without configurable startup controls, so
the current website boot-support mapping is conservative for those images.

## WH16NS58 1.V9: proven cause of unavailable combined control

Input SHA-256:
`97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061`.

Its report contains a BD stub but no UHD stub. `BootSupport::from_facts` in
`crates/freemkv-fw/src/boot.rs` requires both before offering Unrestricted access.
That matches the current application behavior.

`find_bd_gate` in `engine/core.rs` recognizes two masked instruction signatures,
preferring the explicit REPORT KEY mode/class ladder. `bd_detour` implements
both that layout and the descriptor-classifier layout. `uhd_gate_detour` only
implements the explicit layout; it deliberately refuses the descriptor layout.
WH16NS58 1.V9 has the latter. This is a missing implementation for a different
control flow, not encrypted input or a filename/version rule.

Among accepted OEM/dump images, the actual emitted BD sites resolve to 30
explicit layouts and 59 descriptor layouts; 30 other images have no BD detour.
The 59 descriptor cases therefore lack the current combined control. This does
not establish that transplanting the explicit hook would work, or that native
UHD media support is absent.

## Additional findings needing separate implementation and tests

1. **Auth-cell matching is still BU40N-specific in coverage.** The exact masked
   `AUTH_CELL_SIG` matches only BU40N 1.00 among the accepted OEM/dump images.
   Its fixed-register instruction shape does not cover other held layouts.
   Contrary to the surrounding comments, the resolver does not validate that
   the loaded literal equals `0x01FF9E04`; it requires a unique pattern and a
   non-filler branch destination. Neither the comments nor a unique byte match
   establish equivalent data flow on a different firmware.
2. **Boot and runtime combined-control semantics differ.** `BootSettings::flags`
   writes the chosen Unrestricted value to slots 3 and 4. Both BD stubs still
   read deprecated slot 4, while the UHD and auth-cell stubs read slot 3.
   The generic runtime SET handler writes only the requested slot. Therefore a
   runtime SET of Unrestricted alone cannot update the BD consumer. This finding
   follows directly from the emitted instructions; it does not affect the fact
   that the current Modify boot settings synchronize both slots.
3. **Optional-hook failure reasons disappear.** The MT1959 RawRead emitter
   collapses UHD, HRL, BD and auth-cell resolution errors into zero addresses.
   The group can still report Applied. Consumers can see emitted facts, but
   cannot distinguish a known alternate layout from ambiguity, a failed semantic
   landmark, or an unsupported optional function. Do not infer those reasons
   from model names.
4. **Configurable settings and fixed modifications need distinct evidence.**
   Classic images can emit region/HRL modifications without a startup settings
   hook. `boot_settings.supported=false` correctly hides a configurable control,
   but is insufficient to describe every fixed effect of Modify. The website
   currently follows the app controls conservatively; a future capability API
   should report both explicitly before broadening advertised features.

## Implementation contract for the next change

- Recognize a typed layout from signatures plus decoded control flow, register
  use, referenced state and accept/deny landmarks. Shared MediaTek analysis
  should own that evidence; UI, website packaging and emitters consume it.
- Give each hook a resolved site, overwritten instruction contract,
  continuation/deny destinations, supported states and a typed unavailable
  reason. Reject ambiguous evidence. A family or model string grants nothing.
- For the descriptor layout, derive the actual UHD discriminator and its
  accept/refuse path. Preserve the live registers, stack frame and flags.
  Do not reuse the explicit layout's offsets.
- Derive auth-cell variants from state producer/consumer data flow and the
  actual failure branch. A relaxed pattern or relocated RAM literal alone is
  insufficient evidence of equivalent meaning.
- Unify the runtime and boot flag consumers without silently changing saved
  legacy settings. Lock both paths down with instruction-execution tests.
- Report per-feature emitted effects separately from editable boot settings.
  The website must continue asking Modify about the exact image hash.
- Test every variant with positive/negative/ambiguous fixtures, register and
  stack preservation, all public state choices, input immutability and output
  integrity. Re-run the full corpus. Hardware verification remains separate.

No new UHD hook, relaxed signature, production adaptation JSON or crossflash
permission was shipped by this diagnosis.
