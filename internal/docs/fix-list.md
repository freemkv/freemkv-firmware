# General fix list

## Native BD/UHD capability classification

Status: open. Stock UHD capability has not yet been established for the reported
case; a chipset label or the existing media badge is not evidence by itself.

1. Confirm the actual stock BD/UHD capability of the exact firmware and hardware.
   Keep a proven negative separate from an unknown result.
2. If the stock image is BD-only, trace why the shared classifier labels it UHD
   and why that classification reaches the website. Inspect the original rule,
   parsed evidence and fallbacks before changing the label.
3. Audit this classification generally across the hoard, optical/chipset code,
   app and website. Separate native media support, available Modify controls and
   a future firmware conversion. A successful hook build does not establish
   native UHD support or physical UHD reading.
4. Correct the shared rule and add regression cases for BD-only, proven UHD and
   unknown inputs. Avoid model-name or chipset-only exceptions.

Reported example:

- LG WH14NS40 1.03, build N0009A0: website shows MT1939 and BD/UHD.
- Package: `WH14NS40_1.03_3b8730cc.tar`.
- Final BIN SHA-256:
  `f6a5a578f9b5347f6371a7ef1195ab84b1bea4d80b58c97efa23c8ddf0d6f6e9`.
- Recorded original: `LG_WH14NS40_1.03-A0_20140326_src.zip`.
- Initial code lead: `crates/freemkv-chipset/src/capability.rs` defines
  `MediaClass::UhdBd` and renders it as `BD/UHD`. This is a lead for tracing the
  rule, not confirmation of the drive's stock capabilities.

Release constraints: work and validation stay on dev. Website claims must match
the deployed Modify app; no website capability changes before the corresponding
correct firmware release.

Confirmed rule defect: `capability_for` reads the model-token unlock-scope map,
and unknown models default to `UhdBd`. This is patch applicability, not measured
native media support. Engine reports serialize that scope as `media`, which the
catalog uses as the top badge. WH14NS40 is an explicit `UhdBd` map entry across
both MT1939 and MT1959 hardware. Neither that entry nor the fallback is valid
proof of stock UHD reading. Do not fix this by changing the WH14NS40 token:
the consumer needs a separate evidence-backed native-media result, including
unknown, while patch scope remains available to the hook planner.

The exact MT1939 stock UHD result remains unknown. The existing code tests prove
state and layer routing, not physical UHD reads. The classic Unrestricted
control therefore stays unavailable. Release gating now requires website
capability manifests to identify the exact officially released Modify binary;
no new dev results have been copied to the website.
