# Adversarial G07 audit (2026-10-30)

Verdict: **conditional needed**. G07 can remain outside a narrowly described media-recognition/plain-sector milestone. It cannot be ignored for an authenticated UHD host-playback claim, and the existing Encryption/AKE patches do not establish a bypass of its command routing. A raw encrypted-sector milestone may exclude it only when the specified host workflow actually avoids class-3 REPORT/SEND KEY; that exclusion is a workflow condition, not firmware parity.

Scope: freemkv-firmware f5b7f12 and mediatek-optical 66c4b1c. No production edits, flashes or claims of physical acquisition. Independently re-read registered handler grammar and feature-stub implementation, hash-checked and disassembled three source images. Script `/tmp/freemkv-g07-inspect.py`, output `/tmp/freemkv-g07-disassembly.txt`. Existing 171-image routing/worker receipts supply breadth; their guard-success and stage-entry assumptions remain assumptions.

## What the feature patches actually change

`crates/freemkv-fw/src/engine/core.rs:2262` (`build_ake_stub`) runs at the failed-certificate state writer. Encryption Off invokes the light session reset, then passes AGID in R0 and forced state 6 in R1 to the OEM setter. It preserves outer LR through its B.W/tail-call contract. The NB variant (`build_ake_stub_nb`, line 2327) hooks the shared setter call and preserves the native R1 on non-Off paths. Neither hook replaces the registered A3/A4 entry, changes CDB byte 7, supplies a certificate response, nor guarantees that a class-3 request reaches the certificate verifier at all.

Encryption On and passthrough both retain native AKE decisions. Off is the only forced state arm. `build_gatea_stub` (line 2946) hooks the separate VID producer comparison with state 6: Off clears the session latch and the CDB/AGID selector bits, then jumps to the native response continuation with live R1/R2 arguments preserved. It changes the VID access path; it does not rewrite the REPORT/SEND KEY wrapper. Deny-reset replays 05/6F/02 after reset. UHD/Bd gate detours in `mt1959.rs:749` and `:811` govern the media accept/refuse gate and explicitly do not add missing AACS2 workers.

Thus forced authentication state is downstream of command routing and cannot cure a request that has already selected the legacy wrong worker. The forced path's de-bus latch clearing also does not constitute an authenticated bus-key negotiation for an unmodified playback host.

## Concrete routing counterexample and native controls

The source-bound dependency `src/image/analysis/uhd_keys.rs` binds opcode A4/A3 command registration (flags 7, Thumb handlers), shared CDB, wrapper selectors, status checks, and actual called worker. A legacy REPORT wrapper has **two** class-2 selectors (including the format 0x38 short route), SEND has one; changing one comparison is incomplete. Native grammar explicitly admits class 2 or class 3 before continuing to the same AACS worker. Registration and wrapper source relationships must remain part of any repair precondition.

For BH16NS50 1.03 SHA256 `e6ae082bba5f617a4de51fba0139c83c7d944ed54bd664177431b43837d5e2ce`, receipt class-3 A4 goes to 0x11D0A8 and calls sense setter 0xA2CD6 with R0/R1/R2 = 5/0x30/2, whereas class 2 goes to 0x139920. Class-3 A3 goes to 0x11D4D4, class 2 to 0x139994. This is an observable error/worker mismatch before the AKE forced-state setter. The SEND legacy worker dispatches formats 1, 3 and 0x3F, while the AACS SEND dispatcher uses 1, 2 and 0x3F; merely calling it “a different address” understates the input interpretation mismatch.

OEM BU40N 1.02 SHA256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396` sends both classes to REPORT 0x1367DC and SEND 0x1368AA (30/30 tested wrapper combinations). REPORT zeroes response length at 0x02000C72, calls setup 0x4147C with (3,1), clears MMIO bit 0x10 at 0x04000000, then checks mode at 0x01FFC095 against CDB class. The mode/class mismatch can return with sense 05/6F/01. Format dispatch is therefore not a transparent class alias even after wrapper admission.

Old-layout BU40N BN11 SHA256 `5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95` already has 30/30 shared routing and mode/class REPORT 0x135090, mode byte 0x01FFC091, certificate 0x134100. “Old layout” cannot select a G07 patch. Conversely its native routing says nothing about every other old image.

## Value and consumer compatibility

The native REPORT worker clears the 16-bit response length before dispatch; unsupported formats set the native command/error byte. Consumers depend on that response-length/error state, not just R0 on return. The legacy refusal can clear its own output state and report 05/30/02 instead of producing the AACS response. Preserving a wrapper's `pop {r4,pc}` alone does not preserve this contract.

Worker receipts demonstrate fixed 116-byte certificate sizing versus mode-selected 116/180-byte sizing, capped by CDB allocation length (0,1,115,116,117,179,180,181,1024 tested). These are allocation assignments after assumed successful session validation, **not** generated certificate contents. A G07 class-selector repair routes the producer but does not add the 180-byte producer, initialize mode, supply nonce/certificate material, or establish the host parser's expected extended response. That is a G07→G08 dependency for authentication. Enlarging length alone risks returning unproduced/stale bytes; aliasing class 3 to class 2 risks returning a valid-length response of the wrong protocol.

## Milestones and minimum combined design

| Milestone | G07 disposition | Required qualification |
|---|---|---|
| Disc detection/media recognition | May exclude | Validate real acquisition/classification via G01–G06 and actual hardware; class-3 host capability probes may still expose rejection. |
| Plain unprotected sector read | May exclude | Demonstrate native read path and content; no inference from key-command stage emulation. |
| Raw encrypted-sector access | Conditional exclusion | Specify host command sequence and show no required class-3 key transaction, successful sector transfer and byte-level content meaning. If the host asks class 3 for keys/VID, revisit routing and response contracts. |
| Authenticated UHD host playback | Required where different; otherwise unresolved end-to-end | Admission, correct mode, complete certificate/key backend and session lifecycle, response buffer/length, bus encryption/key agreement, and host acceptance must all work. |

Minimum change to the design now: retain G07 diagnostics for media-only plans but label their completion as G01–G06 media conversion, never generic UHD/playback parity. Add an explicit requested-milestone/profile requirement so G07/G08 gaps and unresolved inspections block authenticated conversion success. Existing `mt1959_uhd.rs:170–186` expressly allows complete plans despite either outcome, so present success cannot certify authentication.

A future G07 patch must bind both registered wrappers and their exact three legacy selector sites, extend class admission without losing class-2/format-0x38 behavior, preserve native guard/status handling and ABI, and require a positively compatible downstream mode/backend contract. Avoid transplanting workers from a donor by address or increasing response lengths. Test original and installed wrappers for both classes, all supported/unsupported formats, failed as well as successful guard returns, media states, and feature Off/On/passthrough. Then exercise the complete native producer-to-transfer path, buffer canaries and length/error stores, followed by physical host session/read validation. Existing receipts stop at calls or selected stores and cannot satisfy that last requirement.
