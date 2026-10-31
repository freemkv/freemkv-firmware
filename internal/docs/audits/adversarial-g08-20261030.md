# Adversarial G08 audit — 2026-10-30

Decision: **conditionally needed for native extended host authentication; unresolved for an end-to-end raw-sector conversion guarantee.** Keeping G08 diagnostic-only is a reasonable explicitly limited media-code policy, but the justification cannot be “existing AKE/encryption bypasses make it unnecessary,” particularly under shipping defaults. No production changes, flashes, commits, or crypto execution performed.

## Source and evidence

Reviewed freemkv worktree f5b7f12, dependency 66c4b1c. New source disassembly is in `/tmp/freemkv-g08-disassembly.txt` and `/tmp/freemkv-g08-follow.txt`; generating scripts `/tmp/freemkv-g08-disasm.py`, `/tmp/freemkv-g08-follow.py`; selected existing receipts `/tmp/freemkv-g08-reference-evidence.json`. All three referenced image SHA256 hashes were independently verified. Prior receipt extraction is not a new CPU execution. Instruction addresses below are flash offsets/virtual addresses in the named image, not transferable patch addresses.

Native reference BU40N 1.02 SHA256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`. Short-worker comparison ASUS BC-12D2HT 3.00 SHA256 `dd03cdae194de03a710b5f6e88dfedf421fd20667a3cc9ec58e828bd769ab2ed`. BN11 SHA256 `5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95` already has an extended mode/certificate/service path: it is a media-gap example, not evidence of missing G08.

## Actual downstream chain

1. In BU40N 1.02 the selector at `0xcaf78` receives an already-read header word, stores it, validates its low half against `0x1003`, and uses the next nibble to store mode 1 at `0xcaf90` or mode 0 at `0xcafcc`. Mode cell is `0x01ffc095`. Invalid header preserves supplied mode in this implementation. The upstream header acquisition and service/provisioning prerequisites are **not established** by this selector receipt.
2. REPORT KEY worker `0x1367dc` zeroes response length `0x02000c72`, calls setup `0x4147c` with `(3,1)`, and enforces mode/class agreement. Mode 1/class other than 3 and mode 0/class other than 2 take refusal `0x136814`, potentially setting sense `05/6f/01`. This is before certificate production, not a later certificate-verification failure repaired by an AKE reject hook.
3. Format 1 calls certificate worker `0x13584c`. AGID must be less than 2 and the selected session byte must equal **3**, checked at `0x135886`. Failure calls session setter with state 1 at `0x135890` and potentially emits `05/2c/00`. A generic “force state 6” is not a substitute for this earlier state-3 prerequisite.
4. At `0x1358aa..0x1358da`, mode selects `min(CDB allocation,180)` versus `min(CDB allocation,116)` into the shared response-length cell. This is a transfer-length cap; it is not proof of a heap allocation or capacity change. Zero length returns. Mode 1 emits header length `0xb2`; mode 0 emits `0x72`, via byte writer `0xa1c84`. That writer resolves the native response base through cells `0x02000c7c`, `0x02000c78` and offset `0xdc60`.
5. The mode controls the service packet/session storage offset and packet byte, then selects operation **0xb3** at `0x135966` versus **0x12** at `0x13596c`, calling service `0xca564`. The connected extended service dispatch enters the protected backend at `0x14000`, payload `0x14080..0x16fff` (12,160 bytes). The existing backend receipt establishes the call/range and bytes, not backend semantics or successful key material.
6. Certificate-copy helper `0x138b68` receives `(0x24,1)` for extended mode, copies **144 bytes from `0x1e9040`**, versus `(0x18,0)` copying **92 bytes from `0x1e8420`**, using native copy `0x13dc04`. Thus G08 changes actual response contents/layout as well as length.
7. Worker calls response commit `0x98298` at `0x13598c`. Commit consumes the same `0x02000c72` length, rounds odd counts up (special handling for 0xffff), writes response DMA address to `0x040300e8`, clips against a reserved native window, writes count to `0x04042154`, and sets ready byte `0x02000c6d=1`. This connects the stage-only sizing receipt to real response staging, though external transport/device completion was not executed.
8. Certificate worker then advances the selected AGID to state **4** through setter `0xcab78` at `0x135996`, and writes its status byte. Setter validates AGID<2 and stores through native buffer bases. Subsequent SEND KEY/session transitions, hardware crypto completion, and READ authorization are not proven by this trace.

The short BC-12D2HT worker `0x16a44c` has the same state-3 precondition (`0x16a486`) but only the 116-byte cap (`0x16a4b2`), header `0x72`, service `0x12` (`0x16a50a`), short copy path, and state-4 transition (`0x16a526`). REPORT dispatcher `0x16aab8` does not acquire extended mode by merely being routed a class-3 request. Patching G07 routing alone cannot supply the missing G08 representation.

## Interception and default flags

- `crates/freemkv-fw/src/boot.rs:88`: shipping values are `[1,255,255,255,255]`, ordered Unrestricted, HRL, Encryption, Speed, Region (`boot.rs:18`). Encryption is OEM **255**, not bypass 0.
- `engine/core.rs:2262` and `:2327`: AKE stubs force session state 6 and clear bus encryption only when Encryption is `STATE_OFF`. The desktop hook changes one rejected-authentication state writer; NB hooks a shared accept/reject setter. Neither constructs extended certificate/nonce replies nor replaces the registered REPORT/SEND KEY workers.
- `engine/core.rs:2946`: Gate-A separately permits bare READ DISC STRUCTURE format 0x80 (VID) and resets the bus latch only with Encryption OFF. OEM flags retain the `auth==6` decision. This is a structure read, **not a proof about READ(10)/READ(12)/READ CD sector commands**.
- `engine/core.rs:3008` (deny-reset function immediately after Gate-A) idles the engine and replays refusal sense; it does not turn every refusal into success.
- `engine/core.rs:2498..2621`: Unrestricted ON widens a detected auth-cell comparison against 0xC. Its documented binding is the VID-success contract, not wholesale session initialization or certificate production. It neither repairs the certificate worker's state-3 prerequisite nor substitutes for mode/header/backend generation.
- `engine/mt1959.rs:615..715`: these detours are explicitly separate emission paths. `engine/mt1959_uhd.rs:170..184` records G07/G08 only as diagnostics; tests around `:522` assert that policy but do not demonstrate downstream READ independence.
- Dependency `src/image/analysis/uhd_keys.rs:200..335` positively identifies registered wrappers, REPORT worker mode and certificate sizing grammar; it does not prove successful authentication or that other command paths never consume authentication state.

## Scope-specific verdict

| Intended outcome | G08 verdict |
|---|---|
| Optical disc detection / DI classification | No demonstrated G08 dependency; media code work may omit G08. This trace does not prove physical detection. |
| Media readiness | Unresolved: prior selector execution assumes acquired header and excludes setup/auxiliary service calls. Do not turn this into a readiness guarantee. |
| Successful ordinary sector READ | Unresolved: no complete READ handler→session/mode authorization→DMA path was proven here. Authentication failure may remain a gate. |
| Raw encrypted sectors for an independent host decryptor | Plausibly avoid native AACS2 exchange with explicitly enabled Encryption OFF and suitable host sequence; not proven across missing-G08 images. VID/bus-latch evidence is narrower than sector-read evidence. |
| Native AACS2 host authentication, OEM/default encryption | Extended response/session functionality is conditionally required; old short path is observably non-equivalent. Existing bypasses do not replace it and are not active by default. |

Concrete counterexamples to blanket bypass reasoning: the defaults do not activate bypass; native class/mode mismatch rejects before certificate output; state-3 validation can reject before sizing/service/output; short firmware emits at most 116 bytes with a different header/certificate layout even if class routing is extended. These are code-level counterexamples, not claims that a specific disc fails a physical read.

## Next evidence needed

Bind registered READ(10), READ(12), relevant raw/vendor read handlers and their final DMA path in one genuine missing-G08 desktop image plus native reference. Enumerate auth/session/mode consumers on that connected path, then test OEM and Encryption OFF with initial/failure/reset states; include failed REPORT/SEND KEY before READ and disc-insert bus rearm. Track every reject/return and state store, with external hardware calls modeled as unknown rather than successful. Only then claim G08 unnecessary for raw reads. Separately trace header acquisition and native setup `0x4147c` to distinguish readiness from post-ready host authentication. For native AACS2 support, bind the complete SEND KEY state machine, certificate/nonce builders and backend semantics; changing a length constant or transplanting payload bytes is insufficient. Hardware validation should test disc detection, readiness, sectors, VID, bus encryption, and normal authentication as separate outcomes.
