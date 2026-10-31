# MT1959 resident speed-worker qualification — 2026-10-30

Verdict: **cannot establish old fallback equivalence or raw-read exclusion**. The argument4 difference is part of a broadly used speed/mode transition interface. A newly resolved upstream marker consumer selects the mode which enables the resident dispatch, so the difference does not depend solely on an artificial mode input. This remains a bounded software qualification blocker, not proof that physical UHD reads fail.

Source: immutable native BU40N1.02 SHA256 `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`. No production code changes, flashes, or commits.

## Actual caller interface

Halfword-by-halfword Thumb BL/BLX scan (avoiding linear disassembly desynchronization) finds `DD164` as the sole direct flash caller of dispatcher `DCA08`. It is inside real function `DCB26`, whose prologue saves R4–R7/LR and allocates14h bytes. This function preserves input in R4, saves bit7 at SP+10h (`DCB4C–DCB52`), strips bit7 (`DCB56–DCB58`), then passes the remaining seven-bit value to `DCA08` at `DD162–DD164`. The dispatch is therefore a speed-like numeric selector, not a buffer pointer. No host output buffer argument is visible at this edge. The dispatcher subsequently programs MMIO, invokes speed/control helpers and returns a status consumed by its callers.

`DCB26` is exported through ARM veneer chain `DBB80 ->14986C -> [149870]=DCB27`. It has numerous flash callers through `DBB80`, including `6AE42`, `6BA88`, `E037C`, `E03A8`, `E0400`, `E1C7C`, `E28E6`, `E2B8A`, `E2FD6`, `E37AE`, `E424C`, `E43D8`, `E44F6`, `E93A2`, `E988E`, `E98BA`, `E9910`. Several callers add80h to the numeric selector before calling. These are actual call encodings, not inferred names. The broad interface usage defeats a claim that dispatch4 is confined to a standalone optional diagnostic solely because the immediate DCA08 caller is internal.

At `6AD80–6AD90` the caller specifically recognizes selector6 for C7/C8; selector4 has its own handling at `6AD52`. `6AE40–6AE46` passes R4 through DBB80 and saves returned status. At `6BA0E–6BA28`, selector4 chooses mode6 when a context byte is set, otherwise mode2, then calls DBB80 after additional context handling. These blocks substantiate speed/mode policy involvement but do not independently identify a host READ opcode or prove actual media reachability.

## Upstream marker and dispatch predicate are coupled

A concrete caller sequence at `E2FB6–E2FD6` first calls `E2944` with selected value R6, then calls DBB80 with the same R6 for media states whose top three bits are not111 (including C7/C8). `E2944` with input4 sets `02000B01=6` when Umarker is1 (`E297E–E298E`), otherwise sets2 (`E2990–E2992`). Thus the actual `6EABA` predicate `(B01 >>1)&3 ==3` becomes true versus false before entering the exported wrapper. This directly connects two formerly separate marker observations.

Owned experiment `/tmp/freemkv-resident-sol-mode.py`, receipt `/tmp/freemkv-resident-sol-mode.json`, executes actual E2944 and DCA08 instructions, actual switch helper and actual6EABA. Only diagnostic CB1BC is stubbed. Explicit initial states C7/C8, selector4, marker0/1, otherwise zero RAM, B0B=6, SP03008000. After E2944 returns, the harness explicitly starts DCA08 with selector4; **the intervening DCB26 wrapper is not executed**, so this is a coupled-stage experiment rather than full caller reachability proof.

| State | Marker | E2944 resulting B01 | DCA08 worker edge |
| --- | --- | --- | --- |
| C7/C8 | 0 | 2 | DCA72 local worker, argument4 |
| C7/C8 | 1 | 6 | DCA6A resident worker, argument4 |

All four cases execute without emulator errors. This refutes dismissal of the marker branch as requiring the previously supplied B01=0Eh specifically. It does not prove DCB26 preserves mode6 through every intervening call.

## Resident boundary and local fallback

Actual ARM instruction at149874 is `B 01FBAA34`. Local fallback wrapper DBB78 goes through14985C, whose pointer is `DC4F7`; aligned Thumb entry DC4F6. For selector4 that local function chooses index1, reads its own tables, stores B0B, stores B01=2 atDC538–DC53A, and programs controller registers including0420629C and0420B130. Consequently local fallback is an actual controller reconfiguration, not an empty/error return. Its semantics cannot establish equivalence to the unavailable resident worker.

The 2MiB file cannot directly contain CPU address01FBAA34. This audit did not recover a positive boot/copy/scatter mapping for that exact address. Prior audits only excluded mappings for other targets and are not a proof for this target. In particular, do not describe01FBAA34 as proven immutable ROM: **resident region of unresolved backing** is the supported description. Neither arbitrary base subtraction nor a plausible disassembly at a reduced offset supplies mapping evidence. Hoard filename search supplies no labeled resident/ROM dump, but that negative search is not an exhaustive archive-content audit.

## Concrete next action

First execute full native caller slice E2FB6 through DBB80/DCB26 to the worker edge under explicit C7/C8, selected4 contexts, recording every intercepted callee and all B01 writers. This will decide whether the upstream mode6 survives the wrapper without assuming it. In parallel with that bounded execution, resolve the actual startup copy/decompression tables or locate a runtime capture spanning01FBAA34; require positive source/destination/range evidence before mapping it to held bytes. If no backing is found, the minimum new artifact is a read-only runtime capture of the worker's aligned page and its outgoing call targets, with drive/model/version and address provenance. Comparing only the local fallback to itself or treating6 as already resident does not close selector4 equivalence.

Reproduction aids: `/tmp/freemkv-resident-sol-trace.py`, `...-trace.txt`, `...-chain.py`, `...-xrefs.py`, `...-xrefs2.py`, `...-xrefs3.py`, `...-select.py`, `...-select.txt`. All target original bytes; none writes firmware.

## Follow-up: full wrapper and held runtime capture

The full-wrapper experiment now exists at `/tmp/freemkv-resident-sol-full.py` and its receipt. Actual E2FB6 executes E2944, exported ARM DBB80/14986C, DCB26, and the real intervening status function84A26. Unmodeled execution stops at CPU2D4 with an invalid instruction because the original file's low boot region is encrypted. That call is reached through68B62. Do not count that run as a passing complete execution.

A separately labeled modeled run `/tmp/freemkv-resident-sol-full-modeled.py` / `.json` additionally intercepts CPU2D4 (argumentC0, return0) and CPU2CC (argument0, no effects), besides loggerCB1BC. The dependency's state-slot recognizer labels this paired interface save/restore state, but this is **not an executed-body proof** of those services. Under that explicit model all four C7/C8 × marker0/1 cases traverse the entire actual wrapper and reach DCA72/local versusDCA6A/resident with argument4 and mode2 versus6. The only B01 store before the worker is E2944; no wrapper store destroys the selected mode. The actual6EABA predicate is executed. MMIO initially zero; selected speed4, prior speedB0B6, R7 points to actual media-state byte; other RAM zero. Thus the previous intervening-wrapper gap is closed subject to two explicitly modeled low boot services, rather than silently skipped.

### Runtime capture discovery and version binding

A held private capture was found outside hoard at `freemkv-private/research/libredrive/mtk/live_dumps/BU40N_1.03MK_blob_fullram_0x1c00000.bin`. Its README records a live DumpAll capture from BU40N1.03MK, with runtime blob active, VA01C00000..02010000, file offset0=VA01C00000. SHA256 is recorded by `/tmp/freemkv-resident-sol-worker03.py`. The separate `BU40N_OEM_overlay_0x1f80000.bin` is documented as OEM1.00, not1.03; its actual458752-byte length conflicts with README's393216-byte range, so do not use its undocumented tail or assume version equivalence. At native1.02's target01FBAA34 that OEM capture contains data, not a valid ARM worker veneer. This is direct evidence that resident addresses move between versions.

There is nonetheless a **positive homologous-worker binding for1.03**. Held BU40N1.03MK flash file `HL-DT-ST-BD-RE_BU40N-1.03-NM00000-211810241934.bin` contains matching native dispatcher structure: predicate+Umarker argument4 branch atDCC22..DCC36 and C7/C8 argument6 branch atDCC38..DCC50, shared BLX149A68 atDCC52. Actual149A68 is ARM `B 01FBAA50`. At exactly that VA the live1.03 capture contains ARM `B 01FE8CC4`; that veneer loads Thumb pointer01FBB78D. Real worker entry01FBB78C classifies numeric selectors3/4/6/8, calls01FBB02E, programs controller state, and writes selected-speed state. This establishes backing for the1.03 homolog without invented base subtraction. It does **not** prove the exact1.02 body or its identity to1.03.

The newly available worker is clearly media/controller configuration, not merely reporting or authentication. Its helper01FBB02E explicitly reads the U marker at01FBB0A6, follows the argument4 path, and changes actual MMIO and state. Owned `/tmp/freemkv-resident-sol-worker03-cpu.py` / `.json` executes this helper's real captured instructions with argument4 and C7/C8, stopping at common01FBB14E. No callees or predicates are stubbed in this bounded helper run. Each compared pair has identical captured RAM except explicitly zeroed BCE and changed state/marker; all MMIO starts zero.

| Captured1.03 helper output | Marker0 | Marker1 |
| --- | --- | --- |
| MMIO04205034 | 0285h | 0295h |
| MMIO04205044 | 0Dh | 0Ah |
| RAM02000BCE, C7 | 0Eh | 04h |
| RAM02000BCE, C8 | 11h | 04h |

Both also write0420502C=8,04205030=03000000h,04205040=C00h. All four cases reach the common stop without error. These differences refute an assertion that the homologous native resident path simply replays identical local settings. They do not establish hardware read necessity or exact1.02 equivalence. No private capture bytes were copied into this repository; only authored address/behavior facts and local experiment paths are recorded.

Updated concrete next action: bind1.02's resident target to its own capture or positively map/decrypt its sealed overlay, or use the already captured1.03 native reference as the explicitly version-bound qualification target and compare its actual local fallback against its actual resident worker. The vague 'worker unavailable anywhere' premise is now false; the remaining gap is **exact-version mapping plus complete downstream comparison**, not absence of all resident evidence.

## OEM byte equality and fallback comparison follow-up

Actual equality was checked, not inferred from the capture README. `/tmp/freemkv-resident-sol-equality.py` compares OEM overlay `[0:60000h]` with GOLD fullram `[380000h:3E0000h]`: **zero differences across393216bytes**. The extra OEM10000h bytes are also byte-identical to GOLD's actual VA01FE0000..01FF0000. Thus actual OEM file coverage is70000h bytes; README's60000h extent is stale/incomplete, with no evidence that the additional tail is padding. Its recorded stock1.00/no-blob provenance remains a documentation assertion, not something byte equality can independently authenticate. Equality does establish that the compared functions are present unchanged in both recorded OEM baseline and MK-active capture; no MakeMKV-added worker code is being proposed.

Specific equality windows:

- VA01FBAA50,4bytes: SHA256 `8047154d52bcb60056baa344477ba0fb8c34f83002746afde6c488798ca3e7da`.
- VA01FBB78C,500h bytes: SHA256 `1ef5374a927b3041da0cb3e228071b6c13472449d353598d2d83612abe951956`.
- VA01FBB02E,300h bytes: SHA256 `b272d3eeddc0ffbafd4e7441437c20d80b9acd4758903690bd21933dc1f3d997`.

### Same-version local versus resident execution

The1.03 dispatcher local fallback DB D60 (contiguous address `0xDBD60`) branches149A50, which loads Thumb DC6DF; actual local entryDC6DE. Owned `/tmp/freemkv-resident-sol-compare03.py` / `.json` executes this full local worker and the actual captured resident01FBB78C, each with selector4, priorB0B6, C0/C4/C7/C8 × marker0/1, explicit mode2/6, zero other RAM/MMIO, real source-native flash tables and OEM-equal resident bytes. LoggerCB3A4 and paired boot services2D4/2CC are modeled as described earlier; no speed predicates or worker calls are intercepted. **All16 runs exhaust the20000instruction budget in hardware polling; none is reported as completed.** Local polls atDB978 (hardware control04042018 is written then expected to clear); resident polls in hardware command5BB8x/5BB D0. These are genuine unresolved device-state interactions, not passed tests.

The executed prefixes already establish different operations. Local selector4 writes B0B=4 and **B01=2** atDC71C/DC722 regardless of marker; it programs source-derived0420629C=33h,0420B130=FF40h and five known04207580/588/590 table writes before entering measurement polling. Resident writes the marker-dependent04205034/044 andBCE values tabulated above, then B0B=4 at01FBB838, leaves B01 at its incoming mode, and invokes controller command writes04206010=D602h,04206000=00910200h before polling. C7/C8 local marker0/1 prefix writes are identical; resident marker changes the already identified controller values. These traces establish a real configuration-sequence difference; they cannot prove final output equivalence or hardware necessity after the polls.

### Minimal source-bound delta assessment

No justified single old table-index change reproduces this observed resident path. The resident helper writes additional/different controller fields andBCE, while local fallback explicitly forces mode2; merely choosing another index in local worker still executes that unconditional B01=2 store. A proposed repair would need separately bound control-mode retention and controller-field operations, not just a speed scalar. The constants0295h/0Ah/BCE4 are observed OEM reference facts, **not authorized donor constants for old drives**. Before implementation, find the old source's existing mode6/controller path and bind its own selectors/tables to equivalent fields, then prove a minimal C7/C8 conditional redirect or parameter adjustment preserves ordinaryBD behavior. Full-local polling can next be advanced only with explicitly recorded hardware read models for04042018 and command-status registers, or a matching read-only runtime trace; do not replace whole functions with success returns.
