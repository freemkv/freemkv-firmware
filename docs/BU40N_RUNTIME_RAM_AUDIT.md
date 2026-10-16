# BU40N OEM RAM Poke/Call Goal

## Goal

Find an OEM-accepted command sequence that reproduces the modified firmware's **Poke** and **Call** behavior at runtime, without persistent firmware flashing.

The desired proof is:

```text
OEM firmware
  → OEM command writes Thumb bytes to CPU-visible RAM
  → OEM command transfers execution to that RAM
  → RAM code changes a verified sentinel
  → drive remains OEM after power cycle
```

## What is already proven

The modified firmware contains private C0 DE commands:

- `Poke` (`0x0d`) writes one byte to a 32-bit address.
- `Call` (`0x0c`) calls a Thumb address.
- Full CDB frames use `3c 0e de b9` and request a 64-byte data-in phase.

On a modified control image, those commands wrote and executed a 12-byte Thumb routine at `0x02000e80`. The routine changed a separate RAM sentinel. The image was then restored to OEM.

That proves RAM execution after a handler exists. It does not prove an OEM bootstrap path.

## Current OEM result

The OEM drive rejects the C0 DE Poke frame:

```text
3c 0e de b9 0d 02 00 0e 80 a5
→ CHECK CONDITION
→ Illegal Request / Invalid field in CDB
```

The stock WRITE BUFFER and MODE SELECT paths accept data, but the inspected paths write a staging aperture, controller registers, or fixed/state-derived addresses. No host-selected `0x0200xxxx` CPU RAM destination has been proven.

## Acceptance test

A candidate OEM command path must:

1. Write a Thumb payload to a verified CPU-visible RAM address.
2. Transfer control to that address or provide an equivalent callable entry.
3. Change a separate sentinel and return deterministically.
4. Leave the firmware image OEM and pass the same test after a cold power cycle.

Until all four conditions pass, the OEM Poke/Call equivalent remains unproven.

## Research files

- `research/bu40n_runtime_probe.py` — read-only OEM transfer observations.
- `research/bu40n_ram_hook_evidence.py` — RAM proof and C0 DE frame builders.
- `research/build_bu40n_ram_modify_poc.sh` — post-bootstrap loader for the modify-derived RAM payload; it is not an OEM bootstrap.
- `research/emit_bu40n_ram_modify_c0de.py` — emits Poke/Call frames after a handler is available.

## OEM candidate inventory

| OEM path | Can supply data? | Destination/control result | Poke equivalent | Call equivalent |
|---|---:|---|---:|---:|
| `0x3c` READ BUFFER | data-in only | Reads from a CPU address; does not write RAM | No | No |
| `0x3b` WRITE BUFFER mode 6 | yes | Bounded image/staging transfer; CPU RAM alias unproven | No proven path | No |
| `0x3b` mode 5 subpath | CDB address bytes | Final store is `0x04000000 \| CDB[3..5]`; not `0x0200xxxx` RAM | No | No |
| `0x55` MODE SELECT | yes | Fixed/state-derived transfer and parameter destinations; no host-selected CPU RAM pointer | No | No |
| vendor `0xe7` path | command data | Inspected operations use fixed destinations; no executable target found | No proven path | No proven path |
| resident callback cell `0x02000d30` | no stock writer found | OEM dispatcher can call a Thumb pointer if the cell is populated | Potential pivot only | Potential pivot only |

The modified handler's C0 DE Poke/Call remains the only proven pair, but it is absent from OEM. A successful OEM equivalent must add a new row to this table with both a CPU-visible RAM write and a control-transfer proof.

### OEM command table inventory

The OEM table at `0x14fddc..0x14fea4` contains these fixed dispatch opcodes:

```text
3b 46 4a ac b6 bd 55 5a 1e 1d a2 1b 00 ab f3
f1 f7 f5 f8 f6 fe d4 e7 eb ed
```

The separate `0x3c` record is at `0x14fd74`. The table contains fixed Thumb handler pointers; no record encodes a host-selected call target. The data-out candidates requiring full handler tracing are `0x3b`, `0x55`, `0xe7`, and any data-bearing behavior behind the remaining handlers.

## Exhaustive staging-alias probe

`research/probe_oem_stage_cpu_alias.py` tests the strongest remaining equivalence candidate. While the temporary modified handler is present only as a readback instrument, it sends a stock OEM WRITE BUFFER mode-6 marker, then scans the mapped SRAM/DRAM windows through C0 DE DumpAll. A marker hit proves that stock staging is CPU-visible and can replace Poke; no hit rejects the scanned windows. This test does not program flash.

### WRITE BUFFER RAM staging (readback status)

The temporary modified image was reinstalled and its private Identity response
was verified live (`freemkv 0.11.1`). The first repeat using direct `sg_raw`
was misleading: that framing returned zero-filled data. The repository-native
`freemkv-fw info --dump` transport then read the live state correctly:

* `u32[0x02000c78] = 0x01c08000`;
* `u32[0x02000c7c] = 0x00327c80`; and
* the marker `RAM-STAGE-ALIAS-1` was present at `0x01d5b968`.

This restores the earlier result as a verified observation, with an explicit
transport requirement: RAM readback must use the repository-native SCSI
adapter (or duplicate its SG_IO framing), not the current direct `sg_raw`
probe. The marker demonstrates that stock WRITE BUFFER mode 6 places host
bytes in CPU-visible DRAM; it does not yet demonstrate execution from that
region.

The repository now includes
`crates/freemkv-fw/examples/scsi_out_probe.rs`. It sends an explicitly
supplied CDB and data file through the same native SCSI adapter used by the
working RAM reader. This is the transport tool for the pending `0xA8`/`0x1D`
runtime experiment; it does not guess or synthesize either command.

The first live attempt used the statically inferred 12-byte frame
`3b 04 a8 00 00 00 00 01 54 00 00 00` with exactly 340 data bytes. The drive
returned CHECK CONDITION, ASC/ASCQ `24/00` (invalid field), so this frame is
not yet the accepted host representation of the selector-4 `0xa8` path. No
`0x1d` command was sent. The static handler layout remains valid, but the
opcode/transport mapping now requires one more bounded framing check.

A second frame, `3c 04 a8 00 00 00 00 01 54 00 00 00`, was accepted by the
transport, but the 340-byte marker did not appear at the statically predicted
source interval. This proves acceptance only; it does not prove that this is
the selector-4 receive path. A no-overflow `0x1d` length-1 probe using
`1d 01 00 00 01 00 00 00 00 00 00 00` was rejected with sense
`0x0b/0x00`. The unspecified CDB fields therefore remain unresolved and no
return-slot overwrite has been attempted.

On the temporary modified image, stock WRITE BUFFER mode 6 accepted a 16-byte marker at offset `0x153968`. Runtime cells resolved as:

```text
u32[0x02000c78] = 0x01c08000
u32[0x02000c7c] = 0x00327c80
marker destination = 0x01d5b968 = 0x01c08000 + 0x153968
```

C0 DE DumpAll read the marker at `0x01d5b968`. This proves the stock transfer path can place host bytes in CPU-visible DRAM and can serve as the OEM-side code loader.

Mode 6 is an image-download path with `offset + rounded_length <= 0x200000`. Its later conditional update handoff at `0x13da2a` is a separate path and must not be reached during volatile RAM testing; its persistence behavior is not part of this proof.

WRITE BUFFER therefore supplies the Poke equivalent. The remaining requirement is Call: a stock command or normal OEM execution path must transfer control to the staged DRAM address.

### Volatile installation order for the callback probe

The safe dependency order for a volatile experiment is now explicit:

1. Clear byte `0x02000C6C`.
2. Clear the aligned word at `0x02000D30`.
3. Stage the callback and any separate handler in non-overlapping CPU-visible RAM.
4. Write the callback pointer to `0x02000D30` with the Thumb bit set: `(entry & ~1) | 1`.
5. Write a nonzero value to `0x02000C6C` last.
6. Invoke the separately identified OEM runtime path and observe only a RAM sentinel or response.

The callback entry must be halfword-aligned, and the pointer cell is word-aligned. The visible path has no atomic installation or interrupt masking. A dispatcher that has already passed its gate can still read the pointer while installation is in progress, so the gate and pointer must be cleared before staging and armed only after the pointer is complete.

Clearing `0x02000C6C` is not a complete global disable: the zero branch in the dispatcher can load and call a separate pointer at `0x02000D2C`. That cell must therefore be included in the preflight read/clear plan if the live path can reach the dispatcher during installation. The fixture still does not prove that staged RAM is executable or that an OEM command dispatches a new CDB handler; those remain runtime acceptance conditions.

### Correction: gate-byte writer

The earlier shorthand describing three stores near `0x0012051A` as writes to `0x02000C6C` was incorrect for this fixture. The decoded targets are:

```text
0x0012051A: RAM[0x02000C6C] = r5
0x0012051E: RAM[0x02000C6A] = r4
0x00120522: RAM[0x01FFBE54] = r4
```

The gate byte is written nonzero only when the two fixed helper calls using `0x02000CDC` and `0x02000CE2` produce a nonzero result. The routine is registered under table keys `0x022A` and `0x02AA`; the relevant table is selected when `RAM[0x01FFBD2A] != 0` and `(RAM[0x01FF9E04] & 0xE8) == 0x60`, subject to earlier table-selection conditions. The final event or command that dispatches those keys remains unproven.

### Minimal gate-only PoC

The first runtime PoC deliberately omits the new CDB handler. It stages only a tiny Thumb callback whose first instructions clear `0x02000C6C` and zero `0x02000D30`, then records a separate sentinel and returns. The intended sequence is:

```text
clear 0x02000C6C
clear 0x02000D30
clear/check 0x02000D2C
WRITE BUFFER: callback bytes
WRITE BUFFER: callback pointer (entry | 1) to 0x02000D30
WRITE BUFFER: nonzero byte to 0x02000C6C
wait for ordinary runtime processing
read gate, pointer, and sentinel
```

An observed transition of `0x02000C6C` from nonzero back to zero is evidence that a consumer reached the dispatcher. A changed sentinel is required to prove that the staged callback executed. A zero callback cell is an expected post-entry signal if the callback clears it. This PoC does not claim that an OEM command dispatches a new CDB; that is a later phase.

## Why mode 6 is the current staging candidate

Mode 6 is favored because it is the only WRITE BUFFER mode with a verified CPU-visible RAM readback. The files do **not** establish that modes 0–5 or 7+ cannot do the same.

| Mode | Current evidence | Status for volatile RAM use |
|---|---|---|
| 0–4 | No mode-specific semantics or destination have been established | Unknown; requires dispatcher and handler tracing |
| 5 | One subpath constructs a store address as `0x04000000 \| CDB[3..5]` | Not a proven `0x0200xxxx` RAM path; full semantics remain incomplete |
| 6 | Accepts host data and the marker was read back at `base + offset` in CPU-visible DRAM | Strongest Poke candidate; update-handoff boundary and lifetime remain to be proven safe |
| 7+ | No individual mode has been enumerated or traced | Unknown; requires dispatcher enumeration |

The current preference for mode 6 is therefore evidence-based selection, not elimination of the other modes. The next bounded research steps are: (1) enumerate the WRITE BUFFER mode dispatcher and identify which modes are implemented, then (2) trace the mode 6 conditions reaching `0x13da2a` so volatile staging can be separated from update processing. Mode 5 remains a secondary candidate because its complete path has not been traced.

The selector-5 handler range `0x9d106..0x9d3be` is now traced. Its command-addressed word store at `0x9d264` forces bit 26 in the base (`0x04000000`) and permits only a bounded increment, so it cannot reach CPU-visible addresses in the `0x0200xxxx` state/RAM region, including `0x02000d30`. Other stores use inherited `r4` or stack addresses; this range does not establish those inherited pointers as command-controlled. The handler has no command-derived indirect branch. Mode 5 is therefore not a demonstrated alternative Poke or Call path.

Selector 4 (`0x9ce94`) does write CPU-visible fixed globals at `0x02000c72` and `0x02000c66`, proving that this handler can modify RAM state. Its destinations are fixed, however: command bytes select among fixed branches and provide checked values/lengths, while all calls use immediate targets. It neither reaches `0x02000d30` nor transfers control into a data buffer. This is a RAM-write primitive for fixed state, not a general Poke or Call equivalent.

Selector 2 (`0x9ce88..0x9ce92`) has no store or data-controlled transfer. It loads fixed literal `0x336500aa`, calls fixed targets `0xcb3c0` and `0xab9fc`, then follows the ordinary return path. Those callees remain separate boundaries.

Selector 8 (`0x9d782`) is a mixed transfer/update path, not a general Poke or Call primitive. It writes the fixed globals `0x02000c72` and `0x02000c66`; its fixed calls include an operation using flash destination `0x001e84c0`, plus copies to firmware-global base `B` with fixed offsets. CDB fields select conditional branches and lengths, but do not provide a destination or control-flow target. No path identified here reaches `0x02000d30` or executes transferred data.

Selector 10 (`0x9d0cc`) is likewise not a general Poke or Call path. Its handler writes only fixed `0x02000c72 = 0x0110` or the failure-state byte at `0x02000c66`. The command’s 24-bit field is compared against `0x110` to select a fixed branch; it never becomes a store or call address, and all calls are fixed targets.

The two mode-6 base cells have no direct command writer in the OEM image. `0x02000c78` is written at `0x422da` from hardware register `0x04030f20`; `0x02000c7c` is written at `0x422ec` from fixed hardware/state arithmetic. A separate initialization loop writes both from fixed image words. No CDB or payload bytes supply either value, so the host cannot redirect the observed mode-6 staging base through these cells.

The first broader OEM handler checked, opcode `0x46` at `0x981b4`, writes only stack slots, command-buffer byte `0x02000d39`, and fixed state byte `0x02000c66`. Its destinations are not command-selected and it has no indirect control transfer. It does not provide a general RAM write or execution edge; its continuation at `0x981d8` remains a separate bounded boundary.

The `0x4a` handler at `0x986ac..0x98b14` also writes only stack slots and fixed state/controller locations (`0x02000c72`, `0x02000c66`, `0x02000c6d`, `0x040400a8`, and `0x040400d4`). Its CDB fields affect values and branch selection, never store destinations. All calls, including `BLX`, have immediate targets; the only indirect transfer is the saved-return epilogue. It does not reach `0x02000d30` or provide arbitrary RAM execution.

The `0xac` handler at `0x99894` has only a stack-frame store before its first return and one direct call to `0x98cb6`. It reads a byte from the fixed command buffer `0x02000d38` to choose whether to continue, but does not derive a store or call destination from that data. Its continuation at `0x998b2` and callee `0x98cb6` remain separate boundaries.

The `0xb6` handler at `0x9c698..0x9c8ba` writes several fixed CPU-visible state cells, including values selected from CDB bytes, but no destination is command-derived and no store reaches `0x02000d30`. Its 26 calls all use immediate fixed targets; both exits restore the saved return address. It is therefore a fixed-state writer, not a general Poke or Call primitive.

The `0xbd` handler at `0x99974..0x99a0a` also writes fixed state/controller locations (`0x02000c72`, `0x02000c6d`, `0x040400a8`, `0x040400d4`, and `0x01ffbddc/0x01ffbddd`). CDB bytes alter values and conditions only. Its sole call is fixed `0x68b8e`; the exit is a normal saved-return epilogue. It does not provide an input-selected RAM destination or execution edge.

The `0x55` handler wrapper at `0x99ebe..0x99ed0` has no explicit data store beyond its stack-frame save. It calls fixed routines `0x99a0c` and, conditionally, `0x99e1c`; no CDB-derived destination or register-targeted control transfer exists in the wrapper. Those two callees remain separate boundaries.

The `0x5a` handler at `0x9a904..0x9ab34` writes several fixed RAM/state locations, including `0x02000c72`, `0x02000c73`, and `0x02000d43`, but CDB bytes affect only values and branch conditions. Its calls are fixed targets (`0xa2d6a`, `0x68b8e`, `0x10e80c`, and `0x99ed2`), with normal saved-return exits. It does not write `0x02000d30` or expose a command-selected destination.

The `0x1e` handler at `0x9ab42..0x9ab8e` writes only fixed state bytes `0x01ffbdf2` and `0x01ffbdf3`, plus its stack frame. The input byte at `0x02000d3c` selects branches but never forms a destination. Its only call is fixed `0xcb3c0`; there is no non-return register-derived transfer.

The opcode `0x1d` handler at `0x10e8ba..0x10e930` exposes the first credible control-flow edge outside the callback-cell route. It copies payload bytes into a stack buffer at `0x10e908`, while allocating only `0x38` bytes and accepting lengths up to `0x100`; the saved return address is reached at length 69 and fully overwritten at length 72. This is a return-address corruption path, not a normal command-selected branch. It does not directly write `0x02000d30`, and feasibility of using it to reach staged data requires a separate exact analysis of payload layout, accepted length, and stack address.

The exact `0x1d` data flow is now known. Length is `(C[3] << 8) | C[4]` from command buffer `C = 0x02000d38`; the copy source is an internal byte reader using fixed base offset `0xaf90` and firmware cells `0x02000c78/0x02000c7c`, not a host pointer. The destination is `S+i`, where `S = entry_SP - 0x48`, and the saved return slot is `[S+0x44..S+0x47]`. Copy lengths `0x45..0xff` overlap that slot; `0x48..0xff` cover all four bytes. Length `0x100` wraps the byte index and does not normally terminate. This establishes a possible control-flow corruption mechanism, but not yet a verified route to staged code because the entry stack address and accepted command sequence remain unresolved.

The caller trace does not establish an absolute stack address. The handler is reached through the table entry at `0x14fe24` and a table-driven `BLX r0` at `0x1b6a6`; the frame entry address is inherited from outer callers. For the callback cell range `[0x02000d30,0x02000d34)`, the handler frame would overlap only if the entry SP were `0x02000d34..0x02000d78` (word-aligned), but no inspected caller proves that range. The same uncertainty applies to overlap with the mode-6 staging region. Thus the overflow is a real control-flow candidate, but its RAM relationship remains unverified.

The stack-chain accounting is now explicit. In the command-loop path, the outer entry at `0x13d418` pushes `0x10`, `0x13cd48` pushes `0x18`, `0x13cccc` pushes `0x10`, `0x1b400` pushes `0x10`, and `0x1b690` pushes `0x10` before dispatching `0x10e8ba`; therefore the handler entry SP is `S - 0x58`, where `S` is the inherited SP at `0x13d418`. After the handler prologue, its copy-buffer base is `S - 0xa0`. No inspected caller initializes `S` to an absolute address, so the overflow cannot yet be mapped to the staged RAM region.

The repository-wide stack audit is now closed. The existing full-memory capture reads 64-byte windows and has no register snapshot or synchronized command-stack capture; saved probe artifacts contain no stack map. SRAM bounds (`0x02000000..0x02002000`, with an empirical readable end near `0x02001a00`) do not establish stack placement, and the encrypted boot-page artifacts do not provide a usable startup trace. Therefore the absolute `S` value cannot be recovered from current files. The exact handler frame remains: copy buffer `[S-0xa0, S-0x68)`, with the saved return slot at `[S-0x5c, S-0x58)`; only offsets from `S` are proven.

### OEM command-buffer provenance for opcode `0x1d`

The normal receive routine at CPU address `0x40` copies exactly 12 bytes from the controller command window `0x04040e00` into `C = 0x02000d38`. The first five bytes are preserved directly: `C[0..3]` come from controller bytes `0x04040e00..0x04040e03`, and `C[4]` comes from `0x04040e04`; stores continue through `C[11]`. The routine has no supplied-length or opcode-dependent copy count; a state gate can skip the copy, but once entered the copy is fixed at 12 bytes.

The command loop then checks the table record at `0x14fe24`, matches `C[0]` against opcode `0x1d`, loads Thumb target `0x0010e8bb`, and invokes it with `BLX` at `0x1b6a6`. Dispatch performs no length validation. Inside the handler, `L = (C[3] << 8) | C[4]`; `C[1] == 4` returns early, zero length returns, and values above `0x100` are rejected. This proves the command-buffer byte provenance and exact length field, while the transport behavior for an incomplete incoming packet remains a runtime question.

The host transport layer does not impose a special fixed command builder: `ScsiDevice::command_in` and `command_out` accept a CDB slice separately from the optional data buffer, and the real adapter passes that CDB to the SCSI transport unchanged. The firmware evidence proves only that an internal controller window is copied into `C = 0x02000d38`; it does not identify the outer host-facing SCSI opcode or how host CDB bytes populate controller window `0x04040e00`. Therefore the earlier description of `0x1d` as a normal host 12-byte operation was too strong and is withdrawn. The missing runtime question is the outer command envelope that makes controller byte `0x04040e00` equal internal `C[0] = 0x1d`.

For static planning, the minimum handler fields for a nonzero first full return-slot copy are now explicit: `C[0] = 0x1d`, `C[1] != 0x04`, `C[3] = 0x00`, and `C[4] = 0x48`. The handler then copies 72 bytes from the source interval beginning at `B + O + 0xaf90`; `C[2]` and `C[5]..C[11]` are not used by the visible length check or copy loop. This describes the handler’s accepted field constraints only; it does not establish the runtime stack address or a valid replacement return value.

Selector 10’s exact length field is also resolved. At `0x9d0cc..0x9d0da`, the handler reads `C[6]`, `C[7]`, and `C[8]`, assembles a 24-bit value, and compares it with `0x110` at `0x9d0e0`; any other value branches to rejection. It then stores the accepted length and enters the shared receive setup at `0x9d0ea`. The visible selector-10 slice does not use `C[3]..C[5]` to choose a destination; the receive setup derives its destination from the established state cells and fixed `0xaf90` offset. Thus the source interval is selected by firmware state, while selector 10 supplies the exact transfer length `0x110`.

The parallel selector-4 `0xa8` path assembles its transfer length from the same `C[6..8]` field at `0x9ce94..0x9ceaa`, selects subcommand `C[2]` at `0x9ceae..0x9cebe`, and accepts `0x154` only at the `0x9ced0..0x9ced8` check. Therefore both source-population candidates have exact static length fields: selector 10 uses `C[6..8] = 0x000110`; selector 4 with subcommand `0xa8` uses `C[2] = 0xa8` and `C[6..8] = 0x000154`.

### Primary execution candidate: self-contained `0x1d` stack frame

The execution step does not necessarily require a separate staged-code address. The `0x1d` handler copies the first 72 source bytes into `[S-0xa0, S-0x58)`, then overwrites the saved return slot at `[S-0x5c, S-0x58)`. If that stack range is executable, the first part of the same 72-byte source payload can be a Thumb routine, and the four bytes at source offsets `0x44..0x47` can contain the Thumb-tagged address `S-0xa0 | 1`. Returning to the beginning of the just-filled frame would then execute the copied routine and keep the entire mechanism within one OEM handler invocation. This is a static layout candidate, not a runtime proof: it requires the live value of `S`, writable CPU-visible stack memory, executable stack attributes, and a deterministic return path.

A repository-wide search of the available source and fixture-analysis notes finds no documented MPU, execute-never, or stack-permission configuration. That absence does not prove executable stack memory: the boot setup is partly outside the plaintext fixture and the runtime stack bank is not identified. The executable-stack condition therefore remains an explicit runtime check.

The source-region comparison changes the viability assessment. With the observed `B = 0x01c08000` and `O = 0x00327c80`, the `0x1d` handler reads bytes from `[0x01f3ac10, 0x01f3ad10)`. Mode 6 cannot reach that range because its offset bound ends at `B + 0x200000`, but selector 4 subcommand `0xa8` and selector 10’s fixed transfer path both overlap the entire 256-byte source interval. This creates a possible two-stage data path: an OEM transfer populates the source buffer, and the `0x1d` handler copies it into its stack frame. Runtime acceptance, byte preservation, and the absolute stack address are still unproven.

The transfer provenance is now confirmed statically: both selector 4 `0xa8` and selector 10 receive host data through the shared DMA path. Selector 4 accepts exactly `0x154` bytes and selector 10 exactly `0x110`; both program the destination using `*[0x02000c78] + *[0x02000c7c] + 0xaf90`, then start the receive operation through fixed controller registers. Selector 10 leaves the received interval untransformed. The observed address `0x01f3ac10` still depends on the runtime hardware-derived base cells, but when those observed values hold, the full source interval needed by the `0x1d` copy is populated by host data.

The first selector-2 callee, `0xcb3c0..0xcb4be`, fills a local stack buffer and toggles fixed state byte `0x01ffbd88`. It has no callback-cell write and no command-derived destination. Its `bx r3` at `0xcb4be` is the ordinary saved-return path, not a data-controlled transfer; the helper call at `0x44d1c` remains outside this slice.

The second selector-2 callee, `0xab9fc..0xaba6c`, reads CDB bytes from the fixed command buffer `0x02000d38` and stores the assembled value only to `sp+8`. Its remaining calls are fixed targets (`0xcb3c0`, `0xab888`, and `0xab9b6`), and its return restores the saved PC. It supplies no callback-cell writer or command-derived destination.

### WRITE BUFFER selector coverage

The OEM dispatcher extracts `CDB[1] & 0x1f` and uses a compact table. The ARM helper at `0x138d1c..0x138d30` is now decoded: it treats the first table byte as an unsigned entry count, selects an explicit entry when the selector is below that count, otherwise selects the default entry, then branches directly with `BX`. The table count is 11, so selectors 0–10 have individual entries and 11–31 share the default.

| Selector | Apparent target | Current classification |
|---:|---:|---|
| 0 | `0x9cf3e` | Shared/default path; final status unresolved |
| 1 | `0x9d034` | Mode-specific entry; outside the inspected slice |
| 2 | `0x9ce88` | Calls fixed helpers; side effects unresolved |
| 3 | `0x9cf3e` | Shared/default path; final status unresolved |
| 4 | `0x9ce94` | Length and subcommand checks; later effects unresolved |
| 5 | `0x9d032` | Mode-specific entry; outside the inspected slice |
| 6 | `0x9d030` | Staging path; entry instructions still need confirmation |
| 7 | `0x9cf3e` | Shared/default path; final status unresolved |
| 8 | `0x9d02e` | Branches toward `0x9d782`; effects unresolved |
| 9 | `0x9cf3e` | Shared/default path; final status unresolved |
| 10 | `0x9d02c` | Branches toward `0x9d0cc`; effects unresolved |
| 11–31 | `0x9cf3e` (default) | Shared/default path; final status unresolved |

This covers the requested 0–4 and 7+ selectors without claiming that a shared path means rejection. The helper performs a direct branch, not a call, so the selected handler retains the original return address. To classify acceptance and side effects, inspect exactly: caller/table bytes `0x9ce50–0x9ce61`, mode entries `0x9d02c–0x9d038`, and default/mode-8 continuation `0x9d734–0x9d78c`.

For the volatile staging design, the intended transfer remains mode 6 only: omit mode 1 because its documented recipe role is enter-download/pre-erase, and omit mode 7 because its documented recipe role is save/commit. The mode-6 entry at `0x9d030` unconditionally branches to `0x9d484` and performs no prerequisite check at the entry itself. After the temporary staged code has run, overwrite the same mode-6 staging span with a uniform zero or `0xff` payload. This cleanup plan still requires runtime proof that mode 6 alone does not enter the persistent update handoff.

The current static evidence does not yet prove what mode 7 does internally. Its shared entry at `0x9cf3e` immediately branches to `0x9d734`; it does not itself execute the staged buffer or call a save routine. The behavior at `0x9d734` is the next exact range needed before describing mode 7 as an execution or persistence primitive.

The inspected continuation confirms that `0x9d734` immediately branches to `0x9d78a`, so the adjacent call blocks are not fall-through behavior from the shared entry. Within the inspected slice, the only visible persistent-update candidate is a fixed call to `0x13da2a` guarded by a state-byte test; the slice does not prove that mode 7 reaches it. The mode-7 question therefore remains open pending `0x9d78a` onward and the caller state that selects the guarded path.

The next bytes resolve that continuation as `strb r6,[r7]` at `0x9d78a`, followed by an unconditional branch to `0x9d1e0`. It contains no save call, update call, or indirect transfer. Thus mode 7's shared path currently looks like a one-byte state write, but the meanings of incoming `r6` and `r7`, and the behavior reached at `0x9d1e0`, remain unresolved. The nearby fixed call at `0x148e80` belongs to a separate function because the unconditional branch prevents fall-through.

The common continuation at `0x9d1e0` immediately branches to `0x9ce84`; it does not consume the state written by mode 7 in the inspected bytes and contains no update call. The mode-7 path therefore currently has no evidence of executing staged bytes. The exact return/status behavior at `0x9ce84` remains the next missing slice.

At `0x9ce84`, the path is a normal epilogue (`add sp,#0x44; pop {r4,r5,r6,r7,pc}`). It performs no update call or additional store before returning. The adjacent helper block at `0x9ce88` is unreachable by fall-through from this epilogue. Thus the inspected mode-7 chain is a state-byte write followed by ordinary command completion, subject only to unresolved caller-side status handling.

The mode-6 post-transfer gate continues at `0x9d600`: a state byte below `1` loops back to `0x9d5f0`; otherwise it changes that byte to `3`, calls fixed routines at `0x13d958` and `0x29c`, then tests a separate state bit. This is evidence that mode 6 alone can enter additional processing after a transfer. It still does not identify the final update call or prove that a short transfer avoids it; those callees and the following range remain to be traced.

Selector 4's writes to the nearby state cell do not alter the visible mode-6 bounds. The mode-6 comparisons construct `0x200000` as an immediate constant at `0x9d50c..0x9d512` and repeat that immediate bound at `0x9d5f4..0x9d5fc`; no read of `0x02000c72` appears in the inspected slice. The mode-6 slice also contains no register-derived call or branch into transferred data. Pointer literals and fixed callees outside the slice remain unresolved, so this rules out the proposed state-composition path only for the visible code.

The next slice (`0x9d620..0x9d680`) contains no calls. It updates transfer-related state, clears a controller bit, and branches on size and byte comparisons. The later destinations `0x9d704` and `0x9d6fa`, plus the continuation at `0x9d680`, remain unresolved. A mode-6-only staging sequence is therefore not yet proven persistence-free.

### Can the host choose a larger staging base?

Current evidence says no through the mode-6 CDB alone. The host supplies a 24-bit transfer offset and length; the staging base `B` is loaded from firmware state (`u32[0x02000c78]`) and is not assembled from the CDB fields in the traced transfer setup. The observed destination is `B + offset`. Changing `B` would require a separate OEM path that writes the state cell or changes its source; no such path is proven. A large offset can select another location within the bounded staging aperture, but it is not equivalent to supplying an arbitrary CPU address.

A local Thumb disassembly of the mode-6 body `0x9d484..0x9d604` found no `BX` or `BLX` instruction in that range. Its visible calls are fixed targets, so mode 6 currently supplies placement evidence only; it does not provide the required execution edge.

### OEM handler indirect-branch census

The OEM command table was decoded from `0x14fddc..0x14fea4` and its handler starts were scanned as Thumb. The only non-`lr` register branch found in the handler windows was `0xfe` handler address `0xA4B48: bx r3`. Its preceding epilogue is `pop {r3}` at `0xA4B44`, so `r3` is the saved return address, not a command-selected target. Other observed `BX` instructions were returns through `lr`; no handler window yielded a host-derived branch target.

This is a static census, not the final runtime proof. It currently eliminates the obvious OEM-handler Call candidate and leaves the required execution edge unproven.

The separate `0x3c` handler at `0x9ad5a` was also scanned as Thumb; its visible `BLX` instructions use fixed immediate targets (`0x138950` and `0x148e78`), with no register-based branch found in the inspected window. READ BUFFER therefore adds no Call candidate in the current census.

The `0x3c` handler does contain a computed jump at `0x9adc4`, but it is a fixed 14-entry table dispatch. It derives an index from the command mode byte, bounds it to 0–13, and selects fixed targets from `0x9adc6..0x9addf`; it does not use a host-supplied address. This is an OEM mode selector, not a RAM execution edge.

A second sweep for `ADD PC`, `MOV PC`, `LDR PC`, and register `BX/BLX` across every decoded OEM table window found no additional computed control-flow form. The `0x9adc4` table is the sole non-return computed branch in the scanned command handlers.

The `0xe7` handler slice `0xa374c..0xa38c0` is now classified: its visible stores target fixed state cells (`0x01ffbd44`, `0x01ffbd32`, `0x01ffbd29`) or fixed controller address `0x04000020`. Command bytes select branches and values, but do not form a store destination. Its visible calls are fixed targets. Effects inside those callees remain outside this slice, so this is not a whole-program proof, but the handler itself supplies no callback-cell writer or host-selected call target.

The first external callee examined, `0x43dcc..0x43e80`, likewise has no destination derived from its incoming arguments: visible stores target fixed controller/state literals or stack locations, and its indirect control flow is limited to saved-return epilogues. This removes that `0xe7` callee as a direct callback-cell writer in the inspected range; its own external callees remain a separate unresolved boundary.

The resident dispatcher at `0x1b400..0x1b42c` is a genuine indirect-call mechanism: it loads the pointer stored at `0x02000d30` and executes `BLX r0` at `0x1b428`. A literal search finds only the dispatcher’s own reference to that callback cell and no stock writer reference. The known mode-6 staging aperture also ends below the callback cell (`B + offset`, with the bounded offset), so mode 6 cannot be assumed to populate it. This remains the strongest theoretical OEM Call edge, but it is not currently installable through a proven OEM command.

There is therefore no identified “OEM dispatcher CDB.” The dispatcher is an internal routine reached from the ordinary command-processing loop; it is not itself a separately addressable command handler. The CDB question splits into two independent requirements: identify an OEM command that writes `0x02000d30`, and identify the normal command path that causes the loop to reach `0x1b400`. The second path exists, but no first-step writer has been proven.

With the observed `B = 0x01c08000`, reaching the callback cell would require `offset = 0x3f8d30`. The mode-6 bound limits `offset` to at most `0x200000`, making the highest observed destination `0x01e08000`; the callback cell at `0x02000d30` is outside that range. This is the concrete reason the current WRITE BUFFER path cannot write the callback cell.

The next `e7` callee, `0x10e812`, does copy bytes through its incoming `r1` pointer (`strb r0,[r6,r4]`), but the only OEM-table caller found is `0xa37d2`. That caller passes the fixed command-buffer pointer `0x02000d38` as `r1`; it does not pass `0x02000d30`. This copy primitive therefore writes the command buffer on the OEM path, not the callback cell.

A repository-wide byte search of the OEM image finds the little-endian callback-cell literal `0x02000d30` exactly once, at `0x1b4ac`, the dispatcher’s literal pool. There is no second literal reference to the cell. This rules out a direct literal-address writer in the image; only a computed-address writer, if one exists inside an external callee, remains unclassified.

The follow-up scan of all Thumb-1 PC-relative literal loads gives the same result: the only instruction that loads the exact callback-cell address is `0x1b420`, which loads the literal at `0x1b4ac` before the `BLX r0` sequence. Other loads in the surrounding `0x02000d00..0x02000d80` state region target neighboring command/state cells, especially `0x02000d38`; none directly loads `0x02000d30`. This narrows the remaining possibility to a computed address formed from a neighboring base or an external callee, rather than an omitted direct literal reference.

The targeted state-region routine at `0x9f260..0x9f2b0` does not supply that computed case. It writes fixed literals `0x02000d00` and `0x02000d20` with zero or fixed values; it does not add an offset to either base and never forms `0x02000d30`. Its call at `0x9f29a` remains a separate external-callee boundary.

That boundary, `0x43cb0..0x43cd2`, also does not supply the missing edge in its visible body. It has only the entry stack stores, fixed immediate calls to `0xa2bea`, `0x138d1c`, and `0x43b22`, then returns with `pop {r4,pc}`. No explicit store targets the callback cell and no visible branch target comes from a general-purpose register. The stack stores cannot be classified by address without the live stack pointer, but they are ordinary frame saves rather than a command-data destination; the three callees remain separate inspection boundaries.

The first callee, `0xa2bea..0xa2c0e`, likewise has no callback-cell write or command-derived destination through its first normal return. Its only visible store is the entry stack save; its conditional branches are fixed targets and its return is `pop {r3,r4,r5,r6,r7,pc}`. Branches at `0xa2c10` and `0xa2cf6` remain outside this bounded slice.

The second callee, `0x43b22..0x43cae`, is also eliminated as a direct writer or execution edge. Its explicit stores resolve to fixed state/controller addresses, including `0x02000c68`, `0x01ff9b04`, and `0x01ffbe04`; none is `0x02000d30` or a command-derived address. Its only indirect-looking call is an immediate fixed `BLX` to `0x148704`, and it returns through the saved stack PC.

The `0x148704` target is an ARM veneer, not a Thumb body: `ldr pc,[pc,#-4]` loads the fixed literal `0x01f94741` from `0x148708`; the low bit selects Thumb state, so the aligned Thumb entry is `0x01f94740`. The veneer has no store or command-derived branch. The fixed destination `0x01f94740` is the next callee boundary.

The audited fixture is only `0x200000` bytes, so `0x01f94740` lies outside the available image (`0x1f94740 >= 0x200000`). Repository-wide inspection found no larger image, runtime dump, or map containing that target. This call chain therefore ends at an external mapped-region boundary; it is not evidence of a callback-cell writer, and its body cannot be classified from the available artifacts.

The following `e7` callee examined, `0xa0fcc..0xa1040`, also has no host-selected destination. Its literal base is `0x04011f00`, so its sequential word-copy destination is `0x00400000` (derived from the fixed literal), while its other stores use fixed offsets from that base. It does not reach the callback cell.
### Remote gate probe result

The remote test host reached the drive at `/dev/sg0` and verified the correct runtime frames. Safe reads use the `c0 de` knock; Poke uses `de b9`. A harmless scratch test changed `0x02000E80` from `00` to `AA` and was restored to `00`, proving the transport and Poke path. The target gate read `0x01` before the test and remained `0x01` after Poke attempts of `00`, `02`, and `0x7F`; the callback cell `0x02000D30` remained zero. Therefore the PoC did not yet demonstrate gate control or callback execution. The gate appears to be immediately restored or specially handled, and requires a separate trace of its live writer before the test can be interpreted as an arm/poll result.
