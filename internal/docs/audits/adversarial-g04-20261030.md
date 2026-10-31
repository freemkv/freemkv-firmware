# G04 adversarial audit — 2026-10-30

Verdict: **unproven as a requirement for UHD reading; conditional requirement for matching the newer firmware's C7 numerical path.** The native change is real and specifically admits C7 to a pre-existing shared calculation. That does not establish that every UHD read invokes this path, that the older result causes read failure, or that native numerical parity is required for reading.

## Binary evidence

Inspected actual 2 MiB images from `/Users/matthew/Developer/firmware-extractor/hoard`, identified by full SHA-256:

- New BU40N 1.02: `1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396`.
- Old BU40N BN11: `5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95`.

Worktree under audit: `/Users/matthew/Developer/tmp/freemkv-firmware-mt1939-0155`, supplied revision `f5b7f12`; dependency supplied revision `66c4b1c`. Address notation below is firmware file offset / mapped address, not an optical-sector address.

New function entry `0xd866e`, old `0xd7ce6`. Both read a global halfword at `0x02000b2c` through R4, save its original value, optionally divide that halfword by four (new `0xd86ce–0xd86d8`, old `0xd7d46–0xd7d50`), then choose a calculation according to state, a flags byte at `0x02000b6d`, and a comparison with `0x20000`. The comparison operand comes from global cells `0x02000b40`/`0x02000b3c` around a call to new `0xd82d4` / old `0xd795a`. These are prerequisites missing from a stage-only entry.

The bases are **actual fixed literals**, not unknown caller arguments at function entry: R7=`0x5534`, R5=`0x3fd2`, and another base=`0x3b6f` (new literals `0xd87d8`, `0xd87e4`, `0xd87dc`; old `0xd7e50`, `0xd7e54`, `0xd7e58`). A further branch uses `0x44e8`, and the CC-like calculation uses `0x51b1`. Their physical units remain unidentified. The test harness's arbitrary R7 bases test arithmetic generality, not observed firmware inputs.

Old `0xd7d9c–0xd7da0` tests `(0xc8 & ~state) != 0` and bypasses the shared forward worker for C7, retaining an earlier R6 result. New `0xd8726–0xd872a` has the same test but branches to `0xd8752`, where `cmp r0,#0xc7; bne 0xd883a` explicitly admits C7. The worker at new `0xd8756` / old `0xd7dca` loads the current halfword, calls genuine division (`0x13c4e0` / `0x13b18c`) with divisor ten, multiplies quotient by twelve, adds R7, and takes low16 (new `0xd88e4–0xd88e6`; old `0xd7f2e–0xd7f30`). Thus the native forward expression is `low16(0x5534 + 12*floor(current_halfword/10))` on this path.

This worker is **not UHD-exclusive**: old firmware already reaches it when the state includes all C8 bits but does not include all CC bits, e.g. C8, C9, CA, CB. States including CC go through division by twenty and multiplication by twenty-three. Bit-mask tests must not be described as exact equality tests. C7 is the new explicit exception, not a newly invented worker. This supports shared density/media-specific conversion and defeats any claim that the worker's mere existence proves UHD necessity. It does not itself identify which exact BD/BDXL formats each state denotes.

## Callers and consumers

A halfword-aligned Thumb BL/BLX scan found direct callers of the encompassing function at new `0xd9312` and `0xd9336`, old `0xd8924` and `0xd8948`. They are conditional: the first is controlled by bit1 of a global flag; the second by additional word/byte flag checks. There is an alternative route (new `0xd9342` onwards, old `0xd8954` onwards) that obtains a value from another helper, clamps it to 300, and averages it with a global halfword. No trace here establishes the flags for a real UHD insertion/read. These are direct call sites, not proof of exhaustive whole-program reachability; indirect calls remain possible.

The shared function restores the original input halfword at new `0xd8a0a–0xd8a0c` / old `0xd8054–0xd8056`; the numerical harness deliberately stops before this. Later it calls new `0xdb838` / old `0xdadfc`. A zero helper return takes an early return before further use of R6 (new `0xd8a24–0xd8a36`, old `0xd806e–0xd8080`). Otherwise R6 is divided by this helper's return, and a shifted copy is also divided (new `0xd8a38–0xd8a52`, old `0xd8082–0xd809c`), followed by state-dependent processing. Therefore the calculation is an intermediate parameter, not a direct read-success or authentication result. The units of the input and final hardware effect are not established here.

## Counterexamples and limits

1. The same worker executes in **old firmware for non-C7 states**. Its arithmetic correctness cannot prove UHD exclusivity or necessity.
2. There are structurally real alternatives that bypass the whole function, and an early return that avoids consuming its result. These are counterexamples to an unconditional control-flow claim, although not yet demonstrated to be valid successful-UHD operating states.
3. The old C7 path retains a pre-existing result rather than necessarily producing an error or zero. Showing its difference from the newer result does not prove it is outside an acceptable hardware range. No acceptance interval or optical success predicate was established.
4. A newer firmware may improve calibration, speed, margins, or coverage. The observed branch change is consistent with necessity but also with those weaker explanations. Neither explanation is resolved by stage emulation.
5. Admission can matter only if C7 is set, the encompassing routine runs, its direction/flags select this forward branch, and the result is consumed on the operation of interest. Existing stage tests supply those preconditions manually.

The existing calculation script executes a real division worker, a useful stronger fact than substituting arithmetic results. It seeds R0/R4/R5/R6/R7 and memory at the recognized stage, though, so it cannot settle the prerequisites above. No optical read, DI-to-caller execution trace, documented unit interpretation, or failure/success comparison was performed in this audit. The label “ForwardCalculation” is the recognizer's role name, not independently decoded physical semantics.

## Reproduction

Owned scripts and complete output:

```sh
/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-disasm.py > /tmp/freemkv-g04-disasm.txt
/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-details.py > /tmp/freemkv-g04-details.txt
/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-callers.py > /tmp/freemkv-g04-callers.txt
```

Scripts load the corpus JSON to locate the two hashes, read the actual binaries, and disassemble with Capstone. `details.py` scans every aligned potential Thumb BL/BLX instruction rather than trusting one linear disassembly through embedded literal pools. Local Python environment supplied: Unicorn 2.1.4 / Capstone 5.0.7. No firmware patch, flash, production edit, or commit was made.

To promote necessity beyond **unproven**, obtain a real UHD trace from DI classification through these flags/call sites, identify the physical input/output units and acceptable bounds, and demonstrate that retaining the older value causes failure while admitting C7 resolves it under otherwise identical conditions. Until then, describe G04 as native C7 numerical parity, with reading relevance conditional.

## Extension: actual input producer, return and hardware consumer

The output is **not merely a display/diagnostic scalar**. Further binary inspection found a complete software route to a hardware register write, although hardware meaning and actual UHD execution remain unproved.

### Input origin and bounds

For C7 (`state>>6 == 3`), new `0xd82d4` calls `0xd7ec6` at `0xd830e`. That worker derives a difference from `0x02000b40` and `0x02000b3c`, selecting orientation through flag bit0 at `0x02000b15`. For differences large enough to survive `>>13`, it applies helper `0xd7e1e` to each endpoint, subtracts the results, and sometimes adds one. Otherwise it scales endpoints left by three and invokes `0xd7d00`, then restores endpoints. The eventual producer is `0xd7f56–0xd7f72`: compare result against **1500**; above 1500 set bit3 in `0x02000b15` and store `low16(result>>2)` to `0x02000b2c`; at or below 1500 clear that bit and store low16(result). The enclosing caller quarters the halfword when bit3 is clear. Thus a small derived difference reaches the numerical stage divided by four; a large difference is already quartered before storage. Overflow above the 16-bit stored representation remains possible for sufficiently large synthetic producer values. No physical endpoint bounds were established.

This means the old stage harness's complete halfword sweep is an arithmetic stress domain, **not proof those values arise from a real disc**. Exact upstream provenance stops at endpoint globals and conversion helpers here; they are not established as sector addresses, time measurements, or another physical unit.

### Accepted output and its consumers

After the measurement helper `0xdb838` returns nonzero D, new code calculates R6=`floor(stage_result/D)` and R5=`low16(floor((stage_result<<shift)/D))`, where shift is bits4–6 of MMIO byte `0x04000028`. For C7 it then sets R6=`low16(2*R6)` and R5=`low16(2*R5)` at `0xd8a6a–0xd8a70`. These are wrapping operations, not saturating clamps.

Depending on flags, R6 is compared against a four-byte threshold array saved on the stack (`0xd8a8c–0xd8a9e`); the resulting index is bounded to 0–4. The corresponding configuration byte is compared with MMIO shift before calling `0x2a5c6`. It can subsequently pass `low16(R6<<shift)` to `0x27e2c`. With ordinary zeroed auxiliary flags, the path instead clears bit6 in `0x02000b16`, stores R6 to **`0x01ff9e74`** (`0xd8cf0–0xd8cf2`), and returns R5 (`0xd8cf4` through `0xd8a30`). In that case the actual direct caller retrieves the return saved at `[sp+8]` (`0xd9370`) and calls **`0x27e2c` at `0xd9384`**.

`0x27e2c` is an actual bounded hardware configuration consumer. Zero input returns without writing. Nonzero input selects numerator **86400, 172800, 345600 or 691200** according to bits4–5 of MMIO `0x0420c07e`, divides that numerator by the input with the genuine worker, subtracts 256, and shifts left four. It bounds this unsigned intermediate using `0xf000`, `0x2000`, and `0x1800` plus a global flag, then stores a halfword at **`0x01ffa104`** (`0x27eaa`). Its high nibble goes to `0x27e08`, which modifies bits4–5 of **MMIO word `0x04207508`** (`0x27e28`): high nibble >=8 selects 0, 4–7 selects 0x10, below4 selects 0x20. That MMIO write is the exact observed hardware boundary. These constants and reciprocal arithmetic suggest a rate/timing configuration; the register's optical subsystem/function cannot be named from this evidence alone.

There is no blanket downstream rejection of every changed result: many distinct old/new input values map to the same bounded setting. Thus “accepted” can mean the native consumer executes safely and bounds its setting; it cannot mean the physical drive accepts a UHD read.

### Actual-code experiment (bounded and explicitly stubbed)

Ran `/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-endtoend.py` → **PASS 81**. JSON: `/tmp/freemkv-g04-endtoend.json`. The script verifies binary SHA-256 and executes old original, actual prepared G04 candidate installed in memory, and newer original from their calculation sites through their actual return tails. It uses fixed firmware bases and seeds the preceding shared calculation to `low16(0x3fd2+9*floor(input/10))`, matching one concrete pre-stage branch. Inputs: 0,9,10,1499,1500,1501,50719,50720,65535; supplied D: 1,100,1000. It **stubs only the measurement helper return** (new `0xdb838`, old `0xdadfc`) to D, because it polls hardware. Real arithmetic workers run. Auxiliary RAM/MMIO start zero, giving shift0 and the simple C7 return path. It does not execute DI, producer helpers, real hardware polling, or caller instructions themselves.

All **27 candidate return/global pairs match the newer firmware**. For the newer firmware, the script additionally executes actual `0x27e2c` and `0x27e08` with the returned value through actual RAM/MMIO writes, supplying a synthetic return sentinel. With this configuration these values converge to stored bound `0xf000` and MMIO field zero; this proves consumer execution/quantization in that configuration and illustrates why arithmetic differences alone are insufficient evidence of functional failure. It does not validate every MMIO mode, threshold-array path, or actual hardware configuration.

Example input1500,D100: old return352; candidate/new return472. All reach the return path without an explicit validity rejection. New then writes bounded hardware setting `0xf000`, field0. Input50720,D1: old return58436; candidate/new return34280; this exercises post-calculation truncation/doubling, rather than an unbounded “accepted” integer.

Disassembly commands:

```sh
/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-consumers.py > /tmp/freemkv-g04-consumers.txt
/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-hardware.py > /tmp/freemkv-g04-hardware.txt
/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-register.py
/tmp/mt1939-recognition-venv/bin/python /tmp/freemkv-g04-endtoend.py
```

**Updated bounded conclusion:** G04 has a demonstrated path into hardware configuration, and the prepared candidate's return/global values match native on the exercised tail. It is not justified to call it merely diagnostic. Necessity for reading remains **unproven**, since measured D, actual input range, runtime flags, hardware register semantics, and successful/failed UHD operation are unresolved. The next concrete implementation action is to add this real return-tail and bounded hardware-consumer verification to the audit tooling, sweep MMIO numerator/shift modes and threshold paths, and instrument the input producer plus hardware measurement boundary in a read-only trace. Keep “native numerical parity” separate from the reading-necessity claim until those traces identify a failing old configuration.

## Follow-up implementation: read-only reverse substrate contract

At the parent's request, added dependency-only `LegacyReverse` in
`/Users/matthew/Developer/tmp/mediatek-optical-mt1959-uhd/src/image/analysis/uhd_reverse.rs`,
with export in `analysis/mod.rs` and hash-checked sparse fixtures under
`tests/fixtures/analysis/uhd-reverse`. It does not install any firmware patch.

The public ABI binds the four-byte BICS/BNE detour (`site`, `original`,
`accept`, `reject`), shared `state`, independently agreed zero/one coefficient
consumer `mode`, native ARM `divide`, native twelve-quotient subtraction worker
`mode_zero`, common low16 `normalize`, and source-bound `caller: SavedLink`.
Input halfword save/restore and literal-base register setup are recognized
from source code; no new mode storage or lifecycle is inferred.

`cargo check --features analysis` and two targeted tests passed. Tests cover
BN11 and distinct NB50 source fixtures, refusal of missing mode evidence, and
mutations for mismatched neighboring mode cell, ARM dispatcher, normalizer,
and subtraction direction. Full current scan across all24 older images is
`/tmp/freemkv-g04-reverse-rust-scan-final.txt`: **23 positive, one refused**.
The refused early image is
`c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306`:
it has reverse arithmetic but lacks the independently recognized mode-zero
and mode-one coefficient consumer grammar. This is a bounded unsupported
layout, not an assertion that the field/lifecycle does not exist. Inventing
a mode binding to force all24 positive would violate the source-bound contract.
The parent was informed; a distinct positive grammar needs independent evidence
before that image can be admitted.

The temporary Rust scan example was moved to
`/tmp/freemkv-g04-audit-reverse-example.rs` after validation. The production
recognizer uses no source hashes or model names. No commit, flash, or installation.
