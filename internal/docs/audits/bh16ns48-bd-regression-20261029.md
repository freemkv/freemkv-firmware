# BH16NS48 1.02 ordinary-BD regression

The tester reports that ordinary Blu-ray reading regressed after installing the
0.15.4-dev UHD conversion candidate. No failing disc-command trace is available.
The report ZIP proves flashing and protected-byte readback, not media execution.

## Exact inputs

- OEM SHA-256: `43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3`.
- Reported image SHA-256: `dd28bdc7152221b8a2f92d28e71ffc01f6e426608a67676a957b8f7c1cba7a74`.
- Build receipt: source commit `554aff617a2c8ae6f025b1966d5d8570c83aa84d`.
- Report: `freemkv-report-add9fea3-4bf1-4bc2-8272-7440ffd80cce.zip`.
- Embedded startup flags: Unrestricted On; HRL, Encryption, Speed and Region OEM.

## Reproduced instruction compatibility defect

The classic speed emitter replaces the shared native leaf epilogue with a
Thumb-2 `B.W`. In this exact reported image the instruction at `0x0a9666` is
`B.W 0x1aaa88`. The original instructions are `LSLS r0,r0,#24`,
`LSRS r0,r0,#24`, and `BX lr`. Every bound selector path reaches that epilogue.
The branch runs before the replacement stub checks whether Speed is enabled;
leaving Speed at OEM therefore cannot avoid an unsupported branch instruction.

Executing the native selector from `0x0a9622` in Unicorn 2.1.4 with an ordinary
BD-class state (`0xc0`), maximum 12, and Speed OEM gives:

| CPU model | OEM image | Reported image |
| --- | --- | --- |
| ARM926 | Returns normally | Invalid instruction at `0x0a9666` |
| ARM1176 | Returns normally | Invalid instruction at `0x0a9666` |
| Cortex-A9 | Returns normally | Returns normally |

This is a confirmed dependency on a newer instruction set and a plausible cause
of the hardware regression. It does **not** establish this drive's exact CPU
model or prove that this is the only defect. The earlier speed execution test
left Unicorn at its default CPU model, which accepts this instruction.

## Correction

Replace the complete six-byte epilogue with Thumb-1 `PUSH {lr}` followed by `BL`.
The stub restores the saved native LR without changing R0-R12 or NZCV, balances
the stack, then executes the existing speed policy and native normalization.
The native `BX lr` is consumed by the installation rather than left as an
unreachable trailing instruction. The selector locator already validates this
six-byte epilogue and its incoming branches.

The structural audit checks both the saved-return instruction and the call.
The mutation regression rejects the prior `B.W` install and an omitted LR save.
Classic speed and UHD conversion CPU tests now select ARM926 explicitly, so
acceptance by Unicorn's more capable default CPU cannot hide this class of bug.

## Validation

- `cargo test -p freemkv-fw --lib`: 220 passed.
- `cargo clippy -p freemkv-fw --lib --examples -- -D warnings`: passed.
- Formatting and diff whitespace checks: passed.
- Classic speed suite: 24 held sources, 23,040 execution comparisons on ARM926.
- Exact BH16NS48 conversion suite on ARM926: 106,496 routing comparisons plus
  arithmetic, parameter, DI, controller, calibration, position and return checks.
- Rebuilt BH16NS48 output: normal Modify structural audit and all four CMAC
  regions passed; startup choices remain identical to the reported image.
- Full installed speed path: OEM and corrected images match across six media
  states on ARM926, ARM1176 and Cortex-A9 (18 comparisons). The reported image
  faults at `0x0a9666` in all 12 legacy-model cases. These executions use the
  complete binaries, not separately inserted candidate stubs.

Corrected candidate SHA-256:
`137675d7e2b407520e679de6789bdf3997659362fd03395c7604a88f0eeea201`.
The candidate was built locally only; nothing was flashed or released.

## Hardware confirmation still needed

### User-reported follow-up, 2026-10-30

The user reports that DVD and ordinary BD now work after the MT1939 Thumb-only
correction, but UHD still does not work. This establishes a reported recovery
of the ordinary-media baseline, not a successful UHD conversion. The follow-up
does not include the installed image hash, UHD recognition/capacity result,
runtime Unrestricted readback, or failing command/sense data. Do not infer the
exact remaining gate or hardware limitation from this result alone.

The next diagnostic distinction is whether UHD fails during recognition,
after recognition during a data read, or in the client application. Preserve
the exact failure and correlate it with the installed image and runtime setting
before changing another conversion hook.

Compare ordinary BD recognition, capacity and a real data read with the original
image and corrected candidate. Preserve exact sense errors if either fails.
Only after the BD baseline is restored should the UHD experiment be evaluated.
Neither protected-byte verification nor these CPU tests establish UHD reading.
