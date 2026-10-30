# MT1939 detection versus native MT1959 UHD recognition

Hardware follow-up: the user reports the detection-only format-1/5 candidate
has the same unsuccessful detection behavior. Milestone 1 remains unachieved.
That result does not identify the reached stage. The next experiment is a
read-only Windows state capture using the already-installed detection firmware,
before another firmware change or a sector-reading test.

The tester reports that the Thumb-only correction restored DVD and ordinary BD,
but UHD spins/seeks and is not detected. This is consistent with an initialization
or recognition failure; no live command trace or RAM snapshot establishes the
exact failing stage. Detection is milestone 1; real sector reads are milestone 2.

## Exact comparison inputs

| Role | Image | SHA-256 |
|---|---|---|
| Original | BH16NS48 1.02, MT1939 | `43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3` |
| Previously tested correction | BH16NS48, full conversion, Thumb-only speed hook | `137675d7e2b407520e679de6789bdf3997659362fd03395c7604a88f0eeea201` |
| Native UHD reference | WH16NS60 1.00, MT1959, N014500 | `5e2ec51fb3559623e555aadf280c96268fee6da0acfa7b4000c0d4564e7da073` |
| Earlier comparison | WH14NS40 1.02, MT1959 | `648a16d024eea31ef4901f3ac2180cbfffeda1161d70f9096335d8a6097445bc` |

These hashes identify local files, not a new physical test of the reference drive.
The addresses below describe these exact inputs, not runtime selection rules.

## Concrete differences

The WH16NS60 recognizer at `0xe27e2` accepts identifier U, stores one at
`0x02000bf3`, and then handles both format 1 and format 5. Format 1 assigns C0
before generic layer normalization. Format 5 assigns C7 for two layers and C8
for three. The prior MT1939 conversion recognized only U/5. The earlier WH14NS40
reference also lacks the U/1 branch, so that comparison did not expose this gap.

Running the actual native WH16NS60 parser and installed prior BH16NS48 parser
on ARM926 demonstrates the difference with a valid BD prefix, attribute class
zero and an initial C0 state:

| DI identifier/format/layers | Native WH16NS60 | Prior full BH16NS48 conversion |
|---|---|---|
| U / 1 / 2 | accepts, C4, format byte 2 | rejects, clears state |
| U / 1 / 3 | accepts, C8, format byte 2 | rejects, clears state |
| U / 5 / 2 | accepts, C7, format byte 0x20 | accepts, C7, format byte 0x20 |
| U / 5 / 3 | accepts, C8, format byte 0x20 | accepts, C8, format byte 0x20 |

This is a demonstrated software coverage gap. The tester's DI format is unknown,
so it is not yet the demonstrated cause of that physical failure. The broader
32-case comparison also shows that incoming-state/attribute validation differs:
the old conversion already accepts attribute class three more broadly than the
WH16NS60 does. The new detection probe retains that existing extension policy;
it is not a claim of exact parser parity for every tuple.

The separate WH16NS60 U flag is read by code around `0xa4b48`, `0xa4d06`,
`0xa51c0`, `0xa529c`, `0xa5384`, `0x13dff4` and `0x13f782`. At `0x13dff4`,
the flagged path chooses an eight-versus-six rate limit using the native maximum
speed and optimum/request cells. Independent NativeSpeedPolicy inspection binds
those cells to `0x01ff9e02` and `0x02000b0b`. This is evidence of speed-policy
use, not evidence that copying the byte enables recognition. Other uses still
need role-by-role analysis. No such flag is copied into the MT1939 RAM map.

## Earlier acquisition boundaries

BH16NS48's DI parent starts at `0x10a41e`. Before its recognition hook at
`0x10a876`, it programs a native mode, calls `0xb9ff2`, checks abort/error bytes,
and tests bit 1 of `0x02000b14` at `0x10a4e2`. If that bit remains clear, it
returns status 3 via `0x10aa12`; the recognition hook is never reached. Status
0x0b is another early abort path. A CPU test that supplies ready DI cannot
establish that the physical drive obtains those bytes.

The native acquisition worker `0xb9ff2` calls the ROM-media reader at `0xb9e94`
for the ordinary ROM band. The reader configures the controller, tries its
`0x14814e` helper, sets the DI-ready bit on success, and clears it after retries
fail. Forcing the ready bit would make the parser consume unproven buffer data;
it is not a valid detection fix.

The caller at `0x69120` also calls `0x10aa32` before parsing, and can clear the
media state and retry on an error. Its optical/controller return is another
unobserved hardware boundary.

An acquisition dispatcher at `0x7ca8e` selects different functions for C8-mask
and other ROM states. The MT1959 WH14NS40 dispatcher at `0x84b14` makes the same
split. That split alone does not establish a missing classic gate.

The WH14NS40 parser's acquisition call goes through an ARM veneer at
`0x14c3b0`, whose literal destination is `0x01f91be7`. This runtime address is
outside the direct flash disassembly. Subtracting an assumed base and decoding
unrelated bytes at flash offset `0x191be6` is not a validated mapping. Comparison
of that resident implementation requires its load mapping or runtime bytes.

## Detection candidate delivered

Desktop file: `BH16NS48_1.02_freemkv_0.15.4-dev-detection-1-5.bin`.

SHA-256: `8a7ffc47910f7fef6abdac612f94f7d76d8f81149c704ae54e490a9aec1ff800`.

The research-only builder uses the classic base and corrected Thumb-only speed
hook, with other feature settings at OEM, and installs one UHD DI hook. It adds
U/1 recognition using C0 plus the image's own format/layer handling, alongside
U/5 recognition. It omits C7 scaling, controller, position, calibration and
auth-cell conversion hooks. Those are not presumed unnecessary for reading.
No production CLI/UI switch exposes the partial group. The detection probe bakes
its research flag On without advertising complete Unrestricted capability;
leave its settings unchanged during the hardware comparison.

Validation:

- CMAC, metadata, base structural audit and offline Flash admission passed.
- 6,400 executions of the complete installed DI parent on ARM926: 48 new
  recognition cases and 6,352 OEM-preservation cases, including ordinary media
  and disabled/invalid runtime flags. Native switches, layer math, the installed
  stub, saved registers, stack and native return execute. Hardware acquisition
  and logging helpers are explicitly simulated.
- Eight early failure/abort cases preserve native status 3 or 0x0b.
- Eighteen complete OEM/candidate speed-selector comparisons match on ARM926,
  ARM1176 and Cortex-A9. The earlier Thumb-2 image still faults on legacy models.
- Normal production format-five DI stub bytes match the earlier emitter exactly.
- Final library suite: 223 passed. Clippy with tests and `-D warnings`, formatting
  and diff whitespace checks passed.

The JSON receipt and CPU report accompany the Desktop BIN. The experiment does
not establish hardware detection until the tester reports that result. First
check DVD/BD, then stable UHD detection. Sector reads are a separate milestone.

## Next reading experiment

The same research harness can retain the complete existing conversion group
and replace only its DI hook with the format-one/five extension. This prepares
the next comparison without assuming that every read-related component is an
optional feature. It remains outside production authoring. Its success still
depends on real initialization and sector-read results.

The full-group variant was built and signed in local scratch storage and passed
the same 6,400 installed-parser cases plus eight early boundaries. The existing
component suite also passed 106,496 routing comparisons and its native
arithmetic, controller, calibration, position, DI and return checks. These are
offline results; no sector read or new hardware-detection result is implied.

Build either experiment using an exact original hash:

```sh
FREEMKV_DETECTION_SOURCE=/path/to/original.bin \
FREEMKV_DETECTION_SOURCE_SHA256=43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3 \
FREEMKV_DETECTION_OUTPUT=/path/to/research.bin \
cargo test -p freemkv-fw --lib \
  mt1939_detection_tests::build_selected_detection_candidate -- --exact --nocapture
```

Add `FREEMKV_DETECTION_READ_PATH=1` for the subsequent full-group experiment.
Run `scripts/test-mt1939-detection.py` with `--original`, `--candidate`, `--receipt`
and `--output` to check the actual installed detection path independently.
