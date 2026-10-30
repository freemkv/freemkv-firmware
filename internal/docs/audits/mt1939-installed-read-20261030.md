# MT1939 post-recognition read-path checks

The previously delivered detection candidate was not rebuilt. The tester now
reports the same unsuccessful detection behavior. This follow-up tests the next reading candidate, not physical
reads. At the final check the Desktop path was absent; the retained `/tmp` copy
still matches the delivered checksum. The missing Desktop file was not recreated.

Inputs are the original BH16NS48 1.02 (`43c484dc…`), detection candidate
`8a7ffc47…`, full-group/read candidate `4e228b09…`, and native-UHD WH16NS60 1.00
(`5e2ec51f…`). Full hashes and all results are in the adjacent JSON.

## Installed code, shared state and native calls

The earlier component suite installs individual stubs at test addresses. The
new `scripts/test-mt1939-installed-read.py` executes the actual candidate files.
It verifies that all 28 read-component stubs match the bytes at their installed
BL destinations, with the real runtime flag slot. DI recognition is tested
separately through its installed hook; auth-cell installation is covered by the
base structural audit.

The linked test runs the complete DI parent, then the complete native
media-default routine (`0x67728`), parameter getter (`0x1050dc`), and range
wrapper (`0xfcccc`). The wrapper calls the actual `0xfcb24` or `0xfcc30`
functions, including their installed position hooks, rather than replacing them
with mock return values. The test carries the parsed state and chosen mode
between stages and checks native stack/register preservation and controller
write sequences.

| Input | Detection-only mode | Full read mode | Coefficient, detection/read |
|---|---|---|---|
| U / format 1 / two layers → C4 | 7 | 7 | 3400 / 3400 |
| U / format 5 / two layers → C7 | 7 | 0x1c | 3400 / 3100 |
| U / format 5 / three layers → C8 | 0x1c | 0x1c | 3100 / 3100 |

For the 0..8192 range example, C7's wrapper output is 1024 on detection-only
and 2048 on the full reading candidate, under the test controller simulation.
The full candidate matches the original image's existing C8 path. The shorter
range goes through `0xfcb24`; the longer range calls `0xfcc30` twice. Both paths
execute with their native caller and installed hooks.

All 108 scenarios pass across both caller branches, layer/direction values and
three parser outcomes. For U/1 the reference is native C4; for U/5 the reference
is the image's existing C8 policy. This shows a concrete reason to keep the
reading hooks available after detection: the smaller image does not establish
the same C7 mode, parameter and software-scaling behavior.

Hardware DI acquisition/logging helpers are explicitly intercepted. Controller
busy bits are cleared by the emulator; hardware arithmetic is not simulated as
real silicon. These outputs establish software routing and caller compatibility,
not physical position accuracy or successful data reads.

## Capacity and first read-command setup

The ROM-media table records identify these handlers in the exact sources:

| Role | BH16NS48 | WH16NS60 |
|---|---|---|
| READ(10/12) records | `0x1a70e0` / `0x1a70e8` | `0x14f8c4` / `0x14f8cc` |
| READ handler | `0xb468c` | `0xaf120` |
| READ CAPACITY record | `0x1a7108` | `0x14f8ec` |
| READ CAPACITY handler | `0xb518e` | `0xafbb2` |
| Capacity/end cell | `0x02000e18` | `0x02000c60` |
| Read-worker entry | `0x197b70` | `0x13e7e4` |

The checks validate the table record bytes and directly execute these handlers.
They do not establish that the drive has registered the media-specific table at
runtime. The read-only example's new `read-dispatch` query reports initial
registrar roots only; its READ/CAPACITY placeholders are not proof that the later
media handlers are absent or unusable.

The native handlers and all three classic images pass 48 capacity-response
cases and 1,536 READ(10/12) handoffs across C0/C4/C7/C8, three capacity values,
four transfer lengths and boundary LBAs. Capacity responses contain the expected
last LBA and 2048-byte block length. The READ handlers apply the same native
`0x100000` address offset and preserve the requested sector count. They reach
their respective read-worker entries for valid requests. Another 384 requests
crossing the end boundary retain sense 05/21/00 in all four images.

These tests supply valid capacity, ready state and command data. They rule out
an extra C7/C8 rejection in the exercised handler paths under those conditions;
they do not prove that initialization produces those conditions on hardware.
No command handler is patched as a result of this comparison.

## Remaining concrete boundaries

The original BD capacity initializer at `0xb988c` clears the capacity cell and
then requires DI-ready bit 1 at `0x02000b14`. It reads the selected DI buffer's
fields using the image's own helpers. Its `(state & 0xcc) == 0xc4` branch also
includes C7 and applies the native two-layer normalization (`0xb987e`). This is
an analysis lead, not a proven incorrect transformation. The native-UHD image's
corresponding resident implementation must be bound before changing that math.

The whole read worker and its physical completion remain unproven by the new
tests. Once the tester's detection result arrives, the decision is:

- Stable detection: compare the full reading candidate and capture real
  capacity plus the first data-read result.
- Still no detection: return to DI acquisition and ready/abort state before the
  recognition hook. Further read-handler changes would not address that stage.

The detection test returned the latter result. The reached stage is not yet
known, so `mt1939_disc_probe` captures the existing native media/ready/abort/mode
and capacity fields first. It does not infer a pre-parser failure solely from
the user-visible symptom or force DI-ready state.

The next full-group BIN is retained locally and has not replaced the delivered
detection-only experiment as the current hardware test.

## Reproduce

Generate a source plan with `mtk_receiver_evidence ORIGINAL uhd-conversion`.
Build both research candidates as described in the recognition comparison note.
Then run:

```sh
python scripts/test-mt1939-installed-read.py \
  --original /path/to/BH16NS48-original.bin \
  --detection /path/to/detection.bin \
  --read /path/to/read.bin \
  --native /path/to/WH16NS60-original.bin \
  --plan /path/to/plan.json \
  --output /path/to/results.json
```

Both candidates require their matching `.json` build receipts beside the BIN.
The script requires Unicorn 2.1.4 and selects ARM926 explicitly.
